#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/event_log.h"
#include "util/format_utils.h"

#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "_dbgfunctions.h"

namespace handlers {

void register_command_routes(c_http_router& router) {
    // POST /api/command/exec - Execute x64dbg command
    router.post("/api/command/exec", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("command")) {
            return s_http_response::bad_request("Missing 'command' field");
        }

        auto command = body["command"].get<std::string>();
        auto success = bridge.exec_command(command);

        return s_http_response::ok({
            {"command", command},
            {"success", success}
        });
    });

    // POST /api/command/eval - Evaluate expression
    router.post("/api/command/eval", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("expression")) {
            return s_http_response::bad_request("Missing 'expression' field");
        }

        auto expression = body["expression"].get<std::string>();

        if (!bridge.is_valid_expression(expression)) {
            return s_http_response::bad_request("Invalid expression: " + expression);
        }

        auto result = bridge.eval_expression(expression);

        return s_http_response::ok({
            {"expression", expression},
            {"value",      format_utils::format_address(result)},
            {"decimal",    result}
        });
    });

    // POST /api/command/format - Format string using x64dbg expression engine
    router.post("/api/command/format", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("format")) {
            return s_http_response::bad_request("Missing 'format' field");
        }

        auto fmt = body["format"].get<std::string>();
        char result[1024] = {};
        auto success = DbgFunctions()->StringFormatInline(fmt.c_str(), sizeof(result), result);

        return s_http_response::ok({
            {"success", success},
            {"format",  fmt},
            {"result",  std::string(result)}
        });
    });

    // GET /api/command/events?since=<seq> - Buffered debugger events
    //
    // Returns every event newer than <seq>. Clients keep the highest seq they
    // have seen and pass it back, which gives them a resumable event stream
    // without SSE or long-polling sockets.
    router.get("/api/command/events", [](const s_http_request& req) -> s_http_response {
        uint64_t since_seq = 0;
        const auto raw = req.get_query("since");
        if (!raw.empty()) {
            try {
                since_seq = std::stoull(raw);
            } catch (...) {
                return s_http_response::bad_request("'since' must be a non-negative integer");
            }
        }

        return s_http_response::ok(event_log::since(since_seq));
    });

    // POST /api/command/clear_events - Drop the buffered event log
    router.post("/api/command/clear_events", [](const s_http_request&) -> s_http_response {
        event_log::clear();
        return s_http_response::ok({
            {"message", "Event log cleared"},
            {"latest_seq", event_log::latest_seq()}
        });
    });

    // GET /api/command/events/wait?since=<seq>&timeout=<ms>&types=a,b&max=<n>
    //
    // Long poll: blocks on the plugin side until an event arrives, so the
    // client does not have to spin. `types` filters what counts as newsworthy;
    // the payload still contains every event since the cursor.
    router.get("/api/command/events/wait", [](const s_http_request& req) -> s_http_response {
        uint64_t since_seq = 0;
        int timeout_ms = 30000;
        size_t max_events = 256;
        std::vector<std::string> types;

        try {
            if (!req.get_query("since").empty()) since_seq = std::stoull(req.get_query("since"));
            if (!req.get_query("timeout").empty()) timeout_ms = std::stoi(req.get_query("timeout"));
            if (!req.get_query("max").empty()) {
                max_events = static_cast<size_t>(std::stoull(req.get_query("max")));
            }
        } catch (...) {
            return s_http_response::bad_request("'since'/'timeout'/'max' must be integers");
        }

        // Cap the hold time: a client that disappears must not pin a thread
        // for minutes. 120s matches the MCP-side wait default.
        if (timeout_ms < 0) timeout_ms = 0;
        if (timeout_ms > 120000) timeout_ms = 120000;

        const auto raw_types = req.get_query("types");
        if (!raw_types.empty()) {
            size_t start = 0;
            while (start <= raw_types.size()) {
                const size_t comma = raw_types.find(',', start);
                const auto token = raw_types.substr(
                    start, comma == std::string::npos ? std::string::npos : comma - start);
                if (!token.empty()) types.push_back(token);
                if (comma == std::string::npos) break;
                start = comma + 1;
            }
        }

        return s_http_response::ok(event_log::wait_since(since_seq, timeout_ms, types, max_events));
    });

    // POST /api/command/init_script - Set debuggee init script
    router.post("/api/command/init_script", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("file")) {
            return s_http_response::bad_request("Missing 'file' field");
        }

        auto file = body["file"].get<std::string>();
        DbgFunctions()->DbgSetDebuggeeInitScript(file.c_str());

        return s_http_response::ok({
            {"file", file},
            {"message", "Init script set"}
        });
    });

    // GET /api/command/init_script - Get debuggee init script
    router.get("/api/command/init_script", [](const s_http_request&) -> s_http_response {
        auto* script = DbgFunctions()->DbgGetDebuggeeInitScript();

        return s_http_response::ok({
            {"file", script ? std::string(script) : ""}
        });
    });

    // GET /api/command/hash - Get database hash
    router.get("/api/command/hash", [](const s_http_request&) -> s_http_response {
        auto hash = DbgFunctions()->DbGetHash();

        return s_http_response::ok({
            {"hash", format_utils::format_address(hash)}
        });
    });

    // POST /api/command/script - Execute batch of commands
    router.post("/api/command/script", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("commands")) {
            return s_http_response::bad_request("Missing 'commands' field (array of strings)");
        }

        auto commands = body["commands"];
        if (!commands.is_array()) {
            return s_http_response::bad_request("'commands' must be an array of strings");
        }

        auto results = nlohmann::json::array();
        int succeeded = 0;
        int failed = 0;

        for (const auto& cmd : commands) {
            auto cmd_str = cmd.get<std::string>();
            auto success = bridge.exec_command(cmd_str);

            results.push_back({
                {"command", cmd_str},
                {"success", success}
            });

            if (success) ++succeeded;
            else ++failed;
        }

        return s_http_response::ok({
            {"results",   results},
            {"total",     commands.size()},
            {"succeeded", succeeded},
            {"failed",    failed}
        });
    });
}

} // namespace handlers
