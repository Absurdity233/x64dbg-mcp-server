#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>

#include "bridgelist.h"
#include "_scriptapi_function.h"

namespace handlers {

void register_functions_routes(c_http_router& router) {
    // GET /api/functions/list?module=<name>&offset=<n>&limit=<n>
    //
    // The function list can be large (tens of thousands of entries for a big
    // module), so it is paged. x64dbg's Script::Function::GetList returns the
    // whole list at once; we slice it here rather than shipping everything to
    // the model in one response.
    router.get("/api/functions/list", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        size_t offset = 0;
        size_t limit = 500;
        try {
            if (!req.get_query("offset").empty()) offset = std::stoull(req.get_query("offset"));
            if (!req.get_query("limit").empty()) limit = std::stoull(req.get_query("limit"));
        } catch (...) {
            return s_http_response::bad_request("'offset'/'limit' must be non-negative integers");
        }
        if (limit == 0 || limit > 5000) limit = 500;

        const auto module_filter = req.get_query("module");

        BridgeList<Script::Function::FunctionInfo> list;
        if (!Script::Function::GetList(&list)) {
            return s_http_response::ok({
                {"functions", nlohmann::json::array()},
                {"total", 0}, {"offset", offset}, {"returned", 0}
            });
        }

        auto functions = nlohmann::json::array();
        size_t matched = 0;
        std::string cached_mod;
        duint cached_base = 0;

        for (int i = 0; i < list.Count(); ++i) {
            const auto& fn = list[i];
            if (!module_filter.empty() && module_filter != fn.mod) continue;
            if (matched++ < offset) continue;
            if (functions.size() >= limit) continue;

            // FunctionInfo carries RVAs; resolve the module base once per module
            // so the caller gets addresses it can use directly.
            if (cached_mod != fn.mod) {
                cached_mod = fn.mod;
                cached_base = bridge.get_module_base(fn.mod);
            }
            const duint base = cached_base ? cached_base : 0;

            functions.push_back({
                {"module",            fn.mod},
                {"base",              format_utils::format_address(base)},
                {"start",             format_utils::format_address(base + fn.rvaStart)},
                {"end",               format_utils::format_address(base + fn.rvaEnd)},
                {"rva_start",         format_utils::format_address(fn.rvaStart)},
                {"size",              fn.rvaEnd > fn.rvaStart ? fn.rvaEnd - fn.rvaStart : 0},
                {"manual",            fn.manual},
                {"instruction_count", fn.instructioncount}
            });
        }

        return s_http_response::ok({
            {"functions", functions},
            {"total",     matched},
            {"offset",    offset},
            {"returned",  functions.size()},
            {"has_more",  matched > offset + functions.size()}
        });
    });
}

} // namespace handlers
