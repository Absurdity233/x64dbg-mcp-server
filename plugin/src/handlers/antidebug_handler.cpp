#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "util/antidebug_hard.h"
#include "util/anti_vm.h"
#include "util/host_artifacts.h"
#include "util/kernel_driver.h"
#include "util/ntdll_hook.h"
#include "util/probe_scan.h"
#include "util/time_hook.h"

#include <algorithm>
#include <cstring>
#include <vector>
#include <string>
#include <windows.h>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "_scriptapi_module.h"

namespace handlers {

namespace {

// Resolve the module the caller means, defaulting to the main module. Shared by
// every route that scans a module, so the "which module" answer is the same
// everywhere - an inconsistency there is what makes two scans disagree.
std::string resolve_module(c_bridge_executor& bridge, const std::string& requested,
                           std::string* error) {
    if (!requested.empty()) {
        if (bridge.get_module_base(requested) == 0) {
            *error = "module not found: " + requested;
        }
        return requested;
    }
    char main_name[MAX_MODULE_SIZE] = {};
    if (!Script::Module::GetMainModuleName(main_name) || main_name[0] == '\0') {
        *error = "Missing 'module' and the main module name is unavailable";
        return {};
    }
    return main_name;
}

// The ntdll stub set, parsed from the request.
//
// Delegates the class table and the per-function register conventions to
// ntdll_hook::install_defaults(), so this route and the default set used by
// harden(level=paranoid) cannot drift apart. A second copy of "which class number
// means what, and which register holds it" is exactly the kind of duplication that
// produces a hook which installs cleanly and never matches.
bool parse_hook_list(const nlohmann::json& body, std::vector<std::string>* functions) {
    if (body.contains("functions") && body["functions"].is_array()) {
        for (const auto& f : body["functions"]) functions->push_back(f.get<std::string>());
        return true;
    }
    // No list: the default set, which is the useful answer for "just hook the
    // obvious oracles".
    *functions = {"NtQueryInformationProcess", "NtQueryObject",
                  "NtQuerySystemInformation", "NtSetInformationThread"};
    return true;
}

} // namespace

void register_antidebug_routes(c_http_router& router) {
    // GET /api/antidebug/peb?pid= - Read PEB info
    router.get("/api/antidebug/peb", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto pid_str = req.get_query("pid", "");
        DWORD pid = 0;
        if (pid_str.empty()) {
            pid = static_cast<DWORD>(bridge.eval_expression("$pid"));
        } else {
            pid = static_cast<DWORD>(std::stoul(pid_str));
        }

        auto peb_addr = DbgGetPebAddress(pid);
        if (peb_addr == 0) {
            return s_http_response::not_found("Failed to get PEB address");
        }

        nlohmann::json data = {
            {"peb_address", format_utils::format_address(peb_addr)},
            {"pid", pid}
        };

        // Read BeingDebugged (offset 0x2 in PEB, 1 byte)
        auto being_debugged = bridge.read_memory(peb_addr + 0x2, 1);
        if (being_debugged.has_value()) {
            data["being_debugged"] = being_debugged.value()[0];
        }

        // Read NtGlobalFlag (offset 0x68 on x86, 0xBC on x64)
#ifdef _WIN64
        constexpr duint ntglobalflag_offset = 0xBC;
#else
        constexpr duint ntglobalflag_offset = 0x68;
#endif
        auto ntglobal = bridge.read_memory(peb_addr + ntglobalflag_offset, 4);
        if (ntglobal.has_value()) {
            DWORD flags = 0;
            memcpy(&flags, ntglobal.value().data(), 4);
            data["nt_global_flag"] = format_utils::format_address(flags);
            data["nt_global_flag_decimal"] = flags;
        }

        // Read ProcessHeap (offset 0x18 on x86, 0x30 on x64)
#ifdef _WIN64
        constexpr duint heap_offset = 0x30;
#else
        constexpr duint heap_offset = 0x18;
#endif
        auto heap_data = bridge.read_memory(peb_addr + heap_offset, sizeof(duint));
        if (heap_data.has_value()) {
            duint heap_addr = 0;
            memcpy(&heap_addr, heap_data.value().data(), sizeof(duint));
            data["process_heap"] = format_utils::format_address(heap_addr);
        }

        return s_http_response::ok(data);
    });

    // GET /api/antidebug/teb?tid= - Read TEB info
    router.get("/api/antidebug/teb", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto tid_str = req.get_query("tid", "");
        DWORD tid = 0;
        if (tid_str.empty()) {
            tid = static_cast<DWORD>(bridge.eval_expression("$tid"));
        } else {
            tid = static_cast<DWORD>(std::stoul(tid_str));
        }

        auto teb_addr = DbgGetTebAddress(tid);
        if (teb_addr == 0) {
            return s_http_response::not_found("Failed to get TEB address");
        }

        nlohmann::json data = {
            {"teb_address", format_utils::format_address(teb_addr)},
            {"tid", tid}
        };

        // Read SEH chain pointer (offset 0x0 in TEB)
        auto seh = bridge.read_memory(teb_addr, sizeof(duint));
        if (seh.has_value()) {
            duint seh_addr = 0;
            memcpy(&seh_addr, seh.value().data(), sizeof(duint));
            data["seh_frame"] = format_utils::format_address(seh_addr);
        }

        // Read stack base (offset 0x4/0x8) and limit (offset 0x8/0x10)
#ifdef _WIN64
        constexpr duint stack_base_offset = 0x8;
        constexpr duint stack_limit_offset = 0x10;
        constexpr duint peb_offset = 0x60;
#else
        constexpr duint stack_base_offset = 0x4;
        constexpr duint stack_limit_offset = 0x8;
        constexpr duint peb_offset = 0x30;
#endif

        auto stack_base = bridge.read_memory(teb_addr + stack_base_offset, sizeof(duint));
        if (stack_base.has_value()) {
            duint val = 0;
            memcpy(&val, stack_base.value().data(), sizeof(duint));
            data["stack_base"] = format_utils::format_address(val);
        }

        auto stack_limit = bridge.read_memory(teb_addr + stack_limit_offset, sizeof(duint));
        if (stack_limit.has_value()) {
            duint val = 0;
            memcpy(&val, stack_limit.value().data(), sizeof(duint));
            data["stack_limit"] = format_utils::format_address(val);
        }

        auto peb = bridge.read_memory(teb_addr + peb_offset, sizeof(duint));
        if (peb.has_value()) {
            duint val = 0;
            memcpy(&val, peb.value().data(), sizeof(duint));
            data["peb_address"] = format_utils::format_address(val);
        }

        return s_http_response::ok(data);
    });

    // POST /api/antidebug/hide_debugger - Hide debugger from PEB
    router.post("/api/antidebug/hide_debugger", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto pid = static_cast<DWORD>(bridge.eval_expression("$pid"));
        auto peb_addr = DbgGetPebAddress(pid);
        if (peb_addr == 0) {
            return s_http_response::internal_error("Failed to get PEB address");
        }

        nlohmann::json changes = nlohmann::json::array();
        nlohmann::json failed = nlohmann::json::array();

        // Write, then read back. A successful DbgMemWrite only means the write
        // call returned; the target's own code (or a protection layer) can put
        // the value straight back, and reporting "hidden" in that case would be
        // a lie the caller then relies on.
        auto poke_verified = [&](duint addr, size_t size, const std::string& field) {
            std::vector<uint8_t> zeros(size, 0);
            const auto before = bridge.read_memory(addr, size);
            if (!before.has_value()) {
                failed.push_back({{"field", field}, {"reason", "read failed before write"}});
                return;
            }

            const auto w = bridge.write_memory(addr, zeros);
            if (!w.has_value()) {
                failed.push_back({{"field", field}, {"reason", w.error()}});
                return;
            }

            const auto after = bridge.read_memory(addr, size);
            if (!after.has_value()) {
                failed.push_back({{"field", field}, {"reason", "read failed after write"}});
                return;
            }

            const bool all_zero = std::all_of(after->begin(), after->end(),
                                              [](uint8_t b) { return b == 0; });
            if (all_zero) {
                changes.push_back({
                    {"field", field},
                    {"address", format_utils::format_address(addr)},
                    {"was", format_utils::format_hex(
                        static_cast<duint>(before->size() == 1 ? (*before)[0]
                                             : before->size() == 4
                                                 ? *reinterpret_cast<const uint32_t*>(before->data())
                                                 : 0))},
                    {"value", 0},
                    {"verified", true}
                });
            } else {
                failed.push_back({
                    {"field", field},
                    {"address", format_utils::format_address(addr)},
                    {"reason", "value came back non-zero after the write "
                               "(another thread or a protection layer restored it)"}
                });
            }
        };

        poke_verified(peb_addr + 0x2, 1, "BeingDebugged");

#ifdef _WIN64
        constexpr duint ntglobalflag_offset = 0xBC;
#else
        constexpr duint ntglobalflag_offset = 0x68;
#endif
        poke_verified(peb_addr + ntglobalflag_offset, 4, "NtGlobalFlag");

        const bool all_ok = failed.empty();

        return s_http_response::ok({
            {"peb_address", format_utils::format_address(peb_addr)},
            {"changes", changes},
            {"failed", failed},
            {"success", all_ok},
            {"message", all_ok
                ? "Debugger hidden from PEB checks (verified by read-back)"
                : "Some PEB fields could not be cleared - see 'failed'"}
        });
    });

    // POST /api/antidebug/harden - Anti-detection pass
    //
    // Body: { "level": "basic"|"deep"|"paranoid", "threads": bool,
    //         "hooks": ["NtQueryInformationProcess"], "guard": bool }
    //
    // Three levels rather than one, because they cost very different amounts and
    // each covers a different class of check:
    //   basic     - two PEB fields; defeats IsDebuggerPresent and nothing else
    //   deep      - + heap flags + per-thread sweep + DR registers
    //   paranoid  - + ntdll stubs for ProcessDebugPort/ObjectHandle/Flags, and
    //               optionally the kernel component
    // See util/antidebug_hard.h for why each of those is not covered by the
    // level below it.
    router.post("/api/antidebug/harden", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) body = nlohmann::json::object();

        const auto level_str = body.value("level", std::string("deep"));
        const auto lvl = antidebug_hard::parse_level(level_str);

        std::vector<std::string> hook_names;
        if (body.contains("hooks") && body["hooks"].is_array()) {
            for (const auto& h : body["hooks"]) hook_names.push_back(h.get<std::string>());
        }

        // "threads" defaults to true at deep and above: a per-thread sweep is
        // the whole reason that level exists.
        const bool all_threads = body.value("threads", lvl != antidebug_hard::level::basic);

        auto data = antidebug_hard::apply(bridge, lvl, all_threads, hook_names);

        // The background guard is opt-in. It writes the PEB on every pause,
        // which changes the target's memory underneath a caller who is trying to
        // watch it change - so it must be asked for, not assumed.
        if (body.value("guard", false)) {
            antidebug_hard::start_guard(lvl);
            data["guard"] = {{"running", antidebug_hard::guard_active()},
                             {"note", "re-clears the PEB on every pause; stop with "
                                      "harden_guard_stop"}};
        }

        // Say what the kernel component would add and whether it is there. A
        // caller reading "harden succeeded" should not conclude the process is
        // invisible to a driver.
        data["kernel_driver"] = kernel_driver::describe();
        return s_http_response::ok(data);
    });

    // POST /api/antidebug/guard_stop - Stop the background PEB guard
    router.post("/api/antidebug/guard_stop", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok(antidebug_hard::stop_guard());
    });

    // GET /api/antidebug/vm_probes?module=&max_hits= - Locate anti-VM probes
    //
    // Discovery only. The table and the confirmation rule live in
    // util/probe_scan.cpp so this route and the anti_vm stub engine can never
    // disagree about what a "probe" is.
    router.get("/api/antidebug/vm_probes", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        std::string error;
        const auto module_name = resolve_module(bridge, req.get_query("module", ""), &error);
        if (module_name.empty()) return s_http_response::bad_request(error);

        size_t max_hits = 200;
        const auto raw_max = req.get_query("max_hits", "");
        if (!raw_max.empty()) {
            try {
                max_hits = static_cast<size_t>(std::stoul(raw_max));
            } catch (...) {
                return s_http_response::bad_request("'max_hits' must be a number");
            }
            if (max_hits == 0) max_hits = 1;
            if (max_hits > 2000) max_hits = 2000;
        }

        return s_http_response::ok(probe_scan::scan(bridge, module_name, max_hits));
    });

    // POST /api/antidebug/probe_breakpoints - Instrument every anti-VM probe
    //
    // Scanning tells you where the checks are; this makes them observable. Each
    // hit gets a silent logging breakpoint that records the registers and the
    // result the instruction produces, so the event log becomes a timeline of
    // "which check ran, when, and what it decided" - which is the part that
    // actually explains a behaviour difference between hosts.
    //
    // Body: { "module": "...", "max_hits": 200, "log_text": "...",
    //         "resume": true }
    router.post("/api/antidebug/probe_breakpoints", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) body = nlohmann::json::object();

        std::string error;
        const auto module_name = resolve_module(bridge, body.value("module", std::string("")), &error);
        if (module_name.empty()) return s_http_response::bad_request(error);

        size_t max_hits = body.value("max_hits", static_cast<size_t>(200));
        if (max_hits == 0) max_hits = 1;
        if (max_hits > 500) max_hits = 500;   // one breakpoint per instruction

        // Default log captures what the check itself computes: cip, all four
        // scratch registers (the CPUID result lands in eax/ebx/ecx/edx) and the
        // thread, so a hit is attributable without pausing.
        const auto log_text = body.value(
            "log_text",
            std::string("{p:cip} probe rax={p:rax} rbx={p:rbx} "
                        "rcx={p:rcx} rdx={p:rdx} tid={tid()} tick={GetTickCount()}"));

        const auto scan = probe_scan::scan(bridge, module_name, max_hits);
        if (scan.contains("error")) {
            return s_http_response::internal_error(scan["error"].get<std::string>());
        }

        nlohmann::json armed = nlohmann::json::array();
        nlohmann::json failed = nlohmann::json::array();

        for (const auto& hit : scan["hits"]) {
            const auto addr = hit["address"].get<std::string>();

            // Software breakpoint: the probe instructions are real code, not
            // guarded memory, so an 0xCC is appropriate here - unlike the
            // memory breakpoints that fault on a self-modifying unpacker.
            if (!bridge.exec_command("bp " + addr)) {
                failed.push_back({{"address", addr}, {"reason", "bp rejected"}});
                continue;
            }

            bridge.exec_command("SetBreakpointSilent " + addr + ", 1");
            bridge.exec_command("SetBreakpointLog " + addr + ", \"" + log_text + "\"");
            // Log and continue: the point is a timeline, not a stop.
            bridge.exec_command("SetBreakpointFastResume " + addr + ", 1");
            // Name it so the event-log entry identifies the instruction.
            bridge.exec_command("SetBreakpointName " + addr + ", \"vmprobe:" +
                                hit["probe"].get<std::string>() + "\"");

            armed.push_back({
                {"probe",   hit["probe"]},
                {"address", addr},
                {"section", hit["section"]},
                {"detects", hit["detects"]}
            });
        }

        // Optionally start the target so the probes actually fire.
        const bool resume = body.value("resume", true);
        if (resume && !armed.empty() && !bridge.is_running()) {
            bridge.exec_command_async("run");
        }

        nlohmann::json out = {
            {"module",   module_name},
            {"armed",    armed},
            {"count",    armed.size()},
            {"failed",   failed},
            {"resumed",  resume && !armed.empty()},
            {"log_text", log_text},
            {"note", "Each hit is written to the event log (x64dbg_command "
                     "get_events / wait_for_event, type 'breakpoint'). Nothing "
                     "was patched: the checks still run and still decide. To change "
                     "what they decide, use anti_vm."}
        };

        // fast_resume does not take effect for every instruction: measured on
        // 2026.05.27, an rdtscp breakpoint with silent=1 and fast_resume=1 still
        // paused the target on all 10 hits, while cpuid breakpoints resumed.
        // Say so rather than letting the caller discover the target stopped.
        if (!armed.empty()) {
            out["warning"] =
                "Some probes may still pause the target (fast_resume is not honoured "
                "for every instruction). If it stops, check trace/debug state and "
                "run again; hits already logged are kept.";
        }
        return s_http_response::ok(out);
    });

    // POST /api/antidebug/anti_vm - Make the checks return "physical machine"
    //
    // This is the part that actually changes an answer. A breakpoint cannot:
    // it fires before the instruction, so whatever it writes is overwritten by
    // the cpuid/rdtsc it was watching. The stub runs the real instruction and
    // edits the result - see util/code_stub.h.
    //
    // Body: { "module": "...", "max_hits": 200,
    //         "arms": ["cpuid","rdtsc","vmware_backdoor"], "restore": false }
    router.post("/api/antidebug/anti_vm", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) body = nlohmann::json::object();

        if (body.value("restore", false)) {
            auto result = anti_vm::disarm(bridge);
            result["remaining"] = anti_vm::list();
            return s_http_response::ok(result);
        }

        std::string error;
        const auto module_name = resolve_module(bridge, body.value("module", std::string("")), &error);
        if (module_name.empty()) return s_http_response::bad_request(error);

        std::vector<std::string> probes;
        if (body.contains("arms") && body["arms"].is_array()) {
            for (const auto& a : body["arms"]) probes.push_back(a.get<std::string>());
        }

        size_t max_hits = body.value("max_hits", static_cast<size_t>(200));
        if (max_hits == 0) max_hits = 1;
        if (max_hits > 500) max_hits = 500;

        auto result = anti_vm::arm(bridge, module_name, probes, max_hits);
        result["armed_total"] = anti_vm::list()["count"];
        return s_http_response::ok(result);
    });

    // GET /api/antidebug/anti_vm/list - What is currently stubbed
    router.get("/api/antidebug/anti_vm/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok(anti_vm::list());
    });

    // POST /api/antidebug/hook_ntdll - Stub the Nt* oracles directly
    //
    // Body: { "functions": ["NtQueryInformationProcess"], "dry_run": bool }
    // Caller-facing version of what harden(level=paranoid) installs, for when a
    // specific check has to be neutralised in isolation.
    router.post("/api/antidebug/hook_ntdll", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) body = nlohmann::json::object();

        if (body.value("restore", false)) {
            auto result = ntdll_hook::restore();
            result["remaining"] = ntdll_hook::list();
            return s_http_response::ok(result);
        }

        std::vector<std::string> functions;
        parse_hook_list(body, &functions);

        nlohmann::json out = ntdll_hook::install_defaults(functions,
                                                          body.value("dry_run", false));
        out["active"] = ntdll_hook::list();
        return s_http_response::ok(out);
    });

    // POST /api/antidebug/timers - Neutralise the API-level timing side channels
    //
    // Body: { "timers": ["qpc","tick64","tick32"], "synthetic_step": bool,
    //         "restore": bool }
    //
    // RDTSC is handled by anti_vm as an instruction stub. The API timers are a
    // different shape: QueryPerformanceCounter writes through a pointer, so the stub
    // writes memory rather than registers, and freezing the counter makes every
    // measured delta zero - the same answer a bare-metal machine gives.
    router.post("/api/antidebug/timers", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) body = nlohmann::json::object();

        if (body.value("restore", false)) {
            auto result = time_hook::disarm();
            result["remaining"] = time_hook::list();
            return s_http_response::ok(result);
        }

        // Default: the ones a check actually reaches for. QPC first because it is
        // the calibrated clock, then the tick counters.
        std::vector<std::string> names;
        if (body.contains("timers") && body["timers"].is_array()) {
            for (const auto& t : body["timers"]) names.push_back(t.get<std::string>());
        } else {
            names = {"qpc", "tick64", "tick32"};
        }

        std::vector<time_hook::timer> timers;
        nlohmann::json unknown = nlohmann::json::array();
        for (const auto& n : names) {
            if (n == "qpc")         timers.push_back(time_hook::timer::qpc);
            else if (n == "tick64") timers.push_back(time_hook::timer::tick64);
            else if (n == "tick32") timers.push_back(time_hook::timer::tick32);
            else if (n == "qpc_freq") timers.push_back(time_hook::timer::qpc_freq);
            else unknown.push_back({{"timer", n},
                                    {"reason", "unknown; supported: qpc, tick64, tick32, qpc_freq"}});
        }

        time_hook::options opt{};
        opt.synthetic_step = body.value("synthetic_step", false);

        auto out = time_hook::arm(timers, opt);
        if (!unknown.empty()) out["unsupported"] = unknown;
        out["active"] = time_hook::list();
        return s_http_response::ok(out);
    });

    // GET /api/antidebug/timers/list - Which timers are currently stubbed
    router.get("/api/antidebug/timers/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok(time_hook::list());
    });

    // GET /api/antidebug/artifacts - What a VM check sees on this host
    //
    // Read-only survey. The point is to answer "which check is firing" with
    // evidence instead of a guess, so the fix can be applied to the check that
    // exists rather than to all of them.
    router.get("/api/antidebug/artifacts", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok(host_artifacts::survey());
    });

    // ---- kernel component ------------------------------------------------
    //
    // These four routes are the only ones that need the driver. They are
    // separate from harden because the driver is optional and its failure modes
    // (not loaded, access denied, offset unresolved) are different from a PEB
    // write that did not stick.

    router.get("/api/antidebug/kernel/status", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok(kernel_driver::status());
    });

    router.post("/api/antidebug/kernel/attach", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) body = nlohmann::json::object();

        unsigned long pid = 0;
        if (body.contains("pid")) {
            if (body["pid"].is_number()) {
                pid = body["pid"].get<unsigned long>();
            } else {
                const auto s = body["pid"].get<std::string>();
                if (!s.empty()) {
                    try { pid = std::stoul(s, nullptr, 0); }
                    catch (...) { return s_http_response::bad_request("'pid' is not a number"); }
                }
            }
        }

        auto result = kernel_driver::attach(pid);
        if (!result.value("ok", false)) {
            return s_http_response::conflict(result.value("error", std::string("attach failed")));
        }
        return s_http_response::ok(result);
    });

    router.post("/api/antidebug/kernel/detach", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok(kernel_driver::detach());
    });

    // POST /api/antidebug/kernel/apply - Clear EPROCESS fields
    //
    // Body: { "mask": 7, "debugport_offset": 0, "flags_offset": 0,
    //         "cross_session_offset": 0 }
    // Offsets are overrides for a kernel build the driver could not resolve;
    // 0 leaves the driver's own resolution in place.
    router.post("/api/antidebug/kernel/apply", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) body = nlohmann::json::object();

        // Default: the three fields a user-mode target can observe. KDPRINT is
        // left out because it needs an offset the driver may not have resolved,
        // and asking for a bit that cannot be applied turns a clean report into
        // a partial one.
        uint64_t mask = kernel_driver::default_mask;
        if (body.contains("mask")) {
            if (body["mask"].is_number_unsigned() || body["mask"].is_number_integer()) {
                mask = body["mask"].get<uint64_t>();
            } else if (body["mask"].is_string()) {
                try { mask = std::stoull(body["mask"].get<std::string>(), nullptr, 0); }
                catch (...) { return s_http_response::bad_request("'mask' is not a number"); }
            }
        }
        if (mask == 0) return s_http_response::bad_request("'mask' selects nothing");

        const auto dp = body.value("debugport_offset", 0u);
        const auto fo = body.value("flags_offset", 0u);
        const auto cs = body.value("cross_session_offset", 0u);

        auto result = kernel_driver::apply(mask, dp, fo, cs);
        if (!result.value("ok", false) && !result.contains("applied_mask")) {
            return s_http_response::conflict(result.value("error", std::string("apply failed")));
        }
        return s_http_response::ok(result);
    });

    // GET /api/antidebug/kernel/query - What the driver has applied
    router.get("/api/antidebug/kernel/query", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok(kernel_driver::query());
    });

    // GET /api/antidebug/dep_status - DEP enabled status
    router.get("/api/antidebug/dep_status", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto dep_enabled = DbgFunctions()->IsDepEnabled();

        return s_http_response::ok({
            {"dep_enabled", dep_enabled}
        });
    });
}

} // namespace handlers
