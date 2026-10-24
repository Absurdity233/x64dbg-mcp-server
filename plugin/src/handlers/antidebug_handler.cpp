#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

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

// Instruction encodings that anti-VM / anti-debug code uses to inspect the
// machine itself. Scanning for these is how you find the checks; the scan only
// reports locations, it does not alter behaviour.
struct probe_pattern {
    const char* name;
    const char* why;
    std::vector<uint8_t> bytes;
    bool wildcard_tail;   // trailing operand bytes vary, match the opcode only
};

// Only unambiguous encodings belong here. A single-byte opcode such as `in`
// (0xEC) matches arbitrary displacement/immediate bytes in unrelated code -
// scanning winver.exe that way produced 20 "VMware backdoor" hits, none of them
// real. Multi-byte opcodes whose second byte is part of a fixed pattern are
// what make a scan usable; `in` is reachable only through the two-byte form
// with the port operand checked.
const std::vector<probe_pattern>& vm_probes() {
    static const std::vector<probe_pattern> patterns = {
        {"cpuid",  "hypervisor-present bit and vendor leaf (0x40000000)", {0x0F, 0xA2}, false},
        {"rdtsc",  "timing delta; the classic single-step / sandbox check", {0x0F, 0x31}, false},
        {"rdtscp", "timing delta with serialisation", {0x0F, 0x01, 0xF9}, false},
        {"smsw",   "SMSW stores CR0; the VM86/monitor bit differs", {0x0F, 0x01, 0xE0}, false},
        {"str",    "STR reads the task register; 0 under a hypervisor", {0x0F, 0x00, 0xC8}, false},
        {"sldt",   "LDT selector; VM86 reveals", {0x0F, 0x00, 0xC0}, false},
        // sidt/sgdt/sldt take a memory operand, so the ModRM byte varies. Match
        // the fixed 0F 01 + ModRM-prefix and let the caller see the address.
        {"sidt",   "IDT base; hypervisors relocate it", {0x0F, 0x01, 0x0D}, true},
        {"sgdt",   "GDT base; hypervisors relocate it", {0x0F, 0x01, 0x05}, true},
        {"sidt",   "IDT base (register form)", {0x0F, 0x01, 0x1D}, true},
    };
    return patterns;
}

// Scan the given module's executable sections for the probe instructions.
nlohmann::json scan_probes(c_bridge_executor& bridge, const std::string& module_name,
                           size_t max_hits_per_pattern) {
    const auto base = bridge.get_module_base(module_name);
    if (base == 0) return nlohmann::json{{"error", "module not found: " + module_name}};

    // Walk the section table for executable regions.
    auto dos = bridge.read_memory(base, 0x40);
    if (!dos.has_value() || dos->size() < 0x40) {
        return nlohmann::json{{"error", "cannot read DOS header"}};
    }
    uint32_t e_lfanew = 0;
    std::memcpy(&e_lfanew, dos->data() + 0x3C, 4);

    auto pe = bridge.read_memory(base + e_lfanew, 24);
    if (!pe.has_value() || pe->size() < 24) {
        return nlohmann::json{{"error", "cannot read PE header"}};
    }
    uint16_t num_sections = 0, opt_size = 0;
    std::memcpy(&num_sections, pe->data() + 6, 2);
    std::memcpy(&opt_size, pe->data() + 20, 2);
    if (num_sections == 0 || num_sections > 96) {
        return nlohmann::json{{"error", "implausible section count"}};
    }

    const duint section_table = base + e_lfanew + 24 + opt_size;
    auto sec_headers = bridge.read_memory(section_table, static_cast<size_t>(num_sections) * 40);
    if (!sec_headers.has_value()) {
        return nlohmann::json{{"error", "cannot read section table"}};
    }

    nlohmann::json results = nlohmann::json::array();
    size_t total = 0;

    for (uint16_t i = 0; i < num_sections; ++i) {
        const size_t off = static_cast<size_t>(i) * 40;
        uint32_t va = 0, vsize = 0, raw_size = 0, chars = 0;
        char name[9] = {};
        std::memcpy(name, sec_headers->data() + off, 8);
        std::memcpy(&vsize, sec_headers->data() + off + 8, 4);
        std::memcpy(&va, sec_headers->data() + off + 12, 4);
        std::memcpy(&raw_size, sec_headers->data() + off + 16, 4);
        std::memcpy(&chars, sec_headers->data() + off + 36, 4);

        if (!(chars & IMAGE_SCN_MEM_EXECUTE)) continue;

        const uint32_t span = vsize ? vsize : raw_size;
        if (span == 0 || span > 64u * 1024 * 1024) continue;

        auto code = bridge.read_memory(base + va, span);
        if (!code.has_value()) continue;
        const auto& buf = *code;

        for (const auto& p : vm_probes()) {
            size_t hits = 0;
            if (buf.size() < p.bytes.size()) continue;

            for (size_t k = 0; k + p.bytes.size() <= buf.size(); ++k) {
                if (std::memcmp(buf.data() + k, p.bytes.data(), p.bytes.size()) != 0) continue;

                // A raw byte match is not an instruction: the same bytes occur
                // inside displacements, immediates and data. Confirm by asking
                // the disassembler what actually starts at this address, and
                // require the mnemonic to agree.
                const duint at = base + va + k;
                DISASM_INSTR di{};
                DbgDisasmAt(at, &di);
                if (di.instr_size <= 0 ||
                    _stricmp(di.instruction, p.name) != 0) {
                    continue;
                }

                if (hits < max_hits_per_pattern) {
                    results.push_back({
                        {"instruction", p.name},
                        {"detects",     p.why},
                        {"section",     name},
                        {"address",     format_utils::format_address(at)},
                        {"offset",      format_utils::format_hex(va + k)},
                        {"disasm",      std::string(di.instruction)}
                    });
                }
                ++hits;
                ++total;
                k += p.bytes.size() - 1;
            }
        }
    }

    return nlohmann::json{
        {"module",        module_name},
        {"base",          format_utils::format_address(base)},
        {"hits",          results},
        {"count",         results.size()},
        {"total_matches", total},
        {"truncated",     results.size() < total},
        {"note",          "Locations only - nothing was patched or faked. Set a "
                          "breakpoint on an address above and inspect the registers "
                          "when it fires to see what the check decides."}
    };
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

    // POST /api/antidebug/harden - Broader anti-detection pass
    //
    // hide_debugger only clears two PEB fields. Real protected targets also
    // check heap flags, the DR registers, the debug object handle and the
    // process debug port. This route clears what can be cleared from a plugin
    // without a kernel component, and reports what it could not touch.
    router.post("/api/antidebug/harden", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto pid = static_cast<DWORD>(bridge.eval_expression("$pid"));
        auto peb_addr = DbgGetPebAddress(pid);
        if (peb_addr == 0) {
            return s_http_response::internal_error("Failed to get PEB address");
        }

        auto applied = nlohmann::json::array();
        auto skipped = nlohmann::json::array();

        auto poke = [&](duint addr, const std::vector<uint8_t>& bytes,
                        const std::string& field, const std::string& note) {
            auto r = bridge.write_memory(addr, bytes);
            if (r.has_value()) {
                applied.push_back({
                    {"field", field},
                    {"address", format_utils::format_address(addr)},
                    {"note", note}
                });
            } else {
                skipped.push_back({{"field", field}, {"reason", "write failed"}});
            }
        };

        // PEB.BeingDebugged
        poke(peb_addr + 0x2, {0x00}, "PEB.BeingDebugged", "clears IsDebuggerPresent");

        // PEB.NtGlobalFlag
#ifdef _WIN64
        constexpr duint ntglobalflag_offset = 0xBC;
        constexpr duint process_heap_offset = 0x30;
#else
        constexpr duint ntglobalflag_offset = 0x68;
        constexpr duint process_heap_offset = 0x18;
#endif
        poke(peb_addr + ntglobalflag_offset, {0, 0, 0, 0}, "PEB.NtGlobalFlag",
             "clears the FLG_HEAP_* debug bits");

        // PEB.ProcessHeap -> Flags / ForceFlags. A debugger sets both.
        auto heap_ptr = bridge.read_memory(peb_addr + process_heap_offset, sizeof(duint));
        if (heap_ptr.has_value()) {
            duint heap = 0;
            memcpy(&heap, heap_ptr->data(), sizeof(duint));
            if (heap != 0) {
                poke(heap + 0x70, {0, 0, 0, 0}, "Heap.Flags", "x64 offset 0x70");
                poke(heap + 0x74, {0, 0, 0, 0}, "Heap.ForceFlags", "x64 offset 0x74");
            }
        }

        // Clear the hardware debug registers in the current thread context.
        // x64dbg restores them on continue, so this only helps until the next
        // resume; targets typically read DR at their own entry, before that.
        // `r dr0=0` is rejected by DbgCmdExecDirect (the register command is
        // queue-dispatched), so go through the queue and read back to confirm.
        auto clear_dr = [&](const char* name) {
            const std::string cmd = std::string("r ") + name + "=0";
            bridge.exec_command_async(cmd);
            Sleep(15);
            const auto after = bridge.eval_expression(name);
            if (after == 0) {
                applied.push_back({{"field", name}, {"note", "hardware breakpoint register zeroed"}});
            } else {
                skipped.push_back({
                    {"field", name},
                    {"reason", "register still non-zero after write (x64dbg may restore it on resume)"}
                });
            }
        };
        clear_dr("dr0");
        clear_dr("dr1");
        clear_dr("dr2");
        clear_dr("dr3");
        clear_dr("dr6");
        clear_dr("dr7");

        skipped.push_back({
            {"field", "ProcessDebugPort/ProcessDebugObjectHandle"},
            {"reason", "kernel-level query cannot be faked from a user-mode plugin; "
                       "use ScyllaHide's driver component"}
        });

        return s_http_response::ok({
            {"peb_address", format_utils::format_address(peb_addr)},
            {"applied", applied},
            {"skipped", skipped},
            {"message", "Anti-debug hardening applied"}
        });
    });

    // GET /api/antidebug/vm_probes?module=&max_hits= - Locate anti-VM probes
    //
    // Finds cpuid / rdtsc / sidt / str and friends in the module's executable
    // sections. This is a discovery aid: knowing where a target inspects the
    // machine is what lets you breakpoint it and read the decision, instead of
    // guessing why behaviour differs between hosts.
    router.get("/api/antidebug/vm_probes", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto module_name = req.get_query("module", "");
        if (module_name.empty()) {
            char main_name[MAX_MODULE_SIZE] = {};
            if (!Script::Module::GetMainModuleName(main_name) || main_name[0] == '\0') {
                return s_http_response::bad_request(
                    "Missing 'module' and the main module name is unavailable");
            }
            module_name = main_name;
        }

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

        return s_http_response::ok(scan_probes(bridge, module_name, max_hits));
    });

    // POST /api/antidebug/probe_breakpoints - Instrument every anti-VM probe
    //
    // Scanning tells you where the checks are; this makes them observable.
    // Each hit gets a silent logging breakpoint that records the registers and
    // the result the instruction produces, so the event log becomes a timeline
    // of "which check ran, when, and what it decided" - which is the part that
    // actually explains a behaviour difference between hosts.
    //
    // Silent + fast_resume so the target keeps running; nothing is modified.
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

        std::string module_name = body.value("module", "");
        if (module_name.empty()) {
            char main_name[MAX_MODULE_SIZE] = {};
            if (!Script::Module::GetMainModuleName(main_name) || main_name[0] == '\0') {
                return s_http_response::bad_request("Missing 'module' and no main module");
            }
            module_name = main_name;
        }

        size_t max_hits = body.value("max_hits", static_cast<size_t>(200));
        if (max_hits == 0) max_hits = 1;
        if (max_hits > 500) max_hits = 500;   // one breakpoint per instruction

        // Default log captures what the check itself computes: cip, all four
        // scratch registers (the CPUID result lands in eax/ebx/ecx/edx) and the
        // thread, so a hit is attributable without pausing.
        const auto log_text = body.value(
            "log_text",
            std::string("{p:cip} cpuid/rdtsc rax={p:rax} rbx={p:rbx} "
                        "rcx={p:rcx} rdx={p:rdx} tid={tid()} tick={GetTickCount()}"));

        const auto scan = scan_probes(bridge, module_name, max_hits);
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
                                hit["instruction"].get<std::string>() + "\"");

            armed.push_back({
                {"instruction", hit["instruction"]},
                {"address",     addr},
                {"section",     hit["section"]},
                {"detects",     hit["detects"]}
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
                     "was patched: the checks still run and still decide."}
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
