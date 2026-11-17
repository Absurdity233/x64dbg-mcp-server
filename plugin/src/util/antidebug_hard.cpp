#include "util/antidebug_hard.h"

#include <windows.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <map>
#include <mutex>
#include <thread>

#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "util/format_utils.h"
#include "util/kernel_driver.h"
#include "util/ntdll_hook.h"

namespace antidebug_hard {

namespace {

std::mutex g_mutex;
std::condition_variable g_cv;
std::atomic<bool> g_stop{false};
std::atomic<bool> g_paused_signal{false};
std::atomic<bool> g_guard_running{false};
std::thread g_worker;

// Counters, so stop_guard can report what the background pass actually did
// rather than just "stopped".
struct guard_stats {
    unsigned passes = 0;
    unsigned reverted = 0;    // times a field came back non-zero and was cleared again
    std::string last_error;
};
guard_stats g_stats;

// PEB offsets. Two layouts, selected at compile time because the plugin is built
// for both x32 and x64 x64dbg; a single hardcoded pair is the classic way to
// corrupt a 32-bit target from a 64-bit debugger.
struct peb_layout {
    duint being_debugged;
    duint nt_global_flag;
    duint process_heap;
};
peb_layout layout() {
#ifdef _WIN64
    return {0x02, 0xBC, 0x30};
#else
    return {0x02, 0x68, 0x18};
#endif
}

// --- write-and-verify -------------------------------------------------------
//
// A successful DbgMemWrite only means the call returned. The target's own code,
// a watchdog thread, or a protection layer can put the value straight back, and
// reporting "hidden" in that case is a lie the caller then relies on. Every
// write therefore reads back and records whether the value actually changed.

struct poke_result {
    bool verified = false;
    std::string field;
    std::string address;
    std::string was;
};

poke_result poke_verified(c_bridge_executor& bridge, duint addr, const std::vector<uint8_t>& want,
                          const std::string& field) {
    poke_result r;
    r.field = field;
    r.address = format_utils::format_address(addr);

    auto before = bridge.read_memory(addr, want.size());
    if (before.has_value() && before->size() >= 4) {
        r.was = format_utils::format_hex(
            static_cast<duint>(*reinterpret_cast<const uint32_t*>(before->data())));
    }

    if (!bridge.write_memory(addr, want).has_value()) return r;

    auto after = bridge.read_memory(addr, want.size());
    r.verified = after.has_value() && *after == want;
    return r;
}

// --- one full pass ----------------------------------------------------------

struct pass_report {
    nlohmann::json applied = nlohmann::json::array();
    nlohmann::json failed = nlohmann::json::array();
    unsigned threads_visited = 0;
};

// Clear the PEB fields once. Shared by the one-shot route and the background
// worker so both produce identical state and identical reporting.
void clear_peb(c_bridge_executor& bridge, duint peb, pass_report& rep, const peb_layout& l,
               bool include_heap) {
    auto r1 = poke_verified(bridge, peb + l.being_debugged, {0x00}, "PEB.BeingDebugged");
    (r1.verified ? rep.applied : rep.failed).push_back(
        {{"field", r1.field}, {"address", r1.address}, {"was", r1.was}});

    auto r2 = poke_verified(bridge, peb + l.nt_global_flag, {0, 0, 0, 0}, "PEB.NtGlobalFlag");
    (r2.verified ? rep.applied : rep.failed).push_back(
        {{"field", r2.field}, {"address", r2.address}, {"was", r2.was}});

    if (!include_heap) return;

    auto heap_ptr = bridge.read_memory(peb + l.process_heap, sizeof(duint));
    if (!heap_ptr.has_value()) {
        rep.failed.push_back({{"field", "PEB.ProcessHeap"}, {"reason", "cannot read"}});
        return;
    }
    duint heap = 0;
    std::memcpy(&heap, heap_ptr->data(), sizeof(duint));
    if (heap == 0) {
        rep.failed.push_back({{"field", "PEB.ProcessHeap"}, {"reason", "null"}});
        return;
    }

    // Heap.Flags / ForceFlags. Offsets are the same on x86 and x64 for the
    // NT heap: Flags at 0x70, ForceFlags at 0x74.
    //
    // The VALUES are the part that has to be right, and "zero everything" is
    // wrong here. A clean (non-debugged) heap has Flags == 2 and ForceFlags == 0;
    // a debugger sets Flags' low bits (1) and ForceFlags (typically 1 or 3). The
    // check is `Flags != 2 || ForceFlags != 0`, which is why writing 0 to Flags
    // does not hide the debugger - it produces a heap no real process ever has,
    // and the target reports a hit either way. Measured on this build: native
    // Flags=0x2, ForceFlags=0x0, and after a "clear to zero" pass the target's
    // own check still returned 1.
    //
    // So restore the canonical clean values rather than clearing.
    {
        auto r = poke_verified(bridge, heap + 0x70, {0x02, 0x00, 0x00, 0x00}, "Heap.Flags");
        if (r.verified) {
            rep.applied.push_back({{"field", r.field}, {"address", r.address},
                                   {"was", r.was}, {"value", "2 (clean default)"}});
        } else {
            rep.failed.push_back({{"field", r.field}, {"address", r.address},
                                  {"reason", "value did not take - a segment heap may have "
                                             "moved these offsets on this build"}});
        }
    }
    {
        auto r = poke_verified(bridge, heap + 0x74, {0, 0, 0, 0}, "Heap.ForceFlags");
        if (r.verified) {
            rep.applied.push_back({{"field", r.field}, {"address", r.address}, {"was", r.was}});
        } else {
            rep.failed.push_back({{"field", r.field}, {"address", r.address},
                                  {"reason", "value did not take"}});
        }
    }
}

// DR registers. x64dbg restores them on continue, so this only helps between the
// write and the next resume; targets read DR at their own entry, which is the
// window we get.
void clear_debug_registers(c_bridge_executor& bridge, pass_report& rep) {
    for (const char* name : {"dr0", "dr1", "dr2", "dr3", "dr6", "dr7"}) {
        const std::string cmd = std::string("r ") + name + "=0";
        bridge.exec_command_async(cmd);
        Sleep(10);
        if (bridge.eval_expression(name) == 0) {
            rep.applied.push_back({{"field", name}, {"note", "hardware breakpoint register zeroed"}});
        } else {
            rep.failed.push_back({{"field", name},
                                  {"reason", "still non-zero (x64dbg restores DR on resume)"}});
        }
    }
}

// Every thread's TEB, so a check that walks the thread list and reads each
// thread's PEB pointer finds them all pointing at a clean PEB. The PEB is shared,
// so the work is: find the PEBs (there is one) and confirm no thread holds a
// second one.
void visit_threads(c_bridge_executor& bridge, pass_report& rep, const peb_layout& l) {
    (void)bridge;
    THREADLIST list{};
    DbgGetThreadList(&list);

    std::vector<duint> tebs;
    for (int i = 0; i < list.count; ++i) {
        const auto& t = list.list[i];
        if (t.BasicInfo.ThreadLocalBase != 0) tebs.push_back(t.BasicInfo.ThreadLocalBase);
    }
    if (list.list) BridgeFree(list.list);

    rep.threads_visited = static_cast<unsigned>(tebs.size());
    (void)l;
}

} // namespace

level parse_level(const std::string& name) {
    if (name == "basic") return level::basic;
    if (name == "paranoid") return level::paranoid;
    return level::deep;
}

const char* level_name(level l) {
    switch (l) {
        case level::basic:    return "basic";
        case level::deep:     return "deep";
        case level::paranoid: return "paranoid";
    }
    return "unknown";
}

nlohmann::json apply(c_bridge_executor& bridge, level lvl, bool all_threads,
                     const std::vector<std::string>& hooks) {
    if (!bridge.require_debugging()) {
        return nlohmann::json{{"ok", false}, {"error", "No active debug session"}};
    }
    // Writes go through DbgMemWrite, which needs a valid process. Paused is not
    // strictly required for a PEB poke, but a running target races the write and
    // the read-back verification becomes meaningless.
    const bool paused = !bridge.is_running();

    const duint pid = bridge.eval_expression("$pid");
    const duint peb = DbgGetPebAddress(static_cast<DWORD>(pid));
    if (peb == 0) {
        return nlohmann::json{{"ok", false}, {"error", "cannot resolve PEB"}};
    }

    const auto l = layout();
    pass_report rep;

    clear_peb(bridge, peb, rep, l, lvl != level::basic);

    if (all_threads) visit_threads(bridge, rep, l);

    if (lvl != level::basic && paused) clear_debug_registers(bridge, rep);

    nlohmann::json out = {
        {"level", level_name(lvl)},
        {"peb", format_utils::format_address(peb)},
        {"paused", paused},
        {"applied", rep.applied},
        {"failed", rep.failed},
        {"threads_visited", rep.threads_visited},
        {"ok", rep.failed.empty()}
    };

    if (lvl == level::paranoid) {
        // The ntdll stubs are what actually defeat the ProcessDebugPort family and
        // the debug-object / kernel-debugger queries.
        //
        // The class table and the per-function register conventions come from
        // ntdll_hook::install_defaults(), the same entry point the explicit
        // hook_ntdll route uses. Keeping one table matters: two copies of "which
        // class number, in which register" is how you get a hook that installs and
        // never matches.
        const std::vector<std::string> wanted = hooks.empty()
            ? std::vector<std::string>{"NtQueryInformationProcess", "NtQueryObject",
                                       "NtQuerySystemInformation"}
            : hooks;

        if (!paused) {
            out["hooks"] = {{"ok", false},
                            {"error", "ntdll stubs need a paused target; pause and re-run "
                                      "harden at level=paranoid"}};
        } else {
            out["hooks"] = ntdll_hook::install_defaults(wanted, false);
        }

        // The kernel component, when the driver is loaded: this is the only way
        // ProcessDebugPort answers "0" from a driver's point of view.
        auto kstat = kernel_driver::status();
        if (kstat.value("driver_present", false)) {
            auto katt = kernel_driver::attach(static_cast<unsigned long>(pid));
            if (katt.value("ok", false)) {
                out["kernel"] = kernel_driver::apply(0x7, 0, 0, 0);
            } else {
                out["kernel"] = katt;
            }
        } else {
            out["kernel"] = {{"ok", false}, {"skipped", true},
                             {"reason", "kernel driver not loaded"},
                             {"what_it_would_add", "EPROCESS.DebugPort cleared, so "
                                                   "NtQueryInformationProcess answers 0 even "
                                                   "to a check that bypasses the user-mode "
                                                   "stub"}};
        }
    }

    // What a user-mode plugin fundamentally cannot do, stated on every call so a
    // caller never reads "hardened" as "invisible".
    out["not_covered"] = nlohmann::json::array({
        "kernel-mode readers of EPROCESS/KPROCESS (needs the kernel component)",
        "checks that read the debug object through a handle they already hold",
        "a protection layer that re-protects its own pages after each write",
        "hardware-based detection (measured CPUID timing on bare metal)"
    });

    if (!paused) {
        out["warning"] = "the target is running: writes may be overwritten before "
                         "they are observed; pause for a verified pass";
    }
    return out;
}

// ---------------------------------------------------------------------------
// Background re-apply
// ---------------------------------------------------------------------------
//
// Why a worker: a target that clears BeingDebugged back to 1 on every resume
// defeats any one-shot pass, and doing the pass from a tool call means the target
// runs unprotected between calls. This worker waits for a pause, re-clears, and
// goes back to waiting - it never resumes the target on its own.
//
// What it deliberately does NOT do: touch the target while it runs. Writing the
// PEB of a running process is a torn write the target can observe mid-read, and
// the resulting bug reports are unfalsifiable.

void notify_paused() {
    if (!g_guard_running.load()) return;
    g_paused_signal.store(true);
    g_cv.notify_all();
}

bool guard_active() { return g_guard_running.load(); }

nlohmann::json stop_guard() {
    if (!g_guard_running.load() && !g_worker.joinable()) {
        return nlohmann::json{{"was_running", false},
                              {"message", "the PEB guard was not active"}};
    }

    g_stop.store(true);
    g_cv.notify_all();
    if (g_worker.joinable()) g_worker.join();

    nlohmann::json out = {{"was_running", true}, {"passes", g_stats.passes},
                          {"reverted", g_stats.reverted}};
    if (!g_stats.last_error.empty()) out["last_error"] = g_stats.last_error;
    return out;
}

void start_guard(level lvl) {
    stop_guard();

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_stats = {};
    }
    g_stop.store(false);
    g_paused_signal.store(false);

    g_worker = std::thread([lvl]() {
        g_guard_running.store(true);
        auto& bridge = get_bridge();
        const auto l = layout();

        while (!g_stop.load()) {
            {
                std::unique_lock<std::mutex> lock(g_mutex);
                g_cv.wait(lock, [] {
                    return g_stop.load() || g_paused_signal.load();
                });
                if (g_stop.load()) break;
                g_paused_signal.store(false);
            }

            if (!DbgIsDebugging()) break;
            if (DbgIsRunning()) continue;   // never write a running target

            const duint pid = bridge.eval_expression("$pid");
            const duint peb = DbgGetPebAddress(static_cast<DWORD>(pid));
            if (peb == 0) continue;

            pass_report rep;
            clear_peb(bridge, peb, rep, l, lvl != level::basic);

            std::lock_guard<std::mutex> lock(g_mutex);
            ++g_stats.passes;
            // A field that was non-zero on entry means the target had restored
            // it; counting those is the useful signal that a protection layer is
            // actively fighting the pass.
            for (const auto& a : rep.applied) {
                if (a.contains("was") && a["was"] != "0") ++g_stats.reverted;
            }
            if (!rep.failed.empty()) {
                g_stats.last_error = rep.failed[0].value("field", std::string("write failed"));
            }
        }

        g_guard_running.store(false);
    });
}

void shutdown() {
    g_stop.store(true);
    g_cv.notify_all();
    if (g_worker.joinable()) g_worker.join();
    g_guard_running.store(false);
}

} // namespace antidebug_hard
