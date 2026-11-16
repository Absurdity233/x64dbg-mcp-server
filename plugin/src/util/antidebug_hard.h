#pragma once

// Deep anti-detection: the hardening that has to touch every thread, not just
// the current one.
//
// The existing hide_debugger route clears two PEB fields once. That is enough
// for IsDebuggerPresent and nothing else, for three concrete reasons:
//
//   * Every new thread starts with clean debug registers and a fresh TEB, so a
//     thread that reads FS:[0x30] -> PEB after a resume sees whatever the
//     protection layer put back.
//   * The debug object handle and the debug port are kernel state; a plugin in
//     user mode cannot reach them (the kernel_driver component can).
//   * Heap flags live behind PEB.ProcessHeap, which can move if the process
//     recreates its heap.
//
// So "harden" is a loop over /all/ threads plus a re-application strategy: clear
// the fields, then keep them clear across resumes, and verify after each pass
// rather than assuming a successful write stayed.

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "bridge/c_bridge_executor.h"

namespace antidebug_hard {

// How much to touch. Named by effect, not by mechanism, because that is what the
// caller is choosing between.
enum class level {
    // PEB.BeingDebugged + NtGlobalFlag. One pass, current thread. Enough for
    // IsDebuggerPresent / CheckRemoteDebuggerPresent.
    basic,
    // + heap flags, + every thread's TEB/PEB view, + DR registers, + the
    // ProcessDebugObjectHandle-facing PEB fields. The default: it covers every
    // user-mode check that reads the PEB.
    deep,
    // + ntdll stubs for the three NtQueryInformationProcess classes and
    // NtSetInformationThread(ThreadHideFromDebugger), + a re-apply thread that
    // keeps the PEB clear while the target runs.
    paranoid,
};

// Apply a pass. `hooks` names which ntdll stubs to install when level is
// paranoid; empty means the default set.
nlohmann::json apply(c_bridge_executor& bridge, level lvl, bool all_threads,
                     const std::vector<std::string>& hooks);

// Start the background worker that re-clears the PEB on every pause.
void start_guard(level lvl);

// Stop the re-apply worker (if running) and report what it did.
nlohmann::json stop_guard();

// Is the background re-apply worker running?
bool guard_active();

// Called from the debugger thread's pause callback: cheap, lock-free signal that
// the PEB should be re-cleared before the target's code gets to run.
void notify_paused();

// Worker lifecycle, wired into plugin init/stop like trace_auto.
void shutdown();

// Name <-> level for the HTTP layer.
level parse_level(const std::string& name);
const char* level_name(level l);

} // namespace antidebug_hard
