#pragma once

// Inline stubs for the ntdll calls that anti-debug code uses as its oracle.
//
// Why stubs instead of breakpoints: a breakpoint pauses the target and shows up
// in the debugger's own state, so a target that times itself around the call
// notices. A stub at the function entry changes the answer while the call still
// costs roughly what it used to.
//
// There are TWO layouts in the wild and both must be handled, because patching
// the wrong one either fails or corrupts the call:
//
//   1. Direct syscall stub (ntdll's own .text)
//        mov r10, rcx / mov eax, ssn / test..jne..ret / syscall / ret
//      Here the entry is real code, so it is displaced into a trampoline that
//      re-enters the real syscall for any info class we do not intercept.
//
//   2. Hotpatch jump thunk (what Windows 11 ships for NtQueryInformationProcess)
//        nop / jmp qword ptr [rip+0] / <absolute address of the real body>
//      The entry is not code, it is a pointer slot. Displacing it is impossible
//      (the jump is RIP-relative) and unnecessary: rewriting the pointer is the
//      single-write equivalent, and the hotpatch slot exists precisely so this
//      can be done atomically. Measured on 26200: the slot holds a real function
//      prologue, so the target's call goes wherever the slot points.
//
// The stub for layout 2 has no range constraint at all (the slot holds a full
// 64-bit address), which is why it is also the layout that works when the
// dispatcher cannot be placed near ntdll.

#include <cstdint>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace ntdll_hook {

// The behaviours a stub can implement. Named after the check they defeat, not
// after the API, because the API is an implementation detail of the check.
enum class action {
    // Write a zeroed pointer-sized value through the info buffer, return
    // STATUS_SUCCESS. ProcessDebugPort / ProcessDebugObjectHandle.
    fake_zero_success,

    // Return STATUS_SUCCESS without touching the buffer. ProcessDebugFlags
    // reads its value as the INVERSE of the debug state, so a zero already
    // means "not being debugged" - writing anything would be wrong.
    return_success,

    // Refuse the query with STATUS_INVALID_PARAMETER. Used where a wrong answer
    // is worse than no answer.
    return_invalid_parameter,
};

struct target_spec {
    std::string function;     // "NtQueryInformationProcess"
    unsigned long info_class; // the class value to intercept, as seen in EDX
    action       what;
};

// Install stubs for `targets`.
//
// All-or-nothing on purpose: a half-hooked ntdll produces failures that look
// like the target's own bugs. If any requested function cannot be prepared, the
// whole set is rolled back.
nlohmann::json install(const std::vector<target_spec>& targets, bool dry_run);

// Write the original bytes (or the original slot pointer) back.
nlohmann::json restore();

// Session-teardown variant: restore what can be restored, and ALWAYS clear the
// registry. restore() requires a paused target; at session end the process may
// already be gone, and a stale registry entry would be written into an unrelated
// process next session.
nlohmann::json teardown();

// What is currently hooked, without touching the target.
nlohmann::json list();

// True when this build can emit the dispatcher at all (x64 only).
bool supported();

} // namespace ntdll_hook
