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
//      re-enters the real syscall for any class we do not intercept.
//
//   2. Hotpatch jump thunk (what Windows 11 ships for the Nt* exports)
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
    // Write a zeroed dword through the info buffer, return STATUS_SUCCESS.
    // ProcessDebugPort / ProcessDebugObjectHandle / ProcessDebugObject.
    fake_zero_success,

    // Write 1 through the info buffer, return STATUS_SUCCESS.
    // ProcessDebugFlags reads its value as the INVERSE of the debug state, so a
    // non-zero means "not being debugged". Writing it explicitly is what makes the
    // answer independent of what the caller left in the buffer.
    fake_nonzero_success,

    // Return STATUS_SUCCESS without touching the buffer. For callers that already
    // zero their buffer and treat any non-zero as "debugged", this is the same
    // answer as fake_nonzero_success with no risk of overflowing a short buffer.
    return_success,

    // Refuse the query with STATUS_INVALID_PARAMETER. Used where a wrong answer
    // is worse than no answer.
    return_invalid_parameter,

    // Write an explicit byte pattern through the buffer, return STATUS_SUCCESS.
    //
    // Needed because a single zero is not always the right answer. The clearest
    // case is SystemKernelDebuggerInformation (0x23): the structure is
    // { BOOLEAN DebuggerPresent; BOOLEAN DebuggerNotPresent; }, and "no kernel
    // debugger" is {0, 1} - not {0, 0}. Writing all zeros produces a state no real
    // machine reports, which is itself detectable. `pattern` is copied to the
    // buffer, and only as many bytes as it holds, so a caller passing a 2-byte
    // buffer is not overrun.
    fake_pattern_success,
};

// Where an argument lives.
//
// The Nt* functions are not uniform, and getting this wrong is silent: the stub
// compares the wrong register, never matches, and falls through to the default -
// which looks identical to "the hook did not install". Measured:
//
//   NtQueryInformationProcess(handle, class, buf, len, ret)  class=rdx  buf=r8
//   NtQuerySystemInformation(class, buf, len, ret)           class=rcx  buf=rdx
//   NtQueryObject(handle, class, buf, len, ret)              class=rdx  buf=r8
struct arg_regs {
    std::string class_reg;   // "rdx" or "rcx"
    std::string buffer_reg;  // "r8" or "rdx"
};

// A register the stub can write a 32-bit value into.
enum class reg { eax, ebx, ecx, edx, eax_at_buf, edx_at_buf };

struct target_spec {
    std::string function;     // "NtQueryInformationProcess"
    unsigned long info_class; // the class value to intercept
    action       what;
    arg_regs     args;        // where class/buffer live for this function
    // For fake_pattern_success: the exact bytes to place in the buffer. Empty for
    // every other action.
    std::vector<uint8_t> pattern;
};

// The register convention for a known function, so callers do not have to
// remember the table above. Returns false for an unknown name.
bool arg_regs_for(const std::string& function, arg_regs* out);

// Install stubs for `targets`.
//
// All-or-nothing on purpose: a half-hooked ntdll produces failures that look
// like the target's own bugs. If any requested function cannot be prepared, the
// whole set is rolled back.
nlohmann::json install(const std::vector<target_spec>& targets, bool dry_run);

// Convenience: build the default spec set for the named functions, each with the
// classes that matter for anti-debugging. Unknown names are reported, not ignored.
nlohmann::json install_defaults(const std::vector<std::string>& functions, bool dry_run);

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
