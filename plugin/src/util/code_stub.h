#pragma once

// Trampoline machinery for replacing a single instruction with a stub.
//
// Why this exists at all: the obvious way to fake a `cpuid` or `rdtsc` result is
// a breakpoint whose command rewrites a register. That does not work, and the
// reason is worth writing down. A software breakpoint fires BEFORE the
// instruction executes, so `ecx=ecx&0x7FFFFFFF;run` on a `cpuid` is overwritten
// by the cpuid itself a microsecond later. The value a check reads is produced
// after the breakpoint has already run, so only a stub that runs the real
// instruction and then edits its output can change the answer.
//
// Hence: displace the instruction into a stub, run it there, filter the result,
// continue at the instruction after the original. The pieces below are what that
// needs and nothing more.

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

#include "bridge/c_bridge_executor.h"

namespace code_stub {

// x64 only: the emit sequences are written for the x64 call/return shape.
bool supported();

// Allocate executable memory inside the target, bump-allocated from one page
// per session. Returns 0 on failure. The page is released when the debug session
// ends, so nothing is leaked into a target that outlives the debugger.
//
// `near_addr` is where the patch will go. The page is requested near it because
// the entry patch must fit in one instruction's worth of bytes, which means a
// 5-byte relative jump - and a page allocated anywhere in a 64-bit address space
// is usually out of reach of that. Pass 0 only when the address is genuinely
// unknown.
duint alloc(c_bridge_executor& bridge, size_t size, duint near_addr);

// Absolute jump from `from` to `to`, as a patch to place at `from`.
//
// Uses the 5-byte relative form when the two addresses are within ±2 GB (the
// common case, since the stub page is allocated near the module) and falls back
// to the 14-byte `jmp qword ptr [rip+0]` form otherwise. The caller must have
// room for whichever it gets - `prepare` reports the size it chose.
std::vector<uint8_t> jump_patch(duint from, duint to);

// Whole instructions at `site` covering at least `min_bytes`, plus the patch
// that replaces them.
//
// Refuses (rather than producing a broken trampoline) when a displaced
// instruction is RIP-relative, a relative branch, or a call: copying those
// changes their meaning, and a silently wrong trampoline shows up as a crash
// deep inside the target's own code path.
struct prepared {
    std::vector<uint8_t> patch;      // bytes to write at site
    std::vector<uint8_t> original;   // what was there
    std::vector<uint8_t> displaced;  // whole instructions copied for the stub
    duint    site = 0;
    duint    stub = 0;               // where the stub body goes
    size_t   patch_len = 0;          // == patch.size(), == original.size()
    size_t   resume_at = 0;          // site + displaced.size()
};

std::expected<prepared, std::string> prepare(c_bridge_executor& bridge, duint site,
                                             size_t min_bytes);

} // namespace code_stub
