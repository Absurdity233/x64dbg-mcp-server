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

// Permutation of a displaced relative branch/call.
//
// A relative branch encodes "next instruction + displacement", so copying its
// bytes into a stub changes where it goes. The fix is to recompute the
// displacement for the new location, which is exact for a rel32 jmp/call and
// needs a little care for the shorter forms:
//
//   rel8  jcc/loop/jrcxz  -> widen to the rel32 form (0F 8x / E9) because the
//                            original ±127 window does not survive the move
//   rel32 jmp/call        -> same size, new displacement
//
// Widening changes the instruction's length, which the caller must add to the
// stub layout - `reloc.size_delta` reports it.
struct relocation {
    size_t offset = 0;        // byte offset inside `displaced`
    size_t old_size = 0;      // original instruction length
    std::vector<uint8_t> replacement;  // bytes to use instead
    int    size_delta = 0;    // replacement.size() - old_size
    // Absolute destination in the ORIGINAL image. The branch still has to reach
    // here, but measured from its new address in the stub.
    duint  original_target = 0;
    std::string what;         // mnemonic/encoding, for reporting
};

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
// Refuses when a displaced instruction genuinely cannot be moved: a RIP-relative
// memory operand addresses data by its distance from the instruction, and there
// is no general way to re-express that without knowing what the operand means.
//
// Relative branches and calls ARE handled now: they are recomputed for their new
// location (widening a rel8 form to rel32 when needed) and reported through
// `relocations`. That matters in practice - the cpuid sites inside a real
// detection routine are frequently followed by a `jnz` within the bytes the patch
// has to displace, and refusing those skipped exactly the site that decided the
// check.
struct prepared {
    std::vector<uint8_t> patch;      // bytes to write at site
    std::vector<uint8_t> original;   // what was there
    std::vector<uint8_t> displaced;  // whole instructions copied for the stub
    // Relocated branches inside `displaced`. The caller writing a stub must use
    // `displaced_with_relocations()` instead of `displaced`, and must account for
    // the size change when placing whatever follows.
    std::vector<relocation> relocations;
    duint    site = 0;
    duint    stub = 0;               // where the stub body goes
    // Where the stub must jump back to: the first byte after the region the patch
    // overwrote. This is patch.size(), NOT displaced.size(), because a widening
    // relocation and NOP fill both change how much of the original instruction
    // stream the stub has already accounted for.
    size_t   patch_len = 0;          // == patch.size(), == original.size()
    duint    resume_at = 0;

    // The displaced instruction stream with every branch re-encoded for `stub`.
    // Compute after `stub` is known; prepare() already did it once using the
    // address it allocated.
    [[nodiscard]] std::vector<uint8_t> displaced_with_relocations() const;
};

std::expected<prepared, std::string> prepare(c_bridge_executor& bridge, duint site,
                                             size_t min_bytes);

} // namespace code_stub
