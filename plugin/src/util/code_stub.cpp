#include "util/code_stub.h"

#include <algorithm>
#include <cstring>
#include <mutex>

#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "util/format_utils.h"

namespace code_stub {

namespace {

constexpr size_t STUB_PAGE_SIZE = 0x1000;

std::mutex g_mutex;
duint g_page_base = 0;
size_t g_page_used = 0;

// Last allocation that could not reach its site, kept so alloc() can explain
// "unreachable" precisely instead of returning a bare 0 that reads like failure.
duint g_unreachable_page = 0;
duint g_unreachable_site = 0;

// Can a 5-byte relative jump from `from` reach `to`?
bool rel32_reachable(duint from, duint to) {
    const long long delta = static_cast<long long>(to) - static_cast<long long>(from + 5);
    return delta >= INT32_MIN && delta <= INT32_MAX;
}

// Allocate `size` bytes at or near `hint` inside the target, from the plugin's
// own process context.
//
// This does not go through x64dbg's `alloc`. Measured on 2026.05.27: `alloc`
// ignores the requested address entirely (it reports success and leaves $result
// at 0 when a hint is supplied, and returns whatever the target's free list hands
// out when it is not). A page 40 TB away from the patched instruction is useless
// here, because the entry patch has to fit in one instruction and therefore can
// only be a 5-byte relative jump. VirtualAllocEx with an explicit address is the
// only way to place it where that jump can reach.
//
// The scan walks outward from the hint in 64 KB steps (the allocation
// granularity), which is what keeps this from being a linear search.
// Lowest address Windows will actually map code at in a 64-bit process.
//
// This matters because the failure is silent in the worst way: VirtualAllocEx
// succeeds for an address below 64 KB, the bytes read back correctly, and the
// process takes an access violation the moment the stub is entered. Measured
// here: a hotpatch dispatcher placed at 0x10000 assembled perfectly and could not
// execute. The scan therefore never proposes an address under this floor.
constexpr duint kMinUserAddress = 0x10000;

duint alloc_near_target(DWORD pid, duint hint, size_t size) {
    if (pid == 0 || size == 0) return 0;

    HANDLE proc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
                              FALSE, pid);
    if (!proc) {
        // A protected process refuses this even to the debugger; there is no
        // user-mode fallback worth pretending to have.
        return 0;
    }

    constexpr duint granularity = 0x10000;

    // With no hint (the slot-stub case, where the dispatcher may live anywhere)
    // start from a high, conventional region rather than from zero, because the
    // low 64 KB is unmappable and the scan would otherwise waste its radius.
    const duint start = hint ? hint : 0x0000010000000000ull;
    const duint aligned = start & ~static_cast<duint>(granularity - 1);

    duint found = 0;
    for (int step = 0; step < 128 && found == 0; ++step) {
        for (int dir = 0; dir < 2 && found == 0; ++dir) {
            if (step == 0 && dir == 1) continue;
            const duint at = (dir == 0)
                ? aligned + static_cast<duint>(step) * granularity
                : aligned - static_cast<duint>(step) * granularity;
            if (at < kMinUserAddress) continue;

            void* page = VirtualAllocEx(proc, reinterpret_cast<void*>(at), size,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!page) continue;

            const duint got = reinterpret_cast<duint>(page);
            // VirtualAllocEx honours the address when it can; verify rather than
            // trust. With no hint there is no range requirement, only the floor.
            if (got < kMinUserAddress ||
                (hint != 0 && !rel32_reachable(hint, got))) {
                VirtualFreeEx(proc, page, 0, MEM_RELEASE);
                continue;
            }
            found = got;
        }
    }

    CloseHandle(proc);
    return found;
}

// Instructions whose bytes cannot be relocated as-is. Kept as a function so the
// list reads as documentation rather than a magic condition.
//
// Relative branches and calls are NOT in this list any more: they are re-encoded
// for their new address (see relocate_branch). Only RIP-relative memory operands
// remain unhandled, because "the data is N bytes from here" has no meaning once
// the instruction moves and there is no generic rewrite for it.
bool is_unrelocatable(const DISASM_INSTR& di) {
    const std::string mn = di.instruction;   // full text, e.g. "mov rax,[rip+8]"
    if (mn.find("[rip") != std::string::npos || mn.find("[eip") != std::string::npos) {
        return true;
    }
    (void)di.type;
    return false;
}

// Re-encode a relative branch or call so it still reaches the same target from
// `new_at` instead of `old_at`.
//
// Two shapes:
//
//   E9/E8 rel32        -> same length, displacement recomputed
//   0F 8x rel32        -> same length, displacement recomputed
//   7x rel8  (jcc)     -> widened to 0F 8x rel32. The ±127 window almost never
//                         survives a move into a different page, and a truncated
//                         rel8 would branch into arbitrary code.
//   EB rel8  (jmp)     -> widened to E9 rel32, same reason
//   E3 rel8  (jrcxz)   -> NOT widened: jrcxz has no rel32 form, so it stays
//                         unhandled and the site is refused.
//
// `target` is the absolute destination in the ORIGINAL image, which the caller
// computes from the original bytes and the original address.
// Re-encode a relative branch or call so it reaches the same absolute target from
// a new location. Returns the replacement bytes and the resulting size change.
//
// Two shapes:
//
//   E9/E8 rel32, 0F 8x rel32  -> same length, displacement recomputed
//   7x rel8 (jcc), EB rel8    -> widened to the rel32 form. The ±127-byte window
//                                almost never survives a move into another page,
//                                and a truncated rel8 would branch into arbitrary
//                                code - so widening is the only safe option. That
//                                is why `size_delta` exists.
//   E3 rel8 (jrcxz/jecxz)     -> refused: no rel32 equivalent exists.
//
// The caller patches the displacement once the destination address is known,
// because it depends on where the stub was allocated.
std::expected<relocation, std::string> relocate_branch(const std::vector<uint8_t>& orig) {
    relocation r;
    r.old_size = orig.size();

    if (orig.size() == 2 && (orig[0] & 0xF0) == 0x70) {
        r.replacement = {0x0F, static_cast<uint8_t>(0x80 | (orig[0] & 0x0F)), 0, 0, 0, 0};
        r.what = "jcc rel8 -> rel32";
    } else if (orig.size() == 2 && orig[0] == 0xEB) {
        r.replacement = {0xE9, 0, 0, 0, 0};
        r.what = "jmp rel8 -> rel32";
    } else if (orig.size() == 5 && (orig[0] == 0xE9 || orig[0] == 0xE8)) {
        r.replacement = {orig[0], 0, 0, 0, 0};
        r.what = (orig[0] == 0xE8) ? "call rel32" : "jmp rel32";
    } else if (orig.size() == 6 && orig[0] == 0x0F && (orig[1] & 0xF0) == 0x80) {
        r.replacement = {orig[0], orig[1], 0, 0, 0, 0};
        r.what = "jcc rel32";
    } else {
        return std::unexpected("branch form has no rel32 equivalent "
                               "(jrcxz/jecxz or an unrecognised encoding)");
    }

    r.size_delta = static_cast<int>(r.replacement.size()) - static_cast<int>(orig.size());
    return r;
}

// Original absolute destination of a relative branch at `at`.
duint branch_target(const std::vector<uint8_t>& orig, duint at) {
    if (orig.size() == 5 && (orig[0] == 0xE9 || orig[0] == 0xE8)) {
        const auto rel = static_cast<int32_t>(
            static_cast<uint32_t>(orig[1]) | (static_cast<uint32_t>(orig[2]) << 8) |
            (static_cast<uint32_t>(orig[3]) << 16) | (static_cast<uint32_t>(orig[4]) << 24));
        return at + 5 + static_cast<duint>(static_cast<int64_t>(rel));
    }
    if (orig.size() == 6 && orig[0] == 0x0F && (orig[1] & 0xF0) == 0x80) {
        const auto rel = static_cast<int32_t>(
            static_cast<uint32_t>(orig[2]) | (static_cast<uint32_t>(orig[3]) << 8) |
            (static_cast<uint32_t>(orig[4]) << 16) | (static_cast<uint32_t>(orig[5]) << 24));
        return at + 6 + static_cast<duint>(static_cast<int64_t>(rel));
    }
    if (orig.size() == 2 && ((orig[0] & 0xF0) == 0x70 || orig[0] == 0xEB)) {
        return at + 2 + static_cast<duint>(static_cast<int64_t>(static_cast<int8_t>(orig[1])));
    }
    return 0;
}

// True when the instruction is a relative branch, call or jcc/loop worth
// relocating rather than refusing.
bool is_relative_branch(const DISASM_INSTR& di, const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return false;
    if (bytes.size() == 2 && (bytes[0] & 0xF0) == 0x70) return true;
    if (bytes.size() == 2 && bytes[0] == 0xEB) return true;
    if (bytes.size() == 5 && (bytes[0] == 0xE9 || bytes[0] == 0xE8)) return true;
    if (bytes.size() == 6 && bytes[0] == 0x0F && (bytes[1] & 0xF0) == 0x80) return true;
    (void)di;
    return false;
}

duint branch_target_duint(const std::vector<uint8_t>& orig, duint at);

} // namespace

bool supported() { return sizeof(void*) == 8; }

duint alloc(c_bridge_executor& bridge, size_t size, duint near_addr) {
    if (!supported()) return 0;

    const size_t need = std::max<size_t>(size, 1);

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        // Only reuse the cached page when it is actually reachable from this
        // site; a second site in a different module can be more than 2 GB away
        // from a page that suited the first one.
        if (g_page_base != 0 && g_page_used + need <= STUB_PAGE_SIZE &&
            (near_addr == 0 || rel32_reachable(near_addr, g_page_base))) {
            const duint at = g_page_base + g_page_used;
            g_page_used += need;
            return at;
        }
    }

    // Place the page where the entry patch can jump to it. The patch has to fit
    // in the bytes of one or a few instructions, so it can only be a 5-byte
    // relative jump, and a page anywhere in a 64-bit address space is usually
    // 40 TB away from that.
    const duint pid = bridge.eval_expression("$pid");
    const duint hinted = alloc_near_target(static_cast<DWORD>(pid), near_addr, STUB_PAGE_SIZE);

    duint base = hinted;
    if (base == 0) {
        // Fallback: x64dbg's own allocator. It ignores the address hint on this
        // build, so the page is likely out of reach - but it is still the right
        // thing to try when VirtualAllocEx was refused (protected process), and
        // the reachability check below decides what to report.
        if (!bridge.exec_command("alloc 0x" +
                                 format_utils::format_hex(static_cast<duint>(STUB_PAGE_SIZE)))) {
            return 0;
        }
        base = bridge.eval_expression("$result");
    }
    if (base == 0) return 0;

    if (near_addr != 0 && !rel32_reachable(near_addr, base)) {
        // Both allocators landed out of range. Keep the page (a later site in the
        // same region may reach it) and tell the caller precisely which way it
        // failed, because only this failure has a workaround.
        std::lock_guard<std::mutex> lock(g_mutex);
        g_page_base = base;
        g_page_used = need;
        g_unreachable_page = base;
        g_unreachable_site = near_addr;
        return 0;
    }

    // VirtualAllocEx was called with PAGE_EXECUTE_READWRITE; x64dbg's alloc grants
    // RWX too, but assert it because an unexecutable stub page fails as an access
    // violation inside the target, which reads like the target's own bug.
    bridge.exec_command("VirtualProtect " + format_utils::format_address(base) + ", 0x" +
                        format_utils::format_hex(static_cast<duint>(STUB_PAGE_SIZE)) +
                        ", PAGE_EXECUTE_READWRITE");

    std::lock_guard<std::mutex> lock(g_mutex);
    g_page_base = base;
    g_page_used = need;
    return base;
}

std::vector<uint8_t> jump_patch(duint from, duint to) {
    std::vector<uint8_t> patch;

    const long long delta = static_cast<long long>(to) - static_cast<long long>(from + 5);
    if (delta >= INT32_MIN && delta <= INT32_MAX) {
        patch.push_back(0xE9);                       // jmp rel32
        const auto d = static_cast<int32_t>(delta);
        for (int i = 0; i < 4; ++i) {
            patch.push_back(static_cast<uint8_t>((static_cast<uint32_t>(d) >> (8 * i)) & 0xFF));
        }
        return patch;
    }

    // Out of ±2 GB: the absolute indirect form. 14 bytes, but the caller only
    // reaches here when the displacement does not fit, and that also means the
    // stub page and the site are far apart.
    patch = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};    // jmp qword ptr [rip+0]
    for (int i = 0; i < 8; ++i) {
        patch.push_back(static_cast<uint8_t>((static_cast<uint64_t>(to) >> (8 * i)) & 0xFF));
    }
    return patch;
}

std::expected<prepared, std::string> prepare(c_bridge_executor& bridge, duint site,
                                             size_t min_bytes) {
    if (!supported()) {
        return std::unexpected("instruction stubs are x64 only in this build");
    }
    if (min_bytes == 0 || min_bytes > 64) {
        return std::unexpected("min_bytes must be 1..64");
    }

    prepared p;
    p.site = site;

    // Walk whole instructions until the displaced region can hold the jump.
    duint cur = site;
    std::vector<uint8_t> displaced;
    std::vector<relocation> relocs;

    while (displaced.size() < min_bytes) {
        DISASM_INSTR di{};
        DbgDisasmAt(cur, &di);
        if (di.instr_size <= 0) {
            return std::unexpected("cannot disassemble at " +
                                   format_utils::format_address(cur) +
                                   " - the site is not valid code, so a stub cannot be "
                                   "placed without guessing instruction boundaries");
        }

        auto bytes = bridge.read_memory(cur, static_cast<size_t>(di.instr_size));
        if (!bytes.has_value()) {
            return std::unexpected("cannot read the instruction at " +
                                   format_utils::format_address(cur));
        }

        if (is_unrelocatable(di)) {
            return std::unexpected(
                "the instruction at " + format_utils::format_address(cur) + " (\"" +
                std::string(di.instruction) + "\") uses RIP-relative addressing: its operand "
                "is addressed by distance from the instruction, so it cannot be moved into a "
                "stub. Move the stub site, or use probe_breakpoints (a logging breakpoint) "
                "for this site.");
        }

        // A relative branch or call has to be re-encoded for its new address.
        // Keeping the original bytes would make it branch relative to the stub.
        if (is_relative_branch(di, *bytes)) {
            auto reloc = relocate_branch(*bytes);
            if (!reloc.has_value()) {
                return std::unexpected(
                    "the branch at " + format_utils::format_address(cur) + " (\"" +
                    std::string(di.instruction) + "\") cannot be re-encoded: " +
                    reloc.error());
            }
            reloc->offset = displaced.size();
            reloc->original_target = branch_target(*bytes, cur);
            relocs.push_back(*reloc);
            displaced.insert(displaced.end(), reloc->replacement.begin(),
                             reloc->replacement.end());
        } else {
            displaced.insert(displaced.end(), bytes->begin(), bytes->end());
        }

        cur += static_cast<duint>(di.instr_size);
        if (displaced.size() > 48) {
            return std::unexpected("no instruction boundary within 48 bytes of " +
                                   format_utils::format_address(site));
        }
    }

    // Two-pass: patch length depends on the stub address (relative vs absolute
    // jump), and the stub address depends on how much we allocate, so reserve the
    // worst case first and then size the patch to what the jump actually needs.
    const size_t worst_case_patch = 14;
    const size_t stub_size = displaced.size() + worst_case_patch + 32;

    // Allocate before reading the original bytes so a failure leaves the target
    // untouched. The site is passed as the "near" hint: the entry patch has to fit
    // inside whole instructions (5 bytes for a relative jump), so a page allocated
    // far from the site could not be reached at all.
    const duint stub = alloc(bridge, stub_size, site);
    if (stub == 0) {
        // Distinguish the two failure modes: they have different fixes, and a
        // single "could not allocate" would hide the one the caller can act on.
        duint far_page = 0, far_site = 0;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            far_page = g_unreachable_page;
            far_site = g_unreachable_site;
        }
        if (far_page != 0 && far_site != 0) {
            return std::unexpected(
                "stub page " + format_utils::format_address(far_page) +
                " is out of reach of " + format_utils::format_address(far_site) +
                ": the 5-byte relative jump the site can hold cannot span more than "
                "2 GB, and this x64dbg build's `alloc` ignores the address hint. Set a "
                "breakpoint + log_text on the instruction instead (probe_breakpoints), "
                "which needs no stub page.");
        }
        return std::unexpected("could not allocate stub memory in the target");
    }
    p.stub = stub;

    auto patch = jump_patch(site, stub);
    // A patch shorter than the displaced region needs NOP fill so the following
    // instruction starts where it did before.
    //
    // The reverse case - the patch being LONGER than the displaced instructions -
    // is fine and common: a 2-byte `cpuid` becomes a 5-byte relative jump, and the
    // 3 bytes left over are filled with NOPs. That is why the caller can pass the
    // probe's own length instead of a fixed 5 and avoid dragging the target's next
    // instruction into the stub.
    if (patch.size() < displaced.size()) {
        patch.resize(displaced.size(), 0x90);
    }

    auto original = bridge.read_memory(site, patch.size());
    if (!original.has_value()) {
        return std::unexpected("cannot read the site bytes");
    }

    p.patch = patch;
    p.original = *original;
    p.displaced = displaced;
    p.relocations = relocs;
    p.patch_len = patch.size();
    // The stub resumes after everything the patch overwrote. patch.size() is now
    // the authority: a widened relocation can make `displaced` longer than the
    // original instruction stream, and the NOP fill can make the patch longer than
    // `displaced`. Using displaced.size() here would resume mid-instruction in
    // either case.
    p.resume_at = site + patch.size();
    return p;
}

std::vector<uint8_t> prepared::displaced_with_relocations() const {
    // prepare() emitted the widened replacements with zero displacements, so all
    // that is missing is the real displacement for each one - recomputed from the
    // stub address, which only the caller knows.
    std::vector<uint8_t> out = displaced;

    for (const auto& r : relocations) {
        if (r.replacement.size() < 5) continue;   // placeholders are all >= 5 bytes
        if (r.offset + r.replacement.size() > out.size()) continue;

        // The new displacement is measured from the END of the replacement, in its
        // new home inside the stub.
        const duint new_next = stub + static_cast<duint>(r.offset) + r.replacement.size();
        const long long disp = static_cast<long long>(r.original_target) -
                               static_cast<long long>(new_next);
        const auto d = static_cast<int32_t>(disp);

        // The displacement always occupies the trailing 4 bytes: E9/E8 and 0F 8x
        // already end in rel32, and the widened forms end in rel32 too.
        const size_t disp_at = r.offset + r.replacement.size() - 4;
        if (disp_at + 4 <= out.size()) {
            for (int i = 0; i < 4; ++i) {
                out[disp_at + static_cast<size_t>(i)] =
                    static_cast<uint8_t>((static_cast<uint32_t>(d) >> (8 * i)) & 0xFF);
            }
        }
    }
    return out;
}

} // namespace code_stub
