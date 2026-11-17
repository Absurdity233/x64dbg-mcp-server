#include "util/anti_vm.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <mutex>

#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "util/code_stub.h"
#include "util/format_utils.h"
#include "util/probe_scan.h"

namespace anti_vm {

namespace {

std::mutex g_mutex;
std::map<duint, armed_stub> g_armed;

// x64 encodings for the filter that follows the displaced instruction. Written
// as raw bytes rather than through the assembler because `AssembleAtEx` refuses
// to write into freshly allocated memory that has no x64dbg function/analysis
// record, and a filter that silently failed to assemble would leave the check
// untouched while reporting success.
struct filter_bytes {
    std::vector<uint8_t> code;
    std::string what;
};

// cpuid: clear ECX bit 31 (hypervisor-present) and blank the vendor leaf.
//
// The branch displacements are COMPUTED, not written by hand. Hand-counted rel8
// offsets are how this first shipped broken: a two-byte miscount made `jne` land
// in the middle of `and ecx, imm32`, and the target died with
// STATUS_ILLEGAL_INSTRUCTION (0xC000001D) at the stub. A patch cannot express the
// intent, so the offsets are derived from the actual instruction lengths.
//
// On the vendor leaf the filter zeroes eax/ebx/ecx/edx, which makes leaf
// 0x40000000 answer like a CPU with no hypervisor vendor. That also destroys the
// `r8d = edi`-style follow-up bookkeeping the compiler emits, but those registers
// are the caller's to reload, not ours to invent.
filter_bytes cpuid_filter() {
    filter_bytes f;

    // Detect "this was a hypervisor-vendor query" AFTER the cpuid has already run,
    // which means eax no longer holds the requested leaf - cpuid overwrites it with
    // the answer. For a vendor query that answer is the highest hypervisor leaf
    // (0x4000000C on this host), so it lands in the 0x40000000..0x400000FF range
    // while leaf 0 (max basic leaf) and leaf 1 (version, ~0x000BEAxx) do not.
    //
    // Comparing `eax == 0x40000000` is the natural-looking mistake and it never
    // matches: that is the leaf the caller ASKED for, not what cpuid returned. It
    // made every vendor-leaf stub silently ineffective while leaving the
    // hypervisor-bit stub working, which is exactly the split observed.
    //
    //   cmp eax, 0x40000000     ; 3D 00 00 00 40
    //   jb  .not_vendor         ; 72 xx   (unsigned: below the vendor space)
    //   xor eax,eax / xor ebx,ebx / xor ecx,ecx / xor edx,edx
    //   jmp .done
    // .not_vendor:
    //   and ecx, 0x7FFFFFFF     ; clear the hypervisor-present bit only
    // .done:
    f.code.insert(f.code.end(), {0x3D, 0x00, 0x00, 0x00, 0x40});   // cmp eax, 0x40000000
    const size_t jb_at = f.code.size();
    f.code.insert(f.code.end(), {0x72, 0x00});                     // jb rel8, patched below

    f.code.insert(f.code.end(), {0x31, 0xC0, 0x31, 0xDB, 0x31, 0xC9, 0x31, 0xD2});
    const size_t jmp_at = f.code.size();
    f.code.insert(f.code.end(), {0xEB, 0x00});                     // jmp rel8, patched below

    const size_t and_at = f.code.size();
    f.code.insert(f.code.end(), {0x81, 0xE1, 0xFF, 0xFF, 0xFF, 0x7F});  // and ecx, 0x7FFFFFFF

    const size_t done_at = f.code.size();

    // A vendor leaf at or above 0x40000000 falls to the zeroing; anything below
    // (leaf 0, leaf 1, ...) only has its hypervisor bit cleared.
    f.code[jb_at + 1] = static_cast<uint8_t>(static_cast<int>(and_at) -
                                             static_cast<int>(jb_at + 2));
    f.code[jmp_at + 1] = static_cast<uint8_t>(static_cast<int>(done_at) -
                                              static_cast<int>(jmp_at + 2));

    f.what = "ecx bit31 cleared (leaf 1), hypervisor vendor leaves zeroed";
    return f;
}

// rdtsc / rdtscp: collapse the delta.
//
// A timing check asks "how long did these instructions take". Returning the same
// counter for every reading makes every delta zero, which is the tightest
// possible answer and the one a fast bare-metal machine would produce. edx is
// zeroed too, so the 64-bit value is consistent.
filter_bytes tsc_filter() {
    filter_bytes f;
    // xor eax,eax ; xor edx,edx        -> the whole 64-bit counter reads 0
    f.code.insert(f.code.end(), {0x31, 0xC0, 0x31, 0xD2});
    f.what = "eax:edx zeroed - every timestamp reads 0, so every measured delta is 0";
    return f;
}

// sidt / sgdt / sldt / str / smsw: replace the descriptor-table value with a
// plausible bare-metal-looking one.
//
// These instructions write their result to a memory operand, which means the
// filter cannot fix the value in a register - the value is already in the
// target's buffer by the time the stub regains control. The honest answer is
// that this needs a different technique: the memory the instruction wrote is
// known, so the stub clears the parts a check looks at.
//
// For a 10-byte descriptor (`sidt [rsp-0x0A]`) the check reads the base address;
// a hypervisor's IDT/GDT sits at an address whose high bits look nothing like a
// native one. Writing a synthetic-but-plausible base over it is what defeats the
// Red Pill family. We cannot do that generically without knowing the operand
// register, so instead the stub is not armed for these and the report says why.
filter_bytes none_filter(const std::string& why) {
    filter_bytes f;
    f.what = why;
    return f;
}

} // namespace

// KUSER_SHARED_DATA read -> frozen value in the same register.
//
// These sites need a fundamentally simpler treatment than cpuid/rdtsc, and the
// difference is worth stating: the instruction is a pure load of one absolute
// address into one register, so it can be replaced IN PLACE by an immediate move
// to that same register. No stub page, no jump, no displaced instructions, no
// range constraint, no relocation - and none of the two bugs that dominated the
// instruction stubs (filter ordering and RIP displacement).
//
//   original:  8B 04 25 04 00 FE 7F     mov eax,[0x7FFE0004]      (7 bytes)
//   replaced:  B8 xx xx xx xx 90 90     mov eax,imm32 ; nop nop   (7 bytes)
//
// The equal length is the whole trick: the next instruction keeps its address, so
// nothing else in the target's code shifts.
//
// The destination register is in the modrm byte, which is why the catalog has one
// entry per destination instead of a wildcard - the replacement must name the same
// register.
filter_bytes kuser_filter(const std::vector<uint8_t>& original, uint32_t frozen_value) {
    filter_bytes f;

    // The modrm byte is at index 1; its register field is bits 3..5.
    if (original.size() < 7 || original[0] != 0x8B) {
        f.what = "not a KUSER load";
        return f;   // an empty body means "cannot build"
    }
    const uint8_t reg = static_cast<uint8_t>((original[1] >> 3) & 0x07);

    f.code.push_back(static_cast<uint8_t>(0xB8 + reg));   // mov r32, imm32
    for (int i = 0; i < 4; ++i) {
        f.code.push_back(static_cast<uint8_t>((frozen_value >> (8 * i)) & 0xFF));
    }
    while (f.code.size() < original.size()) f.code.push_back(0x90);

    f.what = "KUSER tick read replaced by a frozen immediate (in place, same length)";
    return f;
}

std::string default_spoof_for(const std::string& probe) {
    if (probe == "cpuid")  return "ecx bit31 cleared, vendor leaf zeroed";
    if (probe == "rdtsc" || probe == "rdtscp") return "timestamps forced to 0 (zero delta)";
    if (probe == "vmware_backdoor") return "backdoor IN not taken: EBX left non-'VMXh'";
    if (probe == "kuser_addrload") {
        // Measured on this toolchain: `*(volatile DWORD*)0x7FFE0004` compiles to
        //   mov ebx, 0x7FFE0004
        //   mov edi, dword ptr [rbx]      <- register-indirect, no address in the bytes
        // The load cannot be patched (the target needs that address to read the
        // page) and the read cannot be recognised from its own bytes, so this is
        // discovery: it tells a caller where the shared page address enters the
        // target, which is the one instruction before the read they need to trap.
        return "KUSER shared-page address load: discovery only - the register-indirect "
               "read that follows carries no address, so patch the read site (find it "
               "with a breakpoint on this instruction and follow the register) or use "
               "timers to cover the API path";
    }
    return "memory-operand probe - needs a per-site filter, discovery only";
}

nlohmann::json arm(c_bridge_executor& bridge, const std::string& module,
                   const std::vector<std::string>& probes, size_t max_hits) {
    if (!bridge.require_paused()) {
        return nlohmann::json{{"ok", false},
                              {"error", "the target must be paused: stubs are written into "
                                        "live code and patching while it runs races the "
                                        "target's own writes"}};
    }
    if (!code_stub::supported()) {
        return nlohmann::json{
            {"ok", false},
            {"supported", false},
            {"error", "instruction stubs are x64 only: the emitted filter sequences are "
                      "x64 encodings, and on x86 the displaced instructions use different "
                      "operand forms"}
        };
    }
    if (max_hits == 0) max_hits = 1;
    if (max_hits > 500) max_hits = 500;

    // Which probes were asked for. Empty means "all stubbable ones", which is
    // the useful default: the catalog is already limited to unambiguous sites.
    auto wanted = [&](const std::string& name) {
        if (probes.empty()) return true;
        return std::find(probes.begin(), probes.end(), name) != probes.end();
    };

    const auto scan = probe_scan::scan(bridge, module, max_hits + 1);
    if (scan.contains("error")) {
        return nlohmann::json{{"ok", false},
                              {"error", scan["error"].get<std::string>()}};
    }

    nlohmann::json armed = nlohmann::json::array();
    nlohmann::json skipped = nlohmann::json::array();
    size_t per_probe = 0;
    std::string current_probe;

    for (const auto& hit : scan["hits"]) {
        const auto probe = hit.value("probe", std::string());
        const auto addr_str = hit["address"].get<std::string>();
        const duint site = format_utils::parse_address(addr_str);

        if (!wanted(probe)) continue;
        if (!hit.value("stubbable", false)) {
            skipped.push_back({{"probe", probe}, {"address", addr_str},
                               {"reason", "not stubbable: " + default_spoof_for(probe)}});
            continue;
        }

        if (probe != current_probe) { current_probe = probe; per_probe = 0; }
        if (per_probe >= max_hits) {
            skipped.push_back({{"probe", probe}, {"address", addr_str},
                               {"reason", "max_hits reached for this probe"}});
            continue;
        }

        // ---- choose the filter -------------------------------------------
        filter_bytes filter;

        // KUSER_SHARED_DATA loads are handled first and differently: replace the
        // load in place with an immediate move of the same length. No stub page,
        // no jump, no relocation - see kuser_filter().
        const int kuser_off = hit.value("kuser_offset", -1);
        if (kuser_off >= 0) {
            auto orig = bridge.read_memory(site, static_cast<size_t>(hit.value("size", 0)));
            if (!orig.has_value() || orig->size() < 7) {
                skipped.push_back({{"probe", probe}, {"address", addr_str},
                                   {"reason", "cannot read the KUSER load"}});
                continue;
            }

            // The frozen value must not be zero: a tick counter reading exactly 0
            // after boot is its own fingerprint. Derived from the site address so
            // different sites differ, and stable for the session so every delta is
            // still exactly zero.
            const uint32_t frozen =
                (static_cast<uint32_t>(site >> 4) ^ 0x9E3779B9u) | 1u;

            filter = kuser_filter(*orig, frozen);
            if (filter.code.empty()) {
                skipped.push_back({{"probe", probe}, {"address", addr_str},
                                   {"reason", "not the expected mov-from-absolute form"}});
                continue;
            }

            if (!bridge.write_memory(site, filter.code).has_value()) {
                skipped.push_back({{"probe", probe}, {"address", addr_str},
                                   {"reason", "in-place write failed"}});
                continue;
            }
            auto after_inplace = bridge.read_memory(site, filter.code.size());
            if (!after_inplace.has_value() || *after_inplace != filter.code) {
                (void)bridge.write_memory(site, *orig);
                skipped.push_back({{"probe", probe}, {"address", addr_str},
                                   {"reason", "the in-place patch did not stick - reverted"}});
                continue;
            }

            armed.push_back({
                {"probe",     probe},
                {"address",   addr_str},
                {"stub",      "in-place (no stub page)"},
                {"spoof",     filter.what},
                {"frozen_at", format_utils::format_hex(frozen)},
                {"verified",  true},
                {"displaced", 0}
            });

            {
                std::lock_guard<std::mutex> lock(g_mutex);
                armed_stub rec_inplace;
                rec_inplace.probe = probe;
                rec_inplace.site = site;
                rec_inplace.stub = 0;          // no stub page
                rec_inplace.spoof = filter.what;
                rec_inplace.patch = filter.code;
                rec_inplace.original = *orig;
                g_armed[site] = rec_inplace;
            }
            ++per_probe;
            continue;
        }

        if (probe == "cpuid") {
            filter = cpuid_filter();
        } else if (probe == "rdtsc" || probe == "rdtscp") {
            filter = tsc_filter();
        } else if (probe == "vmware_backdoor") {
            // The detected prefix is the `mov dx,0x5658`; the BACKDOOR is the
            // following `in`. Arm on the `in`, which is where registers can be
            // changed. Read forward to find it rather than assuming a distance.
            DISASM_INSTR after{};
            DbgDisasmAt(site + static_cast<duint>(hit.value("size", 0)), &after);
            if (after.instr_size <= 0 || _stricmp(after.instruction, "in") != 0) {
                skipped.push_back({{"probe", probe}, {"address", addr_str},
                                   {"reason", "no `in` instruction directly after the "
                                              "0x5658 load - pattern matched but the "
                                              "backdoor sequence is not intact"}});
                continue;
            }
            // A real IN returns 'VMXh' in EBX; on metal it raises #GP. Leaving
            // the registers as the IN returns them on this host means the target
            // sees whatever the hypervisor actually answers - which is the truth
            // and is what we must change. Clearing ebx is the minimal spoof.
            filter.code = {0x31, 0xDB};    // xor ebx, ebx
            filter.what = "ebx zeroed - the 'VMXh' magic is gone";
        } else {
            skipped.push_back({{"probe", probe}, {"address", addr_str},
                               {"reason", default_spoof_for(probe)}});
            continue;
        }

        // ---- build the stub ----------------------------------------------
        // The entry patch is a 5-byte relative jump, so `prepare` must displace at
        // least 5 bytes of WHOLE instructions - for a 2-byte probe that means it
        // also copies the instruction after it onto the stub.
        //
        // That is correct and necessary (those bytes would otherwise be lost), but
        // it dictates the stub layout, and getting this wrong is what made the
        // first version silently ineffective:
        //
        //   WRONG:  [probe][following instructions...][filter][jmp back]
        //   RIGHT:  [probe][filter][following instructions...][jmp back]
        //
        // With the filter last, the target's own next instruction ran first and
        // consumed the probe's output. Measured on the test target: `cpuid` was
        // displaced together with its `shr ecx, 0x1F`, so by the time the filter
        // ran, ecx had already been shifted and `and ecx, 0x7FFFFFFF` operated on
        // a value that no longer held the hypervisor bit - the check still saw a VM.
        // The filter has to see the raw instruction output, before anything the
        // target does with it.
        const size_t probe_len = static_cast<size_t>(hit.value("size", 0));
        if (probe_len == 0 || probe_len > 16) {
            skipped.push_back({{"probe", probe}, {"address", addr_str},
                               {"reason", "unknown instruction length"}});
            continue;
        }

        // min_bytes stays at the jump size so the displaced region can hold the
        // patch; code_stub grows it to whole instructions.
        auto prepared = code_stub::prepare(bridge, site, 5);
        if (!prepared.has_value()) {
            skipped.push_back({{"probe", probe}, {"address", addr_str},
                               {"reason", prepared.error()}});
            continue;
        }

        auto& p = *prepared;

        // Build the instruction stream the stub will actually run, with every
        // displaced relative branch re-encoded for its new home. Using the raw
        // `displaced` bytes would send those branches to an address measured from
        // the stub instead of from the site.
        std::vector<uint8_t> relocated = p.displaced_with_relocations();

        // Split at the probe. The probe itself is never a branch (it is cpuid /
        // rdtsc / the VMware `in`), so no relocation applies to it and the first
        // `probe_len` bytes are the original encoding.
        if (relocated.size() < probe_len || probe_len == 0) {
            skipped.push_back({{"probe", probe}, {"address", addr_str},
                               {"reason", "displaced region shorter than the probe"}});
            continue;
        }
        const std::vector<uint8_t> probe_bytes(relocated.begin(),
                                              relocated.begin() + probe_len);
        const std::vector<uint8_t> following(relocated.begin() + probe_len,
                                             relocated.end());

        // Stub layout: [probe] [filter] [following instructions] [jmp resume]
        //
        // The filter sits immediately after the probe so it sees the raw output.
        // See the comment above for what goes wrong when it does not.
        std::vector<uint8_t> body;
        body.insert(body.end(), probe_bytes.begin(), probe_bytes.end());
        body.insert(body.end(), filter.code.begin(), filter.code.end());
        body.insert(body.end(), following.begin(), following.end());

        // Where the stub jumps back to. This is patch-derived (see prepared::
        // resume_at), not displaced-derived: a widened branch makes the two differ.
        const duint resume = p.resume_at;
        const auto back = code_stub::jump_patch(p.stub + body.size(), resume);
        body.insert(body.end(), back.begin(), back.end());

        if (!bridge.write_memory(p.stub, body).has_value()) {
            skipped.push_back({{"probe", probe}, {"address", addr_str},
                               {"reason", "failed writing the stub body"}});
            continue;
        }

        if (!bridge.write_memory(site, p.patch).has_value()) {
            skipped.push_back({{"probe", probe}, {"address", addr_str},
                               {"reason", "failed patching the site"}});
            continue;
        }

        // Verify, because a protection layer that re-protects its own code will
        // already have undone the patch - and reporting "armed" would hide it.
        auto after = bridge.read_memory(site, p.patch.size());
        const bool verified = after.has_value() && *after == p.patch;

        armed_stub rec;
        rec.probe = probe;
        rec.site = site;
        rec.stub = p.stub;
        rec.spoof = filter.what;
        rec.patch = p.patch;
        rec.original = p.original;

        armed.push_back({
            {"probe",     probe},
            {"address",   addr_str},
            {"stub",      format_utils::format_address(p.stub)},
            {"spoof",     filter.what},
            {"verified",  verified},
            {"displaced", p.displaced.size()}
        });

        if (verified) {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_armed[site] = rec;
            ++per_probe;
        } else {
            // Put the original bytes back so a re-protected site does not end up
            // with a jump into a stub that will never be used. The result is
            // deliberately unchecked: this is the already-failed path, and the
            // site is reported as skipped either way.
            (void)bridge.write_memory(site, p.original);
            skipped.push_back({{"probe", probe}, {"address", addr_str},
                               {"reason", "the patch did not stick (something restored the "
                                          "page) - reverted"}});
        }
    }

    return nlohmann::json{
        {"ok", true},
        {"module", module},
        {"armed", armed},
        {"count", armed.size()},
        {"skipped", skipped},
        {"note", "Each stub executes the real instruction and then edits what it produced, "
                 "because a breakpoint would fire before the instruction and be overwritten "
                 "by it. Use restore:true (anti_vm against the same module) to write the "
                 "original bytes back."}
    };
}

nlohmann::json disarm(c_bridge_executor& bridge) {
    if (!bridge.require_paused()) {
        return nlohmann::json{{"ok", false},
                              {"error", "the target must be paused to restore stubs"}};
    }

    std::map<duint, armed_stub> taken;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        taken.swap(g_armed);
    }

    if (taken.empty()) {
        return nlohmann::json{{"ok", true}, {"restored", nlohmann::json::array()},
                              {"message", "no stubs were armed"}};
    }

    nlohmann::json restored = nlohmann::json::array();
    nlohmann::json failed = nlohmann::json::array();

    for (auto& [site, rec] : taken) {
        if (!bridge.write_memory(site, rec.original).has_value()) {
            failed.push_back({{"probe", rec.probe},
                              {"address", format_utils::format_address(site)},
                              {"reason", "write failed"}});
            continue;
        }
        auto after = bridge.read_memory(site, rec.original.size());
        if (after.has_value() && *after == rec.original) {
            restored.push_back({{"probe", rec.probe},
                                {"address", format_utils::format_address(site)}});
        } else {
            failed.push_back({{"probe", rec.probe},
                              {"address", format_utils::format_address(site)},
                              {"reason", "original bytes did not stick"}});
        }
    }

    if (!failed.empty()) {
        std::lock_guard<std::mutex> lock(g_mutex);
        for (auto& [site, rec] : taken) {
            const bool was_failed = std::any_of(
                failed.begin(), failed.end(),
                [&](const auto& f) { return f["address"] == format_utils::format_address(site); });
            if (was_failed) g_armed[site] = rec;
        }
    }

    return nlohmann::json{{"ok", failed.empty()}, {"restored", restored}, {"failed", failed}};
}

// Session-teardown path.
//
// Restoring needs a live process AND a writable page; neither is guaranteed here.
// What IS guaranteed to matter is that the registry is emptied: a stale entry
// would be restored into whatever process occupies that address next session.
// So the bytes are written back only when the session is still alive, and the
// registry is cleared unconditionally.
nlohmann::json teardown(c_bridge_executor& bridge) {
    std::map<duint, armed_stub> taken;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        taken.swap(g_armed);
    }

    if (taken.empty()) {
        return nlohmann::json{{"ok", true}, {"restored", nlohmann::json::array()},
                              {"count", 0}, {"message", "no stubs were armed"}};
    }

    // A terminated target cannot be written to; that is the ordinary case (the
    // debugger killed it) and is not a failure worth reporting as one.
    const bool live = bridge.is_debugging();
    const bool paused = live && !bridge.is_running();

    nlohmann::json restored = nlohmann::json::array();
    nlohmann::json failed = nlohmann::json::array();
    size_t written = 0;

    if (live) {
        for (auto& [site, rec] : taken) {
            if (bridge.write_memory(site, rec.original).has_value()) {
                ++written;
                restored.push_back({{"probe", rec.probe},
                                    {"address", format_utils::format_address(site)}});
            } else if (paused) {
                failed.push_back({{"probe", rec.probe},
                                  {"address", format_utils::format_address(site)},
                                  {"reason", "write failed"}});
            }
        }
    }

    return nlohmann::json{
        {"ok", failed.empty()},
        {"restored", restored},
        {"failed", failed},
        {"count", written},
        {"process_gone", !live},
        {"message", live
            ? "original bytes written back for " + std::to_string(written) + " stub(s)"
            : "the target had already exited; registry cleared so the addresses are not "
              "restored into a future process"}
    };
}

nlohmann::json list() {
    std::lock_guard<std::mutex> lock(g_mutex);
    nlohmann::json out = nlohmann::json::array();
    for (const auto& [site, rec] : g_armed) {
        out.push_back({
            {"probe",   rec.probe},
            {"address", format_utils::format_address(site)},
            {"stub",    format_utils::format_address(rec.stub)},
            {"spoof",   rec.spoof}
        });
    }
    return nlohmann::json{{"stubs", out}, {"count", out.size()}};
}

} // namespace anti_vm
