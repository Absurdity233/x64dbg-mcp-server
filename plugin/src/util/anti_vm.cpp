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
// This is the layout the target sees as the instant after the real cpuid ran:
//
//   cmp eax, 0x40000000
//   jne  .not_vendor
//   xor eax,eax / xor ebx,ebx / xor ecx,ecx / xor edx,edx   ; vendur leaf -> absent
//   jmp  .done
// .not_vendor:
//   and ecx, 0x7FFFFFFF                                     ; clear bit 31
// .done:
//
// The branch displacements are COMPUTED, not written by hand. Hand-counted rel8
// offsets are how this first shipped broken: a two-byte miscount made `jne` land
// in the middle of `and ecx, imm32`, and the target died with
// STATUS_ILLEGAL_INSTRUCTION (0xC000001D) at the stub. A patch cannot express the
// intent, so the offsets are derived from the actual instruction lengths.
filter_bytes cpuid_filter() {
    filter_bytes f;

    // cmp eax, 0x40000000
    f.code.insert(f.code.end(), {0x3D, 0x00, 0x00, 0x00, 0x40});
    const size_t jne_at = f.code.size();
    f.code.insert(f.code.end(), {0x75, 0x00});          // jne rel8, patched below

    // vendor leaf -> all four registers zeroed ("no hypervisor vendor")
    f.code.insert(f.code.end(), {0x31, 0xC0, 0x31, 0xDB, 0x31, 0xC9, 0x31, 0xD2});
    const size_t jmp_at = f.code.size();
    f.code.insert(f.code.end(), {0xEB, 0x00});          // jmp rel8, patched below

    // not the vendor leaf: clear the hypervisor-present bit only, so the feature
    // bits the target reads next stay intact
    const size_t and_at = f.code.size();
    f.code.insert(f.code.end(), {0x81, 0xE1, 0xFF, 0xFF, 0xFF, 0x7F});   // and ecx, 0x7FFFFFFF

    const size_t done_at = f.code.size();

    // jne -> .not_vendor (the `and`)
    const auto jne_disp = static_cast<int8_t>(static_cast<int>(and_at) -
                                              static_cast<int>(jne_at + 2));
    f.code[jne_at + 1] = static_cast<uint8_t>(jne_disp);

    // jmp -> .done (past the `and`)
    const auto jmp_disp = static_cast<int8_t>(static_cast<int>(done_at) -
                                              static_cast<int>(jmp_at + 2));
    f.code[jmp_at + 1] = static_cast<uint8_t>(jmp_disp);

    f.what = "ecx bit31 cleared (leaf 1), vendor leaf 0x40000000 zeroed";
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

std::string default_spoof_for(const std::string& probe) {
    if (probe == "cpuid")  return "ecx bit31 cleared, vendor leaf zeroed";
    if (probe == "rdtsc" || probe == "rdtscp") return "timestamps forced to 0 (zero delta)";
    if (probe == "vmware_backdoor") return "backdoor IN not taken: EBX left non-'VMXh'";
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

        // Split the displaced region at the probe instruction. `displaced` holds
        // whole instructions starting at the site, and the probe is the first of
        // them, so its length is the split point.
        if (p.displaced.size() < probe_len) {
            skipped.push_back({{"probe", probe}, {"address", addr_str},
                               {"reason", "displaced region shorter than the probe"}});
            continue;
        }
        const std::vector<uint8_t> probe_bytes(p.displaced.begin(),
                                               p.displaced.begin() + probe_len);
        const std::vector<uint8_t> following(p.displaced.begin() + probe_len,
                                             p.displaced.end());

        // Stub layout: [probe] [filter] [following instructions] [jmp resume]
        //
        // The filter sits immediately after the probe so it sees the raw output.
        // See the comment above for what goes wrong when it does not.
        std::vector<uint8_t> body;
        body.insert(body.end(), probe_bytes.begin(), probe_bytes.end());
        body.insert(body.end(), filter.code.begin(), filter.code.end());
        body.insert(body.end(), following.begin(), following.end());

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
