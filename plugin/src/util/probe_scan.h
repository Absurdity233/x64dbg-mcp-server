#pragma once

// Locating the instructions a VM/anti-debug check inspects the machine with.
//
// Kept in one place because two very different consumers need the same answer:
// the discovery route (tell me where the checks are) and the stub engine (make
// this check return something else). Two copies of this table would drift, and
// a stub armed on a site the discovery route does not report is unfalsifiable.
//
// The scan only CONFIRMS a candidate: a raw byte match is not an instruction,
// because the same bytes appear inside displacements, immediates and data. Each
// candidate goes through the disassembler and must produce the expected
// mnemonic.

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "bridge/c_bridge_executor.h"

namespace probe_scan {

struct probe_spec {
    const char* name;        // stable id used by callers ("cpuid", "vmware_backdoor")
    const char* mnemonic;    // the mnemonic the disassembler must print
    const char* detects;     // what the instruction reveals about the machine
    // Fixed opcode prefix. `wildcard_tail` means the bytes after the prefix
    // (a ModRM or a displacement) vary, so only the prefix is matched.
    std::vector<uint8_t> bytes;
    bool wildcard_tail;
    // Can a stub change the answer, or is this a discovery-only site?
    bool stubbable;
    // The instruction reads KUSER_SHARED_DATA through an ABSOLUTE address, so it
    // bypasses every API hook. `kuser_offset` is the field offset (0x4 = low tick,
    // 0x320 = 64-bit tick); `kuser_dest` names the destination register class so a
    // stub can substitute a frozen value without touching the addressing.
    //
    // Why this cannot be handled by an API stub: the whole point of reading the
    // shared page is to avoid the syscall and the export. Measured on 26200:
    // kernel32.GetTickCount64 itself is `mov ecx,[0x7FFE0004]`, and a scan of a
    // running process finds 20+ such sites outside any timer API.
    int  kuser_offset = -1;   // -1 = not a KUSER read
    int  dest_is_64 = 0;      // 0 = 32-bit destination (eax/ecx/edx/...), 1 = rax/...
};

// The table. Only unambiguous encodings belong here: a single-byte opcode such
// as `in` (0xEC) matches arbitrary displacement bytes in unrelated code, which
// is how a naive scan of winver.exe reports twenty "VMware backdoor" hits.
const std::vector<probe_spec>& catalog();

// Scan a module's executable sections. Returns { module, base, hits, count,
// total_matches, truncated, note } where each hit is { instruction, detects,
// section, address, offset, stubbable }.
nlohmann::json scan(c_bridge_executor& bridge, const std::string& module_name,
                    size_t max_hits_per_pattern);

// Find the probe_spec for a mnemonic, or null.
const probe_spec* find(const std::string& mnemonic);

} // namespace probe_scan
