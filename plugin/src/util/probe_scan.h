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
