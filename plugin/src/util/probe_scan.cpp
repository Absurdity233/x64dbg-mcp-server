#include "util/probe_scan.h"

#include <algorithm>
#include <cstring>

#include <windows.h>

#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "_scriptapi_module.h"
#include "util/format_utils.h"

namespace probe_scan {

const std::vector<probe_spec>& catalog() {
    static const std::vector<probe_spec> specs = {
        // --- CPU identity ---------------------------------------------------
        {"cpuid",  "cpuid",  "hypervisor-present bit (leaf 1, ecx bit 31) and the vendor leaf "
                   "0x40000000; the most-used VM check there is",
         {0x0F, 0xA2}, false, true},

        // --- Timing ---------------------------------------------------------
        {"rdtsc",  "rdtsc", "cycle counter; a delta across a region exposes single-stepping, "
                   "breakpoint traps and a slow (emulated) hypervisor",
         {0x0F, 0x31}, false, true},
        {"rdtscp", "rdtscp", "serialising timing variant; same checks as rdtsc, harder to fool "
                   "with a plain instruction counter",
         {0x0F, 0x01, 0xF9}, false, true},

        // --- Descriptor tables ----------------------------------------------
        // sidt/sgdt take a memory operand, so the ModRM/displacement bytes vary;
        // match only the fixed 0F 01 prefix and let the disassembler confirm.
        {"sidt",   "sidt", "IDT base; a hypervisor that relocates the IDT is visible here "
                   "(the classic Red Pill check)",
         {0x0F, 0x01, 0x0D}, true, true},
        {"sidt",   "sidt", "IDT base via the alternate ModRM form",
         {0x0F, 0x01, 0x1D}, true, true},
        {"sgdt",   "sgdt", "GDT base; relocated by hypervisors",
         {0x0F, 0x01, 0x05}, true, true},
        {"sgdt",   "sgdt", "GDT base via the alternate ModRM form",
         {0x0F, 0x01, 0x15}, true, true},
        {"sldt",   "sldt", "LDT selector; zero or an implausible value under a hypervisor",
         {0x0F, 0x00, 0xC0}, false, true},
        {"str",    "str", "task register; 0 under many hypervisors, and the classic "
                   "VMware-backdoor companion check",
         {0x0F, 0x00, 0xC8}, false, true},
        {"smsw",   "smsw", "CR0 via SMSW; the VM86/monitor bit differs on some hypervisors",
         {0x0F, 0x01, 0xE0}, false, true},

        // --- VMware backdoor port --------------------------------------------
        // The detection is `mov dx, 0x5658` followed by `in eax, dx`: the IN is
        // what returns the "VMXh" magic in EBX on a VMware guest, and what
        // raises #GP on real hardware (IN is privileged). We match the MOV
        // because 0x5658 in the operand is what makes the site unambiguous;
        // the stub is armed on the following IN, which is the only place the
        // returned registers can be changed. Matching a bare 0xED (`in eax,dx`)
        // would hit ordinary code.
        {"vmware_backdoor", "mov dx, 0x5658", "VMware backdoor probe: DX=0x5658 then IN; on a guest EBX becomes 'VMXh', "
         "on metal the IN faults - the strongest single VM indicator there is",
         {0x66, 0xBA, 0x58, 0x56}, false, true},
    };
    return specs;
}

const probe_spec* find(const std::string& name) {
    for (const auto& s : catalog()) {
        if (name == s.name) return &s;
    }
    return nullptr;
}

nlohmann::json scan(c_bridge_executor& bridge, const std::string& module_name,
                    size_t max_hits_per_pattern) {
    const auto base = bridge.get_module_base(module_name);
    if (base == 0) return nlohmann::json{{"error", "module not found: " + module_name}};

    auto dos = bridge.read_memory(base, 0x40);
    if (!dos.has_value() || dos->size() < 0x40) {
        return nlohmann::json{{"error", "cannot read DOS header"}};
    }
    uint32_t e_lfanew = 0;
    std::memcpy(&e_lfanew, dos->data() + 0x3C, 4);

    auto pe = bridge.read_memory(base + e_lfanew, 24);
    if (!pe.has_value() || pe->size() < 24) {
        return nlohmann::json{{"error", "cannot read PE header"}};
    }
    uint16_t num_sections = 0, opt_size = 0;
    std::memcpy(&num_sections, pe->data() + 6, 2);
    std::memcpy(&opt_size, pe->data() + 20, 2);
    if (num_sections == 0 || num_sections > 96) {
        return nlohmann::json{{"error", "implausible section count"}};
    }

    const duint section_table = base + e_lfanew + 24 + opt_size;
    auto sec_headers = bridge.read_memory(section_table, static_cast<size_t>(num_sections) * 40);
    if (!sec_headers.has_value()) {
        return nlohmann::json{{"error", "cannot read section table"}};
    }

    nlohmann::json results = nlohmann::json::array();
    size_t total = 0;

    for (uint16_t i = 0; i < num_sections; ++i) {
        const size_t off = static_cast<size_t>(i) * 40;
        uint32_t va = 0, vsize = 0, raw_size = 0, chars = 0;
        char name[9] = {};
        std::memcpy(name, sec_headers->data() + off, 8);
        std::memcpy(&vsize, sec_headers->data() + off + 8, 4);
        std::memcpy(&va, sec_headers->data() + off + 12, 4);
        std::memcpy(&raw_size, sec_headers->data() + off + 16, 4);
        std::memcpy(&chars, sec_headers->data() + off + 36, 4);

        if (!(chars & IMAGE_SCN_MEM_EXECUTE)) continue;

        const uint32_t span = vsize ? vsize : raw_size;
        if (span == 0 || span > 64u * 1024 * 1024) continue;

        auto code = bridge.read_memory(base + va, span);
        if (!code.has_value()) continue;
        const auto& buf = *code;

        for (const auto& p : catalog()) {
            size_t hits = 0;
            if (buf.size() < p.bytes.size()) continue;

            for (size_t k = 0; k + p.bytes.size() <= buf.size(); ++k) {
                if (std::memcmp(buf.data() + k, p.bytes.data(), p.bytes.size()) != 0) continue;

                // A raw byte match is not an instruction. Ask the disassembler
                // what actually starts here and require the mnemonic to agree.
                const duint at = base + va + k;
                DISASM_INSTR di{};
                DbgDisasmAt(at, &di);
                if (di.instr_size <= 0 || _stricmp(di.instruction, p.mnemonic) != 0) {
                    continue;
                }

                if (hits < max_hits_per_pattern) {
                    results.push_back({
                        {"probe",       std::string(p.name)},
                        {"instruction", std::string(di.instruction)},
                        {"detects",     std::string(p.detects)},
                        {"section",     name},
                        {"address",     format_utils::format_address(at)},
                        {"offset",      format_utils::format_hex(va + k)},
                        {"disasm",      std::string(di.instruction)},
                        {"size",        di.instr_size},
                        {"stubbable",   p.stubbable}
                    });
                }
                ++hits;
                ++total;
                k += p.bytes.size() - 1;
            }
        }
    }

    return nlohmann::json{
        {"module",        module_name},
        {"base",          format_utils::format_address(base)},
        {"hits",          results},
        {"count",         results.size()},
        {"total_matches", total},
        {"truncated",     results.size() < total},
        {"note", "Locations only - nothing was patched or faked. Set a breakpoint on an "
                 "address above and inspect the registers when it fires to see what the "
                 "check decides; use anti_vm to make the check return something else."}
    };
}

} // namespace probe_scan
