#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "bridgelist.h"
#include "_scriptapi_module.h"
// State-requirement policy for this file.
//
// Anything that writes into the debuggee (branch_patch, iat_redirect) demands a PAUSED target:
// patching while the target runs races the code executing, so the byte overwritten may be the one
// about to be fetched, and a read-back can confirm bytes the CPU already fetched past. Pausing
// removes that class of "verified but ineffective" outcomes. sig_make only reads (bytes +
// disassembly), so a live session without a pause is enough - the pattern is a snapshot of the
// module as loaded. compare_trace changes debugger state (breakpoints), not target memory, and
// x64dbg accepts breakpoint commands while the target runs.
namespace handlers {
namespace {
constexpr size_t kMaxSigBytes      = 128;
constexpr int    kDefaultSigBytes  = 32;
constexpr size_t kMaxSigMatches    = 8;     // enough to disprove uniqueness
constexpr size_t kMaxBranchRecords = 4096;
constexpr size_t kMaxIatModules    = 32;
constexpr size_t kMaxThunks        = 4096;
constexpr int    kMaxCompareSites  = 256;
constexpr int    kDefaultMaxSites  = 64;
constexpr size_t kPtrSize          = sizeof(duint);
constexpr duint  kScanCap          = 64u * 1024 * 1024;

// Restore bookkeeping. x64dbg has its own patch database, but it does not know that a branch was
// rewritten as a *branch* rather than as an arbitrary byte patch. Keeping our own keyed copy means
// `restore` puts back what we ourselves found, even if something else also wrote to that page (a
// packer stub, a protection layer).
std::mutex                            g_state_lock;
std::map<duint, std::vector<uint8_t>> g_branch_originals;
std::deque<duint>                     g_branch_order;      // FIFO eviction
std::map<duint, duint>                g_iat_originals;     // slot -> original
std::map<std::string, std::pair<duint, bool>> g_stubs;      // "mode:value" -> (page, prot_ok)

struct sig_byte { uint8_t value = 0; bool wildcard = false; };
struct module_range { duint base = 0; duint size = 0; std::string name; };

bool in_module_range(duint value, const std::vector<module_range>& mods) {
    for (const auto& m : mods) if (value >= m.base && value < m.base + m.size) return true;
    return false;
}
// Every loaded module with its virtual extent: "does this immediate look like an address" for
// sig_make, and the walk list for the IAT scan.
std::vector<module_range> list_modules() {
    std::vector<module_range> out;
    BridgeList<Script::Module::ModuleInfo> list;
    if (!Script::Module::GetList(&list)) return out;
    for (int i = 0; i < list.Count(); ++i) {
        const auto& info = list[static_cast<size_t>(i)];
        if (info.base == 0 || info.size == 0) continue;
        out.push_back({info.base, info.size, std::string(info.name)});
    }
    return out;
}

std::string to_lower(std::string s) {
    for (char& c : s) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}
// nlohmann's value() throws on a type mismatch, and a throw escaping a route handler would
// unwind into the HTTP server loop. Every body read is type-checked instead.
bool get_bool(const nlohmann::json& b, const char* key, bool fallback) {
    if (!b.contains(key)) return fallback;
    const auto& v = b[key];
    return v.is_boolean() ? v.get<bool>() : fallback;
}

std::string get_string(const nlohmann::json& b, const char* key, const std::string& fb = {}) {
    if (!b.contains(key)) return fb;
    const auto& v = b[key];
    return v.is_string() ? v.get<std::string>() : fb;
}

int get_int(const nlohmann::json& b, const char* key, int fallback) {
    if (!b.contains(key)) return fallback;
    const auto& v = b[key];
    if (v.is_number_integer()) return v.get<int>();
    if (v.is_number_unsigned()) return static_cast<int>(v.get<unsigned>());
    // Accept "0x40" and "64": base is inferred.
    if (v.is_string()) return static_cast<int>(std::strtol(v.get<std::string>().c_str(), nullptr, 0));
    return fallback;
}
// Wildcard matcher, same shape as search_handler.cpp's. Duplicated rather than shared because
// that one is file-local and this file must not require another handler to change.
std::vector<size_t> scan_buffer(const uint8_t* buf, size_t buf_size,
                                const std::vector<sig_byte>& pattern,
                                size_t max_hits, bool& truncated) {
    std::vector<size_t> hits;
    truncated = false;
    if (pattern.empty() || buf_size < pattern.size()) return hits;
    const size_t pat_len = pattern.size();
    for (size_t i = 0; i + pat_len <= buf_size; ++i) {
        bool match = true;
        for (size_t j = 0; j < pat_len; ++j) {
            if (!pattern[j].wildcard && buf[i + j] != pattern[j].value) { match = false; break; }
        }
        if (!match) continue;
        hits.push_back(i);
        if (hits.size() >= max_hits) { truncated = true; break; }
    }
    return hits;
}

std::string format_pattern(const std::vector<sig_byte>& pattern) {
    std::string out;
    out.reserve(pattern.size() * 3);
    for (size_t i = 0; i < pattern.size(); ++i) {
        if (i) out += ' ';
        if (pattern[i].wildcard) { out += "??"; continue; }
        char buf[4];
        snprintf(buf, sizeof(buf), "%02X", static_cast<unsigned>(pattern[i].value));
        out += buf;
    }
    return out;
}
// The SDK reports the total instruction size but not the opcode/operand split, and only the
// opcode half is position-independent. Walk the legacy prefixes, an optional REX byte and the
// (up to three byte) opcode; ModRM, SIB, displacement and immediate is what a rebase changes.
size_t opcode_length(const std::vector<uint8_t>& code) {
    if (code.empty()) return 0;
    size_t i = 0;
    while (i < code.size()) {
        const uint8_t b = code[i];
        const bool legacy = (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
                             b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 ||
                             b == 0x65);
        if (!legacy && !(b >= 0x40 && b <= 0x4F)) break;
        ++i;
    }
    if (i >= code.size()) return code.size();
    if (code[i] == 0x0F && i + 1 < code.size()) {
        const uint8_t op2 = code[i + 1];
        if ((op2 == 0x38 || op2 == 0x3A) && i + 2 < code.size()) return i + 3;
        return i + 2;
    }
    return i + 1;
}
// Minimal PE section reader. The signature scan needs the executable sections of the *loaded*
// image (the file on disk has a different layout), so headers are parsed out of debuggee
// memory the way antidebug_handler.cpp does it.
struct pe_dirs { bool ok = false; uint32_t e_lfanew = 0; uint16_t num_sections = 0, opt_size = 0; };

pe_dirs read_pe_dirs(c_bridge_executor& bridge, duint base) {
    pe_dirs out;
    auto dos = bridge.read_memory(base, 0x40);
    if (!dos.has_value() || dos->size() < 0x40) return out;
    if ((*dos)[0] != 'M' || (*dos)[1] != 'Z') return out;
    uint32_t e_lfanew = 0;
    std::memcpy(&e_lfanew, dos->data() + 0x3C, 4);
    if (e_lfanew == 0 || e_lfanew > 0x1000) return out;   // implausible header offset

    auto pe = bridge.read_memory(base + e_lfanew, 24);
    if (!pe.has_value() || pe->size() < 24) return out;
    uint32_t sig = 0;
    std::memcpy(&sig, pe->data(), 4);
    if (sig != 0x00004550u) return out;                   // "PE\0\0"
    uint16_t num_sections = 0, opt_size = 0;
    std::memcpy(&num_sections, pe->data() + 6, 2);
    std::memcpy(&opt_size, pe->data() + 20, 2);
    if (num_sections == 0 || num_sections > 96) return out;

    out.ok = true;
    out.e_lfanew = e_lfanew;
    out.num_sections = num_sections;
    out.opt_size = opt_size;
    return out;
}

struct exec_section { duint addr = 0; duint size = 0; std::string name; };

std::vector<exec_section> executable_sections(c_bridge_executor& bridge, duint base, const pe_dirs& dirs) {
    std::vector<exec_section> out;
    if (!dirs.ok) return out;
    const duint table = base + dirs.e_lfanew + 24 + dirs.opt_size;
    auto headers = bridge.read_memory(table, static_cast<size_t>(dirs.num_sections) * 40);
    if (!headers.has_value() || headers->size() < static_cast<size_t>(dirs.num_sections) * 40) return out;
    for (uint16_t i = 0; i < dirs.num_sections; ++i) {
        const size_t off = static_cast<size_t>(i) * 40;
        char name[9] = {};
        uint32_t vsize = 0, va = 0, raw_size = 0, chars = 0;
        std::memcpy(name, headers->data() + off, 8);
        std::memcpy(&vsize, headers->data() + off + 8, 4);
        std::memcpy(&va, headers->data() + off + 12, 4);
        std::memcpy(&raw_size, headers->data() + off + 16, 4);
        std::memcpy(&chars, headers->data() + off + 36, 4);
        if (!(chars & IMAGE_SCN_MEM_EXECUTE)) continue;
        const uint32_t span = vsize ? vsize : raw_size;
        if (span == 0 || span > kScanCap) continue;
        out.push_back({base + va, static_cast<duint>(span), std::string(name)});
    }
    return out;
}
// Every jcc short form is 7x and (7x, 7x+1) are the two halves of one condition, so the
// condition number lives in the low bit of the opcode; the near form moves it to the low bit of
// the second byte. That property is what `invert` relies on.
bool is_cond_jump_opcode(const uint8_t* code, int size) {
    if (size < 2) return false;
    if (code[0] >= 0x70 && code[0] <= 0x7F) return true;
    return code[0] == 0x0F && code[1] >= 0x80 && code[1] <= 0x8F;
}

void remember_branch_original(duint address, const std::vector<uint8_t>& bytes) {
    std::lock_guard<std::mutex> lock(g_state_lock);
    auto it = g_branch_originals.find(address);
    if (it != g_branch_originals.end()) { it->second = bytes; return; }
    // FIFO eviction: an unbounded map is a leak, and the oldest record is the least likely to
    // still be needed.
    while (g_branch_originals.size() >= kMaxBranchRecords && !g_branch_order.empty()) {
        g_branch_originals.erase(g_branch_order.front());
        g_branch_order.pop_front();
    }
    g_branch_originals.emplace(address, bytes);
    g_branch_order.push_back(address);
}

std::vector<uint8_t> recall_branch_original(duint address, bool& found) {
    std::lock_guard<std::mutex> lock(g_state_lock);
    auto it = g_branch_originals.find(address);
    found = (it != g_branch_originals.end());
    return found ? it->second : std::vector<uint8_t>{};
}
// Stub planting for IAT redirection: one page per (mode, value), so ten redirects reuse the
// same six bytes instead of leaving ten executable pages behind in the target - which would
// itself be a detectable anomaly.
struct stub_info { duint page = 0; bool page_rights_set = false; std::string error; };

stub_info stub_for(c_bridge_executor& bridge, const std::string& key, const std::vector<uint8_t>& code) {
    stub_info out;
    {
        std::lock_guard<std::mutex> lock(g_state_lock);
        auto it = g_stubs.find(key);
        if (it != g_stubs.end()) {
            out.page = it->second.first;
            out.page_rights_set = it->second.second;
            return out;
        }
    }
    if (!bridge.exec_command("alloc 0x1000")) {
        out.error = "'alloc 0x1000' was rejected by the debugger (is the target still alive?) - the "
                    "IAT was left untouched";
        return out;
    }
    const duint page = bridge.eval_expression("$result");
    if (page == 0) {
        out.error = "'alloc 0x1000' returned address 0 ($result) - the IAT was left untouched";
        return out;
    }
    auto wrote = bridge.write_memory(page, code);
    if (!wrote.has_value()) { out.error = "stub write into the allocated page failed: " + wrote.error(); return out; }
    // Same discipline as every other write here: the write call returning true only means the
    // API accepted it.
    auto back = bridge.read_memory(page, code.size());
    if (!back.has_value() || *back != code) { out.error = "stub bytes did not read back as written"; return out; }
    // `alloc` commits the region PAGE_EXECUTE_READWRITE already; asking for the rights
    // explicitly records whether a protection layer vetoed it, without treating a veto as a
    // failure.
    const bool prot_ok = DbgFunctions()->SetPageRights(page, "ERW");
    {
        std::lock_guard<std::mutex> lock(g_state_lock);
        g_stubs[key] = {page, prot_ok};
    }
    out.page = page;
    out.page_rights_set = prot_ok;
    return out;
}

struct import_hit { std::string module, name; duint slot = 0; };
struct iat_scan {
    std::vector<import_hit>  hits;
    std::vector<std::string> modules_scanned;
    size_t thunks_examined = 0;
    bool   modules_truncated = false;
};
// Find every import slot whose current value is the target address. The slot VALUE is what
// decides, not the import name: a redirected or forwarded import can sit at a slot whose name
// says something else, and an API reached through a copied thunk has no name entry at all. The
// SDK's GetImports supplies iatVa directly, so only the thunk values have to be read - which is
// the part that differs between the file and the loaded image.
iat_scan find_iat_slots(c_bridge_executor& bridge, duint target) {
    iat_scan result;
    for (const auto& mod : list_modules()) {
        if (result.modules_scanned.size() >= kMaxIatModules) { result.modules_truncated = true; break; }
        result.modules_scanned.push_back(mod.name);

        Script::Module::ModuleInfo info{};
        if (!Script::Module::InfoFromName(mod.name.c_str(), &info)) continue;
        BridgeList<Script::Module::ModuleImport> imports;
        if (!Script::Module::GetImports(&info, &imports)) continue;

        const int count = imports.Count();
        for (int i = 0; i < count; ++i) {
            const auto& imp = imports[static_cast<size_t>(i)];
            if (imp.iatVa == 0) continue;
            if (static_cast<size_t>(++result.thunks_examined) > kMaxThunks) break;

            auto value = bridge.read_memory(imp.iatVa, kPtrSize);
            if (!value.has_value() || value->size() != kPtrSize) continue;
            duint current = 0;
            std::memcpy(&current, value->data(), kPtrSize);
            if (current != target) continue;

            import_hit hit;
            hit.module = mod.name;
            hit.slot = imp.iatVa;
            hit.name = imp.name;
            if (hit.name.empty()) hit.name = bridge.get_label_at(current);
            result.hits.push_back(hit);
        }
    }
    return result;
}

struct sig_instr { duint address = 0; int size = 0; size_t mask_from = 0; };

// One decoded instruction with both the detailed and the fast view of it, because the two
// answer different questions: DISASM_INSTR gives the operand types sig_make masks on,
// BASIC_INSTRUCTION_INFO gives the resolved branch/call target compare_trace needs.
struct decoded_instr {
    duint  address = 0;
    DISASM_INSTR      detail{};
    BASIC_INSTRUCTION_INFO fast{};
    std::vector<uint8_t> bytes;
};

// Walk [start, end) decoding instruction by instruction. Bounded by `limit` instructions and by
// the disassembler's own size sanity check: if the bytes are not really code it hands back
// nonsense sizes, and an unbounded loop on those would hang the HTTP thread.
std::vector<decoded_instr> walk_range(c_bridge_executor& bridge, duint start, duint end, int limit) {
    std::vector<decoded_instr> out;
    duint cur = start;
    for (int i = 0; cur < end && i < limit; ++i) {
        decoded_instr ins;
        ins.address = cur;
        DbgDisasmAt(cur, &ins.detail);
        if (ins.detail.instr_size <= 0 || ins.detail.instr_size > 15) break;
        auto code = bridge.read_memory(cur, static_cast<size_t>(ins.detail.instr_size));
        if (!code.has_value()) break;
        ins.bytes = *code;
        DbgDisasmFastAt(cur, &ins.fast);
        cur += static_cast<duint>(ins.detail.instr_size);
        out.push_back(std::move(ins));
    }
    return out;
}

// Turn a decoded walk into the mask offsets sig_make needs: every byte past the opcode is
// wildcarded when the instruction encodes something a rebase moves.
std::vector<sig_instr> mask_offsets(const std::vector<decoded_instr>& walk,
                                    const std::vector<module_range>& mods) {
    std::vector<sig_instr> out;
    out.reserve(walk.size());
    for (const auto& d : walk) {
        const auto& di = d.detail;
        // Branch/call offsets, ModRM-relative displacements and immediates that land inside a
        // module are what a rebase or a different allocation moves.
        bool relocatable = (di.type == instr_branch) || d.fast.call;
        for (int a = 0; a < di.argcount && a < 3 && !relocatable; ++a) {
            if (di.arg[a].type == arg_memory) relocatable = true;
            else if (di.arg[a].constant != 0 && in_module_range(di.arg[a].constant, mods)) relocatable = true;
        }
        out.push_back({d.address, di.instr_size,
                       relocatable ? opcode_length(d.bytes) : static_cast<size_t>(di.instr_size)});
    }
    return out;
}

bool looks_like_immediate(const char* mnemonic) {
    if (mnemonic == nullptr || mnemonic[0] == '\0') return false;
    const char c = mnemonic[0];
    return (c >= '0' && c <= '9') || c == '-';
}

std::string hex_of(const std::vector<uint8_t>& v) { return format_utils::format_bytes_hex(v.data(), v.size()); }

// Resolve the body's "address" field. Returns "" and sets `address` on success, otherwise the
// message to hand back as a 400 - one wording for all four routes.
std::string resolve_body_address(c_bridge_executor& bridge, const nlohmann::json& body, duint& address) {
    if (!body.contains("address")) return "Missing 'address' field";
    const auto expr = get_string(body, "address");
    if (expr.empty()) return "Missing 'address' field";
    address = bridge.eval_expression(expr);
    return address == 0 ? "Address did not evaluate: " + expr : std::string();
}

// Write, then read back, in one place so the verify discipline cannot drift between routes.
// Returns "" on success, otherwise a description - never a bool the caller could mistake for
// "done".
std::string apply_verified(c_bridge_executor& bridge, duint address,
                           const std::vector<uint8_t>& bytes, const char* what) {
    auto wrote = bridge.write_memory(address, bytes);
    if (!wrote.has_value()) return std::string(what) + " failed: " + wrote.error();
    auto back = bridge.read_memory(address, bytes.size());
    if (!back.has_value()) {
        return std::string(what) + " could not be read back at " + format_utils::format_address(address);
    }
    if (*back == bytes) return {};
    return std::string(what) + " at " + format_utils::format_address(address) + " did not take: wanted [" +
           hex_of(bytes) + "] but memory reads back as [" + hex_of(*back) + "]";
}

} // namespace

void register_crack_routes(c_http_router& router) {
    // POST /api/crack/branch_patch - rewrite one conditional branch in place.
    //
    // The licence-check / game-guard workhorse: the decision is one branch, so rewriting that
    // branch is more targeted than patching the code that computes the value. Length is preserved
    // exactly, which keeps every relative jump and recorded function boundary in the rest of the
    // module valid.
    router.post("/api/crack/branch_patch", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) return s_http_response::conflict("Debugger must be paused");
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) return s_http_response::bad_request("Body is not valid JSON");
        duint address = 0;
        if (auto err = resolve_body_address(bridge, body, address); !err.empty()) return s_http_response::bad_request(err);
        const auto address_str = get_string(body, "address");
        // restore is a separate operation, not a modifier: the caller may send it with or without
        // `mode`.
        const bool want_restore = get_bool(body, "restore", false);
        const auto mode = get_string(body, "mode", "invert");
        if (!want_restore && mode != "invert" && mode != "always" && mode != "never") {
            return s_http_response::bad_request("Unknown 'mode': " + mode + " (invert | always | never | restore)");
        }

        if (want_restore || mode == "restore") {
            bool found = false;
            auto original = recall_branch_original(address, found);
            if (!found) {
                return s_http_response::not_found("No recorded original bytes for " +
                    format_utils::format_address(address) +
                    " (only branches patched through this route in this session can be restored)");
            }
            const auto current = bridge.read_memory(address, original.size());
            if (auto bad = apply_verified(bridge, address, original, "restore"); !bad.empty()) {
                return s_http_response::internal_error(bad);
            }
            return s_http_response::ok({
                {"address", format_utils::format_address(address)}, {"mnemonic", ""},
                {"before", current.has_value() ? hex_of(*current) : ""}, {"after", hex_of(original)},
                {"mode", "restore"}, {"restored", true}, {"verified", true},
                {"original_instruction", ""}});
        }

        DISASM_INSTR di{};
        DbgDisasmAt(address, &di);
        if (di.instr_size <= 0 || di.instr_size > 15) {
            return s_http_response::bad_request("Cannot disassemble a complete instruction at " + address_str);
        }
        const std::string mnemonic = di.instruction;
        BASIC_INSTRUCTION_INFO basic{};
        DbgDisasmFastAt(address, &basic);
        // instr_branch covers `call` too, and rewriting a call into a jmp (or into NOPs) silently
        // breaks the stack discipline - the return address is never pushed. Everything here starts
        // with 'j'.
        if (di.type != instr_branch || mnemonic.empty() || mnemonic[0] != 'j') {
            return s_http_response::bad_request("not a conditional branch: " + mnemonic);
        }

        auto code = bridge.read_memory(address, static_cast<size_t>(di.instr_size));
        if (!code.has_value()) {
            return s_http_response::internal_error("Cannot read the instruction bytes at " + address_str);
        }
        const std::vector<uint8_t> before = *code;
        std::vector<uint8_t> patch;
        patch.reserve(before.size());

        if (mode == "invert") {
            if (!is_cond_jump_opcode(before.data(), di.instr_size)) {
                return s_http_response::bad_request("Cannot invert '" + mnemonic +
                    "': only Jcc encodings in 70..7F and 0F 80..8F carry the condition number in the "
                    "low bit of the opcode (loop/jrcxz share that byte range with different meanings)");
            }
            patch = before;
            // Near form: the condition is the low bit of the SECOND opcode byte. Short form:
            // flipping bit 0 of the single opcode byte negates it.
            if (before[0] == 0x0F) patch[1] = static_cast<uint8_t>(before[1] ^ 0x01);
            else patch[0] = static_cast<uint8_t>(before[0] ^ 0x01);
        } else if (mode == "never") {
            patch.assign(before.size(), 0x90);
        } else {
            duint target = bridge.eval_expression("dis.branchtarget(" + address_str + ")");
            if (target == 0) target = basic.addr;   // the fast disassembler's addrvalue
            if (target == 0) {
                return s_http_response::bad_request("Cannot resolve the branch target of '" + mnemonic +
                                                    "' at " + address_str);
            }
            const auto rel = static_cast<int64_t>(target) - (static_cast<int64_t>(address) + di.instr_size);
            if (rel >= -128 && rel <= 127 && di.instr_size >= 2) {
                patch.push_back(0xEB);
                patch.push_back(static_cast<uint8_t>(static_cast<int8_t>(rel)));
            } else if (di.instr_size >= 5) {
                patch.push_back(0xE9);
                const auto rel32 = static_cast<int32_t>(rel);
                for (int s = 0; s < 4; ++s) patch.push_back(static_cast<uint8_t>((rel32 >> (8 * s)) & 0xFF));
            } else {
                return s_http_response::bad_request("'always' cannot encode a jump to " +
                    format_utils::format_address(target) + " inside " + std::to_string(di.instr_size) +
                    " byte(s): a near jump needs 5 and the target is out of rel8 range");
            }
            // Unreachable filler rather than a shorter instruction: the length must stay identical
            // so the module's other relative encodings keep their meaning.
            patch.resize(before.size(), 0x90);
        }
        if (patch.size() != before.size()) return s_http_response::internal_error("Internal patch length mismatch");

        remember_branch_original(address, before);
        // A failed read-back means another writer won the race or the page is protected. Claiming
        // success here would send the caller off to test a patch that is not in memory.
        if (auto bad = apply_verified(bridge, address, patch, "branch patch"); !bad.empty()) {
            return s_http_response::internal_error(bad);
        }
        return s_http_response::ok({
            {"address", format_utils::format_address(address)}, {"mnemonic", mnemonic},
            {"before", hex_of(before)}, {"after", hex_of(patch)}, {"mode", mode},
            {"restored", false}, {"verified", true},
            {"original_instruction", std::string(basic.instruction)},
            {"unconditional_source", mnemonic == "jmp"}});
    });
    // POST /api/crack/sig_make - build a rebase-stable signature and prove it unique in the module.
    router.post("/api/crack/sig_make", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        // Read-only: bytes and disassembly are snapshotted, nothing is written.
        if (!bridge.require_debugging()) return s_http_response::conflict("No active debug session");
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) return s_http_response::bad_request("Body is not valid JSON");
        duint address = 0;
        if (auto err = resolve_body_address(bridge, body, address); !err.empty()) return s_http_response::bad_request(err);
        const auto address_str = get_string(body, "address");

        size_t length = static_cast<size_t>(get_int(body, "length", kDefaultSigBytes));
        if (length == 0) length = kDefaultSigBytes;
        if (length > kMaxSigBytes) length = kMaxSigBytes;

        std::string module_name = get_string(body, "module");
        if (module_name.empty()) module_name = bridge.get_module_at(address);
        if (module_name.empty()) {
            return s_http_response::not_found("Cannot determine the module containing " + address_str);
        }
        const duint module_base = bridge.get_module_base(module_name);
        if (module_base == 0) return s_http_response::not_found("Module not found: " + module_name);

        auto bytes = bridge.read_memory(address, length);
        if (!bytes.has_value()) {
            return s_http_response::internal_error("Cannot read " + std::to_string(length) + " bytes at " + address_str);
        }
        length = bytes->size();

        const auto modules = list_modules();
        const auto instructions = mask_offsets(
            walk_range(bridge, address, address + static_cast<duint>(length), 512), modules);
        // Start from the raw bytes and wildcard the relocatable halves. This is operand-aware
        // masking, not a byte diff against a second build: it works on one loaded image and assumes
        // only that displacement, immediate and branch-offset fields move on rebase/recompile, while
        // opcodes do not.
        std::vector<sig_byte> pattern(length);
        for (size_t i = 0; i < length; ++i) pattern[i].value = (*bytes)[i];
        for (const auto& ins : instructions) {
            const size_t start = static_cast<size_t>(ins.address - address);
            for (size_t off = ins.mask_from; off < static_cast<size_t>(ins.size); ++off) {
                if (start + off < length) pattern[start + off].wildcard = true;
            }
        }

        const auto dirs = read_pe_dirs(bridge, module_base);
        if (!dirs.ok) return s_http_response::internal_error("Cannot parse the PE headers of " + module_name);
        const auto sections = executable_sections(bridge, module_base, dirs);

        std::vector<duint> candidates;
        bool truncated = false;
        size_t bytes_scanned = 0;
        for (const auto& sec : sections) {
            if (candidates.size() >= kMaxSigMatches) { truncated = true; break; }
            // Same ceiling as the antidebug scan: the bridge refuses a larger single read.
            const duint want = sec.size > kScanCap ? kScanCap : sec.size;
            auto buf = bridge.read_memory(sec.addr, static_cast<size_t>(want));
            if (!buf.has_value()) continue;
            bytes_scanned += buf->size();
            bool chunk_truncated = false;
            for (size_t hit : scan_buffer(buf->data(), buf->size(), pattern,
                                          kMaxSigMatches - candidates.size(), chunk_truncated)) {
                candidates.push_back(sec.addr + static_cast<duint>(hit));
            }
            if (chunk_truncated) { truncated = true; break; }
        }
        auto candidates_json = nlohmann::json::array();
        for (auto c : candidates) candidates_json.push_back(format_utils::format_address(c));

        return s_http_response::ok({
            {"address", format_utils::format_address(address)}, {"module", module_name},
            {"module_base", format_utils::format_address(module_base)},
            {"bytes", hex_of(*bytes)}, {"pattern", format_pattern(pattern)},
            {"unique", candidates.size() == 1 && !truncated},
            {"candidates", candidates_json}, {"matches", candidates.size()},
            {"truncated", truncated}, {"bytes_scanned", bytes_scanned},
            {"sections_scanned", sections.size()},
            {"note", "Operand-aware masking, not a byte diff: branch/call opcodes, memory operands and "
                     "module-resident immediates keep only their opcode bytes and become ?? - that is "
                     "what a rebase moves. Everything else is literal, so the pattern is as unique as "
                     "the bytes it pins. Uniqueness holds for this module as loaded; a re-packed build "
                     "needs a fresh sig_make, and 'truncated' means the scan stopped at 8 candidates."}});
    });
    // POST /api/crack/iat_redirect - point an imported API's IAT slot at a planted stub.
    router.post("/api/crack/iat_redirect", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) return s_http_response::conflict("Debugger must be paused");
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) body = nlohmann::json::object();
        const auto target_expr = get_string(body, "target");
        const auto mode = get_string(body, "mode");

        auto slot_record = [](const import_hit& hit) {
            return nlohmann::json{{"slot", format_utils::format_address(hit.slot)},
                                  {"module", hit.module}, {"name", hit.name}};
        };

        if (mode == "restore") {
            auto restored = nlohmann::json::array();
            auto failed = nlohmann::json::array();
            std::map<duint, duint> pending;
            {
                std::lock_guard<std::mutex> lock(g_state_lock);
                pending.swap(g_iat_originals);
            }
            for (const auto& [slot, original] : pending) {
                std::vector<uint8_t> raw(kPtrSize);
                std::memcpy(raw.data(), &original, kPtrSize);
                const auto bad = apply_verified(bridge, slot, raw, "IAT restore");
                if (!bad.empty()) {
                    failed.push_back({{"slot", format_utils::format_address(slot)}, {"reason", bad}});
                    continue;
                }
                restored.push_back({{"slot", format_utils::format_address(slot)},
                                    {"original", format_utils::format_address(original)},
                                    {"verified", true}});
            }
            return s_http_response::ok({
                {"target", target_expr}, {"resolved", ""}, {"mode", "restore"}, {"stub", ""},
                {"slots", restored}, {"patched", restored.size()}, {"failed", failed},
                {"restored", true},
                {"note", "Every slot recorded by this route in this session was written back and "
                         "re-read. Slots patched by another tool, or recorded in an earlier plugin "
                         "session, are not in that registry and were not touched."}});
        }
        if (mode != "succeed" && mode != "fail" && mode != "constant") {
            return s_http_response::bad_request("Unknown 'mode': " + mode +
                                               " (succeed | fail | constant | restore)");
        }
        if (target_expr.empty()) return s_http_response::bad_request("Missing 'target' field");

        auto resolve = [&](const std::string& raw) -> duint {
            if (raw.empty()) return 0;
            if (bridge.is_valid_expression(raw)) {
                const auto v = bridge.eval_expression(raw);
                if (v != 0) return v;
            }
            // API docs write module!Name; x64dbg's parser wants module.Name. Retry across the
            // notation difference rather than failing on it.
            const auto bang = raw.find('!');
            if (bang != std::string::npos) {
                std::string alt = raw;
                alt[bang] = '.';
                if (bridge.is_valid_expression(alt)) return bridge.eval_expression(alt);
            }
            return 0;
        };
        const duint resolved = resolve(target_expr);
        if (resolved == 0) return s_http_response::not_found("Cannot resolve '" + target_expr + "' to an address");

        const auto scan = find_iat_slots(bridge, resolved);
        if (scan.hits.empty()) {
            return s_http_response::ok({
                {"target", target_expr}, {"resolved", format_utils::format_address(resolved)},
                {"mode", mode}, {"stub", ""}, {"slots", nlohmann::json::array()},
                {"patched", 0}, {"failed", nlohmann::json::array()},
                {"modules_scanned", scan.modules_scanned.size()},
                {"modules_truncated", scan.modules_truncated},
                {"thunks_examined", scan.thunks_examined},
                {"note", "No IAT slot points at " + format_utils::format_address(resolved) + ". The "
                         "target may import the API through its own copied thunk, resolve it "
                         "dynamically (LoadLibrary + GetProcAddress), or issue the syscall stub "
                         "directly - none of which pass through a slot this route can find."}});
        }

        std::vector<uint8_t> stub_code;
        std::string stub_key;
        if (mode == "succeed") {
            stub_code = {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3};   // mov eax,1; ret
            stub_key = "succeed";
        } else if (mode == "fail") {
            stub_code = {0x33, 0xC0, 0xC3};                     // xor eax,eax; ret
            stub_key = "fail";
        } else {
            // value defaults to 1; an unparseable expression is treated as 1 rather than silently
            // becoming 0, which would read as "the API failed".
            const auto value_str = get_string(body, "value", "1");
            const auto constant_value = static_cast<uint32_t>(
                bridge.is_valid_expression(value_str) ? bridge.eval_expression(value_str) : 1u);
            char keybuf[32];
            snprintf(keybuf, sizeof(keybuf), "constant:%08X", constant_value);
            stub_key = keybuf;
            stub_code = {0xB8};                                 // mov eax,imm32; ret
            for (int s = 0; s < 4; ++s) stub_code.push_back(static_cast<uint8_t>((constant_value >> (8 * s)) & 0xFF));
            stub_code.push_back(0xC3);
        }

        const auto stub = stub_for(bridge, stub_key, stub_code);
        if (stub.page == 0) {
            // No invented fallback: redirecting at a `ret` found somewhere else in the image would
            // change the return VALUE in an unknown way, and the caller would have no way to tell.
            return s_http_response::internal_error(stub.error);
        }

        auto patched = nlohmann::json::array();
        auto failed = nlohmann::json::array();
        for (const auto& hit : scan.hits) {
            // Read the slot first so the first patch of a slot records what was really there, not
            // what the import table implies.
            auto current = bridge.read_memory(hit.slot, kPtrSize);
            if (!current.has_value() || current->size() != kPtrSize) {
                auto rec = slot_record(hit);
                rec["reason"] = "cannot read the current slot value";
                failed.push_back(rec);
                continue;
            }
            duint previous = 0;
            std::memcpy(&previous, current->data(), kPtrSize);
            {
                std::lock_guard<std::mutex> lock(g_state_lock);
                if (g_iat_originals.find(hit.slot) == g_iat_originals.end()) g_iat_originals[hit.slot] = previous;
            }
            std::vector<uint8_t> raw(kPtrSize);
            std::memcpy(raw.data(), &stub.page, kPtrSize);
            const auto bad = apply_verified(bridge, hit.slot, raw, "IAT slot");
            if (!bad.empty()) {
                auto rec = slot_record(hit);
                rec["reason"] = bad;
                failed.push_back(rec);
                continue;
            }
            auto rec = slot_record(hit);
            rec["previous"] = format_utils::format_address(previous);
            rec["now"] = format_utils::format_address(stub.page);
            rec["verified"] = true;
            patched.push_back(rec);
        }

        return s_http_response::ok({
            {"target", target_expr}, {"resolved", format_utils::format_address(resolved)},
            {"mode", mode}, {"stub", format_utils::format_address(stub.page)},
            {"stub_bytes", hex_of(stub_code)}, {"stub_page_executable", stub.page_rights_set},
            {"slots", patched}, {"patched", patched.size()}, {"failed", failed},
            {"slots_found", scan.hits.size()},
            {"modules_scanned", scan.modules_scanned.size()},
            {"modules_truncated", scan.modules_truncated},
            {"thunks_examined", scan.thunks_examined},
            {"note", "Only import-table slots are covered. A target that calls the API through its own "
                     "copied thunk, resolves it with LoadLibrary + GetProcAddress, or issues the "
                     "syscall directly (ntdll stubs, heaven's gate, a manually mapped image) never "
                     "touches these slots. 'restore' writes back every slot this route recorded."}});
    });
    // POST /api/crack/compare_trace - turn a serial/licence comparison into a table instead of a
    // single-step session.
    router.post("/api/crack/compare_trace", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        // Debugger-state change only; the target may still be running.
        if (!bridge.require_debugging()) return s_http_response::conflict("No active debug session");
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) return s_http_response::bad_request("Body is not valid JSON");
        duint address = 0;
        if (auto err = resolve_body_address(bridge, body, address); !err.empty()) return s_http_response::bad_request(err);

        int max_sites = get_int(body, "max_hits", kDefaultMaxSites);
        if (max_sites < 1) max_sites = 1;
        if (max_sites > kMaxCompareSites) max_sites = kMaxCompareSites;
        // Default log: both operands of the comparison plus the flags it just produced, so the event
        // log records the decision and not merely that the instruction ran.
        const auto log_text = get_string(body, "log_text",
            std::string("{p:cip} {p:rax} {p:rbx} {p:rcx} {p:rdx} {p:rsi} {p:rdi} flags={p:eflags}"));

        duint start = address;
        duint end = 0;
        bool bounded = false;
        auto bounds = bridge.get_function_bounds(address);
        if (bounds.has_value()) {
            start = format_utils::parse_address(bounds.value()["start"].get<std::string>());
            end = format_utils::parse_address(bounds.value()["end"].get<std::string>());
            bounded = true;
        }
        if (end <= start) {
            // No analysed function (packed / virtualised module): treat the next 512 bytes as the
            // range. That is an assumption, and the response says so rather than implying the range
            // is the real function.
            start = address;
            end = address + 512;
        }

        // Classify each decoded instruction: is it a comparison whose operands a serial check
        // would put a guess and a truth into?
        auto comparison_kind = [&](const decoded_instr& d) -> std::string {
            const auto& di = d.detail;
            const std::string mnemonic = di.instruction;
            if (mnemonic == "cmp" || mnemonic == "test" || mnemonic == "sub") return "arith";
            if (mnemonic == "xor" && di.argcount >= 2 && di.arg[1].type == arg_normal &&
                looks_like_immediate(di.arg[1].mnemonic)) {
                // xor reg, imm is how a compiler writes "compare against a constant" when it wants
                // the zero flag without a temp register.
                return "xor_imm";
            }
            if (mnemonic == "call" && d.fast.call && d.fast.addr != 0) {
                // strcmp/memcmp/CompareString hides the comparison behind a call.
                const auto label = to_lower(bridge.get_label_at(d.fast.addr));
                if (label.find("cmp") != std::string::npos || label.find("compare") != std::string::npos) {
                    return "compare_call";
                }
            }
            return {};
        };

        struct site { duint address; std::string mnemonic, instruction, kind; };
        std::vector<site> sites;
        for (const auto& d : walk_range(bridge, start, end, 4096)) {
            const auto kind = comparison_kind(d);
            if (!kind.empty()) {
                sites.push_back({d.address, d.detail.instruction, std::string(d.fast.instruction), kind});
                if (static_cast<int>(sites.size()) >= max_sites) break;
            }
        }

        auto armed = nlohmann::json::array();
        auto failed = nlohmann::json::array();
        for (const auto& s : sites) {
            const auto addr_str = format_utils::format_address(s.address);
            if (!bridge.exec_command("bp " + addr_str)) {
                failed.push_back({{"address", addr_str}, {"reason", "bp rejected"}});
                continue;
            }
            // silent + fast_resume: the point is a timeline in the event log, not a stop. log_text
            // carries the operands, the name identifies the site.
            bridge.exec_command("SetBreakpointSilent " + addr_str + ", 1");
            bridge.exec_command("SetBreakpointFastResume " + addr_str + ", 1");
            bridge.exec_command("SetBreakpointLog " + addr_str + ", \"" + log_text + "\"");
            bridge.exec_command("SetBreakpointName " + addr_str + ", \"crack:compare\"");
            armed.push_back({{"address", addr_str}, {"mnemonic", s.mnemonic},
                             {"instruction", s.instruction}, {"kind", s.kind}});
        }

        const bool resume = get_bool(body, "resume", false);
        bool resumed = false;
        if (resume && !armed.empty() && !bridge.is_running()) {
            bridge.exec_command_async("run");
            resumed = true;
        }

        nlohmann::json out = {
            {"function", {{"start", format_utils::format_address(start)},
                          {"end", format_utils::format_address(end)}, {"bounded", bounded}}},
            {"sites", armed}, {"count", armed.size()}, {"armed", armed.size()},
            {"failed", failed}, {"log_text", log_text}, {"resumed", resumed},
            {"note", "Hits land in the event log (x64dbg_command get_events / wait_for_event, type "
                     "'breakpoint'); the breakpoints only record. fast_resume is not honoured for every "
                     "instruction, so the target may still stop - inspect and continue, the armed sites "
                     "stay armed. Nothing was patched: the comparisons still decide, they just become "
                     "visible."}};
        if (!bounded) {
            out["range_note"] =
                "No analysed function boundary at the given address, so the next 512 bytes were used as "
                "the range. Run analysis first ('anal') for a real extent; an over-wide range only arms "
                "more sites, it does not change what they record.";
        }
        return s_http_response::ok(out);
    });
}
} // namespace handlers
