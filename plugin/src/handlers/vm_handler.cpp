#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "util/event_log.h"
#include "util/trace_state.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <expected>
#include <fstream>
#include <map>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <windows.h>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "_scriptapi_module.h"

// Virtualisation-obfuscation analysis: steps [1]-[4] of docs/vm-analysis.md as four
// routes. The target shape is `.text` plus a second section of hundreds of MB, high
// entropy, non-linear control flow, and one address the CPU returns to after every
// unit of work. Everything here is a heuristic over that observation, so each route
// reports what it could not do instead of inventing a value for it.
namespace handlers {
namespace {

// A handler table or encrypted bytecode blob sits near 8.0 bits/byte; ordinary x86
// code lands around 6.2-6.6 and structured data lower. 7.0 is where a section stops
// looking like code and starts looking like ciphertext.
constexpr double kEntropyThreshold = 7.0;

// A 64 KB payload is a plausible stub (the doc's case is 237 MB). Below this a
// section is normal-sized and flagging it as an obfuscation payload is noise.
constexpr duint kMinCandidateSize = 0x10000;

// Entropy over 64 MB already lands within ~0.001 of the section's value while reading
// 237 MB over the bridge takes minutes, so above the cap whole pages are sampled.
constexpr duint kSectionSampleCap = 64ull * 1024 * 1024;
constexpr duint kReadChunk = 1024 * 1024;   // well under the bridge's 10 MB read cap
constexpr duint kPageSize = 0x1000;

// 4M rows is ~32 MB of duints plus the index and edges. A GB-scale trace is 10x
// that, so the head is used and the response says so.
constexpr size_t kMaxTraceLines = 4000000;

// Three visits and two distinct predecessors exclude one-off call sites without
// hiding a cold handler.
constexpr uint64_t kMinDispatcherVisits = 3;
constexpr uint32_t kMinDispatcherPreds = 2;
constexpr uint32_t kMaxDispatcherSuccs = 2;

// A handler body is tens of instructions; this bounds hashing a path that runs into
// unrelated code after a missed boundary.
constexpr int kMaxHandlerInsns = 256;

// Real handlers are far smaller; the bound only stops a handler with no preceding
// terminator from scanning back forever.
constexpr duint kEntryScanBack = 4096;

// Each tail costs a window read plus a disassembly per candidate boundary, so the
// tail count bounds this route's runtime.
constexpr size_t kMaxTails = 4096;

// FNV-1a 64 over mnemonics only - the doc's "[4] cluster by instruction-sequence
// hash". Operands are excluded because an immediate differs between executions of
// the same handler, and a separator is folded in so "mov"+"add" cannot hash as
// "mova"+"dd".
constexpr uint64_t kFnvOffset = 1469598103934665603ull;
constexpr uint64_t kFnvPrime = 1099511628211ull;

// json::value() forwards to get<T>() when the key exists, so {"module": 5} throws and
// there is no catch-all: check the type first and let bad input take the route's own
// "missing field" path.
std::string json_string(const nlohmann::json& object, const char* key,
                        const std::string& fallback = std::string()) {
    if (!object.is_object()) return fallback;
    const auto it = object.find(key);
    if (it == object.end() || !it->is_string()) return fallback;
    return it->get<std::string>();
}

// Numeric body field with clamping. Digits-only strings are accepted because HTTP
// clients send them; anything else (including a non-numeric type) falls back.
uint64_t body_u64(const nlohmann::json& body, const char* key, uint64_t fallback,
                  uint64_t lo, uint64_t hi) {
    const auto it = body.find(key);
    if (it == body.end() || !(it->is_number() || it->is_string())) {
        return (std::min)((std::max)(fallback, lo), hi);
    }
    uint64_t out = 0;
    bool any = false;
    for (char c : it->dump()) {
        if (c < '0' || c > '9') continue;
        out = out * 10 + static_cast<uint64_t>(c - '0');
        any = true;
    }
    return (std::min)((std::max)(any ? out : fallback, lo), hi);
}

// Accepts `{p:cip}` output ("0000000140001000") and pasted forms ("0x140001000",
// "140001000") with whitespace or a CRLF '\r'. A malformed cell is data to count.
bool parse_hex_token(const std::string& raw, duint& out) {
    std::string s;
    for (char c : raw) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '"' || c == '\'') continue;
        s.push_back(c);
    }
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s = s.substr(2);
    // 16 nibbles fills a 64-bit duint. On a 32-bit build a pasted 64-bit address would
    // silently truncate, so reject it instead: a wrong CIP is worse than a counted
    // malformed line.
    if (s.empty() || s.size() > sizeof(duint) * 2) return false;

    duint v = 0;
    for (char c : s) {
        int digit;
        if (c >= '0' && c <= '9')      digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else return false;
        v = (v << 4) | static_cast<duint>(digit);
    }
    out = v;
    return true;
}

bool starts_with(const char* text, const char* prefix) {
    return text && prefix && std::strncmp(text, prefix, std::strlen(prefix)) == 0;
}

// Rounds as the response documents it ("3 decimals") rather than relying on the JSON
// writer's shortest-round-trip formatting.
double round_to(double value, double scale) { return std::round(value * scale) / scale; }

std::string main_module_name() {
    char name[MAX_MODULE_SIZE] = {};
    if (Script::Module::GetMainModuleName(name) && name[0] != '\0') return name;
    return {};
}

uint64_t fnv_push(uint64_t hash, const std::string& text) {
    for (unsigned char c : text) {
        hash ^= static_cast<uint64_t>(c);
        hash *= kFnvPrime;
    }
    return (hash ^ 0xFFull) * kFnvPrime;
}

std::string hex16(uint64_t value) {
    char buf[32];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%016llX", static_cast<unsigned long long>(value));
    return buf;
}

// PE section walk, same shape as scan_probes() in antidebug_handler.cpp.
struct pe_section {
    std::string name;
    duint va = 0;          // RVA, not a VA
    duint vsize = 0;
    duint raw_size = 0;
    duint chars = 0;

    bool exec() const { return (chars & IMAGE_SCN_MEM_EXECUTE) != 0; }
    // "image" = carries bytes in the file and is mapped readable, i.e. real content
    // rather than a .bss-style reservation. An entropy reading only means something
    // for a section that actually holds data.
    bool image() const { return raw_size > 0 && (chars & IMAGE_SCN_MEM_READ) != 0; }
};

std::expected<std::vector<pe_section>, std::string>
read_pe_sections(c_bridge_executor& bridge, duint base) {
    auto dos = bridge.read_memory(base, 0x40);
    if (!dos.has_value() || dos->size() < 0x40) return std::unexpected("cannot read DOS header");
    uint32_t e_lfanew = 0;
    std::memcpy(&e_lfanew, dos->data() + 0x3C, 4);

    auto pe = bridge.read_memory(base + e_lfanew, 24);
    if (!pe.has_value() || pe->size() < 24) return std::unexpected("cannot read PE header");
    uint16_t num_sections = 0, opt_size = 0;
    std::memcpy(&num_sections, pe->data() + 6, 2);
    std::memcpy(&opt_size, pe->data() + 20, 2);
    if (num_sections == 0 || num_sections > 96) return std::unexpected("implausible section count");

    auto headers = bridge.read_memory(base + e_lfanew + 24 + opt_size,
                                      static_cast<size_t>(num_sections) * 40);
    if (!headers.has_value()) return std::unexpected("cannot read section table");

    std::vector<pe_section> out;
    out.reserve(num_sections);
    for (uint16_t i = 0; i < num_sections; ++i) {
        const size_t off = static_cast<size_t>(i) * 40;
        pe_section s;
        char name[9] = {};
        std::memcpy(name, headers->data() + off, 8);
        std::memcpy(&s.vsize, headers->data() + off + 8, 4);
        std::memcpy(&s.va, headers->data() + off + 12, 4);
        std::memcpy(&s.raw_size, headers->data() + off + 16, 4);
        std::memcpy(&s.chars, headers->data() + off + 36, 4);
        s.name = name;
        out.push_back(std::move(s));
    }
    return out;
}

struct entropy_result {
    double entropy = 0.0;
    uint64_t bytes = 0;       // bytes actually fed into the histogram
    uint64_t unreadable = 0;  // bytes the bridge refused
    bool sampled = false;
};

// One pass per section in 1 MB chunks (the bridge rejects reads above 10 MB);
// oversized sections are page-sampled so 237 MB costs 64 MB of reads.
entropy_result section_entropy(c_bridge_executor& bridge, duint address, duint span) {
    entropy_result result;
    if (span == 0) return result;

    std::array<uint64_t, 256> hist{};
    auto add = [&](duint at, duint want) {
        auto buf = bridge.read_memory(at, want);
        if (!buf.has_value()) {
            result.unreadable += want;
            return;
        }
        for (uint8_t b : *buf) ++hist[b];
        result.bytes += buf->size();
    };

    if (span <= kSectionSampleCap) {
        for (duint off = 0; off < span; off += kReadChunk) {
            add(address + off, (std::min)(kReadChunk, span - off));
        }
    } else {
        result.sampled = true;
        const duint step = static_cast<duint>(kPageSize) * ((span / kSectionSampleCap) + 1);
        for (duint page = 0; page < span; page += step) {
            add(address + page, (std::min)(static_cast<duint>(kPageSize), span - page));
        }
    }

    if (result.bytes != 0) {
        const double denom = static_cast<double>(result.bytes);
        for (uint64_t count : hist) {
            if (count == 0) continue;
            const double p = static_cast<double>(count) / denom;
            result.entropy -= p * std::log2(p);
        }
    }
    return result;
}

// [1] Normalisation. x64dbg records some instructions more than once per step (768
// rows for a 300-step trace), so runs are collapsed: the successor set then means "the
// next instruction", not "the same one again".
struct cip_stream {
    std::vector<duint> sequence;
    uint64_t accepted = 0;
    uint64_t malformed = 0;
    uint64_t repeats_collapsed = 0;
    bool truncated = false;

    void append(duint address) {
        ++accepted;
        if (!sequence.empty() && sequence.back() == address) {
            ++repeats_collapsed;
            return;
        }
        sequence.push_back(address);
    }
};

std::expected<cip_stream, std::string> parse_trace_file(const std::string& path) {
    std::ifstream in(path);
    if (!in.is_open()) return std::unexpected("cannot open trace file: " + path);

    cip_stream stream;
    std::string line;
    while (std::getline(in, line)) {
        if (stream.accepted + stream.malformed >= kMaxTraceLines) {
            stream.truncated = true;
            break;
        }
        // Column 1 is CIP for every log format this API sets. A line with no comma is
        // still worth parsing: a one-column log is valid.
        const auto comma = line.find(',');
        duint address = 0;
        if (!parse_hex_token(comma == std::string::npos ? line : line.substr(0, comma), address)) {
            ++stream.malformed;
            continue;
        }
        stream.append(address);
    }
    return stream;
}

// [2] Dispatcher discovery. Edges are one u64 per transition (pred<<32 | succ), sorted
// and deduped: at 4M rows a per-node hash set would be hundreds of MB, this is 32 MB.
nlohmann::json analyse_cip_sequence(const std::vector<duint>& sequence, size_t top) {
    nlohmann::json out = nlohmann::json::object();
    out["steps"] = sequence.size();

    if (sequence.empty()) {
        out["unique_addrs"] = 0;
        out["dispatchers"] = nlohmann::json::array();
        out["periodicity"] = nullptr;
        return out;
    }

    std::unordered_map<duint, uint32_t> index;
    index.reserve(sequence.size() / 2 + 16);

    std::vector<uint32_t> node_of(sequence.size());
    std::vector<uint64_t> visits;
    for (size_t i = 0; i < sequence.size(); ++i) {
        const uint32_t node =
            index.emplace(sequence[i], static_cast<uint32_t>(index.size())).first->second;
        node_of[i] = node;
        if (visits.size() <= node) visits.resize(static_cast<size_t>(node) + 1, 0);
        ++visits[node];
    }

    std::vector<duint> address_of(visits.size(), 0);
    for (const auto& kv : index) address_of[kv.second] = kv.first;

    std::vector<uint64_t> edges;
    edges.reserve(sequence.size());
    for (size_t i = 1; i < node_of.size(); ++i) {
        edges.push_back((static_cast<uint64_t>(node_of[i - 1]) << 32) | node_of[i]);
    }
    std::sort(edges.begin(), edges.end());
    edges.erase(std::unique(edges.begin(), edges.end()), edges.end());

    std::vector<uint32_t> distinct_succ(visits.size(), 0);
    std::vector<uint32_t> distinct_pred(visits.size(), 0);
    for (uint64_t edge : edges) {
        ++distinct_succ[static_cast<uint32_t>(edge >> 32)];
        ++distinct_pred[static_cast<uint32_t>(edge & 0xFFFFFFFFull)];
    }

    // Doc criterion 3: predecessors >> successors. Score = visits * distinct_preds /
    // fan-out, so a plain loop header (many visits, one predecessor) scores low while
    // the VM's single re-entry point scores high.
    std::vector<std::pair<double, uint32_t>> candidates;
    for (uint32_t node = 0; node < visits.size(); ++node) {
        if (visits[node] < kMinDispatcherVisits) continue;
        if (distinct_pred[node] < kMinDispatcherPreds) continue;
        if (distinct_succ[node] < 1 || distinct_succ[node] > kMaxDispatcherSuccs) continue;
        const double score = static_cast<double>(visits[node]) *
                             static_cast<double>(distinct_pred[node]) /
                             static_cast<double>((std::max<uint32_t>)(1, distinct_succ[node]));
        candidates.emplace_back(score, node);
    }

    std::sort(candidates.begin(), candidates.end(),
              [&visits](const auto& a, const auto& b) {
                  if (a.first != b.first) return a.first > b.first;
                  return visits[a.second] > visits[b.second];
              });

    auto list = nlohmann::json::array();
    for (size_t i = 0; i < candidates.size() && i < top; ++i) {
        const uint32_t node = candidates[i].second;
        list.push_back({
            {"address",               format_utils::format_address(address_of[node])},
            {"visits",                visits[node]},
            {"distinct_predecessors", distinct_pred[node]},
            {"distinct_successors",   distinct_succ[node]},
            {"score",                 round_to(candidates[i].first, 100.0)}
        });
    }

    nlohmann::json periodicity = nullptr;
    if (!candidates.empty()) {
        // Doc criterion 2: re-entry at a stable stride. Gaps are in collapsed steps, so
        // a handler of n instructions yields a gap of n; one dominant gap means one
        // dispatch loop, a flat histogram means many.
        const uint32_t best = candidates.front().second;
        std::map<uint32_t, uint32_t> gaps;
        size_t previous = 0;
        bool have_previous = false;
        for (size_t i = 0; i < node_of.size(); ++i) {
            if (node_of[i] != best) continue;
            if (have_previous) ++gaps[static_cast<uint32_t>(i - previous)];
            previous = i;
            have_previous = true;
        }

        uint64_t total_gaps = 0;
        uint32_t best_gap = 0, best_count = 0;
        for (const auto& kv : gaps) {
            total_gaps += kv.second;
            if (kv.second > best_count) {
                best_count = kv.second;
                best_gap = kv.first;
            }
        }

        periodicity = {
            {"address",         format_utils::format_address(address_of[best])},
            {"most_common_gap", best_gap},
            {"gap_occurrences", best_count},
            {"total_gaps",      total_gaps},
            {"distinct_gaps",   gaps.size()},
            {"share",           total_gaps == 0
                                    ? 0.0
                                    : round_to(static_cast<double>(best_count) /
                                                   static_cast<double>(total_gaps),
                                               1000.0)}
        };
    }

    out["unique_addrs"] = visits.size();
    out["dispatchers"] = list;
    out["periodicity"] = periodicity;
    return out;
}

// Real x64dbg puts the whole text in DISASM_INSTR::instruction ("mov eax, dword ptr
// ds:[rbx+8]"), so the mnemonic is what precedes the first space.
std::string mnemonic_of(const DISASM_INSTR& insn) {
    std::string text(insn.instruction);
    const auto space = text.find(' ');
    if (space != std::string::npos) text.resize(space);
    return text.empty() ? std::string("?") : text;
}

// [3] Where a handler body starts.
//
// Preferred: x64dbg's function bound - but only when it precedes the tail, does not
// contain the dispatcher, and is short enough. In a virtualised binary the analyser
// usually did not split the handlers apart, and the returned "function" often spans the
// dispatcher, which would make every handler look identical.
//
// Fallback: the byte after the terminator ending the previous handler. A raw byte match
// is not a boundary (the byte occurs inside displacements too), so each candidate is
// disassembled and must be a ret/int3/jmp ending strictly before the tail. The window is
// read in one call: 4096 single-byte round-trips per handler would be unusable.
duint find_handler_entry(c_bridge_executor& bridge, duint tail, duint module_base,
                         duint dispatcher, std::string& method) {
    duint func_start = 0, func_end = 0;
    if (DbgFunctionGet(tail, &func_start, &func_end) && func_start >= module_base &&
        func_start < tail && !(dispatcher >= func_start && dispatcher < func_end) &&
        (tail - func_start) <= kEntryScanBack) {
        method = "function";
        return func_start;
    }

    const duint start = (std::max)(tail > kEntryScanBack ? tail - kEntryScanBack : 0, module_base);
    if (tail <= start) {
        method = "none";
        return 0;
    }

    auto bytes = bridge.read_memory(start, static_cast<size_t>(tail - start));
    if (!bytes.has_value()) {
        method = "none";
        return 0;
    }

    // Newest first: the terminator immediately before the tail is the one that ended
    // the previous handler.
    for (duint offset = tail - start; offset > 0; --offset) {
        const uint8_t opcode = (*bytes)[offset - 1];
        const bool plausible = opcode == 0xC3 ||   // ret
                               opcode == 0xC2 ||   // ret imm16
                               opcode == 0xCB ||   // retf
                               opcode == 0xCC ||   // int3, the handler separator
                               opcode == 0xE9 ||   // jmp rel32
                               opcode == 0xEB;     // jmp rel8
        if (!plausible) continue;

        const duint at = start + offset - 1;
        DISASM_INSTR insn{};
        DbgDisasmAt(at, &insn);
        if (insn.instr_size <= 0) continue;
        if (!starts_with(insn.instruction, "ret") && !starts_with(insn.instruction, "int3") &&
            !starts_with(insn.instruction, "jmp")) {
            continue;
        }

        const duint after = at + static_cast<duint>(insn.instr_size);
        if (after >= tail) continue;   // the boundary must sit strictly before the tail

        method = "scan";
        return after;
    }

    method = "none";
    return 0;
}

struct handler_record {
    duint entry = 0;
    duint tail = 0;
    uint64_t hash = kFnvOffset;
    int instruction_count = 0;
    bool reached_tail = false;
};

// Hashes the mnemonic sequence from the entry through the jump back to the dispatcher.
// A body that hits a terminator or walks past its tail never reached the tail: the entry
// landed mid-handler and the hash is not an identity.
handler_record build_handler(duint entry, duint tail) {
    handler_record record;
    record.entry = entry;
    record.tail = tail;

    duint current = entry;
    for (int i = 0; i < kMaxHandlerInsns; ++i) {
        DISASM_INSTR insn{};
        DbgDisasmAt(current, &insn);
        if (insn.instr_size <= 0) break;

        const auto mnemonic = mnemonic_of(insn);
        record.hash = fnv_push(record.hash, mnemonic);
        ++record.instruction_count;

        if (current == tail) {
            record.reached_tail = true;
            break;
        }
        current += static_cast<duint>(insn.instr_size);
        if (current > tail) break;   // the tail was not inside this body
        // A terminator before the tail means the body ended here; continuing would hash
        // the next handler instead.
        if (mnemonic != "call" && (mnemonic.compare(0, 3, "ret") == 0 || mnemonic == "int3")) {
            break;
        }
    }
    return record;
}

} // namespace

void register_vm_routes(c_http_router& router) {
    // POST /api/vm/region - Section map with entropy, plus obfuscation candidates.
    //
    // Only reads target memory (DbgMemRead), which is safe while the target runs, so an
    // active session is enough - no pause needed.
    router.post("/api/vm/region", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) body = nlohmann::json::object();

        std::string module_name = json_string(body, "module");
        if (module_name.empty()) module_name = main_module_name();
        if (module_name.empty()) {
            return s_http_response::bad_request(
                "Missing 'module' and the main module name is unavailable");
        }

        const auto base = bridge.get_module_base(module_name);
        if (base == 0) return s_http_response::not_found("Module not found: " + module_name);

        auto sections = read_pe_sections(bridge, base);
        if (!sections.has_value()) {
            return s_http_response::internal_error(sections.error() + " (" + module_name + ")");
        }

        auto section_list = nlohmann::json::array();
        auto candidates = nlohmann::json::array();

        for (const auto& section : *sections) {
            const duint span = section.vsize ? section.vsize : section.raw_size;
            const auto entropy = section_entropy(bridge, base + section.va, span);

            auto entry = nlohmann::json{
                {"name",    section.name},
                {"va",      format_utils::format_address(base + section.va)},
                {"size",    span},
                {"entropy", round_to(entropy.entropy, 1000.0)},
                {"exec",    section.exec()},
                {"image",   section.image()},
                {"chars",   "0x" + format_utils::format_hex(section.chars)}};

            if (span == 0) {
                entry["warning"] = "empty section (vsize and raw size are both 0)";
            } else if (entropy.bytes == 0) {
                entry["warning"] = "section bytes could not be read; entropy is not meaningful";
            }
            if (entropy.sampled) {
                entry["sampled"] = true;
                entry["sampled_bytes"] = entropy.bytes;
                entry["sample_note"] =
                    "section exceeds the 64 MB read cap; entropy computed on page samples";
            }
            if (entropy.unreadable > 0) entry["unreadable_bytes"] = entropy.unreadable;

            section_list.push_back(entry);

            if (entropy.bytes > 0 && entropy.entropy >= kEntropyThreshold &&
                (section.exec() || section.image()) && span >= kMinCandidateSize) {
                std::string why = section.exec()
                                      ? "high entropy + executable, not a normal code section"
                                      : "high entropy + image data, not a normal data section";
                if (span >= 64ull * 1024 * 1024) why += "; multi-megabyte payload";
                if (entropy.sampled) why += " (entropy sampled)";

                auto candidate = entry;
                candidate["why"] = why;
                candidates.push_back(candidate);
            }
        }

        // Largest first: the doc's target is one enormous section, and size is what
        // separates a payload from a packed helper blob.
        std::sort(candidates.begin(), candidates.end(),
                  [](const nlohmann::json& a, const nlohmann::json& b) {
                      return a.value("size", duint{0}) > b.value("size", duint{0});
                  });

        return s_http_response::ok({
            {"module",          module_name},
            {"base",            format_utils::format_address(base)},
            {"sections",        section_list},
            {"count",           section_list.size()},
            {"candidates",      candidates},
            {"candidate_count", candidates.size()},
            {"note", "Entropy >= 7.0 with exec/image and >= 64 KB is a heuristic, not a verdict: "
                     "packed resources and compressed assets score that high too. A candidate means "
                     "'look here first'; the largest is usually the VM payload section."}});
    });

    // POST /api/vm/discover - Locate the dispatcher in a CIP sequence.
    //
    // Neither source touches target memory: "trace" reads a CSV and "events" reads the
    // plugin's own log, so both work while the target runs and stay useful after it
    // stopped.
    router.post("/api/vm/discover", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) body = nlohmann::json::object();

        const auto source = json_string(body, "source", "trace");
        const auto top = static_cast<size_t>(body_u64(body, "top", 10, 1, 50));

        if (source == "trace") {
            std::string path = json_string(body, "trace_file");
            if (path.empty()) {
                // Fall back to what the tracing routes last wrote, so a caller that just
                // finished a trace need not repeat the path. trace_status() reports "file"
                // while writing and "last_file" once finished.
                const auto status = mcp::trace_status();
                path = json_string(status, "file");
                if (path.empty()) path = json_string(status, "last_file");
                if (path.empty()) {
                    return s_http_response::bad_request(
                        "Missing 'trace_file' and /api/trace/status knows no trace file (start a "
                        "trace first, or pass 'trace_file')");
                }
            }

            auto parsed = parse_trace_file(path);
            if (!parsed.has_value()) return s_http_response::not_found(parsed.error());

            auto analysis = analyse_cip_sequence(parsed->sequence, top);
            analysis["source"] = "trace";
            analysis["file"] = path;
            analysis["accepted_lines"] = parsed->accepted;
            analysis["malformed_lines"] = parsed->malformed;
            analysis["repeat_collapsed"] = parsed->repeats_collapsed;
            analysis["truncated"] = parsed->truncated;

            std::string note =
                "Consecutive duplicate rows are collapsed before analysis (x64dbg records some "
                "instructions more than once per step), so 'steps' counts distinct transitions. "
                "Only column 1 (CIP) is used.";
            if (parsed->truncated) {
                note += " The file exceeded 4M lines: this is the head of it, so the dispatcher "
                        "ranking over a long tail may differ.";
            }
            if (parsed->sequence.empty()) {
                note += " No parseable CIP value was found - check the trace log format (it must "
                        "start with {p:cip}).";
            }
            analysis["note"] = note;
            return s_http_response::ok(analysis);
        }

        if (source == "events") {
            const auto since_seq = body_u64(body, "since", 0, 0, UINT64_MAX);
            const auto payload = event_log::since(since_seq);

            cip_stream collected;
            uint64_t skipped = 0;
            for (const auto& event : payload.value("events", nlohmann::json::array())) {
                const auto type = json_string(event, "type");
                if (type != "breakpoint" && type != "exception") continue;

                duint address = 0;
                if (!parse_hex_token(json_string(event, "address"), address)) {
                    ++skipped;
                    continue;
                }
                collected.append(address);
            }

            auto analysis = analyse_cip_sequence(collected.sequence, top);
            analysis["source"] = "events";
            analysis["since"] = since_seq;
            analysis["accepted_events"] = collected.accepted;
            analysis["repeat_collapsed"] = collected.repeats_collapsed;
            analysis["skipped_events"] = skipped;
            analysis["dropped"] = payload.value("dropped", 0ull);
            analysis["latest_seq"] = payload.value("latest_seq", 0ull);
            analysis["note"] =
                "Event-based discovery only sees addresses that were instrumented "
                "(breakpoints, exceptions), so the sequence is sparse: it cannot rank handlers "
                "by execution count the way a trace does. It complements the trace for "
                "exception-driven VMs, where the interesting transitions happen through faults "
                "rather than linear stepping. Set breakpoints or probe logging first if this "
                "list looks empty.";
            return s_http_response::ok(analysis);
        }

        return s_http_response::bad_request("'source' must be 'trace' or 'events'");
    });

    // POST /api/vm/handlers - Handlers that jump back to the dispatcher.
    //
    // Needs a paused target: xrefs, function bounds and disassembly all come from the
    // analyser's state, which is only coherent while stopped.
    router.post("/api/vm/handlers", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) body = nlohmann::json::object();

        const auto dispatcher_text = json_string(body, "dispatcher");
        if (dispatcher_text.empty()) {
            return s_http_response::bad_request("Missing 'dispatcher' (address or symbol)");
        }

        const auto dispatcher = bridge.eval_expression(dispatcher_text);
        if (dispatcher == 0) {
            return s_http_response::bad_request("Cannot resolve 'dispatcher': " + dispatcher_text);
        }

        std::string module_name = json_string(body, "module");
        if (module_name.empty()) module_name = bridge.get_module_at(dispatcher);
        if (module_name.empty()) {
            return s_http_response::bad_request(
                "dispatcher is not inside a loaded module; pass 'module' explicitly");
        }

        const auto module_base = bridge.get_module_base(module_name);
        if (module_base == 0) return s_http_response::not_found("Module not found: " + module_name);

        const auto max_handlers = static_cast<size_t>(body_u64(body, "max_handlers", 512, 1, 1024));

        // Every jump landing on the dispatcher is a handler tail. An indirect jump
        // through a stack slot is recorded as XREF_DATA, which is why data references
        // count too.
        std::vector<duint> tails;
        std::string warning;
        if (DbgGetXrefCountAt(dispatcher) == 0) {
            warning = "no cross-references to the dispatcher: the analyser has not run over this "
                      "module (run analysis first), or the dispatch is a computed jump with no "
                      "static reference. Use /api/vm/discover to confirm this is the address being "
                      "re-entered.";
        } else {
            XREF_INFO xref_info{};
            if (DbgXrefGet(dispatcher, &xref_info)) {
                for (duint i = 0; i < xref_info.refcount && tails.size() < kMaxTails; ++i) {
                    const auto& ref = xref_info.references[i];
                    if (ref.type == XREF_JMP || ref.type == XREF_DATA) tails.push_back(ref.addr);
                }
                if (xref_info.references) BridgeFree(xref_info.references);
            } else {
                warning = "DbgXrefGet failed for the dispatcher; no tails were collected";
            }
            std::sort(tails.begin(), tails.end());
            tails.erase(std::unique(tails.begin(), tails.end()), tails.end());
        }

        // [4] Cluster by mnemonic hash: the same sequence is the same handler reached by a
        // different path, so records merge and tails accumulate. Bodies that never reached
        // their tail are reported, not clustered - merging on a mid-instruction entry
        // would invent a handler that does not exist.
        std::unordered_map<uint64_t, size_t> by_hash;
        std::vector<nlohmann::json> merged;
        nlohmann::json skipped = nlohmann::json::array();
        for (duint tail : tails) {
            std::string method;
            const duint entry = find_handler_entry(bridge, tail, module_base, dispatcher, method);
            if (entry == 0) {
                skipped.push_back({
                    {"tail",   format_utils::format_address(tail)},
                    {"reason", "no handler entry found within 4096 bytes before the tail"}});
                continue;
            }

            const auto record = build_handler(entry, tail);
            if (!record.reached_tail) {
                skipped.push_back({
                    {"tail",   format_utils::format_address(tail)},
                    {"entry",  format_utils::format_address(entry)},
                    {"reason", "walk from the entry did not reach its own tail; the entry "
                               "heuristic probably landed mid-handler, so this body was not "
                               "clustered"}});
                continue;
            }

            auto it = by_hash.find(record.hash);
            if (it == by_hash.end()) {
                it = by_hash.emplace(record.hash, merged.size()).first;
                merged.push_back({
                    {"id",                hex16(record.hash)},
                    {"entry",             format_utils::format_address(record.entry)},
                    {"instruction_count", record.instruction_count},
                    {"hash",              "0x" + hex16(record.hash)},
                    {"hits",              0},
                    {"tails",             nlohmann::json::array()},
                    {"entry_method",      method}});
            }
            auto& slot = merged[it->second];
            slot["hits"] = slot["hits"].get<uint64_t>() + 1;
            slot["tails"].push_back(format_utils::format_address(record.tail));
        }

        std::sort(merged.begin(), merged.end(),
                  [](const nlohmann::json& a, const nlohmann::json& b) {
                      const auto ah = a.value("hits", 0ull);
                      const auto bh = b.value("hits", 0ull);
                      if (ah != bh) return ah > bh;
                      return a.value("entry", std::string()) < b.value("entry", std::string());
                  });

        auto handlers = nlohmann::json::array();
        for (size_t i = 0; i < merged.size() && i < max_handlers; ++i) {
            handlers.push_back(merged[i]);
        }

        nlohmann::json out = {
            {"dispatcher", format_utils::format_address(dispatcher)},
            {"module",     module_name},
            {"handlers",   handlers},
            {"total",      merged.size()},
            {"tail_count", tails.size()},
            {"truncated",  merged.size() > max_handlers},
            {"note", "Handlers come from xrefs to the dispatcher, so they exist only once the "
                     "analyser has run. An entry point is the analyser's function bound or, when that "
                     "would span the dispatcher or look implausible, the byte after the nearest "
                     "preceding ret/int3/jmp - byte-level, so a mid-instruction entry is possible and "
                     "lands in 'skipped', not the cluster. 'hits' counts jump sites, not "
                     "executions; execution frequency comes from /api/vm/discover. The hash covers "
                     "mnemonics only, entry through the jump back, so immediates cannot split a "
                     "handler."}};
        if (!warning.empty()) out["warning"] = warning;
        if (!skipped.empty()) out["skipped"] = skipped;
        return s_http_response::ok(out);
    });

    // POST /api/vm/exception_flow - Exception stream and its dispatch pattern.
    //
    // Reads only the plugin's event log, so it works while the target runs.
    router.post("/api/vm/exception_flow", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) body = nlohmann::json::object();

        const auto since_seq = body_u64(body, "since", 0, 0, UINT64_MAX);
        const auto limit = static_cast<size_t>(body_u64(body, "limit", 200, 1, 2000));
        const auto payload = event_log::since(since_seq);

        auto events = nlohmann::json::array();
        std::map<std::string, uint64_t> counts_by_code;
        // Addresses per code, deduped on insert: this decides whether a repeated code is
        // a dispatch loop or noise, and stays small because the set of codes is small.
        std::map<std::string, std::vector<duint>> addresses_by_code;
        std::string dominant_code;
        uint64_t dominant_count = 0;
        uint64_t total = 0;

        for (const auto& event : payload.value("events", nlohmann::json::array())) {
            if (json_string(event, "type") != "exception") continue;
            ++total;

            const auto code = json_string(event, "code", "unknown");
            const auto address_text = json_string(event, "address");

            if (events.size() < limit) {
                events.push_back({
                    {"seq",          event.value("seq", 0ull)},
                    {"tick_ms",      event.value("tick_ms", 0ull)},
                    {"type",         "exception"},
                    {"code",         code},
                    {"address",      address_text},
                    {"first_chance", event.value("first_chance", true)},
                    {"nested",       event.value("nested", false)}});
            }

            if (++counts_by_code[code] > dominant_count) {
                dominant_count = counts_by_code[code];
                dominant_code = code;
            }

            duint address = 0;
            if (!parse_hex_token(address_text, address)) continue;
            auto& known = addresses_by_code[code];
            if (std::find(known.begin(), known.end(), address) == known.end()) {
                known.push_back(address);
            }
        }

        const auto& dominant_addresses = addresses_by_code[dominant_code];
        const bool dominant_share = total > 0 &&
                                    static_cast<double>(dominant_count) /
                                            static_cast<double>(total) >= 0.60;
        const bool small_handler_set = dominant_addresses.size() <= 16;

        nlohmann::json out = {
            {"since", since_seq},
            {"total", total},
            {"count", events.size()},
            {"limit", limit},
            {"events", events},
            {"counts_by_code", counts_by_code}};

        if (total > 0 && dominant_share && small_handler_set) {
            auto handlers = nlohmann::json::array();
            for (duint address : dominant_addresses) {
                handlers.push_back(format_utils::format_address(address));
            }
            out["pattern"] = "exception-driven dispatch";
            out["dominant_code"] = dominant_code;
            out["dominant_count"] = dominant_count;
            out["handler_addresses"] = handlers;
            out["note"] =
                "The same first-chance code fires repeatedly and the fault addresses cycle "
                "through a small set: control flow is carried by faults, which is the "
                "exception-driven VM shape. That is expected behaviour, not a bug in the target "
                "or the debugger. The addresses above are the handlers to disassemble first - "
                "passing one to /api/vm/handlers as a dispatcher is meaningless, so use the "
                "recurring address with the most distinct predecessors from /api/vm/discover "
                "instead.";
            return s_http_response::ok(out);
        }

        auto top_codes = nlohmann::json::array();
        std::vector<std::pair<uint64_t, std::string>> sorted;
        sorted.reserve(counts_by_code.size());
        for (const auto& kv : counts_by_code) sorted.emplace_back(kv.second, kv.first);
        std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
            return a.first != b.first ? a.first > b.first : a.second < b.second;
        });
        for (size_t i = 0; i < sorted.size() && i < 16; ++i) {
            top_codes.push_back({{"code", sorted[i].second}, {"count", sorted[i].first}});
        }
        out["pattern"] = "mixed";
        out["top_codes"] = top_codes;
        out["note"] = total == 0
            ? std::string("No exception events were buffered after 'since'. Either the target "
                          "has not faulted yet, or the event ring already wrapped past them (see "
                          "'dropped' in /api/command/events). Pass a lower 'since' or exercise the "
                          "protected code first: an empty result here is missing data, not "
                          "evidence that the target is not exception-driven.")
            : std::string("No single exception code dominates with a small set of fault "
                          "addresses, so this does not look like an exception-driven dispatcher: "
                          "it is either ordinary fault traffic (guard pages, load-time exceptions) "
                          "or several unrelated patterns interleaved. Run more of the workload "
                          "and pass a higher 'since' to narrow the window.");
        return s_http_response::ok(out);
    });
}

} // namespace handlers
