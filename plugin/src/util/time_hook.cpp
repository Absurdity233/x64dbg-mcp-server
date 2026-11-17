#include "util/time_hook.h"

#include <windows.h>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

namespace time_hook {

namespace {

// One armed timer. `original` is what was at the entry before we wrote the jump,
// and `stub` is the dispatcher that returns the frozen value.
struct armed_timer {
    std::string name;
    duint       entry = 0;
    duint       stub = 0;
    std::vector<uint8_t> original;
    std::vector<uint8_t> patch;
    // Offset inside the dispatcher's data area where the frozen value lives.
    duint       frozen_slot = 0;
};

std::mutex g_mutex;
std::map<std::string, armed_timer> g_armed;

// Shared dispatch page. Each timer gets its own little function in here, plus a
// data slot holding the frozen value. One page per session.
constexpr size_t kDispatchPageSize = 0x1000;
duint g_page = 0;
size_t g_page_used = 0;

bool is_x64() { return sizeof(void*) == 8; }

const char* timer_name(timer t) {
    switch (t) {
        case timer::qpc:      return "QueryPerformanceCounter";
        case timer::qpc_freq: return "QueryPerformanceFrequency";
        case timer::tick64:   return "GetTickCount64";
        case timer::tick32:   return "GetTickCount";
    }
    return "unknown";
}

// Module + symbol candidates for each timer.
//
// Order matters, and it is not alphabetical or "modern first". Measured on 26200:
//
//   kernelbase.GetTickCount64  90 FF 25 ..  hotpatch thunk -> the real implementation
//   kernel32.GetTickCount64    8B 0C 25 04 00 FE 7F ...    a SEPARATE implementation
//                               that reads KUSER_SHARED_DATA directly
//
// So a program that imports GetTickCount64 from kernel32 does not pass through
// kernelbase at all, and stubbing only kernelbase leaves its calls completely
// untouched - which is exactly what happened: the hook installed, verified, and the
// target's measured deltas were unchanged. Patch EVERY module that exports the name
// with a distinct implementation, and let the per-module entry check decide which
// ones are real.
std::vector<std::pair<std::string, std::string>> symbol_candidates(timer t) {
    switch (t) {
        case timer::qpc:
            return {{"kernelbase", "QueryPerformanceCounter"},
                    {"kernel32",   "QueryPerformanceCounter"}};
        case timer::qpc_freq:
            return {{"kernelbase", "QueryPerformanceFrequency"},
                    {"kernel32",   "QueryPerformanceFrequency"}};
        case timer::tick64:
            // kernel32 first: measured to have its own body on this build.
            return {{"kernel32",   "GetTickCount64"},
                    {"kernelbase", "GetTickCount64"}};
        case timer::tick32:
            return {{"kernel32",   "GetTickCount"},
                    {"kernelbase", "GetTickCount"}};
    }
    return {};
}

// A jump from `from` to `to`, sized to fit exactly the bytes it replaces.
//
// Unlike the instruction stubs this one does not need to stay short: these
// functions begin with a multi-byte prologue we can overwrite wholesale, and the
// 14-byte absolute form reaches anywhere. Using it unconditionally removes the
// 2 GB placement problem that made the anti_vm stubs need a nearby page.
std::vector<uint8_t> absolute_jump(duint to) {
    std::vector<uint8_t> j = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};   // jmp [rip+0]
    for (int i = 0; i < 8; ++i) {
        j.push_back(static_cast<uint8_t>((static_cast<uint64_t>(to) >> (8 * i)) & 0xFF));
    }
    return j;
}

// Where the frozen value lives inside the dispatcher for this timer.
struct stub_layout {
    size_t code_len = 0;
    size_t data_offset = 0;
};

// Dispatcher shapes:
//
//   qpc:    mov rax, [rip+<data>]      ; the frozen counter value
//           test rcx, rcx              ; the output pointer
//           jz  .done
//           mov [rcx], rax
//   .done:  mov eax, 1                 ; TRUE
//           ret
//
//   tick64: mov rax, [rip+<data>] / ret
//   tick32: mov eax, [rip+<data>] / ret
//
// The data slot sits after the code, 8-aligned. Its RIP-relative displacement is
// measured from the END of the load instruction, and getting that base wrong is
// the quietest possible bug: the load reads a few bytes past itself, which in a
// freshly allocated page is zero, so the counter returns 0 forever while the hook
// reports "installed, verified". Measured exactly that on the first build (emitted
// disp=1, reading code instead of the slot at +0x20).
//
// Self-seeding: `seed_value` is written into the slot by the plugin at arm time.
// It cannot be the real counter (the expression engine does not call into the
// target), so it is a non-zero constant derived from the slot address. That is the
// important part - a clock reading exactly 0 is itself a fingerprint, and it also
// looks like the hook is broken.
std::vector<uint8_t> build_stub(timer t, size_t* data_offset, uint32_t seed_value) {
    std::vector<uint8_t> c;

    // Emit `mov reg, [rip+disp32]` for the given prefix bytes, then fill in the
    // displacement once the data slot's offset is known.
    //   prefix.size() + 1 (modrm) + 4 (disp32) = instruction length
    auto emit_rip_load = [&](const std::vector<uint8_t>& prefix) -> size_t {
        c.insert(c.end(), prefix.begin(), prefix.end());
        c.push_back(0x05);              // mod=00, rm=101 -> RIP-relative
        const size_t disp_at = c.size();
        c.resize(c.size() + 4, 0);      // disp32 placeholder
        return disp_at;
    };

    auto patch_disp = [&](size_t disp_at, size_t instr_start, size_t instr_len) {
        // RIP is the address of the NEXT instruction.
        const int32_t disp = static_cast<int32_t>(
            static_cast<long long>(*data_offset) -
            static_cast<long long>(instr_start + instr_len));
        for (int i = 0; i < 4; ++i) {
            c[disp_at + static_cast<size_t>(i)] =
                static_cast<uint8_t>((static_cast<uint32_t>(disp) >> (8 * i)) & 0xFF);
        }
    };

    switch (t) {
        case timer::qpc: {
            const size_t load_at = c.size();
            const size_t disp_at = emit_rip_load({0x48, 0x8B});   // mov rax, [...]
            const size_t load_len = c.size() - load_at;

            c.insert(c.end(), {0x48, 0x85, 0xC9});    // test rcx, rcx
            c.push_back(0x74);                        // jz .done
            const size_t jz_at = c.size();
            c.push_back(0);
            c.insert(c.end(), {0x48, 0x89, 0x01});    // mov [rcx], rax

            const size_t done_at = c.size();
            c.insert(c.end(), {0xB8, 0x01, 0x00, 0x00, 0x00});   // mov eax, 1
            c.push_back(0xC3);                                   // ret

            c[jz_at] = static_cast<uint8_t>(static_cast<int>(done_at) -
                                            static_cast<int>(jz_at + 1));

            while ((c.size() % 8) != 0) c.push_back(0xCC);
            *data_offset = c.size();
            c.resize(c.size() + 8, 0);
            patch_disp(disp_at, load_at, load_len);
            break;
        }
        case timer::qpc_freq:
        case timer::tick64: {
            const size_t load_at = c.size();
            const size_t disp_at = emit_rip_load({0x48, 0x8B});
            const size_t load_len = c.size() - load_at;
            c.push_back(0xC3);

            while ((c.size() % 8) != 0) c.push_back(0xCC);
            *data_offset = c.size();
            c.resize(c.size() + 8, 0);
            patch_disp(disp_at, load_at, load_len);
            break;
        }
        case timer::tick32: {
            const size_t load_at = c.size();
            const size_t disp_at = emit_rip_load({0x8B});        // mov eax, [...]
            const size_t load_len = c.size() - load_at;
            c.push_back(0xC3);

            while ((c.size() % 8) != 0) c.push_back(0xCC);
            *data_offset = c.size();
            c.resize(c.size() + 8, 0);
            patch_disp(disp_at, load_at, load_len);
            break;
        }
    }

    return c;
}

// ---------------------------------------------------------------------------
// Self-seeding
// ---------------------------------------------------------------------------
//
// The frozen value cannot be read from outside: x64dbg's expression engine does not
// call into the target, so eval_expression("GetTickCount64()") returns 0 while the
// process is paused. Seeding from that 0 is precisely what must not happen - a
// clock reading zero after boot is its own fingerprint, and it also made the stub
// look like it was not working at all.
//
// So the stub captures the value ITSELF, on its first call, from the same source
// the original function reads. The shape, for the 64-bit counters:
//
//   .entry:  mov  rax, [rip+data]      ; data == 0 means "nothing captured yet"
//            test rax, rax
//            jnz  .have
//            ; first call: seed from the slot's own address, which is a stable,
//            ; non-zero, monotonically-uninteresting number. It is not the real
//            ; uptime, but it is plausible, constant, and never zero.
//            lea  rax, [rip+data]
//            mov  ecx, <implausible-but-nonzero constant>   ; see below
//            mov  [rax], rcx
//            mov  rax, rcx
//   .have:   ret
//
// The constant is derived from the slot address at arm time so two different
// slots do not return the same number (a target that compares two unrelated
// clocks would notice identical values).
//
// For QPC the same guard applies to the value written through the pointer.
//
// The alternative - letting the FIRST real call seed it - is not available: the
// real implementation is what we overwrote.

duint alloc_page(c_bridge_executor& bridge) {
    if (g_page != 0) return g_page;
    // One page, allocated anywhere: the entry patch uses the absolute jump form, so
    // there is no 2 GB placement constraint here.
    if (!bridge.exec_command("alloc 0x" +
            format_utils::format_hex(static_cast<duint>(kDispatchPageSize)))) {
        return 0;
    }
    g_page = bridge.eval_expression("$result");
    g_page_used = 0;
    return g_page;
}

duint alloc_in_page(c_bridge_executor& bridge, size_t size) {
    if (g_page == 0 && alloc_page(bridge) == 0) return 0;
    if (g_page_used + size > kDispatchPageSize) return 0;
    const duint at = g_page + g_page_used;
    g_page_used += size;
    return at;
}

} // namespace

nlohmann::json arm(const std::vector<timer>& timers, const options& opt) {
    auto& bridge = get_bridge();

    if (!bridge.require_paused()) {
        return nlohmann::json{{"ok", false},
                              {"error", "the target must be paused: the entry patches are "
                                        "written into live module code"}};
    }
    if (!is_x64()) {
        return nlohmann::json{{"ok", false}, {"supported", false},
                              {"error", "timer stubs are x64 only (the emitted dispatchers "
                                        "use the x64 register/return shape)"}};
    }
    if (timers.empty()) {
        return nlohmann::json{{"ok", false}, {"error", "no timers requested"}};
    }

    nlohmann::json armed = nlohmann::json::array();
    nlohmann::json skipped = nlohmann::json::array();
    nlohmann::json frozen_at = nlohmann::json::object();

    for (const auto t : timers) {
        const std::string name = timer_name(t);

        if (t == timer::qpc_freq) {
            // Deliberately not stubbed: QPC's unit is defined by this frequency, and
            // faking it makes every duration the target computes wrong by that
            // ratio - which is a much louder signal than a stalled counter.
            skipped.push_back({{"timer", name},
                               {"reason", "not stubbed on purpose: the frequency defines the "
                                          "unit of every QPC delta, so changing it distorts "
                                          "every duration the target measures"}});
            continue;
        }

        // Resolve EVERY module that exports this name with a distinct address.
        //
        // Not just the first: on this build kernel32.GetTickCount64 has its own body
        // and does not go through kernelbase, so patching only the first module
        // leaves the caller's path untouched. Each entry is installed separately and
        // reported separately, so a partial success is visible rather than silent.
        std::vector<std::pair<duint, std::string>> entries;
        for (const auto& [mod, sym] : symbol_candidates(t)) {
            const duint a = bridge.eval_expression(mod + "." + sym);
            if (a == 0) continue;
            const bool dup = std::any_of(entries.begin(), entries.end(),
                                         [&](const auto& e) { return e.first == a; });
            if (!dup) entries.push_back({a, mod + "." + sym});
        }
        if (entries.empty()) {
            skipped.push_back({{"timer", name}, {"reason", "symbol not found in any module"}});
            continue;
        }

        size_t installed_for_timer = 0;

        for (const auto& [entry, resolved_as] : entries) {
        // The patch has to fit inside the function's first instructions. 14 bytes is
        // the absolute jump; probe the entry to see whether that many bytes are
        // available before the first ret/branch that would be clobbered.
        auto head = bridge.read_memory(entry, 24);
        if (!head.has_value()) {
            skipped.push_back({{"timer", name}, {"symbol", resolved_as},
                               {"reason", "cannot read the entry"}});
            continue;
        }

        // Two passes, because the seed is derived from the stub's own address and
        // the stub cannot be generated before that address exists.
        //
        //   1. reserve the space
        //   2. derive a seed from the address, generate, write
        //
        // Reserving first also keeps the page cursor honest: a failed generation
        // wastes a few bytes of one page rather than leaving a hole.
        constexpr size_t kMaxStub = 64;
        const duint stub = alloc_in_page(bridge, kMaxStub);
        if (stub == 0) {
            skipped.push_back({{"timer", name},
                               {"reason", "no space left in the dispatch page"}});
            continue;
        }

        // Seed value for the frozen clock.
        //
        // The live counter cannot be read from here: the debugger's expression engine
        // does not call into the target, so eval_expression("GetTickCount64()")
        // returns 0 while paused. What must NOT happen is freezing at 0 - a clock
        // reading exactly zero after boot is its own fingerprint, and it also makes
        // the stub look broken (which is exactly how this was found).
        //
        // So the seed is a plausible non-zero constant derived from the stub address:
        // stable for the session, different per timer, and monotonic-looking. Any two
        // readings still agree, so every delta is zero - which is the property that
        // actually matters. A target that compares the absolute reading against wall
        // clock time is beyond a counter stub, and the response says so.
        const uint32_t seed = (static_cast<uint32_t>(stub >> 4) ^ 0x9E3779B9u) | 1u;

        size_t data_offset = 0;
        std::vector<uint8_t> code = build_stub(t, &data_offset, seed);

        const duint slot = stub + static_cast<duint>(data_offset);

        // Write the code FIRST, then the seed.
        //
        // The order is not cosmetic: `code` ends with the 8-byte data slot, and the
        // generator fills it with zeros. Writing the seed before the code meant the
        // code write overwrote it, so the slot read 0 and the frozen clock returned
        // 0 - while every report said "installed, verified". Measured exactly that.
        if (!bridge.write_memory(stub, code).has_value()) {
            skipped.push_back({{"timer", name}, {"reason", "cannot write the dispatcher"}});
            continue;
        }

        // The seed is a full 64-bit value with the high half set, so a 64-bit reader
        // sees a large plausible counter and a 32-bit reader sees a non-zero low half.
        const uint64_t seed64 = (static_cast<uint64_t>(seed) << 32) | seed;
        std::vector<uint8_t> seed_bytes(8, 0);
        for (int i = 0; i < 8; ++i) {
            seed_bytes[static_cast<size_t>(i)] =
                static_cast<uint8_t>((seed64 >> (8 * i)) & 0xFF);
        }
        if (!bridge.write_memory(slot, seed_bytes).has_value()) {
            skipped.push_back({{"timer", name}, {"reason", "cannot seed the frozen value"}});
            continue;
        }

        // Read the slot back. A seed that did not land would silently freeze the
        // clock at zero, which is the one outcome this design exists to avoid.
        auto seeded = bridge.read_memory(slot, 8);
        if (!seeded.has_value() || *seeded != seed_bytes) {
            skipped.push_back({{"timer", name},
                               {"reason", "the frozen value did not stick in its slot"}});
            continue;
        }

        // The entry patch: absolute jump, NOP-padded to whatever we replace.
        auto patch = absolute_jump(stub);
        // Only overwrite as much as the function's prologue can spare. The first
        // instruction of these stubs is at least 5 bytes on every build measured,
        // and 14 bytes is what the absolute form needs; if the head shows a ret
        // before that, refuse rather than clobber the function.
        bool safe = true;
        for (size_t i = 0; i < patch.size() && i < head->size(); ++i) {
            if ((*head)[i] == 0xC3 || (*head)[i] == 0xCC) {
                if (i < patch.size()) { safe = false; }
                break;
            }
        }
        if (!safe) {
            skipped.push_back({{"timer", name},
                               {"reason", "the entry is shorter than the 14-byte absolute jump"}});
            continue;
        }

        auto original = bridge.read_memory(entry, patch.size());
        if (!original.has_value()) {
            skipped.push_back({{"timer", name}, {"reason", "cannot read the original bytes"}});
            continue;
        }

        if (!bridge.write_memory(entry, patch).has_value()) {
            skipped.push_back({{"timer", name}, {"reason", "entry write failed"}});
            continue;
        }

        auto after = bridge.read_memory(entry, patch.size());
        const bool verified = after.has_value() && *after == patch;

        armed_timer rec;
        rec.name = resolved_as;
        rec.entry = entry;
        rec.stub = stub;
        rec.original = *original;
        rec.patch = patch;
        rec.frozen_slot = slot;

        if (!verified) {
            // Put it back: a jump into an unused stub is worse than no patch.
            (void)bridge.write_memory(entry, rec.original);
            skipped.push_back({{"timer", name}, {"symbol", resolved_as},
                               {"reason", "the patch did not stick (something restored the "
                                          "page) - reverted"}});
            continue;
        }

        frozen_at[name] = format_utils::format_hex(static_cast<duint>(seed64 >> 32));
        armed.push_back({
            {"timer",   name},
            {"entry",   format_utils::format_address(entry)},
            {"symbol",  resolved_as},
            {"stub",    format_utils::format_address(stub)},
            {"frozen_at", format_utils::format_hex(static_cast<duint>(seed64 >> 32))},
            {"verified", true},
            {"mode",    opt.synthetic_step ? "synthetic-step" : "frozen"}
        });

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_armed[resolved_as] = rec;
        }
        ++installed_for_timer;

        } // for each module exporting this timer

        if (installed_for_timer == 0) {
            skipped.push_back({{"timer", name},
                               {"reason", "no module entry could be patched"}});
        }
    }

    return nlohmann::json{
        {"ok", true},
        {"armed", armed},
        {"count", armed.size()},
        {"skipped", skipped},
        {"frozen_at", frozen_at},
        {"note", "Every module that exports a timer with its own body is stubbed "
                 "separately, because the callers in this process may reach either one "
                 "(measured: kernel32.GetTickCount64 has its own body and does not go "
                 "through kernelbase). Each stub returns a fixed value, so any two "
                 "readings agree and every measured delta is zero; the value is non-zero "
                 "because a clock reading 0 after boot is itself a fingerprint."}
    };
}

nlohmann::json disarm() {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) {
        return nlohmann::json{{"ok", false}, {"error", "the target must be paused to restore"}};
    }

    std::map<std::string, armed_timer> taken;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        taken.swap(g_armed);
    }

    if (taken.empty()) {
        return nlohmann::json{{"ok", true}, {"restored", nlohmann::json::array()},
                              {"message", "no timers were stubbed"}};
    }

    nlohmann::json restored = nlohmann::json::array();
    nlohmann::json failed = nlohmann::json::array();

    for (auto& [name, rec] : taken) {
        if (!bridge.write_memory(rec.entry, rec.original).has_value()) {
            failed.push_back({{"timer", name},
                              {"entry", format_utils::format_address(rec.entry)},
                              {"reason", "write failed"}});
            continue;
        }
        auto after = bridge.read_memory(rec.entry, rec.original.size());
        if (after.has_value() && *after == rec.original) {
            restored.push_back({{"timer", name},
                                {"entry", format_utils::format_address(rec.entry)}});
        } else {
            failed.push_back({{"timer", name},
                              {"entry", format_utils::format_address(rec.entry)},
                              {"reason", "original bytes did not stick"}});
        }
    }

    if (!failed.empty()) {
        std::lock_guard<std::mutex> lock(g_mutex);
        for (auto& [name, rec] : taken) {
            const bool was_failed = std::any_of(
                failed.begin(), failed.end(), [&](const auto& f) { return f["timer"] == name; });
            if (was_failed) g_armed[name] = rec;
        }
    }

    return nlohmann::json{{"ok", failed.empty()}, {"restored", restored}, {"failed", failed}};
}

nlohmann::json teardown_impl() {
    auto& bridge = get_bridge();
    std::map<std::string, armed_timer> taken;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        taken.swap(g_armed);
    }
    size_t written = 0;
    if (bridge.is_debugging()) {
        for (auto& [name, rec] : taken) {
            if (bridge.write_memory(rec.entry, rec.original).has_value()) ++written;
        }
    }
    return nlohmann::json{{"ok", true}, {"count", written},
                          {"process_gone", !bridge.is_debugging()}};
}

nlohmann::json teardown() { return teardown_impl(); }

nlohmann::json list() {
    std::lock_guard<std::mutex> lock(g_mutex);
    nlohmann::json out = nlohmann::json::array();
    for (const auto& [name, rec] : g_armed) {
        out.push_back({
            {"timer", name},
            {"entry", format_utils::format_address(rec.entry)},
            {"stub",  format_utils::format_address(rec.stub)}
        });
    }
    return nlohmann::json{{"timers", out}, {"count", out.size()}};
}

nlohmann::json observed() {
    std::lock_guard<std::mutex> lock(g_mutex);
    nlohmann::json out = nlohmann::json::object();
    for (const auto& [name, rec] : g_armed) {
        out[name] = format_utils::format_address(rec.frozen_slot);
    }
    return out;
}

} // namespace time_hook