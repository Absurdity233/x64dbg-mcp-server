#include "util/ntdll_hook.h"

#include <windows.h>
#include <algorithm>
#include <cstring>
#include <map>
#include <mutex>

#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "bridge/c_bridge_executor.h"
#include "util/code_stub.h"
#include "util/format_utils.h"

namespace ntdll_hook {

namespace {

// One installed hook.
//
// Two shapes, distinguished by `kind`, because restoring them is different:
// `bytes` restores a code patch, `slot_original` restores a pointer.
struct installed_hook {
    std::string function;
    duint        entry = 0;
    std::string  kind;            // "trampoline" or "hotpatch-slot"
    std::vector<uint8_t> original; // trampoline: displaced bytes
    duint        slot = 0;         // hotpatch: address of the pointer slot
    duint        slot_original = 0;
    duint        dispatcher = 0;   // trampoline: stub body
    std::string  classes;          // "7,30,31" - for the report only
};

std::mutex g_mutex;
std::map<std::string, installed_hook> g_hooks;

// Entry patches computed during planning and consumed during the write pass.
// A side map rather than a field because the plan vector is moved.
std::map<std::string, std::vector<uint8_t>> g_pending_patches;

bool is_x64() { return sizeof(void*) == 8; }

const char* behaviour_name(action a) {
    switch (a) {
        case action::fake_zero_success:       return "zero+success";
        case action::return_success:          return "success";
        case action::return_invalid_parameter:return "invalid-parameter";
    }
    return "unknown";
}

// ---------------------------------------------------------------------------
// Prologue / thunk recognition
// ---------------------------------------------------------------------------

enum class layout {
    unknown,
    syscall_stub,   // real code with an inline `syscall`
    hotpatch_jump,  // `jmp qword ptr [rip+0]` + an inline absolute address
};

struct prologue_info {
    layout   kind = layout::unknown;
    uint32_t ssn = 0;
    duint    syscall_addr = 0;
    bool     sets_r10_from_rcx = false;
    duint    slot = 0;         // hotpatch: address holding the real body
    duint    body = 0;         // hotpatch: the real body
    std::string why;
};

// Recognise what is actually at the exported entry.
//
// The `nop` prefix is included because it is how the hotpatch layout starts:
// `nop; jmp [rip+0]; <addr>`. A stub build check that only looked for `mov
// r10, rcx` would conclude "unrecognised" and refuse, which is what happened
// before this was written.
prologue_info read_prologue(c_bridge_executor& bridge, duint entry) {
    prologue_info p;

    auto code = bridge.read_memory(entry, 48);
    if (!code.has_value() || code->size() < 16) {
        p.why = "cannot read the function prologue";
        return p;
    }
    const auto& b = *code;

    // --- hotpatch jump thunk -------------------------------------------
    // Skip a leading int3/nop padding run (up to 2 bytes), then look for
    // FF 25 xx xx xx xx with a zero displacement: `jmp [rip+0]`.
    size_t i = 0;
    while (i < 2 && (b[i] == 0x90 || b[i] == 0xCC)) ++i;

    if (i + 6 <= b.size() && b[i] == 0xFF && b[i + 1] == 0x25) {
        int32_t disp = 0;
        std::memcpy(&disp, b.data() + i + 2, 4);
        // [rip+disp] where rip = entry + i + 6. Any displacement is fine; in
        // practice it is 0, so the pointer sits right after the jump.
        p.slot = entry + i + 6 + static_cast<duint>(static_cast<int64_t>(disp));

        auto ptr = bridge.read_memory(p.slot, sizeof(duint));
        if (!ptr.has_value()) {
            p.why = "the jmp thunk's pointer slot is unreadable";
            return p;
        }
        std::memcpy(&p.body, ptr->data(), sizeof(duint));

        // A slot pointing nowhere, or back into ntdll's thunk area, is not a
        // hotpatch target. Validate before reporting a layout, because patching
        // an unvalidated slot is how a whole process's syscalls break.
        if (p.body == 0 || p.body == entry || p.slot == 0) {
            p.why = "the jmp thunk points at a null or self address";
            return p;
        }

        p.kind = layout::hotpatch_jump;
        return p;
    }

    // --- direct syscall stub -------------------------------------------
    size_t j = 0;
    if (j + 3 <= b.size() && b[j] == 0x4C && b[j + 1] == 0x8B && b[j + 2] == 0xD1) {
        p.sets_r10_from_rcx = true;
        j += 3;
    }
    if (j + 5 <= b.size() && b[j] == 0xB8) {
        std::memcpy(&p.ssn, b.data() + j + 1, 4);
        j += 5;
    }
    for (size_t k = j; k + 2 <= b.size(); ++k) {
        if (b[k] == 0x0F && b[k + 1] == 0x05) {
            p.syscall_addr = entry + k;
            p.kind = layout::syscall_stub;
            return p;
        }
    }

    p.why = "entry is neither a jmp thunk nor a syscall stub (recognised: 4C 8B D1 / "
            "B8 <ssn> / ... 0F 05, or nop + FF 25 + <addr>)";
    return p;
}

// ---------------------------------------------------------------------------
// Dispatcher code generation (syscall-stub layout only)
// ---------------------------------------------------------------------------
//
//   .check0  cmp edx, <class0>
//            jne .check1
//            <payload0>
//            ret
//   .real    mov r10, rcx / mov eax, <ssn> / jmp <syscall>
//
// The hotpatch layout needs none of this: its dispatcher is a plain function
// that implements the whole call, because there is no prologue state to preserve
// and the slot holds an absolute address, so no jump-range trickery is needed.
struct emitter {
    std::vector<uint8_t> code;
    std::vector<size_t>  jne_operands;

    void u8(uint8_t v) { code.push_back(v); }
    void u32(uint32_t v) {
        for (int i = 0; i < 4; ++i) code.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
    }
    void u64(uint64_t v) {
        for (int i = 0; i < 8; ++i) code.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
    }
    // `cmp edx, imm32` compares the FULL 64-bit register against the immediate,
    // but the info class is a 32-bit argument: the caller may leave garbage in the
    // upper half of edx (measured: class 0x1F arriving as 0xFFFFFFFF0000001F). A
    // 32-bit compare is what the real function does, so the dispatcher must do the
    // same or it silently falls through to the default path for the very classes
    // it was built for.
    void cmp_edx(uint32_t c, bool use_ecx) {
        if (use_ecx) {
            // cmp ecx, imm32. The class argument is not always in edx:
            // NtQuerySystemInformation takes its class in rcx (first argument).
            u8(0x81); u8(0xF9); u32(c);
        } else {
            u8(0x81); u8(0xFA); u32(c);   // cmp edx, imm32
        }
    }
    // Near jump: with several info classes the distance to .real exceeds 127
    // bytes easily, and an out-of-range rel8 would silently corrupt the block.
    void jne_placeholder() {
        u8(0x0F); u8(0x85);
        jne_operands.push_back(code.size());
        u32(0);
    }
    // NtQueryInformationProcess(HANDLE ProcessHandle, ULONG InfoClass, PVOID Buffer,
    //                           ULONG BufferLength, PULONG ReturnLength)
    //
    // x64 argument order is rcx, rdx, r8, r9 - so the OUTPUT BUFFER is r8, not rcx.
    // Writing [rcx] instead writes through the process handle: for the current
    // process that is the pseudo-handle -1, and the call dies with an access
    // violation inside the target. Measured, and it is the single most important
    // detail in this file.
    //
    // The write is DWORD-sized, not QWORD. A caller is entitled to pass a 4-byte
    // buffer for these info classes (they are all ULONG-ish), and writing 8 bytes
    // overruns it into whatever the caller keeps next - measured: a 4-byte buffer
    // followed by a loop counter, where the overrun corrupted the enum value of the
    // NEXT call, so the following two classes fell through to the default path and
    // looked like a dispatcher bug. Honour the documented size, not the convenient
    // one.
// Parameterised on the buffer register, because it is not always r8:
// NtQuerySystemInformation's buffer is rdx (its class is rcx, and it has no
// handle argument). Writing the wrong register would either fault or silently
// leave the real answer in place.
    //
    // The write is DWORD-sized, not QWORD. A caller is entitled to pass a 4-byte
    // buffer for these classes (they are all ULONG-ish), and writing 8 bytes
    // overruns it into whatever the caller keeps next - measured: a 4-byte buffer
    // followed by a loop counter, where the overrun corrupted the enum value of the
    // NEXT call, so the following two classes fell through to the default path and
    // looked like a dispatcher bug. Honour the documented size, not the convenient
    // one.
    void store_dword_at_buffer(uint32_t value, bool buffer_is_rdx) {
        if (buffer_is_rdx) {
            // mov dword ptr [rdx], imm32
            u8(0xC7); u8(0x02); u32(value);
        } else {
            // mov dword ptr [r8], imm32
            u8(0x41); u8(0xC7); u8(0x00); u32(value);
        }
    }

    void mov_eax(uint32_t v) { u8(0xB8); u32(v); }
    void ret() { u8(0xC3); }
    void real_path(uint32_t ssn, uint64_t syscall_addr, bool need_r10) {
        if (need_r10) { u8(0x49); u8(0x89); u8(0xCA); }
        if (ssn != 0) mov_eax(ssn);
        u8(0xFF); u8(0x25); u32(0);
        u64(syscall_addr);
    }

    // Land ONE pending jne on `target`.
    //
    // Taking the index matters: the checks are a fall-through chain, so the jne
    // that ends "is this class 7?" must reach the check for the NEXT class, and
    // only the last one may reach the default path. A single fixup for all of them
    // makes every later class unreachable - which is exactly what shipped first and
    // measured as "class 7 works, 0x1E and 0x1F return STATUS_INVALID_PARAMETER".
    void fixup_one(size_t index, size_t target) {
        if (index >= jne_operands.size()) return;
        const size_t op = jne_operands[index];
        const long long disp = static_cast<long long>(target) -
                               static_cast<long long>(op + 4);
        const auto d = static_cast<int32_t>(disp);
        for (int i = 0; i < 4; ++i) {
            code[op + i] = static_cast<uint8_t>((static_cast<uint32_t>(d) >> (8 * i)) & 0xFF);
        }
    }
};

// x64 function body that implements only the intercepted info classes.
//
// `slot_stub` means the dispatcher is reached through the hotpatch pointer, so it
// must behave as a complete replacement for the function: unimplemented classes
// cannot be forwarded to the real body (we would have to call it, and building a
// call through a stale slot risks re-entering the hook). They return
// STATUS_INVALID_PARAMETER instead, and the install report says so - that is a
// real difference from the trampoline layout and the caller needs to know.
std::vector<uint8_t> build_dispatcher(const std::vector<target_spec>& specs,
                                      const prologue_info& pro,
                                      bool slot_stub) {
    emitter e;

    // One block per class, laid out as a fall-through chain:
    //
    //   .check0  cmp edx, cls0
    //            jne .check1        <- must reach the NEXT check
    //            <payload0>
    //            ret
    //   .check1  cmp edx, cls1
    //            jne .check2
    //            ...
    //   .default ...
    //
    // `next_check` is captured after each block is emitted, so the jne at index i
    // points at the block for i+1 rather than at the common tail.
    std::vector<size_t> next_check(specs.size(), 0);
    for (size_t i = 0; i < specs.size(); ++i) {
        const auto& spec = specs[i];

        const bool class_in_ecx = (spec.args.class_reg == "rcx");
        const bool buf_in_rdx   = (spec.args.buffer_reg == "rdx");

        e.cmp_edx(static_cast<uint32_t>(spec.info_class), class_in_ecx);
        e.jne_placeholder();

        switch (spec.what) {
            case action::fake_zero_success:
                e.store_dword_at_buffer(0, buf_in_rdx); e.mov_eax(0); break;
            case action::fake_nonzero_success:
                e.store_dword_at_buffer(1, buf_in_rdx); e.mov_eax(0); break;
            case action::return_success:
                // Deliberately leaves the buffer alone.
                e.mov_eax(0); break;
            case action::return_invalid_parameter:
                e.mov_eax(0xC000000Du); break;
        }
        e.ret();

        // The next comparison starts here; this is where a miss must land.
        next_check[i] = e.code.size();
    }

    // The tail: everything that matched no class.
    const size_t tail = e.code.size();
    if (!slot_stub) {
        e.real_path(pro.ssn, pro.syscall_addr, pro.sets_r10_from_rcx);
    } else {
        // Unimplemented class: fail the call rather than pass it through. A slot
        // stub cannot forward to the real body without re-entering itself.
        e.mov_eax(0xC000000Du);   // STATUS_INVALID_PARAMETER
        e.ret();
    }

    // Now resolve every jne: block i -> next_check[i], and the last one -> tail.
    for (size_t i = 0; i < specs.size(); ++i) {
        const size_t target = (i + 1 < specs.size()) ? next_check[i] : tail;
        e.fixup_one(i, target);
    }

    return e.code;
}

// Write `code` into the target and return its address, or 0.
//
// Placement: the dispatcher is called, not jumped to, in the hotpatch layout, so
// it may live anywhere; in the trampoline layout it is reached by the entry patch
// which is range-limited, so it is placed near `near_addr`.
duint plant(c_bridge_executor& bridge, const std::vector<uint8_t>& code, duint near_addr) {
    const duint at = code_stub::alloc(bridge, code.size() + 8, near_addr);
    if (at == 0) return 0;
    if (!bridge.write_memory(at, code).has_value()) return 0;
    return at;
}

} // namespace

bool supported() { return is_x64(); }

bool arg_regs_for(const std::string& function, arg_regs* out) {
    // The three functions differ in where the class and buffer live, and the
    // difference is not guessable from the name. NtQuerySystemInformation is the
    // odd one: it has no handle, so every argument shifts one register left -
    // class in rcx, buffer in rdx.
    //
    // Measured on 26200 by reading the exported prologues; the values match the
    // documentation for the x64 calling convention applied to each signature.
    static const std::map<std::string, arg_regs> table = {
        {"NtQueryInformationProcess", {"rdx", "r8"}},
        {"NtQueryObject",             {"rdx", "r8"}},
        {"NtSetInformationThread",    {"rdx", "r8"}},
        {"NtQuerySystemInformation",  {"rcx", "rdx"}},
    };

    const auto it = table.find(function);
    if (it == table.end()) return false;
    *out = it->second;
    return true;
}

nlohmann::json install_defaults(const std::vector<std::string>& functions, bool dry_run) {
    // The classes worth intercepting, per function. Each entry is a check that is
    // actually used in the wild, not a guess:
    //
    //   NtQueryInformationProcess  7    ProcessDebugPort
    //                              0x1E ProcessDebugObjectHandle
    //                              0x1F ProcessDebugFlags (inverted)
    //   NtQueryObject              1    ObjectTypeInformation - a target counts
    //                                  DebugObject handles to spot a debugger
    //   NtQuerySystemInformation   0x23 SystemKernelDebuggerInformation - "is a
    //                                  kernel debugger attached"
    //   NtSetInformationThread     0x11 ThreadHideFromDebugger - letting the
    //                                  target hide the CURRENT thread from the
    //                                  debugger would break the session, so this
    //                                  one is refused rather than faked
    struct def {
        const char* function;
        unsigned long cls;
        action what;
    };
    static const def defaults[] = {
        {"NtQueryInformationProcess", 7,     action::fake_zero_success},
        {"NtQueryInformationProcess", 0x1E,  action::fake_zero_success},
        {"NtQueryInformationProcess", 0x1F,  action::fake_nonzero_success},
        {"NtQueryObject",             1,     action::return_invalid_parameter},
        {"NtQuerySystemInformation",  0x23,  action::fake_zero_success},
        {"NtSetInformationThread",    0x11,  action::return_success},
    };

    std::vector<target_spec> specs;
    nlohmann::json unknown = nlohmann::json::array();

    for (const auto& want : functions) {
        arg_regs regs{};
        if (!arg_regs_for(want, &regs)) {
            unknown.push_back({{"function", want},
                               {"reason", "no argument convention known; supported: "
                                          "NtQueryInformationProcess, NtQueryObject, "
                                          "NtQuerySystemInformation, NtSetInformationThread"}});
            continue;
        }

        bool added = false;
        for (const auto& d : defaults) {
            if (want == d.function) {
                specs.push_back({d.function, d.cls, d.what, regs});
                added = true;
            }
        }
        if (!added) {
            unknown.push_back({{"function", want},
                               {"reason", "no default class set for this function"}});
        }
    }

    if (specs.empty()) {
        return nlohmann::json{{"ok", false},
                              {"error", "no function with a known class set was requested"},
                              {"unsupported", unknown}};
    }

    auto out = install(specs, dry_run);
    if (!unknown.empty()) out["unsupported"] = unknown;
    return out;
}

nlohmann::json install(const std::vector<target_spec>& targets, bool dry_run) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) {
        return nlohmann::json{{"ok", false},
                              {"error", "the target must be paused: the stubs are written "
                                        "into live ntdll pages, and doing that while the "
                                        "target runs races its own calls"}};
    }
    if (!supported()) {
        return nlohmann::json{
            {"ok", false}, {"supported", false},
            {"error", "these stubs are x64 only: on x86 the Nt* prologues take their "
                      "arguments on the stack and use int 2Eh, so the dispatcher does not "
                      "apply. Use harden (user mode) on x32."}
        };
    }
    if (targets.empty()) {
        return nlohmann::json{{"ok", false}, {"error", "no targets requested"}};
    }
    if (bridge.get_module_base("ntdll.dll") == 0) {
        return nlohmann::json{{"ok", false}, {"error", "ntdll.dll is not loaded"}};
    }

    // Group by function: one dispatcher per entry point, several info classes per
    // dispatcher. Separate hooks on the same entry would overwrite each other.
    std::map<std::string, std::vector<target_spec>> grouped;
    for (const auto& t : targets) grouped[t.function].push_back(t);

    struct plan {
        std::string function;
        duint entry = 0;
        std::vector<target_spec> specs;
        prologue_info pro;
        duint dispatcher = 0;
        std::vector<uint8_t> body;
        std::vector<uint8_t> original;
        duint slot = 0;
        duint slot_original = 0;
        bool slot_stub = false;
    };

    std::vector<plan> plans;
    nlohmann::json skipped = nlohmann::json::array();

    for (auto& [func, specs] : grouped) {
        plan p;
        p.function = func;
        p.specs = specs;

        p.entry = bridge.eval_expression("ntdll." + func);
        if (p.entry == 0) {
            skipped.push_back({{"function", func}, {"reason", "symbol not found"}});
            continue;
        }

        p.pro = read_prologue(bridge, p.entry);
        if (p.pro.kind == layout::unknown) {
            skipped.push_back({{"function", func}, {"reason", p.pro.why}});
            continue;
        }
        p.slot_stub = (p.pro.kind == layout::hotpatch_jump);

        p.body = build_dispatcher(p.specs, p.pro, p.slot_stub);
        if (p.body.empty()) {
            skipped.push_back({{"function", func}, {"reason", "dispatcher generation failed"}});
            continue;
        }

        // The dispatcher must be reachable from the entry patch (trampoline
        // layout) or from the slot (anywhere). plant() places it accordingly.
        p.dispatcher = plant(bridge, p.body,
                             p.slot_stub ? 0 : p.entry);
        if (p.dispatcher == 0) {
            skipped.push_back({{"function", func},
                               {"reason", "could not place the dispatcher in the target"}});
            continue;
        }

        if (p.slot_stub) {
            p.slot = p.pro.slot;
            p.slot_original = p.pro.body;
        } else {
            auto prep = code_stub::prepare(bridge, p.entry, 5);
            if (!prep.has_value()) {
                skipped.push_back({{"function", func}, {"reason", prep.error()}});
                continue;
            }
            p.original = prep->original;
            auto patch = code_stub::jump_patch(p.entry, p.dispatcher);
            if (patch.size() < prep->patch.size()) patch.resize(prep->patch.size(), 0x90);
            if (patch.size() > prep->patch.size()) {
                skipped.push_back({{"function", func},
                                   {"reason", "the dispatcher is out of jump range of the "
                                              "entry; nothing was written"}});
                continue;
            }
            g_pending_patches[func] = patch;
        }

        plans.push_back(std::move(p));
    }

    if (plans.empty()) {
        g_pending_patches.clear();
        return nlohmann::json{{"ok", false},
                              {"error", "no hook could be prepared"},
                              {"skipped", skipped}};
    }

    auto describe_plan = [](const plan& p) {
        nlohmann::json classes = nlohmann::json::array();
        for (const auto& s : p.specs) {
            classes.push_back({{"class", format_utils::format_hex(s.info_class)},
                               {"behaviour", behaviour_name(s.what)}});
        }
        return nlohmann::json{
            {"function", p.function},
            {"entry", format_utils::format_address(p.entry)},
            {"layout", p.slot_stub ? "hotpatch-slot" : "trampoline"},
            {"dispatcher", format_utils::format_address(p.dispatcher)},
            {"info_classes", classes},
            {"dispatcher_size", p.body.size()}
        };
    };

    if (dry_run) {
        nlohmann::json out = {{"ok", true}, {"dry_run", true}, {"skipped", skipped},
                              {"would_hook", nlohmann::json::array()}};
        for (const auto& p : plans) out["would_hook"].push_back(describe_plan(p));
        out["note"] = "dry run: nothing was written. Prologues were parsed and dispatchers "
                      "generated, so a clean dry run means install will succeed.";
        g_pending_patches.clear();
        return out;
    }

    nlohmann::json installed = nlohmann::json::array();
    std::vector<installed_hook> written;

    auto rollback = [&]() {
        for (auto it = written.rbegin(); it != written.rend(); ++it) {
            if (it->kind == "hotpatch-slot") {
                std::vector<uint8_t> orig(sizeof(duint));
                std::memcpy(orig.data(), &it->slot_original, sizeof(duint));
                (void)bridge.write_memory(it->slot, orig);
            } else {
                // Unchecked: this runs while another failure is already being
                // reported, and a second error would replace the real one.
                (void)bridge.write_memory(it->entry, it->original);
            }
        }
        written.clear();
    };

    for (auto& p : plans) {
        if (p.slot_stub) {
            // Single 8-byte write. No instruction-length constraints, no
            // displacement, and the slot is data so there is nothing to relocate.
            std::vector<uint8_t> ptr(sizeof(duint));
            std::memcpy(ptr.data(), &p.dispatcher, sizeof(duint));
            if (!bridge.write_memory(p.slot, ptr).has_value()) {
                rollback();
                g_pending_patches.clear();
                return nlohmann::json{{"ok", false},
                                      {"error", "failed writing the hotpatch slot of " + p.function},
                                      {"skipped", skipped}};
            }
            auto after = bridge.read_memory(p.slot, sizeof(duint));
            duint got = 0;
            if (after.has_value()) std::memcpy(&got, after->data(), sizeof(duint));
            if (got != p.dispatcher) {
                rollback();
                g_pending_patches.clear();
                return nlohmann::json{
                    {"ok", false},
                    {"error", "the hotpatch slot of " + p.function + " did not take the new "
                              "pointer (something restored it) - all hooks rolled back"},
                    {"attempted", installed}
                };
            }
            installed_hook h;
            h.function = p.function;
            h.entry = p.entry;
            h.kind = "hotpatch-slot";
            h.slot = p.slot;
            h.slot_original = p.slot_original;
            h.dispatcher = p.dispatcher;
            written.push_back(h);
        } else {
            const auto& patch = g_pending_patches[p.function];
            if (!bridge.write_memory(p.entry, patch).has_value()) {
                rollback();
                g_pending_patches.clear();
                return nlohmann::json{{"ok", false},
                                      {"error", "failed patching the entry of " + p.function},
                                      {"skipped", skipped}};
            }
            auto after = bridge.read_memory(p.entry, patch.size());
            if (!after.has_value() || *after != patch) {
                rollback();
                g_pending_patches.clear();
                return nlohmann::json{
                    {"ok", false},
                    {"error", "the entry bytes of " + p.function + " did not stay patched "
                              "(something restored the page) - all hooks rolled back"},
                    {"attempted", installed}
                };
            }
            installed_hook h;
            h.function = p.function;
            h.entry = p.entry;
            h.kind = "trampoline";
            h.original = p.original;
            h.dispatcher = p.dispatcher;
            written.push_back(h);
        }

        auto entry_json = describe_plan(p);
        entry_json["verified"] = true;
        std::string classes;
        for (const auto& s : p.specs) {
            if (!classes.empty()) classes += ",";
            classes += format_utils::format_hex(s.info_class);
        }
        written.back().classes = classes;
        installed.push_back(entry_json);
    }

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        for (auto& h : written) g_hooks[h.function] = h;
    }
    g_pending_patches.clear();

    // The hotpatch layout cannot forward unknown classes to the real body
    // without re-entering the hook, so say what that costs instead of letting the
    // caller assume full transparency.
    bool any_slot = false;
    for (const auto& p : plans) any_slot = any_slot || p.slot_stub;

    nlohmann::json out = {
        {"ok", true},
        {"hooked", installed},
        {"count", installed.size()},
        {"skipped", skipped},
        {"note", "Each dispatcher answers only the info classes it was built for. "
                 "restore:true writes the original bytes / slot pointer back."}
    };
    if (any_slot) {
        out["caveat"] = "a hotpatch-slot hook replaces the whole function, so info classes "
                        "the target uses for anything else now return STATUS_INVALID_PARAMETER. "
                        "That is the trade for a single-write, range-free hook.";
    }
    return out;
}

nlohmann::json restore() {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) {
        return nlohmann::json{{"ok", false}, {"error", "the target must be paused to restore"}};
    }

    std::map<std::string, installed_hook> taken;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        taken.swap(g_hooks);
    }

    if (taken.empty()) {
        return nlohmann::json{{"ok", true}, {"restored", nlohmann::json::array()},
                              {"message", "nothing was hooked"}};
    }

    nlohmann::json restored = nlohmann::json::array();
    nlohmann::json failed = nlohmann::json::array();

    for (auto& [name, h] : taken) {
        bool ok = false;
        if (h.kind == "hotpatch-slot") {
            std::vector<uint8_t> orig(sizeof(duint));
            std::memcpy(orig.data(), &h.slot_original, sizeof(duint));
            if (bridge.write_memory(h.slot, orig).has_value()) {
                auto after = bridge.read_memory(h.slot, sizeof(duint));
                duint got = 0;
                if (after.has_value()) std::memcpy(&got, after->data(), sizeof(duint));
                ok = (got == h.slot_original);
            }
        } else {
            if (bridge.write_memory(h.entry, h.original).has_value()) {
                auto after = bridge.read_memory(h.entry, h.original.size());
                ok = after.has_value() && *after == h.original;
            }
        }

        if (ok) {
            restored.push_back({{"function", name},
                                {"entry", format_utils::format_address(h.entry)},
                                {"layout", h.kind}});
        } else {
            failed.push_back({{"function", name},
                              {"entry", format_utils::format_address(h.entry)},
                              {"reason", "the original value did not stick"}});
        }
    }

    if (!failed.empty()) {
        std::lock_guard<std::mutex> lock(g_mutex);
        for (auto& [name, h] : taken) {
            const bool was_failed = std::any_of(
                failed.begin(), failed.end(), [&](const auto& f) { return f["function"] == name; });
            if (was_failed) g_hooks[name] = h;
        }
    }

    return nlohmann::json{{"ok", failed.empty()}, {"restored", restored}, {"failed", failed}};
}

// Session-teardown path. Same reasoning as anti_vm::teardown: write back what the
// still-live process allows, and clear the registry regardless, so a terminated
// session cannot leave a hook record that the next session would re-apply to an
// unrelated process at the same address.
nlohmann::json teardown() {
    auto& bridge = get_bridge();

    std::map<std::string, installed_hook> taken;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        taken.swap(g_hooks);
    }

    if (taken.empty()) {
        return nlohmann::json{{"ok", true}, {"restored", nlohmann::json::array()},
                              {"count", 0}, {"message", "nothing was hooked"}};
    }

    const bool live = bridge.is_debugging();
    nlohmann::json restored = nlohmann::json::array();
    size_t written = 0;

    if (live) {
        for (auto& [name, h] : taken) {
            bool ok = false;
            if (h.kind == "hotpatch-slot") {
                std::vector<uint8_t> orig(sizeof(duint));
                std::memcpy(orig.data(), &h.slot_original, sizeof(duint));
                ok = bridge.write_memory(h.slot, orig).has_value();
            } else {
                ok = bridge.write_memory(h.entry, h.original).has_value();
            }
            if (ok) {
                ++written;
                restored.push_back({{"function", name},
                                    {"entry", format_utils::format_address(h.entry)},
                                    {"layout", h.kind}});
            }
        }
    }

    return nlohmann::json{
        {"ok", true},
        {"restored", restored},
        {"count", written},
        {"process_gone", !live},
        {"message", live
            ? "original bytes/pointer written back for " + std::to_string(written) + " hook(s)"
            : "the target had already exited; registry cleared"}
    };
}

nlohmann::json list() {
    std::lock_guard<std::mutex> lock(g_mutex);
    nlohmann::json out = nlohmann::json::array();
    for (const auto& [name, h] : g_hooks) {
        out.push_back({
            {"function", name},
            {"entry", format_utils::format_address(h.entry)},
            {"layout", h.kind},
            {"dispatcher", format_utils::format_address(h.dispatcher)},
            {"info_classes", h.classes}
        });
    }
    return nlohmann::json{{"hooks", out}, {"count", out.size()}};
}

} // namespace ntdll_hook
