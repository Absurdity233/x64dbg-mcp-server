// Test target for the x64dbg MCP anti-detection work.
//
// Deliberately implements every check the plugin claims to defeat, and prints
// which ones fired, so "the feature works" is a claim backed by the target's own
// verdict rather than by the plugin's self-report.
//
// Build:  cl /nologo /O1 adtest.cpp /link /SUBSYSTEM:CONSOLE /OUT:adtest.exe

#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>
#include <string.h>

// NtQueryInformationProcess comes from winternl.h (declared there with the
// PROCESSINFOCLASS enum). The plugin's stub dispatches on the raw info-class
// numbers, so the calls below pass them as explicit ULONGs - that is the
// contract under test, not the SDK enum's spelling.

// --- 1. PEB checks ---------------------------------------------------------

static int check_is_debugger_present() {
    return IsDebuggerPresent() ? 1 : 0;
}

static int check_peb_direct() {
    // Read the PEB the way a packer does, without going through the API.
#ifdef _WIN64
    const auto peb = reinterpret_cast<BYTE*>(__readgsqword(0x60));
#else
    const auto peb = reinterpret_cast<BYTE*>(__readfsdword(0x30));
#endif
    return peb[0x02];   // PEB.BeingDebugged
}

static int check_ntglobalflag() {
#ifdef _WIN64
    const auto peb = reinterpret_cast<BYTE*>(__readgsqword(0x60));
    const DWORD flags = *reinterpret_cast<DWORD*>(peb + 0xBC);
#else
    const auto peb = reinterpret_cast<BYTE*>(__readfsdword(0x30));
    const DWORD flags = *reinterpret_cast<DWORD*>(peb + 0x68);
#endif
    return (flags & 0x70) ? 1 : 0;   // FLG_HEAP_ENABLE_TAIL_CHECK|FREE_CHECK|VALIDATE_PARAMETERS
}

static int check_heap_flags() {
#ifdef _WIN64
    const auto peb = reinterpret_cast<BYTE*>(__readgsqword(0x60));
    const auto heap = *reinterpret_cast<BYTE**>(peb + 0x30);
    const DWORD flags = *reinterpret_cast<DWORD*>(heap + 0x70);
    const DWORD force = *reinterpret_cast<DWORD*>(heap + 0x74);
#else
    const auto peb = reinterpret_cast<BYTE*>(__readfsdword(0x30));
    const auto heap = *reinterpret_cast<BYTE**>(peb + 0x18);
    const DWORD flags = *reinterpret_cast<DWORD*>(heap + 0x40);
    const DWORD force = *reinterpret_cast<DWORD*>(heap + 0x44);
#endif
    return (flags != 2 || force != 0) ? 1 : 0;
}

// --- 2. Kernel-mode checks (need the driver to defeat) ---------------------

static int check_debug_port() {
    DWORD_PTR port = 0;
    const auto st = NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)7,
                                              &port, sizeof(port), nullptr);
    if (st != 0) return -1;
    return port != 0 ? 1 : 0;
}

static int check_debug_object() {
    HANDLE obj = nullptr;
    const auto st = NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)0x1E,
                                              &obj, sizeof(obj), nullptr);
    if (st != 0) return -1;
    return obj != nullptr ? 1 : 0;
}

static int check_debug_flags() {
    // ProcessDebugFlags is INVERTED: 0 means being debugged.
    DWORD flags = 1;
    const auto st = NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)0x1F,
                                              &flags, sizeof(flags), nullptr);
    if (st != 0) return -1;
    return flags == 0 ? 1 : 0;
}

// --- 3. Hardware / VM probes ------------------------------------------------

static int check_cpuid_hypervisor() {
    int regs[4];
    __cpuid(regs, 1);
    return (regs[2] & (1 << 31)) ? 1 : 0;
}

static int check_cpuid_vendor() {
    int regs[4];
    __cpuid(regs, 0x40000000);
    // "VMwareVMware" / "VBoxVBoxVBox" / "Microsoft Hv"
    return (regs[1] == 0x61774D56 || regs[1] == 0x786F4256 || regs[1] == 0x7263694D) ? 1 : 0;
}

static int check_rdtsc_delta() {
    // A region of work whose cost is measured. Under a debugger with breakpoints
    // this explodes; the plugin's stub makes every reading zero so the delta is
    // exactly zero.
    const auto t0 = __rdtsc();
    volatile int acc = 0;
    for (int i = 0; i < 1000; ++i) acc += i;
    const auto t1 = __rdtsc();
    return (t1 - t0) > 100000 ? 1 : 0;
}

static int check_dr_registers() {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &ctx)) return -1;
    return (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || ctx.Dr7) ? 1 : 0;
}

// --- 4. The licence-check pattern a crack tool has to defeat ----------------

static int license_valid = 0;

// The shape of every serial check: compute, compare, branch.
static int check_serial(const char* serial) {
    unsigned h = 0;
    for (const char* p = serial; *p; ++p) {
        h = h * 31u + static_cast<unsigned char>(*p);
    }
    // Both branches are reachable so a patch can flip either one.
    if (h == 0x8F3A21C7u) {
        license_valid = 1;
    } else if (h > 0x80000000u) {
        license_valid = 0;
    } else {
        license_valid = 0;
    }
    return license_valid;
}

int main(int argc, char** argv) {
    // Where to write the verdict.
    //
    // Taken from an environment variable, not a command-line switch: the
    // interesting run is under the debugger, and passing extra arguments through
    // x64dbg's own command line makes x64dbg itself fail before the target is
    // even created. An env var arrives untouched.
    const char* report_path = getenv("ADTEST_REPORT");
    FILE* out = stdout;
    if (report_path && *report_path) {
        out = fopen(report_path, "w");
        if (!out) out = stdout;
    }

    fprintf(out, "=== anti-debug / anti-VM self check ===\n");
    fprintf(out, "pid=%lu\n\n", GetCurrentProcessId());

    fprintf(out, "[1] PEB\n");
    fprintf(out, "  IsDebuggerPresent        = %d\n", check_is_debugger_present());
    fprintf(out, "  PEB.BeingDebugged        = %d\n", check_peb_direct());
    fprintf(out, "  PEB.NtGlobalFlag         = %d\n", check_ntglobalflag());
    fprintf(out, "  Heap flags/force         = %d\n", check_heap_flags());

    fprintf(out, "[2] Kernel\n");
    fprintf(out, "  ProcessDebugPort         = %d\n", check_debug_port());
    fprintf(out, "  ProcessDebugObjectHandle = %d\n", check_debug_object());
    fprintf(out, "  ProcessDebugFlags        = %d\n", check_debug_flags());

    fprintf(out, "[3] Hardware / VM\n");
    fprintf(out, "  CPUID hypervisor bit     = %d\n", check_cpuid_hypervisor());
    fprintf(out, "  CPUID vendor leaf        = %d\n", check_cpuid_vendor());
    fprintf(out, "  RDTSC delta              = %d\n", check_rdtsc_delta());
    fprintf(out, "  DR registers             = %d\n", check_dr_registers());

    fprintf(out, "[4] Licence\n");
    const char* serial = (argc > 1) ? argv[1] : "AAAA-BBBB-CCCC";
    fprintf(out, "  serial '%s' -> valid=%d\n", serial, check_serial(serial));

    fprintf(out, "\n"); fflush(out); fprintf(out, "(press Enter to exit)\n"); fflush(out);
    (void)getchar();
    return 0;
}
