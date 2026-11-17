// Verifies the two new ntdll behaviours against the target's own reading:
//   0x0D ProcessDebugObject  - was completely unstubbed before
//   0x23 SystemKernelDebuggerInformation - must answer {0,1}, not {0,0}
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" NTSTATUS NTAPI NtQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
extern "C" NTSTATUS NTAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

int main() {
    const char* rp = getenv("ADTEST_REPORT");
    FILE* o = rp ? fopen(rp, "w") : stdout;
    if (!o) o = stdout;
    fprintf(o, "=== ntdll new classes ===\n\n");

    // 0x0D returns DEBUG_OBJECT whose leading field is the Handle.
    unsigned char dobj[32]; memset(dobj, 0xAA, sizeof(dobj));
    ULONG ret = 0;
    NTSTATUS st = NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)0x0D,
                                            dobj, sizeof(dobj), &ret);
    unsigned long long handle = 0; memcpy(&handle, dobj, 8);
    fprintf(o, "ProcessDebugObject(0x0D)  status=0x%08X handle=%llu %s\n",
            (unsigned)st, handle, handle ? "DETECTED" : "clean");

    struct { BYTE present; BYTE notpresent; } kd = {0xAA, 0xAA};
    st = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x23, &kd, sizeof(kd), &ret);
    fprintf(o, "KernelDebugger(0x23)     status=0x%08X present=%u notpresent=%u %s\n",
            (unsigned)st, kd.present, kd.notpresent,
            (kd.present == 0 && kd.notpresent == 1) ? "clean" : "ODD");

    fflush(o);
    if (rp) fclose(o);
    (void)getchar();
    return 0;
}
