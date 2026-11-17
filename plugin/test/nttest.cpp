// Verifies the extended ntdll hook set: NtQueryObject and NtQuerySystemInformation
// are the ones with DIFFERENT argument registers, so they are what actually proves
// the per-function convention table works.
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct _MY_OBJECT_TYPE_INFO {
    UNICODE_STRING TypeName;
    ULONG Reserved[6];
} MY_OBJECT_TYPE_INFO;




int main() {
    const char* rp = getenv("ADTEST_REPORT");
    FILE* o = rp ? fopen(rp, "w") : stdout;
    if (!o) o = stdout;

    fprintf(o, "=== extended ntdll oracles ===\n\n");

    // ObjectTypeInformation = 1, buffer = r8 on this one
    MY_OBJECT_TYPE_INFO oti{};
    ULONG ret = 0;
    NTSTATUS st = NtQueryObject(GetCurrentProcess(), (OBJECT_INFORMATION_CLASS)1, &oti, sizeof(oti), &ret);
    fprintf(o, "NtQueryObject(TypeInformation)  status=0x%08X type='%ws'\n",
            (unsigned)st, oti.TypeName.Buffer ? oti.TypeName.Buffer : L"<none>");

    // SystemKernelDebuggerInformation = 0x23, buffer = rdx on this one
    struct { BYTE DebuggerPresent; BYTE DebuggerNotPresent; } kd = {0xFF, 0xFF};
    st = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x23, &kd, sizeof(kd), &ret);
    fprintf(o, "NtQuerySystemInformation(0x23) status=0x%08X present=%u notpresent=%u\n",
            (unsigned)st, kd.DebuggerPresent, kd.DebuggerNotPresent);

    fflush(o);
    if (rp) fclose(o);
    (void)getchar();
    return 0;
}
