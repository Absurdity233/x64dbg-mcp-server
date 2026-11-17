// Does freezing KUSER_SHARED_DATA itself stop a register-indirect tick read?
// The page is read-only mapped copy-on-write per process, so a write from the
// debugger changes only the debuggee's view - which is exactly what we need.
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    const char* rp = getenv("ADTEST_REPORT");
    FILE* o = rp ? fopen(rp, "w") : stdout;
    if (!o) o = stdout;

    volatile DWORD* tickLow  = (volatile DWORD*)0x7FFE0004;
    volatile DWORD* intrTime = (volatile DWORD*)0x7FFE0014;

    DWORD a0 = *tickLow;  DWORD i0 = *intrTime;
    Sleep(120);
    DWORD a1 = *tickLow;  DWORD i1 = *intrTime;

    fprintf(o, "tick   %lu -> %lu  delta=%ld\n", a0, a1, (long)(a1 - a0));
    fprintf(o, "intr   %lu -> %lu  delta=%ld\n", i0, i1, (long)(i1 - i0));
    fprintf(o, "verdict: %s\n",
            (a1 != a0 || i1 != i0) ? "ADVANCED" : "frozen");
    fflush(o);
    if (rp) fclose(o);
    (void)getchar();
    return 0;
}
