// KUSER_SHARED_DATA timing check: reads the tick counter with NO timer API, the way
// a protection that wants to avoid inline hooks would. This is what api-level stubs
// cannot see, so it is the test that decides whether the direct-read handling works.
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    const char* rp = getenv("ADTEST_REPORT");
    FILE* o = rp ? fopen(rp, "w") : stdout;
    if (!o) o = stdout;

    fprintf(o, "=== KUSER_SHARED_DATA direct timing ===\n\n");

    // Volatile absolute reads: the compiler must emit the real memory access.
    volatile DWORD* tickLow  = (volatile DWORD*)0x7FFE0004;
    volatile DWORD* tickHigh = (volatile DWORD*)0x7FFE0324;
    volatile DWORD* intrTime = (volatile DWORD*)0x7FFE0014;

    DWORD a0 = *tickLow;
    Sleep(60);
    DWORD a1 = *tickLow;
    fprintf(o, "  TickCountLow(0x7FFE0004)  %lu -> %lu  delta=%ld\n",
            a0, a1, (long)(a1 - a0));

    DWORD h0 = *tickHigh;
    Sleep(10);
    DWORD h1 = *tickHigh;
    fprintf(o, "  TickCountHigh(0x7FFE0324) %lu -> %lu  delta=%ld\n",
            h0, h1, (long)(h1 - h0));

    DWORD i0 = *intrTime;
    Sleep(60);
    DWORD i1 = *intrTime;
    fprintf(o, "  InterruptTime(0x7FFE0014) %lu -> %lu  delta=%ld\n",
            i0, i1, (long)(i1 - i0));

    fprintf(o, "\n  verdict: %s\n",
            (a1 != a0 || i1 != i0) ? "clock ADVANCED (detectable)" : "clock frozen (clean)");

    fflush(o);
    if (rp) fclose(o);
    (void)getchar();
    return 0;
}
