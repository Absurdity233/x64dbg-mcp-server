// Timing-check target: measures a region with each API-level timer the way a real
// protection does, so the verdict is the target's own, not the plugin's claim.
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

static void report(FILE* o, const char* name, long long delta, long long threshold) {
    fprintf(o, "  %-22s delta=%-12lld %s\n", name, delta,
            delta > threshold ? "DETECTED (slow)" : "clean");
}

int main() {
    const char* rp = getenv("ADTEST_REPORT");
    FILE* o = rp ? fopen(rp, "w") : stdout;
    if (!o) o = stdout;

    fprintf(o, "=== timing side-channel check ===\n\n[QPC]\n");
    LARGE_INTEGER a{}, b{};
    QueryPerformanceCounter(&a);
    volatile long long acc = 0;
    for (int i = 0; i < 20000; ++i) acc += i;
    QueryPerformanceCounter(&b);
    report(o, "QueryPerformanceCounter", b.QuadPart - a.QuadPart, 50);

    fprintf(o, "[Ticks]\n");
    ULONGLONG t0 = GetTickCount64();
    Sleep(60);
    ULONGLONG t1 = GetTickCount64();
    report(o, "GetTickCount64", (long long)(t1 - t0), 20);

    DWORD d0 = GetTickCount();
    Sleep(60);
    DWORD d1 = GetTickCount();
    report(o, "GetTickCount", (long long)(d1 - d0), 20);

    fprintf(o, "[RDTSC]\n");
    unsigned long long r0 = __rdtsc();
    for (int i = 0; i < 20000; ++i) acc += i;
    unsigned long long r1 = __rdtsc();
    report(o, "RDTSC", (long long)(r1 - r0), 100000);

    fprintf(o, "\n[ptr] %lld\n", acc);
    fflush(o);
    if (rp) fclose(o);
    (void)getchar();
    return 0;
}
