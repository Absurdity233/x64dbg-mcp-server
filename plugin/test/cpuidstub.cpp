// cpuidstub.cpp - minimal reproduction for the anti_vm cpuid stub.
//
// Runs ONE cpuid and prints what came back, so a broken stub shows up as an
// access violation here instead of as "the big test target exited early".
//
// Build: cl /nologo /O1 cpuidstub.cpp /link /SUBSYSTEM:CONSOLE /OUT:cpuidstub.exe

#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    const char* rp = getenv("ADTEST_REPORT");
    FILE* o = rp ? fopen(rp, "w") : stdout;
    if (!o) o = stdout;

    int regs[4] = {0, 0, 0, 0};
    __cpuid(regs, 1);
    fprintf(o, "leaf1  eax=%d ebx=%d ecx=0x%08X edx=%d  hypervisor_bit=%d\n",
            regs[0], regs[1], regs[2], regs[3], (regs[2] >> 31) & 1);
    fflush(o);

    int v[4] = {0, 0, 0, 0};
    __cpuid(v, 0x40000000);
    fprintf(o, "leaf40 eax=0x%08X ebx=0x%08X ecx=0x%08X edx=0x%08X\n",
            v[0], v[1], v[2], v[3]);
    fflush(o);

    unsigned long long t0 = __rdtsc();
    volatile int acc = 0;
    for (int i = 0; i < 1000; ++i) acc += i;
    unsigned long long t1 = __rdtsc();
    fprintf(o, "rdtsc  t0=0x%llX t1=0x%llX delta=%llu\n", t0, t1, t1 - t0);
    fflush(o);

    fprintf(o, "DONE acc=%d\n", acc);
    fflush(o);
    if (rp) fclose(o);
    return 0;
}
