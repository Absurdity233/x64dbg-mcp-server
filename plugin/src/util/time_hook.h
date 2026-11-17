#pragma once

// Timing side-channels beyond RDTSC.
//
// RDTSC is the famous one, and anti_vm already handles it with an instruction
// stub. But the API-level timers are what modern protections actually use more of,
// for one concrete reason: RDTSC's frequency depends on the host, so a raw delta
// needs calibration before it means anything, while QueryPerformanceCounter is
// already in a fixed, calibrated unit. A check that measures "how long did this
// function take" reaches for QPC first.
//
// Those checks are also structurally different from the instruction ones, and the
// difference dictates a different stub:
//
//   * RDTSC leaves its answer in registers, so the stub can edit registers.
//   * QueryPerformanceCounter writes through a POINTER argument, so the stub has
//     to write memory - which means it can read and write that pointer no matter
//     where the stub itself lives.
//   * GetTickCount returns a value in EAX, so the stub only has to fail to change
//     anything on consecutive calls.
//
// All three are defeated by the same idea: make the counter appear not to advance
// across the region being measured, so every delta reads zero. That is the
// tightest possible answer and the one a fast machine produces.
//
// Mechanism: these exports are leaf forwards to KUSER_SHARED_DATA (a per-boot
// counter at a fixed address in every process), or to the same hotpatch-thunk shape
// ntdll uses. Rather than displace instructions and allocate a page, the entry is
// redirected to a dispatcher that returns the FIRST value it saw, forever. The
// counter stays monotonic (it never goes backwards, so a target that sanity-checks
// ordering is satisfied) and every delta is exactly zero.

#include <cstdint>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace time_hook {

// Which timer to neutralise.
enum class timer {
    qpc,          // QueryPerformanceCounter(LARGE_INTEGER* out) -> BOOL
    qpc_freq,     // QueryPerformanceFrequency(...) - left alone; a fake value breaks maths
    tick64,       // GetTickCount64() -> ULONGLONG
    tick32,       // GetTickCount() -> DWORD
};

// Arm the requested timers in `modules` (default: kernelbase, kernel32, winmm).
//
// `frozen` is the strategy: every call returns the value of the FIRST call, so
// deltas are zero. The alternative - a synthetic value that advances by a fixed
// step - is provided for callers whose target sanity-checks that the clock moves;
// it makes deltas constant rather than zero.
struct options {
    bool synthetic_step = false;   // advance by 1 tick per call instead of freezing
};

nlohmann::json arm(const std::vector<timer>& timers, const options& opt);
nlohmann::json disarm();
nlohmann::json list();

// Session-teardown variant: write back what the still-live process allows and
// always clear the registry, so a terminated session cannot leave a record that the
// next session re-applies to an unrelated process at the same address.
nlohmann::json teardown();

// The observed first value per timer, for reporting: "frozen at 0x...".
nlohmann::json observed();

} // namespace time_hook