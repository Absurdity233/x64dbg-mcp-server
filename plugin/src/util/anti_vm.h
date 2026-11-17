#pragma once

// Making an anti-VM check see a physical machine.
//
// The naive approach (a silent breakpoint whose command rewrites a register)
// does not work for any of these instructions, and understanding why fixes the
// design:
//
//   * A software breakpoint traps BEFORE the instruction executes. For `cpuid`
//     the registers a check reads are produced by the cpuid itself, so any value
//     the breakpoint command writes is overwritten microseconds later. Verified
//     on this build: `ecx=ecx&0x7FFFFFFF;run` on a cpuid site changes nothing.
//   * `rdtsc` is worse: the interesting quantity is the DELTA between two
//     timestamps, so faking one reading in isolation is not even the right
//     shape of answer.
//
// What works is a stub that runs the real instruction and edits its output:
//
//     <site>        jmp <stub>
//     ...
//     <stub>        <displaced instruction>
//                   <filter: patch the registers the check reads>
//                   jmp <site + displaced_size>
//
// The instruction still executes (so the CPU state the target depends on stays
// consistent), but what the check observes is ours.

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "bridge/c_bridge_executor.h"

namespace anti_vm {

// One armed stub.
struct armed_stub {
    std::string probe;       // "cpuid", "rdtsc", ...
    duint site = 0;
    duint stub = 0;
    std::string spoof;       // what the filter does, for the report
    std::vector<uint8_t> patch;      // bytes written at site
    std::vector<uint8_t> original;   // what was there
};

// Arm stubs on every stubbable probe in `module` whose name is in `probes`
// (empty = every probe in the catalog).
//
// `max_hits` caps how many sites are armed per probe: a browser-wide cpuid scan
// can find hundreds of sites, and arming all of them turns a debuggable target
// into a stall. The report says how many were skipped for that reason.
nlohmann::json arm(c_bridge_executor& bridge, const std::string& module,
                   const std::vector<std::string>& probes, size_t max_hits);

// Write every original byte back. Returns what was restored and what failed.
nlohmann::json disarm(c_bridge_executor& bridge);

// Session-teardown variant.
//
// The difference from disarm() is not cosmetic: disarm() insists on a paused
// target because writing a *running* process races its own code. At session end
// there is no correct state to demand - the process may already be gone (the
// debugger killed it) or still alive (detach). So this:
//
//   * writes the original bytes only when the process still exists, and
//   * ALWAYS clears the registry, because stale entries would otherwise be
//     restored into an unrelated process in the next session at the same address.
//
// Returns the count of stubs whose bytes were actually written back (0 on a
// terminated target, which is the normal case and not an error).
nlohmann::json teardown(c_bridge_executor& bridge);

// Currently armed stubs.
nlohmann::json list();

// The default spoof for a probe name, for the report.
std::string default_spoof_for(const std::string& probe);

} // namespace anti_vm
