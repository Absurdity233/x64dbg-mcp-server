#pragma once

// User-mode bridge to the x64dbg_mcp_hide kernel driver.
//
// The driver is optional: every user-mode anti-debug technique in this plugin
// works without it. What the driver adds is the three checks that live below
// user mode and cannot be faked from a plugin:
//
//   NtQueryInformationProcess(ProcessDebugPort)         -> EPROCESS.DebugPort
//   NtQueryInformationProcess(ProcessDebugObjectHandle) -> same field, non-NULL
//   NtQueryInformationProcess(ProcessDebugFlags)        -> inverted DebugPort
//
// A target that asks the kernel "am I being debugged" gets the truth no matter
// what user mode believes, so clearing the EPROCESS field is the only way to
// answer those three questions with "no" while a debugger is attached.
//
// Everything here is best-effort and reports honestly: a missing driver, a
// refused IOCTL, or an unresolved EPROCESS offset all surface as data, never as
// a silent success.

#include <cstdint>
#include <string>
#include <nlohmann/json.hpp>

namespace kernel_driver {

// The mask `kernel_apply` uses when the caller does not pass one: the three
// EPROCESS fields a user-mode target can observe. Exposed here so the HTTP layer
// does not have to include the driver's ABI header just to name a default.
constexpr uint64_t default_mask = 0x1 | 0x2 | 0x4;

// Every field the driver knows how to clear, including the ones that need an
// offset some kernel builds do not expose.
constexpr uint64_t all_mask = 0x1 | 0x2 | 0x4 | 0x8;

// Where the driver exposes itself. Taken from the shared ABI header so the
// plugin and the driver cannot disagree about the name.
std::wstring device_path();

// Is the driver loaded and speaking our ABI?
//
// Returns a JSON object rather than a bool because the useful answer is never
// just "yes/no": when it is absent the caller needs to know whether the problem
// is "not loaded", "loaded but wrong ABI", or "loaded but access denied" - each
// has a different fix.
nlohmann::json status();

// Pin the process the driver should act on. Empty pid = the current debuggee.
nlohmann::json attach(unsigned long pid);
nlohmann::json detach();

// Clear the requested EPROCESS fields for the attached process.
//
// mask uses the X64MCP_HIDE_* bits from the ABI header. The offsets are
// optional overrides for a kernel build whose accessor the driver could not
// disassemble; passing 0 leaves the driver's own resolution in place.
nlohmann::json apply(uint64_t mask,
                     unsigned long debugport_offset,
                     unsigned long flags_offset,
                     unsigned long cross_session_offset);

// What the driver currently has applied (and which offsets it is using).
nlohmann::json query();

// Human-readable one-liner for tool output: "driver loaded (os 26100, ...)".
std::string describe();

} // namespace kernel_driver
