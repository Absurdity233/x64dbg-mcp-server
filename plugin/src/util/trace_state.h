#pragma once

#include <string>
#include <nlohmann/json.hpp>

// Run-trace state shared between the HTTP handlers (connection threads) and the
// debugger-thread callbacks. Implemented in plugin_main.cpp.
//
// CB_STARTTRACE / CB_STOPTRACE do NOT fire for a run-trace (they belong to the
// trace-record feature), so the state is tracked here instead: every route that
// starts or stops a trace goes through these helpers, and the pause/stop
// callbacks clear it.
namespace mcp {

// Record the trace that the caller just started.
void trace_mark_started(const std::string& file);

// Clear the active trace. Returns the file that was being written ("" if none).
std::string trace_mark_stopped();

// True when a run-trace is believed to be writing.
bool trace_is_active();

// Snapshot for /api/trace/status. When a trace is active this also reports the
// file's current size and how long it has been running, so a trace that started
// but produces no rows (the corrupted-engine failure mode) is visible without
// waiting for a timeout.
[[nodiscard]] nlohmann::json trace_status();

// Stop a running run-trace before the debug session is destroyed.
//
// Measured on x64dbg 2026.05.27: calling `stop` while TraceIntoConditional is
// still executing leaves the instance unable to start any further run-trace
// (TraceSetLogFile/TraceSetLog/TraceIntoConditional all report success, a 0-byte
// file is created, and the target runs untraced). The damage survives `restart`
// and every later `init` in that process; only a new x64dbg process clears it.
// Pausing first makes the trace unwind cleanly and the next session works.
//
// Safe to call from a connection thread. Returns true when a trace was stopped.
bool trace_quiesce_for_stop(std::string* out_file = nullptr);

} // namespace mcp
