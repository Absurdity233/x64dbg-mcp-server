#pragma once

#include <string>
#include <nlohmann/json.hpp>

// Continuous run-trace across pauses.
//
// x64dbg's run-trace only advances while the target runs: a pause ends it, and
// TraceIntoConditional can only be started from a paused debugger. Those two
// facts together mean a "keep tracing" loop has to arm a fresh segment at every
// pause - arming resumes the target, which is what makes the coverage
// contiguous rather than gapped.
//
// That also has a consequence worth stating: while auto mode is on, a
// breakpoint no longer holds the target. It pauses, a segment is written, the
// next segment is armed (after hold_ms, if set) and execution continues. The
// pause is still observable in the event log and the trace timeline; use
// trace_auto_stop to regain control.
namespace mcp {

struct trace_auto_config {
    bool enabled = false;
    std::string dir;                 // segment directory (created if missing)
    std::string prefix = "seg";      // segment file name prefix
    std::string condition = "0";     // trace break condition ("0" = never)
    std::string max_steps;           // per-segment step budget, decimal or expression
    std::string log_text = "{p:cip},{p:rax},{tid()},{GetTickCount()}";
    int hold_ms = 0;                 // dwell time after each pause before re-arming
    unsigned max_segments = 0;       // 0 = unlimited
};

// Enable continuous tracing. If the debugger is already paused the first
// segment is armed by the worker, so this call does not block or resume the
// target itself.
void trace_auto_start(const trace_auto_config& cfg);

// Disable continuous tracing. A segment already running is left alone; stop it
// with /api/trace/stop if the target should not keep running.
nlohmann::json trace_auto_stop();

nlohmann::json trace_auto_status();

// Called from the debugger-thread pause callback.
void trace_auto_notify_paused();

// Called from plugstop. Joins the worker.
void trace_auto_shutdown();

} // namespace mcp
