#pragma once

#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

// Bounded, thread-safe log of debugger callbacks.
//
// x64dbg invokes plugin callbacks on the debugger thread, so everything here
// must be cheap and must not touch the Bridge API (which can block waiting on
// the debugger thread we are already on). Only data already present in the
// callback struct is recorded.
//
// Consumers poll GET /api/command/events?since=<seq> for an immediate snapshot,
// or GET /api/command/events/wait?since=<seq>&timeout=<ms> which blocks on the
// plugin side until something new arrives. The long-poll variant removes the
// need for the client to spin at a fixed interval.
namespace event_log {

// Large enough to hold a full module-load burst plus a trace of breakpoint
// hits without wrapping. 2048 * ~200 bytes is well under 1 MB.
constexpr size_t MAX_EVENTS = 2048;

struct entry {
    uint64_t seq = 0;
    uint64_t tick_ms = 0;   // GetTickCount64() at the time of the callback
    std::string type;       // e.g. "breakpoint", "exception", "paused"
    nlohmann::json details = nlohmann::json::object();
};

// Record an event. Safe to call from any thread; wakes blocked waiters.
void push(const std::string& type, nlohmann::json details = nlohmann::json::object());

// Events with seq > since. `since` = 0 returns whatever is currently buffered.
nlohmann::json since(uint64_t since_seq);

// Block until at least one event with seq > since arrives, `timeout_ms` elapses,
// or the log is cleared. When `types` is non-empty only those types count as
// newsworthy - but any type is still returned in the payload.
//
// Returns the same shape as since(), plus:
//   "timed_out": true when nothing arrived before the deadline
nlohmann::json wait_since(
    uint64_t since_seq,
    int timeout_ms,
    const std::vector<std::string>& types,
    size_t max_events
);

// Monotonic sequence number of the newest event (0 if none).
uint64_t latest_seq();

// Drop all buffered events (used when a new debug session starts).
void clear();

} // namespace event_log
