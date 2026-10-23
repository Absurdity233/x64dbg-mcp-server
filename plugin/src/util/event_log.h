#pragma once

#include <cstdint>
#include <deque>
#include <mutex>
#include <string>

#include <nlohmann/json.hpp>

// Bounded, thread-safe log of debugger callbacks.
//
// x64dbg invokes plugin callbacks on the debugger thread, so everything here
// must be cheap and must not touch the Bridge API (which can block waiting on
// the debugger thread we are already on). Only data already present in the
// callback struct is recorded.
//
// Consumers poll GET /api/command/events?since=<seq> and get every event with
// a sequence number greater than <seq>, which makes the ring buffer behave
// like a server-side event stream without needing SSE.
namespace event_log {

constexpr size_t MAX_EVENTS = 512;

struct entry {
    uint64_t seq = 0;
    uint64_t tick_ms = 0;   // GetTickCount64() at the time of the callback
    std::string type;       // e.g. "breakpoint", "exception", "paused"
    nlohmann::json details = nlohmann::json::object();
};

// Record an event. Safe to call from any thread.
void push(const std::string& type, nlohmann::json details = nlohmann::json::object());

// Events with seq > since. `since` = 0 returns whatever is currently buffered.
nlohmann::json since(uint64_t since_seq);

// Monotonic sequence number of the newest event (0 if none).
uint64_t latest_seq();

// Drop all buffered events (used when a new debug session starts).
void clear();

} // namespace event_log
