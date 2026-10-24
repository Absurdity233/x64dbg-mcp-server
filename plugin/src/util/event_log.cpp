#include "util/event_log.h"

#include <windows.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>

namespace event_log {

namespace {

std::mutex g_mutex;
std::condition_variable g_cv;
std::deque<entry> g_events;
uint64_t g_next_seq = 1;
// Highest seq discarded by clear() (a new session). Sequence numbers are never
// reused, so a client cursor from the previous session stays comparable; those
// events were intentionally dropped rather than lost to ring-buffer pressure.
uint64_t g_cleared_upto = 0;

bool matches_any(const entry& e, const std::vector<std::string>& types) {
    if (types.empty()) return true;
    return std::find(types.begin(), types.end(), e.type) != types.end();
}

} // namespace

void push(const std::string& type, nlohmann::json details) {
    {
        std::lock_guard<std::mutex> lock(g_mutex);

        entry ev;
        ev.seq = g_next_seq++;
        ev.tick_ms = GetTickCount64();
        ev.type = type;
        ev.details = std::move(details);

        g_events.push_back(std::move(ev));
        while (g_events.size() > MAX_EVENTS) {
            g_events.pop_front();
        }
    }
    // Notify outside the lock so a woken waiter does not contend with us.
    g_cv.notify_all();
}

nlohmann::json since(uint64_t since_seq) {
    std::lock_guard<std::mutex> lock(g_mutex);

    auto events = nlohmann::json::array();
    for (const auto& e : g_events) {
        if (e.seq <= since_seq) continue;
        auto item = e.details.is_object() ? e.details : nlohmann::json::object();
        item["seq"] = e.seq;
        item["tick_ms"] = e.tick_ms;
        item["type"] = e.type;
        events.push_back(std::move(item));
    }

    // Events the caller missed because the ring wrapped (or because a new
    // session cleared it) are everything between its cursor and the oldest
    // event still buffered. Deriving this from the oldest retained seq - not
    // from seq arithmetic - keeps it correct across session clears.
    uint64_t dropped = 0;
    if (!g_events.empty()) {
        const uint64_t oldest = g_events.front().seq;
        const uint64_t from = since_seq > g_cleared_upto ? since_seq : g_cleared_upto;
        if (oldest > from + 1) {
            dropped = oldest - from - 1;
        }
    }

    return {
        {"events",     events},
        {"count",      events.size()},
        {"latest_seq", g_next_seq > 1 ? g_next_seq - 1 : 0},
        {"dropped",    dropped}
    };
}

nlohmann::json wait_since(
    uint64_t since_seq,
    int timeout_ms,
    const std::vector<std::string>& types,
    size_t max_events
) {
    if (max_events == 0) max_events = 256;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

    std::unique_lock<std::mutex> lock(g_mutex);

    auto has_match = [&]() {
        for (const auto& e : g_events) {
            if (e.seq > since_seq && matches_any(e, types)) return true;
        }
        return false;
    };

    // Wait in a loop: spurious wakeups are allowed, and events of unrelated
    // types must not release a filtered wait.
    while (!has_match()) {
        if (g_cv.wait_until(lock, deadline) == std::cv_status::timeout) break;
    }

    const bool timed_out = !has_match();

    auto events = nlohmann::json::array();
    for (const auto& e : g_events) {
        if (e.seq <= since_seq) continue;
        if (events.size() >= max_events) break;
        auto item = e.details.is_object() ? e.details : nlohmann::json::object();
        item["seq"] = e.seq;
        item["tick_ms"] = e.tick_ms;
        item["type"] = e.type;
        events.push_back(std::move(item));
    }

    uint64_t dropped = 0;
    if (!g_events.empty()) {
        const uint64_t oldest = g_events.front().seq;
        const uint64_t from = since_seq > g_cleared_upto ? since_seq : g_cleared_upto;
        if (oldest > from + 1) {
            dropped = oldest - from - 1;
        }
    }

    return {
        {"events",     events},
        {"count",      events.size()},
        {"latest_seq", g_next_seq > 1 ? g_next_seq - 1 : 0},
        {"dropped",    dropped},
        {"timed_out",  timed_out}
    };
}

uint64_t latest_seq() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_next_seq > 1 ? g_next_seq - 1 : 0;
}

void clear() {
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_events.clear();
        g_cleared_upto = g_next_seq > 1 ? g_next_seq - 1 : 0;
    }
    g_cv.notify_all();
}

} // namespace event_log
