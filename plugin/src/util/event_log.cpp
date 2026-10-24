#include "util/event_log.h"

#include <windows.h>

namespace event_log {

namespace {

std::mutex g_mutex;
std::deque<entry> g_events;
uint64_t g_next_seq = 1;
// Highest seq discarded by clear() (a new session). Sequence numbers are never
// reused, so a client cursor from the previous session stays comparable; those
// events were intentionally dropped rather than lost to ring-buffer pressure.
uint64_t g_cleared_upto = 0;

} // namespace

void push(const std::string& type, nlohmann::json details) {
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
        // Start counting after both the caller's cursor and any clear() point:
        // events wiped by a new session are not "dropped", they are gone by
        // design and the caller asked for them by accident.
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

uint64_t latest_seq() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_next_seq > 1 ? g_next_seq - 1 : 0;
}

void clear() {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_events.clear();
    g_cleared_upto = g_next_seq > 1 ? g_next_seq - 1 : 0;
}

} // namespace event_log
