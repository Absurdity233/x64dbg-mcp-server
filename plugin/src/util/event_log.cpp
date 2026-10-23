#include "util/event_log.h"

#include <windows.h>

namespace event_log {

namespace {

std::mutex g_mutex;
std::deque<entry> g_events;
uint64_t g_next_seq = 1;

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

    return {
        {"events",     events},
        {"count",      events.size()},
        {"latest_seq", g_next_seq > 1 ? g_next_seq - 1 : 0},
        {"dropped",    g_next_seq > 1 && g_next_seq - 1 > MAX_EVENTS + since_seq
                           ? (g_next_seq - 1) - MAX_EVENTS - since_seq
                           : 0}
    };
}

uint64_t latest_seq() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_next_seq > 1 ? g_next_seq - 1 : 0;
}

void clear() {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_events.clear();
}

} // namespace event_log
