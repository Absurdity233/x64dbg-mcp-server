#include "util/trace_auto.h"

#include "util/trace_state.h"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <filesystem>
#include <mutex>
#include <thread>

#include "bridgemain.h"

namespace mcp {

namespace {

std::mutex g_mutex;
std::condition_variable g_cv;

trace_auto_config g_cfg;
std::thread g_worker;
std::atomic<bool> g_stop_requested{false};
std::atomic<bool> g_paused_signal{false};
std::atomic<bool> g_armed{false};

// Status snapshots. Written by the worker, read by HTTP connection threads, so
// they are guarded by g_mutex rather than being plain globals.
nlohmann::json g_segments = nlohmann::json::array();
unsigned g_segment_count = 0;
std::string g_last_error;
bool g_stop_reason_set = false;
std::string g_stop_reason;

// TraceIntoConditional reads its step count through the expression engine,
// which parses bare numbers as hex. "5000" would trace 0x5000 instructions.
std::string normalise_steps(const std::string& raw) {
    if (raw.empty()) return raw;
    if (raw.size() > 2 && raw[0] == '0' && (raw[1] == 'x' || raw[1] == 'X')) return raw;
    for (char c : raw) {
        if (c < '0' || c > '9') return raw;   // an expression; leave it alone
    }
    char buf[32];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "0x%llX", _strtoui64(raw.c_str(), nullptr, 10));
    return buf;
}

std::string segment_path(const trace_auto_config& cfg, unsigned index) {
    char name[64];
    _snprintf_s(name, sizeof(name), _TRUNCATE, "%s_%04u.csv", cfg.prefix.c_str(), index);
    return (std::filesystem::path(cfg.dir) / name).string();
}

void record_error(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_last_error = msg;
}

void finish(const std::string& reason) {
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_stop_reason_set) {
            g_stop_reason = reason;
            g_stop_reason_set = true;
        }
        g_cfg.enabled = false;
    }
    g_cv.notify_all();
}

// Arm one segment. Must be called on a paused debugger; the trace command
// resumes the target itself.
bool arm_segment(const trace_auto_config& cfg) {
    unsigned index;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        index = g_segment_count;
    }

    std::error_code ec;
    std::filesystem::create_directories(cfg.dir, ec);

    const auto path = segment_path(cfg, index);

    std::string setlog = "TraceSetLogFile \"" + path + "\"";
    if (!DbgCmdExecDirect(setlog.c_str())) {
        record_error("TraceSetLogFile failed: " + path);
        return false;
    }
    std::string setfmt = "TraceSetLog \"" + cfg.log_text + "\"";
    DbgCmdExecDirect(setfmt.c_str());

    std::string cmd = "TraceIntoConditional " + (cfg.condition.empty() ? "0" : cfg.condition);
    if (!cfg.max_steps.empty()) cmd += ", " + normalise_steps(cfg.max_steps);

    // The segment only becomes visible once the command resumes the target, so
    // mark the trace state first for the short window in between.
    trace_mark_started(path);
    if (!DbgCmdExec(cmd.c_str())) {
        trace_mark_stopped();
        record_error("TraceIntoConditional rejected: " + cmd);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        ++g_segment_count;
        g_armed = true;
    }
    return true;
}

void worker_loop() {
    trace_auto_config cfg;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        cfg = g_cfg;
    }

    while (true) {
        bool paused = false;
        {
            std::unique_lock<std::mutex> lock(g_mutex);
            g_cv.wait(lock, [] { return g_stop_requested.load() || g_paused_signal.load(); });
            if (g_stop_requested.load()) break;
            g_paused_signal = false;
            paused = true;
        }
        (void)paused;

        // The previous segment just ended because of this pause. Record what it
        // produced before the next one overwrites the log destination.
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_armed) {
                const auto index = g_segment_count - 1;
                const auto path = segment_path(g_cfg, index);
                unsigned long long size = 0;
                WIN32_FILE_ATTRIBUTE_DATA fad{};
                if (GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &fad)) {
                    size = (static_cast<unsigned long long>(fad.nFileSizeHigh) << 32)
                           | fad.nFileSizeLow;
                }
                g_segments.push_back({{"index", index},
                                      {"file", path},
                                      {"size", size}});
                g_armed = false;
            }
        }

        if (cfg.hold_ms > 0) {
            std::unique_lock<std::mutex> lock(g_mutex);
            g_cv.wait_for(lock, std::chrono::milliseconds(cfg.hold_ms),
                          [] { return g_stop_requested.load(); });
            if (g_stop_requested.load()) break;
        }

        if (cfg.max_segments > 0 && g_segment_count >= cfg.max_segments) {
            finish("max_segments reached");
            break;
        }
        if (!DbgIsDebugging()) {
            finish("debug session ended");
            break;
        }
        if (DbgIsRunning()) {
            // Something resumed the target between the pause and now. Arming
            // from here would fail; wait for the next pause instead.
            continue;
        }

        if (!arm_segment(cfg)) {
            finish("could not arm the next segment");
            break;
        }
    }

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_cfg.enabled = false;
    }
}

} // namespace

void trace_auto_start(const trace_auto_config& cfg) {
    trace_auto_shutdown();

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_cfg = cfg;
        g_cfg.enabled = true;
        g_segments = nlohmann::json::array();
        g_segment_count = 0;
        g_last_error.clear();
        g_stop_reason.clear();
        g_stop_reason_set = false;
        g_armed = false;
    }
    g_stop_requested.store(false);
    g_paused_signal.store(false);
    g_worker = std::thread(worker_loop);

    // If we are already paused there will be no pause event to react to.
    if (DbgIsDebugging() && !DbgIsRunning()) {
        g_paused_signal.store(true);
        g_cv.notify_all();
    }
}

nlohmann::json trace_auto_stop() {
    const bool was_enabled = [&] {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_cfg.enabled;
    }();

    if (!was_enabled && !g_worker.joinable()) {
        return {{"was_running", false}, {"message", "continuous tracing was not active"}};
    }

    g_stop_requested.store(true);
    g_cv.notify_all();
    if (g_worker.joinable()) g_worker.join();

    std::lock_guard<std::mutex> lock(g_mutex);
    g_cfg.enabled = false;
    return {
        {"was_running",   true},
        {"segments",      g_segment_count},
        {"segment_files", g_segments},
        {"stop_reason",   g_stop_reason.empty() ? "stopped by request" : g_stop_reason},
        {"last_error",    g_last_error}
    };
}

nlohmann::json trace_auto_status() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return {
        {"enabled",       g_cfg.enabled},
        {"dir",           g_cfg.dir},
        {"prefix",        g_cfg.prefix},
        {"segments",      g_segment_count},
        {"max_segments",  g_cfg.max_segments},
        {"hold_ms",       g_cfg.hold_ms},
        {"armed",         g_armed.load()},
        {"stop_reason",   g_stop_reason},
        {"last_error",    g_last_error}
    };
}

void trace_auto_notify_paused() {
    if (!g_worker.joinable()) return;
    if (!g_cfg.enabled) return;
    g_paused_signal.store(true);
    g_cv.notify_all();
}

void trace_auto_shutdown() {
    g_stop_requested.store(true);
    g_cv.notify_all();
    if (g_worker.joinable()) g_worker.join();
}

} // namespace mcp
