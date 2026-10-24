#include "plugin_main.h"

#include <string>
#include <cstdio>
#include <cstring>
#include <mutex>

#include <nlohmann/json.hpp>

#include "_plugins.h"
#include "http/c_http_server.h"
#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "util/trace_state.h"
#include "util/event_log.h"
#include "resources/plugin_icon.h"
#include "ui/settings_dialog.h"
#include "ui/about_dialog.h"

// Forward declarations for handler registration functions
namespace handlers {
    void register_debug_routes(c_http_router& router);
    void register_register_routes(c_http_router& router);
    void register_memory_routes(c_http_router& router);
    void register_breakpoint_routes(c_http_router& router);
    void register_disasm_routes(c_http_router& router);
    void register_module_routes(c_http_router& router);
    void register_thread_routes(c_http_router& router);
    void register_stack_routes(c_http_router& router);
    void register_symbol_routes(c_http_router& router);
    void register_annotation_routes(c_http_router& router);
    void register_search_routes(c_http_router& router);
    void register_patch_routes(c_http_router& router);
    void register_memmap_routes(c_http_router& router);
    void register_command_routes(c_http_router& router);
    void register_analysis_routes(c_http_router& router);
    void register_tracing_routes(c_http_router& router);
    void register_dumping_routes(c_http_router& router);
    void register_antidebug_routes(c_http_router& router);
    void register_exception_routes(c_http_router& router);
    void register_process_routes(c_http_router& router);
    void register_handles_routes(c_http_router& router);
    void register_controlflow_routes(c_http_router& router);
    void register_functions_routes(c_http_router& router);
} // namespace handlers

// Globals
static int g_plugin_handle = -1;
static int g_menu_handle = -1;
static HWND g_hwnd_dlg = nullptr;
static c_http_server g_server;
static c_http_router g_router;
static s_plugin_settings g_settings;

// ============================================================================
// Trace state (shared with /api/trace/status via util/trace_state.h)
// ============================================================================

static std::mutex g_trace_mutex;
static bool g_trace_active = false;
static std::string g_trace_file;
static ULONGLONG g_trace_started_tick = 0;
// Last file a trace wrote to, kept after the trace ends so the caller can still
// find its output. A run-trace finishes on its own (max_steps) or on pause, and
// without this the path disappears exactly when the analysis needs it.
static std::string g_trace_last_file;
// Only trace_quiesce_for_stop touches these; they serialise the pause/stop
// sequence so two concurrent stops cannot interleave.
static std::mutex g_trace_stop_mutex;

namespace mcp {

void trace_mark_started(const std::string& file) {
    std::lock_guard<std::mutex> lock(g_trace_mutex);
    g_trace_active = true;
    g_trace_file = file;
    g_trace_started_tick = GetTickCount64();
    // Do not carry the previous run's path into a trace that has none of its
    // own yet (the /into and /over routes write wherever TraceSetLogFile last
    // pointed, which is not knowable from here).
    if (!file.empty()) g_trace_last_file.clear();
}

std::string trace_mark_stopped() {
    std::lock_guard<std::mutex> lock(g_trace_mutex);
    const auto file = g_trace_file;
    // Only remember the path here. This runs on the debugger thread (pause and
    // stop-debug callbacks), so no file I/O: trace_status stat()s it lazily from
    // a connection thread instead.
    if (!file.empty()) g_trace_last_file = file;
    g_trace_active = false;
    g_trace_file.clear();
    g_trace_started_tick = 0;
    return file;
}

namespace {

unsigned long long file_size_of(const std::string& path) {
    if (path.empty()) return 0;
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &fad)) return 0;
    return (static_cast<unsigned long long>(fad.nFileSizeHigh) << 32) | fad.nFileSizeLow;
}

} // namespace

bool trace_is_active() {
    std::lock_guard<std::mutex> lock(g_trace_mutex);
    return g_trace_active;
}

nlohmann::json trace_status() {
    bool active;
    std::string file;
    std::string last_file;
    ULONGLONG started;
    {
        std::lock_guard<std::mutex> lock(g_trace_mutex);
        active = g_trace_active;
        file = g_trace_file;
        last_file = g_trace_last_file;
        started = g_trace_started_tick;
    }

    // Stat outside the lock: this runs on a connection thread while the trace
    // writer keeps appending, and a torn read only makes the advertised size
    // stale, which is harmless.
    if (!active) {
        if (last_file.empty()) {
            return nlohmann::json{{"tracing", false}, {"file", ""}};
        }
        return nlohmann::json{
            {"tracing",   false},
            {"file",      ""},
            {"last_file", last_file},
            {"last_size", file_size_of(last_file)},
            {"message",   "trace finished; read last_file for the output"}
        };
    }

    return nlohmann::json{
        {"tracing",     true},
        {"file",        file},
        {"size",        file_size_of(file)},
        {"elapsed_ms",  started ? (GetTickCount64() - started) : 0}
    };
}

bool trace_quiesce_for_stop(std::string* out_file) {
    std::lock_guard<std::mutex> lock(g_trace_stop_mutex);
    const auto file = trace_mark_stopped();
    if (out_file) *out_file = file;

    if (!DbgIsDebugging() || !DbgIsRunning()) {
        // Not running means no trace loop is executing; nothing to unwind.
        return !file.empty();
    }

    // StopRunTrace alone leaves the debugger running mid-trace, which is the
    // state that corrupts the next session. Pause first: that lets the trace
    // loop exit on its own, and StopRunTrace then only clears the bookkeeping.
    DbgCmdExecDirect("pause");
    for (int i = 0; i < 200 && DbgIsRunning(); ++i) {
        Sleep(10);
    }
    DbgCmdExecDirect("StopRunTrace");
    return !file.empty();
}

} // namespace mcp

// ============================================================================
// Debugger event capture
//
// These run on the debugger thread, so they only copy data out of the callback
// struct - never call the Bridge API, which could deadlock on this thread.
// ============================================================================

static void cb_init_debug(CBTYPE, void* cb_info) {
    auto* info = static_cast<PLUG_CB_INITDEBUG*>(cb_info);
    event_log::clear();
    event_log::push("session_start", {
        {"file", info && info->szFileName ? info->szFileName : ""}
    });
}

static void cb_stop_debug(CBTYPE, void*) {
    mcp::trace_mark_stopped();
    event_log::push("session_stop");
}

static void cb_attached(CBTYPE, void* cb_info) {
    auto* info = static_cast<PLUG_CB_ATTACH*>(cb_info);
    event_log::clear();
    event_log::push("session_attach", {
        {"pid", info ? static_cast<unsigned>(info->dwProcessId) : 0u}
    });
}

static void cb_breakpoint(CBTYPE, void* cb_info) {
    auto* info = static_cast<PLUG_CB_BREAKPOINT*>(cb_info);
    if (!info || !info->breakpoint) {
        event_log::push("breakpoint");
        return;
    }

    const auto& bp = *info->breakpoint;
    char addr[32];
    snprintf(addr, sizeof(addr), "0x%llX", static_cast<unsigned long long>(bp.addr));

    // GetCurrentThreadId is a plain Win32 call (no Bridge), so it is safe on
    // the debugger thread and tells us which thread tripped the breakpoint -
    // essential when several threads share a hot code path.
    event_log::push("breakpoint", {
        {"address",   addr},
        {"name",      bp.name},
        {"module",    bp.mod},
        {"type",      static_cast<int>(bp.type)},
        {"hit_count", bp.hitCount},
        {"log_text",  bp.logText},
        {"tid",       static_cast<unsigned>(GetCurrentThreadId())}
    });
}

static void cb_exception(CBTYPE, void* cb_info) {
    auto* info = static_cast<PLUG_CB_EXCEPTION*>(cb_info);
    if (!info || !info->Exception) {
        event_log::push("exception");
        return;
    }

    const auto& ex = *info->Exception;
    char code[32];
    snprintf(code, sizeof(code), "0x%08X", static_cast<unsigned>(ex.ExceptionRecord.ExceptionCode));

    char address[32];
    snprintf(address, sizeof(address), "0x%llX",
             reinterpret_cast<unsigned long long>(ex.ExceptionRecord.ExceptionAddress));

    event_log::push("exception", {
        {"code",            code},
        {"address",         address},
        {"first_chance",    ex.dwFirstChance != 0},
        {"nested",          ex.dwFirstChance == 0}
    });
}

static void cb_paused(CBTYPE, void*) {
    // A run-trace only advances while the target runs; pausing ends it.
    mcp::trace_mark_stopped();
    event_log::push("paused");
}

static void cb_resumed(CBTYPE, void*) {
    event_log::push("resumed");
}

static void cb_system_breakpoint(CBTYPE, void*) {
    event_log::push("system_breakpoint");
}

static void cb_create_process(CBTYPE, void* cb_info) {
    auto* info = static_cast<PLUG_CB_CREATEPROCESS*>(cb_info);
    event_log::push("process_create", {
        {"file", info && info->DebugFileName ? info->DebugFileName : ""}
    });
}

static void cb_exit_process(CBTYPE, void*) {
    event_log::push("process_exit");
}

static void cb_create_thread(CBTYPE, void* cb_info) {
    auto* info = static_cast<PLUG_CB_CREATETHREAD*>(cb_info);
    event_log::push("thread_create", {
        {"tid", info ? static_cast<unsigned>(info->dwThreadId) : 0u}
    });
}

static void cb_load_dll(CBTYPE, void* cb_info) {
    auto* info = static_cast<PLUG_CB_LOADDLL*>(cb_info);
    event_log::push("dll_load", {
        {"module", info && info->modname ? info->modname : ""}
    });
}

static void cb_step(CBTYPE, void*) {
    event_log::push("stepped");
}

// ============================================================================
// Server lifecycle helper
// ============================================================================

// Apply current settings (incl. auth token) and start the server.
static std::expected<void, std::string> start_server() {
    g_server.set_auth_token(g_settings.auth_token);
    return g_server.start(g_settings.host, g_settings.port, &g_router);
}

// ============================================================================
// Menu helpers
// ============================================================================

static void update_menu_state() {
    const bool running = g_server.is_running();
    _plugin_menuentrysetchecked(g_plugin_handle, menu_start_server, running);
    _plugin_menuentrysetchecked(g_plugin_handle, menu_stop_server, !running);
}

// ============================================================================
// Settings persistence
// ============================================================================

static void load_settings() {
    char buf[256];

    if (BridgeSettingGet(SETTINGS_SECTION, SETTINGS_KEY_HOST, buf)) {
        strncpy_s(g_settings.host, buf, _TRUNCATE);
    }

    duint port_val = 0;
    if (BridgeSettingGetUint(SETTINGS_SECTION, SETTINGS_KEY_PORT, &port_val)) {
        if (port_val >= 1 && port_val <= 65535) {
            g_settings.port = static_cast<uint16_t>(port_val);
        }
    }

    duint autostart_val = 0;
    if (BridgeSettingGetUint(SETTINGS_SECTION, SETTINGS_KEY_AUTOSTART, &autostart_val)) {
        g_settings.auto_start = (autostart_val != 0);
    }

    if (BridgeSettingGet(SETTINGS_SECTION, SETTINGS_KEY_TOKEN, buf)) {
        strncpy_s(g_settings.auth_token, buf, _TRUNCATE);
    }
}

static void save_settings() {
    BridgeSettingSet(SETTINGS_SECTION, SETTINGS_KEY_HOST, g_settings.host);
    BridgeSettingSetUint(SETTINGS_SECTION, SETTINGS_KEY_PORT, g_settings.port);
    BridgeSettingSetUint(SETTINGS_SECTION, SETTINGS_KEY_AUTOSTART, g_settings.auto_start ? 1 : 0);
    BridgeSettingSet(SETTINGS_SECTION, SETTINGS_KEY_TOKEN, g_settings.auth_token);
    BridgeSettingFlush();
}

// ============================================================================
// Route registration
// ============================================================================

void register_all_routes(c_http_router& router) {
    // Health check endpoint
    router.get("/api/health", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"version", PLUGIN_VERSION_STR},
            {"plugin",  PLUGIN_NAME},
            {"status",  "ok"}
        });
    });

    // Process info endpoint
    router.get("/api/process/info", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto pid = bridge.eval_expression("$pid");
        auto peb = bridge.eval_expression("peb()");
        auto entry = bridge.eval_expression("mod.entry(0)");

        return s_http_response::ok({
            {"pid",           pid},
            {"peb",           format_utils::format_address(peb)},
            {"entry_point",   format_utils::format_address(entry)},
            {"debugger_state", bridge.get_state_string()}
        });
    });

    // Register all handler categories
    handlers::register_debug_routes(router);
    handlers::register_register_routes(router);
    handlers::register_memory_routes(router);
    handlers::register_breakpoint_routes(router);
    handlers::register_disasm_routes(router);
    handlers::register_module_routes(router);
    handlers::register_thread_routes(router);
    handlers::register_stack_routes(router);
    handlers::register_symbol_routes(router);
    handlers::register_annotation_routes(router);
    handlers::register_search_routes(router);
    handlers::register_patch_routes(router);
    handlers::register_memmap_routes(router);
    handlers::register_command_routes(router);
    handlers::register_analysis_routes(router);
    handlers::register_tracing_routes(router);
    handlers::register_dumping_routes(router);
    handlers::register_antidebug_routes(router);
    handlers::register_exception_routes(router);
    handlers::register_process_routes(router);
    handlers::register_handles_routes(router);
    handlers::register_controlflow_routes(router);
    handlers::register_functions_routes(router);
}

// ============================================================================
// MCP Server command handler
// ============================================================================

static bool mcp_server_command(int argc, char* argv[]) {
    if (argc < 2) {
        _plugin_logputs("[MCP] Usage: mcpserver <start|stop|status>");
        return false;
    }

    std::string subcommand = argv[1];

    if (subcommand == "start") {
        if (g_server.is_running()) {
            _plugin_logputs("[MCP] Server is already running");
            return true;
        }

        auto result = start_server();
        if (result.has_value()) {
            _plugin_logprintf("[MCP] Server started on %s:%u\n", g_settings.host, g_settings.port);
        } else {
            _plugin_logprintf("[MCP] Failed to start server: %s\n", result.error().c_str());
        }
        update_menu_state();
        return result.has_value();
    }

    if (subcommand == "stop") {
        if (!g_server.is_running()) {
            _plugin_logputs("[MCP] Server is not running");
            return true;
        }

        g_server.stop();
        _plugin_logputs("[MCP] Server stopped");
        update_menu_state();
        return true;
    }

    if (subcommand == "status") {
        if (g_server.is_running()) {
            _plugin_logprintf("[MCP] Server is running on %s:%u\n", g_settings.host, g_server.get_port());
        } else {
            _plugin_logputs("[MCP] Server is not running");
        }
        return true;
    }

    _plugin_logputs("[MCP] Unknown subcommand. Usage: mcpserver <start|stop|status>");
    return false;
}

// ============================================================================
// Plugin exports
// ============================================================================

// Explicit DLL entry point. Without this the 32-bit build (clang-cl) does not
// emit a resolvable _DllMain@12 symbol, and newer x64dbg snapshots refuse to
// load x64dbg_mcp.dp32 with "entry point _DllMain@12 could not be located"
// (GitHub issue #1). Defining DllMain ourselves guarantees a valid entry point
// for both x32 and x64 and is the minimum every x64dbg plugin must provide.
BOOL WINAPI DllMain(HINSTANCE /*inst*/, DWORD /*reason*/, LPVOID /*reserved*/) {
    return TRUE;
}

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* init_struct) {
    init_struct->sdkVersion = PLUG_SDKVERSION;
    init_struct->pluginVersion = PLUGIN_VERSION;
    strncpy_s(init_struct->pluginName, PLUGIN_NAME, _TRUNCATE);

    g_plugin_handle = init_struct->pluginHandle;

    // Register the mcpserver command
    _plugin_registercommand(g_plugin_handle, "mcpserver", mcp_server_command, false);

    // Trace lifecycle callbacks (no-op on x64dbg versions that don't fire them).
    // These are not auto-registered by export name, so register explicitly.
    // CB_STARTTRACE / CB_STOPTRACE are trace-record events, not run-trace ones:
    // registering them never produced a callback for TraceIntoConditional. The
    // run-trace state is tracked explicitly through util/trace_state.h instead.

    // Debugger event capture. Registered by name here because only CBMENUENTRY
    // is exported from plugin.def.
    _plugin_registercallback(g_plugin_handle, CB_INITDEBUG, cb_init_debug);
    _plugin_registercallback(g_plugin_handle, CB_STOPDEBUG, cb_stop_debug);
    _plugin_registercallback(g_plugin_handle, CB_ATTACH, cb_attached);
    _plugin_registercallback(g_plugin_handle, CB_BREAKPOINT, cb_breakpoint);
    _plugin_registercallback(g_plugin_handle, CB_EXCEPTION, cb_exception);
    _plugin_registercallback(g_plugin_handle, CB_PAUSEDEBUG, cb_paused);
    _plugin_registercallback(g_plugin_handle, CB_RESUMEDEBUG, cb_resumed);
    _plugin_registercallback(g_plugin_handle, CB_SYSTEMBREAKPOINT, cb_system_breakpoint);
    _plugin_registercallback(g_plugin_handle, CB_CREATEPROCESS, cb_create_process);
    _plugin_registercallback(g_plugin_handle, CB_EXITPROCESS, cb_exit_process);
    _plugin_registercallback(g_plugin_handle, CB_CREATETHREAD, cb_create_thread);
    _plugin_registercallback(g_plugin_handle, CB_LOADDLL, cb_load_dll);
    _plugin_registercallback(g_plugin_handle, CB_STEPPED, cb_step);

    return true;
}

PLUG_EXPORT bool plugstop() {
    // Unregister command + callbacks
    _plugin_unregistercommand(g_plugin_handle, "mcpserver");
    _plugin_unregistercallback(g_plugin_handle, CB_INITDEBUG);
    _plugin_unregistercallback(g_plugin_handle, CB_STOPDEBUG);
    _plugin_unregistercallback(g_plugin_handle, CB_ATTACH);
    _plugin_unregistercallback(g_plugin_handle, CB_BREAKPOINT);
    _plugin_unregistercallback(g_plugin_handle, CB_EXCEPTION);
    _plugin_unregistercallback(g_plugin_handle, CB_PAUSEDEBUG);
    _plugin_unregistercallback(g_plugin_handle, CB_RESUMEDEBUG);
    _plugin_unregistercallback(g_plugin_handle, CB_SYSTEMBREAKPOINT);
    _plugin_unregistercallback(g_plugin_handle, CB_CREATEPROCESS);
    _plugin_unregistercallback(g_plugin_handle, CB_EXITPROCESS);
    _plugin_unregistercallback(g_plugin_handle, CB_CREATETHREAD);
    _plugin_unregistercallback(g_plugin_handle, CB_LOADDLL);
    _plugin_unregistercallback(g_plugin_handle, CB_STEPPED);

    // Stop the HTTP server
    g_server.stop();

    _plugin_logputs("[MCP] Plugin stopped");
    return true;
}

PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setup_struct) {
    // Store GUI handles
    g_hwnd_dlg = setup_struct->hwndDlg;
    g_menu_handle = setup_struct->hMenu;

    // Load persisted settings
    load_settings();

    // Set plugin menu icon
    ICONDATA icon_data;
    icon_data.data = plugin_icon::png_data;
    icon_data.size = plugin_icon::png_size;
    _plugin_menuseticon(g_menu_handle, &icon_data);

    // Build menu entries
    _plugin_menuaddentry(g_menu_handle, menu_start_server, "Start Server");
    _plugin_menuaddentry(g_menu_handle, menu_stop_server, "Stop Server");
    _plugin_menuaddseparator(g_menu_handle);
    _plugin_menuaddentry(g_menu_handle, menu_settings, "Settings...");
    _plugin_menuaddentry(g_menu_handle, menu_about, "About...");

    // Register all API routes
    register_all_routes(g_router);

    // Auto-start the server (if enabled in settings)
    if (g_settings.auto_start) {
        auto result = start_server();
        if (result.has_value()) {
            _plugin_logprintf("[MCP] x64dbg MCP Server started on %s:%u\n",
                g_settings.host, g_settings.port);
        } else {
            _plugin_logprintf("[MCP] Failed to auto-start server: %s\n", result.error().c_str());
            _plugin_logputs("[MCP] Use 'mcpserver start' to retry");
        }
    } else {
        _plugin_logputs("[MCP] Auto-start disabled. Use 'mcpserver start' or menu to start.");
    }

    // Sync checkmarks with actual server state
    update_menu_state();
}

PLUG_EXPORT void CBMENUENTRY(CBTYPE, void* call_info) {
    auto* info = static_cast<PLUG_CB_MENUENTRY*>(call_info);

    switch (info->hEntry) {
    case menu_start_server:
        if (g_server.is_running()) {
            _plugin_logputs("[MCP] Server is already running");
        } else {
            auto result = start_server();
            if (result.has_value()) {
                _plugin_logprintf("[MCP] Server started on %s:%u\n",
                    g_settings.host, g_settings.port);
            } else {
                _plugin_logprintf("[MCP] Failed to start server: %s\n", result.error().c_str());
            }
        }
        update_menu_state();
        break;

    case menu_stop_server:
        if (!g_server.is_running()) {
            _plugin_logputs("[MCP] Server is not running");
        } else {
            g_server.stop();
            _plugin_logputs("[MCP] Server stopped");
        }
        update_menu_state();
        break;

    case menu_settings: {
        // Snapshot current settings in case we need to detect host/port changes
        const auto old_host = std::string(g_settings.host);
        const auto old_port = g_settings.port;

        if (show_settings_dialog(g_hwnd_dlg, g_settings) == IDOK) {
            save_settings();
            _plugin_logputs("[MCP] Settings saved");

            // Restart server if host/port changed and server is running
            const bool host_changed = (old_host != g_settings.host);
            const bool port_changed = (old_port != g_settings.port);

            if (g_server.is_running() && (host_changed || port_changed)) {
                g_server.stop();
                auto result = start_server();
                if (result.has_value()) {
                    _plugin_logprintf("[MCP] Server restarted on %s:%u\n",
                        g_settings.host, g_settings.port);
                } else {
                    _plugin_logprintf("[MCP] Failed to restart server: %s\n",
                        result.error().c_str());
                }
                update_menu_state();
            }
        }
        break;
    }

    case menu_about:
        show_about_dialog(g_hwnd_dlg, g_server.is_running(),
            g_settings.host, g_server.get_port());
        break;

    default:
        break;
    }
}
