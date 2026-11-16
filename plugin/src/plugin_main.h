#pragma once

#include "_plugins.h"
#include "http/c_http_server.h"
#include "http/c_http_router.h"

// Plugin info
constexpr auto PLUGIN_NAME = "x64dbg MCP Server";
constexpr auto PLUGIN_AUTHOR = "Absurdity233";
constexpr auto PLUGIN_VERSION = 1;
// Injected from server/package.json by CMake (see plugin/CMakeLists.txt). If
// the plugin is built outside CMake the fallback makes the mismatch obvious
// rather than silently reporting a version that looks right.
#ifndef PLUGIN_VERSION_STR
#define PLUGIN_VERSION_STR "0.0.0-unknown"
#endif
constexpr auto PLUGIN_REPO_URL = "https://github.com/Absurdity233/x64dbg-mcp-server";
constexpr uint16_t DEFAULT_PORT = 27042;
constexpr auto DEFAULT_HOST = "127.0.0.1";

// Persistent settings keys (BridgeSettingGet/Set)
constexpr auto SETTINGS_SECTION = "MCP";
constexpr auto SETTINGS_KEY_HOST = "Host";
constexpr auto SETTINGS_KEY_PORT = "Port";
constexpr auto SETTINGS_KEY_AUTOSTART = "AutoStart";
constexpr auto SETTINGS_KEY_TOKEN = "AuthToken";

/// @brief Plugin settings persisted via BridgeSetting
struct s_plugin_settings {
    char host[64] = "127.0.0.1";
    uint16_t port = 27042;
    bool auto_start = true;
    char auth_token[128] = ""; // empty = no auth required
};

// Menu entry IDs
enum e_menu_entry : int {
    menu_start_server = 0,
    menu_stop_server  = 1,
    menu_settings     = 2,
    menu_about        = 3
};

// Plugin export macro (functions are also listed in plugin.def)
#ifndef PLUG_EXPORT
#define PLUG_EXPORT extern "C" __declspec(dllexport)
#endif

// Register all API routes on the router
void register_all_routes(c_http_router& router);
