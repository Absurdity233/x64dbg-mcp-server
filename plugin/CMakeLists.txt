cmake_minimum_required(VERSION 3.20)
project(x64dbg_mcp LANGUAGES CXX)

# The plugin and the MCP server ship as separate artifacts, so their version
# strings have to be comparable or /api/meta cannot detect a mismatch. The
# server's package.json is the single source; both sides read it.
set(SERVER_PACKAGE_JSON "${CMAKE_CURRENT_SOURCE_DIR}/../server/package.json")
if(EXISTS "${SERVER_PACKAGE_JSON}")
    file(READ "${SERVER_PACKAGE_JSON}" _pkg)
    string(REGEX MATCH "\"version\"[ \t\r\n]*:[ \t\r\n]*\"([^\"]+)\"" _m "${_pkg}")
    set(PROJECT_VERSION_STR "${CMAKE_MATCH_1}")
else()
    set(PROJECT_VERSION_STR "0.0.0-unknown")
endif()
message(STATUS "Plugin version: ${PROJECT_VERSION_STR}")
add_compile_definitions(PLUGIN_VERSION_STR="${PROJECT_VERSION_STR}")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Determine architecture
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(X64DBG_ARCH "x64")
    set(PLUGIN_EXT ".dp64")
    set(BRIDGE_LIB "x64bridge")
    set(DBG_LIB "x64dbg")
else()
    set(X64DBG_ARCH "x32")
    set(PLUGIN_EXT ".dp32")
    set(BRIDGE_LIB "x32bridge")
    set(DBG_LIB "x32dbg")
endif()

# nlohmann_json is header-only. Prefer a vcpkg-provided package when present,
# otherwise fall back to the vendored copy in third_party/ so the plugin builds
# without vcpkg.
find_package(nlohmann_json CONFIG QUIET)
if(NOT nlohmann_json_FOUND)
    message(STATUS "nlohmann_json not found via package manager - using vendored header")
    add_library(nlohmann_json INTERFACE)
    target_include_directories(nlohmann_json INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party
    )
    add_library(nlohmann_json::nlohmann_json ALIAS nlohmann_json)
endif()

# Source files
set(SOURCES
    src/plugin_main.cpp
    src/http/c_http_server.cpp
    src/http/c_http_router.cpp
    src/bridge/c_bridge_executor.cpp
    src/util/format_utils.cpp
    src/util/trace_auto.cpp
    src/util/event_log.cpp
    src/handlers/debug_handler.cpp
    src/handlers/register_handler.cpp
    src/handlers/memory_handler.cpp
    src/handlers/breakpoint_handler.cpp
    src/handlers/disasm_handler.cpp
    src/handlers/module_handler.cpp
    src/handlers/thread_handler.cpp
    src/handlers/stack_handler.cpp
    src/handlers/symbol_handler.cpp
    src/handlers/annotation_handler.cpp
    src/handlers/search_handler.cpp
    src/handlers/patch_handler.cpp
    src/handlers/memmap_handler.cpp
    src/handlers/command_handler.cpp
    src/handlers/analysis_handler.cpp
    src/handlers/tracing_handler.cpp
    src/handlers/dumping_handler.cpp
    src/handlers/antidebug_handler.cpp
    src/handlers/exceptions_handler.cpp
    src/handlers/process_handler.cpp
    src/handlers/handles_handler.cpp
    src/handlers/controlflow_handler.cpp
    src/handlers/functions_handler.cpp
    src/ui/settings_dialog.cpp
    src/ui/about_dialog.cpp
)

# Create shared library (plugin DLL)
add_library(${PROJECT_NAME} SHARED ${SOURCES} plugin.def)

# Include directories (SDK as SYSTEM to suppress its warnings)
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_include_directories(${PROJECT_NAME} SYSTEM PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/sdk
)

# Determine jansson lib based on architecture
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(JANSSON_LIB "${CMAKE_CURRENT_SOURCE_DIR}/sdk/jansson/jansson_x64.lib")
else()
    set(JANSSON_LIB "${CMAKE_CURRENT_SOURCE_DIR}/sdk/jansson/jansson_x86.lib")
endif()

# Link dependencies
target_link_libraries(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/sdk/${BRIDGE_LIB}.lib
    ${CMAKE_CURRENT_SOURCE_DIR}/sdk/${DBG_LIB}.lib
    ${JANSSON_LIB}
    nlohmann_json::nlohmann_json
    ws2_32
    dbghelp
)

# Set output name to match x64dbg plugin convention
set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME "x64dbg_mcp"
    SUFFIX ${PLUGIN_EXT}
    PREFIX ""
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Compiler flags for clang-cl / MSVC
target_compile_options(${PROJECT_NAME} PRIVATE
    /W4
    /utf-8
    /EHsc
)

target_compile_definitions(${PROJECT_NAME} PRIVATE
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    BUILD_PLUGIN
)
