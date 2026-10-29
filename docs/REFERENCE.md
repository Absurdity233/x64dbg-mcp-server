# x64dbg MCP — Full Reference

Complete reference for the x64dbg MCP server: every tool and action, the architecture,
the build system, configuration, and troubleshooting. The [README](../README.md) is the
quick tour; this is the exhaustive version (kept for humans doing deep work and for AI
agents operating the plugin).

- [How it works](#how-it-works)
- [Tool reference (26 mega-tools)](#tool-reference-26-mega-tools)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Building from source](#building-from-source)
- [Troubleshooting](#troubleshooting)
- [Security](#security)

## How it works

```
                         stdio                        HTTP (localhost)
 MCP Client  <───────────────────>  TypeScript MCP  <──────────────────>  C++ Plugin
 (Claude,                           Server            127.0.0.1:27042     (inside x64dbg)
  Cursor,                           26 mega-tools                         170 REST endpoints
  etc.)                             Zod validation                        Bridge/Plugin SDK
```

- **C++ Plugin** (`x64dbg_mcp.dp64` / `.dp32`) runs inside x64dbg as a lightweight REST API
  server on `127.0.0.1:27042`. It wraps the x64dbg Bridge/Plugin SDK with 170 JSON endpoints
  across 23 handler files.
- **TypeScript MCP Server** (`x64dbg-mcp-server` on npm) implements the MCP protocol over
  stdio. The 26 mega-tools use flat Zod schemas (one `action` enum plus optional fields, with
  required-field checks at call time) to validate parameters, then route requests to the
  correct REST endpoint on the plugin via localhost HTTP.

The MCP server waits for the plugin to become available, performs periodic health checks, and
automatically reconnects if x64dbg restarts. Reads default to `X64DBG_MCP_READ_TIMEOUT_MS`
(30s, long-polls excluded); writes and debugger control keep `X64DBG_MCP_TIMEOUT` (0 = wait
indefinitely, since run/trace are unbounded). Transient connection failures retry up to 3 times
with exponential backoff (timeouts are not retried).

**Why stdio?** No SSE reconnection issues, no port conflicts, no dropped connections. The MCP
client spawns the server as a child process — it just works.

### Safety guards

- **Live trace.** `x64dbg_debug` refuses `pause`, `force_pause`, `stop_debug`,
  `restart_debug`, `detach`, `load`, `attach`, `recover` and `run_to_address`;
  `x64dbg_command execute/script` refuses statements whose first token is
  `pause/stop/StopRunTrace/restart/init/attach/detach/load/close/quit`; and
  `x64dbg_tracing` refuses to start a second trace. Pass `force:true` to override
  one call, or use `x64dbg_tracing action=stop` (it pauses, then calls
  `StopRunTrace`).
- **Paused debugger.** `x64dbg_ui` refuses `screenshot`, `ocr`, `findtext`,
  `clicktext` and `typeinto` because `PrintWindow`/OCR can block on a paused
  Direct2D window. Resume first, or pass `force:true` for a modal dialog.
- **Integrity mismatch.** `x64dbg_ui` checks the target's integrity level and
  returns `integrity-mismatch` instead of letting UIPI drop input silently.
- **Elevation.** `x64dbg_instances start elevated=true` returns
  `running-unelevated` for an already-running medium-integrity x64dbg (Windows
  cannot raise an existing process).

Large list responses are paged: `x64dbg_database`, `x64dbg_analysis`
(`xrefs_to/xrefs_from/basic_blocks`) and `x64dbg_search`
(`pattern/string/symbol_auto_complete/memory`) take `limit`/`offset`;
`x64dbg_command get_events` takes `max_events` and leaves the rest buffered.
Plugin errors are returned as `{"error":{"code","message","hint"}}`.

## Tool reference (26 mega-tools)

Each tool accepts an `action` parameter that selects the specific operation. Parameters are
validated with Zod schemas at runtime.

### Debugger control

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_debug` | `run`, `pause`, `force_pause`, `step_into`, `step_over`, `step_out`, `stop_debug`, `restart_debug`, `run_to_address`, `state` | Control execution flow and query debugger state |
| `x64dbg_command` | `execute`, `script`, `evaluate`, `format`, `set_init_script`, `get_init_script`, `get_hash`, `get_events` | Execute raw x64dbg commands, batch scripts, and expression evaluation. `force` overrides the trace guard; `max_events` caps `get_events` |

### CPU & memory

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_registers` | `get_all`, `get_specific`, `get_flags`, `get_avx512`, `set` | Read/write CPU registers including GPR, flags, and AVX-512 |
| `x64dbg_memory` | `read`, `write`, `info`, `is_valid`, `is_code`, `allocate`, `free`, `protect`, `map`, `update_map` | Full memory operations: read, write, allocate, protect, and memory map |
| `x64dbg_stack` | `get_call_stack`, `read`, `pointers`, `seh_chain`, `return_address`, `comment` | Call stack unwinding, raw stack reads, SEH chain, return address |

### Code analysis

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_disassembly` | `at_address`, `function`, `info`, `assemble` | Disassemble instructions, whole functions, or assemble new code |
| `x64dbg_analysis` | `function`, `xrefs_to`, `xrefs_from`, `basic_blocks`, `source`, `mnemonic_brief` | Cross-references, function boundaries, basic blocks, source mapping |
| `x64dbg_control_flow` | `cfg`, `branch_dest`, `is_jump_taken`, `loops`, `func_type`, `add_function`, `delete_function` | Control flow graph, branch analysis, loop detection, function management |
| `x64dbg_database` | `constants`, `error_codes`, `structs`, `strings` | Query x64dbg's analysis database for constants, errors, structs, strings |
| `x64dbg_address_convert` | `va_to_file`, `file_to_va` | Convert between virtual addresses and file offsets |
| `x64dbg_watchdog` | *(id parameter)* | Check if a watch expression watchdog has been triggered |

### Breakpoints & tracing

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_breakpoints` | `set_software`, `set_hardware`, `set_memory`, `delete`, `enable`, `disable`, `toggle`, `set_condition`, `set_log`, `reset_hit_count`, `get`, `list`, `configure`, `configure_batch` | Full breakpoint management: software, hardware, memory, conditional, logging, batch |
| `x64dbg_tracing` | `into`, `over`, `run`, `stop`, `status`, `animate`, `conditional_run`, `log_setup`, `hitcount`, `type`, `set_type` | Execution tracing, trace logging, hit counters, conditional tracing, live trace status. Start actions accept `force` |
| `x64dbg_exceptions` | `set`, `delete`, `list`, `list_codes`, `skip` | Exception breakpoints, known exception codes, skip/pass exceptions |

### Symbols & annotations

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_symbols` | `resolve`, `address`, `search`, `list_module`, `get_label`, `set_label`, `get_comment`, `set_comment`, `bookmark` | Symbol resolution, labels, comments, bookmarks |
| `x64dbg_search` | `pattern`, `string`, `string_at`, `symbol_auto_complete`, `encode_type` | AOB/byte pattern scan, string search, symbol autocomplete |
| `x64dbg_modules` | `list`, `get_info`, `get_base`, `get_section`, `get_party` | Loaded modules, base addresses, sections, user/system classification |

### Process & system

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_process` | `basic`, `detailed`, `cmdline`, `elevated`, `dbversion`, `set_cmdline` | Process info, PID, PEB, elevation status, debugger version |
| `x64dbg_threads` | `list`, `current`, `count`, `info`, `teb`, `name`, `switch`, `suspend`, `resume` | Thread enumeration, TEB access, thread control |
| `x64dbg_handles` | `list_handles`, `list_tcp`, `list_windows`, `list_heaps`, `get_name`, `close` | Handles, TCP connections, windows, heaps |
| `x64dbg_antidebug` | `peb`, `teb`, `dep`, `hide_debugger`, `harden`, `vm_probes`, `probe_breakpoints`, `block_terminate` | PEB/TEB inspection, DEP status, hide debugger, VM-probe scan, stub termination APIs in a paused target (`restore:true` reverts) |

### Instances & UI

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_instances` | `list`, `start`, `use`, `status`, `release`, `steal` | Multi-instance routing, leases, elevated launch |
| `x64dbg_ui` | `windows`, `info`, `activity`, `screenshot`, `ocr`, `findtext`, `clicktext`, `typeinto`, `click`, `realclick`, `type`, `key` | Window capture and input for the debuggee |

### Patching & dumping

| Tool | Actions | Description |
|------|---------|-------------|
| `x64dbg_patches` | `list`, `apply`, `restore`, `export` | Apply byte patches, restore originals, export patched module |
| `x64dbg_dumping` | `pe_header`, `sections`, `imports`, `exports`, `entry_point`, `relocations`, `dump_module`, `fix_iat`, `export_patch_file` | PE analysis, module dumping, IAT reconstruction, patch file export |

## Configuration

Environment variables for the MCP server:

| Variable | Default | Description |
|----------|---------|-------------|
| `X64DBG_MCP_HOST` | `127.0.0.1` | Plugin REST API host |
| `X64DBG_MCP_PORT` | `27042` | Plugin REST API port |
| `X64DBG_MCP_TIMEOUT` | `0` | Per-request timeout in milliseconds. `0` = wait indefinitely (default), since debugger operations like run/trace are unbounded. Set a positive value for a hard ceiling. |
| `X64DBG_MCP_RETRIES` | `3` | Retry count on transient connection failures (not applied to timeouts, 4xx/5xx, or malformed responses) |
| `X64DBG_MCP_TOKEN` | *(empty)* | Bearer token sent on every request. Must match the plugin's **Settings > Token**. Empty = no auth. |
| `X64DBG_MCP_READ_TIMEOUT_MS` | `30000` | Timeout for GET requests. Long-polls (`/api/command/events*`) opt out. `0` disables the cap. |
| `X64DBG_MCP_MAX_BYTES` | `65536` | Cap on non-JSON text replies (disassembly, OCR, dumps). JSON is left intact so paging stays parseable. `0` disables. |
| `X64DBG_MCP_AUDIT` | `off` | Append write actions (memory/patches/breakpoints/commands/UI input) to `%TEMP%\x64dbg-mcp\audit.log`. |
| `X64DBG_MCP_LEASE` | `on` | Set `off` to stop refusing an instance another live MCP process owns. |
| `X64DBG_MCP_LEASE_IDLE_MS` | `0` | Release a lease after this long without a tool call. `0` = never yield. |
| `X64DBG_MCP_AUTOLAUNCH` | `on` | Set `off` to never start x64dbg implicitly; only `x64dbg_instances action=start` launches. |
| `X64DBG_MCP_ELEVATED` | `off` | Launch x64dbg elevated by default. |
| `X64DBG_MCP_ELEVATED_TASK` | *(empty)* | Highest-privilege scheduled task used instead of a UAC prompt (see `scripts/install-elevated-task.ps1`). |
| `X64DBG_MCP_UAC_TIMEOUT_MS` | `120000` | How long to wait for the user to answer a UAC prompt. |
| `X64DBG_MCP_INSTANCES` | *(unset)* | JSON array/object of `{id, port, host?, token?, x64dbgPath?, elevated?, elevatedTask?, label?}`. See [multi-instance](multi-instance.md). |
| `X64DBG_MCP_INSTANCE` | *(first)* | Default instance for this server process. |

Set these in your MCP client config if needed:

```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "npx",
      "args": ["-y", "x64dbg-mcp-server"],
      "env": {
        "X64DBG_MCP_PORT": "27043"
      }
    }
  }
}
```

### Plugin commands

Control the REST API from the x64dbg command bar:

```
mcpserver start     Start the HTTP server
mcpserver stop      Stop the HTTP server
mcpserver status    Show server status and port
```

The plugin also provides GUI dialogs accessible from `Plugins > x64dbg MCP Server`:

- **Settings...** — configure host, port, auto-start, and the optional auth token (persisted via BridgeSetting)
- **About...** — version, live server status (green/red), GitHub link, Discord contact

## Architecture

### System overview

```
┌─────────────────────────────────────────────────────────────────┐
│  MCP Client (Claude Code, Cursor, etc.)                         │
│  Spawns server as child process, communicates via stdin/stdout   │
└──────────────────────────┬──────────────────────────────────────┘
                           │ stdio (MCP JSON-RPC)
┌──────────────────────────▼──────────────────────────────────────┐
│  TypeScript MCP Server (x64dbg-mcp-server)                      │
│                                                                 │
│  26 tools registered via @modelcontextprotocol/sdk              │
│  Flat Zod schemas: action enum + optional fields                │
│  HttpClient: auto-reconnect, health checks, retry logic         │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTP GET/POST (127.0.0.1:27042)
┌──────────────────────────▼──────────────────────────────────────┐
│  C++ Plugin DLL (x64dbg_mcp.dp64 / .dp32)                      │
│                                                                 │
│  Winsock2 HTTP server, JSON via nlohmann/json                   │
│  23 handler files, 170 REST endpoints                           │
│  c_bridge_executor: thread-safe calls to x64dbg SDK             │
└──────────────────────────┬──────────────────────────────────────┘
                           │ x64dbg Bridge/Plugin SDK
┌──────────────────────────▼──────────────────────────────────────┐
│  x64dbg Debugger Engine                                         │
│  DbgFunctions(), Script API, Bridge API                         │
└─────────────────────────────────────────────────────────────────┘
```

### Project structure

```
x64dbg_mcp/
├── build.ps1                       # One-shot build (SDK fetch + plugin + optional server)
├── install.ps1                     # Auto-detecting plugin installer (registry/process/PATH)
├── plugin/                         # C++ x64dbg plugin (REST API server)
│   ├── CMakeLists.txt              # Build config (C++23, clang-cl)
│   ├── CMakePresets.json           # x64-release, x32-release, x64-debug presets
│   ├── fetch-sdk.ps1               # Version-aware x64dbg pluginsdk fetch (headers + libs)
│   ├── plugin.def                  # DLL export definitions
│   ├── sdk/                        # x64dbg Plugin SDK headers (libs fetched, gitignored)
│   │   ├── _plugins.h              # Plugin API
│   │   ├── _dbgfunctions.h         # DbgFunctions() interface
│   │   ├── bridgemain.h            # Bridge API
│   │   ├── jansson/                # JSON library (SDK dependency)
│   │   └── *.lib                   # x64bridge, x32bridge, x64dbg, x32dbg (fetched)
│   └── src/
│       ├── plugin_main.cpp/.h      # Plugin entry, /api/health, /api/process/info
│       ├── bridge/
│       │   └── c_bridge_executor.* # Thread-safe wrapper for x64dbg API calls
│       ├── handlers/               # 22 REST endpoint handler files
│       │   ├── debug_handler.cpp       # /api/debug/* (11 endpoints)
│       │   ├── register_handler.cpp    # /api/registers/* (5 endpoints)
│       │   ├── memory_handler.cpp      # /api/memory/* (9 endpoints)
│       │   ├── breakpoint_handler.cpp  # /api/breakpoints/* (15 endpoints)
│       │   ├── disasm_handler.cpp      # /api/disasm/* (4 endpoints)
│       │   ├── module_handler.cpp      # /api/modules/* (5 endpoints)
│       │   ├── thread_handler.cpp      # /api/threads/* (9 endpoints)
│       │   ├── stack_handler.cpp       # /api/stack/* (7 endpoints)
│       │   ├── symbol_handler.cpp      # /api/symbols/* (4 endpoints)
│       │   ├── annotation_handler.cpp  # /api/labels/*, /api/comments/*, /api/bookmarks/* (5 endpoints)
│       │   ├── search_handler.cpp      # /api/search/* (5 endpoints)
│       │   ├── command_handler.cpp     # /api/command/* (8 endpoints)
│       │   ├── analysis_handler.cpp    # /api/analysis/* (13 endpoints)
│       │   ├── tracing_handler.cpp     # /api/trace/* (10 endpoints)
│       │   ├── dumping_handler.cpp     # /api/dump/*, /api/patches/export_file (10 endpoints)
│       │   ├── patch_handler.cpp       # /api/patches/* (4 endpoints)
│       │   ├── memmap_handler.cpp      # /api/memmap/* (2 endpoints)
│       │   ├── antidebug_handler.cpp   # /api/antidebug/* (4 endpoints)
│       │   ├── exceptions_handler.cpp  # /api/exceptions/* (5 endpoints)
│       │   ├── process_handler.cpp     # /api/process/* (5 endpoints)
│       │   ├── handles_handler.cpp     # /api/handles/* (6 endpoints)
│       │   └── controlflow_handler.cpp # /api/cfg/* (7 endpoints)
│       ├── http/
│       │   ├── c_http_server.*     # Winsock2 HTTP server (localhost only)
│       │   ├── c_http_router.*     # Method + path routing
│       │   ├── s_http_request.h    # Request struct (method, path, body, query)
│       │   └── s_http_response.h   # Response helpers (ok, bad_request, conflict, etc.)
│       ├── ui/
│       │   ├── settings_dialog.*   # Settings dialog (host, port, auto-start)
│       │   └── about_dialog.*      # About dialog (version, status, links)
│       └── util/
│           └── format_utils.*      # Address formatting, hex parsing
│
├── server/                         # TypeScript MCP server (npm package)
│   ├── package.json                # x64dbg-mcp-server
│   ├── tsconfig.json               # ES2022, Node16, strict mode
│   ├── server.json                 # MCP registry manifest
│   └── src/
│       ├── index.ts                # McpServer entry, stdio transport, graceful shutdown
│       ├── config.ts               # Environment variable config
│       ├── http_client.ts          # HTTP client with auto-reconnect and health monitoring
│       └── tools/                  # 19 tool files, 23 MCP tools
│           ├── index.ts            # Registers all tools on the McpServer
│           ├── debug.ts            # x64dbg_debug
│           ├── registers.ts        # x64dbg_registers
│           ├── memory.ts           # x64dbg_memory (includes memmap)
│           ├── disassembly.ts      # x64dbg_disassembly
│           ├── breakpoints.ts      # x64dbg_breakpoints
│           ├── symbols.ts          # x64dbg_symbols (includes labels, comments, bookmarks)
│           ├── stack.ts            # x64dbg_stack
│           ├── threads.ts          # x64dbg_threads
│           ├── modules.ts          # x64dbg_modules
│           ├── search.ts           # x64dbg_search
│           ├── command.ts          # x64dbg_command
│           ├── analysis.ts         # x64dbg_analysis, x64dbg_database, x64dbg_address_convert, x64dbg_watchdog
│           ├── tracing.ts          # x64dbg_tracing
│           ├── dumping.ts          # x64dbg_dumping
│           ├── antidebug.ts        # x64dbg_antidebug
│           ├── exceptions.ts       # x64dbg_exceptions
│           ├── process.ts          # x64dbg_process
│           ├── handles.ts          # x64dbg_handles
│           ├── controlflow.ts      # x64dbg_control_flow
│           └── patches.ts          # x64dbg_patches
│
├── docs/REFERENCE.md               # This file
├── LICENSE                         # MIT
└── README.md
```

### Tech stack

**MCP Server (TypeScript)**
- **Runtime**: Node.js >= 18
- **Language**: TypeScript (ES2022, strict mode)
- **MCP SDK**: `@modelcontextprotocol/sdk` ^1.12.1
- **Validation**: `zod` ^3.25.1
- **Transport**: stdio (stdin/stdout JSON-RPC)

**Plugin (C++)**
- **Standard**: C++23
- **Compiler**: Clang-cl (ships with Visual Studio 2022)
- **Build System**: CMake 3.20+ with Ninja
- **Dependencies**: nlohmann/json (via vcpkg), x64dbg Plugin SDK, Winsock2
- **Package Manager**: vcpkg

## Building from source

### Prerequisites

CMake >= 3.20, Ninja, vcpkg (`VCPKG_ROOT` set), and Clang-cl (Visual Studio 2022 C++ workload),
plus Node.js >= 18 for the server.

The x64dbg plugin SDK import libs (`x64bridge.lib`, `x64dbg.lib`, ...) are release artifacts
that don't live in any source tree, so they're **fetched from the official x64dbg release**
rather than committed. `plugin/fetch-sdk.ps1` pulls them (headers + libs) when the local copy
is behind the latest release, and falls back to the cached SDK when offline. `build.ps1` runs
it for you.

### One-shot

```powershell
$env:VCPKG_ROOT = "C:\path\to\vcpkg"

.\build.ps1                 # fetch SDK + build both x64 + x32 plugins
.\build.ps1 -Arch x64       # x64 only
.\build.ps1 -Server         # also build the TypeScript server
.\build.ps1 -Install        # build, then install into x64dbg (auto-detected)
.\build.ps1 -ForceSdk       # re-download the SDK even if up to date

# Output:
#   plugin/build/x64-release/bin/x64dbg_mcp.dp64
#   plugin/build/x32-release/bin/x64dbg_mcp.dp32
```

### Manual

```powershell
.\plugin\fetch-sdk.ps1        # sync SDK headers + libs
cd plugin
cmake --preset x64-release
cmake --build --preset x64-release
cmake --preset x32-release
cmake --build --preset x32-release
```

### TypeScript server

```bash
cd server
npm install
npm run build
node dist/index.js          # run from source
```

Point your MCP client at a local build instead of npm:

```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "node",
      "args": ["C:/path/to/x64dbg_mcp/server/dist/index.js"]
    }
  }
}
```

### Installing the built plugin

`install.ps1` finds x64dbg automatically (shell registration → running process → PATH →
prompt, cached afterwards) and copies the DLLs into the right `plugins\` folders:

```powershell
.\install.ps1               # detect x64dbg, install both
.\install.ps1 -Arch x64     # x64 only
.\install.ps1 -Build        # build missing plugins first
.\install.ps1 -Path "D:\re\x64dbg\release"
.\install.ps1 -Force        # ignore cached path and re-detect
```

## Troubleshooting

### "Connection refused" or server can't reach plugin

1. Make sure x64dbg is running with a target loaded
2. Verify the plugin is in the correct `plugins/` directory
3. Check the x64dbg log for `[MCP] x64dbg MCP Server started on 127.0.0.1:27042`
4. Test manually: `curl http://127.0.0.1:27042/api/health`

### "Waiting for x64dbg plugin..." hangs

The MCP server waits for the plugin to come online. Either:
- Start x64dbg **before** launching your MCP client
- Or restart the MCP client after x64dbg is running

### Tools return errors about debugger state

| Error | Meaning | Solution |
|-------|---------|----------|
| "Debugger must be paused" | Inspection tools need paused state | Pause the target or hit a breakpoint first |
| "No active debug session" | No executable loaded | Load a target in x64dbg (`File > Open`) |
| "Debugger must be running" | `pause`/`force_pause` need running target | Run the target first |

### 32-bit vs 64-bit

Use the correct plugin for your target architecture:

| Target | Debugger | Plugin file |
|--------|----------|-------------|
| 64-bit | x64dbg | `x64dbg_mcp.dp64` |
| 32-bit | x32dbg | `x64dbg_mcp.dp32` |

Both use the same MCP server — just `npx -y x64dbg-mcp-server`.

### Plugin not loading

1. Check that the DLL is in the right directory (e.g. `x64/plugins/` for 64-bit)
2. Make sure you're using a recent x64dbg snapshot (2024+)
3. Check if another plugin is conflicting on port 27042
4. Try manually: type `mcpserver start` in the x64dbg command bar

### "Entry point `_DllMain@12` could not be located in ...x64dbg_mcp.dp32"

This affected `x32dbg` on newer x64dbg snapshots and is fixed in **v2.2.2+**. Download the
latest `x64dbg_mcp.dp32`/`.dp64` from
[Releases](https://github.com/bromoket/x64dbg_mcp/releases) and replace the old DLLs. (Cause:
older builds lacked an explicit `DllMain` entry point that newer x64dbg loaders require.)

### Request timeouts

By default the server waits indefinitely, because debugger operations such as run/continue and
conditional traces are unbounded. For a hard ceiling (e.g. to fail fast when the plugin is
unresponsive), set a positive millisecond value:

```bash
X64DBG_MCP_TIMEOUT=120000 npx -y x64dbg-mcp-server
```

## Security

- The C++ plugin binds to `127.0.0.1` only — no remote access, no network exposure
- The MCP server communicates exclusively via stdio (stdin/stdout)
- All HTTP traffic stays on localhost — no data leaves your machine
- No permissive CORS headers are sent, so a local browser page cannot drive the debugger
- Authentication is optional (localhost-only by default). Set a token in **Settings > Token**
  and pass `X64DBG_MCP_TOKEN` to require `Authorization: Bearer <token>` on every request —
  useful to keep other local processes out
