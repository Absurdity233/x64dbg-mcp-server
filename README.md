# x64dbg MCP Server

[![npm version](https://img.shields.io/npm/v/x64dbg-mcp-server)](https://www.npmjs.com/package/x64dbg-mcp-server)
[![MCP Registry](https://img.shields.io/badge/MCP-registry-blue)](https://registry.modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Drive [x64dbg](https://x64dbg.com/) with your AI.** Talk to Claude, Cursor, Windsurf, Cline,
or any MCP client in plain English and it sets breakpoints, reads memory, disassembles, traces,
dumps PEs, and bypasses anti-debug — live, inside the debugger.

> **Fork of [bromoket/x64dbg_mcp](https://github.com/bromoket/x64dbg_mcp)** (MIT, by
> [bromo](https://github.com/bromoket)). The plugin, the REST bridge and the original 23 tools
> are that project's work; multi-instance routing, GUI driving, session recovery, function
> discovery, CPUID spoofing and the write-action guards are this fork's addition.
> See [Credits](#credits).

**27 mega-tools** over **169 REST endpoints**, fully typed with Zod. A C++ plugin runs inside
x64dbg; a tiny TypeScript server bridges it to your client over stdio. Everything stays on
`127.0.0.1` — nothing leaves your machine.

> **v2.4.0**
> - **Multi-instance routing.** Every tool takes an `instance` argument; `x64dbg_instances`
>   lists, starts, adopts, releases and steals x64dbg endpoints, with a lease that reports the
>   holder pid and idle time. A target file can only be owned by one session at a time.
> - **GUI driving.** `x64dbg_ui` screenshots, OCRs, finds text and injects input — `message`
>   mode posts to the window thread (no focus theft, several targets in parallel), `real` mode
>   serialises machine-wide and is UIPI-guarded.
> - **Session recovery.** `load` / `attach` / `detach` / `wait_for_pause` / `wait_for_event` /
>   `recover` drive the state machine instead of pushing raw commands.
> - **Function discovery.** `x64dbg_functions` pages x64dbg's analysed function list and runs
>   `anal` / `analr` / `cfanal` on demand.
> - **CPUID spoofing.** `x64dbg_antidebug spoof_cpuid` clears the hypervisor-present bit at every
>   CPUID site that tests it, and zeroes the vendor leaf at sites that compare against
>   `0x40000000`.
> - **Destructive-operation guards.** Trace-in-progress refuses interfering actions unless asked
>   with `force: true`; write actions are gated per tool and action, and can be audited.

---

## What it looks like

```
"Set a breakpoint on CreateFileW and run the program"
"Disassemble the current function and explain what it does"
"Search for 48 8B ?? 48 85 C0 in the main module and disassemble the hits"
"Hide the debugger and bypass the anti-debug checks"
"Trace into the VM dispatcher and log every instruction to a file"
"Dump the main module to disk and fix the import table"
```

Real use: tracing VMProtect'd code, finding anti-cheat scanner threads, decoding XOR'd class
names, mapping detection logic — all by asking, no manual scripting.

## Install

### 1 · Plugin (inside x64dbg)

**Download** `x64dbg_mcp.dp64` / `.dp32` from the
[latest release](https://github.com/Absurdity233/x64dbg-mcp-server/releases/latest) and drop them in:

```
x64dbg/x64/plugins/x64dbg_mcp.dp64    ← 64-bit targets
x64dbg/x32/plugins/x64dbg_mcp.dp32    ← 32-bit targets
```

…or **build + install** it yourself (auto-detects your x64dbg — no path editing):

```powershell
.\build.ps1 -Install
```

Start x64dbg; the log shows `[MCP] x64dbg MCP Server started on 127.0.0.1:27042`.

> The plugin's listen port can differ from `mcp_config.json` if the instance was provisioned
> with `scripts\provision-instances.ps1` — that script records the real endpoint in
> `instances.json`. Point `X64DBG_MCP_PORT` at what `instances.json` says, not at the ini.

### 2 · Server (your AI client)

Install from npm, or point your client at npx. Claude Code:

```json
{
  "mcpServers": {
    "x64dbg": {
      "type": "stdio",
      "command": "cmd",
      "args": ["/c", "npx", "-y", "x64dbg-mcp-server"]
    }
  }
}
```

Claude Desktop / Cursor / Windsurf / Cline use the same block without the `cmd /c` wrapper:
`{ "command": "npx", "args": ["-y", "x64dbg-mcp-server"] }`.
Full per-client paths are in the [reference](docs/REFERENCE.md#configuration).

If you are working on the server itself, point at the built entry point instead:

```json
"args": ["F:\\path\\to\\x64dbg-mcp-2.4.0\\server\\dist\\index.js"]
```

### 3 · Go

Open a target in x64dbg and start talking to your assistant.

## Tools at a glance

27 action-based tools spanning the whole debugger:

- **Control** — run/step/pause, load/attach/detach, wait for pause or event, recovery, raw
  commands, scripts, expression eval
- **CPU & memory** — registers (incl. AVX-512), read/write/alloc/protect, memory map
- **Stack** — call stack, SEH chain, return addresses
- **Code analysis** — disassemble, assemble, xrefs, basic blocks, CFG, loops, functions
- **Breakpoints & tracing** — software/hardware/memory/conditional/logging, batch, trace logs
- **Symbols & search** — labels, comments, bookmarks, AOB pattern + string scan
- **Process & system** — threads/TEB, handles, TCP, PEB, **anti-debug hide & CPUID spoof**
- **Patching & dumping** — byte patches, PE dump, IAT fix, patch export
- **Instances & UI** — multi-instance routing with leases, elevated launch, window OCR/click/type

Every tool, action, and endpoint is documented in **[docs/REFERENCE.md](docs/REFERENCE.md)**.

## Links

- **[Full reference](docs/REFERENCE.md)** — tools, architecture, build, config, troubleshooting
- **[npm: x64dbg-mcp-server](https://www.npmjs.com/package/x64dbg-mcp-server)**
- **[Releases](https://github.com/Absurdity233/x64dbg-mcp-server/releases)** — prebuilt plugin DLLs
- **[x64dbg](https://x64dbg.com/)** — the debugger

## Security

The plugin binds to `127.0.0.1` only; the server talks pure stdio. All traffic stays on
localhost — no remote access, no telemetry, no data leaves your machine. For defense against
other local processes, set a token in the plugin's **Settings** and pass it via
`X64DBG_MCP_TOKEN` — every request must then carry it.

Set `X64DBG_MCP_AUDIT=1` to append one JSON line per write action to the audit log; the default
stays quiet, and a failed audit never fails the tool call.

## Credits

This project is a fork of **[bromoket/x64dbg_mcp](https://github.com/bromoket/x64dbg_mcp)**
by **bromo** ([GitHub](https://github.com/bromoket)), used under the MIT license. The C++ plugin,
the REST bridge, the TypeScript server skeleton and the original 23 tools come from that
project — it is the base this fork stands on.

What this fork added (v2.4.x):

- **Multi-instance routing** — `instances.ts`, `lease.ts`, `target_claims.ts`, and the
  `x64dbg_instances` tool: endpoint registry, exclusive leases with holder pid and idle time,
  one-session-per-target-file claims.
- **GUI driving** — `ui_daemon.ts`, `ui_lock.ts`, and the `x64dbg_ui` tool: window capture, OCR,
  text search, and input injection with `message`/`real` modes and UIPI guards.
- **Session recovery** — `load` / `attach` / `detach` / `wait_for_pause` / `wait_for_event` /
  `recover` on `x64dbg_debug`.
- **Function discovery** — the `x64dbg_functions` tool.
- **CPUID spoofing** — `x64dbg_antidebug spoof_cpuid`.
- **Per-action write gating and audit** — `WRITE_ACTIONS` keyed by tool *and* action, plus the
  opt-in `X64DBG_MCP_AUDIT` log.
- **Destructive-operation guards** — `trace_guard.ts` refusing interfering actions mid-trace.

If you want the original project without these changes, use
[bromoket/x64dbg_mcp](https://github.com/bromoket/x64dbg_mcp) directly.

## Author

Fork maintained by **Absurdity233** — [GitHub](https://github.com/Absurdity233).
Original project by **bromo** — [bromoket/x64dbg_mcp](https://github.com/bromoket/x64dbg_mcp).
[MIT](LICENSE).
