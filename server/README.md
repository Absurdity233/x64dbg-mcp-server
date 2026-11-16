# x64dbg MCP Server

[![npm version](https://img.shields.io/npm/v/x64dbg-mcp-server)](https://www.npmjs.com/package/x64dbg-mcp-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org/)

**Drive [x64dbg](https://x64dbg.com/) with your AI.** Talk to Claude, Cursor, Windsurf, Cline,
or any MCP client in plain English and it sets breakpoints, reads memory, disassembles, traces,
dumps PEs, and bypasses anti-debug — live, inside the debugger.

**27 mega-tools** over **169 REST endpoints**, fully typed with Zod. This package is the
TypeScript MCP server; it bridges your client to a C++ plugin running inside x64dbg. Everything
stays on `127.0.0.1`.

> **v2.4.0** — multi-instance routing with leases, GUI driving (`x64dbg_ui`), session recovery
> (`load`/`attach`/`detach`/`wait_for_pause`/`recover`), function discovery
> (`x64dbg_functions`), CPUID hypervisor-bit spoofing, and per-tool write-action gating.
> [Get the matching plugins →](https://github.com/Absurdity233/x64dbg-mcp-server/releases/latest)

## Install

**1. Plugin** — download `x64dbg_mcp.dp64` / `.dp32` from
[GitHub Releases](https://github.com/Absurdity233/x64dbg-mcp-server/releases/latest) into your x64dbg
`x64/plugins/` and `x32/plugins/` folders. Start x64dbg; the log shows
`[MCP] x64dbg MCP Server started on 127.0.0.1:27042`.

**2. Server** — point your AI client at npx (no install needed):

<details open>
<summary><b>Claude Code</b></summary>

`.claude/settings.json` (project) or `~/.claude/settings.json` (global):

```json
{
  "mcpServers": {
    "x64dbg": { "type": "stdio", "command": "cmd", "args": ["/c", "npx", "-y", "x64dbg-mcp-server"] }
  }
}
```
</details>

<details>
<summary><b>Claude Desktop · Cursor · Windsurf · Cline</b></summary>

Add to your client's MCP config
(`claude_desktop_config.json`, `.cursor/mcp.json`, `~/.codeium/windsurf/mcp_config.json`,
or `cline_mcp_settings.json`):

```json
{
  "mcpServers": {
    "x64dbg": { "command": "npx", "args": ["-y", "x64dbg-mcp-server"] }
  }
}
```
</details>

<details>
<summary><b>Any other MCP client</b></summary>

stdio transport — spawn `npx -y x64dbg-mcp-server` and speak the
[MCP protocol](https://modelcontextprotocol.io/) over stdin/stdout. Or install globally:
`npm install -g x64dbg-mcp-server`.
</details>

**3. Debug** — open a target in x64dbg and ask:

```
"Set a breakpoint on CreateFileW and run"
"Disassemble the current function and explain it"
"Search for 48 8B ?? 48 85 C0 and disassemble the hits"
"Hide the debugger and bypass the anti-debug checks"
"Dump the main module and fix the import table"
```

## Tools

27 action-based tools: **control** (run/step/commands), **CPU & memory** (registers, read/write/
alloc/protect, map), **stack** (call stack, SEH), **analysis** (disasm/assemble, xrefs, CFG,
loops), **breakpoints & tracing** (sw/hw/memory/conditional/logging/batch), **symbols & search**
(labels, comments, AOB + string scan), **process & system** (threads, handles, TCP, PEB,
anti-debug hide), and **patching & dumping** (patches, PE dump, IAT fix).

→ Every tool, action, and REST endpoint: **[full reference](https://github.com/Absurdity233/x64dbg-mcp-server/blob/master/docs/REFERENCE.md)**.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `X64DBG_MCP_HOST` | `127.0.0.1` | Plugin REST API host |
| `X64DBG_MCP_PORT` | `27042` | Plugin REST API port |
| `X64DBG_MCP_TIMEOUT` | `0` | Per-request timeout (ms). `0` = wait indefinitely (default); set a positive value for a hard ceiling. |
| `X64DBG_MCP_RETRIES` | `3` | Retry count on transient connection failures (not applied to timeouts, 4xx/5xx, or malformed responses) |
| `X64DBG_MCP_TOKEN` | *(empty)* | Bearer token sent on every request; must match the plugin's **Settings > Token**. Empty = no auth. |

```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "npx",
      "args": ["-y", "x64dbg-mcp-server"],
      "env": { "X64DBG_MCP_PORT": "27043" }
    }
  }
}
```

## Security

The C++ plugin binds to `127.0.0.1` only; this server talks pure stdio. All traffic stays on
localhost — no remote access, no data leaves your machine.

## Links

- [GitHub repository](https://github.com/Absurdity233/x64dbg-mcp-server) — source, C++ plugin, build
- [Full reference](https://github.com/Absurdity233/x64dbg-mcp-server/blob/master/docs/REFERENCE.md)
- [Plugin releases](https://github.com/Absurdity233/x64dbg-mcp-server/releases) — prebuilt DLLs
- [x64dbg](https://x64dbg.com/)

## License

MIT · fork maintained by **Absurdity233** — [GitHub](https://github.com/Absurdity233).

A fork of **[bromoket/x64dbg_mcp](https://github.com/bromoket/x64dbg_mcp)** by
[bromo](https://github.com/bromoket), used under the MIT license. The original 23 tools, the REST
bridge and the plugin belong to that project; multi-instance routing, GUI driving, session
recovery, function discovery, CPUID spoofing and the per-action write guards are this fork's work.
