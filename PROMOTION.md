# Promotion Notes — x64dbg MCP Server

Internal scratchpad for release copy. Rewrite the version block each release; the boilerplate
below stays.

---

## v2.4.0 angle (lead with this)

The story this release tells: **one debugger became a fleet, and the agent stopped needing a
human at the mouse.**

- **Multi-instance routing.** Every tool takes an `instance` argument. `x64dbg_instances` lists,
  starts, adopts, releases and steals endpoints; a lease reports the holder's pid and how long
  it has been idle, so a crashed session does not wedge the machine until you reboot. A target
  file can only be owned by one session at a time — two agents can no longer fight over the same
  `.exe`.
- **GUI driving.** `x64dbg_ui` screenshots, OCRs, finds text and injects input. `message` mode
  posts to the window thread — no focus theft, so several targets can be driven in parallel;
  `real` mode serialises machine-wide and is UIPI-guarded. Paused Direct2D targets refuse
  PrintWindow unless you pass `force: true`.
- **Session recovery.** `load` / `attach` / `detach` / `wait_for_pause` / `wait_for_event` /
  `recover` drive the state machine instead of pushing raw commands at it. Note that `init`
  always stops at the system breakpoint, so `load` naturally lands paused — this is the
  supported way to get a pauseable session, not "open the GUI then attach".
- **Function discovery.** `x64dbg_functions` pages x64dbg's analysed function list and runs
  `anal` / `analr` / `cfanal` on demand.
- **CPUID spoofing.** `x64dbg_antidebug spoof_cpuid` arms a silent breakpoint at every CPUID site
  that tests ECX bit 31 and clears the hypervisor-present bit before resuming; sites that
  compare against `0x40000000` get the vendor leaf zeroed. Only the debuggee is affected.
- **Destructive-operation guards.** A trace in progress refuses interfering actions unless asked
  with `force: true`. Write actions are gated per tool *and* per action — `x64dbg_handles` gates
  only `close`, `x64dbg_process` only `set_cmdline`. `X64DBG_MCP_AUDIT=1` appends one JSON line
  per write.

26 mega-tools, 169 REST endpoints, all local.

Suggested one-liner:

> "Shipped v2.4.0 of the x64dbg MCP server: multi-instance routing with leases, GUI driving,
> session recovery, and CPUID spoofing. 26 mega-tools, all on localhost."

---

## Ready-to-post copy

### Title

> x64dbg MCP v2.4.0 — let AI drive x64dbg across several debuggers at once

### Body

Built an MCP server that lets Claude (or any MCP client) operate the x64dbg debugger in plain
English. A C++ plugin runs inside x64dbg; a small TypeScript server bridges it over stdio.
Everything stays on localhost.

What v2.4.0 added:

- **Multi-instance routing** — leases tell you who holds an endpoint and for how long; a target
  file is claimed by exactly one session.
- **GUI driving** — screenshot, OCR, find text, click and type into the debuggee. `message` mode
  doesn't steal focus, so you can drive several windows at once.
- **Session recovery** — `load`, `attach`, `detach`, `wait_for_pause`, `wait_for_event`,
  `recover`. `init` stops at the system breakpoint, so `load` lands paused and everything
  downstream works.
- **Function discovery** — page the analysed function list, trigger `anal`/`analr`/`cfanal`.
- **CPUID spoofing** — clear the hypervisor-present bit at every CPUID site that tests it.
- **Guards** — trace-in-progress refuses interfering actions without `force: true`; write
  actions are gated per tool and action, with opt-in audit logging.

26 tools, 169 endpoints: breakpoints, memory read/write, disassembly, tracing, anti-debug,
patching, dumping, instances, UI.

GitHub: https://github.com/Absurdity233/x64dbg-mcp-server

---

## Short-form blurbs

### One-liner

> MCP server for x64dbg — 26 tools, 169 endpoints. Breakpoints, memory, disassembly, tracing,
> anti-debug, multi-instance. All on `127.0.0.1`.

### With the anti-debug hook

> Gave Claude hands inside x64dbg. 26 mega-tools over 169 REST endpoints, all local. Anti-debug
> bypass, CPUID spoofing, PE dumping with IAT fix, multi-instance leases, window OCR/click.
> C++ plugin + TypeScript server over stdio.

### For a debugging-focused audience

> `x64dbg_antidebug hide_debugger` clears the PEB flags *and* verifies by reading back.
> `spoof_cpuid` clears the hypervisor bit at CPUID sites that test it. `block_terminate` stubs
> the termination APIs so the target can't kill the debugger, and `restore: true` puts the
> original bytes back. Nobody is expected to remember which PEB offset holds `NtGlobalFlag`.

---

## Talking points

- **Everything is local.** Plugin binds `127.0.0.1`, server speaks stdio, no telemetry.
- **Optional bearer token.** Set one in the plugin's Settings, pass it as `X64DBG_MCP_TOKEN`;
  every request must then carry it.
- **Write gating is per action, not per tool.** A blanket "this tool is dangerous" flag is
  useless when `x64dbg_debug` also has read-only `state`.
- **Leases beat "hope it exits".** A crashed MCP client leaves a lease with a pid and idle time,
  so the next session can decide to wait or steal rather than guessing.
- **Attribution.** Based on bromo's MIT-licensed `x64dbg_mcp`; the multi-instance, UI,
  recovery, function-discovery and CPUID-spoofing layers are this fork's work. LICENSE keeps
  both copyright lines.

---

## Notes

- Do not claim "23 tools" or "153 endpoints" — that is the upstream v2.3.0 state.
- The plugin's real listen port comes from `instances.json`, not `mcp_config.json`. Copy that
  value into `X64DBG_MCP_PORT`.
- `x64dbg_functions` needs analysis to have run; an empty list is expected on a fresh load.
