# Performance

Measured on the local setup (x64dbg + plugin on loopback):

| Metric | Value |
|---|---|
| Cheap tool call round trip (`x64dbg_process basic`) | **3.35 ms** |
| 8 concurrent calls | **12–17 ms** (the MCP SDK does not serialise handlers) |
| `tools/list` schema, single instance | 29,226 B ≈ **8.1k tokens** |
| `tools/list` schema, two instances | 32,502 B ≈ **9.0k tokens** |
| `handles list` before paging | 61.5 KB ≈ **17k tokens** in one reply |

Local latency is not the problem - a call is a couple of HTTP requests to
127.0.0.1. The cost is **tokens**: the tool schema is part of every request, and
a single unbounded list reply can be larger than the whole schema.

## What is optimised

**Instance parameter is conditional.** `instance` is only added to the 26 tool
schemas when more than one instance is configured; it costs ~1,026 tokens and
is meaningless with a single target. Single-instance schema: 9.2k -> 8.1k.

**Large JSON replies are compacted.** Every tool pretty-prints its result (131
call sites). Instead of rewriting them, the tool wrapper re-serialises any JSON
text block over 2 KB without indentation. `X64DBG_MCP_COMPACT=on|off|auto`
(default `auto`). Small replies stay readable; a 60 KB dump loses ~25% of its
bytes. Non-JSON output (disassembly, OCR text) is never touched.

**Lists are paged and filterable.** `x64dbg_handles` returned the entire handle
table (61.5 KB). It now returns 200 entries by default with
`total`/`returned`/`truncated`, takes `offset`, and accepts
`filter` matched against `type_name`/`name`/`class_name`:

| Query | Size |
|---|---|
| `list_handles` (default page) | 28.5 KB |
| `list_handles filter:"Key"` | 5.2 KB |
| `list_handles filter:"File"` | 2.9 KB |

**A missing plugin fails fast.** The wait budget was a flat 120 s, which is right
while the editor is starting x64dbg but wrong for a routed instance that is not
running: every call stalled for two minutes. Now 120 s single-instance, 15 s
multi-instance, override with `X64DBG_MCP_WAIT_MS`.

**The UI daemon stays warm.** Starting PowerShell costs ~3 s (CLR + WinRT +
Add-Type); the idle shutdown was 10 minutes, so any pause paid it again. Now 60
minutes (`X64DBG_MCP_UI_IDLE_MS`).

## UI flow

Measured on a 900x700 window with a warm daemon:

| Action | After | Before |
|---|---|---|
| `clicktext` (message mode) | **281 ms** | ~1430 ms |
| `findtext` (miss) | **188 ms** | ~3000 ms (daemon restart) |
| `ocr` full window | **188 ms** | 345 ms |
| `type` 8 chars | **124 ms** | 251 ms |
| `click` (message) | 72 ms | 67 ms |
| `realclick` | 204 ms | 196 ms |

What changed:

**A miss no longer kills the daemon.** `findtext`/`clicktext`/`typeinto` used
`exit 2` when OCR did not find the label. In one-shot mode that is an exit code;
inside the long-lived daemon it terminated the process, so every miss cost a
~3 s PowerShell restart. It now returns. This was the single biggest cost in
real UI flows - a first attempt frequently misses.

**Upscale is clamped, not fixed at 3x.** 3x of a 1600x900 window is 14.4M
pixels: slow to allocate and encode, and past the engine's
`MaxImageDimension` (10000 px) it is rejected outright. The factor is now
capped by that dimension and a 12M pixel budget, and reported back as
`Factor`. Small windows still get the full 3x that accuracy needs - lowering
it costs accuracy ("HIT" is misread at 1.9x).

**Matching tolerates OCR noise.** Comparison is case-insensitive and falls back
to an edit-distance match (1 for short needles, 2 otherwise), reported as
`fuzzy match, edit distance 1 from 'PASSWORD'`. A real OCR pass returned
`PÅSSWORD`; exact matching failed and burned a call.

**Input addresses the right child window.** Both the click and the following
`WM_CHAR` now go to the child resolved by `ChildWindowFromPointEx`. Before,
`typeinto` clicked the control (after the earlier fix) but typed into the
top-level window, so a standard `TextBox` stayed empty.

**`typeinto`'s x/y override works in serve mode.** It was guarded by
`$PSBoundParameters.ContainsKey('X')`, which is never true for the daemon's
calls - the override silently did nothing and every `typeinto` clicked its own
label.

**Fixed sleeps trimmed:** per-character typing 20 ms -> 8 ms, cursor settle
120 ms -> 60 ms, button down/up 60 ms -> 40 ms.

The floor is now the OCR pass itself (~190 ms at 3x). `region` cuts both the
cost and the misread rate, because the engine gets fewer, larger glyphs.

## Where the remaining cost is

- **Tool descriptions**: 4,856 B ≈ 1.3k tokens, dominated by `x64dbg_ui`
  (3.2 KB) and `x64dbg_tracing` (3.0 KB) enumerating every action. Trimming them
  is the next easy win if schema size matters.
- **26 tools** is a reasonable number; splitting them across several MCP servers
  would only add handshake overhead.
- **Long-running debugger operations** (run to a breakpoint, trace) dominate
  wall clock when they happen; nothing in the MCP can change that.
- **OCR** is the slowest UI path (~hundreds of ms, plus a 3x upscale). Use
  `region` to crop, and `input:"message"` to skip focus work.

Claude Code caches tool definitions, so the schema is mostly a context-window
cost rather than a per-request charge - but it still counts against the window.
