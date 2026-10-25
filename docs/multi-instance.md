# Multiple x64dbg instances

One x64dbg window debugs one process, and the MCP plugin's port lives in the
`x64dbg.ini` next to `x64dbg.exe`. Running several models against several
binaries therefore means several x64dbg processes, each on its own port, and
the MCP server routing each tool call to the right one.

## 1. Provision the instances

```powershell
.\scripts\provision-instances.ps1 -Count 3 -BasePort 27042 `
    -Dest F:\reverse1\.tools\x64dbg-instances
```

Each instance gets its own copy of the release (minus `x32/`, ~58 MB) and a
unique `[MCP] Port`. **Ports are written in hex**: the plugin reads them through
`BridgeSetting`, which parses integers as hexadecimal. `27042` written as
decimal becomes `0x27042` and is rejected, so the plugin silently falls back to
the default port.

The script prints the JSON to paste into `.claude.json`.

Provisioning also writes `%USERPROFILE%\.x64dbg-mcp\instances.json`. The MCP
server reads that file automatically and **adds** those instances on top of the
default one, so the common case needs no configuration at all: run the script,
restart Claude Code, and the new instances appear. `X64DBG_MCP_INSTANCES`
overrides the file completely when set.

## 2. Configure the MCP server (optional)

```json
"x64dbg-bromoket": {
  "type": "stdio",
  "command": "node",
  "args": ["F:\\reverse1\\.tools\\x64dbg_mcp-src\\server\\dist\\index.js"],
  "env": {
    "X64DBG_MCP_TOKEN": "<token>",
    "X64DBG_MCP_INSTANCES": "[{\"id\":\"alpha\",\"port\":27042},{\"id\":\"beta\",\"port\":27043}]",
    "X64DBG_MCP_INSTANCE": "alpha"
  }
}
```

- `X64DBG_MCP_INSTANCES` — array or object of endpoints. Fields: `id`, `port`
  (required), `host` (default `127.0.0.1`), `token` (default
  `X64DBG_MCP_TOKEN`), `x64dbgPath` (used by the auto-launcher), `label`.
- `X64DBG_MCP_INSTANCE` — this server process's default instance.
- With `X64DBG_MCP_INSTANCES` unset, the old single-instance behaviour is
  unchanged: one instance called `default`, built from
  `X64DBG_MCP_HOST/PORT/TOKEN/X64DBG_PATH`.

Restart Claude Code after editing the config.

## 3. Use it

Every tool takes an optional `instance` argument:

```text
x64dbg_debug      { action: "load", path: "C:\\target.exe", instance: "beta" }
x64dbg_memory     { action: "read", address: "0x401000", size: "16", instance: "beta" }
x64dbg_instances  { action: "list" }
x64dbg_instances  { action: "use", id: "beta" }   // default for this server process
x64dbg_instances  { action: "status", id: "beta" }
```

An unknown id is a hard error listing the configured ids — it never falls back
to the default, because silently driving the wrong target is the failure this
exists to prevent.

Every response ends with `[state] ... [instance <id>]`, so the transcript shows
which debugger answered.

## Exclusive ownership

Routing alone does not stop two sessions from pointing at the same debugger.
Two models on one x64dbg corrupt each other silently: breakpoints collide, one
`run` clears the other's paused state, and both event streams mix. So an
instance is **leased** to one MCP server process at a time.

- A lease is a file (`%TEMP%\x64dbg-mcp\leases\ep_<host>_<port>.lease`) naming
  the owner pid, refreshed every 10s. Works across independent Claude Code
  sessions, which are separate processes.
- **Keyed by endpoint, not by instance id.** Two ids can name one debugger
  (a duplicate entry, or a copy provisioned onto the default's port); keyed by
  id they would hold two "different" leases over one x64dbg. `x64dbg_instances
  list` marks such ids with `shared_with`, and startup logs a warning.
- A stale lease (owner gone, or heartbeat older than 35s) is reclaimed.
- A call on a leased instance fails with the holder's pid and age:
  `Instance "inst2" is in use by pid 53520 on DESKTOP-..., holding it for 16s.`
- With several instances and no `X64DBG_MCP_INSTANCE`, the first call claims a
  free instance atomically, preferring one whose plugin is answering. Three
  sessions, two instances: the third gets the explicit error above rather than
  quietly sharing.
- `x64dbg_instances action=release id=<id>` gives it up; `list` shows
  `lease: "ours" | "free" | {pid, ...}`.
- `X64DBG_MCP_LEASE=off` disables enforcement.

## Shared target files are refused

Most Windows programs resolve `Config/`, `Logs/` and save files from the module
path, so two debuggers on the same exe overwrite each other. `load` records a
claim keyed by the **debuggee pid** (so it expires with the process) and refuses
a second instance loading the same path:

```text
"C:\...\xxoo.exe" is already being debugged by instance "inst2" (pid 25960).
Both runs would share Config/ and Logs/. Clone the folder with
scripts/provision-target.ps1 and load the copy, or set
X64DBG_MCP_ALLOW_SHARED_TARGET=1 if that is intended.
```

The claim is released on `stop_debug` and `detach`.

## What is isolated

Per instance (separate x64dbg process, so nothing is shared):

- debuggee, breakpoints, patches, memory, registers
- trace state and trace files
- plugin event ring (2048 events)

Per instance in the MCP server (keyed by instance id):

- HTTP client, connection/health monitor
- event cursor (`events.ts`)
- session recovery record, i.e. last target + breakpoints (`session.ts`)
- plugin compatibility result (`compat.ts`)

## Input: message mode vs real mode

Two ways to click and type, chosen per call with `input`:

| | `input: "message"` | `input: "real"` (default) |
|---|---|---|
| How | `PostMessage(WM_LBUTTONDOWN/UP, WM_CHAR, WM_KEYDOWN)` | `SetCursorPos` + `SendInput` |
| Foreground | not needed, never changes | must be stolen first |
| Parallel | **yes**, any number of targets | no, machine-wide lock |
| Works with | standard controls and message-driven custom UIs | also apps reading raw input / `GetAsyncKeyState` |

Message mode resolves the child window under the point with
`ChildWindowFromPointEx` (geometry only, so a background window works) and posts
there - posting to the top-level window alone does nothing for a standard
button. `click` is always message mode.

Use message mode first. Fall back to `input: "real"` only when the app ignores
posted messages; real mode is serialised across **all** MCP server processes
through `%TEMP%\x64dbg-mcp\ui.lock`, waiters queue for `lock_timeout_ms`
(default 30 s) and then get an error naming the holder.

Screenshot/OCR/windows/info are read-only and never take the lock.

### Coordinate calibration

Every click coordinate is derived, never guessed:

```
PrintWindow bitmap (physical px)
  -> Windows OCR word boxes (bitmap px)
  -> / upscale factor (default 3.0, `scale`)
  -> - image_offset (non-client border + title bar, from GetWindowRect vs ClientToScreen)
  -> + region_offset (when `region` cropped the image)
  = client coordinates
  -> real:    + client_origin -> SetCursorPos
  -> message: ChildWindowFromPointEx descent -> child-local coords -> PostMessage
```

`x64dbg_ui action=info` prints the two numbers everything depends on plus the
DPI state:

```
window=390,390 420x320 client=404x281 client_origin=398,421 image_offset=8,31
dpi=96 scale=100% awareness=2 (0=unaware 1=system 2=per-monitor, process=per-monitor-v2)
```

`awareness` is the one to look at. powershell.exe starts DPI-unaware, which
returns 96-DPI virtualised coordinates from `GetWindowRect`/`ClientToScreen`
while `PrintWindow` and `SetCursorPos` are physical. On 125%/150% scaling that
splits the pipeline in two: the screenshot is clipped to the virtualised size
and every click lands short by the scale factor. `ui.ps1` therefore sets
`SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2)` before the first window
call; `awareness` must read `2`. If it reads `0` on a scaled display, the
warning line says so.

Two failure modes are detected instead of silently producing bad coordinates:
a minimized window (nothing to render) and `PrintWindow` returning false
(cloaked window, or a desktop the compositor is not rendering).

Not calibrated, by nature: content that moves between the OCR pass and the
click (animations, scrolling) - use `wait_stable_ms` to settle first; and
windows that read raw input, where no message-based click can work.

### Human-activity guard

The UI lock serialises models; it cannot stop a person from using the machine
while a model clicks. Before every input action the daemon checks the system
idle time (`GetLastInputInfo`) and samples the cursor:

```text
human input detected (last input 16ms ago, cursor moving); refusing to click.
Retry when the machine is idle, or pass guard:'wait' to queue, guard:'off' to force.
```

- `guard: "abort"` (default) — refuse. `guard_ms` is the idle threshold (600 ms).
- `guard: "wait"` — queue until quiet, up to `guard_wait_ms` (3 s), then refuse.
- `guard: "off"` — force.

Our own `SendInput` bumps the same last-input tick, so the daemon records the
tick its click produced and treats it as its own; back-to-back model clicks do
not trip the guard. `PostMessage` (message mode) does not touch the system input
state at all, which is why message-mode sequences never self-trigger.

`x64dbg_ui action="activity"` reports the current state without touching
anything:

```text
idle_ms=241734 last_input_ours=False cursor=1980,948 cursor_moving=False
foreground=0x650EF4 foreground_is_target=False foreground_title='...' guard=abort/600ms
```

Note that `SetCursorPos` (used by the click path) does **not** update the
last-input tick, while `SendInput`/`mouse_event` does — so the tick reliably
means "somebody actually provided input", not "the cursor was repositioned".

Truly parallel *real* input is only possible with one Windows desktop per
target (`CreateDesktop` + the debugger and the UI daemon both attached to it).
That costs a separate window station per target and DWM does not composite
inactive desktops, so `PrintWindow` on a Direct2D window there tends to come
back black. Message mode is the cheaper answer for everything that accepts it.

## Target files: one copy per run

`Config/`, `Logs/` and save files are resolved from the module path, so two
instances debugging the same exe write to the same files and corrupt each
other. Changing the working directory does not help when the app uses its own
module path (the usual case), so the reliable answer is a copy:

```powershell
.\scripts\provision-target.ps1 -Source "<target folder>" -Name xxoo-a
.\scripts\provision-target.ps1 -Source "<target folder>" -Name xxoo-b
```

Then load `F:\reverse1\.tools\targets\xxoo-a\<exe>` on one instance and
`xxoo-b` on another. The copies are byte-identical, so integrity checks still
pass. `-HardLinkBig` saves space by hard-linking files >= 16 MB, but any file
the target writes to (self-patching exe, config) must stay a real copy.

## Hard limit: one debuggee per debugger

x64dbg has a single debug session per process. N simultaneous targets means N
x64dbg processes, each ~150-250 MB. What can be automated is the bookkeeping:
`provision-instances.ps1` creates and numbers them, `x64dbg_instances` shows
which one holds which pid, and the launcher starts a missing instance on demand.
Child-process debugging does not help here - x64dbg switches to the child and
detaches from the parent rather than debugging both.

## Independent sessions vs parallel subagents

- **Independent Claude Code sessions** each spawn their own MCP server process.
  Both see the same instance list; assign different defaults (via
  `x64dbg_instances action=use` at the start of the session) or pass `instance`
  on each call.
- **Parallel subagents in one session** share one MCP server process. They must
  pass `instance` explicitly; the value is resolved per call through
  AsyncLocalStorage, so concurrent calls cannot leak into each other.

## Verifying

```powershell
curl -H "Authorization: Bearer <token>" http://127.0.0.1:27042/api/health
curl -H "Authorization: Bearer <token>" http://127.0.0.1:27043/api/health
```

Then `x64dbg_instances action=list` should show both, with their pids and
current targets.
