import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { currentInstance } from '../context.js';
import { uiDaemon } from '../ui_daemon.js';
import { withUiLock } from '../ui_lock.js';
import { requireString } from './util.js';

/**
 * Actions that can synthesise real mouse/keyboard input. They need the
 * foreground window and a global cursor, so in the default `input: "real"` mode
 * they are serialised machine-wide.
 *
 * `input: "message"` switches clicktext/typeinto/type/key to PostMessage, which
 * targets the window's own thread: no focus change, no cursor movement, and
 * therefore no machine-wide lock - several targets can be driven at once.
 * `click` is always PostMessage and never takes the lock.
 */
const REAL_INPUT_ACTIONS = new Set(['realclick', 'clicktext', 'typeinto', 'type', 'key']);

/** Every action that injects input (and is therefore blocked by UIPI). */
const INPUT_ACTIONS = new Set(['click', 'realclick', 'clicktext', 'typeinto', 'type', 'key']);

/** Actions that read the target's pixels/text, which also cross integrity. */
const WINDOW_ACTIONS = new Set([...INPUT_ACTIONS, 'screenshot', 'ocr', 'findtext']);

/**
 * Actions that need PrintWindow/OCR. A paused Direct2D target can block
 * PrintWindow indefinitely, so these are refused while the debugger is paused
 * unless the caller explicitly passes force:true.
 */
const PAUSED_UNSAFE_ACTIONS = new Set(['screenshot', 'ocr', 'findtext', 'clicktext', 'typeinto']);

/** Cache of pid -> window handle, so a UI flow does not re-enumerate windows. */
const windowCache = new Map<number, { hwnd: number; at: number }>();
// A window handle is stable for the life of a debug session. Resolve it through
// the daemon (a few ms) rather than a fresh powershell.exe (~3s).
const WINDOW_CACHE_MS = 10 * 60 * 1000;

async function findMainWindow(pid: number): Promise<number | null> {
  const cached = windowCache.get(pid);
  if (cached && Date.now() - cached.at < WINDOW_CACHE_MS) return cached.hwnd;

  const res = await uiDaemon.run({ action: 'findwindow', pid } as any);
  if (!res.ok) return null;

  const text = (res.output || '').trim();
  const lastLine = text.substring(text.lastIndexOf(String.fromCharCode(10)) + 1).trim();
  const hwnd = parseInt(lastLine, 10);
  if (!Number.isFinite(hwnd) || hwnd <= 0) return null;

  windowCache.set(pid, { hwnd, at: Date.now() });
  return hwnd;
}

/**
 * Integrity levels of the target process and of the UI daemon.
 *
 * Windows UIPI silently drops synthesized input and PrintWindow calls from a
 * medium-integrity process to a high-integrity window, so a click on an
 * elevated target "succeeds" while doing nothing. Ask the daemon before
 * touching the window so this becomes an explicit error instead.
 */
async function probeElevation(
  pid: number | null,
  hwnd: number | undefined
): Promise<{ target: boolean; daemon: boolean } | null> {
  const req: any = { action: 'elevation' };
  if (pid) req.pid = pid;
  if (hwnd) req.hwnd = hwnd;

  const res = await uiDaemon.run(req);
  if (!res.ok) return null;
  const m = /target_elevated=(true|false)[\s\S]*?daemon_elevated=(true|false)/.exec(res.output);
  if (!m) return null;
  return { target: m[1] === 'true', daemon: m[2] === 'true' };
}

export function registerUiTools(server: McpServer) {
  server.tool(
    'x64dbg_ui',
    'Interact with the debuggee\'s window. Actions: windows, info, activity (diagnostics), screenshot/ocr/findtext (capture; pause-guarded), clicktext/typeinto/click/realclick/type/key (input; UIPI-guarded). Prefer input:"message"; use "real" only for raw-input UIs. Details: docs/REFERENCE.md.',
    {
      action: z.enum([
        'windows', 'info', 'activity', 'screenshot', 'ocr', 'findtext', 'clicktext', 'typeinto',
        'click', 'realclick', 'type', 'key',
      ]).describe('Operation to perform'),
      hwnd: z.number().optional().describe('Window handle; omit to use the debuggee\'s largest visible window'),
      x: z.number().optional().describe('click/realclick: client X; key: virtual key code; typeinto: override click X'),
      y: z.number().optional().describe('click/realclick: client Y; typeinto: override click Y'),
      text: z.string().optional().describe('type/typeinto: text to send as WM_CHAR'),
      match: z.string().optional().describe('findtext/clicktext/typeinto: text to locate on screen (OCR)'),
      regex: z.boolean().optional().describe('match: treat the string as a regular expression'),
      lang: z.string().optional().describe('OCR language tag, e.g. zh-Hans-CN or en-US (default: user profile)'),
      scale: z.number().optional().describe('OCR upscale percentage (default 300; small text needs more)'),
      region: z.string().optional().describe("OCR: crop to 'x,y,w,h' in client coordinates before recognising - use for small or busy areas"),
      wait_stable_ms: z.number().optional().describe('OCR: poll until the window stops changing, sampling every N ms (e.g. 200). Avoids reading a half-drawn frame.'),
      stable_timeout_ms: z.number().optional().describe('OCR: give up waiting for a stable frame after this long (default 8000)'),
      file: z.string().optional().describe('screenshot: output PNG path; ocr: save what OCR saw'),
      timeout_ms: z.number().optional().describe('screenshot/ocr: give up after this long (default 15000) - a paused Direct2D window can block PrintWindow'),
      lock_timeout_ms: z.number().optional().describe('input actions: how long to queue behind another model driving a different target (default 30000). Real input is machine-global and serialised.'),
      guard: z.enum(['abort', 'wait', 'off']).optional().describe(
        'input actions: what to do when a human is using the machine (last input < guard_ms, or cursor moving). ' +
        '"abort" (default) refuses and reports the idle time; "wait" queues until quiet (up to guard_wait_ms); ' +
        '"off" forces the action. Use activity to inspect the current state.'
      ),
      guard_ms: z.number().optional().describe('input actions: idle time (ms) below which the machine counts as in use (default 600)'),
      guard_wait_ms: z.number().optional().describe('guard:"wait": how long to queue before giving up (default 3000)'),
      input: z.enum(['real', 'message']).optional().describe(
        'clicktext/typeinto/type/key: "real" (default) uses SetCursorPos+SendInput and steals the foreground window, ' +
        'so it is serialised across all instances. "message" posts WM_* straight to the target window: no focus, ' +
        'no global cursor, and several targets can be driven in parallel. Use "message" first; fall back to ' +
        '"real" only if the app ignores posted messages (raw input / GetAsyncKeyState).'
      ),
      force: z.boolean().optional().describe(
        'screenshot/ocr/findtext/clicktext/typeinto: proceed even when the debugger is paused. ' +
        'Without it these are refused because PrintWindow/OCR on a paused Direct2D window can hang.'
      ),
    },
    async (args) => {
      let hwnd = args.hwnd;
      let pid: number | null = null;
      // activity is a machine-level diagnostic; it must work without a session.
      if (!hwnd && args.action !== 'activity') {
        try {
          const info = await httpClient.get<any>('/api/process/info');
          pid = info?.pid ?? null;
        } catch {
          pid = null;
        }
        if (!pid) throw new Error('No active debug session - load a target first, or pass hwnd explicitly');
        hwnd = (await findMainWindow(pid)) ?? undefined;
        if (!hwnd) throw new Error(`No visible window found for pid ${pid}`);
      }

      // The script calls the screenshot action "shot"; keep the MCP-facing
      // name descriptive and translate here.
      const scriptAction = args.action === 'screenshot' ? 'shot' : args.action;
      const req: any = { action: scriptAction, hwnd };
      if (args.x !== undefined) req.x = args.x;
      if (args.y !== undefined) req.y = args.y;
      if (args.text !== undefined) req.text = args.text;
      if (args.match !== undefined) req.match = args.match;
      if (args.file !== undefined) req.file = args.file;
      if (args.lang) req.lang = args.lang;
      if (args.scale !== undefined) req.scale = args.scale;
      if (args.region) req.region = args.region;
      if (args.wait_stable_ms) req.wait_stable_ms = args.wait_stable_ms;
      if (args.stable_timeout_ms) req.stable_timeout_ms = args.stable_timeout_ms;
      if (args.regex) req.regex = true;
      if (args.input) req.input = args.input;
      if (args.guard) req.guard = args.guard;
      if (args.guard_ms !== undefined) req.guard_ms = args.guard_ms;
      if (args.guard_wait_ms !== undefined) req.guard_wait_ms = args.guard_wait_ms;

      // Required-argument checks up front so the daemon is not woken for a
      // request that can only fail.
      if (args.action === 'screenshot') requireString(args.file, 'file');
      if (args.action === 'click' || args.action === 'realclick') {
        if (args.x === undefined) throw new Error("'x' is required for this action");
        if (args.y === undefined) throw new Error("'y' is required for this action");
      }
      if (args.action === 'key' && args.x === undefined) throw new Error("'x' is required for this action");
      if (args.action === 'type' || args.action === 'typeinto') requireString(args.text, 'text');
      if (args.action === 'findtext' || args.action === 'clicktext' || args.action === 'typeinto') {
        requireString(args.match, 'match');
      }

      // A paused Direct2D window can block PrintWindow until the timeout (or
      // forever, depending on the driver). Refuse capture/OCR up front and tell
      // the caller to resume; force:true is the explicit escape hatch for modal
      // dialogs that really must be read/clicked while the target is paused.
      if (!args.force && PAUSED_UNSAFE_ACTIONS.has(args.action)) {
        try {
          const st = await httpClient.get<any>('/api/debug/state');
          if (st?.state === 'paused') {
            return {
              isError: true,
              content: [{
                type: 'text',
                text: JSON.stringify({
                  hwnd,
                  action: args.action,
                  instance: currentInstance().id,
                  ok: false,
                  error: 'debugger-paused',
                  state: st.state,
                  message:
                    'The debugger is paused; PrintWindow/OCR can block on a paused Direct2D window. ' +
                    'Resume first (x64dbg_debug action=run), or pass force:true if the window must be ' +
                    'captured/clicked while paused (e.g. a modal dialog).',
                }, null, 2),
              }],
            };
          }
        } catch {
          // No session or plugin down: the action itself will report it.
        }
      }

      // Fail before the silent nothing: an elevated window ignores input from
      // the medium-integrity daemon, and PrintWindow tends to come back black.
      let integrityWarning: string | undefined;
      if (hwnd && WINDOW_ACTIONS.has(args.action)) {
        const elev = await probeElevation(pid, hwnd);
        if (elev && elev.target && !elev.daemon) {
          const message =
            'The target window belongs to an elevated (high-integrity) process, but the UI daemon runs ' +
            'at medium integrity. Windows UIPI blocks SendInput/PostMessage and PrintWindow across that ' +
            'boundary, so this action would silently do nothing. Restart Claude Code as administrator ' +
            '(the MCP server and this daemon inherit that token), or observe the target through debugger ' +
            'memory instead.';
          if (INPUT_ACTIONS.has(args.action)) {
            return {
              isError: true,
              content: [{
                type: 'text',
                text: JSON.stringify({
                  hwnd,
                  action: args.action,
                  instance: currentInstance().id,
                  ok: false,
                  error: 'integrity-mismatch',
                  target_elevated: true,
                  daemon_elevated: false,
                  message,
                }, null, 2),
              }],
            };
          }
          integrityWarning = message;
        }
      }

      const runOnce = () => uiDaemon.run(req);
      // Message-mode input never touches the global cursor or the foreground
      // window, so it does not need the machine-wide lock.
      const needsGlobalLock = REAL_INPUT_ACTIONS.has(args.action) && args.input !== 'message';
      let res;
      try {
        res = needsGlobalLock
          ? await withUiLock(
              { instance: currentInstance().id, action: args.action, hwnd },
              args.lock_timeout_ms ?? 30_000,
              runOnce
            )
          : await runOnce();
      } catch (err) {
        // A dead handle is the usual cause of a hard failure here - drop the
        // cache entry so the next call re-resolves it.
        windowCache.clear();
        throw err;
      }
      const payload = {
        hwnd,
        action: args.action,
        instance: currentInstance().id,
        ok: res.ok,
        output: res.output || res.error,
        ...(integrityWarning ? { integrity_warning: integrityWarning } : {}),
      };

      // findtext/clicktext/typeinto report a miss as a plain "NOTFOUND" line;
      // surface it as an error so the caller does not treat it as success.
      if (!res.ok || /^NOTFOUND\b/m.test(res.output)) {
        return { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }], isError: true };
      }
      return { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }] };
    }
  );
}
