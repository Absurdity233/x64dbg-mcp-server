import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { uiDaemon } from '../ui_daemon.js';
import { requireString } from './util.js';

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

export function registerUiTools(server: McpServer) {
  server.tool(
    'x64dbg_ui',
    'Interact with the debuggee\'s window - the half x64dbg cannot do. Actions: windows (list top-level windows), info (geometry), screenshot (PNG to file, then read it), ocr (recognise on-screen text with positions), findtext (locate a string, return its client coordinates), clicktext (OCR + realclick on the match - no hardcoded coordinates), typeinto (OCR + click + type), click (posted message, does not move the mouse), realclick (SendInput, needed by custom-drawn UIs), type (WM_CHAR into the focused control), key (single virtual key).',
    {
      action: z.enum([
        'windows', 'info', 'screenshot', 'ocr', 'findtext', 'clicktext', 'typeinto',
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
    },
    async (args) => {
      let hwnd = args.hwnd;
      if (!hwnd) {
        let pid: number | null = null;
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

      let res;
      try {
        res = await uiDaemon.run(req);
      } catch (err) {
        // A dead handle is the usual cause of a hard failure here - drop the
        // cache entry so the next call re-resolves it.
        windowCache.clear();
        throw err;
      }
      const payload = { hwnd, action: args.action, ok: res.ok, output: res.output || res.error };

      // findtext/clicktext/typeinto report a miss as a plain "NOTFOUND" line;
      // surface it as an error so the caller does not treat it as success.
      if (!res.ok || /^NOTFOUND\b/m.test(res.output)) {
        return { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }], isError: true };
      }
      return { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }] };
    }
  );
}
