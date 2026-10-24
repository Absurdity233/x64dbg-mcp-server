import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'scripts', 'ui.ps1');

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

function runPowerShell(args: string[], timeoutMs: number): Promise<RunResult> {
  return new Promise((resolve) => {
    const child = spawn('powershell', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', ...args], {
      windowsHide: true,
    });

    let stdout = '';
    let stderr = '';
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, timeoutMs);

    child.stdout?.on('data', (d: Buffer) => { stdout += d.toString('utf8'); });
    child.stderr?.on('data', (d: Buffer) => { stderr += d.toString('utf8'); });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? -1, stdout: stdout.trim(), stderr: stderr.trim(), timedOut });
    });
    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({ code: -1, stdout, stderr: String(err), timedOut });
    });
  });
}

/**
 * Find the process's main window.
 *
 * Process.MainWindowHandle covers the normal case; the EnumWindows fallback
 * catches processes whose main window is not the one .NET picked (frameworks
 * that create several top-level windows). The delegate accumulates into
 * $global: because script-block scoping inside a delegate is unreliable.
 */
async function findMainWindow(pid: number): Promise<number | null> {
  const script = `
$h = (Get-Process -Id ${pid} -ErrorAction SilentlyContinue).MainWindowHandle
if ($h -and $h -ne 0) { Write-Output $h; exit 0 }
Add-Type -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, IntPtr pid);
[DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
[DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
public struct RECT { public int Left, Top, Right, Bottom; }
'@ -Name F -Namespace FindW
$global:bestHwnd = 0; $global:bestArea = 0
$cb = [FindW.F+EnumWindowsProc]{
  param($w, $l)
  $p = 0
  $null = [FindW.F]::GetWindowThreadProcessId($w, [ref]$p)
  if ($p -eq ${pid} -and [FindW.F]::IsWindowVisible($w)) {
    $r = New-Object FindW.F+RECT
    $null = [FindW.F]::GetWindowRect($w, [ref]$r)
    $area = ($r.Right - $r.Left) * ($r.Bottom - $r.Top)
    if ($area -gt $global:bestArea) { $global:bestArea = $area; $global:bestHwnd = $w.ToInt64() }
  }
  return $true
}
[FindW.F]::EnumWindows($cb, [IntPtr]::Zero) | Out-Null
Write-Output $global:bestHwnd
`;
  const res = await runPowerShell(['-Command', script], 15000);
  const hwnd = parseInt(res.stdout.trim().split(/\r?\n/).pop() ?? '0', 10);
  return Number.isFinite(hwnd) && hwnd > 0 ? hwnd : null;
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
      x: z.number().optional().describe('click/realclick: client X; key: virtual key code'),
      y: z.number().optional().describe('click/realclick: client Y'),
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
      // Resolve the window handle up front so every action works the same way.
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

      const captureActions = new Set(['screenshot', 'ocr', 'findtext', 'clicktext', 'typeinto']);

      if (args.action === 'screenshot') {
        const file = requireString(args.file, 'file');
        const res = await runPowerShell(
          ['-File', SCRIPT, '-Hwnd', String(hwnd), '-Action', 'shot', '-Out', file],
          args.timeout_ms ?? 15000
        );
        if (res.timedOut) {
          throw new Error(
            `Screenshot timed out after ${args.timeout_ms ?? 15000}ms. A paused Direct2D window ` +
            'cannot repaint - resume the target first, take the shot, then pause again.'
          );
        }
        return { content: [{ type: 'text', text: JSON.stringify({ hwnd, file, output: res.stdout || res.stderr }, null, 2) }] };
      }


      const cliArgs = ['-File', SCRIPT, '-Hwnd', String(hwnd), '-Action', args.action];
      if (args.action === 'click' || args.action === 'realclick' || args.action === 'key') {
        if (args.x === undefined) throw new Error("'x' is required for this action");
        cliArgs.push('-X', String(args.x));
      }
      if (args.action === 'click' || args.action === 'realclick') {
        if (args.y === undefined) throw new Error("'y' is required for this action");
        cliArgs.push('-Y', String(args.y));
      }
      if (args.action === 'typeinto') {
        // -X/-Y are optional here: they override the OCR-derived click point,
        // which is needed when the label opens a dialog but the edit box sits
        // somewhere else.
        if (args.x !== undefined) cliArgs.push('-X', String(args.x));
        if (args.y !== undefined) cliArgs.push('-Y', String(args.y));
      }
      if (args.action === 'type' || args.action === 'typeinto') {
        cliArgs.push('-Text', requireString(args.text, 'text'));
      }
      if (args.action === 'findtext' || args.action === 'clicktext' || args.action === 'typeinto') {
        cliArgs.push('-Match', requireString(args.match, 'match'));
      }
      if (args.regex) cliArgs.push('-Regex');
      if (args.lang) cliArgs.push('-Lang', args.lang);
      if (args.scale !== undefined) cliArgs.push('-Scale', String(args.scale));
      if (args.region) cliArgs.push('-Region', args.region);
      if (args.wait_stable_ms) cliArgs.push('-WaitStable', String(args.wait_stable_ms));
      if (args.stable_timeout_ms) cliArgs.push('-StableTimeout', String(args.stable_timeout_ms));
      if (args.file && args.action === 'ocr') cliArgs.push('-Out', args.file);

      // OCR actions capture + recognise, which is slower than a plain click.
      const timeout = captureActions.has(args.action)
        ? (args.timeout_ms ?? 30000)
        : 30000;

      const res = await runPowerShell(cliArgs, timeout);
      if (res.timedOut) {
        throw new Error(
          `${args.action} timed out after ${timeout}ms. A paused Direct2D window cannot repaint - ` +
          'resume the target first, then retry.'
        );
      }
      // exit 2 is ui.ps1's "text not found"; surface the available text rather
      // than throwing away the diagnostic.
      if (res.code === 2) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ hwnd, action: args.action, found: false, output: res.stdout }, null, 2),
          }],
          isError: true,
        };
      }
      if (res.code !== 0) {
        throw new Error(`ui.ps1 failed (${res.code}): ${res.stderr || res.stdout}`);
      }
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ hwnd, action: args.action, found: true, output: res.stdout }, null, 2),
        }],
      };
    }
  );
}
