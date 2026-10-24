import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { config, getBaseUrl } from './config.js';

const SLEEP = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

function log(msg: string): void {
  // stdout carries the MCP protocol; all diagnostics go to stderr.
  console.error(`[x64dbg-mcp] ${msg}`);
}

/** True when the plugin answers /api/health with 200. */
async function pluginReady(timeoutMs = 2000): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(`${getBaseUrl()}/api/health`, {
      headers: config.token ? { Authorization: `Bearer ${config.token}` } : {},
      signal: controller.signal,
    });
    clearTimeout(timer);
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * Candidate x64dbg.exe locations, most specific first:
 *  1. X64DBG_PATH (env) or --x64dbg=... - may point at the exe or its folder
 *  2. Common install layouts
 *  3. A snapshot build next to a previously seen x64dbg.exe
 */
function candidatePaths(): string[] {
  const out: string[] = [];

  if (config.x64dbgPath) {
    const p = config.x64dbgPath;
    out.push(p, join(p, 'x64dbg.exe'), join(p, 'x64', 'x64dbg.exe'));
  }

  for (const root of ['C:\\x64dbg', 'D:\\x64dbg', 'F:\\x64dbg']) {
    out.push(join(root, 'x64dbg.exe'), join(root, 'x64', 'x64dbg.exe'));
  }

  return out.filter((p) => existsSync(p));
}

/** Ask a running x64dbg for its own path. */
async function runningX64dbgPath(): Promise<string | null> {
  try {
    const ps = spawn('powershell', [
      '-NoProfile', '-NonInteractive', '-Command',
      "(Get-Process x64dbg -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Path)",
    ], { stdio: ['ignore', 'pipe', 'ignore'] });

    const chunks: Buffer[] = [];
    ps.stdout?.on('data', (c: Buffer) => chunks.push(c));
    const code = await new Promise<number>((resolve) => ps.on('close', resolve));

    if (code !== 0) return null;
    const p = Buffer.concat(chunks).toString('utf8').trim();
    return p && existsSync(p) ? p : null;
  } catch {
    return null;
  }
}

/**
 * Ensure x64dbg (and therefore the MCP plugin) is up.
 *
 * Returns immediately when the plugin already answers. Otherwise launches
 * x64dbg detached and polls until the plugin comes online, so the MCP client
 * can start before the debugger does - which is the normal case when the MCP
 * server is spawned by the editor at startup.
 */
export async function ensureX64dbg(timeoutMs = 60_000): Promise<{ launched: boolean; ok: boolean }> {
  if (await pluginReady()) {
    log(`plugin already running at ${getBaseUrl()}`);
    return { launched: false, ok: true };
  }

  // x64dbg is already up but its plugin is not answering (server stopped,
  // plugin not loaded, wrong port, wrong token). Starting a second instance
  // would just open another GUI window and still not answer on this port, so
  // wait for the existing one instead.
  const running = await runningX64dbgPath();
  if (running) {
    log(`x64dbg is running (${running}) but the plugin is not answering at ${getBaseUrl()}; ` +
        'waiting instead of starting a second instance');
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      await SLEEP(1000);
      if (await pluginReady()) {
        log('plugin is online');
        return { launched: false, ok: true };
      }
    }
    log('plugin did not come online. Check Plugins > x64dbg MCP Server > Start Server, ' +
        'the configured port, and X64DBG_MCP_TOKEN.');
    return { launched: false, ok: false };
  }

  const candidates = candidatePaths();
  if (candidates.length === 0) {
    log('x64dbg.exe not found. Set X64DBG_PATH or pass --x64dbg=<path to x64dbg.exe>.');
    return { launched: false, ok: false };
  }
  const exe = candidates[0];

  log(`starting ${exe}`);
  try {
    const child = spawn(exe, [], {
      cwd: dirname(exe),
      detached: true,
      stdio: 'ignore',
    });
    child.unref();
  } catch (err) {
    log(`failed to start x64dbg: ${err instanceof Error ? err.message : String(err)}`);
    return { launched: false, ok: false };
  }

  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await SLEEP(500);
    if (await pluginReady()) {
      log('plugin is online');
      return { launched: true, ok: true };
    }
  }

  log(`x64dbg did not expose the plugin within ${timeoutMs / 1000}s`);
  return { launched: true, ok: false };
}
