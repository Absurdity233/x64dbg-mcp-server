import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { config } from './config.js';
import type { InstanceEndpoint } from './instances.js';

const SLEEP = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

function log(msg: string): void {
  // stdout carries the MCP protocol; all diagnostics go to stderr.
  console.error(`[x64dbg-mcp] ${msg}`);
}

function baseUrl(instance: InstanceEndpoint): string {
  return `http://${instance.host}:${instance.port}`;
}

/** True when this instance's plugin answers /api/health with 200. */
async function pluginReady(instance: InstanceEndpoint, timeoutMs = 2000): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(`${baseUrl(instance)}/api/health`, {
      headers: instance.token ? { Authorization: `Bearer ${instance.token}` } : {},
      signal: controller.signal,
    });
    clearTimeout(timer);
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * Candidate x64dbg.exe locations for one instance, most specific first:
 *  1. the instance's own x64dbgPath (registry / --x64dbg=...)
 *  2. X64DBG_PATH (legacy single-instance env)
 *  3. common install layouts
 */
function candidatePaths(instance: InstanceEndpoint): string[] {
  const out: string[] = [];

  for (const raw of [instance.x64dbgPath, config.x64dbgPath]) {
    if (!raw) continue;
    out.push(raw, join(raw, 'x64dbg.exe'), join(raw, 'x64', 'x64dbg.exe'));
  }

  for (const root of ['C:\\x64dbg', 'D:\\x64dbg', 'F:\\x64dbg']) {
    out.push(join(root, 'x64dbg.exe'), join(root, 'x64', 'x64dbg.exe'));
  }

  return out.filter((p) => existsSync(p));
}

/** Every running x64dbg.exe path (there can be several now). */
async function runningX64dbgPaths(): Promise<string[]> {
  try {
    const ps = spawn('powershell', [
      '-NoProfile', '-NonInteractive', '-Command',
      "(Get-CimInstance Win32_Process -Filter \"name='x64dbg.exe'\" | " +
      'Select-Object -ExpandProperty ExecutablePath) -join \"`n\"',
    ], { stdio: ['ignore', 'pipe', 'ignore'] });

    const chunks: Buffer[] = [];
    ps.stdout?.on('data', (c: Buffer) => chunks.push(c));
    const code = await new Promise<number>((resolve) => ps.on('close', resolve));

    if (code !== 0) return [];
    return Buffer.concat(chunks)
      .toString('utf8')
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter((s) => s && existsSync(s));
  } catch {
    return [];
  }
}

function samePath(a: string, b: string): boolean {
  try {
    return resolve(a).toLowerCase() === resolve(b).toLowerCase();
  } catch {
    return a.toLowerCase() === b.toLowerCase();
  }
}

/**
 * Ensure this instance's x64dbg (and therefore the MCP plugin) is up.
 *
 * Returns immediately when the plugin already answers. Otherwise launches
 * x64dbg detached and polls until the plugin comes online, so the MCP client
 * can start before the debugger does - which is the normal case when the MCP
 * server is spawned by the editor at startup.
 *
 * With several instances configured, "x64dbg is already running" is no longer
 * a reason to wait: the running one may belong to a different instance. The
 * check therefore matches on this instance's executable path when one is known.
 */
export async function ensureX64dbg(
  instance: InstanceEndpoint,
  timeoutMs = 60_000
): Promise<{ launched: boolean; ok: boolean }> {
  if (await pluginReady(instance)) {
    log(`plugin already running at ${baseUrl(instance)} (${instance.id})`);
    return { launched: false, ok: true };
  }

  const candidates = candidatePaths(instance);
  const exe = candidates[0];
  const running = await runningX64dbgPaths();
  const oursAlreadyRunning = exe
    ? running.some((p) => samePath(p, exe))
    : running.length > 0;

  // Our x64dbg is up but its plugin is not answering (server stopped, plugin
  // not loaded, wrong port, wrong token). Starting a second instance would
  // just open another GUI window and still not answer on this port, so wait.
  if (oursAlreadyRunning) {
    log(`${instance.id}: x64dbg is running but the plugin is not answering at ` +
        `${baseUrl(instance)}; waiting instead of starting a second instance`);
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      await SLEEP(1000);
      if (await pluginReady(instance)) {
        log(`${instance.id}: plugin is online`);
        return { launched: false, ok: true };
      }
    }
    log(`${instance.id}: plugin did not come online. Check Plugins > x64dbg MCP Server > ` +
        'Start Server, the configured port, and the auth token.');
    return { launched: false, ok: false };
  }

  if (!exe) {
    log(`${instance.id}: x64dbg.exe not found. Set x64dbgPath for the instance ` +
        'in X64DBG_MCP_INSTANCES, or X64DBG_PATH, or pass --x64dbg=<path>.');
    return { launched: false, ok: false };
  }

  log(`${instance.id}: starting ${exe}`);
  try {
    const child = spawn(exe, [], {
      cwd: dirname(exe),
      detached: true,
      stdio: 'ignore',
    });
    child.unref();
  } catch (err) {
    log(`${instance.id}: failed to start x64dbg: ${err instanceof Error ? err.message : String(err)}`);
    return { launched: false, ok: false };
  }

  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await SLEEP(500);
    if (await pluginReady(instance)) {
      log(`${instance.id}: plugin is online`);
      return { launched: true, ok: true };
    }
  }

  log(`${instance.id}: x64dbg did not expose the plugin within ${timeoutMs / 1000}s`);
  return { launched: true, ok: false };
}
