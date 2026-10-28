import { spawn, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from './config.js';
import type { InstanceEndpoint } from './instances.js';

const SLEEP = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

// server/dist/launcher.js -> server/scripts/process-info.ps1
const PROCESS_INFO_SCRIPT = join(
  dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'process-info.ps1'
);

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

/** The executable this instance would launch, or undefined if it is not installed. */
export function instanceExe(instance: InstanceEndpoint): string | undefined {
  return candidatePaths(instance)[0];
}

export interface X64dbgProcess {
  pid: number;
  path: string;
  /** TokenElevation; null when the token could not be queried. */
  elevated: boolean | null;
}

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

function runCommand(file: string, args: string[], timeoutMs: number): Promise<RunResult> {
  return new Promise((resolvePromise) => {
    let child: ChildProcess;
    try {
      child = spawn(file, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    } catch (err) {
      resolvePromise({ code: -1, stdout: '', stderr: err instanceof Error ? err.message : String(err) });
      return;
    }

    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let settled = false;
    const finish = (code: number) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolvePromise({
        code,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8'),
      });
    };

    child.stdout?.on('data', (c: Buffer) => out.push(c));
    child.stderr?.on('data', (c: Buffer) => err.push(c));
    child.on('error', (e) => finish(-1));
    child.on('close', (code) => finish(typeof code === 'number' ? code : -1));
    const timer = setTimeout(() => {
      try { child.kill(); } catch { /* already gone */ }
      finish(-2);
    }, timeoutMs);
    timer.unref?.();
  });
}

function samePath(a: string, b: string): boolean {
  try {
    return resolve(a).toLowerCase() === resolve(b).toLowerCase();
  } catch {
    return a.toLowerCase() === b.toLowerCase();
  }
}

let processCache: { at: number; list: X64dbgProcess[] } | null = null;

/**
 * Every running x64dbg.exe with its path and elevation.
 *
 * Get-CimInstance/Win32_Process returns an empty ExecutablePath for an elevated
 * process when the caller is not elevated, which used to make the launcher
 * believe no x64dbg was running and start a second window. The helper script
 * uses QueryFullProcessImageName(PROCESS_QUERY_LIMITED_INFORMATION) instead.
 */
export async function listX64dbgProcesses(force = false): Promise<X64dbgProcess[]> {
  if (!force && processCache && Date.now() - processCache.at < 5_000) {
    return processCache.list;
  }

  const res = await runCommand(
    'powershell',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', PROCESS_INFO_SCRIPT],
    20_000
  );

  const list: X64dbgProcess[] = [];
  if (res.code === 0) {
    for (const raw of res.stdout.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line) continue;
      const [pidRaw, path, elevatedRaw] = line.split('|');
      const pid = parseInt(pidRaw, 10);
      if (!Number.isInteger(pid) || pid <= 0 || !path) continue;
      list.push({
        pid,
        path,
        elevated: elevatedRaw === 'true' ? true : elevatedRaw === 'false' ? false : null,
      });
    }
  } else {
    log(`process-info.ps1 failed (code ${res.code}): ${(res.stderr || res.stdout).trim().slice(0, 300)}`);
  }

  processCache = { at: Date.now(), list };
  return list;
}

/** The running x64dbg that belongs to this instance, or null. */
export async function findInstanceProcess(
  instance: InstanceEndpoint,
  force = false
): Promise<X64dbgProcess | null> {
  const exe = instanceExe(instance);
  const running = await listX64dbgProcesses(force);
  if (!exe) return running[0] ?? null;
  return running.find((p) => samePath(p.path, exe)) ?? null;
}

// ---------------------------------------------------------------------------
// Cross-process launch lock
//
// Two MCP server processes starting at the same time both saw "plugin not
// answering, x64dbg not running" and both spawned the same exe. The second
// window cannot bind the same plugin port and just sits there, which looks
// exactly like the debugger "fighting itself".
// ---------------------------------------------------------------------------

const LAUNCH_LOCK_DIR = join(tmpdir(), 'x64dbg-mcp', 'launch');
const LAUNCH_LOCK_TTL_MS = 90_000;

interface LaunchLock { pid: number; at: number }

function launchLockPath(exe: string): string {
  const hash = createHash('sha1').update(resolve(exe).toLowerCase()).digest('hex').slice(0, 16);
  return join(LAUNCH_LOCK_DIR, `${hash}.lock`);
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException)?.code === 'EPERM';
  }
}

function writeLaunchLock(path: string): boolean {
  try {
    const fd = openSync(path, 'wx');
    try {
      writeSync(fd, JSON.stringify({ pid: process.pid, at: Date.now() } satisfies LaunchLock));
    } finally {
      closeSync(fd);
    }
    return true;
  } catch {
    return false;
  }
}

function acquireLaunchLock(exe: string): boolean {
  try {
    mkdirSync(LAUNCH_LOCK_DIR, { recursive: true });
  } catch {
    // Cannot create the lock directory: do not block a legitimate launch.
    return true;
  }

  const path = launchLockPath(exe);
  if (writeLaunchLock(path)) return true;

  let info: LaunchLock | null = null;
  try {
    info = JSON.parse(readFileSync(path, 'utf8')) as LaunchLock;
  } catch {
    info = null;
  }
  const stale = !info || !pidAlive(info.pid) || Date.now() - info.at > LAUNCH_LOCK_TTL_MS;
  if (!stale) return false;

  try { unlinkSync(path); } catch { /* raced with the other owner */ }
  return writeLaunchLock(path);
}

function releaseLaunchLock(exe: string): void {
  const path = launchLockPath(exe);
  try {
    const info = JSON.parse(readFileSync(path, 'utf8')) as LaunchLock;
    if (info.pid === process.pid) unlinkSync(path);
  } catch {
    // Not ours, already gone, or never created.
  }
}

// ---------------------------------------------------------------------------
// Launch
// ---------------------------------------------------------------------------

export type LaunchReason =
  | 'already-running'
  | 'running-unelevated'
  | 'exe-not-found'
  | 'launch-lock'
  | 'spawn-failed'
  | 'uac-cancelled'
  | 'uac-failed'
  | 'elevated-task-failed'
  | 'plugin-timeout';

export interface LaunchResult {
  launched: boolean;
  ok: boolean;
  reason?: LaunchReason;
  pid?: number;
  elevated?: boolean | null;
  detail?: string;
}

export interface EnsureOptions {
  timeoutMs?: number;
  /** Start x64dbg with an elevated token. Ignored when it is already running. */
  elevated?: boolean;
}

function normalizeOptions(
  instance: InstanceEndpoint,
  opts?: number | EnsureOptions
): { timeoutMs: number; elevated: boolean } {
  if (typeof opts === 'number') {
    return { timeoutMs: opts, elevated: instance.elevated ?? false };
  }
  return {
    timeoutMs: opts?.timeoutMs ?? 60_000,
    elevated: opts?.elevated ?? instance.elevated ?? false,
  };
}

async function waitForPlugin(
  instance: InstanceEndpoint,
  timeoutMs: number,
  base: Omit<LaunchResult, 'ok'>
): Promise<LaunchResult> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await SLEEP(500);
    if (await pluginReady(instance)) {
      log(`${instance.id}: plugin is online`);
      return { ...base, ok: true, reason: undefined };
    }
  }

  log(`${instance.id}: plugin did not answer on ${baseUrl(instance)} within ` +
      `${Math.round(timeoutMs / 1000)}s. Check Plugins > x64dbg MCP Server > Start Server, ` +
      'the configured port, and the auth token.');
  return { ...base, ok: false, reason: 'plugin-timeout' };
}

interface SpawnResult {
  ok: boolean;
  reason?: LaunchReason;
  detail?: string;
}

function spawnDetached(exe: string): Promise<SpawnResult> {
  return new Promise((resolvePromise) => {
    try {
      const child = spawn(exe, [], { cwd: dirname(exe), detached: true, stdio: 'ignore' });
      let settled = false;
      const finish = (ok: boolean, detail?: string) => {
        if (settled) return;
        settled = true;
        resolvePromise({ ok, detail });
      };
      child.on('spawn', () => {
        child.unref();
        finish(true);
      });
      child.on('error', (err) => finish(false, err.message));
      // 'spawn' normally arrives immediately; guard against a silent hang.
      setTimeout(() => finish(false, 'spawn event did not fire'), 5_000).unref?.();
    } catch (err) {
      resolvePromise({ ok: false, detail: err instanceof Error ? err.message : String(err) });
    }
  });
}

/** PowerShell single-quoted literal. */
function psQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

async function spawnElevated(
  exe: string,
  instance: InstanceEndpoint
): Promise<SpawnResult> {
  const task = instance.elevatedTask || config.elevatedTask;
  if (task) {
    const res = await runCommand('schtasks', ['/run', '/tn', task], 20_000);
    if (res.code !== 0) {
      return {
        ok: false,
        reason: 'elevated-task-failed',
        detail: `schtasks /run /tn "${task}" failed: ${(res.stderr || res.stdout).trim()}`,
      };
    }
    log(`${instance.id}: started elevated task "${task}"`);
    return { ok: true };
  }

  const script = [
    "$ErrorActionPreference = 'Stop'",
    'try {',
    `  $p = Start-Process -FilePath ${psQuote(exe)} -WorkingDirectory ${psQuote(dirname(exe))} -Verb RunAs -PassThru`,
    "  if (-not $p) { throw 'Start-Process returned no process' }",
    '  $p.Id',
    '} catch {',
    '  [Console]::Error.WriteLine($_.Exception.Message)',
    '  exit 1',
    '}',
  ].join('\n');

  // UAC is interactive: the budget is for the user to answer, not for x64dbg
  // to boot. The actual startup wait happens below in waitForPlugin.
  const res = await runCommand(
    'powershell',
    ['-NoProfile', '-NonInteractive', '-Command', script],
    Math.max(30_000, config.uacTimeoutMs)
  );

  if (res.code !== 0) {
    const msg = (res.stderr || res.stdout).trim();
    const cancelled = /cancel|1223|取消|拒绝/i.test(msg);
    return {
      ok: false,
      reason: cancelled ? 'uac-cancelled' : 'uac-failed',
      detail: msg || `powershell exited with code ${res.code}`,
    };
  }
  return { ok: true, detail: res.stdout.trim() };
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
 * check therefore matches on this instance's executable path.
 *
 * `elevated: true` refuses to wait on an existing medium-integrity process
 * (Windows cannot raise an existing process) and starts a new one through UAC
 * or, when configured, a highest-privilege scheduled task.
 */
export async function ensureX64dbg(
  instance: InstanceEndpoint,
  opts: number | EnsureOptions = 60_000
): Promise<LaunchResult> {
  const { timeoutMs, elevated } = normalizeOptions(instance, opts);
  const exe = instanceExe(instance);

  let running: X64dbgProcess[] | null = null;
  if (elevated) {
    running = await listX64dbgProcesses(true);
    const ours = exe ? running.find((p) => samePath(p.path, exe)) : running[0];
    if (ours && ours.elevated === false) {
      log(`${instance.id}: x64dbg pid ${ours.pid} is running without elevation; ` +
          'an existing process cannot be raised. Close it and start again, or launch it elevated yourself.');
      return {
        launched: false,
        ok: false,
        reason: 'running-unelevated',
        pid: ours.pid,
        elevated: false,
      };
    }
  }

  if (await pluginReady(instance)) {
    log(`plugin already running at ${baseUrl(instance)} (${instance.id})`);
    return { launched: false, ok: true, reason: 'already-running' };
  }

  if (!running) running = await listX64dbgProcesses(true);
  const ours = exe ? running.find((p) => samePath(p.path, exe)) : running[0];

  // Our x64dbg is up but its plugin is not answering (server stopped, plugin
  // not loaded, wrong port, wrong token). Starting a second instance would
  // just open another GUI window and still not answer on this port, so wait.
  if (ours) {
    log(`${instance.id}: x64dbg pid ${ours.pid} is running ` +
        `(${ours.elevated === null ? 'elevation unknown' : ours.elevated ? 'elevated' : 'not elevated'}); ` +
        `waiting for the plugin at ${baseUrl(instance)} instead of starting a second instance`);
    return waitForPlugin(instance, timeoutMs, {
      launched: false,
      pid: ours.pid,
      elevated: ours.elevated,
    });
  }

  if (!exe) {
    log(`${instance.id}: x64dbg.exe not found. Set x64dbgPath for the instance ` +
        'in X64DBG_MCP_INSTANCES, or X64DBG_PATH, or pass --x64dbg=<path>.');
    return { launched: false, ok: false, reason: 'exe-not-found' };
  }

  if (!acquireLaunchLock(exe)) {
    log(`${instance.id}: another MCP process is already starting ${exe}; waiting for its plugin ` +
        'instead of opening a second window');
    return waitForPlugin(instance, timeoutMs, { launched: false, reason: 'launch-lock' });
  }

  try {
    log(`${instance.id}: starting ${exe}${elevated ? ' (elevated)' : ''}`);
    const spawned = elevated ? await spawnElevated(exe, instance) : await spawnDetached(exe);
    if (!spawned.ok) {
      log(`${instance.id}: failed to start x64dbg: ${spawned.detail ?? spawned.reason ?? 'unknown error'}`);
      return {
        launched: false,
        ok: false,
        reason: spawned.reason ?? 'spawn-failed',
        detail: spawned.detail,
      };
    }
    return await waitForPlugin(instance, timeoutMs, {
      launched: true,
      elevated: elevated ? true : undefined,
    });
  } finally {
    releaseLaunchLock(exe);
  }
}
