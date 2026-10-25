import {
  closeSync,
  mkdirSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * Exclusive ownership of an x64dbg instance.
 *
 * The `instance` argument only says where a call should go; it does not stop
 * two models from pointing at the same debugger. Two agents on one x64dbg
 * silently corrupt each other: breakpoints collide, one agent's run clears the
 * other's paused state, both see each other's events. There is no way to
 * isolate that inside the debugger, so ownership is enforced here instead.
 *
 * The lease is a file, not an in-process lock: independent Claude Code sessions
 * are independent MCP server processes. A lease names the owner pid and is
 * refreshed every HEARTBEAT_MS; a lease whose owner is gone (same machine) or
 * whose heartbeat is older than STALE_MS is reclaimed.
 *
 * X64DBG_MCP_LEASE=off disables enforcement (the old advisory behaviour).
 */

const DIR = join(tmpdir(), 'x64dbg-mcp', 'leases');
const HEARTBEAT_MS = 10_000;
const STALE_MS = 35_000;

export interface LeaseInfo {
  instance: string;
  pid: number;
  host: string;
  started_at: number;
  heartbeat: number;
  token: string;
}

export type AcquireResult =
  | { ok: true; reclaimed: boolean }
  | { ok: false; holder: LeaseInfo | null };

const held = new Map<string, { info: LeaseInfo; timer: NodeJS.Timeout }>();

function safeName(instance: string): string {
  return instance.replace(/[^A-Za-z0-9._-]/g, '_');
}

function leasePath(instance: string): string {
  return join(DIR, `${safeName(instance)}.lease`);
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException)?.code === 'EPERM';
  }
}

function readLease(instance: string): LeaseInfo | null {
  try {
    return JSON.parse(readFileSync(leasePath(instance), 'utf8')) as LeaseInfo;
  } catch {
    return null;
  }
}

function isStale(info: LeaseInfo): boolean {
  // A lease from another machine cannot be pid-checked; age is all we have.
  const sameHost = info.host === hostname();
  if (sameHost && !pidAlive(info.pid)) return true;
  return Date.now() - info.heartbeat > STALE_MS;
}

function writeLease(info: LeaseInfo): boolean {
  try {
    mkdirSync(DIR, { recursive: true });
    const fd = openSync(leasePath(info.instance), 'wx');
    try {
      writeSync(fd, JSON.stringify(info));
    } finally {
      closeSync(fd);
    }
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException)?.code === 'EEXIST') return false;
    throw err;
  }
}

function startHeartbeat(info: LeaseInfo): NodeJS.Timeout {
  const timer = setInterval(() => {
    const current = readLease(info.instance);
    // Someone stole it (we were considered stale): stop pretending we own it.
    if (!current || current.token !== info.token) {
      clearInterval(timer);
      held.delete(info.instance);
      return;
    }
    info.heartbeat = Date.now();
    try {
      const fd = openSync(leasePath(info.instance), 'w');
      try {
        writeSync(fd, JSON.stringify(info));
      } finally {
        closeSync(fd);
      }
    } catch {
      // Best effort; the next acquire will notice.
    }
  }, HEARTBEAT_MS);
  timer.unref?.();
  return timer;
}

/**
 * Take the lease for `instance`, or report who holds it.
 *
 * Re-entrant for this process: the second call for the same instance is a
 * no-op. Reclaiming a stale lease is not reported as a conflict.
 */
export function acquireLease(instance: string): AcquireResult {
  const existing = held.get(instance);
  if (existing) return { ok: true, reclaimed: false };

  const info: LeaseInfo = {
    instance,
    pid: process.pid,
    host: hostname(),
    started_at: Date.now(),
    heartbeat: Date.now(),
    token: `${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  };

  if (writeLease(info)) {
    held.set(instance, { info, timer: startHeartbeat(info) });
    return { ok: true, reclaimed: false };
  }

  const current = readLease(instance);
  if (!current) {
    // Unreadable/corrupt or removed between EEXIST and read: retry once.
    if (writeLease(info)) {
      held.set(instance, { info, timer: startHeartbeat(info) });
      return { ok: true, reclaimed: false };
    }
    return { ok: false, holder: null };
  }

  if (!isStale(current)) {
    return { ok: false, holder: current };
  }

  try {
    unlinkSync(leasePath(instance));
  } catch {
    // Someone else removed it first.
  }
  if (writeLease(info)) {
    held.set(instance, { info, timer: startHeartbeat(info) });
    return { ok: true, reclaimed: true };
  }
  return { ok: false, holder: readLease(instance) };
}

/** True when this process currently owns the instance. */
export function ownsLease(instance: string): boolean {
  return held.has(instance);
}

/** Read-only view: the live holder of `instance`, or null if it is free. */
export function peekLease(instance: string): LeaseInfo | null {
  const info = readLease(instance);
  if (!info) return null;
  return isStale(info) ? null : info;
}

export function releaseLease(instance: string): void {
  const entry = held.get(instance);
  if (!entry) return;
  clearInterval(entry.timer);
  held.delete(instance);
  const current = readLease(instance);
  if (current?.token === entry.info.token) {
    try {
      unlinkSync(leasePath(instance));
    } catch {
      // Already gone.
    }
  }
}

export function releaseAllLeases(): void {
  for (const instance of [...held.keys()]) releaseLease(instance);
}

/** Describe a holder for an error message. */
export function describeHolder(info: LeaseInfo): string {
  const age = Math.round((Date.now() - info.started_at) / 1000);
  return `pid ${info.pid} on ${info.host}, holding it for ${age}s`;
}

// A killed process cannot run handlers; these cover the normal exits.
process.on('exit', releaseAllLeases);
