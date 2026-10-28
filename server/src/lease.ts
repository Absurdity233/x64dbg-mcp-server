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
import { config } from './config.js';

/**
 * Exclusive ownership of an x64dbg *endpoint*.
 *
 * The `instance` argument only says where a call should go; it does not stop
 * two models from pointing at the same debugger. Two agents on one x64dbg
 * silently corrupt each other: breakpoints collide, one agent's run clears the
 * other's paused state, both see each other's events.
 *
 * The lease is keyed by host:port, not by instance id. Two ids can name the
 * same endpoint (a duplicate entry, or a provisioned copy that ended up on the
 * default's port); keying by id would then hand out two "different" leases over
 * one debugger, which is exactly the failure this exists to prevent.
 *
 * The lease is a file, not an in-process lock: independent Claude Code sessions
 * are independent MCP server processes. A lease names the owner pid and is
 * refreshed every HEARTBEAT_MS; a lease whose owner is gone (same host) or
 * whose heartbeat is older than STALE_MS is reclaimed.
 *
 * X64DBG_MCP_LEASE=off disables enforcement (the old advisory behaviour).
 */

const DIR = join(tmpdir(), 'x64dbg-mcp', 'leases');
const HEARTBEAT_MS = 10_000;
const STALE_MS = 35_000;

export interface LeaseInfo {
  /** Instance id the owner used; only for messages. */
  instance: string;
  /** host:port this lease actually protects. */
  endpoint: string;
  pid: number;
  host: string;
  started_at: number;
  heartbeat: number;
  /** Last tool call routed to this endpoint (missing on older lease files). */
  last_call?: number;
  token: string;
}

export type AcquireResult =
  | { ok: true; reclaimed: boolean }
  | { ok: false; holder: LeaseInfo | null };

interface Held { info: LeaseInfo; timer: NodeJS.Timeout; host: string; port: number }
const held = new Map<string, Held>();

function safeName(s: string): string {
  return s.replace(/[^A-Za-z0-9._-]/g, '_');
}

/** The identity of a debugger: what the lease and every lookup key on. */
export function leaseKey(host: string, port: number): string {
  return `ep_${safeName(host)}_${port}`;
}

function leasePath(key: string): string {
  return join(DIR, `${safeName(key)}.lease`);
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException)?.code === 'EPERM';
  }
}

function readLease(key: string): LeaseInfo | null {
  try {
    return JSON.parse(readFileSync(leasePath(key), 'utf8')) as LeaseInfo;
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

/** Milliseconds since the owner last routed a tool call here. */
function idleFor(info: LeaseInfo): number {
  return Date.now() - (info.last_call ?? info.heartbeat);
}

function isIdle(info: LeaseInfo): boolean {
  return config.leaseIdleMs > 0 && idleFor(info) > config.leaseIdleMs;
}

function writeLease(key: string, info: LeaseInfo): boolean {
  try {
    mkdirSync(DIR, { recursive: true });
    const fd = openSync(leasePath(key), 'wx');
    try {
      writeSync(fd, JSON.stringify(info));
    } finally {
      closeSync(fd);
    }
    return true;
  } catch (err) {
    // EEXIST is the normal "somebody else has it" path. Anything else (a
    // transient sharing violation while another process rewrites its lease)
    // must not crash a tool call either: report "not acquired" and let the
    // caller surface the conflict.
    if ((err as NodeJS.ErrnoException)?.code === 'EEXIST') return false;
    return false;
  }
}

function startHeartbeat(key: string, info: LeaseInfo): NodeJS.Timeout {
  const timer = setInterval(() => {
    if (held.get(key)?.info.token !== info.token) {
      clearInterval(timer);
      return;
    }
    const current = readLease(key);
    // Someone else took it (our heartbeat was considered stale): stop
    // pretending we own it.
    if (!current || current.token !== info.token) {
      clearInterval(timer);
      held.delete(key);
      return;
    }
    info.heartbeat = Date.now();
    try {
      const fd = openSync(leasePath(key), 'w');
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

function take(key: string, info: LeaseInfo, host: string, port: number, reclaimed: boolean): AcquireResult {
  held.set(key, { info, timer: startHeartbeat(key, info), host, port });
  return { ok: true, reclaimed };
}

/**
 * Take the lease for an endpoint, or report who holds it.
 *
 * Re-entrant for this process: a second call for the same endpoint is a no-op.
 * Reclaiming a stale lease is not reported as a conflict.
 */
export function acquireLease(instanceId: string, host: string, port: number): AcquireResult {
  const key = leaseKey(host, port);
  if (held.has(key)) return { ok: true, reclaimed: false };

  const now = Date.now();
  const info: LeaseInfo = {
    instance: instanceId,
    endpoint: `${host}:${port}`,
    pid: process.pid,
    host: hostname(),
    started_at: now,
    heartbeat: now,
    last_call: now,
    token: `${process.pid}-${now}-${Math.random().toString(36).slice(2)}`,
  };

  if (writeLease(key, info)) return take(key, info, host, port, false);

  const current = readLease(key);
  if (!current) {
    // Corrupt or removed between EEXIST and read: retry once.
    if (writeLease(key, info)) return take(key, info, host, port, false);
    return { ok: false, holder: null };
  }

  // A live but idle session yields: otherwise the first Claude Code window to
  // touch a debugger blocks every other window until that process exits.
  if (!isStale(current) && !isIdle(current)) return { ok: false, holder: current };

  try {
    unlinkSync(leasePath(key));
  } catch {
    // Someone else removed it first.
  }
  if (writeLease(key, info)) return take(key, info, host, port, true);
  return { ok: false, holder: readLease(key) };
}

/** Mark the endpoint as used just now (called on every routed tool call). */
export function touchLease(host: string, port: number): void {
  const entry = held.get(leaseKey(host, port));
  if (entry) entry.info.last_call = Date.now();
}

/** True when this process owns the endpoint. */
export function ownsLease(host: string, port: number): boolean {
  return held.has(leaseKey(host, port));
}

export type TakeoverResult =
  | { ok: true; previous: LeaseInfo | null }
  | { ok: false; holder: LeaseInfo | null };

/**
 * Explicitly take an endpoint from another live session.
 *
 * Without `force` this only succeeds when the holder has been idle for
 * X64DBG_MCP_LEASE_IDLE_MS; with `force` it overwrites any live lease. The
 * previous owner's heartbeat notices the token change and stops claiming it,
 * so its next call gets a normal conflict instead of driving a debugger it no
 * longer owns.
 */
export function takeOverLease(
  instanceId: string,
  host: string,
  port: number,
  force = false
): TakeoverResult {
  const key = leaseKey(host, port);
  if (held.has(key)) return { ok: true, previous: null };

  const current = readLease(key);
  const live = current && !isStale(current);
  if (live && !force && !isIdle(current)) {
    return { ok: false, holder: current };
  }

  const now = Date.now();
  const info: LeaseInfo = {
    instance: instanceId,
    endpoint: `${host}:${port}`,
    pid: process.pid,
    host: hostname(),
    started_at: now,
    heartbeat: now,
    last_call: now,
    token: `${process.pid}-${now}-${Math.random().toString(36).slice(2)}`,
  };

  try {
    mkdirSync(DIR, { recursive: true });
    const fd = openSync(leasePath(key), 'w');
    try {
      writeSync(fd, JSON.stringify(info));
    } finally {
      closeSync(fd);
    }
  } catch {
    return { ok: false, holder: readLease(key) };
  }

  take(key, info, host, port, true);
  return { ok: true, previous: current };
}

/** Read-only view: the live holder of an endpoint, or null if it is free. */
export function peekLease(host: string, port: number): LeaseInfo | null {
  const info = readLease(leaseKey(host, port));
  if (!info) return null;
  return isStale(info) ? null : info;
}

export function releaseLease(host: string, port: number): void {
  const key = leaseKey(host, port);
  const entry = held.get(key);
  if (!entry) return;
  clearInterval(entry.timer);
  held.delete(key);
  const current = readLease(key);
  if (current?.token === entry.info.token) {
    try {
      unlinkSync(leasePath(key));
    } catch {
      // Already gone.
    }
  }
}

export function releaseAllLeases(): void {
  for (const entry of [...held.values()]) {
    releaseLease(entry.host, entry.port);
  }
}

/** Describe a holder for an error message. */
export function describeHolder(info: LeaseInfo): string {
  const age = Math.round((Date.now() - info.started_at) / 1000);
  const idle = Math.round(idleFor(info) / 1000);
  return `pid ${info.pid} on ${info.host}, holding ${info.endpoint} for ${age}s (idle ${idle}s)`;
}

// A killed process cannot run handlers; this covers the normal exit.
process.on('exit', releaseAllLeases);
