import {
  closeSync,
  mkdirSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * Machine-wide serialisation for synthetic UI input.
 *
 * realclick/clicktext/typeinto call SetCursorPos + SendInput and must steal the
 * foreground window first. Those are machine-global: if two models drive two
 * different x64dbg targets at the same time, one of them will type into the
 * other's window. An in-process mutex is not enough - independent Claude Code
 * sessions are independent MCP server processes - so the lock is a file.
 *
 * Scope is deliberately narrow: only actions that generate input take it.
 * screenshot/ocr/findtext/windows/info are read-only and stay concurrent.
 *
 * Staleness: a holder that crashed leaves the file behind, so a lock is
 * considered stale when its pid is gone or it is older than STALE_MS. Both are
 * checked on every failed acquire, which keeps a dead session from wedging the
 * machine until a reboot.
 */

const LOCK_DIR = join(tmpdir(), 'x64dbg-mcp');
const LOCK_PATH = join(LOCK_DIR, 'ui.lock');
const STALE_MS = 120_000;
const POLL_MS = 150;

export interface UiLockHolder {
  pid: number;
  instance: string;
  action: string;
  hwnd?: number;
  at: number;
  token: string;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function readHolder(): UiLockHolder | null {
  try {
    return JSON.parse(readFileSync(LOCK_PATH, 'utf8')) as UiLockHolder;
  } catch {
    return null;
  }
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM means the process exists but belongs to someone else.
    return (err as NodeJS.ErrnoException)?.code === 'EPERM';
  }
}

function tryCreate(holder: UiLockHolder): boolean {
  try {
    mkdirSync(LOCK_DIR, { recursive: true });
    const fd = openSync(LOCK_PATH, 'wx');
    try {
      writeSync(fd, JSON.stringify(holder));
    } finally {
      closeSync(fd);
    }
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException)?.code === 'EEXIST') return false;
    throw err;
  }
}

function acquireOnce(holder: UiLockHolder, allowSteal: boolean): boolean {
  if (tryCreate(holder)) return true;
  if (!allowSteal) return false;

  const current = readHolder();
  const stale =
    !current ||
    Date.now() - current.at > STALE_MS ||
    !pidAlive(current.pid);
  if (!stale) return false;

  try {
    unlinkSync(LOCK_PATH);
  } catch {
    // Someone else removed it first; the next tryCreate will tell.
  }
  return tryCreate(holder);
}

function release(token: string): void {
  const current = readHolder();
  if (current?.token === token) {
    try {
      unlinkSync(LOCK_PATH);
    } catch {
      // Already gone - nothing to do.
    }
  }
}

/**
 * Run `fn` while holding the machine-wide UI input lock.
 *
 * `timeoutMs` is how long to queue behind another holder before failing; the
 * error names the holder so the caller can tell "busy" from "hung".
 */
export async function withUiLock<T>(
  owner: { instance: string; action: string; hwnd?: number },
  timeoutMs: number,
  fn: () => Promise<T>
): Promise<T> {
  const token = `${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const holder: UiLockHolder = {
    pid: process.pid,
    instance: owner.instance,
    action: owner.action,
    hwnd: owner.hwnd,
    at: Date.now(),
    token,
  };

  const started = Date.now();
  let stealAllowed = true;
  for (;;) {
    if (acquireOnce(holder, stealAllowed)) break;
    // A failed steal means the holder is alive; stop trying to unlink its file
    // on every poll and just queue.
    stealAllowed = false;

    if (Date.now() - started >= timeoutMs) {
      const current = readHolder();
      const who = current
        ? `instance "${current.instance}" (pid ${current.pid}) is running "${current.action}" ` +
          `since ${Math.round((Date.now() - current.at) / 1000)}s ago`
        : 'another process holds it';
      throw new Error(
        `UI input is busy: ${who}. Waited ${Math.round(timeoutMs / 1000)}s. ` +
        'Real mouse/keyboard input is machine-global and is serialised across all ' +
        'x64dbg instances; retry, or raise lock_timeout_ms.'
      );
    }

    await sleep(POLL_MS);
  }

  try {
    return await fn();
  } finally {
    release(token);
  }
}
