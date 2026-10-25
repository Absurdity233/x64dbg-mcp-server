import { createHash } from 'node:crypto';
import { closeSync, mkdirSync, openSync, readFileSync, unlinkSync, writeSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

/**
 * Which live debuggee owns a given executable path.
 *
 * Most Windows programs resolve Config/, Logs/ and save files from their module
 * path, so two debuggers running the *same* exe write to the same files and
 * corrupt each other's runs. Different binaries are fine; the same path is not.
 *
 * A claim is keyed by the debuggee's pid, not the MCP server's: when the
 * process dies the claim is stale even if the agent that loaded it is still
 * running. provision-target.ps1 is the way to run the same binary twice.
 */

const DIR = join(tmpdir(), 'x64dbg-mcp', 'targets');
const STALE_MS = 24 * 60 * 60 * 1000;

export interface TargetClaim {
  path: string;
  instance: string;
  pid: number;
  host: string;
  at: number;
}

function normalize(p: string): string {
  return resolve(p).toLowerCase();
}

function claimPath(p: string): string {
  const hash = createHash('sha1').update(normalize(p)).digest('hex').slice(0, 16);
  return join(DIR, `${hash}.json`);
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException)?.code === 'EPERM';
  }
}

/** The live claim on this path, or null. Stale claims are removed. */
export function findTargetClaim(p: string): TargetClaim | null {
  const file = claimPath(p);
  let claim: TargetClaim;
  try {
    claim = JSON.parse(readFileSync(file, 'utf8')) as TargetClaim;
  } catch {
    return null;
  }

  const stale =
    (claim.host === hostname() && !pidAlive(claim.pid)) ||
    Date.now() - claim.at > STALE_MS;
  if (stale) {
    try {
      unlinkSync(file);
    } catch {
      // Already gone.
    }
    return null;
  }
  return claim;
}

export function claimTarget(p: string, instance: string, pid: number): void {
  try {
    mkdirSync(DIR, { recursive: true });
    const claim: TargetClaim = {
      path: resolve(p),
      instance,
      pid,
      host: hostname(),
      at: Date.now(),
    };
    const fd = openSync(claimPath(p), 'w');
    try {
      writeSync(fd, JSON.stringify(claim));
    } finally {
      closeSync(fd);
    }
  } catch {
    // A claim is advisory bookkeeping; never fail a load because of it.
  }
}

export function releaseTarget(p: string, pid?: number): void {
  const claim = findTargetClaim(p);
  if (!claim) return;
  if (pid !== undefined && claim.pid !== pid) return;
  try {
    unlinkSync(claimPath(p));
  } catch {
    // Already gone.
  }
}
