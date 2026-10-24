import { spawn, ChildProcessWithoutNullStreams } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

/**
 * Long-lived PowerShell host for ui.ps1.
 *
 * Launching powershell.exe costs ~3s (CLR + WinRT + Add-Type compilation), and
 * a UI flow needs a dozen calls, so one-shot spawning dominated the wall clock.
 * This keeps a single process alive and speaks a line-delimited JSON protocol:
 *
 *   -> {"id":1,"hwnd":123,"action":"clicktext","match":"OK"}
 *   <- {"id":1,"ok":true,"output":"...","error":""}
 */

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'ui.ps1');

const IDLE_SHUTDOWN_MS = 10 * 60 * 1000;
const REQUEST_TIMEOUT_MS = 120_000;

export interface UiRequest {
  action: string;
  hwnd?: number;
  x?: number;
  y?: number;
  text?: string;
  match?: string;
  file?: string;
  scale?: number;
  lang?: string;
  region?: string;
  wait_stable_ms?: number;
  stable_timeout_ms?: number;
  enhance?: boolean;
  regex?: boolean;
}

export interface UiResponse {
  ok: boolean;
  output: string;
  error: string;
}

interface Pending {
  resolve: (r: UiResponse) => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
}

class UiDaemon {
  private child: ChildProcessWithoutNullStreams | null = null;
  private pending = new Map<number, Pending>();
  private nextId = 1;
  private buffer = '';
  private idleTimer: NodeJS.Timeout | null = null;
  private starting: Promise<void> | null = null;

  private async ensureStarted(): Promise<void> {
    if (this.child && !this.child.killed) return;
    if (this.starting) return this.starting;

    this.starting = new Promise<void>((resolve, reject) => {
      const child = spawn(
        'powershell',
        ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', SCRIPT, '-Hwnd', '0', '-Action', 'serve'],
        { windowsHide: true }
      ) as ChildProcessWithoutNullStreams;

      let settled = false;
      const failAll = (err: Error) => {
        for (const [, p] of this.pending) {
          clearTimeout(p.timer);
          p.reject(err);
        }
        this.pending.clear();
      };

      child.stdout.setEncoding('utf8');
      child.stdout.on('data', (chunk: string) => this.onData(chunk));
      child.stderr.setEncoding('utf8');
      child.stderr.on('data', (chunk: string) => {
        // Startup warnings are not fatal; keep them out of the protocol stream.
        const text = chunk.trim();
        if (text) console.error(`[x64dbg-mcp] ui daemon: ${text}`);
      });

      child.on('error', (err) => {
        this.child = null;
        if (!settled) {
          settled = true;
          reject(err);
        }
        failAll(err);
      });

      child.on('close', () => {
        this.child = null;
        this.starting = null;
        failAll(new Error('UI daemon exited'));
      });

      // The daemon prints nothing on startup; a short grace period is enough to
      // know it did not die immediately.
      setTimeout(() => {
        if (settled) return;
        settled = true;
        this.child = child;
        resolve();
      }, 250);
    }).finally(() => {
      this.starting = null;
    });

    return this.starting;
  }

  private onData(chunk: string): void {
    this.buffer += chunk;
    let nl: number;
    while ((nl = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, nl).trim();
      this.buffer = this.buffer.slice(nl + 1);
      if (!line) continue;

      let msg: any;
      try {
        msg = JSON.parse(line);
      } catch {
        // Non-protocol noise on stdout (a stray Write-Host) - ignore.
        continue;
      }

      const pending = this.pending.get(msg.id);
      if (!pending) continue;
      this.pending.delete(msg.id);
      clearTimeout(pending.timer);
      pending.resolve({
        ok: !!msg.ok,
        output: typeof msg.output === 'string' ? msg.output : '',
        error: typeof msg.error === 'string' ? msg.error : '',
      });
    }
  }

  private touchIdle(): void {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => {
      // Idle for a while: release the process so it does not linger after the
      // session ends. The next call transparently restarts it.
      this.shutdown();
    }, IDLE_SHUTDOWN_MS);
    this.idleTimer.unref?.();
  }

  async run(req: UiRequest): Promise<UiResponse> {
    await this.ensureStarted();
    const child = this.child;
    if (!child) throw new Error('UI daemon is not running');

    const id = this.nextId++;
    const payload = JSON.stringify({ id, ...req });

    return new Promise<UiResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`UI daemon request timed out after ${REQUEST_TIMEOUT_MS}ms`));
      }, REQUEST_TIMEOUT_MS);
      timer.unref?.();

      this.pending.set(id, { resolve, reject, timer });
      child.stdin.write(payload + '\n');
      this.touchIdle();
    });
  }

  shutdown(): void {
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
      this.idleTimer = null;
    }
    const child = this.child;
    this.child = null;
    if (child) {
      try { child.stdin.end(); } catch { /* already gone */ }
      try { child.kill(); } catch { /* already gone */ }
    }
  }
}

export const uiDaemon = new UiDaemon();
