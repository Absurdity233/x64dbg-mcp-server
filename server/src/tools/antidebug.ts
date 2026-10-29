import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { httpClient } from '../http_client.js';
import { currentInstance } from '../context.js';

interface TerminateTarget {
  label: string;
  /** Name variants; x64dbg accepts both `module!symbol` and `module.symbol`. */
  symbols: string[];
  bytes: string;
}

/**
 * User-mode termination APIs a target may use to kill the agent (or itself).
 *
 * BOOL functions return TRUE; NTSTATUS functions return STATUS_SUCCESS; void
 * functions just return. Direct `syscall` stubs bypass these patches, and a
 * spawned `taskkill.exe` runs in its own address space - neither is covered.
 */
const TERMINATE_TARGETS: TerminateTarget[] = [
  {
    label: 'TerminateProcess',
    symbols: ['kernelbase!TerminateProcess', 'kernelbase.TerminateProcess', 'kernel32!TerminateProcess', 'kernel32.TerminateProcess'],
    bytes: 'B8 01 00 00 00 C3',
  },
  {
    label: 'ExitProcess',
    symbols: ['kernelbase!ExitProcess', 'kernelbase.ExitProcess', 'kernel32!ExitProcess', 'kernel32.ExitProcess'],
    bytes: 'B8 01 00 00 00 C3',
  },
  {
    label: 'TerminateThread',
    symbols: ['kernelbase!TerminateThread', 'kernelbase.TerminateThread', 'kernel32!TerminateThread', 'kernel32.TerminateThread'],
    bytes: 'B8 01 00 00 00 C3',
  },
  {
    label: 'NtTerminateProcess',
    symbols: ['ntdll!NtTerminateProcess', 'ntdll.NtTerminateProcess'],
    bytes: '33 C0 C3',
  },
  {
    label: 'NtTerminateThread',
    symbols: ['ntdll!NtTerminateThread', 'ntdll.NtTerminateThread'],
    bytes: '33 C0 C3',
  },
  {
    label: 'RtlExitUserProcess',
    symbols: ['ntdll!RtlExitUserProcess', 'ntdll.RtlExitUserProcess'],
    bytes: 'C3',
  },
  {
    label: 'RtlExitUserThread',
    symbols: ['ntdll!RtlExitUserThread', 'ntdll.RtlExitUserThread'],
    bytes: 'C3',
  },
];

interface TerminatePatchRecord {
  label: string;
  symbol: string;
  address: string;
  original_bytes: string;
  patch_bytes: string;
}

function patchDir(): string {
  return join(tmpdir(), 'x64dbg-mcp');
}

function patchFile(): string {
  const inst = currentInstance();
  const safe = (inst.id || `${inst.host}_${inst.port}`).replace(/[^A-Za-z0-9._-]/g, '_');
  return join(patchDir(), `block_terminate_${safe}.json`);
}

function readRecords(): TerminatePatchRecord[] {
  try {
    const parsed = JSON.parse(readFileSync(patchFile(), 'utf8'));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeRecords(records: TerminatePatchRecord[]): void {
  mkdirSync(patchDir(), { recursive: true });
  writeFileSync(patchFile(), JSON.stringify(records, null, 2));
}

function clearRecords(): void {
  try { unlinkSync(patchFile()); } catch { /* already gone */ }
}

function normHex(value: string | undefined | null): string {
  return (value ?? '').trim().replace(/\s+/g, ' ').toUpperCase();
}

async function resolveSymbol(name: string): Promise<string | null> {
  try {
    const data = await httpClient.get<{ address?: string }>('/api/symbols/resolve', { name });
    return data?.address ?? null;
  } catch {
    return null;
  }
}

async function readHex(address: string, size: number): Promise<string | null> {
  try {
    const data = await httpClient.get<{ hex?: string }>('/api/memory/read', {
      address,
      size: String(size),
    });
    return data?.hex ?? null;
  } catch {
    return null;
  }
}

async function blockTerminate(restore: boolean): Promise<any> {
  if (restore) {
    const records = readRecords();
    if (!records.length) {
      return {
        restored: 0,
        message: 'No block_terminate patches recorded for this instance.',
      };
    }
    const restored: TerminatePatchRecord[] = [];
    const failed: Array<TerminatePatchRecord & { error: string }> = [];
    for (const rec of records) {
      try {
        await httpClient.post('/api/memory/write', {
          address: rec.address,
          bytes: rec.original_bytes,
          verify: true,
        });
        restored.push(rec);
      } catch (err) {
        failed.push({ ...rec, error: err instanceof Error ? err.message : String(err) });
      }
    }
    if (failed.length) writeRecords(failed);
    else clearRecords();
    return {
      restored,
      failed,
      patch_file: patchFile(),
      message: failed.length
        ? 'Some patches could not be restored; the records were kept.'
        : 'Original bytes written back; termination APIs are no longer stubbed.',
    };
  }

  const state = await httpClient.get<{ state?: string }>('/api/debug/state');
  if (state?.state !== 'paused') {
    throw new Error(
      'block_terminate requires a paused debugger: pause at the point where the target is unpacked, ' +
      'then apply the patches. Patching while running can race the target\'s own code writes.'
    );
  }

  const previous = readRecords();
  const byAddress = new Map(previous.map((r) => [r.address.toUpperCase(), r]));
  const patched: TerminatePatchRecord[] = [];
  const already: Array<{ label: string; address: string; bytes: string }> = [];
  const skipped: Array<{ label: string; symbol?: string; address?: string; reason: string }> = [];
  const seen = new Set<string>();

  for (const target of TERMINATE_TARGETS) {
    let address: string | null = null;
    let symbol = '';
    for (const candidate of target.symbols) {
      const resolved = await resolveSymbol(candidate);
      if (resolved) {
        address = resolved;
        symbol = candidate;
        break;
      }
    }
    if (!address) {
      skipped.push({ label: target.label, reason: 'symbol not found in this process', symbol: target.symbols[0] });
      continue;
    }

    const key = address.toUpperCase();
    if (seen.has(key)) {
      skipped.push({ label: target.label, address, reason: 'duplicate address (forwarder)' });
      continue;
    }
    seen.add(key);

    const size = target.bytes.split(/\s+/).length;
    const current = await readHex(address, size);
    if (normHex(current) === normHex(target.bytes)) {
      already.push({ label: target.label, address, bytes: target.bytes });
      continue;
    }

    try {
      const result = await httpClient.post<{ original_bytes?: string }>('/api/patches/apply', {
        address,
        bytes: target.bytes,
      });
      const record: TerminatePatchRecord = {
        label: target.label,
        symbol,
        address,
        original_bytes: result?.original_bytes ?? current ?? '',
        patch_bytes: target.bytes,
      };
      byAddress.set(key, record);
      patched.push(record);
    } catch (err) {
      skipped.push({
        label: target.label,
        symbol,
        address,
        reason: err instanceof Error ? err.message : String(err),
      });
    }
  }

  if (byAddress.size) writeRecords([...byAddress.values()]);
  else clearRecords();

  return {
    patched,
    already,
    skipped,
    patch_file: patchFile(),
    note:
      'Writes stub the termination APIs inside the debuggee, not the agent. Direct syscalls and a ' +
      'spawned taskkill.exe are not covered. Use restore:true to write the original bytes back.',
  };
}

export function registerAntiDebugTools(server: McpServer) {
  server.tool(
    'x64dbg_antidebug',
    'Anti-debugging analysis. Actions: peb, teb, dep, hide_debugger (clears BeingDebugged/NtGlobalFlag and verifies by read-back), harden (also clears heap flags and the DR registers; reports what needs a kernel component), vm_probes (locates cpuid/rdtsc/sidt/str and other anti-VM instructions in a module - discovery only, nothing is patched), probe_breakpoints (arms a silent logging breakpoint on every probe found so each hit lands in the event log with its registers), block_terminate (paused target: stub TerminateProcess/ExitProcess/NtTerminateProcess/TerminateThread/NtTerminateThread/RtlExitUserProcess/RtlExitUserThread so the target cannot kill the agent or itself; restore:true writes the original bytes back).',
    {
      action: z.enum([
        'peb', 'teb', 'dep', 'hide_debugger', 'harden', 'vm_probes',
        'probe_breakpoints', 'block_terminate',
      ]).describe('Operation to perform'),
      pid: z.string().optional().describe('peb: process id (default current)'),
      tid: z.string().optional().describe('teb: thread id (default current)'),
      module: z.string().optional().describe('vm_probes/probe_breakpoints: module name (default the main module)'),
      max_hits: z.number().optional().describe('vm_probes/probe_breakpoints: cap (default 200)'),
      log_text: z.string().optional().describe('probe_breakpoints: per-hit log format'),
      resume: z.boolean().optional().describe('probe_breakpoints: start the target after arming (default true)'),
      restore: z.boolean().optional().describe(
        'block_terminate: write the original bytes back instead of applying the stubs.'
      ),
    },
    async (args) => {
      switch (args.action) {
        case 'peb': {
          const data = await httpClient.get('/api/antidebug/peb', { pid: args.pid ?? '' });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'teb': {
          const data = await httpClient.get('/api/antidebug/teb', { tid: args.tid ?? '' });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'dep': {
          const data = await httpClient.get('/api/antidebug/dep_status');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'hide_debugger': {
          const data = await httpClient.post('/api/antidebug/hide_debugger');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'harden': {
          const data = await httpClient.post('/api/antidebug/harden');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'vm_probes': {
          const data = await httpClient.get('/api/antidebug/vm_probes', {
            module: args.module ?? '',
            max_hits: String(args.max_hits ?? 200),
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'probe_breakpoints': {
          const data = await httpClient.post('/api/antidebug/probe_breakpoints', {
            module: args.module ?? '',
            max_hits: args.max_hits ?? 200,
            log_text: args.log_text ?? '',
            resume: args.resume ?? true,
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'block_terminate': {
          const data = await blockTerminate(args.restore ?? false);
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
