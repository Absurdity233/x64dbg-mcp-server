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

interface SpoofRecord {
  address: string;
  instruction: string;
  mode: 'hypervisor-bit' | 'hypervisor-vendor';
  condition: string;
  command: string;
}

function spoofFile(): string {
  const inst = currentInstance();
  const safe = (inst.id || `${inst.host}_${inst.port}`).replace(/[^A-Za-z0-9._-]/g, '_');
  return join(patchDir(), `spoof_cpuid_${safe}.json`);
}

function readSpoofRecords(): SpoofRecord[] {
  try {
    const parsed = JSON.parse(readFileSync(spoofFile(), 'utf8'));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeSpoofRecords(records: SpoofRecord[]): void {
  mkdirSync(patchDir(), { recursive: true });
  writeFileSync(spoofFile(), JSON.stringify(records, null, 2));
}

function clearSpoofRecords(): void {
  try { unlinkSync(spoofFile()); } catch { /* already gone */ }
}

/**
 * Spoof CPUID-based hypervisor detection.
 *
 * For every CPUID site that is followed by a check of ECX bit 31 (the
 * hypervisor-present bit) arm a silent breakpoint that clears the bit and
 * resumes. Sites that compare EAX with 0x40000000 (the hypervisor vendor leaf)
 * instead get zeroed EAX/EBX/ECX/EDX. Only the debuggee is affected; a host
 * with Hyper-V/VBS enabled still reports a hypervisor to any check outside
 * these sites, and direct CPUID executed by a driver is not covered.
 */
async function spoofCpuid(args: {
  restore?: boolean;
  module?: string;
  max_hits?: number;
  vendor?: boolean;
  only_checked?: boolean;
}): Promise<any> {
  if (args.restore) {
    const records = readSpoofRecords();
    const removed: string[] = [];
    const failed: Array<{ address: string; error: string }> = [];
    for (const rec of records) {
      try {
        await httpClient.post('/api/breakpoints/delete', { address: rec.address });
        removed.push(rec.address);
      } catch (err) {
        failed.push({ address: rec.address, error: err instanceof Error ? err.message : String(err) });
      }
    }
    if (failed.length) writeSpoofRecords(records.filter((r) => failed.some((f) => f.address === r.address)));
    else clearSpoofRecords();
    return {
      removed,
      failed,
      note: 'CPUID spoof breakpoints deleted.',
    };
  }

  const state = await httpClient.get<{ state?: string }>('/api/debug/state');
  if (state?.state !== 'paused') {
    throw new Error('spoof_cpuid requires a paused debugger: pause before the target performs its VM check.');
  }

  const probes = await httpClient.get<any>('/api/antidebug/vm_probes', {
    module: args.module ?? '',
    max_hits: String(args.max_hits ?? 200),
  });
  const cpuidHits = (probes?.hits ?? []).filter((h: any) => h?.instruction === 'cpuid');
  const vendor = args.vendor ?? true;
  const onlyChecked = args.only_checked ?? true;
  const armed: SpoofRecord[] = [];
  const skipped: Array<{ address: string; reason: string }> = [];

  for (const hit of cpuidHits) {
    const address = String(hit.address ?? '');
    if (!address) continue;

    let text = '';
    try {
      const dis = await httpClient.get<any>('/api/disasm/at', { address, count: '24' });
      text = (dis?.instructions ?? []).map((i: any) => String(i.instruction ?? '')).join('\n').toLowerCase();
    } catch {
      skipped.push({ address, reason: 'disassembly unavailable' });
      continue;
    }

    const hasBit = /bt\s+ecx\s*,\s*0x1f|test\s+ecx\s*,\s*0x80000000|shr\s+ecx\s*,\s*0x1f|and\s+ecx\s*,\s*0x80000000/.test(text);
    const hasVendor = /0x40000000/.test(text);

    if (onlyChecked && !hasBit && !hasVendor) {
      skipped.push({ address, reason: 'no hypervisor bit/vendor check nearby' });
      continue;
    }

    // Prefer the bit spoof when both patterns are present: zeroing the vendor
    // registers would destroy the feature bits the target may read next.
    const mode: SpoofRecord['mode'] = hasVendor && !hasBit ? 'hypervisor-vendor' : 'hypervisor-bit';
    if (mode === 'hypervisor-vendor' && !vendor) {
      skipped.push({ address, reason: 'vendor spoof disabled' });
      continue;
    }

    const condition = mode === 'hypervisor-bit' ? 'eax==1' : 'eax==0x40000000';
    const command = mode === 'hypervisor-bit'
      ? 'ecx=ecx&0x7FFFFFFF;run'
      : 'eax=0;ebx=0;ecx=0;edx=0;run';

    try {
      await httpClient.post('/api/breakpoints/configure', {
        address,
        bp_type: 'software',
        break_condition: condition,
        command_text: command,
        fast_resume: true,
        silent: true,
        name: `anti-vm cpuid (${mode})`,
      });
      armed.push({ address, instruction: 'cpuid', mode, condition, command });
    } catch (err) {
      skipped.push({ address, reason: err instanceof Error ? err.message : String(err) });
    }
  }

  if (armed.length) writeSpoofRecords(armed);
  else clearSpoofRecords();

  return {
    module: probes?.module ?? (args.module || '<main>'),
    cpuid_sites: cpuidHits.length,
    armed,
    skipped,
    spoof_file: spoofFile(),
    note:
      'Silent breakpoints clear ECX bit 31 (leaf 1) or zero the vendor leaf (0x40000000) and resume. ' +
      'Only CPUID sites near a recognizable check are armed by default. Direct syscalls, RDTSC/SIDT ' +
      'checks and host Hyper-V/VBS outside these sites are not covered. Use restore:true to remove them.',
  };
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
    'Anti-debugging analysis. Actions: peb, teb, dep, hide_debugger (clears BeingDebugged/NtGlobalFlag and verifies by read-back), harden (also clears heap flags and the DR registers; reports what needs a kernel component), vm_probes (locates cpuid/rdtsc/sidt/str and other anti-VM instructions in a module - discovery only, nothing is patched), probe_breakpoints (arms a silent logging breakpoint on every probe found so each hit lands in the event log with its registers), spoof_cpuid (paused target: arm silent breakpoints on CPUID sites that check the hypervisor bit/vendor and rewrite the registers), block_terminate (paused target: stub TerminateProcess/ExitProcess/NtTerminateProcess/TerminateThread/NtTerminateThread/RtlExitUserProcess/RtlExitUserThread so the target cannot kill the agent or itself; restore:true writes the original bytes back).',
    {
      action: z.enum([
        'peb', 'teb', 'dep', 'hide_debugger', 'harden', 'vm_probes',
        'probe_breakpoints', 'spoof_cpuid', 'block_terminate',
      ]).describe('Operation to perform'),
      pid: z.string().optional().describe('peb: process id (default current)'),
      tid: z.string().optional().describe('teb: thread id (default current)'),
      module: z.string().optional().describe('vm_probes/probe_breakpoints: module name (default the main module)'),
      max_hits: z.number().optional().describe('vm_probes/probe_breakpoints: cap (default 200)'),
      log_text: z.string().optional().describe('probe_breakpoints: per-hit log format'),
      resume: z.boolean().optional().describe('probe_breakpoints: start the target after arming (default true)'),
      restore: z.boolean().optional().describe(
        'block_terminate/spoof_cpuid: revert instead of applying (write original bytes / delete spoof breakpoints).'
      ),
      vendor: z.boolean().optional().describe(
        'spoof_cpuid: also spoof the 0x40000000 hypervisor-vendor leaf (default true).'
      ),
      only_checked: z.boolean().optional().describe(
        'spoof_cpuid: only arm CPUID sites near a recognizable hypervisor check (default true).'
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
        case 'spoof_cpuid': {
          const data = await spoofCpuid({
            restore: args.restore,
            module: args.module,
            max_hits: args.max_hits,
            vendor: args.vendor,
            only_checked: args.only_checked,
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
