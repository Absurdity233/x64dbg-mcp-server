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

/** Driver-side hardening: NTDLL hook functions and the VM-probe arms. */
const NTDLL_HOOKS = [
  'NtQueryInformationProcess',
  'NtSetInformationThread',
  'NtQueryObject',
  'NtQuerySystemInformation',
] as const;

const ANTI_VM_ARMS = ['cpuid', 'rdtsc', 'sidt', 'sgdt', 'sldt', 'str', 'smsw', 'vmx', 'in'] as const;

const HARDEN_LEVELS = ['basic', 'deep', 'paranoid'] as const;

interface KernelVersion {
  abi?: string | number;
  build?: string | number;
  os_build?: string;
  ep_debugport_offset?: string;
  flags_source?: string;
}

interface KernelStatus {
  driver_present?: boolean;
  user_path?: string;
  version?: KernelVersion;
  error?: string;
  /** Emitted by this tool, not the plugin, when the driver is not loaded. */
  next_step?: string;
}

interface ArtifactFinding {
  category?: string;
  item?: string;
  value?: string;
  why?: string;
}

interface ArtifactReport {
  findings?: ArtifactFinding[];
  count?: number;
  note?: string;
}

/**
 * Host-side VM fingerprints, regrouped into "what the target will see" buckets.
 *
 * The plugin returns a flat finding list; grouping it by category is what makes
 * it readable as an evasion checklist (registry first, then services/devices,
 * then hardware strings, then window classes and process names).
 */
async function antiVmArtifacts() {
  const data = await httpClient.get<ArtifactReport>('/api/antidebug/artifacts');
  const findings = data?.findings ?? [];
  const order: string[] = [];
  const groups = new Map<string, Array<{ item: string; value: string; why: string }>>();

  for (const finding of findings) {
    const category = finding?.category?.trim() || 'uncategorized';
    if (!groups.has(category)) {
      groups.set(category, []);
      order.push(category);
    }
    groups.get(category)!.push({
      item: finding?.item ?? '',
      value: finding?.value ?? '',
      why: finding?.why ?? '',
    });
  }

  return {
    count: data?.count ?? findings.length,
    note: data?.note ?? '',
    groups: order.map((category) => ({ category, items: groups.get(category) ?? [] })),
    findings,
  };
}

export function registerAntiDebugTools(server: McpServer) {
  server.tool(
    'x64dbg_antidebug',
    'Anti-debugging analysis. Actions: peb, teb, dep, hide_debugger (clears BeingDebugged/NtGlobalFlag and verifies by read-back), harden (clears heap flags and the DR registers; level=basic|deep|paranoid, threads:boolean and hooks[] extend it into NTDLL hooking; reports what needs a kernel component), vm_probes (locates cpuid/rdtsc/sidt/str and other anti-VM instructions in a module - discovery only, nothing is patched), probe_breakpoints (arms a silent logging breakpoint on every probe found so each hit lands in the event log with its registers), spoof_cpuid (paused target: arm silent breakpoints on CPUID sites that check the hypervisor bit/vendor and rewrite the registers), block_terminate (paused target: stub TerminateProcess/ExitProcess/NtTerminateProcess/TerminateThread/NtTerminateThread/RtlExitUserProcess/RtlExitUserThread so the target cannot kill the agent or itself; restore:true writes the original bytes back), hook_ntdll (inline-hook NtQueryInformationProcess/NtSetInformationThread/NtQueryObject/NtQuerySystemInformation inside the debuggee and report stub_form_ok per function; dry_run:true probes without patching, restore:true writes the original bytes back), anti_vm (arm silent spoofing breakpoints on the given probe arms - cpuid, rdtsc, sidt, sgdt, sldt, str, smsw, vmx, in - and report armed/skipped/restored), kernel_status (GET: is the .sys anti-debug driver loaded, its path and detected ABI/build/EP-DebugPort offset - driver_present:false is the normal first-run state, load the .sys to continue), kernel_attach (POST: read DebugPort/Flags from the kernel for pid, empty pid = current process), kernel_apply (POST: write a mask of DEBUGPORT|FLAGS|CROSSSESSION, default 0x7, with optional per-build offsets), kernel_detach (POST: stop kernel-side modifications, restoring the original pointers), artifacts (GET: host-side VM fingerprints the target can read - registry keys, services, device paths, MAC OUI, disk model, ACPI/BIOS strings, window classes and process names - grouped by category as "what the target will see").',
    {
      action: z.enum([
        'peb', 'teb', 'dep', 'hide_debugger', 'harden', 'vm_probes',
        'probe_breakpoints', 'spoof_cpuid', 'block_terminate',
        'hook_ntdll', 'anti_vm', 'kernel_status', 'kernel_attach',
        'kernel_apply', 'kernel_detach', 'artifacts',
      ]).describe('Operation to perform'),
      pid: z.string().optional().describe('peb/kernel_attach: process id (default current)'),
      tid: z.string().optional().describe('teb: thread id (default current)'),
      module: z.string().optional().describe('vm_probes/probe_breakpoints/anti_vm: module name (default the main module)'),
      max_hits: z.number().optional().describe('vm_probes/probe_breakpoints/anti_vm: cap (default 200)'),
      log_text: z.string().optional().describe('probe_breakpoints: per-hit log format'),
      resume: z.boolean().optional().describe('probe_breakpoints: start the target after arming (default true)'),
      restore: z.boolean().optional().describe(
        'block_terminate/spoof_cpuid/hook_ntdll/anti_vm: revert instead of applying ' +
        '(write original bytes / delete spoof breakpoints).'
      ),
      vendor: z.boolean().optional().describe(
        'spoof_cpuid: also spoof the 0x40000000 hypervisor-vendor leaf (default true).'
      ),
      only_checked: z.boolean().optional().describe(
        'spoof_cpuid: only arm CPUID sites near a recognizable hypervisor check (default true).'
      ),

      // harden
      level: z.enum(HARDEN_LEVELS).optional().describe(
        'harden: basic clears PEB fields only; deep also clears heap flags and debug registers; ' +
        'paranoid additionally hides the debug objects NtQueryObject would enumerate (default deep).'
      ),
      threads: z.boolean().optional().describe('harden: also hide the debugger from every thread (default plugin-side)'),
      hooks: z.array(z.enum(NTDLL_HOOKS)).optional().describe(
        'harden: NTDLL functions to inline-hook as part of hardening; omit for the plugin default set.'
      ),

      // hook_ntdll
      functions: z.array(z.enum(NTDLL_HOOKS)).optional().describe(
        'hook_ntdll: functions to hook (default all four).'
      ),
      dry_run: z.boolean().optional().describe(
        'hook_ntdll: verify the stub prologue matches without writing anything (default false).'
      ),

      // anti_vm
      arms: z.array(z.enum(ANTI_VM_ARMS)).optional().describe(
        'anti_vm: probe arms to arm (default all detected); cpuid, rdtsc, sidt, sgdt, sldt, str, ' +
        'smsw, vmx, in. vmx/in are armed as fault-suppressing stubs, not value spoofs.'
      ),

      // kernel_apply
      mask: z.number().optional().describe(
        'kernel_apply: bitmask of what to hide - 0x1 DEBUGPORT, 0x2 FLAGS, 0x4 CROSSSESSION (default 0x7).'
      ),
      flags_offset: z.number().optional().describe(
        'kernel_apply: override the EPROCESS flags offset (default from kernel_status.version).'
      ),
      cross_session_offset: z.number().optional().describe(
        'kernel_apply: override the cross-session flags offset (default from kernel_status.version).'
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
          const body: Record<string, unknown> = { level: args.level ?? 'deep' };
          if (args.threads !== undefined) body.threads = args.threads;
          if (args.hooks?.length) body.hooks = args.hooks;
          const data = await httpClient.post('/api/antidebug/harden', body);
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
        case 'hook_ntdll': {
          const body: Record<string, unknown> = {
            restore: args.restore ?? false,
            dry_run: args.dry_run ?? false,
          };
          if (args.functions?.length) body.functions = args.functions;
          const data = await httpClient.post('/api/antidebug/hook_ntdll', body);
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'anti_vm': {
          const body: Record<string, unknown> = {
            module: args.module ?? '',
            max_hits: args.max_hits ?? 200,
            restore: args.restore ?? false,
          };
          if (args.arms?.length) body.arms = args.arms;
          const data = await httpClient.post('/api/antidebug/anti_vm', body);
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'kernel_status': {
          const data = await httpClient.get<KernelStatus>('/api/antidebug/kernel/status');
          // driver_present:false is the expected first-run answer, not a failure:
          // say what to do next instead of handing back a bare false.
          if (!data?.driver_present) {
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  ...data,
                  next_step:
                    'The kernel component is not loaded. Load the anti-debug driver ' +
                    '(the .sys next to the plugin, or its user_path once loaded) before kernel_attach/apply; ' +
                    'user-mode modes (harden, hook_ntdll, block_terminate) work without it. ' +
                    'kernel_status.version is only populated once the driver answers.',
                }, null, 2),
              }],
            };
          }
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'kernel_attach': {
          const data = await httpClient.post('/api/antidebug/kernel/attach', {
            pid: args.pid ?? '',
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'kernel_apply': {
          const body: Record<string, unknown> = { mask: args.mask ?? 0x7 };
          if (args.flags_offset !== undefined) body.flags_offset = args.flags_offset;
          if (args.cross_session_offset !== undefined) body.cross_session_offset = args.cross_session_offset;
          const data = await httpClient.post('/api/antidebug/kernel/apply', body);
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'kernel_detach': {
          const data = await httpClient.post('/api/antidebug/kernel/detach');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'artifacts': {
          const data = await antiVmArtifacts();
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
