import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerAntiDebugTools(server: McpServer) {
  server.tool(
    'x64dbg_antidebug',
    'Anti-debugging analysis. Actions: peb, teb, dep, hide_debugger (clears BeingDebugged/NtGlobalFlag and verifies by read-back), harden (also clears heap flags and the DR registers; reports what needs a kernel component), vm_probes (locates cpuid/rdtsc/sidt/str and other anti-VM instructions in a module - discovery only, nothing is patched), probe_breakpoints (arms a silent logging breakpoint on every probe found so each hit lands in the event log with its registers).',
    {
      action: z.enum(['peb', 'teb', 'dep', 'hide_debugger', 'harden', 'vm_probes', 'probe_breakpoints'])
        .describe('Operation to perform'),
      pid: z.string().optional().describe('peb: process id (default current)'),
      tid: z.string().optional().describe('teb: thread id (default current)'),
      module: z.string().optional().describe('vm_probes/probe_breakpoints: module name (default the main module)'),
      max_hits: z.number().optional().describe('vm_probes/probe_breakpoints: cap (default 200)'),
      log_text: z.string().optional().describe('probe_breakpoints: per-hit log format'),
      resume: z.boolean().optional().describe('probe_breakpoints: start the target after arming (default true)'),
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
      }
    }
  );
}
