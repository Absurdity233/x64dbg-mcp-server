import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';

const DISCOVER_SOURCES = ['trace', 'events'] as const;

interface VmSection {
  name?: string;
  va?: string;
  size?: number;
  entropy?: number;
  exec?: boolean;
  image?: boolean;
  chars?: string;
}

interface VmCandidate {
  name?: string;
  va?: string;
  size?: number;
  entropy?: number;
  why?: string;
}

interface VmRegion {
  sections?: VmSection[];
  candidates?: VmCandidate[];
  note?: string;
}

interface VmDispatcher {
  address?: string;
  visits?: number;
  distinct_predecessors?: number;
  distinct_successors?: number;
  score?: number;
}

interface VmDiscover {
  steps?: number;
  unique_addrs?: number;
  dispatchers?: VmDispatcher[];
  note?: string;
}

interface VmHandler {
  id?: number | string;
  entry?: string;
  instruction_count?: number;
  hash?: string;
  hits?: number;
}

interface VmHandlers {
  dispatcher?: string;
  handlers?: VmHandler[];
  total?: number;
  truncated?: boolean;
  note?: string;
}

interface VmExceptionEvent {
  seq?: number;
  tick_ms?: number;
  type?: string;
  code?: string | number;
  address?: string;
}

interface VmExceptionFlow {
  events?: VmExceptionEvent[];
  pattern?: string;
  note?: string;
}

const DISPATCHER_NOTE =
  'A dispatcher is the address with the highest (visits x predecessor diversity) that branches into ' +
  '1-2 distinct successors: many paths converge on it, and it fans out to the next handler. ' +
  'Handlers feed back to that same dispatcher, which is why it is the anchor for handler extraction.';

export function registerVmProtectTools(server: McpServer) {
  server.tool(
    'x64dbg_vmprotect',
    'Virtualization-obfuscation (VMProtect/Themida-style) counter-analysis. Actions: region (per-section entropy/exec flags plus the sections that look like the VM body - high entropy, executable, not image-backed; default module = main module), discover (find the dispatcher from a trace file or the event log: highest visits x predecessor diversity with 1-2 distinct successors; source=trace needs trace_file, source=events reads the in-memory event log, since/top narrow the window), handlers (extract every handler reachable from a dispatcher: entry, instruction count, per-handler byte hash and hit count, truncated when max_handlers cuts the list), exception_flow (replay the exception log for exception-driven VMs - SEH/VEH handlers, INT3/SINGLE_STEP, guard-page and access-violation patterns; since is a tick, limit caps the returned events). Caveats: all four actions report evidence, not a verdict - high entropy alone is not proof, and a virtualiser with a per-run generated dispatcher needs a fresh discover for every run.',
    {
      action: z.enum(['region', 'discover', 'handlers', 'exception_flow']).describe('Operation to perform'),

      // region
      module: z.string().optional().describe('region/handlers: module name (default the main module)'),

      // discover
      source: z.enum(DISCOVER_SOURCES).optional().describe(
        'discover: trace reads a saved trace file, events reads the live event log ' +
        '(default: trace when trace_file is given, otherwise required).'
      ),
      trace_file: z.string().optional().describe('discover: absolute path of the trace log for source=trace'),
      since: z.string().optional().describe(
        'discover/exception_flow: only consider records after this tick (ms) or sequence number.'
      ),
      top: z.number().optional().describe('discover: number of dispatcher candidates to return (default 10)'),

      // handlers
      dispatcher: z.string().optional().describe('handlers: dispatcher address from discover'),
      max_handlers: z.number().optional().describe('handlers: handler cap (default 512)'),

      // exception_flow
      limit: z.number().optional().describe('exception_flow: cap on returned events (default 200)'),
    },
    async (args) => {
      switch (args.action) {
        case 'region': {
          const data = await httpClient.post<VmRegion>('/api/vm/region', {
            module: args.module ?? '',
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'discover': {
          // A trace_file without an explicit source is a trace; anything else
          // has to say which stream it means (the live event log has no file).
          const source = requireString(args.source ?? (args.trace_file ? 'trace' : undefined), 'source');
          const body: Record<string, unknown> = {
            source,
            since: args.since ?? '',
            top: args.top ?? 10,
          };
          if (source === 'trace') body.trace_file = requireString(args.trace_file, 'trace_file');
          const data = await httpClient.post<VmDiscover>('/api/vm/discover', body);
          const dispatchers = data?.dispatchers ?? [];
          const best = dispatchers[0];
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                ...data,
                dispatcher_note: DISPATCHER_NOTE,
                best_guess: best?.address
                  ? {
                    address: best.address,
                    visits: best.visits ?? 0,
                    distinct_predecessors: best.distinct_predecessors ?? 0,
                    distinct_successors: best.distinct_successors ?? 0,
                    score: best.score ?? 0,
                  }
                  : null,
              }, null, 2),
            }],
          };
        }
        case 'handlers': {
          const data = await httpClient.post<VmHandlers>('/api/vm/handlers', {
            dispatcher: requireString(args.dispatcher, 'dispatcher'),
            module: args.module ?? '',
            max_handlers: args.max_handlers ?? 512,
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'exception_flow': {
          const data = await httpClient.post<VmExceptionFlow>('/api/vm/exception_flow', {
            since: args.since ?? '',
            limit: args.limit ?? 200,
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
