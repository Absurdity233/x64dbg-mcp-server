import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { drain, describe, resetCursor, setCursor } from '../events.js';
import { requireString } from './util.js';
import { activeTrace, traceBlocked } from './trace_guard.js';

/**
 * First token of an x64dbg command that would disturb a live run-trace.
 * Raw `execute`/`script` is an escape hatch, so the server-side guard has to
 * inspect the command text itself - otherwise `x64dbg_command execute "pause"`
 * bypasses every check in x64dbg_debug.
 */
const TRACE_DESTRUCTIVE_COMMANDS = new Set([
  'pause', 'stop', 'stopdebug', 'stoptrace', 'stopruntrace',
  'restart', 'restartadmin', 'init', 'attach', 'detach', 'load', 'close', 'quit',
]);

function firstDestructiveStatement(text: string): string | null {
  for (const statement of text.split(/[;\r\n]+/)) {
    const first = statement.trim().split(/\s+/)[0]?.toLowerCase();
    if (first && TRACE_DESTRUCTIVE_COMMANDS.has(first)) return first;
  }
  return null;
}

async function commandTraceGuard(
  action: string,
  text: string,
  force?: boolean
): Promise<any | null> {
  if (force) return null;
  const keyword = firstDestructiveStatement(text);
  if (!keyword) return null;
  const st = await activeTrace();
  if (!st) return null;
  return traceBlocked(
    action,
    st,
    `The command starts with the trace-destructive keyword "${keyword}". ` +
    'Stop the trace first (x64dbg_tracing action=stop), or pass force:true.'
  );
}

export function registerCommandTools(server: McpServer) {
  server.tool(
    'x64dbg_command',
    'Escape hatch into x64dbg. Actions: execute, script, evaluate, format, set_init_script, get_init_script, get_hash, get_events, clear_events, watch, save_database, list_commands.',
    {
      action: z.enum([
        'execute', 'script', 'evaluate', 'format',
        'set_init_script', 'get_init_script', 'get_hash', 'get_events',
        'clear_events', 'watch', 'save_database', 'list_commands',
      ]).describe('Operation to perform'),
      command: z.string().optional().describe('execute: x64dbg command string'),
      commands: z.array(z.string()).optional().describe('script: array of x64dbg commands'),
      expression: z.string().optional().describe('evaluate: expression to resolve'),
      expressions: z.array(z.string()).optional().describe('watch: expressions to evaluate in one call'),
      format: z.string().optional().describe('format: format string for the x64dbg expression engine'),
      file: z.string().optional().describe('set_init_script: path to the init script'),
      category: z.string().optional().describe('list_commands: filter by category (control, breakpoints, memory, analysis, trace, misc)'),
      max_events: z.number().int().min(1).max(2000).optional()
        .describe('get_events: max events to return (default 200). The rest stay buffered for the next call.'),
      force: z.boolean().optional().describe(
        'execute/script: proceed even when the command would pause/stop/reload during a live trace. ' +
        'Without it such commands are refused because they can corrupt the debug engine.'
      ),
    },
    async (args) => {
      let data: any;
      switch (args.action) {
        case 'execute': {
          const command = requireString(args.command, 'command');
          const blocked = await commandTraceGuard('execute', command, args.force);
          if (blocked) return blocked;
          data = await httpClient.post('/api/command/exec', { command });
          break;
        }
        case 'script': {
          if (!Array.isArray(args.commands)) throw new Error("'commands' is required for this action");
          const blocked = await commandTraceGuard('script', args.commands.join('\n'), args.force);
          if (blocked) return blocked;
          data = await httpClient.post('/api/command/script', { commands: args.commands });
          break;
        }
        case 'evaluate':
          data = await httpClient.post('/api/command/eval', { expression: requireString(args.expression, 'expression') });
          break;
        case 'format':
          data = await httpClient.post('/api/command/format', { format: requireString(args.format, 'format') });
          break;
        case 'set_init_script':
          data = await httpClient.post('/api/command/init_script', { file: requireString(args.file, 'file') });
          break;
        case 'get_init_script':
          data = await httpClient.get('/api/command/init_script');
          break;
        case 'get_hash':
          data = await httpClient.get('/api/command/hash');
          break;
        case 'get_events': {
          const max = Math.min(Math.max(args.max_events ?? 200, 1), 2000);
          const { events, dropped } = await drain();
          const shown = events.slice(0, max);
          // drain() advanced the cursor past the whole batch. Rewind it to the
          // last event we are showing so the next get_events returns the rest
          // instead of silently dropping them.
          if (shown.length < events.length) {
            const last = shown[shown.length - 1]?.seq;
            if (typeof last === 'number') setCursor(last);
          }
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                count: events.length,
                returned: shown.length,
                truncated: shown.length < events.length,
                dropped,
                summary: shown.map(describe),
                events: shown,
              }, null, 2),
            }],
          };
        }
        case 'clear_events': {
          const res = await httpClient.post<any>('/api/command/clear_events');
          resetCursor();
          return { content: [{ type: 'text', text: JSON.stringify(res, null, 2) }] };
        }
        case 'watch': {
          if (!Array.isArray(args.expressions) || args.expressions.length === 0) {
            throw new Error("'expressions' is required for this action");
          }
          const values: Record<string, unknown> = {};
          for (const expr of args.expressions) {
            try {
              const res = await httpClient.post<any>('/api/command/eval', { expression: expr });
              values[expr] = res?.value ?? null;
            } catch (err) {
              values[expr] = { error: err instanceof Error ? err.message : String(err) };
            }
          }
          return { content: [{ type: 'text', text: JSON.stringify({ values }, null, 2) }] };
        }
        case 'save_database': {
          // Native x64dbg command that persists the .dd64/.dd32 database
          // (labels, comments, breakpoints, analysis). Not in the public SDK,
          // so it has to go through the command engine.
          data = await httpClient.post('/api/command/exec', { command: 'dbsave' });
          break;
        }
        case 'list_commands': {
          const cat = args.category?.toLowerCase();
          const catalog: Record<string, string[]> = {
            control: ['run', 'pause', 'stepinto', 'stepover', 'stepout', 'runtocursor', 'run_to', 'restart', 'stop', 'init', 'attach', 'detach'],
            breakpoints: ['bp', 'bph', 'bpm', 'bc', 'bd', 'be', 'bpx', 'bpe', 'SetBreakpointCondition', 'SetBreakpointLog', 'SetBreakpointCommand', 'SetBreakpointFastResume', 'DeleteAllBreakpoints'],
            memory: ['dump', 'alloc', 'free', 'memset', 'memcpy', 'memmapdump', 'savedata', 'strref', 'ref'],
            analysis: ['anal', 'analr', 'cfanal', 'exanal', 'analyse', 'xref', 'functionlist', 'find', 'findall', 'findmem', 'findmemall'],
            trace: ['TraceIntoConditional', 'TraceOverConditional', 'TraceSetLog', 'TraceSetLogFile', 'TraceSetCommand', 'TraceSetStepFilter', 'ticnd', 'tocnd', 'tracelog'],
            misc: ['log', 'clear', 'cls', 'scriptcmd', 'scriptload', 'scriptunload', 'loaddb', 'savedata', 'SetExceptionBPX', 'DeleteExceptionBPX'],
          };
          const out = cat ? { [cat]: catalog[cat] ?? [] } : catalog;
          return { content: [{ type: 'text', text: JSON.stringify({ categories: out, note: 'run any of these through action=execute' }, null, 2) }] };
        }
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
