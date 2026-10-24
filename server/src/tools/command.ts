import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { drain, describe, resetCursor } from '../events.js';
import { requireString } from './util.js';

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
    },
    async (args) => {
      let data: any;
      switch (args.action) {
        case 'execute':
          data = await httpClient.post('/api/command/exec', { command: requireString(args.command, 'command') });
          break;
        case 'script':
          if (!Array.isArray(args.commands)) throw new Error("'commands' is required for this action");
          data = await httpClient.post('/api/command/script', { commands: args.commands });
          break;
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
          const { events, dropped } = await drain();
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                count: events.length,
                dropped,
                summary: events.map(describe),
                events,
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
