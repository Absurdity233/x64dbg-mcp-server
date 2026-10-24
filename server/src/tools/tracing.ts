import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';

export function registerTracingTools(server: McpServer) {
  server.tool(
    'x64dbg_tracing',
    'Execution tracing. Actions: into, over, run, stop, status, animate, conditional_run, log_setup (write a trace log to file), hitcount, type, set_type, trace_thread (record the thread id and GetTickCount() in every row; the tick is what makes event alignment exact), step_filter (restrict tracing to a module), trace_all_threads (start a trace and tag rows with the current thread id). A run-trace only advances while the target runs: pausing ends it, so restart the trace after each resume.',
    {
      action: z.enum([
        'into', 'over', 'run', 'stop', 'status', 'animate',
        'conditional_run', 'log_setup', 'hitcount', 'type', 'set_type',
        'trace_thread', 'step_filter', 'trace_all_threads',
      ]).describe('Operation to perform'),

      condition: z.string().optional().describe('Break condition expression (into/over/conditional_run/log_setup)'),
      max_steps: z.string().optional().describe('Maximum number of steps (into/over)'),
      log_text: z.string().optional().describe('Per-step log format string'),
      log_condition: z.string().optional().describe('Condition for logging'),
      command_text: z.string().optional().describe('Per-step command to run'),
      command_condition: z.string().optional().describe('Condition for the command'),
      party: z.string().optional().describe('run: party / thread filter'),
      command: z.string().optional().describe('animate: x64dbg command to repeat while animating'),
      type: z.enum(['into', 'over']).optional().describe('conditional_run: trace mode (default into)'),
      file: z.string().optional().describe('log_setup: absolute path of the trace log file'),
      address: z.string().optional().describe('hitcount/type/set_type: address'),
      record_type: z.number().optional().describe('set_type: trace record type (default 0)'),
      tid: z.union([z.string(), z.number()]).optional().describe('trace_thread: thread id to switch to before tracing'),
      filter: z.string().optional().describe("step_filter: 'user', 'system', 'none', or a module name to restrict tracing to"),
      mode: z.enum(['into', 'over']).optional().describe('trace_thread: trace mode (default into)'),
    },
    async (args) => {
      const { action } = args;

      switch (action) {
        case 'into':
        case 'over': {
          const data = await httpClient.post(`/api/trace/${action}`, {
            condition: args.condition ?? '',
            max_steps: args.max_steps ?? '',
            log_text: args.log_text ?? '',
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'run': {
          const data = await httpClient.post('/api/trace/run', { party: args.party ?? '0' });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'stop': {
          const data = await httpClient.post('/api/trace/stop');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'status': {
          const data = await httpClient.get('/api/trace/status');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'animate': {
          const data = await httpClient.post('/api/trace/animate', {
            command: requireString(args.command, 'command'),
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'conditional_run': {
          const data = await httpClient.post('/api/trace/conditional_run', {
            break_condition: args.condition ?? '',
            log_text: args.log_text ?? '',
            log_condition: args.log_condition ?? '',
            command_text: args.command_text ?? '',
            command_condition: args.command_condition ?? '',
            type: args.type ?? 'into',
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'log_setup': {
          const data = await httpClient.post('/api/trace/log', {
            file: requireString(args.file, 'file'),
            text: args.log_text ?? '',
            condition: args.condition ?? '',
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'hitcount': {
          const data = await httpClient.get('/api/trace/record/hitcount', { address: requireString(args.address, 'address') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'type': {
          const data = await httpClient.get('/api/trace/record/type', { address: requireString(args.address, 'address') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'trace_thread':
        case 'trace_all_threads': {
          const data = await httpClient.post('/api/trace/thread', {
            mode: args.mode ?? 'into',
            condition: args.condition ?? '',
            max_steps: args.max_steps ?? '',
            log_text: args.log_text ?? '',
            file: args.file ?? '',
            include_tid: true,
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'step_filter': {
          const data = await httpClient.post('/api/trace/step_filter', {
            filter: requireString(args.filter, 'filter'),
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'set_type': {
          const data = await httpClient.post('/api/trace/record/set_type', {
            address: requireString(args.address, 'address'),
            type: args.record_type ?? 0,
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
