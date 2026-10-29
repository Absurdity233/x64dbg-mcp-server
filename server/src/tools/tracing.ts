import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';
import { activeTrace, traceBlocked } from './trace_guard.js';

/** Actions that start a trace; starting a second one over a live trace is unsafe. */
const TRACE_START_ACTIONS = new Set([
  'into', 'over', 'run', 'animate', 'conditional_run',
  'trace_thread', 'trace_all_threads', 'auto',
]);

export function registerTracingTools(server: McpServer) {
  server.tool(
    'x64dbg_tracing',
    'Execution tracing. Actions: into/over/run/stop/status/animate/conditional_run/log_setup/hitcount/type/set_type/trace_thread/step_filter/trace_all_threads/auto/auto_status/auto_stop. A run-trace advances only while the target runs; pausing ends it (use auto for continuous tracing). Always stop a trace with action=stop, never by pausing the debugger.',
    {
      action: z.enum([
        'into', 'over', 'run', 'stop', 'status', 'animate',
        'conditional_run', 'log_setup', 'hitcount', 'type', 'set_type',
        'trace_thread', 'step_filter', 'trace_all_threads',
        'auto', 'auto_status', 'auto_stop',
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
      dir: z.string().optional().describe('auto: directory for numbered segment files (required)'),
      prefix: z.string().optional().describe('auto: segment file prefix (default seg)'),
      hold_ms: z.number().optional().describe('auto: dwell time after each pause before re-arming (default 0)'),
      max_segments: z.number().optional().describe('auto: stop after this many segments (0 = unlimited)'),
      force: z.boolean().optional().describe(
        'start actions (into/over/run/animate/conditional_run/trace_thread/trace_all_threads/auto): ' +
        'proceed even when a trace is already running. Without it the call is refused.'
      ),
    },
    async (args) => {
      const { action } = args;

      if (!args.force && TRACE_START_ACTIONS.has(action)) {
        const st = await activeTrace();
        if (st) {
          return traceBlocked(
            action,
            st,
            'Another trace is already running. Stop it with action=stop (or auto_stop) first, ' +
            'or pass force:true to start anyway.'
          );
        }
      }

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
        case 'auto': {
          const data = await httpClient.post('/api/trace/auto', {
            dir: requireString(args.dir, 'dir'),
            prefix: args.prefix ?? 'seg',
            condition: args.condition ?? '0',
            max_steps: args.max_steps ?? '',
            log_text: args.log_text ?? '',
            hold_ms: args.hold_ms ?? 0,
            max_segments: args.max_segments ?? 0,
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'auto_status': {
          const data = await httpClient.get('/api/trace/auto/status');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'auto_stop': {
          const data = await httpClient.post('/api/trace/auto/stop');
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
