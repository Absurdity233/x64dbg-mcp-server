import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';

const BP_TYPES = ['software', 'hardware', 'memory'] as const;

const breakpointSchema = {
  address: z.string(),
  bp_type: z.string().optional(),
  singleshot: z.boolean().optional(),
  hw_type: z.string().optional(),
  hw_size: z.string().optional(),
  mem_type: z.string().optional(),
  break_condition: z.string().optional(),
  command_condition: z.string().optional(),
  command_text: z.string().optional(),
  log_text: z.string().optional(),
  log_condition: z.string().optional(),
  silent: z.boolean().optional(),
  fast_resume: z.boolean().optional(),
  name: z.string().optional(),
};

export function registerBreakpointTools(server: McpServer) {
  server.tool(
    'x64dbg_breakpoints',
    'Breakpoint management. Actions: set_software, set_hardware, set_memory, delete, enable, disable, toggle, set_condition, set_log, reset_hit_count, get, list, configure, configure_batch.',
    {
      action: z.enum([
        'set_software', 'set_hardware', 'set_memory', 'delete', 'enable', 'disable',
        'toggle', 'set_condition', 'set_log', 'reset_hit_count', 'get', 'list',
        'configure', 'configure_batch',
      ]).describe('Operation to perform'),

      address: z.string().optional().describe('Breakpoint address'),
      condition: z.string().optional().describe("set_condition: expression, e.g. eax==0"),
      text: z.string().optional().describe('set_log: log format string'),

      // configure
      bp_type: z.enum(BP_TYPES).optional().describe("configure: breakpoint type (default software)"),
      singleshot: z.boolean().optional(),
      hw_type: z.enum(['r', 'w', 'x']).optional().describe('Hardware access type'),
      hw_size: z.enum(['1', '2', '4', '8']).optional().describe('Hardware access size'),
      mem_type: z.enum(['a', 'r', 'w', 'x']).optional().describe('Memory access type'),
      break_condition: z.string().optional(),
      command_condition: z.string().optional(),
      command_text: z.string().optional(),
      log_text: z.string().optional(),
      log_condition: z.string().optional(),
      silent: z.boolean().optional(),
      fast_resume: z.boolean().optional(),
      name: z.string().optional(),

      // configure_batch
      breakpoints: z.array(z.object(breakpointSchema)).optional().describe('configure_batch: array of breakpoint definitions'),

      // delete / configure
      type: z.enum(['software', 'hardware', 'memory', 'r', 'w', 'x', 'a']).optional().describe('delete: bp type; set_hardware/set_memory: access type'),
      size: z.enum(['1', '2', '4', '8']).optional().describe('set_hardware: access size'),
    },
    async (args) => {
      const { action, address, condition, text, breakpoints } = args;

      const requireAddress = () => requireString(address, 'address');

      switch (action) {
        case 'set_software': {
          const data = await httpClient.post('/api/breakpoints/set', {
            address: requireAddress(),
            singleshot: args.singleshot ?? false,
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'set_hardware': {
          const data = await httpClient.post('/api/breakpoints/set_hardware', {
            address: requireAddress(),
            type: (args.type as string) ?? 'x',
            size: args.size ?? '1',
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'set_memory': {
          const data = await httpClient.post('/api/breakpoints/set_memory', {
            address: requireAddress(),
            type: (args.type as string) ?? 'a',
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'delete': {
          const data = await httpClient.post('/api/breakpoints/delete', {
            address: requireAddress(),
            type: args.type,
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'enable':
        case 'disable':
        case 'toggle':
        case 'reset_hit_count': {
          const data = await httpClient.post(`/api/breakpoints/${action}`, { address: requireAddress() });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'set_condition': {
          const data = await httpClient.post('/api/breakpoints/set_condition', {
            address: requireAddress(),
            condition: requireString(condition, 'condition'),
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'set_log': {
          const data = await httpClient.post('/api/breakpoints/set_log', {
            address: requireAddress(),
            text: requireString(text, 'text'),
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'get': {
          const data = await httpClient.get('/api/breakpoints/get', { address: requireAddress() });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'list': {
          const data = await httpClient.get('/api/breakpoints/list');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'configure': {
          const body: Record<string, unknown> = { address: requireAddress() };
          for (const key of [
            'bp_type', 'singleshot', 'hw_type', 'hw_size', 'mem_type', 'break_condition',
            'command_condition', 'command_text', 'log_text', 'log_condition', 'silent',
            'fast_resume', 'name',
          ] as const) {
            if ((args as any)[key] !== undefined) body[key] = (args as any)[key];
          }
          const data = await httpClient.post('/api/breakpoints/configure', body);
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'configure_batch': {
          if (!Array.isArray(breakpoints)) throw new Error("'breakpoints' is required for this action");
          const data = await httpClient.post('/api/breakpoints/configure_batch', { breakpoints });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
