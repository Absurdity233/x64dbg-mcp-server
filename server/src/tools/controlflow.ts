import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';

export function registerControlFlowTools(server: McpServer) {
  server.tool(
    'x64dbg_control_flow',
    'Control-flow analysis. Actions: cfg, branch_dest, is_jump_taken, loops, func_type, add_function, delete_function.',
    {
      action: z.enum(['cfg', 'branch_dest', 'is_jump_taken', 'loops', 'func_type', 'add_function', 'delete_function'])
        .describe('Operation to perform'),
      address: z.string().optional().describe('Address to analyse (default cip); delete_function: function start'),
      start: z.string().optional().describe('add_function: function start address'),
      end: z.string().optional().describe('add_function: function end address'),
    },
    async (args) => {
      switch (args.action) {
        case 'cfg':
        case 'branch_dest':
        case 'is_jump_taken':
        case 'loops':
        case 'func_type': {
          // 'cfg' maps to /api/cfg/function (the CFG-producing route).
          const route = args.action === 'cfg' ? 'function' : args.action;
          const data = await httpClient.get(`/api/cfg/${route}`, { address: args.address ?? 'cip' });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'add_function': {
          const data = await httpClient.post('/api/cfg/add_function', {
            start: requireString(args.start, 'start'),
            end: requireString(args.end, 'end'),
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'delete_function': {
          const data = await httpClient.post('/api/cfg/delete_function', {
            address: requireString(args.address, 'address'),
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
