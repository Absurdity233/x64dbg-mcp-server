import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';

export function registerRegisterTools(server: McpServer) {
  server.tool(
    'x64dbg_registers',
    'CPU registers. Actions: get_all, get_flags, get_avx512, get_specific, set.',
    {
      action: z.enum(['get_all', 'get_flags', 'get_avx512', 'get_specific', 'set'])
        .describe('Operation to perform'),
      name: z.string().optional().describe("get_specific/set: register name (e.g. 'rax', 'eip', 'dr0')"),
      value: z.string().optional().describe("set: new value (hex string or expression)"),
    },
    async (args) => {
      switch (args.action) {
        case 'get_all': {
          const data = await httpClient.get('/api/registers/all');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'get_flags': {
          const data = await httpClient.get('/api/registers/flags');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'get_avx512': {
          const data = await httpClient.get('/api/registers/avx512');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'get_specific': {
          const data = await httpClient.get('/api/registers/get', { name: requireString(args.name, 'name') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'set': {
          const data = await httpClient.post('/api/registers/set', {
            name: requireString(args.name, 'name'),
            value: requireString(args.value, 'value'),
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
