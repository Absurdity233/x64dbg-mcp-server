import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';

export function registerHandleTools(server: McpServer) {
  server.tool(
    'x64dbg_handles',
    'Handles, TCP connections, windows, heaps. Actions: list_handles, list_tcp, list_windows, list_heaps, get_name, close.',
    {
      action: z.enum(['list_handles', 'list_tcp', 'list_windows', 'list_heaps', 'get_name', 'close'])
        .describe('Operation to perform'),
      handle: z.string().optional().describe('get_name/close: handle value'),
    },
    async (args) => {
      switch (args.action) {
        case 'list_handles':
        case 'list_tcp':
        case 'list_windows':
        case 'list_heaps': {
          const route = args.action === 'list_handles' ? 'list' : args.action.replace('list_', '');
          const data = await httpClient.get(`/api/handles/${route}`);
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'get_name': {
          const data = await httpClient.get('/api/handles/get', { handle: requireString(args.handle, 'handle') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'close': {
          const data = await httpClient.post('/api/handles/close', { handle: requireString(args.handle, 'handle') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
