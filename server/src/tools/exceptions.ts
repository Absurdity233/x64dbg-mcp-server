import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';

export function registerExceptionTools(server: McpServer) {
  server.tool(
    'x64dbg_exceptions',
    'Exception breakpoints. Actions: set, delete, list, list_codes, skip.',
    {
      action: z.enum(['set', 'delete', 'list', 'list_codes', 'skip']).describe('Operation to perform'),
      code: z.string().optional().describe('Exception code in hex, e.g. C0000005'),
      chance: z.enum(['first', 'second', 'all']).optional().describe('set: break chance (default first)'),
    },
    async (args) => {
      switch (args.action) {
        case 'set': {
          const data = await httpClient.post('/api/exceptions/set_bp', {
            code: requireString(args.code, 'code'),
            chance: args.chance ?? 'first',
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'delete': {
          const data = await httpClient.post('/api/exceptions/delete_bp', { code: requireString(args.code, 'code') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'list': {
          const data = await httpClient.get('/api/exceptions/list_bps');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'list_codes': {
          const data = await httpClient.get('/api/exceptions/list_codes');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'skip': {
          const data = await httpClient.post('/api/exceptions/skip');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
