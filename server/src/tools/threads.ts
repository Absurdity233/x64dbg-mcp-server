import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';

export function registerThreadTools(server: McpServer) {
  server.tool(
    'x64dbg_threads',
    'Thread operations. Actions: list, current, count, info, teb, name, switch, suspend, resume.',
    {
      action: z.enum(['list', 'current', 'count', 'info', 'teb', 'name', 'switch', 'suspend', 'resume'])
        .describe('Operation to perform'),
      tid: z.string().optional().describe('Thread ID (decimal) for info/teb/name'),
      id: z.string().optional().describe('Thread ID (decimal) for switch/suspend/resume'),
    },
    async (args) => {
      switch (args.action) {
        case 'list': {
          const data = await httpClient.get('/api/threads/list');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'current': {
          const data = await httpClient.get('/api/threads/current');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'count': {
          const data = await httpClient.get('/api/threads/count');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'info': {
          const data = await httpClient.get('/api/threads/get', { id: requireString(args.tid, 'tid') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'teb':
        case 'name': {
          const data = await httpClient.get(`/api/threads/${args.action}`, { tid: requireString(args.tid, 'tid') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'switch':
        case 'suspend':
        case 'resume': {
          const data = await httpClient.post(`/api/threads/${args.action}`, { id: requireString(args.id, 'id') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
