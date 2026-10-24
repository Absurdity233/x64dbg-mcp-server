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
          // The plugin parses `id` as a number, so coerce here - sending a
          // string throws a json type_error inside the handler.
          const raw = requireString(args.id, 'id');
          const id = Number(raw);
          if (!Number.isFinite(id)) throw new Error(`'id' must be a decimal thread id, got '${raw}'`);
          const data = await httpClient.post(`/api/threads/${args.action}`, { id });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
