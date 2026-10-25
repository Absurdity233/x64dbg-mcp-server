import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';

/** Default page size for the list actions. A real process has 300+ handles. */
const DEFAULT_LIMIT = 200;

/** The plugin names the array after the thing being listed. */
const LIST_KEYS = ['handles', 'connections', 'windows', 'heaps'];

export function registerHandleTools(server: McpServer) {
  server.tool(
    'x64dbg_handles',
    'Handles, TCP connections, windows, heaps. Actions: list_handles, list_tcp, list_windows, list_heaps, get_name, close.',
    {
      action: z.enum(['list_handles', 'list_tcp', 'list_windows', 'list_heaps', 'get_name', 'close'])
        .describe('Operation to perform'),
      handle: z.string().optional().describe('get_name/close: handle value'),
      limit: z.number().optional().describe(
        `list_*: entries to return (default ${DEFAULT_LIMIT}; 0 = all). A full handle list can be 60 KB, ` +
        'so it is paged by default - check "truncated" and page with offset.'
      ),
      offset: z.number().optional().describe('list_*: entries to skip (default 0)'),
      filter: z.string().optional().describe(
        'list_*: case-insensitive substring matched against type_name and name. ' +
        'Much cheaper than paging through 300 handles: filter:"Key" or filter:"\\\\Device".'
      ),
    },
    async (args) => {
      switch (args.action) {
        case 'list_handles':
        case 'list_tcp':
        case 'list_windows':
        case 'list_heaps': {
          const route = args.action === 'list_handles' ? 'list' : args.action.replace('list_', '');
          const data = await httpClient.get<any>(`/api/handles/${route}`);

          const key = LIST_KEYS.find((k) => Array.isArray(data?.[k]));
          if (!key) {
            return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
          }

          let all: any[] = data[key];
          if (args.filter) {
            const needle = args.filter.toLowerCase();
            all = all.filter((e) =>
              String(e?.type_name ?? '').toLowerCase().includes(needle) ||
              String(e?.name ?? '').toLowerCase().includes(needle) ||
              String(e?.class_name ?? '').toLowerCase().includes(needle)
            );
          }
          const offset = Math.max(0, args.offset ?? 0);
          const limit = args.limit === 0 ? all.length : (args.limit ?? DEFAULT_LIMIT);
          const page = all.slice(offset, offset + limit);

          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                total: all.length,
                offset,
                returned: page.length,
                truncated: offset + page.length < all.length,
                [key]: page,
              }, null, 2),
            }],
          };
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
