import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString, pageResult } from './util.js';

export function registerSymbolTools(server: McpServer) {
  server.tool(
    'x64dbg_symbols',
    'Symbols, labels, comments, bookmarks. Actions: resolve, address, search, list_module, get_label, set_label, get_comment, set_comment, bookmark. ' +
      'search and list_module can return thousands of rows - page them with offset/limit.',
    {
      action: z.enum([
        'resolve', 'address', 'search', 'list_module',
        'get_label', 'set_label', 'get_comment', 'set_comment', 'bookmark',
      ]).describe('Operation to perform'),

      name: z.string().optional().describe('resolve: symbol name'),
      address: z.string().optional().describe('address-based actions'),
      pattern: z.string().optional().describe('search: symbol pattern (substring)'),
      module: z.string().optional().describe('search/list_module: module name'),
      text: z.string().optional().describe('set_label/set_comment: new text'),
      set: z.boolean().optional().describe('bookmark: true to set (default), false to clear'),
      offset: z.number().int().min(0).optional().describe('search/list_module: skip this many rows (default 0)'),
      limit: z.number().int().min(1).max(5000).optional().describe('search/list_module: return at most this many rows (default 200)'),
      include_raw: z.boolean().optional().describe('Also return the unpaged plugin response'),
    },
    async (args) => {
      switch (args.action) {
        case 'resolve': {
          const data = await httpClient.get('/api/symbols/resolve', { name: requireString(args.name, 'name') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'address': {
          const data = await httpClient.get('/api/symbols/at', { address: requireString(args.address, 'address') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'search': {
          const params: Record<string, string> = { pattern: requireString(args.pattern, 'pattern') };
          if (args.module) params.module = args.module;
          const data = await httpClient.get('/api/symbols/search', params);
          const paged = pageResult(data, args.offset ?? 0, args.limit ?? 200);
          if (args.include_raw) return { content: [{ type: 'text', text: JSON.stringify({ paged, raw: data }, null, 2) }] };
          return { content: [{ type: 'text', text: JSON.stringify(paged, null, 2) }] };
        }
        case 'list_module': {
          const data = await httpClient.get('/api/symbols/list', { module: requireString(args.module, 'module') });
          const paged = pageResult(data, args.offset ?? 0, args.limit ?? 200);
          if (args.include_raw) return { content: [{ type: 'text', text: JSON.stringify({ paged, raw: data }, null, 2) }] };
          return { content: [{ type: 'text', text: JSON.stringify(paged, null, 2) }] };
        }
        case 'get_label': {
          const data = await httpClient.get('/api/labels/get', { address: requireString(args.address, 'address') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'set_label': {
          const data = await httpClient.post('/api/labels/set', {
            address: requireString(args.address, 'address'),
            text: requireString(args.text, 'text'),
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'get_comment': {
          const data = await httpClient.get('/api/comments/get', { address: requireString(args.address, 'address') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'set_comment': {
          const data = await httpClient.post('/api/comments/set', {
            address: requireString(args.address, 'address'),
            text: requireString(args.text, 'text'),
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'bookmark': {
          const data = await httpClient.post('/api/bookmarks/set', {
            address: requireString(args.address, 'address'),
            set: args.set ?? true,
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
