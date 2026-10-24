import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';

export function registerSearchTools(server: McpServer) {
  server.tool(
    'x64dbg_search',
    'Search. Actions: pattern (AOB), string, string_at, symbol_auto_complete, encode_type, memory (scan all committed readable memory - use for heap values the module-scoped search cannot see).',
    {
      action: z.enum(['pattern', 'string', 'string_at', 'symbol_auto_complete', 'encode_type', 'memory'])
        .describe('Operation to perform'),
      query: z.string().optional().describe("pattern: byte pattern (e.g. '48 89 5C ??'); string/symbol_auto_complete: text; string_at/encode_type: address"),
      address: z.string().optional().describe('pattern: start address'),
      size: z.string().optional().describe('pattern/encode_type: range size'),
      max_results: z.number().optional().describe('pattern/symbol_auto_complete: result cap'),
      module: z.string().optional().describe('string: module to search (empty = all)'),
      encoding: z.enum(['utf8', 'ascii', 'unicode', 'auto']).optional().describe('string/string_at: text encoding'),
      max_length: z.number().optional().describe('string_at: maximum string length (default 256)'),
    },
    async (args) => {
      switch (args.action) {
        case 'pattern': {
          const body: Record<string, unknown> = {
            pattern: requireString(args.query, 'query'),
            max_results: args.max_results ?? 1000,
          };
          if (args.address) body.address = args.address;
          if (args.size) body.size = args.size;
          const data = await httpClient.post('/api/search/pattern', body);
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'string': {
          const data = await httpClient.post('/api/search/string', {
            text: requireString(args.query, 'query'),
            module: args.module ?? '',
            encoding: args.encoding ?? 'utf8',
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'string_at': {
          const data = await httpClient.get('/api/search/string_at', {
            address: requireString(args.query, 'query'),
            encoding: args.encoding ?? 'auto',
            max_length: String(args.max_length ?? 256),
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'symbol_auto_complete': {
          const data = await httpClient.post('/api/search/auto_complete', {
            search: requireString(args.query, 'query'),
            max_results: args.max_results ?? 256,
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'memory': {
          const data = await httpClient.post('/api/search/memory', {
            pattern: requireString(args.query, 'query'),
            max_results: args.max_results ?? 100,
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'encode_type': {
          const data = await httpClient.get('/api/search/encode_type', {
            address: requireString(args.query, 'query'),
            size: args.size ?? '1',
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
