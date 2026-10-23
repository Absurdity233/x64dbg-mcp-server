import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';

export function registerMemoryTools(server: McpServer) {
  server.tool(
    'x64dbg_memory',
    'Memory operations. Actions: read, write, info, is_valid, is_code, allocate, free, protect, map, update_map.',
    {
      action: z.enum([
        'read', 'write', 'info', 'is_valid', 'is_code',
        'allocate', 'free', 'protect', 'map', 'update_map',
      ]).describe('Operation to perform'),

      address: z.string().optional().describe('Hex string or expression'),
      size: z.string().optional().describe("read: size in bytes (default 256); allocate/protect: size in hex (default 0x1000)"),
      bytes: z.string().optional().describe("write: hex bytes (e.g. '90 90' or 'CC')"),
      verify: z.boolean().optional().describe('write: read back and verify (default false)'),
      protection: z.string().optional().describe("protect: e.g. 'PAGE_EXECUTE_READWRITE'"),
    },
    async (args) => {
      const { action } = args;

      switch (action) {
        case 'read': {
          const data = await httpClient.get('/api/memory/read', {
            address: requireString(args.address, 'address'),
            size: args.size ?? '256',
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'write': {
          const data = await httpClient.post('/api/memory/write', {
            address: requireString(args.address, 'address'),
            bytes: requireString(args.bytes, 'bytes'),
            verify: args.verify ?? false,
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'info': {
          const data = await httpClient.get('/api/memory/page_info', { address: requireString(args.address, 'address') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'is_valid': {
          const data = await httpClient.get('/api/memory/is_valid', { address: requireString(args.address, 'address') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'is_code': {
          const data = await httpClient.get('/api/memory/is_code', { address: requireString(args.address, 'address') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'allocate': {
          const data = await httpClient.post('/api/memory/allocate', { size: args.size ?? '0x1000' });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'free': {
          const data = await httpClient.post('/api/memory/free', { address: requireString(args.address, 'address') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'protect': {
          const data = await httpClient.post('/api/memory/protect', {
            address: requireString(args.address, 'address'),
            size: args.size ?? '0x1000',
            protection: requireString(args.protection, 'protection'),
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'map': {
          const data = args.address
            ? await httpClient.get('/api/memmap/at', { address: args.address })
            : await httpClient.get('/api/memmap/list');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'update_map': {
          const data = await httpClient.post('/api/memory/update_map');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
