import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';

export function registerMemoryTools(server: McpServer) {
  server.tool(
    'x64dbg_memory',
    'Memory operations. Actions: read, write, info, is_valid, is_code, allocate, free, protect, map, update_map, follow_pointer, dump.',
    {
      action: z.enum([
        'read', 'write', 'info', 'is_valid', 'is_code',
        'allocate', 'free', 'protect', 'map', 'update_map',
        'follow_pointer', 'dump',
      ]).describe('Operation to perform'),

      address: z.string().optional().describe('Hex string or expression'),
      size: z.string().optional().describe("read: size in bytes (default 256); allocate/protect: size in hex (default 0x1000); dump: byte count"),
      bytes: z.string().optional().describe("write: hex bytes (e.g. '90 90' or 'CC')"),
      verify: z.boolean().optional().describe('write: read back and verify (default false)'),
      protection: z.string().optional().describe("protect: e.g. 'PAGE_EXECUTE_READWRITE'"),
      depth: z.number().optional().describe('follow_pointer: dereference depth (default 1, max 16)'),
      file: z.string().optional().describe('dump: output file path'),
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
        case 'follow_pointer': {
          // Walk a pointer chain: read 8 bytes at each level, treat the value as
          // the next address. 32-bit targets use 4-byte pointers, so try 8 first
          // and fall back to 4 when the 8-byte value is not readable.
          const start = requireString(args.address, 'address');
          const depth = Math.min(Math.max(args.depth ?? 1, 1), 16);

          const chain: Array<{ level: number; address: string; value: string; error?: string }> = [];
          let current = start;

          for (let level = 0; level < depth; level++) {
            let read: any;
            try {
              read = await httpClient.get<any>('/api/memory/read', { address: current, size: '8' });
            } catch (err) {
              chain.push({
                level,
                address: current,
                value: '<unreadable>',
                error: err instanceof Error ? err.message : String(err),
              });
              break;
            }
            const hex = (read?.hex ?? '').replace(/\s+/g, '');
            if (hex.length < 8) {
              chain.push({ level, address: current, value: '<unreadable>', error: 'short read' });
              break;
            }
            // Little-endian 64-bit value.
            const bytes = hex.match(/../g) ?? [];
            const value = bytes.slice(0, 8).reverse().join('');
            chain.push({ level, address: current, value: '0x' + value.toUpperCase() });
            current = '0x' + value.toUpperCase();
            if (/^0x0+$/.test(current)) break;
          }

          return { content: [{ type: 'text', text: JSON.stringify({ start, depth, chain }, null, 2) }] };
        }
        case 'dump': {
          const data = await httpClient.post('/api/memory/dump', {
            address: requireString(args.address, 'address'),
            size: Number(args.size ?? '0x1000'),
            file: requireString(args.file, 'file'),
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
