import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';

export function registerPatchTools(server: McpServer) {
  server.tool(
    'x64dbg_patches',
    'Byte patches. Actions: list, apply, restore, export.',
    {
      action: z.enum(['list', 'apply', 'restore', 'export']).describe('Operation to perform'),
      address: z.string().optional().describe('apply/restore: patch address'),
      bytes: z.string().optional().describe('apply: hex bytes to write'),
      module: z.string().optional().describe('export: module to export (default current)'),
      path: z.string().optional().describe('export: output file path'),
    },
    async (args) => {
      switch (args.action) {
        case 'list': {
          const data = await httpClient.get('/api/patches/list');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'apply': {
          const data = await httpClient.post('/api/patches/apply', {
            address: requireString(args.address, 'address'),
            bytes: requireString(args.bytes, 'bytes'),
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'restore': {
          const data = await httpClient.post('/api/patches/restore', { address: requireString(args.address, 'address') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'export': {
          const body: Record<string, string> = { path: requireString(args.path, 'path') };
          if (args.module) body.module = args.module;
          const data = await httpClient.post('/api/patches/export', body);
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
