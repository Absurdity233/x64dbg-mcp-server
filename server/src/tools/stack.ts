import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';

export function registerStackTools(server: McpServer) {
  server.tool(
    'x64dbg_stack',
    'Stack operations. Actions: get_call_stack, read, pointers, seh_chain, return_address, comment.',
    {
      action: z.enum(['get_call_stack', 'read', 'pointers', 'seh_chain', 'return_address', 'comment'])
        .describe('Operation to perform'),
      handle: z.string().optional().describe('get_call_stack: thread handle (hex); omit for the current thread'),
      max_depth: z.string().optional().describe('get_call_stack: depth (default 50)'),
      address: z.string().optional().describe("read: start address (default 'csp'); comment: address"),
      size: z.string().optional().describe('read: bytes to read (default 256)'),
    },
    async (args) => {
      switch (args.action) {
        case 'get_call_stack': {
          const data = args.handle
            ? await httpClient.get('/api/stack/callstack_thread', { handle: args.handle })
            : await httpClient.get('/api/stack/trace', { max_depth: args.max_depth ?? '50' });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'read': {
          const data = await httpClient.get('/api/stack/read', {
            address: args.address ?? 'csp',
            size: args.size ?? '256',
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'pointers': {
          const data = await httpClient.get('/api/stack/pointers');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'seh_chain': {
          const data = await httpClient.get('/api/stack/seh_chain');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'return_address': {
          const data = await httpClient.get('/api/stack/return_address');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'comment': {
          const data = await httpClient.get('/api/stack/comment', { address: requireString(args.address, 'address') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
