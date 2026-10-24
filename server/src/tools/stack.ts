import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';

export function registerStackTools(server: McpServer) {
  server.tool(
    'x64dbg_stack',
    'Stack operations. Actions: get_call_stack, read, pointers, seh_chain, return_address, comment, arguments.',
    {
      action: z.enum(['get_call_stack', 'read', 'pointers', 'seh_chain', 'return_address', 'comment', 'arguments'])
        .describe('Operation to perform'),
      handle: z.string().optional().describe('get_call_stack: thread handle (hex); omit for the current thread'),
      max_depth: z.string().optional().describe('get_call_stack: depth (default 50)'),
      address: z.string().optional().describe("read: start address (default 'csp'); comment: address"),
      size: z.string().optional().describe('read: bytes to read (default 256)'),
      count: z.number().optional().describe('arguments: how many arguments to read (default 4)'),
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
        case 'arguments': {
          // x64 fastcall: rcx, rdx, r8, r9, then stack at rsp+0x28 (0x20 shadow
          // space + 8-byte return address). x86 cdecl: everything at esp+4.
          const regs = await httpClient.get<any>('/api/registers/all');
          const is64 = regs?.rip !== undefined;
          const count = Math.min(Math.max(args.count ?? 4, 1), 16);

          const values: Array<{ source: string; value: string }> = [];
          if (is64) {
            const order = ['rcx', 'rdx', 'r8', 'r9'];
            for (const r of order) {
              if (values.length >= count) break;
              values.push({ source: r, value: regs[r] });
            }
            if (values.length < count) {
              const rsp = parseInt(String(regs.rsp), 16);
              const stackArgs = count - values.length;
              const read = await httpClient.get<any>('/api/stack/read', {
                address: '0x' + (rsp + 0x28).toString(16),
                size: String(stackArgs * 8),
              });
              const hex = (read?.hex ?? '').replace(/\s+/g, '');
              const chunks = hex.match(/.{16}/g) ?? [];
              for (let i = 0; i < chunks.length && values.length < count; i++) {
                const le = chunks[i].match(/../g)!.reverse().join('');
                values.push({ source: `[rsp+0x${(0x28 + i * 8).toString(16)}]`, value: '0x' + le.toUpperCase() });
              }
            }
          } else {
            const esp = parseInt(String(regs.rsp ?? regs.esp), 16);
            const read = await httpClient.get<any>('/api/stack/read', {
              address: '0x' + (esp + 4).toString(16),
              size: String(count * 4),
            });
            const hex = (read?.hex ?? '').replace(/\s+/g, '');
            const chunks = hex.match(/.{8}/g) ?? [];
            for (let i = 0; i < chunks.length && values.length < count; i++) {
              const le = chunks[i].match(/../g)!.reverse().join('');
              values.push({ source: `[esp+0x${(4 + i * 4).toString(16)}]`, value: '0x' + le.toUpperCase() });
            }
          }

          return {
            content: [{
              type: 'text',
              text: JSON.stringify({ arch: is64 ? 'x64' : 'x86', convention: is64 ? 'fastcall' : 'cdecl', arguments: values }, null, 2),
            }],
          };
        }
      }
    }
  );
}
