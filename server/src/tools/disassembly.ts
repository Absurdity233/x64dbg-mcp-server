import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString, pageResult } from './util.js';

export function registerDisassemblyTools(server: McpServer) {
  server.tool(
    'x64dbg_disassembly',
    'Disassemble or assemble. Actions: at_address, function, info, assemble. ' +
      'function returns every instruction of the function, which on a large or ' +
      'obfuscated routine is enormous - page it with offset/limit.',
    {
      action: z.enum(['at_address', 'function', 'info', 'assemble']).describe('Operation to perform'),
      address: z.string().optional().describe("Address to start from (default 'cip')"),
      count: z.string().optional().describe('at_address: instruction count (default 10)'),
      max_instructions: z.number().optional().describe('function: plugin-side cap (default 50)'),
      // The plugin generates the whole function first; paging happens here so a
      // 500k-instruction VM dispatcher does not land in the model's context.
      offset: z.number().int().min(0).optional().describe('function: skip this many instructions (default 0)'),
      limit: z
        .number()
        .int()
        .min(1)
        .max(5000)
        .optional()
        .describe('function: return at most this many instructions (default 200)'),
      include_raw: z.boolean().optional().describe('Also return the unpaged plugin response'),
      instruction: z.string().optional().describe("assemble: mnemonic to write (e.g. 'nop')"),
    },
    async (args) => {
      switch (args.action) {
        case 'at_address': {
          const data = await httpClient.get('/api/disasm/at', {
            address: args.address ?? 'cip',
            count: args.count ?? '10',
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'function': {
          const data = await httpClient.get('/api/disasm/function', {
            address: args.address ?? 'cip',
            max_instructions: String(args.max_instructions ?? 50),
          });
          const paged = pageResult(data, args.offset ?? 0, args.limit ?? 200);
          if (args.include_raw) {
            return {
              content: [{ type: 'text', text: JSON.stringify({ paged, raw: data }, null, 2) }],
            };
          }
          return { content: [{ type: 'text', text: JSON.stringify(paged, null, 2) }] };
        }
        case 'info': {
          const data = await httpClient.get('/api/disasm/basic', { address: args.address ?? 'cip' });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'assemble': {
          const data = await httpClient.post('/api/disasm/assemble', {
            address: requireString(args.address, 'address'),
            instruction: requireString(args.instruction, 'instruction'),
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}