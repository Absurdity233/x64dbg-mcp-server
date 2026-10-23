import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';

export function registerDisassemblyTools(server: McpServer) {
  server.tool(
    'x64dbg_disassembly',
    'Disassemble or assemble. Actions: at_address, function, info, assemble.',
    {
      action: z.enum(['at_address', 'function', 'info', 'assemble']).describe('Operation to perform'),
      address: z.string().optional().describe("Address to start from (default 'cip')"),
      count: z.string().optional().describe('at_address: instruction count (default 10)'),
      max_instructions: z.number().optional().describe('function: cap (default 50)'),
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
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
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
