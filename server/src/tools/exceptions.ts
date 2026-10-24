import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';

export function registerExceptionTools(server: McpServer) {
  server.tool(
    'x64dbg_exceptions',
    'Exception breakpoints. Actions: set, delete, list, list_codes, skip, preset. ' +
    'preset applies a named bundle - "protected" demotes the fault codes that packed/virtualised ' +
    'binaries raise on purpose to second chance, so the target keeps running instead of stopping ' +
    'on every internal fault.',
    {
      action: z.enum(['set', 'delete', 'list', 'list_codes', 'skip', 'preset'])
        .describe('Operation to perform'),
      code: z.string().optional().describe('Exception code in hex, e.g. C0000005'),
      chance: z.enum(['first', 'second', 'all']).optional().describe('set: break chance (default first)'),
      preset: z.enum(['protected', 'none']).optional()
        .describe("preset: 'protected' demotes common fault codes to second chance; 'none' restores first chance"),
    },
    async (args) => {
      // Codes a virtualised/packed binary raises as normal control flow. Breaking
      // on these is what makes `run` stop every few milliseconds.
      const PROTECTED_CODES = [
        'C0000005', // access violation - the most common VM dispatch signal
        'C000001D', // illegal instruction
        'C0000094', // integer divide by zero
        'C0000095', // integer overflow
        'C0000096', // privileged instruction
        'C000008E', // float divide by zero
        'C000001E', // in-page error
        '80000003', // breakpoint instruction
        'E06D7363', // C++ exception
        'E0434352', // CLR exception
      ];

      switch (args.action) {
        case 'preset': {
          const name = args.preset ?? 'protected';
          const chance = name === 'protected' ? 'second' : 'first';
          const results: Array<{ code: string; ok: boolean }> = [];
          for (const code of PROTECTED_CODES) {
            try {
              await httpClient.post('/api/exceptions/set_bp', { code, chance });
              results.push({ code, ok: true });
            } catch {
              results.push({ code, ok: false });
            }
          }
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                preset: name,
                chance,
                applied: results.filter((r) => r.ok).length,
                total: results.length,
                codes: results,
                note: name === 'protected'
                  ? 'the target will no longer pause on first-chance faults; a genuine crash still stops on second chance'
                  : 'restored: the target pauses on first-chance faults again',
              }, null, 2),
            }],
          };
        }
        case 'set': {
          const data = await httpClient.post('/api/exceptions/set_bp', {
            code: requireString(args.code, 'code'),
            chance: args.chance ?? 'first',
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'delete': {
          const data = await httpClient.post('/api/exceptions/delete_bp', { code: requireString(args.code, 'code') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'list': {
          const data = await httpClient.get('/api/exceptions/list_bps');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'list_codes': {
          const data = await httpClient.get('/api/exceptions/list_codes');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'skip': {
          const data = await httpClient.post('/api/exceptions/skip');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
