import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerFunctionTools(server: McpServer) {
  server.tool(
    'x64dbg_functions',
    'Function discovery. Actions: list (paged, from x64dbg analysis), analyze (run analysis first - the list is empty until you do).',
    {
      action: z.enum(['list', 'analyze']).describe('Operation to perform'),
      module: z.string().optional().describe('Only return functions in this module'),
      address: z.string().optional().describe("analyze: analyze the function at this address (analr); omit to analyze the module (anal)"),
      mode: z.enum(['anal', 'analr', 'cfanal']).optional().describe('analyze: analysis command (default analr when address is given, else anal)'),
      offset: z.number().optional().describe('Skip this many matches (default 0)'),
      limit: z.number().optional().describe('Return at most this many (default 500, max 5000)'),
    },
    async (args) => {
      if (args.action === 'analyze') {
        const mode = args.mode ?? (args.address ? 'analr' : 'anal');
        const command = args.address ? `${mode} ${args.address}` : mode;
        const res = await httpClient.post('/api/command/exec', { command });
        return { content: [{ type: 'text', text: JSON.stringify({ command, result: res, hint: 'analysis runs asynchronously; call action=list again in a moment' }, null, 2) }] };
      }

      const params: Record<string, string> = {
        offset: String(args.offset ?? 0),
        limit: String(args.limit ?? 500),
      };
      if (args.module) params.module = args.module;

      const data = await httpClient.get('/api/functions/list', params);
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
