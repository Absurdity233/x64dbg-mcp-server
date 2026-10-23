import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';

export function registerProcessTools(server: McpServer) {
  server.tool(
    'x64dbg_process',
    'Process info. Actions: basic, detailed, cmdline, elevated, dbversion, set_cmdline.',
    {
      action: z.enum(['basic', 'detailed', 'cmdline', 'elevated', 'dbversion', 'set_cmdline'])
        .describe('Operation to perform'),
      cmdline: z.string().optional().describe('set_cmdline: new command line'),
    },
    async (args) => {
      switch (args.action) {
        case 'basic':
        case 'detailed':
        case 'cmdline':
        case 'elevated':
        case 'dbversion': {
          const route = args.action === 'basic' || args.action === 'detailed' ? 'info' : args.action;
          const data = await httpClient.get(`/api/process/${route}`);
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'set_cmdline': {
          const data = await httpClient.post('/api/process/set_cmdline', { cmdline: requireString(args.cmdline, 'cmdline') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
