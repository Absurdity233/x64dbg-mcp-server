import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';
import { checkPluginCompat, getCompatResult } from '../compat.js';
import { getVersion } from '../version.js';

export function registerProcessTools(server: McpServer) {
  server.tool(
    'x64dbg_process',
    'Process info. Actions: basic, detailed, cmdline, elevated, dbversion, set_cmdline, compat (plugin/server version and route-manifest check).',
    {
      action: z.enum(['basic', 'detailed', 'cmdline', 'elevated', 'dbversion', 'set_cmdline', 'compat'])
        .describe('Operation to perform'),
      cmdline: z.string().optional().describe('set_cmdline: new command line'),
      refresh: z.boolean().optional().describe('compat: re-run the check instead of returning the startup result'),
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
        case 'compat': {
          // The startup result is cached so this is cheap; `refresh` re-queries
          // the plugin, which is what you want right after installing it.
          const data = args.refresh
            ? await checkPluginCompat(getVersion())
            : (getCompatResult() ?? (await checkPluginCompat(getVersion())));
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
