import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';

export function registerModuleTools(server: McpServer) {
  server.tool(
    'x64dbg_modules',
    'Loaded modules. Actions: list, get_info, get_base, get_section, get_party.',
    {
      action: z.enum(['list', 'get_info', 'get_base', 'get_section', 'get_party']).describe('Operation to perform'),
      module: z.string().optional().describe('get_info/get_base: module name'),
      address: z.string().optional().describe('get_section: address inside the module'),
      base: z.string().optional().describe('get_party: module base address'),
    },
    async (args) => {
      switch (args.action) {
        case 'list': {
          const data = await httpClient.get('/api/modules/list');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'get_info': {
          const data = await httpClient.get('/api/modules/get', { name: requireString(args.module, 'module') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'get_base': {
          const data = await httpClient.get('/api/modules/base', { name: requireString(args.module, 'module') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'get_section': {
          const data = await httpClient.get('/api/modules/section', { address: requireString(args.address, 'address') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'get_party': {
          const data = await httpClient.get('/api/modules/party', { base: requireString(args.base, 'base') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
