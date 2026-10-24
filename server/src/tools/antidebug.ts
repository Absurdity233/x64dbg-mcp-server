import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';

export function registerAntiDebugTools(server: McpServer) {
  server.tool(
    'x64dbg_antidebug',
    'Anti-debugging analysis. Actions: peb, teb, dep, hide_debugger, harden (clears BeingDebugged, NtGlobalFlag, heap flags and the DR registers, and reports what needs a kernel component).',
    {
      action: z.enum(['peb', 'teb', 'dep', 'hide_debugger', 'harden']).describe('Operation to perform'),
      pid: z.string().optional().describe('peb: process id (default current)'),
      tid: z.string().optional().describe('teb: thread id (default current)'),
    },
    async (args) => {
      switch (args.action) {
        case 'peb': {
          const data = await httpClient.get('/api/antidebug/peb', { pid: args.pid ?? '' });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'teb': {
          const data = await httpClient.get('/api/antidebug/teb', { tid: args.tid ?? '' });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'dep': {
          const data = await httpClient.get('/api/antidebug/dep_status');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'hide_debugger': {
          const data = await httpClient.post('/api/antidebug/hide_debugger');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'harden': {
          const data = await httpClient.post('/api/antidebug/harden');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
