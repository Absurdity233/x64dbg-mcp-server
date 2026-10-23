import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { drain, describe } from '../events.js';
import { requireString } from './util.js';

export function registerCommandTools(server: McpServer) {
  server.tool(
    'x64dbg_command',
    'Escape hatch into x64dbg. Actions: execute, script, evaluate, format, set_init_script, get_init_script, get_hash, get_events.',
    {
      action: z.enum([
        'execute', 'script', 'evaluate', 'format',
        'set_init_script', 'get_init_script', 'get_hash', 'get_events',
      ]).describe('Operation to perform'),
      command: z.string().optional().describe('execute: x64dbg command string'),
      commands: z.array(z.string()).optional().describe('script: array of x64dbg commands'),
      expression: z.string().optional().describe('evaluate: expression to resolve'),
      format: z.string().optional().describe('format: format string for the x64dbg expression engine'),
      file: z.string().optional().describe('set_init_script: path to the init script'),
    },
    async (args) => {
      let data: any;
      switch (args.action) {
        case 'execute':
          data = await httpClient.post('/api/command/exec', { command: requireString(args.command, 'command') });
          break;
        case 'script':
          if (!Array.isArray(args.commands)) throw new Error("'commands' is required for this action");
          data = await httpClient.post('/api/command/script', { commands: args.commands });
          break;
        case 'evaluate':
          data = await httpClient.post('/api/command/eval', { expression: requireString(args.expression, 'expression') });
          break;
        case 'format':
          data = await httpClient.post('/api/command/format', { format: requireString(args.format, 'format') });
          break;
        case 'set_init_script':
          data = await httpClient.post('/api/command/init_script', { file: requireString(args.file, 'file') });
          break;
        case 'get_init_script':
          data = await httpClient.get('/api/command/init_script');
          break;
        case 'get_hash':
          data = await httpClient.get('/api/command/hash');
          break;
        case 'get_events': {
          const { events, dropped } = await drain();
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                count: events.length,
                dropped,
                summary: events.map(describe),
                events,
              }, null, 2),
            }],
          };
        }
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
