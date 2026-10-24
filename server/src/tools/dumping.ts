import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';

export function registerDumpingTools(server: McpServer) {
  server.tool(
    'x64dbg_dumping',
    'PE analysis, module dumping and IAT repair. Actions: pe_header, sections, imports, exports, entry_point, relocations, dump_module (flat memory copy), rebuild (loader-valid PE with realigned sections, fixed sizes and optional OEP), fix_iat (requires the Scylla plugin; fails loudly when absent), export_patch_file, detect_oep.',
    {
      action: z.enum([
        'pe_header', 'sections', 'imports', 'exports', 'entry_point',
        'relocations', 'dump_module', 'rebuild', 'fix_iat', 'export_patch_file', 'detect_oep',
      ]).describe('Operation to perform'),

      address: z.string().optional().describe('pe_header/relocations: address inside the PE'),
      module: z.string().optional().describe('module-based actions'),
      file: z.string().optional().describe('dump_module/rebuild: output path'),
      oep: z.string().optional().describe('fix_iat/rebuild: original entry point address'),
      filename: z.string().optional().describe('export_patch_file: output path for the .1337 patch file'),
      fix_section_flags: z.boolean().optional().describe('rebuild: clear MEM_WRITE from section flags (default true)'),
    },
    async (args) => {
      switch (args.action) {
        case 'pe_header':
        case 'relocations': {
          const data = await httpClient.get(`/api/dump/${args.action}`, { address: requireString(args.address, 'address') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'sections':
        case 'imports':
        case 'exports':
        case 'entry_point': {
          const data = await httpClient.get(`/api/dump/${args.action}`, { module: requireString(args.module, 'module') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'dump_module': {
          const data = await httpClient.post('/api/dump/module', {
            module: requireString(args.module, 'module'),
            file: args.file ?? '',
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'rebuild': {
          const data = await httpClient.post('/api/dump/rebuild', {
            module: requireString(args.module, 'module'),
            file: requireString(args.file, 'file'),
            oep: args.oep ?? '',
            fix_section_flags: args.fix_section_flags ?? true,
          });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'fix_iat': {
          const data = await httpClient.post('/api/dump/fix_iat', { oep: requireString(args.oep, 'oep') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'export_patch_file': {
          const data = await httpClient.post('/api/patches/export_file', { filename: requireString(args.filename, 'filename') });
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'detect_oep': {
          const data = await httpClient.get('/api/dump/detect_oep');
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
