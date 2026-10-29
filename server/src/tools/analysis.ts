import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { pageResult } from './util.js';

export function registerAnalysisTools(server: McpServer) {
  server.tool(
    'x64dbg_analysis',
    'Get function info, xrefs, basic blocks or source location for an address',
    {
      action: z.enum(['function', 'xrefs_to', 'xrefs_from', 'basic_blocks', 'source', 'mnemonic_brief']).describe('Information to get'),
      query: z.string().optional().default('cip').describe('Address to look up (or mnemonic for mnemonic_brief)'),
      limit: z.number().int().min(1).max(5000).optional().describe('xrefs_to/xrefs_from/basic_blocks: max items (default 500)'),
      offset: z.number().int().min(0).optional().describe('xrefs_to/xrefs_from/basic_blocks: skip this many items'),
    },
    async ({ action, query, limit, offset }) => {
      let data: any;
      switch (action) {
        case 'function': data = await httpClient.get('/api/analysis/function', { address: query }); break;
        case 'xrefs_to': data = await httpClient.get('/api/analysis/xrefs_to', { address: query }); break;
        case 'xrefs_from': data = await httpClient.get('/api/analysis/xrefs_from', { address: query }); break;
        case 'basic_blocks': data = await httpClient.get('/api/analysis/basic_blocks', { address: query }); break;
        case 'source': data = await httpClient.get('/api/analysis/source', { address: query }); break;
        case 'mnemonic_brief': data = await httpClient.get('/api/analysis/mnemonic_brief', { mnemonic: query }); break;
      }
      // Only the list-shaped responses are paged; function/source objects are
      // left exactly as the plugin returned them.
      const pageable = action === 'xrefs_to' || action === 'xrefs_from' || action === 'basic_blocks';
      const out = pageable ? pageResult(data, offset ?? 0, limit ?? 500) : data;
      return { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_database',
    'List known constants, error codes, defined structs, or search strings in a module',
    {
      action: z.enum(['constants', 'error_codes', 'structs', 'strings']).describe('Type of list to retrieve'),
      module: z.string().optional().describe('Module name (required for strings action)'),
      limit: z.number().int().min(1).max(5000).optional().describe('max items (default 500)'),
      offset: z.number().int().min(0).optional().describe('skip this many items'),
    },
    async ({ action, module, limit, offset }) => {
      let data: any;
      switch (action) {
        case 'constants': data = await httpClient.get('/api/analysis/constants'); break;
        case 'error_codes': data = await httpClient.get('/api/analysis/error_codes'); break;
        case 'structs': data = await httpClient.get('/api/analysis/structs'); break;
        case 'strings':
          if (!module) throw new Error("module is required for strings action");
          data = await httpClient.get('/api/analysis/strings', { module });
          break;
      }
      // The plugin caps strings at 5000; constants/structs can also be large.
      const out = pageResult(data, offset ?? 0, limit ?? 500);
      return { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_address_convert',
    'Convert Virtual Address (VA) to File Offset, or File Offset to VA',
    {
      action: z.enum(['va_to_file', 'file_to_va']).describe('Conversion direction'),
      address: z.string().optional().describe('Virtual address (required for va_to_file)'),
      module: z.string().optional().describe('Module name (required for file_to_va)'),
      offset: z.string().optional().describe('File offset hex (required for file_to_va)')
    },
    async ({ action, address, module, offset }) => {
      let data: any;
      if (action === 'va_to_file') {
        if (!address) throw new Error("address is required for va_to_file");
        data = await httpClient.get('/api/analysis/va_to_file', { address });
      } else {
        if (!module || !offset) throw new Error("module and offset required for file_to_va");
        data = await httpClient.get('/api/analysis/file_to_va', { module, offset });
      }
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.tool(
    'x64dbg_watchdog',
    'Check if a watch expression watchdog has been triggered',
    {
      id: z.string().optional().default('0').describe('Watch ID (decimal)'),
    },
    async ({ id }) => {
      const data = await httpClient.get('/api/analysis/watch', { id });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
