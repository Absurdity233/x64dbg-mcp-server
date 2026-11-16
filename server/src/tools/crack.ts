import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { requireString } from './util.js';

const BRANCH_MODES = ['invert', 'always', 'never'] as const;
const IAT_MODES = ['succeed', 'fail', 'constant', 'restore'] as const;

interface BranchPatch {
  address?: string;
  mnemonic?: string;
  before?: string;
  after?: string;
  mode?: string;
  restored?: boolean;
}

interface SigMake {
  address?: string;
  bytes?: string;
  pattern?: string;
  unique?: boolean;
  candidates?: number;
}

interface IatRedirect {
  target?: string;
  resolved?: string;
  mode?: string;
  value?: string;
  patched?: Array<{ label?: string; address?: string; original_bytes?: string; patch_bytes?: string }>;
  restored?: boolean;
  note?: string;
}

interface CompareTraceHit {
  address?: string;
  instruction?: string;
  operands?: string;
  left?: string;
  right?: string;
  equal?: boolean;
  hits?: number;
}

interface CompareTrace {
  function?: string;
  sites?: number;
  hits?: CompareTraceHit[];
  total?: number;
  truncated?: boolean;
  note?: string;
}

export function registerCrackTools(server: McpServer) {
  server.tool(
    'x64dbg_crack',
    'Software-cracking and game-RE debugging. Actions: branch_patch (flip a conditional jump in place - invert swaps JZ/JNZ and friends, always forces the taken path, never forces the fall-through; restore:true writes the original bytes back; the response reports mnemonic, before and after bytes), sig_make (build a byte signature at address and verify it is unique in the module - relocatable and displacement bytes become ??, candidates tells you how many matches survived), iat_redirect (patch an import slot so a call returns a chosen value: succeed returns the success code, fail the failure code, constant returns value, restore puts the original bytes back; typical uses IsDebuggerPresent->succeed, GetTickCount->constant, a licence Check->succeed; target is a module!symbol or an address), compare_trace (arm logging breakpoints on every cmp/test inside the function at address and record both operands per hit, so a serial or licence comparison reads as a table instead of single-stepping; resume:true continues after arming, and the site is only as complete as the max_hits budget). Caveats: branch_patch and iat_redirect write to debuggee memory and are undone only by restore; a signature is unique for the module as loaded, so a re-based or re-packed build needs a fresh sig_make.',
    {
      action: z.enum(['branch_patch', 'sig_make', 'iat_redirect', 'compare_trace']).describe('Operation to perform'),

      // branch_patch / sig_make / compare_trace
      address: z.string().optional().describe(
        'branch_patch/sig_make: instruction address; compare_trace: any address inside the function.'
      ),
      mode: z.enum(BRANCH_MODES).optional().describe(
        'branch_patch: invert swaps the condition, always forces the jump, never forces the fall-through.'
      ),
      restore: z.boolean().optional().describe('branch_patch: write the original bytes back (mode is ignored).'),
      length: z.number().optional().describe('sig_make: byte count to read (default plugin-side, enough for a unique match)'),
      module: z.string().optional().describe('sig_make: module to verify uniqueness in (default the module at address)'),

      // iat_redirect
      target: z.string().optional().describe(
        'iat_redirect: symbol (module!Name) or the IAT slot address to patch.'
      ),
      value: z.string().optional().describe(
        'iat_redirect: hex value for mode=constant (e.g. "0x1000" or "0"); ignored for the other modes.'
      ),

      // compare_trace
      max_hits: z.number().optional().describe('compare_trace: cap on logged comparison hits (default plugin-side)'),
      log_text: z.string().optional().describe('compare_trace: per-hit log format override'),
      resume: z.boolean().optional().describe('compare_trace: resume the target after arming (default plugin-side)'),
    },
    async (args) => {
      switch (args.action) {
        case 'branch_patch': {
          const body: Record<string, unknown> = { address: requireString(args.address, 'address') };
          if (args.restore) {
            body.restore = true;
          } else {
            body.mode = requireString(args.mode, 'mode');
            body.restore = false;
          }
          const data = await httpClient.post<BranchPatch>('/api/crack/branch_patch', body);
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'sig_make': {
          const body: Record<string, unknown> = { address: requireString(args.address, 'address') };
          if (args.length !== undefined) body.length = args.length;
          if (args.module) body.module = args.module;
          const data = await httpClient.post<SigMake>('/api/crack/sig_make', body);
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'iat_redirect': {
          const body: Record<string, unknown> = {
            target: requireString(args.target, 'target'),
            mode: requireString(args.mode, 'mode'),
          };
          if (args.value !== undefined) body.value = args.value;
          const data = await httpClient.post<IatRedirect>('/api/crack/iat_redirect', body);
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
        case 'compare_trace': {
          const body: Record<string, unknown> = { address: requireString(args.address, 'address') };
          if (args.max_hits !== undefined) body.max_hits = args.max_hits;
          if (args.log_text) body.log_text = args.log_text;
          if (args.resume !== undefined) body.resume = args.resume;
          const data = await httpClient.post<CompareTrace>('/api/crack/compare_trace', body);
          return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
        }
      }
    }
  );
}
