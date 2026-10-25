import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import {
  getDefaultInstance,
  listInstances,
  setDefaultInstance,
  type InstanceEndpoint,
} from '../instances.js';
import { requireString } from './util.js';

/**
 * Inventory of the x64dbg processes this MCP server can drive.
 *
 * Probes use raw fetch with a short timeout on purpose: httpClient waits up to
 * two minutes for a plugin that is not there, which is right for a tool call
 * but wrong for "is instance B up?".
 */

interface Probe {
  reachable: boolean;
  error?: string;
  pid?: number;
  module?: string;
  state?: string;
  cip?: string;
}

async function fetchJson(
  inst: InstanceEndpoint,
  path: string,
  timeoutMs = 800
): Promise<any | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(`http://${inst.host}:${inst.port}${path}`, {
      headers: inst.token ? { Authorization: `Bearer ${inst.token}` } : {},
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    const body = (await res.json()) as any;
    return body?.success ? body.data : null;
  } catch {
    return null;
  }
}

async function probe(inst: InstanceEndpoint): Promise<Probe> {
  const health = await fetchJson(inst, '/api/health');
  if (health === null) return { reachable: false, error: 'no plugin answering' };

  const [info, state] = await Promise.all([
    fetchJson(inst, '/api/process/info'),
    fetchJson(inst, '/api/debug/state'),
  ]);

  return {
    reachable: true,
    pid: info?.pid ?? undefined,
    module: state?.module ?? undefined,
    state: state?.state ?? undefined,
    cip: state?.cip ?? undefined,
  };
}

export function registerInstanceTools(server: McpServer) {
  server.tool(
    'x64dbg_instances',
    'Inspect and select x64dbg instances. Actions: list (every configured instance, whether its plugin answers, and what it is debugging), use (make one the default for this MCP server process), status (detail for one instance). Every other tool accepts an optional "instance" argument when more than one is configured.',
    {
      action: z.enum(['list', 'use', 'status']).describe('Operation to perform'),
      id: z.string().optional().describe('use/status: instance id'),
    },
    async (args) => {
      switch (args.action) {
        case 'list': {
          const defaultId = getDefaultInstance().id;
          const rows = await Promise.all(
            listInstances().map(async (inst) => ({
              id: inst.id,
              label: inst.label,
              endpoint: `${inst.host}:${inst.port}`,
              x64dbgPath: inst.x64dbgPath,
              default: inst.id === defaultId,
              ...(await probe(inst)),
            }))
          );
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({ default: defaultId, instances: rows }, null, 2),
            }],
          };
        }

        case 'use': {
          const id = requireString(args.id, 'id');
          const inst = setDefaultInstance(id);
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                default: inst.id,
                endpoint: `${inst.host}:${inst.port}`,
                note: 'Applies to tool calls in this MCP server process that omit "instance".',
              }, null, 2),
            }],
          };
        }

        case 'status': {
          const id = requireString(args.id, 'id');
          const inst = listInstances().find((i) => i.id === id);
          if (!inst) {
            throw new Error(
              `Unknown x64dbg instance "${id}". Configured: ` +
              listInstances().map((i) => i.id).join(', ')
            );
          }
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({ id: inst.id, endpoint: `${inst.host}:${inst.port}`, ...(await probe(inst)) }, null, 2),
            }],
          };
        }
      }
    }
  );
}
