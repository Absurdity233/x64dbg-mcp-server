import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import {
  duplicateEndpoints,
  getDefaultInstance,
  listInstances,
  markDefaultChosen,
  setDefaultInstance,
  type InstanceEndpoint,
} from '../instances.js';
import { config } from '../config.js';
import { acquireLease, ownsLease, peekLease, releaseLease, takeOverLease } from '../lease.js';
import { ensureX64dbg, findInstanceProcess } from '../launcher.js';

import { requireString } from './util.js';

/** 'ours' | 'free' | the live holder. */
function leaseView(instance: InstanceEndpoint): unknown {
  if (ownsLease(instance.host, instance.port)) return 'ours';
  const holder = peekLease(instance.host, instance.port);
  if (!holder) return 'free';
  return {
    pid: holder.pid,
    host: holder.host,
    held_for_s: Math.round((Date.now() - holder.started_at) / 1000),
    idle_s: Math.round((Date.now() - (holder.last_call ?? holder.heartbeat)) / 1000),
  };
}

/** x64dbg's own pid and integrity level, when its executable is running. */
async function processView(instance: InstanceEndpoint): Promise<Record<string, unknown>> {
  const proc = await findInstanceProcess(instance);
  return proc ? { x64dbg_pid: proc.pid, x64dbg_elevated: proc.elevated } : {};
}

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
    'Inspect, start, and select x64dbg instances. Actions: list (every configured instance, whether its plugin answers, what it is debugging, its elevation, and who owns it), start (claim and launch an instance, optionally elevated, then make it the default), use (make a running instance the default), release (give up ownership), steal (take an endpoint from another live session; force skips the idle check), status (detail for one instance). Every other tool accepts an optional "instance" argument when more than one is configured.',
    {
      action: z.enum(['list', 'start', 'use', 'status', 'release', 'steal'])
        .describe('Operation to perform'),
      id: z.string().optional().describe('start/use/status/release/steal: instance id; start defaults to the current instance'),
      timeout_ms: z.number().int().min(1000).max(300000).optional()
        .describe('start: maximum time to wait for the plugin to come online (default 60000)'),
      elevated: z.boolean().optional().describe(
        'start: launch x64dbg with an elevated token (UAC, or the configured scheduled task). ' +
        'Default: the instance\'s "elevated" setting. An already-running medium-integrity process cannot be raised.'
      ),
      force: z.boolean().optional().describe(
        'steal: take the endpoint even while the holder is actively using it. Only for a stuck session - ' +
        'the previous owner\'s next call will conflict.'
      ),
    },
    async (args) => {
      switch (args.action) {
        case 'list': {
          const defaultId = getDefaultInstance().id;
          const dups = duplicateEndpoints();
          const rows = await Promise.all(
            listInstances().map(async (inst) => {
              const ep = `${inst.host}:${inst.port}`;
              return {
                id: inst.id,
                label: inst.label,
                endpoint: ep,
                x64dbgPath: inst.x64dbgPath,
                default: inst.id === defaultId,
                // Same endpoint as another id = same debugger. The lease is
                // keyed by endpoint, so only one of them can ever be used.
                ...(dups.has(ep) ? { shared_with: dups.get(ep)!.filter((x) => x !== inst.id) } : {}),
                lease: leaseView(inst),
                ...(await probe(inst)),
                ...(await processView(inst)),
              };
            })
          );
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({ default: defaultId, instances: rows }, null, 2),
            }],
          };
        }

        case 'start': {
          const id = args.id?.trim() || getDefaultInstance().id;
          const inst = listInstances().find((i) => i.id === id);
          if (!inst) {
            throw new Error(
              `Unknown x64dbg instance "${id}". Configured: ` +
              listInstances().map((i) => i.id).join(', ')
            );
          }

          // Starting an instance is also selecting it for this MCP process.
          // Claim first so two clients cannot both launch/drive the same copy.
          const alreadyOwned = ownsLease(inst.host, inst.port);
          if (config.lease && !alreadyOwned) {
            const got = acquireLease(inst.id, inst.host, inst.port);
            if (!got.ok) {
              const holder = got.holder;
              return {
                content: [{
                  type: 'text',
                  text: JSON.stringify({
                    id,
                    started: false,
                    ...(holder ? {
                      owner: {
                        pid: holder.pid,
                        host: holder.host,
                        held_for_s: Math.round((Date.now() - holder.started_at) / 1000),
                      },
                    } : {}),
                    message: `Instance "${id}" is already owned by another session.`,
                  }, null, 2),
                }],
                isError: true,
              };
            }
          }

          const elevated = args.elevated ?? inst.elevated ?? false;
          const result = await ensureX64dbg(inst, {
            timeoutMs: args.timeout_ms ?? 60_000,
            elevated,
          });
          if (!result.ok) {
            // Do not strand a lease when startup failed. Preserve a lease this
            // process already held before the call, since other work may use it.
            if (config.lease && !alreadyOwned) releaseLease(inst.host, inst.port);
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  id,
                  endpoint: `${inst.host}:${inst.port}`,
                  started: false,
                  process_launched: result.launched,
                  reason: result.reason,
                  ...(result.detail ? { detail: result.detail } : {}),
                  elevated_requested: elevated,
                  ...(await processView(inst)),
                  message:
                    result.reason === 'running-unelevated'
                      ? 'x64dbg is already running without elevation. Windows cannot raise an existing ' +
                        'process: close that window and call start again, or start x64dbg elevated yourself.'
                      : result.reason === 'uac-cancelled'
                        ? 'The UAC prompt was cancelled or dismissed.'
                        : result.reason === 'elevated-task-failed'
                          ? 'The configured elevated scheduled task could not be started. Run ' +
                            'scripts/install-elevated-task.ps1 once from an elevated PowerShell, or clear ' +
                            'X64DBG_MCP_ELEVATED_TASK to use a UAC prompt instead.'
                          : 'x64dbg did not expose the MCP plugin before the timeout. Check the ' +
                            'instance path, plugin installation, port, and auth token.',
                }, null, 2),
              }],
              isError: true,
            };
          }

          setDefaultInstance(id);
          markDefaultChosen();
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                id,
                endpoint: `${inst.host}:${inst.port}`,
                started: true,
                process_launched: result.launched,
                elevated_requested: elevated,
                default: true,
                lease: leaseView(inst),
                ...(await probe(inst)),
                ...(await processView(inst)),
              }, null, 2),
            }],
          };
        }

        case 'use': {
          const id = requireString(args.id, 'id');
          // Switching to an instance another session owns would make every
          // following call fail; say so here rather than one call later.
          const target = listInstances().find((i) => i.id === id);
          const holder = target && !ownsLease(target.host, target.port)
            ? peekLease(target.host, target.port)
            : null;
          if (holder) {
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  default: getDefaultInstance().id,
                  switched: false,
                  owner: { pid: holder.pid, host: holder.host, held_for_s: Math.round((Date.now() - holder.started_at) / 1000) },
                  message:
                    `"${id}" is owned by another session. Pick a free instance from action=list, ` +
                    'or ask that session to run action=release.',
                }, null, 2),
              }],
              isError: true,
            };
          }
          // Take the lease now rather than on the next call: "switch to X"
          // should fail here if X is taken, not one call later.
          if (!target) throw new Error(`Unknown x64dbg instance "${id}".`);
          if (config.lease && !ownsLease(target.host, target.port)) {
            const got = acquireLease(target.id, target.host, target.port);
            if (!got.ok) {
              return {
                content: [{
                  type: 'text',
                  text: JSON.stringify({
                    default: getDefaultInstance().id,
                    switched: false,
                    message: `"${id}" could not be leased; another session took it in the meantime.`,
                  }, null, 2),
                }],
                isError: true,
              };
            }
          }
          const inst = setDefaultInstance(id);
          // Also stops auto-assignment from overriding this choice later.
          markDefaultChosen();

          // Warn immediately instead of letting the next call burn the whole
          // wait budget on a debugger whose plugin is not running.
          const up = (await probe(inst)).reachable;
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                default: inst.id,
                endpoint: `${inst.host}:${inst.port}`,
                switched: true,
                plugin_answering: up,
                ...(up ? {} : {
                  warning: 'The MCP plugin is not answering on this instance yet. ' +
                    'Start that x64dbg (or its plugin) before calling, or calls will wait and fail.',
                }),
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
              text: JSON.stringify({
                id: inst.id,
                endpoint: `${inst.host}:${inst.port}`,
                lease: leaseView(inst),
                ...(await probe(inst)),
                ...(await processView(inst)),
              }, null, 2),
            }],
          };
        }

        case 'steal': {
          const id = requireString(args.id, 'id');
          const inst = listInstances().find((i) => i.id === id);
          if (!inst) {
            throw new Error(
              `Unknown x64dbg instance "${id}". Configured: ` +
              listInstances().map((i) => i.id).join(', ')
            );
          }
          if (!config.lease) {
            setDefaultInstance(id);
            markDefaultChosen();
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  id,
                  stolen: false,
                  default: id,
                  note: 'X64DBG_MCP_LEASE=off: ownership is not enforced, so there was nothing to take.',
                }, null, 2),
              }],
            };
          }

          const got = takeOverLease(inst.id, inst.host, inst.port, !!args.force);
          if (!got.ok) {
            const holder = got.holder;
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  id,
                  stolen: false,
                  ...(holder ? {
                    owner: {
                      pid: holder.pid,
                      host: holder.host,
                      held_for_s: Math.round((Date.now() - holder.started_at) / 1000),
                      idle_s: Math.round((Date.now() - (holder.last_call ?? holder.heartbeat)) / 1000),
                    },
                  } : {}),
                  message:
                    'The holder is still active. Pass force=true only if that session is stuck; ' +
                    'its next call will then conflict instead of silently sharing the debugger.',
                }, null, 2),
              }],
              isError: true,
            };
          }

          setDefaultInstance(id);
          markDefaultChosen();
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                id,
                endpoint: `${inst.host}:${inst.port}`,
                stolen: true,
                previous: got.previous
                  ? {
                      pid: got.previous.pid,
                      host: got.previous.host,
                      held_for_s: Math.round((Date.now() - got.previous.started_at) / 1000),
                    }
                  : null,
                default: id,
                lease: leaseView(inst),
                ...(await probe(inst)),
                ...(await processView(inst)),
              }, null, 2),
            }],
          };
        }

        case 'release': {
          const id = requireString(args.id, 'id');
          const inst = listInstances().find((i) => i.id === id);
          const owned = !!inst && ownsLease(inst.host, inst.port);
          if (inst && owned) releaseLease(inst.host, inst.port);
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                id,
                released: owned,
                note: owned
                  ? 'Another session can claim it now.'
                  : 'This process does not hold that lease.',
              }, null, 2),
            }],
          };
        }
      }
    }
  );
}
