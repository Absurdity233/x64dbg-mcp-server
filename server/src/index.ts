#!/usr/bin/env node
import { appendFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { config } from './config.js';
import { httpClient, PluginError } from './http_client.js';
import { runWithInstance } from './context.js';
import {
  applyX64dbgPathOverride,
  defaultChosen,
  getDefaultInstance,
  getInstance,
  isMultiInstance,
  listInstances,
  markDefaultChosen,
  setDefaultInstance,
  type InstanceEndpoint,
} from './instances.js';
import {
  acquireLease,
  describeHolder,
  ownsLease,
  peekLease,
  releaseAllLeases,
  touchLease,
} from './lease.js';
import { ensureX64dbg } from './launcher.js';
import { checkPluginCompat } from './compat.js';
import { getVersion } from './version.js';
import { registerAllTools } from './tools/index.js';

/**
 * Command-line overrides. Kept intentionally tiny - the launcher is a thin
 * wrapper, not a CLI. Supported:
 *   --x64dbg=<path>   path to x64dbg.exe (or its folder)
 *   --no-launch       never start x64dbg; only connect to a running instance
 */
function applyCliArgs(argv: string[]): { launch: boolean } {
  let launch = true;
  for (const arg of argv) {
    if (arg.startsWith('--x64dbg=')) {
      const path = arg.slice('--x64dbg='.length);
      config.x64dbgPath = path;
      applyX64dbgPathOverride(path);
    } else if (arg === '--no-launch') {
      launch = false;
    }
  }
  return { launch };
}

/**
 * Response size control.
 *
 * Every tool pretty-prints its JSON (131 call sites). That is pleasant for a
 * 150-byte reply and expensive for a 60 KB handle dump, which costs roughly
 * 17k tokens. Rather than rewriting every call site, re-serialise large JSON
 * blocks compactly here: 'auto' leaves anything under 2 KB readable, 'on'
 * compacts everything, 'off' disables it (X64DBG_MCP_COMPACT).
 */
const AUTO_COMPACT_BYTES = 2048;

function compactJsonBlocks(result: any): void {
  if (config.compact === 'off' || !Array.isArray(result?.content)) return;
  for (const block of result.content) {
    if (!block || block.type !== 'text' || typeof block.text !== 'string') continue;
    if (config.compact === 'auto' && block.text.length <= AUTO_COMPACT_BYTES) continue;
    const text = block.text.trim();
    if (!text.startsWith('{') && !text.startsWith('[')) continue;
    try {
      block.text = JSON.stringify(JSON.parse(text));
    } catch {
      // Not JSON (disassembly, OCR output) - leave it exactly as it is.
    }
  }
}

/**
 * Cap huge non-JSON text blocks (disassembly, OCR, raw dumps).
 *
 * JSON blocks are deliberately left alone: truncating a JSON document mid-way
 * makes it unparseable, and the list tools already page their results. Text
 * output has no such structure, so cut it at the last newline before the cap
 * and say how much was dropped.
 */
function truncateTextBlocks(result: any): void {
  const max = config.maxOutputBytes;
  if (!max || !Array.isArray(result?.content)) return;
  for (const block of result.content) {
    if (!block || block.type !== 'text' || typeof block.text !== 'string') continue;
    const text = block.text;
    if (text.length <= max) continue;
    const trimmed = text.trimStart();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) continue;

    const nl = text.lastIndexOf('\n', max);
    const end = nl > max * 0.8 ? nl : max;
    block.text =
      text.slice(0, end) +
      `\n...[truncated: ${end} of ${text.length} chars; raise X64DBG_MCP_MAX_BYTES]`;
  }
}

// ---------------------------------------------------------------------------
// Audit log for write actions
// ---------------------------------------------------------------------------

const AUDIT_LOG = join(tmpdir(), 'x64dbg-mcp', 'audit.log');

/** Actions that change debugger/target state, keyed by tool name. */
const WRITE_ACTIONS: Record<string, Set<string>> = {
  x64dbg_debug: new Set([
    'load', 'attach', 'detach', 'stop_debug', 'restart_debug', 'run', 'pause',
    'force_pause', 'step_into', 'step_over', 'step_out', 'run_to_address', 'recover',
  ]),
  x64dbg_memory: new Set(['write', 'allocate', 'free', 'protect']),
  x64dbg_patches: new Set(['apply', 'restore']),
  x64dbg_registers: new Set(['set']),
  x64dbg_breakpoints: new Set([
    'set_software', 'set_hardware', 'set_memory', 'delete', 'enable', 'disable',
    'toggle', 'set_condition', 'set_log', 'set_logging', 'configure',
    'configure_batch', 'reset_hit_count',
  ]),
  x64dbg_command: new Set(['execute', 'script', 'set_init_script', 'save_database', 'clear_events']),
  x64dbg_instances: new Set(['start', 'use', 'release', 'steal']),
  x64dbg_tracing: new Set([
    'into', 'over', 'run', 'stop', 'animate', 'conditional_run', 'log_setup',
    'step_filter', 'trace_thread', 'trace_all_threads', 'auto', 'auto_stop', 'set_type',
  ]),
  x64dbg_ui: new Set(['click', 'realclick', 'clicktext', 'typeinto', 'type', 'key']),
  x64dbg_exceptions: new Set(['set', 'delete', 'skip', 'preset']),
  x64dbg_antidebug: new Set(['hide_debugger', 'harden', 'probe_breakpoints']),
  x64dbg_dumping: new Set(['dump_module', 'rebuild', 'fix_iat', 'export_patch_file']),
  x64dbg_control_flow: new Set(['add_function', 'delete_function']),
  x64dbg_symbols: new Set(['set_label', 'set_comment', 'bookmark']),
  x64dbg_handles: new Set(['close']),
  x64dbg_process: new Set(['set_cmdline']),
};

function isWriteAction(tool: string, args: Record<string, unknown>): boolean {
  const action = typeof args.action === 'string' ? args.action : '';
  return WRITE_ACTIONS[tool]?.has(action) ?? false;
}

/**
 * Append one JSON line per write action. Opt-in via X64DBG_MCP_AUDIT=1 so the
 * default stays quiet. The full args are capped at 2 KB (a memory-write buffer
 * can be megabytes) and auditing never fails the tool call.
 */
function auditToolCall(
  tool: string,
  instance: InstanceEndpoint,
  args: Record<string, unknown>,
  result: any
): void {
  if (!config.audit || !isWriteAction(tool, args)) return;
  try {
    mkdirSync(dirname(AUDIT_LOG), { recursive: true });
    const raw = JSON.stringify(args);
    appendFileSync(AUDIT_LOG, JSON.stringify({
      ts: new Date().toISOString(),
      instance: instance.id,
      tool,
      action: typeof args.action === 'string' ? args.action : undefined,
      args: raw.length > 2000 ? `${raw.slice(0, 2000)}...` : raw,
      isError: !!result?.isError,
    }) + '\n');
  } catch {
    // Auditing is advisory bookkeeping; never fail a call because of it.
  }
}

/**
 * With several instances and no explicit default, take the first one nobody
 * else owns. Independent Claude Code sessions then land on different debuggers
 * without any per-session configuration. Done once, on the first call.
 */
// These two live in instances.ts so the "use" tool does not have to import
// this module, which would create a cycle (index -> tools -> index).

async function pluginAnswers(instance: InstanceEndpoint): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 700);
    const res = await fetch(`http://${instance.host}:${instance.port}/api/health`, {
      headers: instance.token ? { Authorization: `Bearer ${instance.token}` } : {},
      signal: controller.signal,
    });
    clearTimeout(timer);
    return res.ok;
  } catch {
    return false;
  }
}

async function autoAssignDefaultInstance(): Promise<void> {
  if (defaultChosen()) return;
  if (!config.lease || !isMultiInstance() || process.env.X64DBG_MCP_INSTANCE) {
    // Nothing to choose between: latch so this check is not repeated.
    markDefaultChosen();
    return;
  }

  const free = listInstances().filter((i) => ownsLease(i.host, i.port) || !peekLease(i.host, i.port));
  if (!free.length) {
    // Not latched: another session may release an instance a minute from now,
    // and this one should be able to pick it up instead of failing forever.
    console.error(
      '[x64dbg-mcp] every instance is leased by another session; will retry on the next call. ' +
      'Provision more instances, or set X64DBG_MCP_LEASE=off.'
    );
    return;
  }

  // Prefer one that is actually running: a leased-but-stopped instance would
  // just stall the first call for the whole wait budget.
  const probed = await Promise.all(free.map(async (i) => ({ i, up: await pluginAnswers(i) })));
  const alive = probed.filter((p) => p.up);
  // Claiming an instance whose plugin is not running means the very next call
  // stalls for the whole wait budget. Only fall back to a dead one when nothing
  // is alive, since the launcher may still start it.
  const ranked = alive.length ? alive : [...probed].sort((a, b) => Number(b.up) - Number(a.up));

  // Lease as part of claiming. Two sessions that both merely *pick* the same
  // free instance would race on the first real call and one would be blocked;
  // taking the lease here makes the choice atomic.
  for (const { i, up } of ranked) {
    if (!acquireLease(i.id, i.host, i.port).ok) continue;
    markDefaultChosen();
    setDefaultInstance(i.id);

    // A free but stopped instance used to be claimed and then fail on the very
    // next call after the whole wait budget. Start it here instead; the first
    // call already waits for the debugger either way.
    const started = !up && config.autoLaunch
      ? await ensureX64dbg(i, { timeoutMs: 60_000, elevated: i.elevated })
      : null;

    console.error(
      `[x64dbg-mcp] auto-claimed instance "${i.id}" for this session` +
      (up ? '' : started?.ok ? ' (started by the launcher)' : ' (WARNING: no plugin is answering)')
    );
    return;
  }
  console.error('[x64dbg-mcp] lost the race for every free instance; will retry on the next call.');
}

/**
 * One wrapper for every tool registration.
 *
 * It does three things the 25 tool files should not each have to know about:
 *
 *  1. Adds an optional `instance` parameter to the schema, so a model can name
 *     the x64dbg it wants when several are configured.
 *  2. Resolves that instance and runs the handler inside an AsyncLocalStorage
 *     context. Everything below (httpClient, event cursor, session record)
 *     reads the instance from there, which is why none of the ~160 HTTP call
 *     sites needed changing.
 *  3. Appends the `[state] ...` line, now naming the instance.
 *
 * An unknown instance id fails the call instead of falling back to the default:
 * silently driving the wrong target is the exact failure this exists to avoid.
 */
function installToolMiddleware(server: McpServer): { count: () => number } {
  const original = server.tool.bind(server) as (...a: any[]) => any;
  let registrations = 0;

  (server as any).tool = (...args: any[]) => {
    const handler = args[args.length - 1];
    if (typeof handler === 'function') {
      const registeredToolName = String(args[0]);
      // Every registration in this server uses (name, description, rawShape, handler).
      //
      // The instance parameter is only advertised when there is more than one
      // instance. Tool schemas ship to the model on every request, and the field
      // costs ~1k tokens across the 26 tools - not worth paying when there is
      // nothing to choose between.
      const schemaArg = args[2];
      if (
        registeredToolName !== 'x64dbg_instances' &&
        isMultiInstance() &&
        schemaArg &&
        typeof schemaArg === 'object' &&
        !(schemaArg as any)._def
      ) {
        args[2] = {
          ...schemaArg,
          instance: z.string().optional().describe(
            'x64dbg instance id (see x64dbg_instances list). Default: this server\'s instance.'
          ),
        };
      }

      args[args.length - 1] = async (...callArgs: any[]) => {
        const toolName = registeredToolName;
        const raw = (callArgs[0] ?? {}) as Record<string, unknown>;
        let instance: InstanceEndpoint;
        try {
          // Inventory is deliberately side-effect free. It manages leases in
          // its explicit start/use/release actions; list/status must not claim
          // a debugger merely because the user asked what is available.
          if (!raw.instance && toolName !== 'x64dbg_instances') {
            await autoAssignDefaultInstance();
          }
          instance = getInstance(typeof raw.instance === 'string' ? raw.instance : undefined);
        } catch (err) {
          return {
            content: [{ type: 'text', text: err instanceof Error ? err.message : String(err) }],
            isError: true,
          };
        }

        // Ownership, not just routing. x64dbg_instances is exempt: it is the
        // diagnostic used to find out who holds what.
        if (config.lease && toolName !== 'x64dbg_instances') {
          const lease = acquireLease(instance.id, instance.host, instance.port);
          if (!lease.ok) {
            const who = lease.holder ? describeHolder(lease.holder) : 'another process';
            const free = listInstances()
              .filter((i) => i.id !== instance.id && (ownsLease(i.host, i.port) || !peekLease(i.host, i.port)))
              .map((i) => i.id);
            const idleHint = config.leaseIdleMs > 0
              ? ` An idle session yields after ${Math.round(config.leaseIdleMs / 1000)}s.`
              : '';
            return {
              content: [{
                type: 'text',
                text:
                  `Instance "${instance.id}" is in use by ${who}. ` +
                  'Two models driving one x64dbg corrupt each other: breakpoints collide, one run ' +
                  'clears the other\'s paused state, and both event streams mix. ' +
                  `Free instance(s): ${free.join(', ') || 'none'}. ` +
                  `Use x64dbg_instances action=use id=<free>, wait, or ` +
                  `action=steal id="${instance.id}" force=true if that session is stuck.` +
                  idleHint,
              }],
              isError: true,
            };
          }
          touchLease(instance.host, instance.port);
        }

        // Handlers do not need to know the field exists.
        const clean = { ...raw };
        delete clean.instance;

        return runWithInstance(instance, async () => {
          let result: any;
          try {
            result = await handler(clean, ...callArgs.slice(1));
          } catch (err) {
            if (err instanceof PluginError) {
              const failure = {
                content: [{
                  type: 'text' as const,
                  text: JSON.stringify({
                    error: {
                      code: err.code,
                      message: err.message,
                      ...(err.hint ? { hint: err.hint } : {}),
                    },
                    tool: toolName,
                    instance: instance.id,
                  }, null, 2),
                }],
                isError: true as const,
              };
              auditToolCall(toolName, instance, clean, failure);
              return failure;
            }
            auditToolCall(toolName, instance, clean, { isError: true });
            throw err;
          }

          auditToolCall(toolName, instance, clean, result);
          compactJsonBlocks(result);
          truncateTextBlocks(result);
          // Instance inventory/startup already probes endpoints with a short,
          // bounded timeout. Appending the generic state line here would route
          // through HttpClient and make list/status wait up to two minutes when
          // the default debugger is intentionally offline.
          if (toolName === 'x64dbg_instances') return result;
          // Handlers that already reported a precise state (e.g. run, which
          // knows whether the stop was stable) opt out to avoid contradicting
          // themselves with a stale sample taken a few milliseconds later.
          if (result && (result as any).skipStateLine) {
            delete (result as any).skipStateLine;
            return result;
          }
          try {
            const st = await httpClient.get<any>('/api/debug/state');
            let line = `[state] ${String(st.state).toUpperCase()}`;
            if (st.cip) line += ` at ${st.cip}`;
            if (st.module) line += ` (${st.module})`;
            if (st.label) line += ` | ${st.label}`;
            line += ` [instance ${instance.id}]`;
            if (Array.isArray(result?.content)) {
              result.content.push({ type: 'text', text: line });
            }
          } catch {
            // Plugin down or no session - skip the annotation.
          }
          return result;
        });
      };
    }
    registrations++;
    return original(...args);
  };

  return { count: () => registrations };
}

async function main() {
  const { launch } = applyCliArgs(process.argv.slice(2));

  const server = new McpServer({
    name: 'x64dbg',
    version: getVersion(),
  });

  // Register all tools (wrapped for instance routing + the [state] line)
  const counter = installToolMiddleware(server);
  registerAllTools(server);

  // Connect via stdio (rock-solid transport, no connection drops)
  const transport = new StdioServerTransport();
  await server.connect(transport);

  // Log to stderr (stdout is used by MCP protocol)
  const instances = listInstances();
  const defaultInstance = getDefaultInstance();
  console.error(
    `[x64dbg-mcp] Server started (${counter.count()} tools), ` +
    `${instances.length} instance(s), default=${defaultInstance.id} ` +
    `(${defaultInstance.host}:${defaultInstance.port})`
  );
  if (isMultiInstance()) {
    console.error(
      `[x64dbg-mcp] Instances: ${instances.map((i) => `${i.id}@${i.host}:${i.port}`).join(', ')}. ` +
      'Every tool accepts an optional "instance" argument.'
    );
  }
  const timeout_desc = config.timeout > 0 ? `${config.timeout}ms` : 'none (waits indefinitely)';
  console.error(`[x64dbg-mcp] Timeout: ${timeout_desc}, Retries: ${config.retries}`);

  // Start x64dbg in the background if it is not already up. Deliberately not
  // awaited: the MCP handshake must not block on a GUI process launching.
  // Only the default instance is auto-started; the rest are started on demand
  // (or by the provisioning script) so N configured instances do not open N
  // GUI windows at every session start.
  if (launch && config.autoLaunch) {
    const holder = peekLease(defaultInstance.host, defaultInstance.port);
    if (holder && !ownsLease(defaultInstance.host, defaultInstance.port)) {
      // Two MCP servers starting together used to both spawn the default
      // x64dbg; one of the windows then could not bind the plugin port.
      console.error(
        `[x64dbg-mcp] ${defaultInstance.id} (${defaultInstance.host}:${defaultInstance.port}) ` +
        `is owned by pid ${holder.pid}; not starting a second x64dbg. ` +
        'A call will fail with the holder, or use x64dbg_instances action=list/use/steal.'
      );
    } else if (isMultiInstance()) {
      // Do not open a second GUI just because the default is stopped: if any
      // configured instance is already answering, the first tool call will
      // auto-claim that one. Starting the default unconditionally used to
      // leave two windows open when two sessions shared the same config.
      void (async () => {
        const up = (await Promise.all(instances.map((i) => pluginAnswers(i)))).some(Boolean);
        if (up) {
          console.error(
            '[x64dbg-mcp] another instance is already answering; not auto-starting the default. ' +
            'Instances start on demand (x64dbg_instances action=start).'
          );
          return;
        }
        const res = await ensureX64dbg(defaultInstance, {
          timeoutMs: 60_000,
          elevated: defaultInstance.elevated,
        });
        if (!res.ok) {
          console.error(
            `[x64dbg-mcp] ${defaultInstance.id} is not up: ${res.reason ?? 'launch failed'}` +
            (res.detail ? ` (${res.detail})` : '') +
            '. Set X64DBG_PATH, start it manually, or use x64dbg_instances action=start.'
          );
        }
      })();
    } else {
      void ensureX64dbg(defaultInstance, {
        timeoutMs: 60_000,
        elevated: defaultInstance.elevated,
      }).then((res) => {
        if (!res.ok) {
          console.error(
            `[x64dbg-mcp] ${defaultInstance.id} is not up: ${res.reason ?? 'launch failed'}` +
            (res.detail ? ` (${res.detail})` : '') +
            '. Set X64DBG_PATH, start it manually, or use x64dbg_instances action=start.'
          );
        }
      });
    }
  }

  // Compare the installed plugin's version and route table against what this
  // server expects. Runs after the handshake and after the launcher has had a
  // moment, and only warns - a pinned older plugin is a legitimate setup, and
  // this must never block startup.
  setTimeout(() => {
    void checkPluginCompat(getVersion()).then((compat) => {
      console.error(`[x64dbg-mcp] ${compat.message}`);
    });
  }, 1500);

  // Graceful shutdown
  const cleanup = () => {
    httpClient.destroy();
    releaseAllLeases();
    process.exit(0);
  };
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
}

main().catch((err) => {
  console.error('[x64dbg-mcp] Fatal error:', err);
  process.exit(1);
});
