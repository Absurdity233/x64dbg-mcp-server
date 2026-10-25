#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { config } from './config.js';
import { httpClient } from './http_client.js';
import { runWithInstance } from './context.js';
import {
  applyX64dbgPathOverride,
  getDefaultInstance,
  getInstance,
  isMultiInstance,
  listInstances,
  type InstanceEndpoint,
} from './instances.js';
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
      // Every registration in this server uses (name, description, rawShape, handler).
      //
      // The instance parameter is only advertised when there is more than one
      // instance. Tool schemas ship to the model on every request, and the field
      // costs ~1k tokens across the 26 tools - not worth paying when there is
      // nothing to choose between.
      const schemaArg = args[2];
      if (isMultiInstance() && schemaArg && typeof schemaArg === 'object' && !(schemaArg as any)._def) {
        args[2] = {
          ...schemaArg,
          instance: z.string().optional().describe(
            'x64dbg instance id (see x64dbg_instances list). Default: this server\'s instance.'
          ),
        };
      }

      args[args.length - 1] = async (...callArgs: any[]) => {
        const raw = (callArgs[0] ?? {}) as Record<string, unknown>;
        let instance: InstanceEndpoint;
        try {
          instance = getInstance(typeof raw.instance === 'string' ? raw.instance : undefined);
        } catch (err) {
          return {
            content: [{ type: 'text', text: err instanceof Error ? err.message : String(err) }],
            isError: true,
          };
        }

        // Handlers do not need to know the field exists.
        const clean = { ...raw };
        delete clean.instance;

        return runWithInstance(instance, async () => {
          const result = await handler(clean, ...callArgs.slice(1));
          compactJsonBlocks(result);
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
  if (launch) {
    void ensureX64dbg(defaultInstance).then(({ launched, ok }) => {
      if (!ok && !launched) {
        console.error('[x64dbg-mcp] x64dbg is not running and could not be started. ' +
          'Set X64DBG_PATH or pass --x64dbg=<path>.');
      }
    });
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
    process.exit(0);
  };
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
}

main().catch((err) => {
  console.error('[x64dbg-mcp] Fatal error:', err);
  process.exit(1);
});
