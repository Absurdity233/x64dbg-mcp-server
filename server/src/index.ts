#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { config } from './config.js';
import { httpClient } from './http_client.js';
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
      config.x64dbgPath = arg.slice('--x64dbg='.length);
    } else if (arg === '--no-launch') {
      launch = false;
    }
  }
  return { launch };
}

/**
 * Append a `[state] ...` line to every tool response, mirroring the duty1g
 * server's habit of telling you where the debugger is after each call.
 * Best-effort: a failure to read state never fails the tool call.
 */
function installStateLine(server: McpServer): { count: () => number } {
  const original = server.tool.bind(server) as (...a: any[]) => any;
  let registrations = 0;

  (server as any).tool = (...args: any[]) => {
    const handler = args[args.length - 1];
    if (typeof handler === 'function') {
      args[args.length - 1] = async (...callArgs: any[]) => {
        const result = await handler(...callArgs);
        // Handlers that already reported a precise state (e.g. run, which knows
        // whether the stop was stable) opt out to avoid contradicting themselves
        // with a stale sample taken a few milliseconds later.
        if (result && (result as any).skipStateLine) return result;
        try {
          const st = await httpClient.get<any>('/api/debug/state');
          let line = `[state] ${String(st.state).toUpperCase()}`;
          if (st.cip) line += ` at ${st.cip}`;
          if (st.module) line += ` (${st.module})`;
          if (st.label) line += ` | ${st.label}`;
          if (Array.isArray(result?.content)) {
            result.content.push({ type: 'text', text: line });
          }
          // Do not leak the internal opt-out flag to the client.
          delete (result as any).skipStateLine;
        } catch {
          // Plugin down or no session - skip the annotation.
        }
        return result;
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

  // Register all tools (wrapped so every response carries a [state] line)
  const counter = installStateLine(server);
  registerAllTools(server);

  // Connect via stdio (rock-solid transport, no connection drops)
  const transport = new StdioServerTransport();
  await server.connect(transport);

  // Log to stderr (stdout is used by MCP protocol)
  console.error(`[x64dbg-mcp] Server started (${counter.count()} tools), plugin expected at ${config.host}:${config.port}`);
  const timeout_desc = config.timeout > 0 ? `${config.timeout}ms` : 'none (waits indefinitely)';
  console.error(`[x64dbg-mcp] Timeout: ${timeout_desc}, Retries: ${config.retries}`);

  // Start x64dbg in the background if it is not already up. Deliberately not
  // awaited: the MCP handshake must not block on a GUI process launching.
  if (launch) {
    void ensureX64dbg().then(({ launched, ok }) => {
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
