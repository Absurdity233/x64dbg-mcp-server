import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { httpClient } from '../http_client.js';
import { waitFor, describe, consume } from '../events.js';
import { requireString, quoteArg } from './util.js';

const SLEEP = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

interface DebugState {
  state: 'stopped' | 'running' | 'paused';
  cip?: string;
  module?: string;
  label?: string;
}

/** Poll /api/debug/state until `want` is reached or the deadline passes. */
async function waitForState(
  want: 'paused' | 'stopped' | 'active',
  timeout_ms: number,
  poll_ms: number
): Promise<{ reached: boolean; elapsed_ms: number; state: DebugState }> {
  const started = Date.now();
  let last: DebugState = { state: 'running' };

  for (;;) {
    last = await httpClient.get<DebugState>('/api/debug/state');
    const hit = want === 'active' ? last.state !== 'stopped' : last.state === want;
    if (hit) {
      return { reached: true, elapsed_ms: Date.now() - started, state: last };
    }
    if (Date.now() - started >= timeout_ms) {
      return { reached: false, elapsed_ms: Date.now() - started, state: last };
    }
    await SLEEP(poll_ms);
  }
}

/**
 * Native x64dbg syntax quirk: `attach <pid>` is rejected, while `attach .<pid>`
 * (the form the GUI's "find window" flow uses) attaches successfully. Try the
 * dotted form first and fall back to the bare pid.
 */
async function attachCommand(pid: string): Promise<{ command: string; exec: any }> {
  const dotted = `attach .${pid}`;
  const exec = await httpClient.post<any>('/api/command/exec', { command: dotted });
  if (exec?.success === true) return { command: dotted, exec };

  const bare = `attach ${pid}`;
  const second = await httpClient.post<any>('/api/command/exec', { command: bare });
  if (second?.success === true) return { command: bare, exec: second };

  return { command: dotted, exec };
}

export function registerDebugTools(server: McpServer) {
  server.tool(
    'x64dbg_debug',
    'Core debugger control. Actions: run, pause, force_pause, step_into, step_over, step_out, stop_debug, restart_debug, run_to_address, state, load, attach, detach, wait_for_pause (block until the target pauses, e.g. when you are waiting for a user to click through the GUI).',
    {
      action: z.enum([
        'run', 'pause', 'force_pause', 'step_into', 'step_over', 'step_out',
        'stop_debug', 'restart_debug', 'run_to_address', 'state',
        'load', 'attach', 'detach', 'wait_for_pause', 'wait_for_event',
      ]).describe('Operation to perform'),
      address: z.string().optional().describe("run_to_address: target address or expression"),
      path: z.string().optional().describe("load: absolute path of the executable to open"),
      cmdline: z.string().optional().describe("load: optional command line for the target"),
      pid: z.union([z.string(), z.number()]).optional().describe("attach: process id (decimal)"),
      timeout_ms: z.number().optional().default(120000).describe("wait_for_pause/wait_for_event: maximum time to block (default 120000)"),
      poll_ms: z.number().optional().default(200).describe("wait_for_pause/wait_for_event: state poll interval (default 200)"),
      include_health: z.boolean().optional().describe("state: also query plugin health"),
      event_types: z.array(z.string()).optional()
        .describe("wait_for_event: event types to match, e.g. ['breakpoint','exception']. Omit for any event."),
      match_address: z.string().optional()
        .describe("wait_for_event: only match events whose address equals this expression"),
    },
    async ({ action, address, path, cmdline, pid, timeout_ms, poll_ms, include_health, event_types, match_address }) => {
      let endpoint = '';
      let payload: any = undefined;

      switch (action) {
        case 'run': endpoint = '/api/debug/run'; break;
        case 'pause': endpoint = '/api/debug/pause'; break;
        case 'force_pause': endpoint = '/api/debug/force_pause'; break;
        case 'step_into': endpoint = '/api/debug/step_into'; break;
        case 'step_over': endpoint = '/api/debug/step_over'; break;
        case 'step_out': endpoint = '/api/debug/step_out'; break;
        case 'stop_debug': endpoint = '/api/debug/stop'; break;
        case 'restart_debug': endpoint = '/api/debug/restart'; break;

        case 'run_to_address':
          endpoint = '/api/debug/run_to';
          payload = { address: requireString(address, 'address') };
          break;

        case 'state': {
          const stateData = await httpClient.get('/api/debug/state');
          const result: any = { state: stateData };
          if (include_health) {
            try {
              result.health = await httpClient.get('/api/health');
            } catch {
              result.health = { error: 'Health check failed' };
            }
          }
          return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
        }

        // init/attach are native x64dbg commands; routing them through the
        // command endpoint keeps this a server-only change (no plugin rebuild).
        // Both are asynchronous: a newly launched target stops at the system
        // breakpoint, an attached one keeps running until something breaks.
        case 'load':
        case 'attach': {
          let command: string;
          let exec: any;

          if (action === 'load') {
            const file = requireString(path, 'path');
            command = cmdline ? `init ${quoteArg(file)}, ${quoteArg(cmdline)}` : `init ${quoteArg(file)}`;
            exec = await httpClient.post('/api/command/exec', { command });
          } else {
            if (pid === undefined) throw new Error("'pid' is required for this action");
            ({ command, exec } = await attachCommand(String(pid)));
          }

          // `init` always stops at the system breakpoint, so wait for 'paused'.
          // `attach` resumes the target, so 'active' is the best we can do -
          // waiting for 'paused' there would just burn the timeout.
          const want = action === 'load' ? 'paused' : 'active';
          const waited = await waitForState(want, timeout_ms ?? 30000, poll_ms ?? 200);

          // Consume the events this just produced (session_start, system
          // breakpoint, dll_load, ...). They are returned below so they stay
          // visible, but they no longer sit in the buffer to satisfy a later
          // wait_for_event.
          const startup = waited.reached ? await consume() : { events: [], dropped: 0 };

          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                action,
                command,
                exec,
                started: waited.reached,
                waited_ms: waited.elapsed_ms,
                state: waited.state,
                startup_events: startup.events.map(describe),
              }, null, 2),
            }],
          };
        }

        case 'detach':
          endpoint = '/api/command/exec';
          payload = { command: 'detach' };
          break;

        case 'wait_for_pause': {
          const result = await waitForState('paused', timeout_ms ?? 120000, poll_ms ?? 200);
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                reached: result.reached,
                waited_ms: result.elapsed_ms,
                ...(result.reached
                  ? { message: `Target paused after ${result.elapsed_ms}ms`, state: result.state }
                  : { message: `Timed out after ${result.elapsed_ms}ms waiting for the target to pause`, state: result.state }),
              }, null, 2),
            }],
          };
        }

        case 'wait_for_event': {
          const types = event_types && event_types.length ? new Set(event_types) : null;
          const wanted_addr = match_address?.toLowerCase();

          const res = await waitFor((ev) => {
            if (types && !types.has(ev.type)) return false;
            if (wanted_addr) {
              const ev_addr = typeof ev.address === 'string' ? ev.address.toLowerCase() : '';
              if (ev_addr !== wanted_addr) return false;
            }
            return true;
          }, timeout_ms ?? 120000, poll_ms ?? 200);

          // Snapshot the debugger state at the moment we return, so the caller
          // does not need a second round-trip to see where it stopped.
          let state: DebugState | null = null;
          try {
            state = await httpClient.get<DebugState>('/api/debug/state');
          } catch {
            state = null;
          }

          const summary = res.others.map(describe);
          if (res.matched) summary.push(`>> ${describe(res.matched)}`);

          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                reached: res.matched !== null,
                waited_ms: res.elapsed_ms,
                message: res.matched
                  ? `Matched ${res.matched.type} after ${res.elapsed_ms}ms`
                  : `Timed out after ${res.elapsed_ms}ms waiting for a matching event`,
                event: res.matched,
                skipped: res.others,
                skipped_count: res.others.length,
                dropped: res.dropped,
                summary,
                state,
              }, null, 2),
            }],
          };
        }
      }

      const data = await httpClient.post(endpoint, payload);
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
