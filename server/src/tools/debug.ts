import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { config } from '../config.js';
import { currentInstance } from '../context.js';
import { httpClient } from '../http_client.js';
import { waitFor, describe, consume, resetCursor } from '../events.js';
import { recordLaunch, launchInfo, breakpoints as sessionBreakpoints, noteRecovery } from '../session.js';
import { claimTarget, findTargetClaim, releaseTarget } from '../target_claims.js';
import { requireString, quoteArg } from './util.js';

const SLEEP = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

interface DebugState {
  state: 'stopped' | 'running' | 'paused';
  cip?: string;
  module?: string;
  label?: string;
}

/** Poll /api/debug/state until `want` is reached or the deadline passes. */
/**
 * Poll /api/debug/state until `want` is reached or the deadline passes.
 *
 * `stable_ms` guards against transient pauses: a breakpoint with an auto-run
 * command (logging breakpoints) pauses for a few milliseconds on every hit, and
 * treating that as "the target stopped" makes `run` return immediately. When
 * set, the state must stay put for that long before it counts.
 */
async function waitForState(
  want: 'paused' | 'stopped' | 'active' | 'not_running',
  timeout_ms: number,
  poll_ms: number,
  stable_ms = 0
): Promise<{ reached: boolean; elapsed_ms: number; state: DebugState }> {
  const started = Date.now();
  let last: DebugState = { state: 'running' };
  let stableSince: number | null = null;

  for (;;) {
    last = await httpClient.get<DebugState>('/api/debug/state');
    const hit =
      want === 'active' ? last.state !== 'stopped'
      : want === 'not_running' ? last.state !== 'running'
      : last.state === want;

    if (hit) {
      if (stable_ms <= 0) {
        return { reached: true, elapsed_ms: Date.now() - started, state: last };
      }
      const now = Date.now();
      if (stableSince === null) {
        stableSince = now;
      } else if (now - stableSince >= stable_ms) {
        return { reached: true, elapsed_ms: now - started, state: last };
      }
    } else {
      stableSince = null;
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

/**
 * Refuse to load a path another instance is already debugging.
 *
 * Most Windows programs resolve Config/, Logs/ and save files from the module
 * path, so two debuggers on the same exe overwrite each other. Returns a tool
 * result to pass through, or null when the load may proceed.
 */
function sharedTargetConflict(file: string): { content: Array<{ type: 'text'; text: string }>; isError: true } | null {
  if (config.allowSharedTarget) return null;
  const existing = findTargetClaim(file);
  if (!existing || existing.instance === currentInstance().id) return null;

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        action: 'load',
        path: file,
        loaded: false,
        conflict: { instance: existing.instance, pid: existing.pid, host: existing.host },
        message:
          `"${file}" is already being debugged by instance "${existing.instance}" ` +
          `(pid ${existing.pid}). Both runs would share Config/ and Logs/. ` +
          'Clone the folder with scripts/provision-target.ps1 and load the copy, ' +
          'or set X64DBG_MCP_ALLOW_SHARED_TARGET=1 if that is intended.',
      }, null, 2),
    }],
    isError: true as const,
  };
}

/** Record that this instance now owns `file`, keyed by the debuggee pid. */
async function claimLoadedTarget(file: string): Promise<void> {
  try {
    const info = await httpClient.get<{ pid?: number }>('/api/process/info');
    if (info?.pid) claimTarget(file, currentInstance().id, info.pid);
  } catch {
    // Advisory bookkeeping only - never fail a load over it.
  }
}

/** Actions that end/steal the session and therefore collide with a live trace. */
const TRACE_UNSAFE_ACTIONS = new Set([
  'pause', 'force_pause', 'stop_debug', 'restart_debug', 'detach', 'load', 'attach',
]);

interface TraceStatus {
  tracing?: boolean;
  file?: string;
  last_file?: string;
  message?: string;
}

/**
 * Refuse to pause/stop/load over a live run-trace.
 *
 * In x64dbg, pausing while TraceIntoConditional/TraceOverConditional is running
 * ends the trace, and issuing stop/StopRunTrace at that moment has left the
 * engine in a state that corrupted the next debug session. The trace tools know
 * how to unwind this (`/api/trace/stop` pauses first, then StopRunTrace), so
 * point the caller there instead of letting a generic pause/stop do damage.
 */
async function traceGuard(action: string, force?: boolean): Promise<any | null> {
  if (force || !TRACE_UNSAFE_ACTIONS.has(action)) return null;
  try {
    const st = await httpClient.get<TraceStatus>('/api/trace/status');
    if (!st?.tracing) return null;
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          action,
          blocked: true,
          tracing: true,
          trace_file: st.file,
          message:
            'A trace is running. Pausing or stopping the debugger here terminates the run-trace and ' +
            'has corrupted the debug engine in practice. Use x64dbg_tracing action=stop first ' +
            '(it pauses, then calls StopRunTrace), or pass force:true if you need to interrupt it.',
        }, null, 2),
      }],
      isError: true as const,
    };
  } catch {
    // Plugin down, no session, or an older plugin without /api/trace/status:
    // let the action itself produce the authoritative error.
    return null;
  }
}

export function registerDebugTools(server: McpServer) {
  server.tool(
    'x64dbg_debug',
    'Core debugger control. Actions: run, pause, force_pause, step_into, step_over, step_out, stop_debug, restart_debug, run_to_address, state, load, attach, detach, wait_for_pause (block until the target pauses, e.g. when you are waiting for a user to click through the GUI).',
    {
      action: z.enum([
        'run', 'pause', 'force_pause', 'step_into', 'step_over', 'step_out',
        'stop_debug', 'restart_debug', 'run_to_address', 'state',
        'load', 'attach', 'detach', 'wait_for_pause', 'wait_for_event', 'recover',
      ]).describe('Operation to perform'),
      address: z.string().optional().describe("run_to_address: target address or expression"),
      path: z.string().optional().describe("load: absolute path of the executable to open"),
      cmdline: z.string().optional().describe("load: optional command line for the target"),
      pid: z.union([z.string(), z.number()]).optional().describe("attach: process id (decimal)"),
      timeout_ms: z.number().optional().default(120000).describe("wait_for_pause/wait_for_event: maximum time to block (default 120000)"),
      poll_ms: z.number().optional().default(200).describe("wait_for_pause/wait_for_event: state poll interval (default 200)"),
      include_health: z.boolean().optional().describe("state: also query plugin health"),
      wait: z.boolean().optional().describe("run: block until the target stops again (default true). Set false for fire-and-forget."),
      stable_ms: z.number().optional().describe(
        "run: how long the stop must persist before it counts as stopped (default 400). " +
        "Raise it if auto-continuing logging breakpoints make run return too early."),
      event_types: z.array(z.string()).optional()
        .describe("wait_for_event: event types to match, e.g. ['breakpoint','exception']. Omit for any event."),
      match_address: z.string().optional()
        .describe("wait_for_event: only match events whose address equals this expression"),
      force: z.boolean().optional().describe(
        'pause/force_pause/stop_debug/restart_debug/detach/load/attach: proceed even while a trace is ' +
        'running. Without it the call is refused because interrupting a run-trace corrupts the engine.'
      ),
    },
    async ({ action, address, path, cmdline, pid, timeout_ms, poll_ms, include_health, event_types, match_address, wait, stable_ms, force }) => {
      let endpoint = '';
      let payload: any = undefined;

      const blockedByTrace = await traceGuard(action, force);
      if (blockedByTrace) return blockedByTrace;

      switch (action) {
        case 'pause': {
          // x64dbg's pause frequently loses the race against a running target
          // and is silently dropped. Retry a few times before giving up.
          let lastErr: unknown = null;
          for (let attempt = 0; attempt < 3; attempt++) {
            try {
              const res = await httpClient.post<any>('/api/debug/pause');
              if (res?.message === 'Already paused') {
                const st = await httpClient.get<DebugState>('/api/debug/state');
                return {
                  content: [{
                    type: 'text',
                    text: JSON.stringify({ message: 'Already paused', attempts: attempt + 1, state: st }, null, 2),
                  }],
                };
              }
              // Large virtualized targets can take several seconds to reach a
              // safe point, so allow a generous window per attempt.
              const waited = await waitForState('paused', 5000, 100);
              if (waited.reached) {
                return {
                  content: [{
                    type: 'text',
                    text: JSON.stringify({
                      message: `Paused after ${waited.elapsed_ms}ms`,
                      attempts: attempt + 1,
                      state: waited.state,
                      response: res,
                    }, null, 2),
                  }],
                };
              }
            } catch (err) {
              lastErr = err;
            }
          }
          throw new Error(
            `Could not pause the target after 3 attempts${lastErr ? `: ${lastErr instanceof Error ? lastErr.message : String(lastErr)}` : ''}. ` +
            'The target may be spinning in a fast-resume breakpoint loop - try force_pause.'
          );
        }

        case 'recover': {
          // Rebuild a dead session: reload the remembered target and re-arm the
          // breakpoints that were set through this server. Nothing else (labels,
          // patches) is restored - dump those with the module dumper if needed.
          const info = launchInfo();
          if (!info.path) {
            throw new Error('Nothing to recover: no target has been loaded through this server yet.');
          }

          const current = await httpClient.get<DebugState>('/api/debug/state');
          if (current.state !== 'stopped') {
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  recovered: false,
                  reason: `target is still alive (state=${current.state}) - nothing to rebuild`,
                  state: current,
                }, null, 2),
              }],
            };
          }

          const file = info.path;

          // recover reloads the binary exactly like load does, so it must go
          // through the same shared-target check - otherwise a crashed session
          // could be "recovered" onto an executable another instance is running.
          const guard = sharedTargetConflict(file);
          if (guard) return guard;

          const command = info.cmdline
            ? `init ${quoteArg(file)}, ${quoteArg(info.cmdline)}`
            : `init ${quoteArg(file)}`;
          await httpClient.post('/api/command/exec', { command });
          const started = await waitForState('paused', timeout_ms ?? 60000, poll_ms ?? 200);
          if (started.reached) await consume();
          if (started.reached) await claimLoadedTarget(file);

          const specs = sessionBreakpoints();
          const rearmed: Array<{ address: string; ok: boolean; error?: string }> = [];
          for (const spec of specs) {
            try {
              const body: Record<string, unknown> = {
                address: spec.address,
                bp_type: spec.kind,
                singleshot: spec.singleshot ?? false,
              };
              for (const k of ['hw_type', 'hw_size', 'mem_type', 'break_condition', 'command_condition',
                               'command_text', 'log_text', 'log_condition', 'silent', 'fast_resume', 'name'] as const) {
                if ((spec as any)[k] !== undefined) body[k] = (spec as any)[k];
              }
              await httpClient.post('/api/breakpoints/configure', body);
              rearmed.push({ address: spec.address, ok: true });
            } catch (err) {
              rearmed.push({ address: spec.address, ok: false, error: err instanceof Error ? err.message : String(err) });
            }
          }

          const n = noteRecovery();
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                recovered: started.reached,
                target: file,
                cmdline: info.cmdline,
                breakpoints_restored: rearmed.filter((r) => r.ok).length,
                breakpoints_failed: rearmed.filter((r) => !r.ok),
                recovery_count: n,
                state: started.state,
              }, null, 2),
            }],
          };
        }

        case 'run': {
          // Block by default so the caller learns where and why the target
          // stopped, instead of having to issue a separate wait. Pass
          // wait=false for fire-and-forget.
          const res = await httpClient.post<any>('/api/debug/run');
          if (wait === false) {
            return { content: [{ type: 'text', text: JSON.stringify(res, null, 2) }] };
          }

          // Require the stop to hold for a moment: logging breakpoints with an
          // auto-run command bounce through paused for ~1ms per hit, and a
          // naive poll would report the first of those as the target stopping.
          const waited = await waitForState(
            'not_running', timeout_ms ?? 120000, poll_ms ?? 200, stable_ms ?? 400
          );
          // Drain in both cases: on timeout the events still explain what the
          // target did while we waited (dll loads, breakpoint hits, exceptions).
          const events = await consume();
          const breakpointHits = events.events.filter((e) => e.type === 'breakpoint').length;

          let instruction: string | null = null;
          if (waited.state.state === 'paused') {
            try {
              const dis = await httpClient.get<any>('/api/disasm/at', { address: 'cip', count: '1' });
              instruction = dis?.instructions?.[0]?.instruction ?? null;
            } catch { /* non-fatal */ }
          }

          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                reached: waited.reached,
                waited_ms: waited.elapsed_ms,
                message: waited.reached
                  ? `Target stopped after ${waited.elapsed_ms}ms`
                  : `Timed out after ${waited.elapsed_ms}ms - target still running`,
                // When the stop was not stable, the last sample may have caught
                // a transient pause inside an auto-continuing breakpoint. Report
                // it as running rather than contradicting `reached`.
                state: waited.reached ? waited.state : { state: 'running' },
                ...(!waited.reached && breakpointHits > 0 ? {
                  note: `${breakpointHits} breakpoint hit(s) during the wait - the target is ` +
                        'bouncing through auto-continue breakpoints. Raise stable_ms or remove ' +
                        'the logging breakpoint to get a real stop.',
                } : {}),
                instruction,
                events: events.events.map(describe),
                dropped: events.dropped,
              }, null, 2),
            }],
            // This response already carries the state observed at the stop;
            // a fresh sample could catch a transient pause and contradict it.
            skipStateLine: true,
          } as any;
        }
        case 'force_pause': endpoint = '/api/debug/force_pause'; break;
        case 'step_into': endpoint = '/api/debug/step_into'; break;
        case 'step_over': endpoint = '/api/debug/step_over'; break;
        case 'step_out': endpoint = '/api/debug/step_out'; break;
        case 'stop_debug': {
          const res = await httpClient.post<any>('/api/debug/stop');
          // The next session clears the plugin buffer, but our cursor must not
          // lag behind or the first wait_for_event would replay old events.
          resetCursor();
          const info = launchInfo();
          if (info.path) releaseTarget(info.path);
          return { content: [{ type: 'text', text: JSON.stringify(res, null, 2) }] };
        }

        case 'restart_debug': {
          const res = await httpClient.post<any>('/api/debug/restart');
          // Restart is asynchronous: the new process takes a while to come up.
          // Wait until a session exists again, then consume the new session's
          // startup burst so later waits only see fresh events.
          const started = await waitForState('active', timeout_ms ?? 30000, poll_ms ?? 200);
          if (started.reached) await consume();
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                ...res,
                restarted: started.reached,
                waited_ms: started.elapsed_ms,
                state: started.state,
              }, null, 2),
            }],
          };
        }

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
          let loadedPath: string | null = null;

          if (action === 'load') {
            const file = requireString(path, 'path');
            loadedPath = file;

            const guard = sharedTargetConflict(file);
            if (guard) return guard;

            command = cmdline ? `init ${quoteArg(file)}, ${quoteArg(cmdline)}` : `init ${quoteArg(file)}`;
            exec = await httpClient.post('/api/command/exec', { command });
            // Remember how we started it so recover() can rebuild the session.
            recordLaunch(file, cmdline);
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

          // Record which live process owns this path. Keyed by the debuggee pid,
          // so the claim expires when the target dies even if the agent is still
          // running.
          if (loadedPath && waited.reached) await claimLoadedTarget(loadedPath);

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

        case 'detach': {
          const info = launchInfo();
          if (info.path) releaseTarget(info.path);
          endpoint = '/api/command/exec';
          payload = { command: 'detach' };
          break;
        }

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
          }, timeout_ms ?? 120000, poll_ms ?? 200, event_types);

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
