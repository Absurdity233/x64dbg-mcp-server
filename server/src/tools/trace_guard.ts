import { httpClient } from '../http_client.js';

/**
 * Shared guard for operations that are destructive while a run-trace is live.
 *
 * In x64dbg, pausing while TraceIntoConditional/TraceOverConditional runs ends
 * the trace; issuing stop/StopRunTrace at that moment has left the debug engine
 * in a state that corrupted the next session. The trace tools know how to
 * unwind this (`/api/trace/stop` pauses first, then calls StopRunTrace), so
 * every entry point that can pause/stop/restart/reload points the caller there
 * instead of letting a generic command do damage.
 */

export interface TraceStatus {
  tracing?: boolean;
  file?: string;
  last_file?: string;
  message?: string;
}

export interface ToolResult {
  // The MCP SDK's handler type carries an open index signature; mirror it so a
  // traceBlocked() result can be returned directly from any tool handler.
  [key: string]: unknown;
  content: Array<{ type: 'text'; text: string }>;
  isError: true;
}

/** The live trace, or null when none is running / the plugin cannot answer. */
export async function activeTrace(): Promise<TraceStatus | null> {
  try {
    const st = await httpClient.get<TraceStatus>('/api/trace/status');
    return st?.tracing ? st : null;
  } catch {
    // Plugin down, no session, or an older plugin without /api/trace/status:
    // let the action itself produce the authoritative error.
    return null;
  }
}

export function traceBlocked(action: string, st: TraceStatus, hint: string): ToolResult {
  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        action,
        blocked: true,
        tracing: true,
        trace_file: st.file,
        message: `A trace is running. ${hint}`,
      }, null, 2),
    }],
    isError: true,
  };
}
