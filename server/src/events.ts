import { httpClient } from './http_client.js';
import { config } from './config.js';

export interface DebugEvent {
  seq: number;
  tick_ms: number;
  type: string;
  [key: string]: unknown;
}

interface EventsResponse {
  events: DebugEvent[];
  count: number;
  latest_seq: number;
  dropped: number;
  timed_out?: boolean;
}

/**
 * Highest sequence number known to this client, so polls only return new
 * events. Module-level state: one MCP server process talks to one plugin.
 */
let cursor = 0;

export function currentCursor(): number {
  return cursor;
}

export function resetCursor(): void {
  cursor = 0;
}

function advance(res: EventsResponse): void {
  if (res.latest_seq > cursor) cursor = res.latest_seq;
}

/** Snapshot of everything buffered since the cursor. Does not block. */
export async function drain(): Promise<{ events: DebugEvent[]; dropped: number }> {
  try {
    const res = await httpClient.get<EventsResponse>('/api/command/events', {
      since: String(cursor),
    });
    advance(res);
    return { events: res.events ?? [], dropped: res.dropped ?? 0 };
  } catch {
    return { events: [], dropped: 0 };
  }
}

/**
 * Consume everything buffered and advance the cursor past it.
 *
 * Used right after starting a session: the startup burst (session_start,
 * dll_load x N, system_breakpoint) is returned to the caller so it is still
 * visible, but it is not left in the buffer to satisfy a later wait_for_event.
 */
export async function consume(): Promise<{ events: DebugEvent[]; dropped: number }> {
  return drain();
}

/**
 * Block until an event matches `predicate`, or the deadline passes.
 *
 * Uses the plugin's long-poll endpoint: one HTTP request parks on the plugin
 * side instead of the client polling every N ms. The request is re-issued when
 * the plugin returns a batch that contains no match (filtered wait), so a
 * `types` filter does not turn into a busy loop.
 */
export async function waitFor(
  predicate: (ev: DebugEvent) => boolean,
  timeout_ms: number,
  _poll_ms = 0,
  filterTypes?: string[]
): Promise<{
  matched: DebugEvent | null;
  others: DebugEvent[];
  elapsed_ms: number;
  dropped: number;
}> {
  const started = Date.now();
  const others: DebugEvent[] = [];
  let dropped = 0;

  while (true) {
    const remaining = timeout_ms - (Date.now() - started);
    if (remaining <= 0) {
      return { matched: null, others, elapsed_ms: Date.now() - started, dropped };
    }

    const params: Record<string, string> = {
      since: String(cursor),
      // Hold for at most eventHoldMs per request so a plugin restart is noticed
      // promptly, but never longer than the caller's remaining budget.
      timeout: String(Math.min(remaining, config.eventHoldMs)),
    };
    if (filterTypes && filterTypes.length) params.types = filterTypes.join(',');
    // Server-side waits park on a condition variable, so a single request can
    // return a whole burst; cap it so one huge module load cannot blow up the
    // tool response.
    params.max = String(config.eventBatchMax);

    let res: EventsResponse;
    try {
      res = await httpClient.get<EventsResponse>('/api/command/events/wait', params);
    } catch (err) {
      // Plugin gone or endpoint missing - fall back to a short sleep so we do
      // not spin, then let the next iteration fail or succeed.
      await new Promise((r) => setTimeout(r, Math.min(remaining, 500)));
      continue;
    }

    dropped += res.dropped ?? 0;
    advance(res);

    for (const ev of res.events ?? []) {
      if (predicate(ev)) {
        return { matched: ev, others, elapsed_ms: Date.now() - started, dropped };
      }
      others.push(ev);
    }

    // A single hold expiring is not the caller's deadline: keep re-issuing
    // until the overall timeout budget is spent. (The loop head checks it.)
    if (res.timed_out) continue;
  }
}

/** Human-readable one-liner for an event, used in tool output. */
export function describe(ev: DebugEvent): string {
  const parts = [`[${ev.seq}] ${ev.type}`];
  if (typeof ev.address === 'string') parts.push(`@ ${ev.address}`);
  if (typeof ev.name === 'string' && ev.name) parts.push(`(${ev.name})`);
  if (typeof ev.module === 'string' && ev.module) parts.push(`in ${ev.module}`);
  if (typeof ev.code === 'string') parts.push(`code=${ev.code}`);
  if (typeof ev.file === 'string' && ev.file) parts.push(ev.file);
  if (typeof ev.pid === 'number' && ev.pid) parts.push(`pid=${ev.pid}`);
  if (typeof ev.tid === 'number' && ev.tid) parts.push(`tid=${ev.tid}`);
  if (typeof ev.first_chance === 'boolean') parts.push(ev.first_chance ? 'first-chance' : 'second-chance');
  return parts.join(' ');
}
