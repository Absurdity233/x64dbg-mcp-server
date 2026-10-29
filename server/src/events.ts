import { httpClient } from './http_client.js';
import { config } from './config.js';
import { currentInstance } from './context.js';

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
  /** The plugin buffered more events than this batch carried. */
  has_more?: boolean;
  dropped: number;
  timed_out?: boolean;
}

/**
 * Highest sequence number handed to the caller, per x64dbg endpoint.
 *
 * Keyed by endpoint, not by instance id: two ids can name one debugger, and
 * then two cursors would advance independently over one stream and both
 * silently skip events.
 *
 * The cursor is per *consumer*, not global: drain() and waitFor() both use it,
 * so an unrelated get_events call in the middle of a wait_for_event would
 * advance the cursor past the event the wait was looking for.
 */
const cursors = new Map<string, number>();
let consumerSeq = 0;

function cursorKey(): string {
  const inst = currentInstance();
  return `${inst.host}:${inst.port}`;
}

/**
 * Cursors are per (endpoint, consumer). A "consumer" is one logical reader -
 * a specific wait_for_event call, or the get_events stream - so concurrent
 * readers of the same debugger cannot steal each other's events. Calls that
 * pass no consumer id share the process-wide "drain" cursor.
 */
function scopedKey(consumer?: string): string {
  return `${cursorKey()}|${consumer ?? 'drain'}`;
}

export function currentCursor(consumer?: string): number {
  return cursors.get(scopedKey(consumer)) ?? 0;
}

export function resetCursor(consumer?: string): void {
  cursors.set(scopedKey(consumer), 0);
}

/**
 * Move one consumer's cursor. Used by get_events when the caller caps a batch:
 * the events beyond the cap stay in the plugin buffer for the next call.
 */
export function setCursor(seq: number, consumer?: string): void {
  cursors.set(scopedKey(consumer), seq);
}

/** Allocate a fresh consumer id for one blocking wait. */
export function newConsumer(): string {
  return `c${++consumerSeq}`;
}

export function dropConsumer(consumer: string): void {
  cursors.delete(scopedKey(consumer));
}

function advance(res: EventsResponse, consumer?: string): void {
  const key = scopedKey(consumer);
  if (res.latest_seq > (cursors.get(key) ?? 0)) cursors.set(key, res.latest_seq);
}

/** Highest event sequence buffered right now, per endpoint (no cursor change). */
export async function headSeq(): Promise<number> {
  try {
    const res = await httpClient.get<EventsResponse>('/api/command/events', { since: '0', max: '0' });
    return res.latest_seq ?? 0;
  } catch {
    return 0;
  }
}

/** Snapshot of everything buffered since the cursor. Does not block. */
export async function drain(
  consumer?: string
): Promise<{ events: DebugEvent[]; dropped: number }> {
  try {
    const res = await httpClient.get<EventsResponse>('/api/command/events', {
      since: String(currentCursor(consumer)),
    });
    advance(res, consumer);
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
  // Set when the plugin returned a batch it had truncated: more events are
  // buffered already, so the next request must not hold for new ones.
  let hasMore = false;

  // This wait gets its own cursor, starting wherever the shared drain cursor
  // is. Without that, a get_events or another wait in the same session would
  // advance the cursor past the event this call is looking for.
  const consumer = newConsumer();
  cursors.set(scopedKey(consumer), currentCursor());

  try {
    while (true) {
      const remaining = timeout_ms - (Date.now() - started);
      if (remaining <= 0) {
        return { matched: null, others, elapsed_ms: Date.now() - started, dropped };
      }

      const params: Record<string, string> = {
        since: String(currentCursor(consumer)),
        // Hold for at most eventHoldMs per request so a plugin restart is noticed
        // promptly, but never longer than the caller's remaining budget. When the
        // previous batch was truncated there is already data to read, so do not
        // park at all - the hold is only for waiting on future events.
        timeout: String(hasMore ? 0 : Math.min(remaining, config.eventHoldMs)),
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
      hasMore = res.has_more === true;
      advance(res, consumer);

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
  } finally {
    dropConsumer(consumer);
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
