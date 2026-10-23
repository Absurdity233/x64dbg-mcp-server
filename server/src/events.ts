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
}

const SLEEP = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** Highest sequence number known to this client, so polls only return new events. */
let cursor = 0;

export function currentCursor(): number {
  return cursor;
}

export function resetCursor(): void {
  cursor = 0;
}

/**
 * Jump the cursor to the newest buffered event without returning anything.
 * Called right after starting a session so events from a previous run do not
 * satisfy a subsequent wait_for_event.
 */
export async function syncCursor(): Promise<void> {
  try {
    const res = await httpClient.get<EventsResponse>('/api/command/events', {
      since: String(cursor),
    });
    if (res.latest_seq > cursor) cursor = res.latest_seq;
  } catch {
    // Plugin not ready / old firmware without the endpoint - leave the cursor.
  }
}

async function fetchSince(since: number): Promise<EventsResponse> {
  const res = await httpClient.get<EventsResponse>('/api/command/events', {
    since: String(since),
  });
  if (res.latest_seq > cursor) cursor = res.latest_seq;
  return res;
}

/** Drain whatever is buffered right now. */
export async function drain(): Promise<{ events: DebugEvent[]; dropped: number }> {
  const res = await fetchSince(cursor);
  return { events: res.events ?? [], dropped: res.dropped ?? 0 };
}

/**
 * Poll until an event matches `predicate`, or the deadline passes.
 * Events that do not match are still consumed (the cursor advances), so a
 * later call will not re-report them.
 */
export async function waitFor(
  predicate: (ev: DebugEvent) => boolean,
  timeout_ms: number,
  poll_ms = 150
): Promise<{
  matched: DebugEvent | null;
  others: DebugEvent[];
  elapsed_ms: number;
  dropped: number;
}> {
  const started = Date.now();
  const others: DebugEvent[] = [];
  let dropped = 0;

  for (;;) {
    const res = await fetchSince(cursor);
    dropped += res.dropped ?? 0;

    for (const ev of res.events ?? []) {
      if (predicate(ev)) {
        return { matched: ev, others, elapsed_ms: Date.now() - started, dropped };
      }
      others.push(ev);
    }

    if (Date.now() - started >= timeout_ms) {
      return { matched: null, others, elapsed_ms: Date.now() - started, dropped };
    }

    await SLEEP(Math.max(config.eventPollMs, poll_ms));
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
