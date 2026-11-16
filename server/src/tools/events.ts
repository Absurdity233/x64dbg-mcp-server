import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { config } from '../config.js';
import {
  consume,
  currentCursor,
  describe,
  drain,
  headSeq,
  resetCursor,
  setCursor,
  waitFor,
  type DebugEvent,
} from '../events.js';

/**
 * Debugger event stream.
 *
 * The plugin buffers every callback it receives (breakpoint, exception, dll
 * load, pause/resume, thread and process lifetime) behind a monotonic sequence
 * number. `x64dbg_debug wait_for_event` already mails one of these through, but
 * it lives on the wrong tool: a caller who wants "tell me what happened while I
 * was away" has to start a debug action first. This tool exposes the stream
 * itself.
 *
 * Three actions, three shapes of use:
 *   poll  - one round trip, returns what is buffered now. Safe to call in a loop.
 *   wait  - parks on the plugin's long-poll until a matching event arrives, so a
 *           breakpoint hit wakes the caller instead of being missed between polls.
 *   list  - read-only head/cursor readout; use it to learn the current seq before
 *           handing `since` to poll.
 */
export function registerEventTools(server: McpServer) {
  server.tool(
    'x64dbg_events',
    'Debugger event stream. Actions: poll (buffered events since the cursor, returns immediately), ' +
      'wait (block until an event matches types/address, up to timeout_ms), list (show cursor and head ' +
      'sequence without consuming). Event types: session_start, session_attach, session_stop, ' +
      'system_breakpoint, breakpoint, exception, dll_load, thread_create, process_create, ' +
      'process_exit, paused, resumed, stepped.',
    {
      action: z.enum(['poll', 'wait', 'list']).describe('Operation to perform'),
      types: z
        .array(z.string())
        .optional()
        .describe(
          "Filter by event type, e.g. ['breakpoint','exception']. Omit for every type. " +
            'Applies to poll (client-side) and wait (server-side, so a filtered wait parks efficiently).'
        ),
      address: z
        .string()
        .optional()
        .describe('wait: only match events whose address equals this expression'),
      timeout_ms: z
        .number()
        .optional()
        .default(60_000)
        .describe('wait: maximum time to block (default 60000); poll/list never block'),
      since: z
        .number()
        .optional()
        .describe(
          'poll/wait: start from this sequence number instead of the stored cursor. ' +
            'list: ignored. Use the value list returns to replay from a known point.'
        ),
      max: z
        .number()
        .int()
        .min(1)
        .max(2000)
        .optional()
        .describe('poll: return at most this many events (default and cap follow the plugin batch size)'),
      reset: z
        .boolean()
        .optional()
        .describe('Reset the cursor to the head before acting, so only events that arrive later are returned'),
      include_raw: z
        .boolean()
        .optional()
        .describe('Also return each event as its raw JSON object, not just the one-line summary'),
    },
    async (args) => {
      // `reset` means "from now on". Move the cursor to the head first so the
      // caller does not receive a backlog they explicitly did not ask for.
      if (args.reset) {
        const head = await headSeq();
        resetCursor();
        setCursor(head);
      } else if (args.since !== undefined) {
        setCursor(args.since);
      }

      if (args.action === 'list') {
        const head = await headSeq();
        const cursor = currentCursor();
        const pending = Math.max(0, head - cursor);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  cursor,
                  head_seq: head,
                  pending,
                  batch_max: config.eventBatchMax,
                  hold_ms: config.eventHoldMs,
                  hint:
                    head === 0
                      ? 'No events buffered. Load or attach a target, then poll again.'
                      : pending === 0
                        ? 'Cursor is at the head; the next poll returns nothing until something happens.'
                        : `${pending} event(s) waiting. Call action=poll to drain them.`,
                },
                null,
                2
              ),
            },
          ],
        };
      }

      if (args.action === 'wait') {
        const filter = args.types && args.types.length ? args.types : undefined;
        const res = await waitFor(
          (ev: DebugEvent) => {
            if (args.address && ev.address !== args.address) return false;
            return true;
          },
          args.timeout_ms ?? 60_000,
          0,
          filter
        );

        const events = res.matched ? [...res.others, res.matched] : res.others;
        const body: Record<string, unknown> = {
          matched: res.matched ? describe(res.matched) : null,
          elapsed_ms: res.elapsed_ms,
          dropped: res.dropped,
          count: events.length,
          events: events.map(describe),
        };
        if (args.include_raw) body.raw = events;
        if (!res.matched) {
          body.hint =
            `No matching event within ${args.timeout_ms ?? 60_000}ms. ` +
            'The target may be idle, or it may be running in a fast-resume loop — ' +
            'check action=list, then poll to see what did arrive.';
        }
        return { content: [{ type: 'text', text: JSON.stringify(body, null, 2) }] };
      }

      // poll: one bounded round trip.
      const limit = args.max ?? config.eventBatchMax;
      const { events, dropped } = await drain();
      const filtered = args.types && args.types.length
        ? events.filter((ev) => args.types!.includes(ev.type))
        : events;
      const shown = filtered.slice(0, limit);

      const body: Record<string, unknown> = {
        count: shown.length,
        matched_type_count: filtered.length,
        dropped,
        events: shown.map(describe),
        head_seq: await headSeq(),
      };
      if (args.include_raw) body.raw = shown;
      if (shown.length < filtered.length) {
        body.hint = `${filtered.length - shown.length} further event(s) were dropped by max=${limit}; call poll again.`;
      } else if (shown.length === 0) {
        body.hint = 'Nothing buffered since the cursor.';
      }
      return { content: [{ type: 'text', text: JSON.stringify(body, null, 2) }] };
    }
  );
}

/** Re-exported so the debug tool and this one share one cursor namespace. */
export { consume, drain, describe };
export type { DebugEvent };