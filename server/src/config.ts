function parseTimeout(raw: string | undefined): number {
  // Debugger operations (run, trace, step-over-call) are unbounded by nature,
  // so the default is "no timeout" (0) to match talking to the plugin with curl,
  // which has no default timeout. Users who want a hard ceiling can set
  // X64DBG_MCP_TIMEOUT to a positive millisecond value. 0 or negative = wait forever.
  const value = parseInt(raw ?? '0', 10);
  if (Number.isNaN(value) || value <= 0) {
    return 0;
  }
  return value;
}

function parseWait(raw: string | undefined): number {
  // How long a request waits for a plugin that is not answering. 0 = default,
  // which is 120s for a single instance (the editor may still be starting
  // x64dbg) and 15s when several instances are configured (a stopped instance
  // should fail fast instead of stalling every call for two minutes).
  const value = parseInt(raw ?? '0', 10);
  return Number.isNaN(value) || value < 0 ? 0 : value;
}

/** 'auto' compacts JSON responses over 2 KB, keeps small ones readable. */
function parseCompact(raw: string | undefined): 'auto' | 'on' | 'off' {
  const v = (raw ?? '').trim().toLowerCase();
  if (v === 'on' || v === '1' || v === 'true') return 'on';
  if (v === 'off' || v === '0' || v === 'false') return 'off';
  return 'auto';
}

export const config = {
  host: process.env.X64DBG_MCP_HOST ?? '127.0.0.1',
  port: parseInt(process.env.X64DBG_MCP_PORT ?? '27042', 10),
  // 0 = no timeout (wait indefinitely). See parseTimeout above.
  timeout: parseTimeout(process.env.X64DBG_MCP_TIMEOUT),
  retries: parseInt(process.env.X64DBG_MCP_RETRIES ?? '3', 10),
  // Optional auth token. When set, it must match the plugin's configured token
  // (Settings > Token). Sent as "Authorization: Bearer <token>". Empty = no auth.
  token: process.env.X64DBG_MCP_TOKEN ?? '',
  // Fallback poll interval used only when the plugin lacks the long-poll
  // endpoint. With a current plugin, waits park server-side instead.
  eventPollMs: parseInt(process.env.X64DBG_MCP_EVENT_POLL_MS ?? '150', 10),
  // Cap on how many events one long-poll response may carry.
  eventBatchMax: parseInt(process.env.X64DBG_MCP_EVENT_BATCH ?? '256', 10),
  // Default hold time for a single long-poll request. The MCP-side wait loop
  // re-issues requests until its own deadline.
  eventHoldMs: parseInt(process.env.X64DBG_MCP_EVENT_HOLD_MS ?? '30000', 10),
  // Optional path to x64dbg.exe. When set (or when --x64dbg=<path> is passed),
  // the launcher starts x64dbg if it is not already running.
  x64dbgPath: process.env.X64DBG_PATH ?? '',
  // Wait budget for a plugin that is not answering (see parseWait).
  waitMs: parseWait(process.env.X64DBG_MCP_WAIT_MS),
  // Response formatting (see parseCompact).
  compact: parseCompact(process.env.X64DBG_MCP_COMPACT),
};

export function getBaseUrl(): string {
  return `http://${config.host}:${config.port}`;
}
