import { config } from './config.js';
import { currentInstance } from './context.js';
import { isMultiInstance, type InstanceEndpoint } from './instances.js';

interface PluginResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: {
    code: number;
    message: string;
  };
}

type ConnectionState = 'connected' | 'disconnected' | 'reconnecting';

/** A definite answer from the plugin (success:false), with an actionable hint. */
export class PluginError extends Error {
  readonly code: number;
  readonly hint?: string;

  constructor(code: number, message: string, hint?: string) {
    super(message);
    this.name = 'PluginError';
    this.code = code;
    this.hint = hint;
  }
}

function pluginHint(code: number, message: string): string | undefined {
  switch (code) {
    case 400:
      return 'The plugin rejected the request parameters; check the action and its required fields.';
    case 401:
      return 'Token mismatch: align X64DBG_MCP_TOKEN with the plugin settings, then restart.';
    case 404:
      return 'Plugin route not found: the installed plugin may be older than the server. ' +
        'Run x64dbg_process action=compat or reinstall the plugin.';
    case 409:
      return /trace/i.test(message)
        ? 'A trace is active; stop it with x64dbg_tracing action=stop first.'
        : 'The debugger is in the wrong state. Load or attach a target, and pause/resume as needed.';
    case 500:
      return 'The plugin hit an internal error; this action may be unsupported by this x64dbg build.';
    default:
      return undefined;
  }
}

// Default wait for a plugin that is not answering. Single instance: 2 minutes,
// because the editor may still be starting x64dbg. Multi-instance: 15 seconds,
// because a stopped instance is a routing mistake, not a startup race - stalling
// every call for two minutes would make the whole session look hung.
const WAIT_FOR_PLUGIN_TIMEOUT_MS = 120_000;
const WAIT_FOR_PLUGIN_TIMEOUT_MULTI_MS = 15_000;
const WAIT_POLL_INTERVAL_MS = 2_000;        // poll every 2s

export class HttpClient {
  private base_url: string;
  private token: string;
  private state: ConnectionState = 'disconnected';
  private last_successful_request = 0;
  private consecutive_failures = 0;
  private health_check_interval: ReturnType<typeof setInterval> | null = null;
  // Set when /api/health answers 401. Distinguishes "plugin not running" from
  // "plugin running but rejecting our token" so we fail fast instead of
  // polling for two minutes with a misleading message.
  private auth_rejected = false;

  constructor(instance: InstanceEndpoint) {
    this.base_url = `http://${instance.host}:${instance.port}`;
    this.token = instance.token;
    this.start_health_monitor();
  }

  get baseUrl(): string {
    return this.base_url;
  }

  private waitMs(): number {
    if (config.waitMs > 0) return config.waitMs;
    return isMultiInstance() ? WAIT_FOR_PLUGIN_TIMEOUT_MULTI_MS : WAIT_FOR_PLUGIN_TIMEOUT_MS;
  }

  get connection_state(): ConnectionState {
    return this.state;
  }

  private auth_headers(): Record<string, string> {
    return this.token ? { Authorization: `Bearer ${this.token}` } : {};
  }

  async get<T = unknown>(path: string, params?: Record<string, string>): Promise<T> {
    const url = new URL(path, this.base_url);
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== '') {
          url.searchParams.set(key, value);
        }
      }
    }

    // Event long-polls park server-side for up to X64DBG_MCP_EVENT_HOLD_MS;
    // a read timeout would abort a wait that is working as designed.
    const timeoutMs = /\/events(\/|$)/.test(path) ? 0 : config.readTimeoutMs;
    return this.request<T>(url.toString(), { method: 'GET', headers: this.auth_headers() }, timeoutMs);
  }

  async post<T = unknown>(path: string, body?: unknown): Promise<T> {
    const url = new URL(path, this.base_url);
    const options: RequestInit = {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...this.auth_headers() },
    };

    if (body !== undefined) {
      options.body = JSON.stringify(body);
    }

    // Writes and debugger-control POSTs keep the global timeout: run/trace are
    // unbounded by nature and default to "no timeout".
    return this.request<T>(url.toString(), options, config.timeout);
  }

  destroy() {
    if (this.health_check_interval) {
      clearInterval(this.health_check_interval);
      this.health_check_interval = null;
    }
  }

  private start_health_monitor() {
    // Periodic health check every 15s to maintain connection awareness
    this.health_check_interval = setInterval(async () => {
      await this.check_health();
    }, 15_000);
    // One timer per instance must not keep the process alive on its own.
    this.health_check_interval.unref?.();

    // Initial health check (non-blocking)
    this.check_health().catch(() => {});
  }

  private async check_health(): Promise<boolean> {
    try {
      const controller = new AbortController();
      const timeout_id = setTimeout(() => controller.abort(), 3000);

      const response = await fetch(`${this.base_url}/api/health`, {
        method: 'GET',
        headers: this.auth_headers(),
        signal: controller.signal,
      });

      clearTimeout(timeout_id);

      if (response.ok) {
        const was_disconnected = this.state !== 'connected';
        this.state = 'connected';
        this.auth_rejected = false;
        this.consecutive_failures = 0;
        if (was_disconnected) {
          console.error(`[x64dbg-mcp] Plugin connection established at ${this.base_url}`);
        }
        return true;
      }

      if (response.status === 401) {
        this.auth_rejected = true;
        console.error(
          '[x64dbg-mcp] Plugin rejected the auth token. Set X64DBG_MCP_TOKEN to the ' +
          'token configured in the plugin (Plugins > x64dbg MCP Server > Settings).'
        );
      }
      return false;
    } catch {
      if (this.state === 'connected') {
        console.error('[x64dbg-mcp] Plugin connection lost, will reconnect automatically');
        this.state = 'disconnected';
      }
      return false;
    }
  }

  /**
   * Block until the plugin is reachable. Polls /api/health every 2s
   * for up to 2 minutes. This is the key fix: instead of failing
   * immediately when the plugin isn't running, we wait for it.
   */
  private async wait_for_connection(): Promise<void> {
    // Already connected - skip
    if (this.state === 'connected') return;

    // Quick check first
    if (await this.check_health()) return;

    // The plugin is up but our credentials are wrong - retrying cannot help.
    if (this.auth_rejected) {
      throw new Error(
        `x64dbg plugin at ${this.base_url} rejected the auth token (HTTP 401). ` +
        `Set X64DBG_MCP_TOKEN to match the token in the plugin's settings ` +
        `(Plugins > x64dbg MCP Server > Settings).`
      );
    }

    // Plugin not available - enter wait loop
    const budget = this.waitMs();
    this.state = 'reconnecting';
    console.error(
      `[x64dbg-mcp] Plugin not reachable at ${this.base_url}, waiting up to ${budget / 1000}s for it to come online...`
    );

    const deadline = Date.now() + budget;
    let poll_count = 0;

    while (Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, WAIT_POLL_INTERVAL_MS));
      poll_count++;

      if (await this.check_health()) {
        console.error(`[x64dbg-mcp] Plugin came online after ~${poll_count * 2}s`);
        return;
      }

      // Token was rotated while we were waiting - stop immediately.
      if (this.auth_rejected) {
        throw new Error(
          `x64dbg plugin at ${this.base_url} rejected the auth token (HTTP 401). ` +
          `Set X64DBG_MCP_TOKEN to match the plugin's configured token.`
        );
      }

      // Log progress every 10s
      if (poll_count % 5 === 0) {
        const elapsed = Math.round((Date.now() - (deadline - budget)) / 1000);
        const remaining = Math.round((deadline - Date.now()) / 1000);
        console.error(`[x64dbg-mcp] Still waiting for plugin... (${elapsed}s elapsed, ${remaining}s remaining)`);
      }
    }

    this.state = 'disconnected';
    throw new Error(
      `x64dbg plugin did not come online at ${this.base_url} within ${budget / 1000}s. ` +
      `Make sure x64dbg is running with the MCP plugin loaded. ` +
      `Check with 'mcpserver status' in x64dbg command bar. ` +
      `Raise the budget with X64DBG_MCP_WAIT_MS=<ms>.`
    );
  }

  private is_connection_error(err: Error): boolean {
    const msg = err.message.toLowerCase();
    return (
      msg.includes('econnrefused') ||
      msg.includes('econnreset') ||
      msg.includes('epipe') ||
      msg.includes('enotfound') ||
      msg.includes('enetunreach') ||
      msg.includes('ehostunreach') ||
      msg.includes('socket hang up') ||
      msg.includes('fetch failed') ||
      msg.includes('network') ||
      msg.includes('econnaborted') ||
      msg.includes('etimedout')
    );
  }

  private async request<T>(url: string, options: RequestInit, timeoutMs = config.timeout): Promise<T> {
    // CRITICAL: If not connected, wait for the plugin to come online
    // This prevents Claude from seeing connection errors and giving up
    await this.wait_for_connection();

    let last_error: Error | null = null;

    for (let attempt = 0; attempt <= config.retries; attempt++) {
      try {
        // config.timeout === 0 means "no timeout": debugger operations such as
        // run/continue and conditional traces are unbounded, so by default we
        // wait as long as the plugin needs (same as talking to it with curl).
        const controller = new AbortController();
        const timeout_id =
          timeoutMs > 0
            ? setTimeout(() => controller.abort(), timeoutMs)
            : null;

        const response = await fetch(url, {
          ...options,
          signal: controller.signal,
        });

        if (timeout_id) clearTimeout(timeout_id);

        const text = await response.text();
        let parsed: PluginResponse<T>;

        try {
          parsed = JSON.parse(text) as PluginResponse<T>;
        } catch {
          throw new Error(`Invalid JSON response from plugin: ${text.substring(0, 200)}`);
        }

        if (!parsed.success) {
          const err_msg = parsed.error?.message ?? 'Unknown plugin error';
          const err_code = parsed.error?.code ?? 500;

          if (err_code === 401) {
            this.auth_rejected = true;
            throw new PluginError(
              401,
              `Plugin rejected the auth token (401). Set X64DBG_MCP_TOKEN to match the ` +
              `token configured in Plugins > x64dbg MCP Server > Settings.`,
              pluginHint(401, err_msg)
            );
          }

          throw new PluginError(err_code, err_msg, pluginHint(err_code, err_msg));
        }

        // Success
        this.state = 'connected';
        this.consecutive_failures = 0;
        this.last_successful_request = Date.now();

        return parsed.data as T;
      } catch (err) {
        last_error = err instanceof Error ? err : new Error(String(err));

        // Auth failures never resolve on their own - retrying just spins.
        if (this.auth_rejected) {
          throw last_error;
        }

        // Don't retry on definite plugin responses - they are deterministic, and
        // retrying a non-idempotent POST (memory/write, patches/apply, breakpoints/set)
        // would double-apply the side effect. PluginError covers 4xx/5xx; the
        // malformed-JSON case means the plugin answered but the body is wrong.
        if (
          last_error instanceof PluginError ||
          last_error.message.startsWith('Invalid JSON response')
        ) {
          this.state = 'connected';
          throw last_error;
        }

        // Handle timeout. We do NOT retry here: a timeout means a long-running
        // debugger operation (run, trace, step-over-call) was still in progress,
        // and retrying would just restart it from scratch and time out again.
        // Fail fast and tell the user how to raise or remove the limit.
        if (last_error.name === 'AbortError') {
          this.consecutive_failures++;
          throw new Error(
            `Request aborted after ${timeoutMs}ms. Reads use X64DBG_MCP_READ_TIMEOUT_MS ` +
            `(default 30000); writes/run/trace use X64DBG_MCP_TIMEOUT. The plugin may be busy ` +
            `with a long operation. Raise the relevant limit, or set it to 0 to wait indefinitely.`
          );
        }

        // Connection errors mid-request: the plugin may have restarted
        if (this.is_connection_error(last_error)) {
          this.consecutive_failures++;
          this.state = 'reconnecting';
          console.error(`[x64dbg-mcp] Connection error on attempt ${attempt + 1}: ${last_error.message}`);

          if (attempt < config.retries) {
            // Wait for reconnection before retrying
            console.error('[x64dbg-mcp] Waiting for plugin to come back...');
            try {
              await this.wait_for_connection();
              continue; // Plugin is back, retry the request
            } catch {
              throw last_error; // Timed out waiting
            }
          }

          this.state = 'disconnected';
          throw new Error(
            `Lost connection to x64dbg plugin at ${this.base_url}. ` +
            `The plugin may have been stopped or x64dbg was closed.`
          );
        }

        // Other errors - brief retry
        if (attempt < config.retries) {
          await new Promise(resolve => setTimeout(resolve, 300 * (attempt + 1)));
        }
      }
    }

    throw last_error ?? new Error('Request failed');
  }
}

/**
 * One client per configured instance, created on first use.
 *
 * Every tool handler calls `httpClient.get/post` directly. Instead of threading
 * an instance through ~160 call sites, the facade below resolves the instance
 * from the async context the tool wrapper established (context.ts).
 */
const clients = new Map<string, HttpClient>();

export function getClient(instance: InstanceEndpoint): HttpClient {
  let client = clients.get(instance.id);
  if (!client) {
    client = new HttpClient(instance);
    clients.set(instance.id, client);
  }
  return client;
}

export const httpClient = {
  get<T = unknown>(path: string, params?: Record<string, string>): Promise<T> {
    return getClient(currentInstance()).get<T>(path, params);
  },
  post<T = unknown>(path: string, body?: unknown): Promise<T> {
    return getClient(currentInstance()).post<T>(path, body);
  },
  get connection_state(): ConnectionState {
    return getClient(currentInstance()).connection_state;
  },
  /** Stop the health monitors of every instance client. */
  destroy(): void {
    for (const client of clients.values()) client.destroy();
    clients.clear();
  },
};
