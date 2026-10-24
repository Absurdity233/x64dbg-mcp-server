import { httpClient } from './http_client.js';

/**
 * Plugin/server compatibility check.
 *
 * The plugin ships as a .dp64 the user installs into x64dbg; the server ships
 * as a dist/ tree. Nothing links them, so upgrading one and not the other used
 * to surface as a 404 from a route that "obviously exists" - which reads like a
 * bug in the code rather than a stale install. /api/meta exposes the plugin's
 * version and its actual route table, which makes the mismatch detectable.
 *
 * This is advisory: a mismatch is reported on stderr and stored for a tool to
 * surface, but it never blocks the MCP handshake. A pinned older plugin is a
 * legitimate setup.
 */

export interface PluginMeta {
  plugin: string;
  version: string;
  arch: string;
  route_count: number;
  routes: string[];
}

export interface CompatResult {
  /** The plugin answered /api/meta at all. */
  reachable: boolean;
  /** The plugin predates /api/meta (upgrading it is the whole point). */
  meta_supported: boolean;
  plugin_version?: string;
  server_version?: string;
  version_match?: boolean;
  arch?: string;
  route_count?: number;
  /** Routes the server would call that the installed plugin does not serve. */
  missing_routes: string[];
  message: string;
}

let lastResult: CompatResult | null = null;

export function getCompatResult(): CompatResult | null {
  return lastResult;
}

/**
 * Routes the server depends on. Kept explicit rather than derived from the
 * tool implementations: this is the contract, and a route silently disappearing
 * from a tool should not also silently disappear from the check.
 */
const REQUIRED_ROUTES = [
  'GET /api/health',
  'GET /api/meta',
  'GET /api/debug/state',
  'POST /api/debug/run',
  'GET /api/command/events',
  'GET /api/command/events/wait',
  'POST /api/trace/thread',
  'POST /api/trace/auto',
  'GET /api/trace/auto/status',
  'POST /api/trace/auto/stop',
  'POST /api/dump/rebuild',
  'POST /api/dump/fix_iat',
  'GET /api/antidebug/vm_probes',
];

export async function checkPluginCompat(serverVersion: string): Promise<CompatResult> {
  let meta: PluginMeta;
  try {
    meta = await httpClient.get<PluginMeta>('/api/meta');
  } catch (err) {
    // Distinguish "no /api/meta" from "no plugin": a 404 means the plugin is
    // old, anything else means it is not reachable.
    const msg = String(err);
    const is404 = msg.includes('404');
    const result: CompatResult = {
      reachable: !is404,
      meta_supported: false,
      server_version: serverVersion,
      missing_routes: [],
      message: is404
        ? `The installed plugin does not implement /api/meta, so it predates server ${serverVersion}. ` +
          `Reinstall the plugin (install.ps1) so the two sides match.`
        : `Could not reach the plugin at startup (${msg}). It may not be loaded yet; ` +
          `compatibility will be re-checked on use.`,
    };
    lastResult = result;
    return result;
  }

  const served = new Set(meta.routes ?? []);
  const missing = REQUIRED_ROUTES.filter((r) => !served.has(r));
  const versionMatch = meta.version === serverVersion;

  let message: string;
  if (missing.length) {
    message =
      `Plugin ${meta.version} (${meta.arch}) is missing ${missing.length} route(s) this ` +
      `server needs: ${missing.join(', ')}. Reinstall the plugin.`;
  } else if (!versionMatch) {
    message =
      `Version mismatch: plugin ${meta.version} vs server ${serverVersion}. ` +
      `All required routes are present, so this probably works, but reinstall one ` +
      `side to silence it.`;
  } else {
    message = `Plugin ${meta.version} (${meta.arch}) matches server ${serverVersion}, ` +
      `${meta.route_count} routes.`;
  }

  const result: CompatResult = {
    reachable: true,
    meta_supported: true,
    plugin_version: meta.version,
    server_version: serverVersion,
    version_match: versionMatch,
    arch: meta.arch,
    route_count: meta.route_count,
    missing_routes: missing,
    message,
  };
  lastResult = result;
  return result;
}
