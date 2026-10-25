import { config } from './config.js';

/**
 * Multiple x64dbg instances.
 *
 * One x64dbg window can only debug one target at a time, and the MCP plugin's
 * port lives in the x64dbg.ini next to x64dbg.exe - so "several targets in
 * parallel" means several x64dbg processes, each on its own port.
 *
 * This module is the registry of those endpoints. Tool calls select one by id
 * (see context.ts); the legacy single-instance setup keeps working unchanged:
 * when X64DBG_MCP_INSTANCES is unset, exactly one instance named "default" is
 * synthesised from X64DBG_MCP_PORT / X64DBG_MCP_TOKEN / X64DBG_PATH.
 *
 * X64DBG_MCP_INSTANCES accepts either form:
 *   [{"id":"alpha","port":27042,"token":"..."},
 *    {"id":"beta","port":27043,"x64dbgPath":"D:\\dbg2\\x64\\x64dbg.exe"}]
 *   {"alpha":{"port":27042},"beta":{"port":27043}}
 *
 * Fields per instance: id (from the key), host (default 127.0.0.1), port
 * (required), token (defaults to X64DBG_MCP_TOKEN), x64dbgPath (optional,
 * used by the launcher), label (optional, shown in tool output).
 */

export interface InstanceEndpoint {
  id: string;
  host: string;
  port: number;
  token: string;
  x64dbgPath?: string;
  label?: string;
}

export const DEFAULT_INSTANCE_ID = 'default';

function fromRaw(id: string, raw: unknown): InstanceEndpoint | null {
  if (!raw || typeof raw !== 'object') return null;
  const o = raw as Record<string, unknown>;
  const port = Number(o.port);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;
  return {
    id: typeof o.id === 'string' && o.id ? o.id : id,
    host: typeof o.host === 'string' && o.host ? o.host : config.host,
    port,
    token: typeof o.token === 'string' ? o.token : config.token,
    x64dbgPath: typeof o.x64dbgPath === 'string' && o.x64dbgPath ? o.x64dbgPath : undefined,
    label: typeof o.label === 'string' && o.label ? o.label : undefined,
  };
}

function parseInstances(raw: string | undefined): InstanceEndpoint[] | null {
  if (!raw || !raw.trim()) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    console.error(
      `[x64dbg-mcp] X64DBG_MCP_INSTANCES is not valid JSON (${err instanceof Error ? err.message : String(err)}); ` +
      'falling back to the single-instance env vars'
    );
    return null;
  }

  const out: InstanceEndpoint[] = [];
  if (Array.isArray(parsed)) {
    for (const entry of parsed) {
      const inst = fromRaw('', entry);
      if (inst && inst.id) out.push(inst);
      else console.error('[x64dbg-mcp] ignoring an instance entry without a valid id/port');
    }
  } else if (parsed && typeof parsed === 'object') {
    for (const [id, entry] of Object.entries(parsed as Record<string, unknown>)) {
      const inst = fromRaw(id, entry);
      if (inst) out.push(inst);
      else console.error(`[x64dbg-mcp] ignoring instance "${id}": invalid port`);
    }
  }

  if (!out.length) return null;

  const seen = new Set<string>();
  for (const inst of out) {
    if (seen.has(inst.id)) {
      console.error(`[x64dbg-mcp] duplicate instance id "${inst.id}" in X64DBG_MCP_INSTANCES`);
    }
    seen.add(inst.id);
  }
  return out;
}

const registry = new Map<string, InstanceEndpoint>();

function register(inst: InstanceEndpoint): void {
  registry.set(inst.id, inst);
}

function build(): void {
  registry.clear();
  const parsed = parseInstances(process.env.X64DBG_MCP_INSTANCES);
  if (parsed) {
    for (const inst of parsed) register(inst);
  } else {
    register({
      id: DEFAULT_INSTANCE_ID,
      host: config.host,
      port: config.port,
      token: config.token,
      x64dbgPath: config.x64dbgPath || undefined,
      label: 'single instance (legacy env vars)',
    });
  }

  // The default is the one X64DBG_MCP_INSTANCE names, else the first declared.
  const wanted = process.env.X64DBG_MCP_INSTANCE?.trim();
  if (wanted && registry.has(wanted)) {
    defaultId = wanted;
  } else {
    if (wanted) {
      console.error(
        `[x64dbg-mcp] X64DBG_MCP_INSTANCE="${wanted}" is not a configured instance; ` +
        `using "${[...registry.keys()][0]}"`
      );
    }
    defaultId = [...registry.keys()][0];
  }
}

let defaultId = DEFAULT_INSTANCE_ID;

export function listInstances(): InstanceEndpoint[] {
  return [...registry.values()];
}

export function getDefaultInstance(): InstanceEndpoint {
  return registry.get(defaultId) ?? [...registry.values()][0];
}

export function getDefaultInstanceId(): string {
  return getDefaultInstance().id;
}

/**
 * Resolve a tool call's `instance` argument.
 *
 * undefined = "whatever this server defaults to". An unknown id is a hard error
 * that names the valid ids: silently falling back to the default would let a
 * model drive the wrong target, which is exactly the failure this feature
 * exists to prevent.
 */
export function getInstance(id?: string | null): InstanceEndpoint {
  if (!id) return getDefaultInstance();
  const inst = registry.get(id);
  if (inst) return inst;
  const known = [...registry.keys()].join(', ');
  throw new Error(
    `Unknown x64dbg instance "${id}". Configured instances: ${known}. ` +
    `Call x64dbg_instances action=list to inspect them.`
  );
}

/** Switch this MCP server process's default (in-memory; not persisted). */
export function setDefaultInstance(id: string): InstanceEndpoint {
  const inst = registry.get(id);
  if (!inst) {
    throw new Error(
      `Unknown x64dbg instance "${id}". Configured instances: ${[...registry.keys()].join(', ')}.`
    );
  }
  defaultId = inst.id;
  return inst;
}

export function isMultiInstance(): boolean {
  return registry.size > 1;
}

/**
 * --x64dbg=<path> applies to the default instance only. With a multi-instance
 * registry the per-instance x64dbgPath is authoritative; this exists so the
 * legacy single-instance CLI flag keeps working.
 */
export function applyX64dbgPathOverride(path: string): void {
  getDefaultInstance().x64dbgPath = path;
}

build();
