import { AsyncLocalStorage } from 'node:async_hooks';
import { getDefaultInstance, type InstanceEndpoint } from './instances.js';

/**
 * Which x64dbg instance the current tool call targets.
 *
 * The MCP SDK invokes each tool handler in its own async context, so an
 * AsyncLocalStorage value set around the handler is visible to everything it
 * awaits - including the module-level `httpClient`, the event cursor and the
 * session bookkeeping. That is what lets the rest of the code base keep using
 * plain module imports while actually being multi-instance.
 */
const storage = new AsyncLocalStorage<InstanceEndpoint>();

export function runWithInstance<T>(instance: InstanceEndpoint, fn: () => T): T {
  return storage.run(instance, fn);
}

/** The instance of the tool call in flight, or the server default outside one. */
export function currentInstance(): InstanceEndpoint {
  return storage.getStore() ?? getDefaultInstance();
}

export function inToolCall(): boolean {
  return storage.getStore() !== undefined;
}
