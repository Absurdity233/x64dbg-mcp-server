/**
 * Remembers what the current debug session looks like so it can be rebuilt
 * after the target dies.
 *
 * A protected binary under a debugger crashes easily - an anti-debug check, a
 * deliberate fault the VM expects to handle, or simply our own breakpoints
 * disturbing timing. When that happens x64dbg drops to "stopped" and every
 * breakpoint, patch and label is gone. Re-typing the setup by hand is the most
 * common way an automated session turns back into a manual one.
 *
 * This module keeps the minimum needed to restore: how the target was started
 * and which breakpoints were armed.
 */

import { currentInstance } from './context.js';

export interface BreakpointSpec {
  address: string;
  kind: 'software' | 'hardware' | 'memory';
  singleshot?: boolean;
  hw_type?: string;
  hw_size?: string;
  mem_type?: string;
  break_condition?: string;
  command_condition?: string;
  command_text?: string;
  log_text?: string;
  log_condition?: string;
  silent?: boolean;
  fast_resume?: boolean;
  name?: string;
  /** true when the breakpoint was created with the logging helper */
  logging?: boolean;
}

interface SessionState {
  path: string | null;
  cmdline: string | null;
  breakpoints: Map<string, BreakpointSpec>;
  /** How many times recover() has rebuilt this session. */
  recoveries: number;
}

/**
 * One record per x64dbg instance. Sharing a single record would make one
 * target's recover() reload the other target's binary and re-arm breakpoints
 * that belong to a different process.
 */
const states = new Map<string, SessionState>();

function state(): SessionState {
  const key = currentInstance().id;
  let s = states.get(key);
  if (!s) {
    s = { path: null, cmdline: null, breakpoints: new Map(), recoveries: 0 };
    states.set(key, s);
  }
  return s;
}

const keyOf = (address: string) => address.trim().toLowerCase();

export function recordLaunch(path: string, cmdline?: string): void {
  const s = state();
  s.path = path;
  s.cmdline = cmdline ?? null;
  // A new process starts with no breakpoints.
  s.breakpoints.clear();
}

export function rememberBreakpoint(spec: BreakpointSpec): void {
  state().breakpoints.set(keyOf(spec.address), spec);
}

export function forgetBreakpoint(address: string): void {
  state().breakpoints.delete(keyOf(address));
}

export function forgetAllBreakpoints(): void {
  state().breakpoints.clear();
}

export function launchInfo(): { path: string | null; cmdline: string | null } {
  const s = state();
  return { path: s.path, cmdline: s.cmdline };
}

export function breakpoints(): BreakpointSpec[] {
  return [...state().breakpoints.values()];
}

export function noteRecovery(): number {
  return ++state().recoveries;
}

export function recoveryCount(): number {
  return state().recoveries;
}

export function resetSession(): void {
  const s = state();
  s.path = null;
  s.cmdline = null;
  s.breakpoints.clear();
  s.recoveries = 0;
}
