import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startMockPlugin } from './mock-plugin.mjs';

// Regression cover for the debug state machine and the event stream.
//
// The bug these tests exist for: a target opened by hand in the x64dbg GUI and
// then attached to sits half-initialised, so `pause` answers success:false and
// the state never leaves 'running'. The supported path is `load`, which runs
// `init` and lands on the system breakpoint already paused. That distinction is
// invisible from the tool surface unless something asserts it.
//
// The mock plugin walks the same state transitions, so this runs in CI with no
// debugger and no plugin binary.

const SERVER_DIR = path.resolve(import.meta.dirname, '..');

/** Tool responses may end with a "[state] ..." trailer; strip it first. */
function parseJson(text) {
  const i = text.lastIndexOf('\n[state]');
  const body = i >= 0 ? text.slice(0, i) : text;
  return JSON.parse(body);
}

function startMcp(port, tempDir) {
  const child = spawn('node', [path.join(SERVER_DIR, 'dist', 'index.js'), '--no-launch'], {
    cwd: SERVER_DIR,
    env: {
      ...process.env,
      TEMP: tempDir,
      TMP: tempDir,
      X64DBG_MCP_INSTANCES: JSON.stringify([{ id: 'default', port, token: 'test' }]),
      X64DBG_MCP_INSTANCE: 'default',
      X64DBG_MCP_LEASE: 'off',
      X64DBG_MCP_READ_TIMEOUT_MS: '5000',
      // A plugin that never answers must not park the suite for the default
      // 120s budget; keep the reconnect wait short and explicit.
      X64DBG_MCP_WAIT_MS: '3000',
      // Keep waits short so a broken wait fails the test instead of hanging CI.
      X64DBG_MCP_EVENT_HOLD_MS: '2000',
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  let buffer = '';
  const pending = new Map();
  let nextId = 1;
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    buffer += chunk;
    let nl;
    while ((nl = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (!line) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { continue; }
      const p = pending.get(msg.id);
      if (p) { pending.delete(msg.id); p(msg); }
    }
  });
  child.stderr.setEncoding('utf8');
  let stderr = '';
  child.stderr.on('data', (c) => { stderr += c; });

  const request = (method, params) => new Promise((resolve, reject) => {
    const id = nextId++;
    // `pause` retries 3 x 5s before failing, so the ceiling has to clear that.
    const timer = setTimeout(() => reject(new Error(`MCP request timed out: ${method}\n${stderr}`)), 60000);
    pending.set(id, (msg) => { clearTimeout(timer); resolve(msg); });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });

  const call = async (name, args) => {
    const res = await request('tools/call', { name, arguments: args });
    const result = res.result ?? {};
    return {
      isError: !!result.isError,
      text: (result.content ?? []).map((c) => c.text ?? '').join('\n'),
    };
  };

  const ready = (async () => {
    await request('initialize', {
      protocolVersion: '2024-11-05', capabilities: {},
      clientInfo: { name: 'debug-state-test', version: '0' },
    });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} }) + '\n');
  })();

  return { child, ready, call };
}

test('load lands paused, and everything that needs a pause works', { timeout: 60000 }, async (t) => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'x64dbg-mcp-state-'));
  const plugin = await startMockPlugin({ loadLandsIn: 'paused' });
  const mcp = startMcp(plugin.port, tempDir);

  t.after(async () => {
    try { mcp.child.kill(); } catch {}
    await plugin.stop();
    try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {}
  });
  await mcp.ready;

  // --- state before load --------------------------------------------------
  let r = await mcp.call('x64dbg_debug', { action: 'state' });
  assert.equal(r.isError, false);
  assert.equal(parseJson(r.text).state.state, 'stopped');

  // --- load reaches paused -------------------------------------------------
  r = await mcp.call('x64dbg_debug', { action: 'load', path: 'F:\\mock\\target.exe' });
  assert.equal(r.isError, false, r.text);
  assert.equal(plugin.state, 'paused', 'load must land on the system breakpoint, not running');

  const loaded = parseJson(r.text);
  // The startup burst is returned to the caller so it stays visible...
  assert.ok(Array.isArray(loaded.startup_events), 'load should report startup events');
  assert.ok(
    loaded.startup_events.some((e) => e.includes('session_start')),
    `expected session_start in startup events, got ${JSON.stringify(loaded.startup_events)}`
  );
  assert.ok(
    loaded.startup_events.some((e) => e.includes('paused')),
    `expected paused in startup events, got ${JSON.stringify(loaded.startup_events)}`
  );

  // --- a paused debugger answers register/disassembly reads ---------------
  r = await mcp.call('x64dbg_registers', { action: 'get_all' });
  assert.equal(r.isError, false, r.text);

  // --- run, then pause: the state must come back ---------------------------
  r = await mcp.call('x64dbg_debug', { action: 'run', wait: false });
  assert.equal(r.isError, false, r.text);
  assert.equal(plugin.state, 'running');

  r = await mcp.call('x64dbg_debug', { action: 'pause' });
  assert.equal(r.isError, false, r.text);
  assert.equal(plugin.state, 'paused', 'pause must return the debugger to paused');

  // --- stop returns to stopped --------------------------------------------
  r = await mcp.call('x64dbg_debug', { action: 'stop_debug' });
  assert.equal(r.isError, false, r.text);
  assert.equal(plugin.state, 'stopped');
});

test('a pause the plugin refuses is reported, not silently swallowed', { timeout: 120000 }, async (t) => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'x64dbg-mcp-pausefail-'));
  const plugin = await startMockPlugin({ loadLandsIn: 'running' });
  // The plugin accepts the request but the target never stops - the shape of a
  // fast-resume loop.
  plugin.setPauseFails(true);
  const mcp = startMcp(plugin.port, tempDir);

  t.after(async () => {
    try { mcp.child.kill(); } catch {}
    await plugin.stop();
    try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {}
  });
  await mcp.ready;

  await mcp.call('x64dbg_debug', { action: 'load', path: 'F:\\mock\\target.exe', timeout_ms: 2000 });
  assert.equal(plugin.state, 'running');

  // `pause` retries 3 times with a 5s window each, so this call legitimately
  // takes ~15s before it gives up. The assertion is that it gives up loudly
  // rather than reporting a pause that never happened.
  const r = await mcp.call('x64dbg_debug', { action: 'pause' });
  assert.equal(r.isError, true, `expected an error, got: ${r.text}`);
  assert.match(r.text, /Could not pause/i);
  assert.equal(plugin.state, 'running', 'the mock never stopped, so neither should the report');
});

test('events: list, poll, filter and wait', { timeout: 60000 }, async (t) => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'x64dbg-mcp-events-'));
  const plugin = await startMockPlugin({ loadLandsIn: 'paused' });
  const mcp = startMcp(plugin.port, tempDir);

  t.after(async () => {
    try { mcp.child.kill(); } catch {}
    await plugin.stop();
    try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {}
  });
  await mcp.ready;

  // --- list on an empty buffer --------------------------------------------
  let r = await mcp.call('x64dbg_events', { action: 'list' });
  assert.equal(r.isError, false, r.text);
  let body = parseJson(r.text);
  assert.equal(body.pending, 0, 'a fresh debugger has no buffered events');

  // --- load produces the startup burst ------------------------------------
  await mcp.call('x64dbg_debug', { action: 'load', path: 'F:\\mock\\target.exe' });

  r = await mcp.call('x64dbg_events', { action: 'list' });
  body = parseJson(r.text);
  // load consumes the startup burst so a later wait is not satisfied by it.
  assert.equal(body.pending, 0, 'load drains the startup burst');

  // --- a fresh event shows up as pending then drains on poll --------------
  plugin.pushEvent('breakpoint', { address: '0x0000000140001000' });
  r = await mcp.call('x64dbg_events', { action: 'list' });
  body = parseJson(r.text);
  assert.equal(body.pending, 1, `expected one pending event, got ${r.text}`);

  r = await mcp.call('x64dbg_events', { action: 'poll' });
  body = parseJson(r.text);
  assert.equal(body.count, 1, r.text);
  assert.match(body.events[0], /breakpoint/);
  assert.match(body.events[0], /0x0000000140001000/);

  // --- poll again: cursor advanced, nothing left --------------------------
  r = await mcp.call('x64dbg_events', { action: 'poll' });
  body = parseJson(r.text);
  assert.equal(body.count, 0, 'the cursor must advance past what poll returned');

  // --- type filter --------------------------------------------------------
  plugin.pushEvent('dll_load', { module: 'kernel32.dll' });
  plugin.pushEvent('exception', { code: '0xC0000005' });

  r = await mcp.call('x64dbg_events', { action: 'poll', types: ['exception'] });
  body = parseJson(r.text);
  assert.equal(body.count, 1, r.text);
  assert.match(body.events[0], /exception/);
  assert.match(body.events[0], /0xC0000005/);

  // --- wait returns the event that is already buffered --------------------
  plugin.pushEvent('breakpoint', { address: '0x0000000140002000' });
  r = await mcp.call('x64dbg_events', { action: 'wait', timeout_ms: 5000 });
  body = parseJson(r.text);
  assert.notEqual(body.matched, null, `wait should have matched, got ${r.text}`);
  assert.match(body.matched, /0x0000000140002000/);

  // --- wait on a filter that will not arrive reports a timeout ------------
  const started = Date.now();
  r = await mcp.call('x64dbg_events', { action: 'wait', timeout_ms: 1200, types: ['process_exit'], reset: true });
  body = parseJson(r.text);
  assert.equal(body.matched, null, r.text);
  assert.ok(body.elapsed_ms >= 1000, `wait should have blocked, elapsed ${body.elapsed_ms}`);
  assert.ok(Date.now() - started >= 1000, 'wait returned before its timeout');
});

test('paging: disassembly function honours offset and limit', { timeout: 60000 }, async (t) => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'x64dbg-mcp-page-'));
  const plugin = await startMockPlugin({ loadLandsIn: 'paused' });

  // 600 instructions, enough to prove the slice is real rather than the whole list.
  const instructions = Array.from({ length: 600 }, (_, i) => ({
    address: `0x${(0x140001000 + i * 4).toString(16)}`,
    instruction: `nop ${i}`,
  }));
  // The route the tool actually calls: GET /api/disasm/function.
  plugin.route('/api/disasm/function', 'get', { instructions, count: instructions.length });

  const mcp = startMcp(plugin.port, tempDir);
  t.after(async () => {
    try { mcp.child.kill(); } catch {}
    await plugin.stop();
    try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {}
  });
  await mcp.ready;

  await mcp.call('x64dbg_debug', { action: 'load', path: 'F:\\mock\\target.exe' });

  let r = await mcp.call('x64dbg_disassembly', { action: 'function', address: '0x140001000' });
  let body = parseJson(r.text);
  // pageResult keeps the plugin's own array key and adds the paging metadata
  // beside it, so `instructions` stays `instructions`.
  assert.equal(body.total, 600, 'the unpaged total must survive paging');
  assert.equal(body.instructions.length, 200, 'default limit is 200');
  assert.equal(body.truncated, true);
  assert.equal(body.returned, 200);

  r = await mcp.call('x64dbg_disassembly', { action: 'function', address: '0x140001000', offset: 500, limit: 50 });
  body = parseJson(r.text);
  assert.equal(body.instructions.length, 50);
  assert.equal(body.offset, 500);
  assert.match(body.instructions[0].instruction, /nop 500$/);
  assert.equal(body.truncated, true);

  r = await mcp.call('x64dbg_disassembly', { action: 'function', address: '0x140001000', offset: 550, limit: 100 });
  body = parseJson(r.text);
  assert.equal(body.instructions.length, 50, 'a page past the end returns only what is left');
  assert.equal(body.truncated, false, 'the last page is not truncated');
});