import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Regression tests for the safety guards, paging, structured plugin errors and
// the audit log. Uses a fake plugin over HTTP, so no x64dbg is required.

const SERVER_DIR = path.resolve(import.meta.dirname, '..');
const state = {
  tracing: false,
  paused: false,
  failProcess: false,
  processHits: 0,
  symbols: {},
  memory: {},
  patchWrites: [],
  memWrites: [],
};

/** Tool responses end with a "[state] ..." line; strip it before JSON.parse. */
function parseJson(text) {
  const i = text.lastIndexOf('\n[state]');
  return JSON.parse(i >= 0 ? text.slice(0, i) : text);
}

function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}
const ok = (res, data) => json(res, 200, { success: true, data });
const fail = (res, code, message) => json(res, code, { success: false, error: { code, message } });

function startFakePlugin() {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      let payload = {};
      try { payload = body ? JSON.parse(body) : {}; } catch { payload = {}; }
      switch (url.pathname) {
        case '/api/health':
          return ok(res, { version: '2.4.0', plugin: 'fake', status: 'ok', pid: 4242, elevated: false });
        case '/api/meta':
          return ok(res, { version: '2.4.0', arch: 'x64', route_count: 0, routes: [] });
        case '/api/trace/status':
          return ok(res, { tracing: state.tracing, file: state.tracing ? 'C:\\trace.log' : '' });
        case '/api/debug/state':
          return ok(res, { state: state.paused ? 'paused' : 'running' });
        case '/api/process/info':
          state.processHits++;
          if (state.failProcess) return fail(res, 409, 'No active debug session');
          return ok(res, { pid: 4242 });
        case '/api/command/exec':
          return ok(res, { message: 'ok' });
        case '/api/trace/into':
          return ok(res, { message: 'started' });
        case '/api/analysis/strings':
          return ok(res, {
            module: 'x', base: '0x1000', truncated: false,
            strings: Array.from({ length: 600 }, (_, i) => ({
              address: '0x' + (0x1000 + i).toString(16), type: 'ascii', value: 's' + i,
            })),
          });
        case '/api/analysis/xrefs_to':
          return ok(res, {
            target: '0x1000', count: 600,
            xrefs: Array.from({ length: 600 }, (_, i) => ({
              address: '0x' + (0x1000 + i).toString(16), type: 'call', label: '', module: 'x',
            })),
          });
        case '/api/search/string':
          return ok(res, {
            text: 'x', encoding: 'utf8', pattern: '78', found: true, count: 600,
            matches: Array.from({ length: 600 }, (_, i) => '0x' + (0x1000 + i).toString(16)),
            first_match: '0x1000',
          });
        case '/api/command/events': {
          const since = Number(url.searchParams.get('since') ?? '0');
          const events = Array.from({ length: 300 }, (_, i) => ({ seq: i + 1, tick_ms: i, type: 'debug' }))
            .filter((e) => e.seq > since);
          return ok(res, { events, count: events.length, latest_seq: 300, dropped: 0 });
        }
        case '/api/symbols/resolve': {
          const name = url.searchParams.get('name') ?? '';
          const address = state.symbols[name];
          if (!address) return fail(res, 404, 'Cannot resolve: ' + name);
          return ok(res, { name, address });
        }
        case '/api/memory/read': {
          const addr = (url.searchParams.get('address') ?? '').toLowerCase();
          const size = Number(url.searchParams.get('size') ?? '6');
          const hex = state.memory[addr] ?? Array(size).fill('90').join(' ');
          return ok(res, { address: addr, size, hex, ascii: '' });
        }
        case '/api/patches/apply': {
          const addr = String(payload.address ?? '').toLowerCase();
          const bytes = String(payload.bytes ?? '');
          const original = state.memory[addr] ?? '';
          state.memory[addr] = bytes;
          state.patchWrites.push({ address: addr, bytes, original });
          return ok(res, {
            address: addr,
            bytes_patched: bytes.split(/\s+/).length,
            new_bytes: bytes,
            original_bytes: original,
          });
        }
        case '/api/memory/write': {
          const addr = String(payload.address ?? '').toLowerCase();
          const bytes = String(payload.bytes ?? '');
          state.memory[addr] = bytes;
          state.memWrites.push({ address: addr, bytes });
          return ok(res, { written: bytes.split(/\s+/).length });
        }
        default:
          return fail(res, 404, 'fake plugin has no route ' + url.pathname);
      }
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
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
      X64DBG_MCP_AUDIT: '1',
      X64DBG_MCP_READ_TIMEOUT_MS: '5000',
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

  const request = (method, params) => new Promise((resolve, reject) => {
    const id = nextId++;
    const timer = setTimeout(() => reject(new Error(`MCP request timed out: ${method}`)), 15000);
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
      clientInfo: { name: 'guards-test', version: '0' },
    });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} }) + '\n');
  })();

  return { child, ready, call };
}

test('guards, paging, structured errors and audit', { timeout: 60000 }, async (t) => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'x64dbg-mcp-test-'));
  const server = await startFakePlugin();
  const port = server.address().port;
  const mcp = startMcp(port, tempDir);

  t.after(() => {
    try { mcp.child.kill(); } catch {}
    server.close();
    try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {}
  });

  await mcp.ready;

  // --- trace guard: raw command escape hatch -------------------------------
  state.tracing = true;
  let r = await mcp.call('x64dbg_command', { action: 'execute', command: 'pause' });
  assert.equal(r.isError, true);
  assert.match(r.text, /trace is running/i);
  assert.match(r.text, /trace-destructive/i);

  r = await mcp.call('x64dbg_command', { action: 'script', commands: ['Pause'] });
  assert.equal(r.isError, true);
  assert.match(r.text, /trace-destructive/i);

  // A harmless command must still work while a trace is running.
  r = await mcp.call('x64dbg_command', { action: 'execute', command: 'log hello' });
  assert.equal(r.isError, false);

  // Starting a second trace is refused.
  r = await mcp.call('x64dbg_tracing', { action: 'into' });
  assert.equal(r.isError, true);
  assert.match(r.text, /Another trace is already running/i);

  // With no trace, the same command goes through.
  state.tracing = false;
  r = await mcp.call('x64dbg_command', { action: 'execute', command: 'pause' });
  assert.equal(r.isError, false);

  // --- paused capture guard ----------------------------------------------
  state.paused = true;
  r = await mcp.call('x64dbg_ui', { action: 'screenshot', hwnd: 1, file: path.join(tempDir, 'x.png') });
  assert.equal(r.isError, true);
  assert.match(r.text, /debugger-paused/);
  state.paused = false;

  // --- paging -------------------------------------------------------------
  r = await mcp.call('x64dbg_database', { action: 'strings', module: 'x', limit: 100 });
  let data = parseJson(r.text);
  assert.equal(data.total, 600);
  assert.equal(data.returned, 100);
  assert.equal(data.truncated, true);
  assert.equal(data.strings.length, 100);

  r = await mcp.call('x64dbg_database', { action: 'strings', module: 'x', limit: 100, offset: 500 });
  data = parseJson(r.text);
  assert.equal(data.returned, 100);
  assert.equal(data.truncated, false);

  r = await mcp.call('x64dbg_analysis', { action: 'xrefs_to', query: '0x1000', limit: 50 });
  data = parseJson(r.text);
  assert.equal(data.total, 600);
  assert.equal(data.xrefs.length, 50);

  r = await mcp.call('x64dbg_search', { action: 'string', query: 'x', limit: 50 });
  data = parseJson(r.text);
  assert.equal(data.total, 600);
  assert.equal(data.matches.length, 50);

  // --- event cap keeps the remainder buffered ----------------------------
  r = await mcp.call('x64dbg_command', { action: 'get_events', max_events: 50 });
  data = parseJson(r.text);
  assert.equal(data.count, 300);
  assert.equal(data.returned, 50);
  assert.equal(data.truncated, true);

  r = await mcp.call('x64dbg_command', { action: 'get_events', max_events: 50 });
  data = parseJson(r.text);
  assert.equal(data.count, 250);
  assert.equal(data.returned, 50);
  assert.equal(data.events[0].seq, 51);

  // --- structured plugin error -------------------------------------------
  state.failProcess = true;
  state.processHits = 0;
  r = await mcp.call('x64dbg_process', { action: 'basic' });
  assert.equal(r.isError, true);
  const err = parseJson(r.text);
  assert.equal(err.error.code, 409);
  assert.match(err.error.hint, /wrong state|Load or attach/i);
  // A definite plugin error must not be retried: retrying a non-idempotent
  // POST would double-apply memory writes/patches.
  assert.equal(state.processHits, 1);
  state.failProcess = false;

  // --- audit log ----------------------------------------------------------
  r = await mcp.call('x64dbg_memory', { action: 'write', address: '0x1000', bytes: '90' });
  assert.equal(r.isError, false);
  const auditFile = path.join(tempDir, 'x64dbg-mcp', 'audit.log');
  const lines = fs.readFileSync(auditFile, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.ok(lines.some((l) => l.tool === 'x64dbg_memory' && l.action === 'write' && l.instance === 'default'));
});

test('block_terminate patches and restores termination APIs', { timeout: 60000 }, async (t) => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'x64dbg-mcp-bt-'));
  state.paused = true;
  state.symbols = {
    'kernelbase.TerminateProcess': '0x1000',
    'kernelbase.ExitProcess': '0x2000',
    'kernelbase.TerminateThread': '0x3000',
    'ntdll.NtTerminateProcess': '0x4000',
    'ntdll.NtTerminateThread': '0x5000',
    'ntdll.RtlExitUserThread': '0x6000',
  };
  state.memory = {
    '0x1000': '48 89 5C 24 08 57',
    '0x2000': '40 53 48 83 EC 20',
    '0x3000': '4C 8B DC 49 89 5B',
    '0x4000': '4C 8B D1',
    '0x5000': '4C 8B D1',
    '0x6000': '40',
  };
  state.patchWrites = [];
  state.memWrites = [];

  const server = await startFakePlugin();
  const mcp = startMcp(server.address().port, tempDir);
  t.after(() => {
    try { mcp.child.kill(); } catch {}
    server.close();
    try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {}
  });
  await mcp.ready;

  let r = await mcp.call('x64dbg_antidebug', { action: 'block_terminate' });
  assert.equal(r.isError, false);
  const blocked = parseJson(r.text);
  assert.equal(blocked.patched.length, 6);
  assert.equal(state.memory['0x1000'], 'B8 01 00 00 00 C3');
  assert.equal(state.memory['0x4000'], '33 C0 C3');
  assert.equal(state.memory['0x6000'], 'C3');

  r = await mcp.call('x64dbg_antidebug', { action: 'block_terminate', restore: true });
  assert.equal(r.isError, false);
  assert.equal(state.memory['0x1000'], '48 89 5C 24 08 57');
  assert.equal(state.memory['0x4000'], '4C 8B D1');
  assert.equal(state.memWrites.length, 6);
});
