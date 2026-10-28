import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Must be set before importing config.ts (the lease code reads it at load).
process.env.X64DBG_MCP_LEASE_IDLE_MS = '60000';
const lease = await import('../dist/lease.js');

const HOST = '127.0.0.1';
const PORT = 27999;
const DIR = path.join(os.tmpdir(), 'x64dbg-mcp', 'leases');
const FILE = path.join(DIR, 'ep_127.0.0.1_27999.lease');
const now = Date.now();

function record(lastCall, token = 'other') {
  return {
    instance: 'test',
    endpoint: `${HOST}:${PORT}`,
    pid: process.pid,
    host: os.hostname(),
    started_at: now - 300_000,
    heartbeat: now,
    last_call: lastCall,
    token,
  };
}

function writeLease(value) {
  fs.mkdirSync(DIR, { recursive: true });
  fs.writeFileSync(FILE, JSON.stringify(value));
}

after(() => {
  lease.releaseLease(HOST, PORT);
  try { fs.unlinkSync(FILE); } catch { /* already gone */ }
});

test('an idle lease is reclaimed', () => {
  writeLease(record(now - 120_000));
  const result = lease.acquireLease('test', HOST, PORT);
  assert.equal(result.ok, true);
  assert.equal(result.reclaimed, true);
  lease.releaseLease(HOST, PORT);
});

test('an active lease conflicts; force takes it over', () => {
  writeLease(record(now));

  const acquire = lease.acquireLease('test', HOST, PORT);
  assert.equal(acquire.ok, false);
  assert.equal(acquire.holder?.token, 'other');

  const polite = lease.takeOverLease('test', HOST, PORT, false);
  assert.equal(polite.ok, false);

  const forced = lease.takeOverLease('test', HOST, PORT, true);
  assert.equal(forced.ok, true);
  assert.equal(forced.previous?.token, 'other');

  lease.releaseLease(HOST, PORT);
});
