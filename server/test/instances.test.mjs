import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const SERVER_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function run(code, instances) {
  const env = { ...process.env };
  // Explicit X64DBG_MCP_INSTANCES is authoritative and skips the user manifest.
  env.X64DBG_MCP_INSTANCES = instances;
  env.X64DBG_MCP_TOKEN = 'test-token';
  delete env.X64DBG_MCP_MANIFEST;
  delete env.X64DBG_MCP_INSTANCE;

  const result = spawnSync(
    process.execPath,
    ['--input-type=module', '-e', code],
    { cwd: SERVER_DIR, env, encoding: 'utf8' }
  );
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result.stdout.trim();
}

const LIST = "import('./dist/instances.js').then(m => console.log(JSON.stringify(m.listInstances())))";

test('array form keeps ids, ports and declaration order', () => {
  const raw = run(LIST, JSON.stringify([
    { id: 'alpha', port: 27042 },
    { id: 'beta', port: 27043 },
  ]));
  const list = JSON.parse(raw);
  assert.deepEqual(list.map((i) => i.id), ['alpha', 'beta']);
  assert.deepEqual(list.map((i) => i.port), [27042, 27043]);
});

test('object form maps keys to ids', () => {
  const raw = run(LIST, JSON.stringify({
    alpha: { port: 27042 },
    beta: { port: 27043 },
  }));
  const list = JSON.parse(raw);
  assert.deepEqual(list.map((i) => i.id), ['alpha', 'beta']);
});

test('an invalid port is ignored instead of crashing the registry', () => {
  const raw = run(LIST, JSON.stringify([
    { id: 'alpha', port: 27042 },
    { id: 'bad', port: 70000 },
  ]));
  const list = JSON.parse(raw);
  assert.equal(list.length, 1);
  assert.equal(list[0].id, 'alpha');
});

test('an unknown id is a hard error naming the configured ids', () => {
  const code =
    "import('./dist/instances.js').then(m => { " +
    "try { m.getInstance('nope'); } catch (e) { console.log('ERR:' + e.message); } })";
  const out = run(code, JSON.stringify([{ id: 'alpha', port: 27042 }]));
  assert.match(out, /^ERR:/);
  assert.match(out, /alpha/);
});
