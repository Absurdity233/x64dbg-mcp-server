// Mock x64dbg plugin: a tiny HTTP server that answers the subset of the route
// table the debug state machine depends on. Tests drive it instead of a real
// x64dbg, so `load -> paused -> pause` can be asserted in CI without a debugger.
//
// Usage from a test:
//   const plugin = await startMockPlugin();
//   plugin.url            -> http://127.0.0.1:<port>
//   plugin.state          -> current debug state ('stopped'|'running'|'paused')
//   plugin.setState(s)    -> force the state
//   plugin.calls          -> every request, in order
//   await plugin.stop()

import { createServer } from 'node:http';

const json = (res, body, status = 200) => {
  const text = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text) });
  res.end(text);
};

// ok() mirrors the plugin's envelope: { success, data }
const ok = (res, data) => json(res, { data, success: true });

// The routes the server checks for on connect (see the "missing N route(s)"
// warning). Advertising exactly these keeps /api/meta honest for the mock.
const ROUTES = [
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

export async function startMockPlugin(options = {}) {
  const state = {
    current: 'stopped',
    // Sequence of states `load` walks through. The real `init` stops at the
    // system breakpoint, so a load has to reach 'paused', not 'running'.
    loadLandsIn: options.loadLandsIn ?? 'paused',
    // When true, /api/debug/pause answers success:false, which is what the
    // real plugin does when the target resists (fast-resume loop).
    pauseFails: options.pauseFails ?? false,
    // Events the mock hands out, in order. Each wait call pops what is queued.
    events: [],
    nextSeq: 1,
  };

  const calls = [];
  // Routes a test registers ad hoc, so a specific tool can be exercised with a
  // realistic payload without teaching the mock about every endpoint.
  const extras = new Map();
  const pushEvent = (type, details = {}) => {
    const ev = { seq: state.nextSeq++, tick_ms: Date.now(), type, ...details };
    state.events.push(ev);
    return ev;
  };

  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const path = url.pathname.replace(/^\/api\//, '');
    calls.push({ method: req.method, path, query: Object.fromEntries(url.searchParams) });

    // A test-registered route wins over the built-ins, so a test can shape a
    // payload (a 600-instruction function, a huge import table) on demand.
    const extra = extras.get(`${req.method} ${path}`) ?? extras.get(`GET ${path}`);
    if (extra) return ok(res, extra);

    // ---- health / meta -----------------------------------------------------
    if (path === 'health') {
      return ok(res, { plugin: 'x64dbg MCP Server (mock)', status: 'ok', version: '2.4.0', elevated: false, pid: 4242 });
    }

    // The server probes /api/meta on connect and compares the plugin's route
    // table against what it needs. Answering it keeps the probe from stalling.
    if (path === 'meta') {
      return ok(res, {
        plugin: 'x64dbg MCP Server (mock)',
        version: '2.4.0',
        arch: 'x64',
        route_count: ROUTES.length,
        routes: ROUTES,
      });
    }

    // ---- debug state machine ----------------------------------------------
    if (path === 'debug/state') {
      // `load` in the mock walks straight to the configured landing state, so
      // a caller polling for 'paused' sees it on the first read.
      return ok(res, { state: state.current });
    }

    if (path === 'debug/load' || path === 'command/exec') {
      if (state.current === 'stopped' || state.current === 'running') {
        state.current = state.loadLandsIn;
        // Loading a target always emits the startup burst.
        pushEvent('session_start', { file: 'mock.exe' });
        pushEvent('process_create', { file: 'mock.exe' });
        pushEvent('dll_load', { module: 'ntdll.dll' });
        pushEvent('paused', { address: '0x00007FF9AF3B9294' });
      }
      return ok(res, { command: 'init', success: true });
    }

    if (path === 'debug/pause') {
      if (state.pauseFails) {
        return ok(res, { message: 'Pause requested' });
      }
      state.current = 'paused';
      pushEvent('paused', { address: '0x00007FF9AF3B9294' });
      return ok(res, { message: 'Pause requested' });
    }

    if (path === 'debug/run') {
      state.current = 'running';
      pushEvent('resumed');
      return ok(res, { success: true });
    }

    if (path === 'debug/step_into' || path === 'debug/step_over' || path === 'debug/step_out') {
      state.current = 'paused';
      pushEvent('stepped', { address: '0x00007FF9AF2D1F90' });
      return ok(res, { success: true });
    }

    if (path === 'debug/stop') {
      state.current = 'stopped';
      pushEvent('session_stop');
      return ok(res, { success: true });
    }

    // ---- events -----------------------------------------------------------
    if (path === 'command/events') {
      const since = Number(url.searchParams.get('since') ?? '0');
      const max = url.searchParams.get('max');
      const events = state.events.filter((e) => e.seq > since);
      const latest = state.nextSeq - 1;
      if (max === '0') {
        return ok(res, { events: [], count: 0, latest_seq: latest, dropped: 0 });
      }
      return ok(res, { events, count: events.length, latest_seq: latest, dropped: 0, has_more: false });
    }

    if (path === 'command/events/wait') {
      const since = Number(url.searchParams.get('since') ?? '0');
      const types = url.searchParams.get('types');
      const want = types ? new Set(types.split(',')) : null;
      // Immediate answer: the test queues events before it calls wait.
      const events = state.events.filter((e) => e.seq > since && (!want || want.has(e.type)));
      const latest = state.nextSeq - 1;
      return ok(res, { events, count: events.length, latest_seq: latest, dropped: 0, timed_out: events.length === 0 });
    }

    // ---- assorted read routes some tools touch ----------------------------
    if (path === 'breakpoints/list') return ok(res, { breakpoints: [], count: 0 });
    if (path === 'modules/list') return ok(res, { modules: [], count: 0 });
    if (path === 'registers/all') return ok(res, { rip: '0x0' });
    if (path === 'consistency') return ok(res, { state: state.current });
    // Declared in ROUTES, so answer them instead of 404-ing a probe.
    if (path === 'antidebug/vm_probes') return ok(res, { probes: [], count: 0 });
    if (path === 'trace/auto/status') return ok(res, { running: false });
    if (path === 'trace/auto') return ok(res, { running: false });
    if (path === 'trace/auto/stop') return ok(res, { stopped: true });
    if (path === 'trace/thread') return ok(res, { started: false });
    if (path === 'dump/rebuild') return ok(res, { rebuilt: false });
    if (path === 'dump/fix_iat') return ok(res, { fixed: false });

    // Everything else: answer with an empty object so a tool that reaches for
    // an unexpected route does not crash the test with an HTML 404 body.
    return ok(res, {}) ;
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();

  return {
    url: `http://127.0.0.1:${port}`,
    port,
    calls,
    get state() {
      return state.current;
    },
    setState(s) {
      state.current = s;
    },
    setPauseFails(v) {
      state.pauseFails = v;
    },
    /**
     * Register a payload for one route.
     *   route('/api/disasm', 'get', { instructions: [...] })
     * The path may be given with or without the /api/ prefix.
     */
    route(pathname, method, payload) {
      const clean = pathname.replace(/^\/api\//, '').replace(/^\//, '');
      extras.set(`${String(method).toUpperCase()} ${clean}`, payload);
    },
    pushEvent,
    /** Events of one type, for assertions. */
    eventsOf(type) {
      return state.events.filter((e) => e.type === type);
    },
    async stop() {
      await new Promise((resolve) => server.close(resolve));
    },
  };
}