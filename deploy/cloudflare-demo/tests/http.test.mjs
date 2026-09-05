import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { DemoQueue, QueueError } from '../src/queue.mjs';
import { handleRequest, visitor, localMode } from '../src/http.mjs';

const encode = new TextEncoder();
const EVENT = 'event: result\ndata: {"value":17.25}\n\n';
const DONE = 'event: done\ndata: {}\n\n';
const STOPPED = 'event: opaque_execution_complete\ndata: {}\n\n';

function fixture(t, modelIds = ['gemma4-e2b'], defaultModel = 'gemma4-e2b') {
  let state = null;
  const result = {
    now: 1_800_000_000_000, calls: [], requests: [], network: [], background: [],
    bot: { success: true, action: 'demo_join', hostname: 'demo.example' },
  };
  t.mock.method(Date, 'now', () => result.now);
  result.queue = new DemoQueue({ transaction(callback) {
    const output = callback(structuredClone(state));
    state = structuredClone(output.state);
    return output.result;
  } }, { modelIds });
  result.env = {
    PUBLIC_ORIGIN: 'https://demo.example', DEMO_ENABLED: 'true', DEMO_CAPACITY: '1',
    DEMO_MODEL_IDS: modelIds.join(','), DEMO_DEFAULT_MODEL: defaultModel,
    CONTROLLER_ORIGIN: 'https://controller.example', CONTROLLER_SECRET: 'c'.repeat(64),
    TURNSTILE_SITE_KEY: 'fixture-only-site-key', TURNSTILE_SECRET: 'fixture-only-bot-secret',
    ASSETS: { fetch: async () => new Response('<html><body><script>window.fixture=true;</script></body></html>') },
    DEMO_SCHEDULER: {
      idFromName: (name) => { assert.equal(name, 'global-capacity-v1'); return name; },
      get: () => ({ fetch: async (_url, init) => {
        const { action, args } = JSON.parse(init.body);
        result.calls.push({ action, args });
        try {
          let data;
          switch (action) {
            case 'admit': data = result.queue.join(args[0], args[2], result.now, 0); break;
            case 'status': data = result.queue.status(args[0], result.now); break;
            case 'cancel': data = result.queue.cancel(args[0], result.now); break;
            case 'authorize': data = result.queue.authorize(args[0], result.now); break;
            case 'work': data = result.queue.work(result.now); break;
            case 'report': data = result.queue.report(args[0], result.now); break;
            case 'reserveChat': data = result.queue.reserveChat(args[0], args[1], result.now); break;
            case 'finishChat': data = result.queue.finishChat(args[0], args[1], result.now); break;
            default: throw new Error('unexpected scheduler action');
          }
          result.queue.work(result.now); // Mirrors the DO's alarm-arm sweep.
          return Response.json(data);
        } catch (error) {
          if (!(error instanceof QueueError)) throw error;
          return Response.json({ error: error.code }, { status: error.status });
        }
      } }),
    },
  };
  result.ctx = { waitUntil(promise) { result.background.push(promise); } };
  result.stream = () => new Response(EVENT + DONE + STOPPED, { headers: { 'Content-Type': 'text/event-stream' } });
  t.mock.method(globalThis, 'fetch', async (destination, init) => {
    const url = String(destination);
    result.network.push(url);
    if (url === 'https://challenges.cloudflare.com/turnstile/v0/siteverify') {
      const fields = new URLSearchParams(init.body);
      assert.equal(fields.get('secret'), result.env.TURNSTILE_SECRET);
      assert.ok(fields.get('idempotency_key'));
      assert.equal(init.redirect, 'manual');
      return result.botResponse ? result.botResponse() : Response.json(result.bot);
    }
    assert.equal(new URL(url).origin, result.env.CONTROLLER_ORIGIN, 'unexpected external request');
    result.requests.push({ url, init });
    return result.stream();
  });
  result.request = (path, { method = 'GET', body, cookie = result.cookie, headers = {}, origin = result.env.PUBLIC_ORIGIN } = {}) => {
    const requestHeaders = new Headers(headers);
    if (origin !== null) requestHeaders.set('Origin', origin);
    if (cookie) requestHeaders.set('Cookie', cookie);
    requestHeaders.set('CF-Connecting-IP', '192.0.2.55');
    if (body !== undefined) requestHeaders.set('Content-Type', 'application/json');
    return new Request(result.env.PUBLIC_ORIGIN + path, {
      method, headers: requestHeaders, body: body === undefined ? undefined : JSON.stringify(body),
    });
  };
  result.send = (path, options) => handleRequest(result.request(path, options), result.env, result.ctx);
  result.join = async (modelId = 'gemma4-e2b') => {
    const response = await result.send('/demo/api/join', { method: 'POST', body: { model_id: modelId, turnstile_token: 'fixture-challenge' } });
    assert.equal(response.status, 200);
    result.cookie = response.headers.get('Set-Cookie').split(';')[0];
    const raw = await visitor(result.request('/'), result.env);
    assert.match(raw, /^[a-f0-9]{64}$/);
    result.hash = createHash('sha256').update(raw).digest('hex');
    return response;
  };
  result.ready = async (modelId = 'gemma4-e2b') => {
    await result.join(modelId);
    const action = result.queue.work(result.now).actions[0];
    result.now++;
    result.lease = result.queue.report({ kind: 'ready', lease_id: action.lease_id, slot: action.slot, generation: action.generation }, result.now);
    result.calls.length = result.network.length = result.requests.length = 0;
  };
  result.drainBackground = async () => {
    let cursor = 0;
    do {
      await Promise.all(result.background.slice(cursor));
      cursor = result.background.length;
      await nextTurn();
    } while (cursor < result.background.length);
  };
  result.chats = () => result.calls.filter((call) => call.action === 'finishChat');
  return result;
}

function streamFixture(parts, { fail = false } = {}) {
  let reads = 0, cancelled = false;
  const response = new Response(new ReadableStream({
    pull(controller) {
      const index = reads++;
      if (index < parts.length) controller.enqueue(encode.encode(parts[index]));
      else if (fail) controller.error(new Error('fixture transport ended ambiguously'));
      else controller.close();
    },
    cancel() { cancelled = true; },
  }, { highWaterMark: 0 }), { headers: { 'Content-Type': 'text/event-stream' } });
  return { response, reads: () => reads, cancelled: () => cancelled };
}

test('model catalog defaults to Gemma and exposes presentation metadata only', async (t) => {
  const f = fixture(t);
  delete f.env.DEMO_MODEL_IDS;
  delete f.env.DEMO_DEFAULT_MODEL;
  const response = await f.send('/demo/api/config');
  assert.equal(response.status, 200);
  const config = await response.json();
  assert.equal(Object.hasOwn(config, 'capacity'), false);
  assert.equal(config.default_model, 'gemma4-e2b');
  assert.deepEqual(config.models.map(model => model.id), ['gemma4-e2b']);
  assert.deepEqual(Object.keys(config.models[0]).sort(), ['description', 'id', 'label']);
  assert.ok(!JSON.stringify(config.models).includes('http'));
  assert.equal(f.calls.length, 0);
  assert.equal(f.network.length, 0);
});

test('organization controls remain lease-scoped without charging or resetting model questions', async (t) => {
  const f = fixture(t);
  await f.ready();
  f.stream = () => Response.json({ expires_at: f.now + 900000, model: { id: 'qwen35-4b' }, organization: { persona: 'engineer', support_case: { expires_at: Math.floor(f.now/1000)+900 } } });
  for (const [path, body] of [
    ['/api/demo/persona', { persona_id: 'engineer' }],
    ['/api/demo/persona', { persona_id: 'support', reason: 'Investigate this customer request' }],
    ['/api/organization/sharing', { enabled: true }],
  ]) {
    const response = await f.send(path, { method: 'POST', body, headers: {
      Authorization: 'Bearer browser-must-not-forward', 'X-Tenant-Id': 'other-customer', 'X-Role': 'admin',
    } });
    assert.equal(response.status, 200);
    const view=await response.json();
    assert.equal(view.model.id,'gemma4-e2b');
    assert.equal(view.expires_at,new Date(f.lease.expires_at).toISOString());
    assert.equal(view.demo.expires_at,f.lease.expires_at);
    assert.equal(view.organization.support_case.expires_at,Math.floor(f.lease.expires_at/1000));
    const sent = f.requests.at(-1);
    assert.equal(new URL(sent.url).pathname, `/sessions/${f.lease.lease_id}/proxy${path}`);
    assert.deepEqual(JSON.parse(sent.init.body), body);
    assert.equal(sent.init.headers.Authorization, 'Bearer ' + f.env.CONTROLLER_SECRET);
    assert.ok(!JSON.stringify(sent.init.headers).includes('other-customer'));
    assert.ok(!JSON.stringify(sent.init.headers).includes('browser-must-not-forward'));
  }
  const activity=await f.send('/api/organization/activity');
  assert.equal(activity.status,200);
  assert.equal((await activity.json()).organization.support_case.expires_at,Math.floor(f.lease.expires_at/1000));
  assert.equal(f.requests.at(-1).init.method, 'GET');
  assert.deepEqual(f.calls.map(call => call.action), ['authorize', 'authorize', 'authorize', 'authorize']);
  assert.equal(f.queue.status(f.hash, f.now).questions_remaining, 12);
});

test('organization controls reject added authority, missing reasons and wrong methods before dispatch', async (t) => {
  const f = fixture(t);
  await f.ready();
  for (const [path, body] of [
    ['/api/demo/persona', { persona_id: 'admin' }],
    ['/api/demo/persona', { persona_id: 'engineer', tenant_id: 'other' }],
    ['/api/demo/persona', { persona_id: 'support' }],
    ['/api/demo/persona', { persona_id: 'support', reason: 'short' }],
    ['/api/demo/persona', { persona_id: 'support', reason: 'line one\nline two' }],
    ['/api/demo/persona', { persona_id: 'support', reason: 'a'.repeat(241) }],
    ['/api/demo/persona', { persona_id: 'support', reason: 'Investigate this request', expires_at: f.now + 900000 }],
    ['/api/organization/sharing', { enabled: 'true' }],
    ['/api/organization/sharing', { enabled: true, tenant_id: 'other' }],
  ]) assert.equal((await f.send(path, { method: 'POST', body })).status, 400);
  assert.equal((await f.send('/api/demo/persona')).status, 405);
  assert.equal((await f.send('/api/organization/activity', { method: 'POST', body: {} })).status, 405);
  assert.equal((await f.send('/api/demo/persona', { method: 'POST', body: { persona_id: 'engineer' }, origin: 'https://other.example' })).status, 403);
  assert.equal((await f.send('/api/demo/persona?tenant=other', { method: 'POST', body: { persona_id: 'engineer' } })).status, 400);
  assert.equal(f.calls.length, 0);
  assert.equal(f.requests.length, 0);
});

test('organization reads and controls cannot use an expired or missing visitor lease', async (t) => {
  const f = fixture(t);
  assert.equal((await f.send('/api/organization/activity')).status, 401);
  await f.ready();
  f.now = f.lease.expires_at;
  assert.notEqual((await f.send('/api/organization/activity')).status, 200);
  assert.notEqual((await f.send('/api/demo/persona', { method: 'POST', body: { persona_id: 'engineer' } })).status, 200);
  assert.equal(f.requests.length, 0);
  assert.ok(f.calls.every(call => call.action === 'authorize'));
});

test('model catalog configuration fails closed without silently choosing another model', async (t) => {
  const f = fixture(t);
  for (const [ids, defaultModel] of [
    ['', 'gemma4-e2b'], ['unknown', 'gemma4-e2b'],
    ['gemma4-e2b,gemma4-e2b', 'gemma4-e2b'],
    ['qwen35-4b', 'gemma4-e2b'], ['gemma4-e2b', 'qwen35-4b'],
  ]) {
    f.env.DEMO_MODEL_IDS = ids;
    f.env.DEMO_DEFAULT_MODEL = defaultModel;
    const response = await f.send('/demo/api/config');
    assert.equal(response.status, 503);
    assert.equal((await response.json()).error, 'invalid_model_configuration');
  }
  assert.equal(f.calls.length, 0);
  assert.equal(f.network.length, 0);
});

test('new joins require exactly an enabled canonical model alias before bot or durable calls', async (t) => {
  const f = fixture(t);
  for (const body of [
    { turnstile_token: 'fixture' },
    { turnstile_token: 'fixture', model_id: null },
    ...['', 'qwen35-4b', 'qwen3-14b', 'unknown', 'gemma4-e2b ', 'https://model.example'].map(model_id => ({ turnstile_token: 'fixture', model_id })),
    { turnstile_token: 'fixture', model_id: 'gemma4-e2b', model_url: 'https://model.example' },
  ]) {
    const response = await f.send('/demo/api/join', { method: 'POST', body });
    assert.equal(response.status, 400);
    assert.equal(response.headers.get('Set-Cookie'), null);
  }
  assert.equal(f.calls.length, 0);
  assert.equal(f.network.length, 0);
});

test('chosen model persists across admission, reload and polling; another choice cannot replace it', async (t) => {
  const f = fixture(t, ['gemma4-e2b', 'qwen35-4b'], 'qwen35-4b');
  const config = await (await f.send('/demo/api/config')).json();
  assert.deepEqual(config.models.map(model => model.id), ['gemma4-e2b', 'qwen35-4b']);
  assert.equal(config.default_model, 'qwen35-4b');
  const response = await f.join('qwen35-4b');
  const selected = { id: 'qwen35-4b', label: 'Qwen3.5 4B' };
  assert.deepEqual((await response.json()).model, selected);
  const admit = f.calls.find(call => call.action === 'admit');
  assert.equal(admit.args.length, 3);
  assert.equal(admit.args[2], selected.id);
  const repeated = await f.send('/demo/api/join', { method: 'POST', body: { turnstile_token: 'already-used', model_id: selected.id } });
  assert.equal(repeated.status, 200);
  assert.deepEqual((await repeated.json()).model, selected);
  const switched = await f.send('/demo/api/join', { method: 'POST', body: { turnstile_token: 'fixture', model_id: 'gemma4-e2b' } });
  assert.equal(switched.status, 409);
  assert.equal((await switched.json()).error, 'model_selection_immutable');
  assert.equal(f.calls.filter(call => call.action === 'admit').length, 1);
  assert.equal(f.network.filter(url => url.includes('siteverify')).length, 1);
  assert.deepEqual((await (await f.send('/demo/api/session')).json()).model, selected);
  // An operator can disable new choices without changing a durable session.
  f.env.DEMO_MODEL_IDS = 'gemma4-e2b';
  f.env.DEMO_DEFAULT_MODEL = 'gemma4-e2b';
  assert.deepEqual((await (await f.send('/demo/api/session')).json()).model, selected);
  const disabled = await f.send('/demo/api/join', { method: 'POST', body: { turnstile_token: 'fixture', model_id: selected.id }, cookie: null });
  assert.equal(disabled.status, 400);
  assert.equal(f.calls.filter(call => call.action === 'admit').length, 1);
});

test('workspace session model comes from the durable lease even if upstream metadata disagrees', async (t) => {
  const f = fixture(t, ['gemma4-e2b', 'qwen35-4b']);
  await f.ready('qwen35-4b');
  f.stream = () => Response.json({ customer: { id: f.lease.tenant_id }, model: { id: 'untrusted', label: 'Untrusted' }, runtime: { kind: 'openai_compatible', label: 'Actual configured model' } });
  const session = await (await f.send('/api/session')).json();
  assert.deepEqual(session.model, { id: 'qwen35-4b', label: 'Qwen3.5 4B' });
  assert.equal(session.runtime.label, 'Actual configured model');
  const cancel = await f.send('/demo/api/cancel', { method: 'POST', body: {} });
  assert.equal(cancel.status, 200);
  assert.deepEqual((await cancel.json()).model, session.model);
  assert.equal(f.requests.length, 1);
});

test('join mints a domain-separated MAC cookie; valid reload retains the same admission', async (t) => {
  const f = fixture(t);
  const response = await f.join();
  const header = response.headers.get('Set-Cookie');
  assert.match(header, /^__Host-opaque_demo=[a-f0-9]{64}\.[a-f0-9]{64};/);
  assert.ok(header.includes('Secure'));
  assert.ok(header.includes('HttpOnly'));
  assert.ok(header.includes('SameSite=Strict'));
  const [random, mac] = f.cookie.split('=')[1].split('.');
  assert.equal(mac, createHmac('sha256', f.env.CONTROLLER_SECRET).update('visitor-v1:' + random).digest('hex'));
  assert.equal(f.calls.filter((call) => call.action === 'admit').length, 1);
  const repeated = await f.send('/demo/api/join', { method: 'POST', body: { model_id: 'gemma4-e2b', turnstile_token: 'already-used' } });
  assert.equal(repeated.status, 200);
  assert.equal(f.calls.filter((call) => call.action === 'admit').length, 1);
  assert.equal(f.network.filter((url) => url.includes('siteverify')).length, 1);
});

test('fabricated, duplicate, wrong-key and wrong-domain cookies make zero scheduler calls', async (t) => {
  const f = fixture(t);
  await f.join();
  const [random, validMac] = f.cookie.split('=')[1].split('.');
  const cookies = [
    '__Host-opaque_demo=' + random,
    '__Host-opaque_demo=' + random + '.' + '0'.repeat(64),
    '__Host-opaque_demo=' + 'b'.repeat(64) + '.' + validMac,
    '__Host-opaque_demo=' + random + '.' + createHmac('sha256', 'other-secret').update('visitor-v1:' + random).digest('hex'),
    '__Host-opaque_demo=' + random + '.' + createHmac('sha256', f.env.CONTROLLER_SECRET).update(random).digest('hex'),
    f.cookie + '; ' + f.cookie,
    'opaque_demo_local=' + f.cookie.split('=')[1],
  ];
  f.calls.length = f.network.length = 0;
  for (const cookie of cookies) {
    assert.equal(await visitor(f.request('/', { cookie }), f.env), null);
    const session = await f.send('/demo/api/session', { cookie });
    assert.equal((await session.json()).state, 'none');
    assert.equal((await f.send('/workspace', { cookie })).status, 401);
    assert.equal((await f.send('/api/chat', { method: 'POST', cookie, body: { message: 'test' } })).status, 401);
  }
  assert.equal(f.calls.length, 0);
  assert.equal(f.network.length, 0);
});

test('bot admission verifies exact action and hostname and never accepts a browser priority', async (t) => {
  const f = fixture(t);
  for (const bot of [
    { success: false, action: 'demo_join', hostname: 'demo.example' },
    { success: true, action: 'other_action', hostname: 'demo.example' },
    { success: true, action: 'demo_join', hostname: 'other.example' },
  ]) {
    f.bot = bot;
    const denied = await f.send('/demo/api/join', { method: 'POST', body: { model_id: 'gemma4-e2b', turnstile_token: 'fixture' } });
    assert.equal(denied.status, 403);
  }
  const before = f.network.length;
  assert.equal((await f.send('/demo/api/join', { method: 'POST', body: { model_id: 'gemma4-e2b', turnstile_token: 'fixture', priority: 1 } })).status, 400);
  assert.equal(f.network.length, before);
  assert.equal(f.calls.length, 0);
});

test('local bot bypass cannot activate on a public HTTPS origin', async (t) => {
  const f = fixture(t);
  f.env.LOCAL_TEST_MODE = 'enabled';
  f.bot.success = false;
  assert.equal(localMode(f.env), false);
  const denied = await f.send('/demo/api/join', { method: 'POST', body: { model_id: 'gemma4-e2b', turnstile_token: 'local-demo-test-only' } });
  assert.equal(denied.status, 403);
  assert.equal(f.calls.length, 0);
});

test('bot verification redirects never admit a visitor or forward the bot secret', async (t) => {
  const f = fixture(t);
  for (const status of [301, 302, 303, 307, 308]) {
    f.botResponse = () => new Response(null, { status, headers: { Location: 'https://untrusted.example/collect' } });
    f.network.length = 0;
    const denied = await f.send('/demo/api/join', { method: 'POST', body: { model_id: 'gemma4-e2b', turnstile_token: 'fixture' } });
    assert.equal(denied.status, 403);
    assert.equal(denied.headers.get('Location'), null);
    assert.equal(denied.headers.get('Set-Cookie'), null);
    assert.deepEqual(f.network, ['https://challenges.cloudflare.com/turnstile/v0/siteverify']);
    assert.equal(f.calls.length, 0);
  }
});

test('same-origin, query, internal authentication and strict body gates precede durable work', async (t) => {
  const f = fixture(t);
  const cross = await f.send('/demo/api/join', { method: 'POST', origin: 'https://other.example', body: { model_id: 'gemma4-e2b', turnstile_token: 'fixture' } });
  assert.equal(cross.status, 403);
  const missing = await f.send('/demo/api/join', { method: 'POST', origin: null, body: { model_id: 'gemma4-e2b', turnstile_token: 'fixture' } });
  assert.equal(missing.status, 403);
  assert.equal((await f.send('/demo/api/session?tenant_id=foreign')).status, 400);
  assert.equal((await f.send('/internal/work')).status, 401);
  assert.equal((await f.send('/internal/report', { method: 'POST', body: {} })).status, 401);
  const foreign = await handleRequest(new Request('https://foreign.example/demo/api/session'), f.env, f.ctx);
  assert.equal(foreign.status, 421);
  assert.equal(f.calls.length, 0);
  assert.equal(f.network.length, 0);
});

test('unsupported chat fields and invalid idempotency keys never reserve or reach the controller', async (t) => {
  const f = fixture(t);
  await f.ready();
  for (const body of [{ message: 'test', tenant_id: 'other' }, { message: 'test', priority: 1 }, { message: 'x'.repeat(2001) }, { message: '   ' }]) {
    assert.equal((await f.send('/api/chat', { method: 'POST', body })).status, 400);
  }
  for (const key of ['two keys', 'bad,key', 'x'.repeat(129), '.prefix']) {
    assert.equal((await f.send('/api/chat', { method: 'POST', body: { message: 'test' }, headers: { 'Idempotency-Key': key } })).status, 400);
  }
  assert.equal(f.calls.length, 0);
  assert.equal(f.requests.length, 0);
});

test('fixed proxy destination and authority replace all browser-supplied controller headers', async (t) => {
  const f = fixture(t);
  await f.ready();
  const response = await f.send('/api/chat', { method: 'POST', body: { message: 'What is my request rate?' }, headers: {
    'Authorization': 'Bearer visitor-injected', 'X-Opaque-Lease-Generation': '999',
    'X-Opaque-Lease-Expires-At': '9999999999999', 'Idempotency-Key': 'question-1',
  } });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('Idempotency-Key'), 'question-1');
  const forwarded = f.requests[0];
  assert.equal(forwarded.url, 'https://controller.example/sessions/' + f.lease.lease_id + '/proxy/api/chat');
  const headers = new Headers(forwarded.init.headers);
  assert.equal(headers.get('Authorization'), 'Bearer ' + f.env.CONTROLLER_SECRET);
  assert.equal(headers.get('X-Opaque-Lease-Generation'), String(f.lease.generation));
  assert.equal(headers.get('X-Opaque-Lease-Expires-At'), String(f.lease.expires_at));
  assert.equal(headers.get('Cookie'), null);
  assert.equal(forwarded.init.redirect, 'manual');
  assert.deepEqual(JSON.parse(forwarded.init.body), { message: 'What is my request rate?' });
  await response.text();
  assert.equal(f.chats().length, 1);
});

test('controller redirects never forward authority or release an ambiguous chat reservation', async (t) => {
  const f = fixture(t);
  await f.ready();
  f.stream = () => new Response(null, { status: 307, headers: { Location: 'https://untrusted.example/collect' } });
  const denied = await f.send('/api/chat', { method: 'POST', body: { message: 'test' } });
  assert.equal(denied.status, 502);
  assert.equal((await denied.json()).error, 'controller_redirect_rejected');
  assert.equal(denied.headers.get('Location'), null);
  assert.deepEqual(f.network, ['https://controller.example/sessions/' + f.lease.lease_id + '/proxy/api/chat']);
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].init.redirect, 'manual');
  assert.equal(f.chats().length, 0);
  assert.equal(f.queue.status(f.hash, f.now).chat_busy, true);
});

test('completed stream releases once; a repeated idempotency key never dispatches again', async (t) => {
  const f = fixture(t);
  await f.ready();
  const response = await f.send('/api/chat', { method: 'POST', body: { message: 'test' }, headers: { 'Idempotency-Key': 'stable-request' } });
  assert.equal(await response.text(), EVENT + DONE + STOPPED);
  assert.equal(f.chats().length, 1);
  assert.equal(f.queue.status(f.hash, f.now).chat_busy, false);
  const replay = await f.send('/api/chat', { method: 'POST', body: { message: 'modified question' }, headers: { 'Idempotency-Key': 'stable-request' } });
  assert.equal(replay.status, 409);
  assert.equal(f.requests.length, 1);
  assert.equal(f.queue.status(f.hash, f.now).questions_remaining, 11);
});

test('an unpolled response reads no upstream chunks and cannot deliver after expiry', async (t) => {
  const f = fixture(t);
  await f.ready();
  const upstream = streamFixture([EVENT, DONE, STOPPED]);
  f.stream = () => upstream.response;
  const response = await f.send('/api/chat', { method: 'POST', body: { message: 'test' } });
  await nextTurn();
  assert.equal(upstream.reads(), 0);
  assert.equal(f.calls.filter((call) => call.action === 'authorize').length, 0);
  f.now = f.lease.expires_at;
  await assert.rejects(response.body.getReader().read(), /demo_stream_interrupted/);
  await f.drainBackground();
  assert.ok(upstream.reads() > 1, 'accepted upstream should be drained');
  assert.equal(upstream.cancelled(), false);
  assert.equal(f.chats().length, 1, 'only authenticated completion can clear the model fence');
  assert.equal(f.requests.length, 1, 'no automatic request retry');
  assert.equal(f.queue.status(f.hash, f.now).state, 'cleaning');
});

test('cancelling a lease before consuming its response prevents every queued result', async (t) => {
  const f = fixture(t);
  await f.ready();
  const upstream = streamFixture([EVENT, DONE, STOPPED]);
  f.stream = () => upstream.response;
  const response = await f.send('/api/chat', { method: 'POST', body: { message: 'test' } });
  assert.equal(upstream.reads(), 0);
  const cancelled = await f.send('/demo/api/cancel', { method: 'POST', body: {} });
  assert.equal(cancelled.status, 200);
  await assert.rejects(response.body.getReader().read());
  await f.drainBackground();
  assert.equal(f.queue.status(f.hash, f.now).state, 'cleaning');
  assert.equal(f.chats().length, 1);
  assert.equal(f.requests.length, 1);
});

test('browser cancellation drains accepted work without delivering data or refunding charge', async (t) => {
  const f = fixture(t);
  await f.ready();
  const upstream = streamFixture([EVENT, DONE, STOPPED]);
  f.stream = () => upstream.response;
  const response = await f.send('/api/chat', { method: 'POST', body: { message: 'test' } });
  assert.equal(upstream.reads(), 0);
  await response.body.cancel();
  await f.drainBackground();
  assert.ok(upstream.reads() > 1);
  assert.equal(upstream.cancelled(), false);
  assert.equal(f.chats().length, 1);
  assert.equal(f.queue.status(f.hash, f.now).questions_remaining, 11);
  assert.equal(f.queue.status(f.hash, f.now).chat_busy, false);
});

test('cancellation racing an outstanding pull serializes the remaining drain', { timeout: 2000 }, async (t) => {
  const f = fixture(t);
  await f.ready();
  let allowFirst;
  const gate = new Promise((resolve) => { allowFirst = resolve; });
  let reads = 0;
  f.stream = () => new Response(new ReadableStream({
    async pull(controller) {
      const index = reads++;
      if (index === 0) await gate;
      const part = [EVENT, DONE, STOPPED][index];
      if (part) controller.enqueue(encode.encode(part));
      else controller.close();
    },
  }, { highWaterMark: 0 }), { headers: { 'Content-Type': 'text/event-stream' } });
  const response = await f.send('/api/chat', { method: 'POST', body: { message: 'test' } });
  const consumer = response.body.getReader();
  const pending = consumer.read();
  await nextTurn();
  assert.equal(reads, 1);
  await consumer.cancel();
  assert.deepEqual(await pending, { done: true, value: undefined });
  allowFirst();
  await f.drainBackground();
  assert.equal(reads, 4);
  assert.equal(f.chats().length, 1);
  assert.equal(f.requests.length, 1);
});

test('excessive upstream output terminates delivery and keeps uncertain work charged', async (t) => {
  const f = fixture(t);
  await f.ready();
  const upstream = streamFixture(['x'.repeat(262145), DONE, STOPPED]);
  f.stream = () => upstream.response;
  const response = await f.send('/api/chat', { method: 'POST', body: { message: 'test' } });
  await assert.rejects(response.text(), /demo_stream_interrupted/);
  await f.drainBackground();
  assert.equal(upstream.cancelled(), true);
  assert.equal(f.chats().length, 0);
  assert.equal(f.queue.status(f.hash, f.now).chat_busy, true);
  assert.equal(f.queue.status(f.hash, f.now).questions_remaining, 11);
});

test('clean EOF without both completion proofs retains the global model fence', async (t) => {
  const f = fixture(t);
  await f.ready();
  f.stream = () => new Response(EVENT + DONE, { headers: { 'Content-Type': 'text/event-stream' } });
  const response = await f.send('/api/chat', { method: 'POST', body: { message: 'test' } });
  assert.equal(await response.text(), EVENT + DONE);
  assert.equal(f.chats().length, 0);
  assert.equal(f.queue.status(f.hash, f.now).chat_busy, true);
  assert.equal(f.queue.status(f.hash, f.now).questions_remaining, 11);
});

test('ambiguous upstream termination stays charged even when the browser cancels', async (t) => {
  const f = fixture(t);
  await f.ready();
  const upstream = streamFixture([EVENT, DONE], { fail: true });
  f.stream = () => upstream.response;
  const response = await f.send('/api/chat', { method: 'POST', body: { message: 'test' } });
  await response.body.cancel();
  await f.drainBackground();
  assert.equal(f.chats().length, 0);
  assert.equal(f.queue.status(f.hash, f.now).chat_busy, true);
  assert.equal(f.requests.length, 1);
});

test('controller failures are not retried or mistaken for execution completion', async (t) => {
  const f = fixture(t);
  await f.ready();
  f.stream = () => new Response('rejected by fixture controller', { status: 503 });
  const response = await f.send('/api/chat', { method: 'POST', body: { message: 'test' } });
  assert.equal(response.status, 503);
  assert.equal(f.requests.length, 1);
  assert.equal(f.chats().length, 0);
  assert.equal(f.queue.status(f.hash, f.now).chat_busy, true);
});
