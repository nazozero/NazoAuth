import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { createServer } from 'node:net';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const deviceScript = await readFile(path.join(root, 'crates/server-worker/src/device.js'), 'utf8');
const loginScript = await readFile(path.join(root, 'crates/server-worker/src/passkey-login.js'), 'utf8');
const request = {
  client_name: '<img src=x onerror=alert(1)>', client_id: 'device-client',
  scopes: ['openid', 'profile'], resource_indicators: ['https://api.example'],
  authorization_details: [{ type: 'example', action: 'read' }],
  interval_seconds: 5, issued_at: '2029-12-31T23:50:00Z',
  expires_at: '2030-01-01T00:00:00Z',
};

class Element {
  constructor() {
    this.value = '';
    this.textContent = '';
    this.hidden = false;
    this.disabled = false;
    this.children = [];
    this.listeners = new Map();
  }
  addEventListener(type, handler) { this.listeners.set(type, handler); }
  append(child) { this.children.push(child); }
  replaceChildren() { this.children = []; }
  emit(type) { return this.listeners.get(type)?.({ preventDefault() {} }); }
}

function browser(script, { search = '?user_code=ABCD-EFGH', respond } = {}) {
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  element('details').hidden = true;
  element('approve').disabled = true;
  element('deny').disabled = true;
  const calls = [];
  const redirects = [];
  const history = [];
  const PublicKeyCredential = { parseRequestOptionsFromJSON: value => value };
  const context = vm.createContext({
    document: { getElementById: element, createElement: () => new Element() },
    location: { origin: 'https://auth.example', search, replace: value => redirects.push(value) },
    history: { replaceState: (_, __, value) => history.push(value) },
    URL, URLSearchParams, Uint8Array, atob,
    window: { PublicKeyCredential }, PublicKeyCredential,
    navigator: { credentials: { get: async () => ({ toJSON: () => ({ id: 'assertion' }) }) } },
    fetch: async (url, options) => {
      calls.push({ url, options });
      if (respond) return respond(url, options);
      if (url.startsWith('/device/verification?')) return Response.json({ request, csrf_token: 'old-csrf' });
      if (url === '/auth/csrf') return Response.json({ csrf_token: 'fresh-csrf' });
      if (url === '/device/decision') return new Response(null, { status: 200 });
      if (url === '/auth/passkey/begin') return Response.json({ ceremony_id: 'test', publicKey: {} });
      if (url === '/auth/passkey/finish') return Response.json({});
      throw new Error('Unexpected request: ' + url);
    },
  });
  vm.runInContext(script, context);
  return {
    element, calls, redirects, history,
    ready: async () => {
      // Drain the mocked fetch/Response.json promises without a timer delay.
      for (let count = 0; count < 4; count++) await new Promise(setImmediate);
    },
  };
}

test('device page displays the shared request as text and waits for an explicit decision', async () => {
  const page = browser(deviceScript);
  await page.ready();
  assert.deepEqual(page.calls.map(call => call.url), [
    '/device/verification?user_code=ABCD-EFGH', '/auth/csrf',
  ]);
  assert.equal(page.element('client').textContent, request.client_name);
  assert.equal(page.element('client').children.length, 0);
  assert.equal(page.element('client-id').textContent, request.client_id);
  assert.deepEqual(page.element('permissions').children.map(item => item.textContent), [
    'openid', 'profile', JSON.stringify(request.authorization_details[0]),
  ]);
  assert.equal(page.element('details').hidden, false);
  assert.equal(page.element('approve').disabled, false);
  for (const { options } of page.calls) {
    assert.equal(options.credentials, 'same-origin');
    assert.equal(options.cache, 'no-store');
    assert.equal(options.redirect, 'error');
  }
});

test('device decisions use the refreshed session CSRF token and suppress double submission', async () => {
  for (const decision of ['approve', 'deny']) {
    const page = browser(deviceScript);
    await page.ready();
    const first = page.element(decision).emit('click');
    assert.equal(page.element('approve').disabled, true);
    assert.equal(page.element('deny').disabled, true);
    await page.element(decision).emit('click');
    await first;
    const sent = page.calls.filter(call => call.url === '/device/decision');
    assert.equal(sent.length, 1);
    assert.equal(sent[0].options.method, 'POST');
    assert.deepEqual(Object.fromEntries(sent[0].options.body), {
      user_code: 'ABCD-EFGH', decision, csrf_token: 'fresh-csrf',
    });
    assert.equal(page.element('details').hidden, true);
    assert.equal(page.element('lookup').hidden, true);
    assert.equal(page.history.at(-1), '/device');
    assert.match(page.element('status').textContent, decision === 'approve' ? /已允许/ : /已拒绝/);
  }
});

test('device page handles manual entry and rejects missing or expired requests before login', async () => {
  const manual = browser(deviceScript, { search: '' });
  assert.equal(manual.calls.length, 0);
  await manual.element('lookup').emit('submit');
  assert.equal(manual.calls.length, 0);
  manual.element('user-code').value = 'ABCD EFGH';
  await manual.element('lookup').emit('submit');
  assert.equal(manual.calls[0].url, '/device/verification?user_code=ABCD+EFGH');
  assert.equal(manual.element('details').hidden, false);
  const expired = browser(deviceScript, {
    respond: () => Response.json({ request: null, csrf_token: null }),
  });
  await expired.ready();
  assert.equal(expired.calls.length, 1);
  assert.equal(expired.redirects.length, 0);
  assert.equal(expired.element('approve').disabled, true);
  assert.match(expired.element('status').textContent, /已过期/);
});

test('device page accepts omitted empty resource indicators in the shared serialized payload', async () => {
  const { resource_indicators, ...withoutResources } = request;
  const page = browser(deviceScript, {
    respond: url => url.startsWith('/device/verification?')
      ? Response.json({ user_code: 'ABCD-EFGH', csrf_token: null, request: withoutResources })
      : Response.json({ csrf_token: 'csrf' }),
  });
  await page.ready();
  assert.equal(page.element('details').hidden, false);
  assert.equal(page.element('resources').children.length, 0);
  assert.equal(page.element('expires').dateTime, request.expires_at);
});

test('device page redirects only unauthenticated sessions to Passkey with a local return path', async () => {
  for (const status of [401, 503]) {
    const page = browser(deviceScript, {
      respond: url => url.startsWith('/device/verification?')
        ? Response.json({ request }) : Response.json({ error: 'unavailable' }, { status }),
    });
    await page.ready();
    assert.equal(page.element('details').hidden, true);
    assert.equal(page.element('approve').disabled, true);
    if (status === 401) {
      assert.equal(page.redirects.length, 1);
      const login = new URL(page.redirects[0], 'https://auth.example');
      assert.equal(login.origin, 'https://auth.example');
      assert.equal(login.pathname, '/auth/passkey');
      assert.equal(login.searchParams.get('return_to'), '/device?user_code=ABCD-EFGH');
    } else {
      assert.equal(page.redirects.length, 0);
      assert.match(page.element('status').textContent, /无法确认登录会话/);
    }
  }
});

test('device page does not report approval when the shared decision endpoint rejects it', async () => {
  for (const status of [400, 403, 503]) {
    const page = browser(deviceScript, {
      respond: url => {
        if (url.startsWith('/device/verification?')) return Response.json({ request });
        if (url === '/auth/csrf') return Response.json({ csrf_token: 'csrf' });
        return Response.json({ error: 'rejected' }, { status });
      },
    });
    await page.ready();
    await page.element('approve').emit('click');
    assert.doesNotMatch(page.element('status').textContent, /已允许/);
    assert.equal(page.element('lookup').hidden, false);
    assert.equal(page.element('approve').disabled, status !== 503);
  }
});

test('Passkey login returns only to exact same-origin authorization or device paths', async () => {
  for (const [parameter, value, expected] of [
    ['return_to', '/device?user_code=ABCD-EFGH', '/device?user_code=ABCD-EFGH'],
    ['next', '/authorize?client_id=test', '/authorize?client_id=test'],
    ['return_to', 'https://evil.example/device', null],
    ['return_to', '//evil.example/device', null],
    ['return_to', '/\\evil.example/device', null],
    ['return_to', '/device/evil', null],
    ['return_to', '/auth/setup', null],
    ['return_to', 'javascript:alert(1)', null],
  ]) {
    const page = browser(loginScript, { search: '?' + new URLSearchParams({ [parameter]: value }) });
    page.element('email').value = 'test@example.com';
    await page.element('login').emit('click');
    assert.deepEqual(page.redirects, expected ? [expected] : [], value);
  }
});

test('workerd serves Device UI without a redirect loop and enforces its module gate', async () => {
  const { Miniflare } = await import('miniflare');
  const listener = createServer();
  await new Promise((resolve, reject) => {
    listener.once('error', reject);
    listener.listen(0, '127.0.0.1', resolve);
  });
  const port = listener.address().port;
  await new Promise((resolve, reject) => listener.close(error => error ? reject(error) : resolve()));
  const issuer = `http://127.0.0.1:${port}`;
  const directory = path.join(root, 'crates/server-worker/build');
  const modules = {};
  for (const relative of await readdir(directory, { recursive: true })) {
    if (!/\.(m?js|wasm)$/.test(relative)) continue;
    const contents = await readFile(path.join(directory, relative));
    modules[relative] = relative.endsWith('.wasm')
      ? { type: 'wasm', contents: new Uint8Array(contents) }
      : { type: 'esm', contents: contents.toString() };
  }
  modules['device-ui-driver.mjs'] = { type: 'esm', contents: `
    import Worker from './worker/shim.mjs';
    export default { fetch(request, env, context) {
      const config = JSON.parse(env.NAZO_CONFIG);
      if (request.headers.has('x-disable-device')) config.modules = [];
      return new Worker(context, { ...env, NAZO_CONFIG: JSON.stringify(config) }).fetch(request);
    } };
  ` };
  const config = {
    tenant: {
      tenant_id: '00000000-0000-0000-0000-000000000001',
      realm_id: '00000000-0000-0000-0000-000000000002',
      organization_id: '00000000-0000-0000-0000-000000000003',
    },
    issuer, frontend_base_url: issuer, ingress: 'local',
    modules: ['device_authorization'], passkey_only: true,
  };
  // Static assets are served before application initialization. These bindings
  // deliberately contain no provisioning credentials or real database state.
  const values = {
    NAZO_CONFIG: JSON.stringify(config), NAZO_SIGNING_KEY_ID: 'static-ui',
    NAZO_SIGNING_KEY: 'static-ui', NAZO_CLIENT_SECRET_PEPPER: 'static-ui',
    NAZO_DUMMY_PASSWORD_HASH: 'static-ui',
  };
  const worker = new Miniflare({
    host: '127.0.0.1', port, telemetry: { enabled: false }, cf: false,
    workers: [{ config: {
      name: 'device-ui', compatibilityDate: '2026-11-19',
      manifest: { mainModule: 'device-ui-driver.mjs', modulesRoot: directory, modules },
      env: {
        ...Object.fromEntries(Object.entries(values).map(([name, value]) => [name, { type: 'text', value }])),
        NAZO_DB: { type: 'd1', id: 'device-ui' },
        NAZO_VERSION: { type: 'version-metadata' },
      },
    } }],
  });
  try {
    await worker.ready;
    const page = await worker.dispatchFetch(issuer + '/device?user_code=ABCD-EFGH', { redirect: 'manual' });
    assert.equal(page.status, 200);
    assert.equal(page.headers.get('location'), null);
    assert.equal(page.headers.get('cache-control'), 'no-store');
    assert.match(page.headers.get('content-security-policy'), /form-action 'none'/);
    assert.match(await page.text(), /src="\/device.js"/);
    const script = await worker.dispatchFetch(issuer + '/device.js');
    assert.equal(script.status, 200);
    assert.match(script.headers.get('content-type'), /javascript/);
    assert.equal(await script.text(), deviceScript);
    for (const route of ['/device', '/device.js']) {
      const disabled = await worker.dispatchFetch(issuer + route, { headers: { 'x-disable-device': '1' } });
      assert.equal(disabled.status, 404, route);
    }
  } finally {
    await worker.dispose();
  }
});
