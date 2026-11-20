import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { createServer } from 'node:net';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { Miniflare } from 'miniflare';

const root = fileURLToPath(new URL('../../../', import.meta.url));

test('NazoAuthWeb routes preserve protocol URLs, query strings, authority, and the Device gate', async () => {
  const listener = createServer();
  await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
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
  modules['web-ui-driver.mjs'] = { type: 'esm', contents: `
    import Worker from './worker/shim.mjs';
    export default { fetch(request, env, context) {
      const config = JSON.parse(env.NAZO_CONFIG);
      if (request.headers.has('x-disable-device')) config.modules = [];
      if (request.headers.has('x-machine-only')) { config.machine_only = true; config.passkey_only = false; config.modules = []; }
      return new Worker(context, { ...env, NAZO_CONFIG: JSON.stringify(config) }).fetch(request);
    }};
  ` };
  const values = {
    NAZO_CONFIG: JSON.stringify({
      tenant: { tenant_id: '00000000-0000-0000-0000-000000000001', realm_id: '00000000-0000-0000-0000-000000000002', organization_id: '00000000-0000-0000-0000-000000000003' },
      issuer, frontend_base_url: issuer + '/ui/', ingress: 'local', modules: ['device_authorization'], passkey_only: true,
    }),
    NAZO_SIGNING_KEY_ID: 'static-ui', NAZO_SIGNING_KEY: 'static-ui',
    NAZO_CLIENT_SECRET_PEPPER: 'static-ui', NAZO_DUMMY_PASSWORD_HASH: 'static-ui',
  };
  const worker = new Miniflare({ host: '127.0.0.1', port, telemetry: { enabled: false }, cf: false,
    workers: [{ config: {
      name: 'web-ui', compatibilityDate: '2026-11-19',
      manifest: { mainModule: 'web-ui-driver.mjs', modulesRoot: directory, modules },
      env: { ...Object.fromEntries(Object.entries(values).map(([name, value]) => [name, { type: 'text', value }])),
        ASSETS: { type: 'fetcher', handler: async request => {
          const url = new URL(request.url);
          if (url.pathname !== '/ui/index.html') return new Response('missing', { status: 404 });
          return new Response('<!doctype html><div id="root"></div><script src="/ui/assets/app.js"></script>', {
            headers: { 'content-type': 'text/html', 'content-security-policy': "default-src 'self'", 'x-asset-path': url.pathname } });
        } },
        NAZO_DB: { type: 'd1', id: 'web-ui' }, NAZO_VERSION: { type: 'version-metadata' } },
    } }],
  });
  const request = (route, init) => worker.dispatchFetch(issuer + route, { redirect: 'manual', ...init });
  try {
    await worker.ready;
    for (const [route, target] of [
      ['/', '/ui/'], ['/ui', '/ui/'], ['/auth?next=%2Fauthorize%3Fclient_id%3Dtest', '/ui/auth?next=%2Fauthorize%3Fclient_id%3Dtest'],
      ['/auth/passkey', '/ui/auth'], ['/consent?request_id=test', '/ui/consent?request_id=test'],
      ['/device?user_code=ABCD-EFGH', '/ui/device?user_code=ABCD-EFGH'],
    ]) {
      const response = await request(route);
      assert.equal(response.status, 307, route);
      assert.equal(response.headers.get('location'), target);
      assert.equal(response.headers.get('cache-control'), 'no-store');
    }
    for (const route of ['/ui/', '/ui/auth', '/ui/profile', '/ui/device?user_code=test', '/ui/admin']) {
      const response = await request(route);
      assert.equal(response.status, 200, route + ' ' + await response.clone().text());
      assert.equal(response.headers.get('x-asset-path'), '/ui/index.html');
      assert.equal(response.headers.get('cache-control'), 'no-cache');
      assert.equal(response.headers.get('content-security-policy'), "default-src 'self'");
      assert.match(await response.text(), /id="root"/);
    }
    assert.equal(await (await request('/ui/auth', { method: 'HEAD' })).text(), '');
    for (const route of ['/ui/missing.js', '/ui/assets/missing.js']) assert.equal((await request(route)).status, 404);
    for (const route of ['/device', '/ui/device']) assert.equal((await request(route, { headers: { 'x-disable-device': '1' } })).status, 404);
    for (const route of ['/', '/ui/auth', '/device']) assert.equal((await request(route, { headers: { 'x-machine-only': '1' } })).status, 404);
    assert.equal((await worker.dispatchFetch('https://other.example/ui/auth')).status, 421);
    for (const route of ['/token', '/auth/me', '/auth/login', '/unknown-protocol-path']) {
      const response = await request(route);
      assert.notEqual(response.status, 200, route);
      assert.doesNotMatch(await response.text(), /id="root"/);
    }
  } finally { await worker.dispose(); }
});
