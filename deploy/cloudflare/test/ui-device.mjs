import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { Miniflare } from 'miniflare';

const root = fileURLToPath(new URL('../../../', import.meta.url));

test('NazoAuthWeb routes preserve protocol URLs, query strings, authority, and the Device gate', { timeout: 900_000 }, async () => {
  const temporary = await mkdtemp(path.join(tmpdir(), 'nazo-web-ui-'));
  let worker;
  try {
    const listener = createServer();
    await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
    const port = listener.address().port;
    await new Promise(resolve => listener.close(resolve));
    const issuer = `http://127.0.0.1:${port}`;
    const configuration = {
      tenant: { tenant_id: '00000000-0000-0000-0000-000000000001', realm_id: '00000000-0000-0000-0000-000000000002', organization_id: '00000000-0000-0000-0000-000000000003' },
      issuer, frontend_base_url: issuer + '/ui/', ingress: 'local', modules: ['device_authorization'], passkey_only: true,
    };
    const input = {
      configuration, clients: [], users: [], signing_key_id: 'web-ui-test',
      signing_key_base64: randomBytes(32).toString('base64'),
      client_secret_pepper: randomBytes(32).toString('base64'),
    };
    const sqlite = path.join(temporary, 'seed.sqlite');
    const provisioned = JSON.parse(execFileSync('cargo', [
      'run', '--quiet', '--locked', '--release', '-p', 'nazo-server-worker',
      '--features', 'provisioning', '--bin', 'nazo-worker-provision', '--', sqlite,
    ], { cwd: root, input: JSON.stringify(input), encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 }));
    const statements = JSON.parse(execFileSync('python3', ['-c', [
      'import json,sqlite3,sys',
      'with sqlite3.connect(sys.argv[1]) as c:',
      ' print(json.dumps([s for s in c.iterdump() if s not in ("BEGIN TRANSACTION;","COMMIT;")]))',
    ].join('\n'), sqlite], { encoding: 'utf8' }));
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
      NAZO_CONFIG: JSON.stringify(configuration), NAZO_SIGNING_KEY_ID: input.signing_key_id,
      NAZO_SIGNING_KEY: input.signing_key_base64, NAZO_CLIENT_SECRET_PEPPER: input.client_secret_pepper,
      NAZO_DUMMY_PASSWORD_HASH: provisioned.dummy_password_hash,
    };
    worker = new Miniflare({ host: '127.0.0.1', port, telemetry: { enabled: false }, cf: false,
      resourcePersistencePath: path.join(temporary, 'runtime'),
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
    await worker.ready;
    const database = await worker.getD1Database('NAZO_DB');
    for (let i = 0; i < statements.length; i += 50) {
      await database.batch(statements.slice(i, i + 50).map(sql => database.prepare(sql)));
    }
    // Device UI follows the same authoritative module admission as its protocol.
    // A real initialized graph makes the redirect assertions test that gate.
    const metadata = await request('/.well-known/openid-configuration');
    assert.equal(metadata.status, 200, await metadata.clone().text());
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
  } finally {
    try { await worker?.dispose(); }
    finally { await rm(temporary, { recursive: true, force: true }); }
  }
});

test('full-profile setup keeps its dedicated page and rejects claims without same-origin bearer authorization', { timeout: 900_000 }, async () => {
  const temporary = await mkdtemp(path.join(tmpdir(), 'nazo-full-setup-'));
  let worker;
  try {
    const listener = createServer();
    await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
    const port = listener.address().port;
    await new Promise(resolve => listener.close(resolve));
    const issuer = `http://127.0.0.1:${port}`;
    const configuration = {
      tenant: { tenant_id: '00000000-0000-0000-0000-000000000001', realm_id: '00000000-0000-0000-0000-000000000002', organization_id: '00000000-0000-0000-0000-000000000003' },
      issuer, frontend_base_url: issuer + '/ui/', ingress: 'local', modules: [],
      machine_only: false, passkey_only: false,
    };
    const input = {
      configuration, clients: [], users: [], signing_key_id: 'full-setup-test',
      signing_key_base64: randomBytes(32).toString('base64'),
      client_secret_pepper: randomBytes(32).toString('base64'),
    };
    const sqlite = path.join(temporary, 'seed.sqlite');
    const provisioned = JSON.parse(execFileSync('cargo', [
      'run', '--quiet', '--locked', '--release', '-p', 'nazo-server-worker',
      '--features', 'provisioning', '--bin', 'nazo-worker-provision', '--', sqlite,
    ], { cwd: root, input: JSON.stringify(input), encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 }));
    const statements = JSON.parse(execFileSync('python3', ['-c', [
      'import json,sqlite3,sys',
      'with sqlite3.connect(sys.argv[1]) as c:',
      ' print(json.dumps([s for s in c.iterdump() if s not in ("BEGIN TRANSACTION;","COMMIT;")]))',
    ].join('\n'), sqlite], { encoding: 'utf8' }));
    const directory = path.join(root, 'crates/server-worker/build');
    const modules = {};
    for (const relative of await readdir(directory, { recursive: true })) {
      if (!/\.(m?js|wasm)$/.test(relative)) continue;
      const contents = await readFile(path.join(directory, relative));
      modules[relative] = relative.endsWith('.wasm')
        ? { type: 'wasm', contents: new Uint8Array(contents) }
        : { type: 'esm', contents: contents.toString() };
    }
    modules['full-setup-driver.mjs'] = { type: 'esm', contents: `
      import Worker from './worker/shim.mjs';
      export default { fetch(request, env, context) { return new Worker(context, env).fetch(request); } };
    ` };
    const values = {
      NAZO_CONFIG: JSON.stringify(configuration), NAZO_SIGNING_KEY_ID: input.signing_key_id,
      NAZO_SIGNING_KEY: input.signing_key_base64, NAZO_CLIENT_SECRET_PEPPER: input.client_secret_pepper,
      NAZO_DUMMY_PASSWORD_HASH: provisioned.dummy_password_hash,
    };
    worker = new Miniflare({ host: '127.0.0.1', port, telemetry: { enabled: false }, cf: false,
      resourcePersistencePath: path.join(temporary, 'runtime'),
      workers: [{ config: {
        name: 'full-setup', compatibilityDate: '2026-11-19',
        manifest: { mainModule: 'full-setup-driver.mjs', modulesRoot: directory, modules },
        env: { ...Object.fromEntries(Object.entries(values).map(([name, value]) => [name, { type: 'text', value }])),
          NAZO_DB: { type: 'd1', id: 'full-setup' }, NAZO_VERSION: { type: 'version-metadata' } },
      } }],
    });
    await worker.ready;
    const database = await worker.getD1Database('NAZO_DB');
    for (let i = 0; i < statements.length; i += 50) {
      await database.batch(statements.slice(i, i + 50).map(sql => database.prepare(sql)));
    }
    const request = (route, init) => worker.dispatchFetch(issuer + route, { redirect: 'manual', ...init });
    // Successful real initialization distinguishes forbidden claims from a
    // generic startup failure caused by placeholder bindings.
    const metadata = await request('/.well-known/openid-configuration');
    assert.equal(metadata.status, 200, await metadata.clone().text());
    const page = await request('/auth/setup');
    assert.equal(page.status, 200);
    assert.match(page.headers.get('content-type'), /^text\/html/);
    assert.match(page.headers.get('content-security-policy'), /form-action 'none'/);
    assert.equal(page.headers.get('cache-control'), 'no-store');
    assert.match(await page.text(), /\/auth\/setup\.js/);
    const script = await request('/auth/setup.js');
    assert.equal(script.status, 200);
    assert.match(await script.text(), /\/auth\/setup\/claim/);
    const authorization = `Bearer ${randomBytes(32).toString('base64url')}`;
    for (const headers of [{ authorization }, { origin: 'https://other.example', authorization }, { origin: issuer }]) {
      const rejected = await request('/auth/setup/claim', { method: 'POST', headers });
      assert.equal(rejected.status, 403);
      assert.equal(rejected.headers.get('set-cookie'), null);
      assert.equal(rejected.headers.get('cache-control'), 'no-store');
    }
  } finally {
    await worker?.dispose();
    await rm(temporary, { recursive: true, force: true });
  }
});
