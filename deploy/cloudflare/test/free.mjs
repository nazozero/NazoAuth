import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Miniflare } from 'miniflare';

const root = fileURLToPath(new URL('../../../', import.meta.url));

async function bindPort() {
  const socket = createServer();
  await new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.listen(0, '127.0.0.1', resolve);
  });
  const port = socket.address().port;
  await new Promise((resolve, reject) => socket.close(error => error ? reject(error) : resolve()));
  return port;
}

async function modules(directory) {
  const included = {};
  for (const relative of await readdir(directory, { recursive: true })) {
    if (!/\.(m?js|wasm)$/.test(relative)) continue;
    included[relative] = {
      type: relative.endsWith('.wasm') ? 'wasm' : 'esm',
      contents: relative.endsWith('.wasm')
        ? new Uint8Array(await readFile(path.join(directory, relative)))
        : await readFile(path.join(directory, relative), 'utf8'),
    };
  }
  included['test-driver.mjs'] = {
    type: 'esm',
    contents: await readFile(new URL('./fixtures/worker-driver.mjs', import.meta.url), 'utf8'),
  };
  return { mainModule: 'test-driver.mjs', modulesRoot: directory, modules: included };
}

test('Workers Free machine-only build has honest metadata and rejects interactive login', async () => {
  const tmp = await mkdtemp(path.join(tmpdir(), 'nazo-free-worker-'));
  let worker;
  try {
    const port = await bindPort();
    const issuer = `http://127.0.0.1:${port}`;
    const configuration = {
      tenant: {
        tenant_id: '00000000-0000-0000-0000-000000000001',
        realm_id: '00000000-0000-0000-0000-000000000002',
        organization_id: '00000000-0000-0000-0000-000000000003',
      },
      issuer, frontend_base_url: 'https://client.example', ingress: 'local',
      modules: [], machine_only: true,
    };
    const input = {
      configuration,
      client_secret_pepper: randomBytes(32).toString('base64'),
      signing_key_id: 'free-test',
      signing_key_base64: randomBytes(32).toString('base64'),
      clients: [{
        client_name: 'Free service client', client_type: 'confidential', redirect_uris: [],
        scopes: ['service'], allowed_audiences: ['resource://default'],
        grant_types: ['client_credentials'], token_endpoint_auth_method: 'client_secret_basic',
        security_policy: { version: 1 },
      }],
      users: [],
    };
    const sqlite = path.join(tmp, 'seed.sqlite');
    const provisioned = JSON.parse(execFileSync('cargo', [
      'run', '--quiet', '--locked', '--release', '-p', 'nazo-server-worker',
      '--features', 'provisioning', '--bin', 'nazo-worker-provision', '--', sqlite,
    ], { cwd: root, input: JSON.stringify(input), encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 }));
    const dump = JSON.parse(execFileSync('python3', ['-c', [
      'import json,sqlite3,sys',
      'with sqlite3.connect(sys.argv[1]) as c:',
      ' print(json.dumps([s for s in c.iterdump() if s not in ("BEGIN TRANSACTION;","COMMIT;")]))',
    ].join('\n'), sqlite], { encoding: 'utf8' }));

    const environment = {
      NAZO_CONFIG: JSON.stringify(configuration),
      NAZO_SIGNING_KEY_ID: input.signing_key_id,
      NAZO_SIGNING_KEY: input.signing_key_base64,
      NAZO_CLIENT_SECRET_PEPPER: input.client_secret_pepper,
      NAZO_DUMMY_PASSWORD_HASH: provisioned.dummy_password_hash,
    };
    worker = new Miniflare({
      host: '127.0.0.1', port, telemetry: { enabled: false }, cf: false,
      resourcePersistencePath: path.join(tmp, 'runtime'),
      workers: [{ config: {
        name: 'nazo-free-test', compatibilityDate: '2026-11-19',
        manifest: await modules(path.join(root, 'crates/server-worker/build')),
        env: {
          ...Object.fromEntries(Object.entries(environment).map(([name, value]) => [name, { type: 'text', value }])),
          NAZO_DB: { type: 'd1', id: 'free-test-db' },
          NAZO_VERSION: { type: 'version-metadata' },
        },
      } }],
    });
    await worker.ready;
    const db = await worker.getD1Database('NAZO_DB');
    for (let i = 0; i < dump.length; i += 50) {
      await db.batch(dump.slice(i, i + 50).map(sql => db.prepare(sql)));
    }
    const request = (url, init) => worker.dispatchFetch(issuer + url, { redirect: 'manual', ...init });
    const metadataResponse = await request('/.well-known/oauth-authorization-server');
    assert.equal(metadataResponse.status, 200, await metadataResponse.clone().text());
    const metadata = await metadataResponse.json();
    assert.equal(metadata.issuer, issuer);
    assert.deepEqual(metadata.grant_types_supported, ['client_credentials']);
    assert.equal(metadata.authorization_endpoint, undefined);
    assert.equal(metadataResponse.headers.get('content-type'), 'application/json; charset=utf-8');

    assert.equal((await request('/jwks.json')).status, 200);
    assert.equal((await request('/.well-known/openid-configuration')).status, 404);
    assert.equal((await request('/authorize')).status, 404);
    assert.equal((await request('/auth/login', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
    })).status, 404);

    const client = provisioned.clients[0];
    assert.ok(client.client_secret, 'confidential service client has an issued secret');
    const basic = Buffer.from(`${client.client_id}:${client.client_secret}`).toString('base64');
    const token = await request('/token', {
      method: 'POST',
      headers: { authorization: `Basic ${basic}`, 'content-type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials&scope=service',
    });
    assert.equal(token.status, 200, await token.clone().text());
    const issued = await token.json();
    assert.ok(issued.access_token);
    const bad = await request('/token', {
      method: 'POST',
      headers: { authorization: 'Basic ' + Buffer.from(client.client_id + ':incorrect').toString('base64'),
        'content-type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials&scope=service',
    });
    assert.notEqual(bad.status, 200);
    console.log(JSON.stringify({ profile: 'Workers Free machine-only', token: 'issued', browser_login: 'blocked', runtime: 'local workerd' }));
  } finally {
    await worker?.dispose();
    await rm(tmp, { recursive: true, force: true });
  }
}, { timeout: 900_000 });


test('Workers Free one-use Passkey setup creates only a five-minute enrollment session', async () => {
  const tmp = await mkdtemp(path.join(tmpdir(), 'nazo-free-passkey-'));
  let worker;
  try {
    const port = await bindPort();
    const issuer = 'http://127.0.0.1:' + port;
    const configuration = {
      tenant: {
        tenant_id: '00000000-0000-0000-0000-000000000001',
        realm_id: '00000000-0000-0000-0000-000000000002',
        organization_id: '00000000-0000-0000-0000-000000000003',
      },
      issuer, frontend_base_url: 'https://client.example', ingress: 'local',
      modules: [], machine_only: false, passkey_only: true,
    };
    const token = randomBytes(32).toString('base64url');
    const input = {
      configuration,
      client_secret_pepper: randomBytes(32).toString('base64'),
      signing_key_id: 'passkey-test',
      signing_key_base64: randomBytes(32).toString('base64'),
      clients: [{
        client_name: 'Passkey browser client', client_type: 'public',
        redirect_uris: ['https://client.example/callback'],
        scopes: ['openid', 'profile', 'offline_access'],
        allowed_audiences: ['resource://default'],
        grant_types: ['authorization_code', 'refresh_token'],
        token_endpoint_auth_method: 'none', security_policy: { version: 1 },
      }],
      users: [{
        email: 'setup@example.com', username: 'setup',
        password: randomBytes(32).toString('base64url'),
      }],
    };
    const sqlite = path.join(tmp, 'seed.sqlite');
    const provisioned = JSON.parse(execFileSync('cargo', [
      'run', '--quiet', '--locked', '--release', '-p', 'nazo-server-worker',
      '--features', 'provisioning', '--bin', 'nazo-worker-provision', '--', sqlite,
    ], { cwd: root, input: JSON.stringify(input), encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 }));
    const dump = JSON.parse(execFileSync('python3', ['-c', [
      'import json,sqlite3,sys',
      'with sqlite3.connect(sys.argv[1]) as c:',
      ' print(json.dumps([s for s in c.iterdump() if s not in ("BEGIN TRANSACTION;","COMMIT;")]))',
    ].join('\n'), sqlite], { encoding: 'utf8' }));

    const values = {
      NAZO_CONFIG: JSON.stringify(configuration),
      NAZO_SIGNING_KEY_ID: input.signing_key_id,
      NAZO_SIGNING_KEY: input.signing_key_base64,
      NAZO_CLIENT_SECRET_PEPPER: input.client_secret_pepper,
      NAZO_DUMMY_PASSWORD_HASH: provisioned.dummy_password_hash,
      NAZO_BOOTSTRAP_TOKEN: token,
      NAZO_BOOTSTRAP_USER_ID: provisioned.user_ids[0],
      NAZO_BOOTSTRAP_EXPIRES_AT: String(Math.floor(Date.now() / 1000) + 3600),
    };
    worker = new Miniflare({
      host: '127.0.0.1', port, telemetry: { enabled: false }, cf: false,
      resourcePersistencePath: path.join(tmp, 'runtime'),
      workers: [{ config: {
        name: 'nazo-passkey-free-test', compatibilityDate: '2026-11-19',
        manifest: await modules(path.join(root, 'crates/server-worker/build')),
        env: {
          ...Object.fromEntries(Object.entries(values).map(([name, value]) => [name, { type: 'text', value }])),
          NAZO_DB: { type: 'd1', id: 'free-passkey-test-db' },
          NAZO_VERSION: { type: 'version-metadata' },
        },
      } }],
    });
    await worker.ready;
    const db = await worker.getD1Database('NAZO_DB');
    for (let i = 0; i < dump.length; i += 50) {
      await db.batch(dump.slice(i, i + 50).map(sql => db.prepare(sql)));
    }
    const request = (url, init) => worker.dispatchFetch(issuer + url, { redirect: 'manual', ...init });
    assert.equal((await request('/auth/login', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
    })).status, 404);
    assert.equal((await request('/auth/setup')).status, 200);
    assert.equal((await request('/auth/setup.js')).status, 200);
    assert.equal((await request('/auth/passkey')).status, 200);
    assert.equal((await request('/auth/passkey.js')).status, 200);

    const claim = (ticket, origin = issuer) => request('/auth/setup/claim', {
      method: 'POST',
      headers: { origin, authorization: 'Bearer ' + ticket },
    });
    assert.equal((await claim(randomBytes(32).toString('base64url'))).status, 403);
    assert.equal((await claim(token, 'https://evil.example')).status, 403);
    const first = await claim(token);
    assert.equal(first.status, 200, await first.clone().text());
    const credentials = first.headers.getSetCookie();
    assert.equal(credentials.length, 2);
    assert.ok(credentials.some(cookie => cookie.includes('HttpOnly; SameSite=Strict')));
    const cookie = credentials.map(item => item.split(';')[0]).join('; ');
    const csrf = (await first.json()).csrf_token;
    assert.equal((await claim(token)).status, 403, 'setup token must be single-use');
    assert.equal(
      (await request('/auth/me', { headers: { cookie } })).status, 401,
      'an enrollment session cannot be used as an ordinary account login',
    );
    assert.equal(
      (await request('/auth/me/passkeys', { headers: { cookie } })).status, 401,
      'enrollment may not list or manage existing credentials',
    );
    const begin = await request('/auth/me/passkeys/registration/begin', {
      method: 'POST',
      headers: { cookie, 'x-csrf-token': csrf, 'content-type': 'application/json' },
      body: JSON.stringify({ label: 'First device' }),
    });
    assert.equal(begin.status, 200, await begin.clone().text());
    const payload = await begin.json();
    assert.ok(payload.ceremony_id);
    assert.ok(payload.publicKey.challenge);
    const login = await request('/auth/passkey/begin', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: '{"email":"setup@example.com"}',
    });
    assert.equal(login.status, 200, await login.clone().text());
    console.log(JSON.stringify({ profile: 'Workers Free passkey-only', setup: 'one-use', password_login: 'blocked', runtime: 'local workerd' }));
  } finally {
    await worker?.dispose();
    await rm(tmp, { recursive: true, force: true });
  }
}, { timeout: 900_000 });
