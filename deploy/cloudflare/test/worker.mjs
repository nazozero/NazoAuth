import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, randomUUID, sign, verify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { createServer } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Miniflare } from 'miniflare';

const root = fileURLToPath(new URL('../../../', import.meta.url));
let issuer;
const redirect = 'https://client.example/callback';
const password = 'Worker-integration-password-206';
const email = 'worker-test@example.com';
const configuration = {
  tenant: {
    tenant_id: '00000000-0000-0000-0000-000000000001',
    realm_id: '00000000-0000-0000-0000-000000000002',
    organization_id: '00000000-0000-0000-0000-000000000003',
  },
  issuer: 'http://localhost', frontend_base_url: 'https://client.example', ingress: 'local',
  cors_allowed_origins: ['https://client.example'],
  modules: ['session_management', 'request_objects', 'jarm'],
};
let temporary, mf, database, provisioned, options, signingKeys;
const form = (values) => new URLSearchParams(values).toString();
const sha256 = (value) => createHash('sha256').update(value).digest('base64url');

const base64url = (data) => Buffer.from(data).toString('base64url');
const uuidBytes = (value) => Buffer.from(value.replaceAll('-', ''), 'hex');

// Only the integration test constructs authenticator CBOR; protocol parsing stays in nazo-passkey.
function cborHeader(type, length) {
  if (length < 24) return Buffer.from([(type << 5) | length]);
  if (length < 256) return Buffer.from([(type << 5) | 24, length]);
  if (length < 65536) {
    const bytes = Buffer.alloc(3);
    bytes[0] = (type << 5) | 25;
    bytes.writeUInt16BE(length, 1);
    return bytes;
  }
  const bytes = Buffer.alloc(5);
  bytes[0] = (type << 5) | 26;
  bytes.writeUInt32BE(length, 1);
  return bytes;
}
function cbor(value) {
  if (Number.isSafeInteger(value)) return value >= 0 ? cborHeader(0, value) : cborHeader(1, -value - 1);
  if (Buffer.isBuffer(value)) return Buffer.concat([cborHeader(2, value.length), value]);
  if (typeof value === 'string') {
    const bytes = Buffer.from(value);
    return Buffer.concat([cborHeader(3, bytes.length), bytes]);
  }
  if (value instanceof Map) {
    const entries = [...value].map(([key, item]) => [cbor(key), cbor(item)]);
    entries.sort(([a], [b]) => a.length - b.length || Buffer.compare(a, b));
    return Buffer.concat([cborHeader(5, entries.length), ...entries.flat()]);
  }
  if (Array.isArray(value)) return Buffer.concat([cborHeader(4, value.length), ...value.map(cbor)]);
  if (value && typeof value === 'object') return cbor(new Map(Object.entries(value)));
  throw new Error('Unsupported test CBOR value');
}

const request = (url, init = {}) => mf.dispatchFetch(`${issuer}${url}`, { redirect: 'manual', ...init });
const postForm = (url, values, headers = {}) => request(url, {
  method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers }, body: form(values),
});

async function moduleManifest(directory) {
  const modules = {};
  for (const relative of await readdir(directory, { recursive: true })) {
    if (!/\.(m?js|wasm)$/.test(relative)) continue;
    modules[relative] = {
      type: relative.endsWith('.wasm') ? 'wasm' : 'esm',
      contents: relative.endsWith('.wasm')
        ? new Uint8Array(await readFile(path.join(directory, relative)))
        : await readFile(path.join(directory, relative), 'utf8'),
    };
  }
  modules['test-driver.mjs'] = { type: 'esm', contents: await readFile(new URL('./fixtures/worker-driver.mjs', import.meta.url), 'utf8') };
  return { mainModule: 'test-driver.mjs', modulesRoot: directory, modules };
}

before(async () => {
  temporary = await mkdtemp(path.join(tmpdir(), 'nazo-worker-'));
  // Miniflare's HTTP proxy preserves the URL but rewrites Host to its listener.
  // Use that same loopback authority so the real host admission stays enabled.
  const listener = createServer();
  await new Promise((resolve, reject) => { listener.once('error', reject); listener.listen(0, '127.0.0.1', resolve); });
  const port = listener.address().port;
  await new Promise((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
  issuer = `http://127.0.0.1:${port}`;
  configuration.issuer = issuer;
  const publicClient = {
    client_name: 'Worker browser integration', client_type: 'public', redirect_uris: [redirect],
    scopes: ['openid', 'profile', 'email', 'offline_access'], allowed_audiences: ['resource://default'],
    grant_types: ['authorization_code', 'refresh_token'], token_endpoint_auth_method: 'none',
    security_policy: { version: 1 },
    authorization_signed_response_alg: 'RS256',
  };
  const input = {
    configuration, client_secret_pepper: randomBytes(32).toString('base64'),
    signing_key_id: 'integration', signing_key_base64: randomBytes(32).toString('base64'),
    clients: [publicClient, { ...publicClient, client_name: 'Worker DPoP integration', require_dpop_bound_tokens: true }, {
      client_name: 'Worker service integration', client_type: 'confidential', redirect_uris: [],
      scopes: ['service'], allowed_audiences: ['resource://default'], grant_types: ['client_credentials'],
      token_endpoint_auth_method: 'client_secret_basic',
      security_policy: { version: 1 },
    }],
    users: [{ email, username: 'worker-integration', password }],
  };
  const sqlite = path.join(temporary, 'seed.sqlite');
  // Provision through production registration/key/password code. This process
  // owns native file access; no native driver enters the Worker dependency graph.
  provisioned = JSON.parse(execFileSync('cargo', [
    'run', '--quiet', '--locked', '--release', '-p', 'nazo-server-worker', '--features', 'provisioning',
    '--bin', 'nazo-worker-provision', '--', sqlite,
  ], { cwd: root, input: JSON.stringify(input), encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 }));
  const statements = JSON.parse(execFileSync('python3', ['-c', [
    'import json,sqlite3,sys',
    'c=sqlite3.connect(sys.argv[1])',
    'print(json.dumps([s for s in c.iterdump() if s not in ("BEGIN TRANSACTION;","COMMIT;")]))',
  ].join('\n'), sqlite], { encoding: 'utf8' }));
  const values = {
    NAZO_CONFIG: JSON.stringify(configuration), NAZO_SIGNING_KEY_ID: input.signing_key_id,
    NAZO_SIGNING_KEY: input.signing_key_base64, NAZO_CLIENT_SECRET_PEPPER: input.client_secret_pepper,
    NAZO_DUMMY_PASSWORD_HASH: provisioned.dummy_password_hash,
  };
  options = {
    host: '127.0.0.1', port,
    telemetry: { enabled: false }, cf: false,
    resourcePersistencePath: path.join(temporary, 'runtime'),
    workers: [{ config: {
      name: 'nazoauth-test', compatibilityDate: '2026-11-19',
      manifest: await moduleManifest(path.join(root, 'crates/server-worker/build')),
      env: { ...Object.fromEntries(Object.entries(values).map(([name, value]) => [name, { type: 'text', value }])),
        NAZO_DB: { type: 'd1', id: 'nazoauth-test' },
        NAZO_EMPTY_DB: { type: 'd1', id: 'nazoauth-empty' },
        NAZO_VERSION: { type: 'version-metadata' } },
    } }],
  };
  const boot = performance.now();
  mf = new Miniflare(options);
  await mf.ready;
  console.log(JSON.stringify({ runtime_boot_ms: +(performance.now() - boot).toFixed(2) }));
  database = await mf.getD1Database('NAZO_DB');
  for (let i = 0; i < statements.length; i += 50) {
    await database.batch(statements.slice(i, i + 50).map((sql) => database.prepare(sql)));
  }
}, { timeout: 900_000 });

after(async () => {
  await mf?.dispose();
  if (temporary) await rm(temporary, { recursive: true, force: true });
});

async function expectJson(response, status = 200) {
  assert.equal(response.status, status, `HTTP ${response.status}: ${await response.clone().text()}`);
  return response.json();
}

async function login() {
  const response = await request('/auth/login', {
    method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://client.example' },
    body: JSON.stringify({ email, password }),
  });
  const body = await expectJson(response);
  const cookies = response.headers.getSetCookie();
  assert.equal(cookies.length, 2, 'session and CSRF cookies must remain separate');
  return { cookie: cookies.map((value) => value.split(';')[0]).join('; '), csrf: body.csrf_token };
}

async function authorize(client, session, { pushed = false, ...extra } = {}) {
  const verifier = randomBytes(32).toString('base64url');
  let parameters = {
    response_type: 'code', client_id: client.client_id, redirect_uri: redirect,
    scope: 'openid profile email offline_access', code_challenge: sha256(verifier),
    code_challenge_method: 'S256', state: 'integration-state', nonce: randomUUID(), ...extra,
  };
  if (pushed) {
    const par = await expectJson(await postForm('/par', parameters), 201);
    assert.ok(par.request_uri && par.expires_in > 0);
    parameters = { client_id: client.client_id, request_uri: par.request_uri };
  }
  const response = await request(`/authorize?${form(parameters)}`, { headers: { cookie: session.cookie } });
  assert.equal(response.status, 302, await response.clone().text());
  let location = new URL(response.headers.get('location'));
  if (location.pathname.endsWith('/consent')) {
    const consent = await expectJson(await request(`/authorize/consent?${form({ request_id: location.searchParams.get('request_id') })}`, {
      headers: { cookie: session.cookie },
    }));
    assert.equal(consent.client_id, client.client_id);
    assert.equal(consent.csrf_token, session.csrf);
    const decision = await postForm('/authorize/decision', {
      request_id: location.searchParams.get('request_id'), decision: 'approve', csrf_token: session.csrf,
    }, { cookie: session.cookie });
    assert.equal(decision.status, 303, await decision.clone().text());
    location = new URL(decision.headers.get('location'));
  }
  assert.equal(location.origin + location.pathname, redirect);
  if (extra.response_mode === 'jwt') {
    const jwt = location.searchParams.get('response');
    assert.ok(jwt);
    const [encodedHeader, encodedClaims, signature] = jwt.split('.');
    const header = JSON.parse(Buffer.from(encodedHeader, 'base64url'));
    assert.equal(header.alg, 'RS256');
    const jwk = signingKeys.find((key) => key.kid === header.kid);
    assert.ok(jwk);
    assert.ok(verify('RSA-SHA256', Buffer.from(`${encodedHeader}.${encodedClaims}`),
      createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(signature, 'base64url')));
    const claims = JSON.parse(Buffer.from(encodedClaims, 'base64url'));
    assert.equal(claims.iss, issuer);
    assert.equal(claims.aud, client.client_id);
    assert.equal(claims.state, 'integration-state');
    assert.ok(claims.exp > Date.now() / 1000 && claims.code);
    return { verifier, code: claims.code };
  }
  assert.equal(location.searchParams.get('state'), 'integration-state');
  assert.ok(location.searchParams.get('code'), location.toString());
  return { verifier, code: location.searchParams.get('code') };
}

function tokenForm(client, authorization) {
  return { grant_type: 'authorization_code', client_id: client.client_id,
    code: authorization.code, code_verifier: authorization.verifier, redirect_uri: redirect };
}

test('cold start, discovery and JWKS use the enabled profile', async () => {
  const cold = performance.now();
  const discoveries = await Promise.all(Array.from({ length: 16 }, async () =>
    expectJson(await request('/.well-known/openid-configuration'))));
  const metadata = discoveries[0];
  assert.ok(discoveries.every((document) => document.issuer === issuer));
  console.log(JSON.stringify({ cold_requests: 16, cold_batch_ms: +(performance.now() - cold).toFixed(2) }));
  assert.equal(metadata.issuer, issuer);
  assert.ok(metadata.grant_types_supported.includes('authorization_code'));
  assert.ok(metadata.grant_types_supported.includes('refresh_token'));
  assert.ok(!metadata.grant_types_supported.includes('urn:ietf:params:oauth:grant-type:device_code'));
  assert.ok(!metadata.token_endpoint_auth_methods_supported.includes('tls_client_auth'));
  assert.equal(metadata.registration_endpoint, undefined);
  const jwks = await expectJson(await mf.dispatchFetch(metadata.jwks_uri));
  signingKeys = jwks.keys;
  assert.ok(jwks.keys.length > 0);
  assert.ok(jwks.keys.every((key) => !('d' in key)));
  assert.equal((await request('/does-not-exist')).status, 404);
  assert.equal((await mf.dispatchFetch('http://unknown.example/token')).status, 421);
});

test('enabled PAR and signed authorization responses use the shared flow', async () => {
  const client = provisioned.clients[0];
  const session = await login();
  const authorization = await authorize(client, session, { pushed: true, response_mode: 'jwt' });
  const token = await expectJson(await postForm('/token', tokenForm(client, authorization)));
  assert.ok(token.access_token && token.id_token);
});

test('authorization code, UserInfo, refresh, revocation and logout', async () => {
  const session = await login();
  const client = provisioned.clients[0];
  const authorization = await authorize(client, session);
  const token = await expectJson(await postForm('/token', tokenForm(client, authorization)));
  assert.ok(token.access_token && token.refresh_token && token.id_token);
  const user = await expectJson(await request('/userinfo', { headers: { authorization: `Bearer ${token.access_token}` } }));
  assert.equal(user.email, email);
  const rotated = await expectJson(await postForm('/token', {
    grant_type: 'refresh_token', client_id: client.client_id, refresh_token: token.refresh_token,
  }));
  assert.notEqual(rotated.refresh_token, token.refresh_token);
  const revoke = await postForm('/revoke', { client_id: client.client_id, token: rotated.access_token, token_type_hint: 'access_token' });
  assert.equal(revoke.status, 200);
  assert.equal((await request('/userinfo', { headers: { authorization: `Bearer ${rotated.access_token}` } })).status, 401);
  await expectJson(await postForm('/token', tokenForm(client, authorization)), 400);
  const logout = await request('/auth/logout', { method: 'POST', headers: { cookie: session.cookie, 'x-csrf-token': session.csrf } });
  assert.equal(logout.status, 200, await logout.clone().text());
  assert.ok(logout.headers.getSetCookie().some((value) => value.includes('Max-Age=0')));
  assert.equal((await request('/auth/me', { headers: { cookie: session.cookie } })).status, 401);
});

test('concurrent code redemption and refresh each have one winner', async () => {
  const client = provisioned.clients[0];
  const session = await login();
  const code = await authorize(client, session);
  const attempts = await Promise.all(Array.from({ length: 16 }, () => postForm('/token', tokenForm(client, code))));
  assert.equal(attempts.filter((response) => response.status === 200).length, 1);
  assert.ok(attempts.every((response) => [200, 400].includes(response.status)));
  // Replayed authorization codes revoke their issued family. Exercise the
  // refresh race with a separately redeemed code, preserving that core policy.
  const fresh = await authorize(client, session);
  const winner = await expectJson(await postForm('/token', tokenForm(client, fresh)));
  const refreshes = await Promise.all(Array.from({ length: 16 }, () => postForm('/token', {
    grant_type: 'refresh_token', client_id: client.client_id, refresh_token: winner.refresh_token,
  })));
  assert.equal(refreshes.filter((response) => response.status === 200).length, 1);
  assert.ok(refreshes.every((response) => [200, 400].includes(response.status)));
});

test('DPoP nonce, holder binding and replay use authoritative D1 state', async () => {
  const client = provisioned.clients[1];
  const session = await login();
  const authorization = await authorize(client, session);
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const proof = (method, uri, extra = {}) => {
    const parts = [ { typ: 'dpop+jwt', alg: 'ES256', jwk },
      { htm: method, htu: uri, iat: Math.floor(Date.now() / 1000), jti: randomUUID(), ...extra } ]
      .map((value) => Buffer.from(JSON.stringify(value)).toString('base64url'));
    const input = parts.join('.');
    return `${input}.${sign('sha256', Buffer.from(input), { key: pair.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
  };
  const challenge = await postForm('/token', tokenForm(client, authorization), { dpop: proof('POST', `${issuer}/token`) });
  assert.equal(challenge.status, 400);
  assert.equal((await challenge.json()).error, 'use_dpop_nonce');
  const nonce = challenge.headers.get('dpop-nonce');
  assert.ok(nonce);
  const signed = proof('POST', `${issuer}/token`, { nonce });
  const response = await postForm('/token', tokenForm(client, authorization), { dpop: signed });
  const token = await expectJson(response);
  assert.equal(token.token_type, 'DPoP');
  const replay = await postForm('/token', tokenForm(client, authorization), { dpop: signed });
  assert.equal(replay.status, 400);
  assert.equal((await request('/userinfo', { headers: { authorization: `Bearer ${token.access_token}` } })).status, 401);
  const resourceChallenge = await request('/userinfo', { headers: {
    authorization: `DPoP ${token.access_token}`,
    dpop: proof('GET', `${issuer}/userinfo`, { ath: sha256(token.access_token) }),
  } });
  assert.equal(resourceChallenge.status, 401);
  assert.equal((await resourceChallenge.json()).error, 'use_dpop_nonce');
  const resourceNonce = resourceChallenge.headers.get('dpop-nonce');
  assert.ok(resourceNonce);
  const resourceProof = proof('GET', `${issuer}/userinfo`, { ath: sha256(token.access_token), nonce: resourceNonce });
  const user = await expectJson(await request('/userinfo', { headers: { authorization: `DPoP ${token.access_token}`, dpop: resourceProof } }));
  assert.equal(user.email, email);
  assert.equal((await request('/userinfo', { headers: { authorization: `DPoP ${token.access_token}`, dpop: resourceProof } })).status, 401);
});

test('repeated requests share the prepared graph and accept concurrent service tokens', async () => {
  const client = provisioned.clients[2];
  const headers = { authorization: `Basic ${Buffer.from(`${client.client_id}:${client.client_secret}`).toString('base64')}` };
  const started = performance.now();
  const times = [];
  const concurrency = 64;
  for (let batch = 0; batch < 4; batch++) {
    await Promise.all(Array.from({ length: concurrency }, async () => {
      const start = performance.now();
      const response = await postForm('/token', { grant_type: 'client_credentials', scope: 'service' }, headers);
      assert.equal(response.status, 200, await response.clone().text());
      times.push(performance.now() - start);
    }));
  }
  const duration = performance.now() - started;
  times.sort((a, b) => a - b);
  console.log(JSON.stringify({ runtime: 'local workerd', concurrency, requests: times.length,
    requests_per_second: +(times.length * 1000 / duration).toFixed(2),
    p95_ms: +times[Math.ceil(times.length * 0.95) - 1].toFixed(2),
    p99_ms: +times[Math.ceil(times.length * 0.99) - 1].toFixed(2) }));
});

test('changed bindings never reuse a previous application graph', async () => {
  for (const binding of ['key', 'database']) {
    assert.equal((await request('/.well-known/openid-configuration', { headers: { 'x-nazo-test-binding': binding } })).status, 503);
  }
  assert.equal((await request('/.well-known/openid-configuration', { headers: { 'x-nazo-test-binding': 'configuration' } })).status, 421);
  const restored = await expectJson(await request('/.well-known/openid-configuration'));
  assert.equal(restored.issuer, issuer);
  // The JS resource object can survive a platform version change. Force the
  // real initialization read to fail and prove the version ID invalidates it.
  await database.exec('ALTER TABLE nazo_modules RENAME TO nazo_modules_held');
  try {
    assert.equal((await request('/.well-known/openid-configuration')).status, 200);
    assert.equal((await request('/.well-known/openid-configuration', { headers: { 'x-nazo-test-binding': 'version' } })).status, 503);
  } finally {
    await database.exec('ALTER TABLE nazo_modules_held RENAME TO nazo_modules');
  }
});

test('a fresh isolate reuses durable keys and sessions', async () => {
  const session = await login();
  const metadata = await expectJson(await request('/.well-known/openid-configuration'));
  const jwks = await (await mf.dispatchFetch(metadata.jwks_uri)).text();
  await mf.dispose();
  mf = new Miniflare(options);
  database = await mf.getD1Database('NAZO_DB');
  assert.equal(await (await mf.dispatchFetch(metadata.jwks_uri)).text(), jwks);
  const retained = await request('/auth/me', { headers: { cookie: session.cookie } });
  assert.equal(retained.status, 200, await retained.clone().text());
});


test('WebAuthn Passkey enrollment and login use real D1 credentials and single-use ceremonies', async () => {
  const initial = await login();
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const credentialId = randomBytes(32);
  const encodedId = base64url(credentialId);
  const coseKey = cbor(new Map([
    [1, 2], [3, -7], [-1, 1],
    [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')],
  ]));
  const host = new URL(issuer).hostname;
  const rpHash = createHash('sha256').update(host).digest();
  const authData = Buffer.concat([
    rpHash, Buffer.from([0x45]), Buffer.alloc(4),
    Buffer.alloc(16), Buffer.from([0, credentialId.length]), credentialId, coseKey,
  ]);

  const registered = await expectJson(await request('/auth/me/passkeys/registration/begin', {
    method: 'POST',
    headers: { cookie: initial.cookie, 'x-csrf-token': initial.csrf, 'content-type': 'application/json' },
    body: JSON.stringify({ label: 'Integration passkey' }),
  }));
  const createClientData = Buffer.from(JSON.stringify({
    type: 'webauthn.create', challenge: registered.publicKey.challenge,
    origin: issuer, crossOrigin: false,
  }));
  const registration = {
    ceremony_id: registered.ceremony_id,
    response: {
      id: encodedId, rawId: encodedId, type: 'public-key',
      response: {
        clientDataJSON: base64url(createClientData),
        attestationObject: base64url(cbor(new Map([
          ['fmt', 'none'], ['authData', authData], ['attStmt', new Map()],
        ]))),
      },
    },
  };
  const created = await expectJson(await request('/auth/me/passkeys/registration/finish', {
    method: 'POST',
    headers: { cookie: initial.cookie, 'x-csrf-token': initial.csrf, 'content-type': 'application/json' },
    body: JSON.stringify(registration),
  }), 201);
  assert.equal(created.credential_id, encodedId);
  const replay = await request('/auth/me/passkeys/registration/finish', {
    method: 'POST',
    headers: { cookie: initial.cookie, 'x-csrf-token': initial.csrf, 'content-type': 'application/json' },
    body: JSON.stringify(registration),
  });
  assert.notEqual(replay.status, 201, 'registration challenge must be consumed only once');

  const begun = await expectJson(await request('/auth/passkey/begin', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email }),
  }));
  const assertionData = Buffer.concat([rpHash, Buffer.from([0x05]), Buffer.from([0, 0, 0, 1])]);
  const getClientData = Buffer.from(JSON.stringify({
    type: 'webauthn.get', challenge: begun.publicKey.challenge, origin: issuer, crossOrigin: false,
  }));
  const userHandle = Buffer.concat([
    uuidBytes(configuration.tenant.tenant_id), uuidBytes(provisioned.user_ids[0]),
  ]);
  const toSign = Buffer.concat([assertionData, createHash('sha256').update(getClientData).digest()]);
  const authentication = {
    ceremony_id: begun.ceremony_id,
    response: {
      id: encodedId, rawId: encodedId, type: 'public-key',
      response: {
        authenticatorData: base64url(assertionData),
        clientDataJSON: base64url(getClientData),
        signature: base64url(sign('sha256', toSign, privateKey)),
        userHandle: base64url(userHandle),
      },
    },
  };
  const completed = await request('/auth/passkey/finish', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(authentication),
  });
  assert.equal(completed.status, 200, await completed.clone().text());
  const passkeyCookies = completed.headers.getSetCookie();
  assert.equal(passkeyCookies.length, 2);
  const cookie = passkeyCookies.map(value => value.split(';')[0]).join('; ');
  const me = await expectJson(await request('/auth/me', { headers: { cookie } }));
  assert.equal(me.account.email, email);
  const usedAgain = await request('/auth/passkey/finish', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(authentication),
  });
  assert.notEqual(usedAgain.status, 200, 'assertion challenge cannot be replayed');
});

test('storage failure does not issue tokens or accept a login', async () => {
  await database.exec('DROP TABLE nazo_state');
  const response = await request('/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email, password }) });
  assert.equal(response.status, 503);
  assert.equal(response.headers.get('set-cookie'), null);
  const client = provisioned.clients[2];
  const token = await postForm('/token', { grant_type: 'client_credentials', scope: 'service' }, {
    authorization: `Basic ${Buffer.from(`${client.client_id}:${client.client_secret}`).toString('base64')}`,
  });
  assert.equal(token.status, 503);
  assert.equal((await token.json()).access_token, undefined);
});
