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
const registrationInitialAccessToken = randomBytes(32).toString('base64url');
const configuration = {
  tenant: {
    tenant_id: '00000000-0000-0000-0000-000000000001',
    realm_id: '00000000-0000-0000-0000-000000000002',
    organization_id: '00000000-0000-0000-0000-000000000003',
  },
  issuer: 'http://localhost', frontend_base_url: 'https://client.example', ingress: 'local',
  cors_allowed_origins: ['https://client.example'],
  modules: ['session_management', 'request_objects', 'jarm', 'token_exchange', 'jwt_bearer_grant', 'frontchannel_logout', 'http_message_signatures', 'authorization_details', 'native_sso', 'device_authorization', 'dynamic_client_registration'],
};
let temporary, mf, database, provisioned, options, signingKeys;
const clientKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const clientJwk = { ...clientKey.publicKey.export({ format: 'jwk' }), kid: 'worker-client-es256', alg: 'ES256', use: 'sig' };
const jwt = (claims, typ = 'JWT') => {
  const input = [ { alg: 'ES256', kid: clientJwk.kid, typ }, claims ]
    .map(value => Buffer.from(JSON.stringify(value)).toString('base64url')).join('.');
  return `${input}.${sign('sha256', Buffer.from(input), { key: clientKey.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
};
const clientAssertion = (client, typ = 'JWT') => {
  const now = Math.floor(Date.now() / 1000);
  return jwt({ iss: client.client_id, sub: client.client_id, aud: issuer, iat: now, exp: now + 120, jti: randomUUID() }, typ);
};
const jwtClientForm = (client, values) => ({ client_id: client.client_id,
  client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
  client_assertion: clientAssertion(client), ...values });
const basic = client => ({ authorization: `Basic ${Buffer.from(`${client.client_id}:${client.client_secret}`).toString('base64')}` });
const claims = token => JSON.parse(Buffer.from(token.split('.')[1], 'base64url'));

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
    security_policy: { version: 1, session_management: true },
    frontchannel_logout_uri: 'https://client.example/frontchannel',
    frontchannel_logout_session_required: true,
    post_logout_redirect_uris: ['https://client.example/logged-out'],
    authorization_signed_response_alg: 'RS256',
  };
  const input = {
    configuration, client_secret_pepper: randomBytes(32).toString('base64'),
    signing_key_id: 'integration', signing_key_base64: randomBytes(32).toString('base64'),
    clients: [publicClient, { ...publicClient, client_name: 'Worker DPoP integration', require_dpop_bound_tokens: true }, {
      client_name: 'Worker service integration', client_type: 'confidential', redirect_uris: [],
      scopes: ['service'], allowed_audiences: ['resource://default'],
      grant_types: ['client_credentials', 'urn:ietf:params:oauth:grant-type:token-exchange'],
      token_endpoint_auth_method: 'client_secret_basic',
      security_policy: { version: 1 },
    }, {
      client_name: 'Worker private key integration', client_type: 'confidential', redirect_uris: [],
      scopes: ['service'], allowed_audiences: ['resource://default'],
      grant_types: ['client_credentials', 'urn:ietf:params:oauth:grant-type:jwt-bearer'],
      token_endpoint_auth_method: 'private_key_jwt', token_endpoint_auth_signing_alg: 'ES256',
      jwks: { keys: [clientJwk] }, security_policy: { version: 1 },
    }, ...['source', 'destination'].map(name => ({ ...publicClient,
      client_name: `Worker Native SSO ${name}`,
      scopes: [...publicClient.scopes, 'device_sso'],
      allowed_audiences: ['resource://default', issuer],
      grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:token-exchange'],
    })), { ...publicClient, client_name: 'Worker Device Authorization',
      grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'],
      security_policy: { version: 1, allow_cross_device_flows: true },
    }, { ...publicClient, client_name: 'Worker Request Objects',
      jwks: { keys: [clientJwk] }, request_object_signing_alg: 'ES256',
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
    NAZO_DCR_INITIAL_ACCESS_TOKEN: registrationInitialAccessToken,
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

async function authorize(client, session, { pushed = false, signed = false, ...extra } = {}) {
  const verifier = randomBytes(32).toString('base64url');
  let parameters = {
    response_type: 'code', client_id: client.client_id, redirect_uri: redirect,
    scope: 'openid profile email offline_access', code_challenge: sha256(verifier),
    code_challenge_method: 'S256', state: 'integration-state', nonce: randomUUID(), ...extra,
  };
  if (signed) {
    const now = Math.floor(Date.now() / 1000);
    parameters = { client_id: client.client_id,
      request: jwt({ ...parameters, iss: client.client_id, aud: issuer, iat: now, nbf: now, exp: now + 120, jti: randomUUID() }) };
  }
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
  return { verifier, code: location.searchParams.get('code'), sessionState: location.searchParams.get('session_state') };
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
  assert.ok(metadata.grant_types_supported.includes('urn:ietf:params:oauth:grant-type:device_code'));
  assert.ok(!metadata.token_endpoint_auth_methods_supported.includes('tls_client_auth'));
  assert.equal(metadata.registration_endpoint, `${issuer}/register`);
  assert.equal(metadata.backchannel_logout_supported, false);
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

test('inline signed request objects use registered keys and reject tampering and replay', async () => {
  const client = provisioned.clients[7];
  const session = await login();
  const authorization = await authorize(client, session, { pushed: true, signed: true });
  const token = await expectJson(await postForm('/token', tokenForm(client, authorization)));
  assert.ok(token.access_token && token.id_token);
  const now = Math.floor(Date.now() / 1000);
  const signed = jwt({ response_type: 'code', client_id: client.client_id, redirect_uri: redirect,
    scope: 'openid profile', code_challenge: sha256(randomBytes(32)), code_challenge_method: 'S256',
    state: 'signed-state', nonce: randomUUID(), iss: client.client_id, aud: issuer,
    iat: now, nbf: now, exp: now + 120, jti: randomUUID() });
  await expectJson(await postForm('/par', { client_id: client.client_id, request: signed }), 201);
  const replay = await postForm('/par', { client_id: client.client_id, request: signed });
  assert.equal(replay.status, 400);
  const parts = signed.split('.');
  parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
  const tampered = await expectJson(await postForm('/par', { client_id: client.client_id, request: parts.join('.') }), 400);
  assert.equal(tampered.error, 'invalid_request_object');
});

test('Device Authorization preserves pending, slowdown, approval, denial and one-use token issuance', async () => {
  const client = provisioned.clients[6];
  const profileHeaders = { 'x-nazo-test-binding': 'passkey-profile' };
  const create = () => postForm('/device_authorization', { client_id: client.client_id, scope: 'openid profile email offline_access' }, profileHeaders);
  const poll = device => postForm('/token', { grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    client_id: client.client_id, device_code: device.device_code }, profileHeaders);
  const device = await expectJson(await create());
  assert.ok(device.device_code && device.user_code && device.expires_in > 0 && device.interval > 0);
  const ui = await request('/device', { headers: profileHeaders });
  assert.equal(ui.status, 307);
  assert.equal(ui.headers.get('location'), '/ui/device');
  assert.equal((await expectJson(await poll(device), 400)).error, 'authorization_pending');
  assert.equal((await expectJson(await poll(device), 400)).error, 'slow_down');
  const session = await login();
  const verification = await expectJson(await request(`/device/verification?${form({ user_code: device.user_code })}`,
    { headers: { ...profileHeaders, cookie: session.cookie } }));
  assert.equal(verification.request.client_id, client.client_id);
  const decision = (target, choice, csrf = session.csrf) => postForm('/device/decision',
    { user_code: target.user_code, decision: choice, csrf_token: csrf }, { ...profileHeaders, cookie: session.cookie });
  const invalidCsrf = await expectJson(await decision(device, 'approve', 'wrong-csrf'), 400);
  assert.equal(invalidCsrf.error, 'invalid_request');
  const approval = await decision(device, 'approve');
  assert.equal(approval.status, 200, await approval.clone().text());
  const token = await expectJson(await poll(device));
  assert.ok(token.access_token && token.id_token && token.refresh_token);
  const user = await expectJson(await request('/userinfo', { headers: { authorization: `Bearer ${token.access_token}` } }));
  assert.equal(user.email, email);
  assert.equal((await poll(device)).status, 400);
  const denied = await expectJson(await create());
  assert.equal((await decision(denied, 'deny')).status, 200);
  assert.equal((await expectJson(await poll(denied), 400)).error, 'access_denied');
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
  assert.equal(me.email, email);
  const usedAgain = await request('/auth/passkey/finish', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(authentication),
  });
  assert.notEqual(usedAgain.status, 200, 'assertion challenge cannot be replayed');
});

test('private_key_jwt authenticates service requests and JWT bearer assertions are single-use', async () => {
  const client = provisioned.clients[3];
  const authenticated = jwtClientForm(client, { grant_type: 'client_credentials', scope: 'service' });
  const service = await expectJson(await postForm('/token', authenticated));
  assert.ok(service.access_token);
  const authReplay = await expectJson(await postForm('/token', authenticated), 400);
  assert.equal(authReplay.error, 'invalid_client');

  const assertion = clientAssertion(client, 'oauth-jwt-bearer+jwt');
  const outcomes = await Promise.all(Array.from({ length: 8 }, () => postForm('/token', jwtClientForm(client, {
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion, scope: 'service',
  }))));
  assert.equal(outcomes.filter(response => response.status === 200).length, 1);
  assert.ok(outcomes.every(response => [200, 400].includes(response.status)));
  const issued = await outcomes.find(response => response.status === 200).json();
  assert.equal(claims(issued.access_token).sub, client.client_id);
  assert.equal(issued.refresh_token, undefined);
  const now = Math.floor(Date.now() / 1000);
  const wrongSubject = jwt({ iss: client.client_id, sub: 'other-client', aud: issuer,
    iat: now, exp: now + 120, jti: randomUUID() }, 'oauth-jwt-bearer+jwt');
  const rejected = await expectJson(await postForm('/token', jwtClientForm(client, {
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: wrongSubject, scope: 'service',
  })), 400);
  assert.equal(rejected.error, 'invalid_grant');
});

test('local token exchange enforces targets, scopes and current revocation state', async () => {
  const client = provisioned.clients[2];
  const source = await expectJson(await postForm('/token', { grant_type: 'client_credentials', scope: 'service' }, basic(client)));
  const exchange = { grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    subject_token: source.access_token, subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    resource: 'resource://default', scope: 'service' };
  const issued = await expectJson(await postForm('/token', exchange, basic(client)));
  assert.equal(issued.issued_token_type, 'urn:ietf:params:oauth:token-type:access_token');
  assert.equal(issued.refresh_token, undefined);
  assert.equal(claims(issued.access_token).sub, claims(source.access_token).sub);
  assert.deepEqual(claims(issued.access_token).aud, claims(source.access_token).aud);
  const widened = await expectJson(await postForm('/token', { ...exchange, scope: 'service admin' }, basic(client)), 400);
  assert.equal(widened.error, 'invalid_scope');
  const target = await expectJson(await postForm('/token', { ...exchange, resource: 'https://unregistered.example' }, basic(client)), 400);
  assert.equal(target.error, 'invalid_target');
  assert.equal((await postForm('/revoke', { token: source.access_token, token_type_hint: 'access_token' }, basic(client))).status, 200);
  const revoked = await expectJson(await postForm('/token', exchange, basic(client)), 400);
  assert.equal(revoked.error, 'invalid_grant');
});

test('authorization details survive consent, redemption and refresh through D1', async () => {
  const client = provisioned.clients[0];
  const session = await login();
  const details = [{ type: 'account_information', actions: ['read'], locations: ['https://accounts.example'] }];
  const authorization = await authorize(client, session, { pushed: true, authorization_details: JSON.stringify(details) });
  const token = await expectJson(await postForm('/token', tokenForm(client, authorization)));
  assert.deepEqual(token.authorization_details, details);
  assert.deepEqual(claims(token.access_token).authorization_details, details);
  const refreshed = await expectJson(await postForm('/token', {
    grant_type: 'refresh_token', client_id: client.client_id, refresh_token: token.refresh_token,
  }));
  assert.deepEqual(refreshed.authorization_details, details);
  const invalid = await expectJson(await postForm('/par', {
    client_id: client.client_id, response_type: 'code', redirect_uri: redirect, scope: 'openid',
    code_challenge: sha256(randomBytes(32)), code_challenge_method: 'S256',
    authorization_details: JSON.stringify([{ type: 'unregistered_details' }]),
  }), 400);
  assert.equal(invalid.error, 'invalid_request');
});

test('Passkey profile preserves shared CORS, session management and frontchannel logout', async () => {
  const client = provisioned.clients[0];
  const session = await login();
  const authorization = await authorize(client, session);
  assert.ok(authorization.sessionState);
  const token = await expectJson(await postForm('/token', tokenForm(client, authorization)));
  const profileHeaders = { 'x-nazo-test-binding': 'passkey-profile' };
  const preflight = await request('/token', { method: 'OPTIONS', headers: { ...profileHeaders,
    origin: 'https://client.example', 'access-control-request-method': 'POST',
    'access-control-request-headers': 'content-type,dpop',
  } });
  assert.equal(preflight.status, 200, await preflight.clone().text());
  assert.equal(preflight.headers.get('access-control-allow-origin'), 'https://client.example');
  assert.equal(preflight.headers.get('access-control-allow-credentials'), null);
  const forbidden = await request('/authorize', { method: 'OPTIONS', headers: { ...profileHeaders,
    origin: 'https://client.example', 'access-control-request-method': 'GET',
  } });
  assert.equal(forbidden.headers.get('access-control-allow-origin'), null);
  assert.equal((await request('/auth/login', { method: 'OPTIONS', headers: profileHeaders })).status, 404);
  const iframe = await request('/check_session', { headers: profileHeaders });
  assert.equal(iframe.status, 200, await iframe.clone().text());
  assert.equal(iframe.headers.get('cache-control'), 'no-store');
  const statusUrl = `/check_session/status?${form({ client_id: client.client_id,
    origin: 'https://client.example', session_state: authorization.sessionState })}`;
  assert.equal((await expectJson(await request(statusUrl, {
    headers: { ...profileHeaders, cookie: session.cookie },
  }))).status, 'unchanged');
  const logout = await postForm('/logout', { id_token_hint: token.id_token,
    post_logout_redirect_uri: 'https://client.example/logged-out', state: 'logout-state',
  }, { ...profileHeaders, cookie: session.cookie });
  assert.equal(logout.status, 200, await logout.clone().text());
  const html = await logout.text();
  assert.ok(html.includes('https://client.example/frontchannel?iss='));
  assert.ok(html.includes('sid='));
  assert.ok(logout.headers.getSetCookie().some(value => value.includes('Max-Age=0')));
  assert.equal((await expectJson(await request(statusUrl, {
    headers: { ...profileHeaders, cookie: session.cookie },
  }))).status, 'changed');
});

test('Native SSO reuses valid device authority and refuses it after source revocation', async () => {
  const [sourceClient, destinationClient] = provisioned.clients.slice(4, 6);
  const session = await login();
  const authorization = await authorize(sourceClient, session, { scope: 'openid profile email offline_access device_sso' });
  const source = await expectJson(await postForm('/token', tokenForm(sourceClient, authorization)));
  assert.ok(source.device_secret && source.id_token && source.refresh_token);
  assert.equal(claims(source.id_token).ds_hash, sha256(source.device_secret));
  const exchange = { client_id: destinationClient.client_id,
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange', audience: issuer,
    subject_token: source.id_token, subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
    actor_token: source.device_secret, actor_token_type: 'urn:openid:params:token-type:device-secret',
    scope: 'openid offline_access device_sso' };
  const first = await expectJson(await postForm('/token', exchange));
  const second = await expectJson(await postForm('/token', exchange));
  assert.ok(first.device_secret && first.refresh_token && first.id_token);
  assert.notEqual(first.refresh_token, second.refresh_token, 'Native SSO is a fresh exchange');
  assert.equal(claims(first.id_token).sub, claims(source.id_token).sub);
  assert.equal(claims(first.id_token).aud, destinationClient.client_id);
  const unbound = await expectJson(await postForm('/token', { ...exchange, actor_token: randomBytes(32).toString('base64url') }), 400);
  assert.equal(unbound.error, 'invalid_grant');
  assert.equal((await postForm('/revoke', { client_id: sourceClient.client_id,
    token: source.refresh_token, token_type_hint: 'refresh_token' })).status, 200);
  const revoked = await expectJson(await postForm('/token', exchange), 400);
  assert.equal(revoked.error, 'invalid_grant');
});

test('HTTP message signatures bind requests and responses and consume replay once', async () => {
  const client = provisioned.clients[3];
  const token = await expectJson(await postForm('/token', jwtClientForm(client, {
    grant_type: 'client_credentials', scope: 'service',
  })));
  const authorization = `Bearer ${token.access_token}`;
  const target = `${issuer}/fapi/resource`;
  const params = `("@method" "@target-uri" "authorization");created=${Math.floor(Date.now() / 1000)};keyid="${clientJwk.kid}";alg="ecdsa-p256-sha256";tag="fapi-2-request"`;
  const signatureBase = `"@method": GET\n"@target-uri": ${target}\n"authorization": ${authorization}\n"@signature-params": ${params}`;
  const signature = sign('sha256', Buffer.from(signatureBase), { key: clientKey.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64');
  const headers = { authorization, 'signature-input': `sig1=${params}`, signature: `sig1=:${signature}:`,
    'x-nazo-test-binding': 'passkey-profile' };
  const response = await request('/fapi/resource', { headers });
  assert.equal(response.status, 200, await response.clone().text());
  const body = Buffer.from(await response.arrayBuffer());
  const digest = `sha-256=:${createHash('sha256').update(body).digest('base64')}:`;
  assert.equal(response.headers.get('content-digest'), digest);
  const returnedInput = response.headers.get('signature-input');
  const returnedSignature = response.headers.get('signature');
  assert.ok(returnedInput && returnedSignature);
  const returnedParams = returnedInput.slice(returnedInput.indexOf('=') + 1);
  const components = returnedParams.slice(1, returnedParams.indexOf(')')).match(/"[^"]+"(?:;req)?/g);
  const required = ['"@status"', '"content-digest"', '"content-type"', '"x-fapi-interaction-id"',
    '"@method";req', '"@target-uri";req', '"signature-input";req', '"signature";req'];
  assert.equal(new Set(components).size, components.length, 'signature components cannot repeat');
  for (const component of required) assert.ok(components.includes(component), `missing signed component ${component}`);
  assert.ok(response.headers.get('x-fapi-interaction-id'));
  const derived = { '"@status"': '200', '"@method";req': 'GET', '"@target-uri";req': target };
  const responseBase = components.map(component => {
    const match = /^"([^\"]+)"(;req)?$/.exec(component);
    assert.ok(match, `unsupported signed component parameters ${component}`);
    const [, name, requestComponent] = match;
    const value = name.startsWith('@') ? derived[component]
      : requestComponent ? headers[name] : response.headers.get(name);
    assert.ok(value !== null && value !== undefined, `missing value for signed component ${component}`);
    return `${component}: ${value}`;
  }).concat(`"@signature-params": ${returnedParams}`).join('\n');
  const kid = /;keyid="([^"]+)"/.exec(returnedParams)[1];
  const algorithm = /;alg="([^"]+)"/.exec(returnedParams)[1];
  assert.ok(['ed25519', 'rsa-v1_5-sha256', 'ecdsa-p256-sha256'].includes(algorithm));
  assert.ok(returnedParams.includes(';tag="fapi-2-response"'));
  const key = createPublicKey({ key: signingKeys.find(key => key.kid === kid), format: 'jwk' });
  const responseSignature = Buffer.from(/=:(.+):/.exec(returnedSignature)[1], 'base64');
  assert.ok(verify(algorithm === 'ed25519' ? null : 'sha256', Buffer.from(responseBase),
    algorithm === 'ecdsa-p256-sha256' ? { key, dsaEncoding: 'ieee-p1363' } : key, responseSignature));
  const replay = await request('/fapi/resource', { headers });
  assert.equal(replay.status, 401, await replay.clone().text());
});

test('dynamic registration requires admission and atomically rotates client management authority', async () => {
  const metadata = { client_name: 'Dynamic Worker service', grant_types: ['client_credentials'],
    token_endpoint_auth_method: 'client_secret_basic', scope: 'service' };
  const register = (body, token = registrationInitialAccessToken) => request('/register', {
    method: 'POST', headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body),
  });
  assert.equal((await register(metadata, null)).status, 401);
  assert.equal((await register(metadata, 'wrong-initial-access-token')).status, 401);
  const before = (await database.prepare('SELECT count(*) AS count FROM nazo_clients').first()).count;
  for (const unsupported of [
    { jwks_uri: 'https://client.example/jwks' },
    { sector_identifier_uri: 'https://client.example/sector' },
    { request_uris: ['https://client.example/request.jwt'] },
    { backchannel_logout_uri: 'https://client.example/logout' },
    { tls_client_certificate_bound_access_tokens: true },
    { token_endpoint_auth_method: 'tls_client_auth' },
    { grant_types: ['urn:openid:params:grant-type:ciba'] },
  ]) {
    const response = await register({ ...metadata, ...unsupported });
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error, 'invalid_client_metadata');
  }
  assert.equal((await database.prepare('SELECT count(*) AS count FROM nazo_clients').first()).count, before);
  const response = await register(metadata);
  assert.equal(response.status, 201);
  const created = await response.json();
  assert.ok(created.client_secret && created.registration_access_token);
  const managementPath = new URL(created.registration_client_uri).pathname;
  const manage = (method, token, body) => request(managementPath, { method,
    headers: { authorization: `Bearer ${token}`, ...(body ? { 'content-type': 'application/json' } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  assert.equal((await manage('GET', created.registration_access_token)).status, 200);
  const initialService = await postForm('/token', { grant_type: 'client_credentials', scope: 'service' }, basic(created));
  assert.equal(initialService.status, 200);
  const updatedResponse = await manage('PUT', created.registration_access_token, { ...metadata,
    client_id: created.client_id, client_secret: created.client_secret, client_name: 'Replaced service' });
  assert.equal(updatedResponse.status, 200);
  const updated = await updatedResponse.json();
  assert.equal(updated.client_id, created.client_id);
  assert.notEqual(updated.client_secret, created.client_secret);
  assert.notEqual(updated.registration_access_token, created.registration_access_token);
  assert.equal((await manage('GET', created.registration_access_token)).status, 401);
  assert.equal((await postForm('/token', { grant_type: 'client_credentials', scope: 'service' }, basic(created))).status, 401);
  assert.equal((await postForm('/token', { grant_type: 'client_credentials', scope: 'service' }, basic(updated))).status, 200);
  const replacements = await Promise.all(Array.from({ length: 8 }, (_, index) => manage('PUT', updated.registration_access_token,
    { ...metadata, client_id: updated.client_id, client_secret: updated.client_secret, client_name: `Concurrent ${index}` })));
  assert.equal(replacements.filter(response => response.status === 200).length, 1);
  assert.ok(replacements.every(response => response.status === 200 || response.status === 401));
  const winner = await replacements.find(response => response.status === 200).json();
  assert.equal((await manage('DELETE', winner.registration_access_token)).status, 204);
  assert.equal((await manage('GET', winner.registration_access_token)).status, 401);
  const deleted = await expectJson(await postForm('/token', { grant_type: 'client_credentials', scope: 'service' }, basic(winner)), 400);
  assert.equal(deleted.error, 'unauthorized_client');
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
