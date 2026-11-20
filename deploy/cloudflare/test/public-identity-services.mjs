// Offline client-contract tests. These do not claim remote Worker verification.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync, randomUUID, sign, verify } from 'node:crypto';
import { publicIdentityServices, verifyScimSecurityEvent } from '../test-support/public-identity-services.mjs';

const issuer = 'https://identity-acceptance.example';
const audience = 'urn:nazo:acceptance:security-events';
const signing = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const signingJwk = { ...signing.publicKey.export({ format: 'jwk' }), kid: 'issuer-key', alg: 'ES256', use: 'sig' };
const encode = value => Buffer.from(value).toString('base64url');
const compact = (claims, header = { alg: 'ES256', typ: 'secevent+jwt', kid: 'issuer-key' }) => {
  const input = [header, claims].map(value => encode(JSON.stringify(value))).join('.');
  return input + '.' + encode(sign('sha256', Buffer.from(input), { key: signing.privateKey, dsaEncoding: 'ieee-p1363' }));
};
const eventClaims = () => ({ iss: issuer, aud: [audience], iat: Math.floor(Date.now() / 1000),
  jti: randomUUID(), txn: randomUUID(), sub_id: { format: 'scim', uri: '/Users/' + randomUUID() },
  events: { 'urn:ietf:params:scim:event:prov:create:notice': { attributes: ['active', 'id'] } } });

test('SET verification accepts the signed event profile without inventing an expiry claim', () => {
  const claims = eventClaims();
  assert.deepEqual(verifyScimSecurityEvent(compact(claims), { keys: [signingJwk], issuer, audience,
    id: claims.jti, earliest: claims.iat - 1 }), claims);
});

test('SET verification rejects tampering, recipient substitution, wrong JOSE type and stale events', () => {
  const claims = eventClaims();
  const context = { keys: [signingJwk], issuer, audience, id: claims.jti, earliest: claims.iat - 1 };
  const valid = compact(claims);
  const parts = valid.split('.');
  parts[1] = encode(JSON.stringify({ ...claims, aud: ['urn:other'] }));
  assert.throws(() => verifyScimSecurityEvent(parts.join('.'), context), /signature verification failed/);
  assert.throws(() => verifyScimSecurityEvent(compact({ ...claims, aud: ['urn:other'] }), context), /audience mismatch/);
  assert.throws(() => verifyScimSecurityEvent(compact(claims, { alg: 'ES256', typ: 'JWT', kid: 'issuer-key' }), context), /JOSE profile/);
  assert.throws(() => verifyScimSecurityEvent(compact({ ...claims, iat: claims.iat - 100 }), context), /time is invalid/);
  assert.throws(() => verifyScimSecurityEvent(valid, { ...context, id: randomUUID() }), /identity mismatch/);
  assert.throws(() => verifyScimSecurityEvent(valid, { ...context, keys: [signingJwk, signingJwk] }), /unambiguous/);
});

function fixture({ failScimPatch = false, wrongAdministrator = false } = {}) {
  const mtls = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const applications = [
    { client_id: 'legacy-client', client_name: 'Legacy application', last_scopes: ['openid'],
      authorization_count: null, last_authorized_at: null },
    { client_id: 'new-client', client_name: 'Recorded application', last_scopes: ['openid', 'profile'],
      authorization_count: 2, last_authorized_at: new Date().toISOString() },
  ];
  const administrator = { id: randomUUID(), email: 'admin-acceptance@example.com', role: 'admin', admin_level: 2,
    mfa_enabled: true, authorized_app_count: applications.length, avatar_url: null };
  const session = { cookie: 'session=private-fixture; csrf=private-csrf', csrf: 'private-csrf' };
  const input = { issuer, user: { user_id: randomUUID() }, administrator: {
    user_id: wrongAdministrator ? randomUUID() : administrator.id, email: administrator.email,
  }, modules: ['ciba', 'scim', 'scim_security_events'], dcr_initial_access_token: 'private-iat',
  scim: { token: 'private-scim', audience }, mtls: {
    private_key_pem: mtls.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    public_jwk: mtls.publicKey.export({ format: 'jwk' }), certificate_pem: 'offline mock transport fixture',
    subject_dn: 'CN=Worker acceptance', thumbprint: encode(Buffer.alloc(32, 7)),
  } };
  const calls = [];
  const steps = [];
  const events = new Map();
  const acknowledgements = new Set();
  const ciba = new Map();
  let target;
  let client;
  let registration;
  let scimUser;
  let avatar;
  let clientRetired = false;
  let targetDisabled = false;
  let scimDeleted = false;
  let cibaRetired = false;
  const response = (status, value = {}, headers = {}) => ({ status,
    text: JSON.stringify(value), bytes: Buffer.from(JSON.stringify(value)), headers: new Headers(headers) });
  const json = (result, expected = 200) => {
    assert.equal(result.status, expected, 'Expected fixture response status');
    return JSON.parse(result.text);
  };
  const addEvent = (...types) => {
    const claims = { ...eventClaims(), sub_id: { format: 'scim', uri: '/Users/' + scimUser.id },
      events: Object.fromEntries(types.map(type => ['urn:ietf:params:scim:event:prov:' + type, {}])) };
    events.set(claims.jti, compact(claims));
  };
  const request = async (path, init = {}) => {
    calls.push({ path, method: init.method || 'GET', mtls: init.nazo_mtls === true });
    const method = init.method || 'GET';
    const currentHeaders = init.headers || {};
    let body;
    if (typeof init.body === 'string') body = currentHeaders['content-type'] === 'application/x-www-form-urlencoded'
      ? Object.fromEntries(new URLSearchParams(init.body)) : JSON.parse(init.body);
    if (path === '/auth/me') return response(200, administrator);
    if (path === '/auth/me/applications') return currentHeaders.cookie
      ? response(200, { total: applications.length, items: applications }) : response(401);
    if (path === '/admin/users' && method === 'POST') {
      assert.equal(currentHeaders['x-csrf-token'], session.csrf);
      target = { id: randomUUID(), email: body.email, role: 'user', admin_level: 0, is_active: true };
      return response(201, target);
    }
    if (path === '/admin/users/' + target?.id && method === 'PATCH') {
      if (body.admin_level >= administrator.admin_level) return response(403, { error: 'access_denied' });
      Object.assign(target, body);
      if (body.is_active === false) targetDisabled = true;
      return response(200, target);
    }
    if (path === '/admin/clients' && method === 'POST') {
      client = { ...body, client_id: randomUUID(), client_secret: 'private-client-secret', is_active: true };
      return response(201, client);
    }
    if (path === '/admin/clients/' + client?.client_id) {
      if (method === 'PATCH') Object.assign(client, body);
      if (body?.is_active === false) clientRetired = true;
      const { client_secret: _secret, ...projection } = client;
      return response(200, projection);
    }
    if (path === '/register' && method === 'POST') {
      assert.equal(body.token_endpoint_auth_method, 'tls_client_auth');
      assert.equal(body.tls_client_certificate_bound_access_tokens, true);
      assert.equal(body.tls_client_auth_subject_dn, input.mtls.subject_dn);
      assert.equal(body.backchannel_token_delivery_mode, 'poll');
      assert.equal(body.id_token_signed_response_alg, 'PS256');
      assert.equal(body.backchannel_authentication_request_signing_alg, 'ES256');
      assert.equal(body.jwks.keys[0].x, input.mtls.public_jwk.x);
      registration = { ...body, client_id: randomUUID(), registration_access_token: 'private-rat' };
      registration.registration_client_uri = issuer + '/register/' + registration.client_id;
      return response(201, registration);
    }
    if (path === '/register/' + registration?.client_id && method === 'DELETE') {
      assert.equal(currentHeaders.authorization, 'Bearer private-rat');
      cibaRetired = true;
      return response(204);
    }
    if (path === '/admin/clients/' + registration?.client_id) {
      if (method === 'PATCH') {
        assert.equal(currentHeaders['x-csrf-token'], session.csrf);
        assert.equal(body.security_policy.allow_cross_device_flows, true);
        registration.security_policy = body.security_policy;
      }
      return response(200, { ...registration,
        security_policy: registration.security_policy || { version: 1, allow_cross_device_flows: false } });
    }
    if (path === '/bc-authorize') {
      assert.equal(init.nazo_mtls, true);
      assert.equal(registration.security_policy.allow_cross_device_flows, true);
      assert.deepEqual(Object.keys(body).sort(), ['client_id', 'request']);
      const parts = body.request.split('.');
      const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
      const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
      assert.equal(header.kid, registration.jwks.keys[0].kid);
      assert.equal(header.alg, 'ES256');
      assert.equal(claims.iss, registration.client_id);
      assert.equal(claims.aud, issuer);
      assert.equal(claims.login_hint, administrator.email);
      assert.equal(claims.scope, 'openid profile');
      assert.ok(claims.nbf && claims.iat && claims.exp && claims.jti && claims.binding_message);
      assert.equal(verify('sha256', Buffer.from(parts[0] + '.' + parts[1]), {
        key: createPublicKey({ key: registration.jwks.keys[0], format: 'jwk' }), dsaEncoding: 'ieee-p1363',
      }, Buffer.from(parts[2], 'base64url')), true);
      const transaction = { auth_req_id: randomUUID(), interval: 5, expires_in: 300, polls: 0, decision: null, consumed: false };
      ciba.set(transaction.auth_req_id, transaction);
      return response(200, transaction);
    }
    if (path.startsWith('/auth/ciba/')) {
      const transaction = ciba.get(path.slice('/auth/ciba/'.length));
      assert.ok(transaction);
      if (method === 'GET') return response(200, { auth_req_id: transaction.auth_req_id, csrf_token: session.csrf,
        request: { client_id: registration.client_id, scopes: ['openid', 'profile'] } });
      assert.equal(body.csrf_token, session.csrf);
      transaction.decision = body.decision;
      return response(200, { success: true });
    }
    if (path === '/token') {
      if (body.grant_type === 'client_credentials') {
        if (!client.is_active) return response(400, { error: 'unauthorized_client' });
        return response(200, { access_token: compact({ iss: issuer, exp: Math.floor(Date.now() / 1000) + 300 }) });
      }
      if (!init.nazo_mtls) return response(400, { error: 'invalid_client' });
      const transaction = ciba.get(body.auth_req_id);
      assert.ok(transaction);
      if (transaction.consumed) return response(400, { error: 'invalid_grant' });
      if (transaction.decision === 'deny') return response(400, { error: 'access_denied' });
      if (transaction.decision === 'approve') {
        transaction.consumed = true;
        const claims = { iss: issuer, sub: administrator.id, exp: Math.floor(Date.now() / 1000) + 300 };
        return response(200, { access_token: compact({ ...claims, cnf: { 'x5t#S256': input.mtls.thumbprint } }),
          id_token: compact({ ...claims, aud: registration.client_id }) });
      }
      return response(400, { error: transaction.polls++ ? 'slow_down' : 'authorization_pending' });
    }
    if (path === '/introspect') return response(200, { active: true });
    if (path === '/userinfo') return init.nazo_mtls ? response(200, { sub: administrator.id })
      : response(401, { error: 'invalid_token' });
    if (path === '/revoke') { assert.equal(init.nazo_mtls, true); return response(200); }
    if (path === '/scim/v2/ServiceProviderConfig') return response(200, {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
      patch: { supported: false }, filter: { supported: false },
    });
    if (path === '/scim/v2/Users' && method === 'POST') {
      assert.equal(body.userName, body.emails[0].value);
      scimUser = { ...body, id: randomUUID() };
      addEvent('create:notice');
      return response(201, scimUser);
    }
    if (path === '/scim/v2/Users') return response(401);
    if (path.startsWith('/scim/v2/Users?')) return response(200, { totalResults: 1, Resources: [scimUser] });
    if (path === '/scim/v2/Users/' + scimUser?.id) {
      if (method === 'DELETE') { scimDeleted = true; addEvent('delete'); return response(204); }
      if (scimDeleted) return response(404);
      if (method === 'PUT') { scimUser = { ...scimUser, ...body }; addEvent('put:notice'); }
      if (method === 'PATCH') {
        if (failScimPatch) return response(503, { error: 'server_error' });
        scimUser.active = false;
        scimUser.name.familyName = 'Deactivated';
        addEvent('patch:notice', 'deactivate');
      }
      return response(200, scimUser);
    }
    if (path === '/scim/v2/SecurityEvents') {
      for (const id of body.ack || []) acknowledgements.add(id);
      return response(200, { sets: Object.fromEntries([...events].filter(([id]) => !acknowledgements.has(id))), moreAvailable: false });
    }
    if (path === '/auth/me/avatar/uploads') return response(200, { upload_mode: 'multipart' });
    if (path === '/auth/me/avatar') {
      if (method === 'POST') {
        assert.ok(init.body instanceof FormData);
        avatar = Buffer.from(await init.body.get('avatar').arrayBuffer());
        administrator.avatar_url = '/auth/me/avatar';
        return response(200, administrator);
      }
      if (method === 'DELETE') { avatar = null; administrator.avatar_url = null; return response(200, administrator); }
      if (!avatar) return response(404);
      return { status: 200, bytes: avatar, text: avatar.toString(), headers: new Headers({ 'content-type': 'image/png',
        'x-content-type-options': 'nosniff', 'cache-control': 'private, no-store' }) };
    }
    throw new Error('Unexpected fixture route');
  };
  const postJson = (path, body, headers = {}) => request(path, { method: 'POST',
    headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
  const postForm = (path, body, headers = {}) => request(path, { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers }, body: new URLSearchParams(body).toString() });
  const step = async (name, run) => {
    try { await run(); steps.push({ name, passed: true }); return true; }
    catch (error) { steps.push({ name, passed: false, error }); return false; }
  };
  const verifyJwt = (value, _keys, expectedIssuer, expectedAudience) => {
    const parts = value.split('.');
    assert.equal(verify('sha256', Buffer.from(parts[0] + '.' + parts[1]), {
      key: signing.publicKey, dsaEncoding: 'ieee-p1363',
    }, Buffer.from(parts[2], 'base64url')), true);
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
    assert.equal(claims.iss, expectedIssuer);
    if (expectedAudience) assert.equal(claims.aud, expectedAudience);
    return claims;
  };
  return { args: { issuer, input, request, postJson, postForm, json, step, session, signingKeys: [signingJwk], verifyJwt,
    authenticatedForm: (path, acceptedClient, fields) => {
      assert.equal(acceptedClient.client_id, client.client_id);
      return postForm(path, fields);
    } }, steps, calls,
  cleaned: () => ({ targetDisabled, clientRetired, cibaRetired, scimDeleted, avatarAbsent: !avatar,
    acknowledged: acknowledgements.size }) };
}

test('identity acceptance uses signed CIBA requests, mTLS transport markers and only synthetic mutations', async () => {
  const testFixture = fixture();
  await publicIdentityServices(testFixture.args);
  assert.equal(testFixture.steps.length, 8);
  for (const result of testFixture.steps) assert.equal(result.passed, true, result.name + ': ' + result.error?.message);
  assert.deepEqual(testFixture.cleaned(), { targetDisabled: true, clientRetired: true, cibaRetired: true,
    scimDeleted: true, avatarAbsent: true, acknowledged: 4 });
  assert.equal(testFixture.calls.filter(call => call.path === '/bc-authorize').every(call => call.mtls), true);
  assert.equal(testFixture.calls.filter(call => call.path.startsWith('/auth/ciba/')).every(call => !call.mtls), true);
});

test('failed SCIM mutation still deletes its own synthetic subject and does not claim event success', async () => {
  const testFixture = fixture({ failScimPatch: true });
  await publicIdentityServices(testFixture.args);
  assert.equal(testFixture.cleaned().scimDeleted, true);
  assert.equal(testFixture.cleaned().acknowledged, 0);
  assert.deepEqual(testFixture.steps.filter(result => !result.passed).map(result => result.name), [
    'scim_user_create_replace_patch_deactivate_and_delete', 'scim_security_events_signature_subject_and_ack',
  ]);
});

test('identity acceptance refuses to mutate a session belonging to a different administrator fixture', async () => {
  const testFixture = fixture({ wrongAdministrator: true });
  await publicIdentityServices(testFixture.args);
  assert.deepEqual(testFixture.calls, [{ path: '/auth/me', method: 'GET', mtls: false }]);
  assert.equal(testFixture.steps[0].passed, false);
  assert.equal(testFixture.steps.length, 1);
});
