import assert from 'node:assert/strict';
import { createHash, randomUUID, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { publicAdminWorkflows } from '../test-support/public-admin-workflows.mjs';

const pem = name => new X509Certificate(readFileSync(new URL('../../../crates/crypto/tests/fixtures/certificates/' + name, import.meta.url))).toString();

function fixture({ wrongAdministrator = false, wrongUser = false, loseApproval = false,
  failToken = false, loseTrustApproval = false, trust = false } = {}) {
  const issuer = 'https://issuer.example';
  const admin = { id: randomUUID(), email: 'acceptance-admin@example.test', role: 'admin',
    admin_level: 2, mfa_enabled: true, mfa_required: false };
  const user = { id: randomUUID(), email: 'acceptance-user@example.test', role: 'user', mfa_required: false };
  const session = { cookie: 'admin-cookie', csrf: 'admin-csrf' };
  const baselineSession = { cookie: 'user-cookie', csrf: 'user-csrf' };
  const input = { administrator: { user_id: admin.id, email: admin.email }, user: { user_id: user.id, email: user.email },
    ...(trust ? { mtls_trust_anchors: [pem('root.pem'), pem('intermediate.der')] } : {}) };
  const calls = [];
  const steps = [];
  const accesses = [];
  const anchors = [];
  const existingClient = { client_id: 'existing-real-client', client_name: 'Unrelated existing client', is_active: true };
  const existingGrant = { client_id: existingClient.client_id, user_id: user.id };
  const grants = [existingGrant];
  let client;
  let refreshRevoked = false;
  const response = (status, value = {}, headers = {}) => {
    const text = typeof value === 'string' ? value : JSON.stringify(value);
    return { status, text, bytes: Buffer.from(text), headers: new Headers(headers) };
  };
  const json = (value, status = 200) => {
    assert.equal(value.status, status, 'Expected fixture response status');
    return JSON.parse(value.text);
  };
  const clientView = () => {
    const { client_secret: omitted, ...view } = client;
    assert.ok(omitted);
    return view;
  };
  const anchorView = ({ certificate_pem: omitted, ...view }) => {
    assert.ok(omitted);
    return view;
  };
  const list = (items, search) => {
    const page = Number(search.get('page') || 1);
    const size = Number(search.get('page_size') || 100);
    return response(200, { total: items.length, page, page_size: size, items: items.slice((page - 1) * size, page * size) });
  };
  const request = async (path, init = {}) => {
    const url = new URL(path, issuer);
    assert.equal(url.origin, issuer);
    const method = init.method || 'GET';
    const headers = init.headers || {};
    const body = init.body ? JSON.parse(init.body) : {};
    calls.push({ path: url.pathname, method, body });
    if (url.pathname === '/auth/me') {
      return response(200, headers.cookie === session.cookie
        ? { ...admin, ...(wrongAdministrator ? { id: randomUUID() } : {}) }
        : { ...user, ...(wrongUser ? { id: randomUUID() } : {}) });
    }
    if (url.pathname.startsWith('/admin/')) {
      if (headers.cookie !== session.cookie) return response(403, { error: 'access_denied' });
      if (method !== 'GET' && headers['x-csrf-token'] !== session.csrf) return response(403, { error: 'invalid_request' });
    }
    if (url.pathname === '/auth/me/access-requests') {
      assert.equal(headers.cookie, baselineSession.cookie);
      if (method === 'GET') return response(200, { total: accesses.length, items: accesses.map(value => ({ ...value,
        ...(value.status === 1 && !value.consumed ? { delivery_available: true } : {}),
      })) });
      if (accesses.some(value => value.status === 0)) return response(409, { error: 'invalid_request' });
      const created = { ...body, id: randomUUID(), user_id: user.id, status: 0, approved_client_id: null };
      accesses.push(created);
      return response(201, created);
    }
    if (url.pathname === '/admin/access-requests') return list(accesses, url.searchParams);
    const decision = url.pathname.match(/^\/admin\/access-requests\/([^/]+)\/(approve|reject)$/);
    if (decision) {
      const access = accesses.find(value => value.id === decision[1]);
      assert.ok(access, 'Only this run creates mutable access requests');
      if (access.status !== 0) return response(409, { error: 'invalid_request' });
      if (decision[2] === 'approve') {
        access.status = 1;
        access.approved_client_id = randomUUID();
        client = { ...body, client_id: randomUUID(), client_secret: randomUUID(), is_active: true };
        if (loseApproval) throw new Error('HTTPS request failed or timed out');
      } else {
        access.status = 2;
        access.admin_note = body.admin_note;
      }
      return response(200, access);
    }
    if (url.pathname === '/auth/me/access-delivery') {
      const access = accesses.find(value => value.id === body.request_id);
      if (headers.cookie !== baselineSession.cookie || access?.status !== 1 || access.consumed)
        return response(404, { error: 'invalid_request' });
      access.consumed = true;
      return response(200, { ...client, request_id: access.id, user_id: user.id, read_once_notice: 'Read once' });
    }
    if (url.pathname === '/admin/clients') return list([existingClient, ...(client ? [clientView()] : [])], url.searchParams);
    if (url.pathname.startsWith('/admin/clients/')) {
      assert.equal(url.pathname, '/admin/clients/' + client.client_id, 'No mutation of an existing client');
      if (method === 'PATCH') Object.assign(client, body);
      return response(200, clientView());
    }
    if (url.pathname === '/admin/grants') return list(grants, url.searchParams);
    if (url.pathname === '/admin/grants/revoke') {
      assert.deepEqual(body, { client_id: client.client_id, user_id: user.id });
      const index = grants.findIndex(value => value.client_id === client.client_id && value.user_id === user.id);
      assert.ok(index >= 0);
      grants.splice(index, 1);
      refreshRevoked = true;
      return response(200, { removed_grants: 1, revoked_refresh_tokens: 1 });
    }
    if (url.pathname === '/auth/me/mtls-trust-requests') {
      assert.equal(headers.cookie, baselineSession.cookie);
      if (method === 'GET') return response(200, { total: anchors.length, items: anchors.map(anchorView) });
      assert.equal(body.client_id, client.client_id);
      assert.equal(client.require_mtls_bound_tokens, true);
      const certificate = new X509Certificate(body.certificate_pem);
      const created = { id: randomUUID(), client_id: client.client_id, user_id: user.id, status: 0,
        certificate_sha256: createHash('sha256').update(certificate.raw).digest('hex'), certificate_pem: certificate.toString() };
      anchors.push(created);
      return response(201, anchorView(created));
    }
    if (url.pathname === '/admin/mtls-trust-requests') return list(anchors.map(anchorView), url.searchParams);
    const trustDecision = url.pathname.match(/^\/admin\/mtls-trust-requests\/([^/]+)\/(approve|reject|revoke)$/);
    if (trustDecision) {
      const anchor = anchors.find(value => value.id === trustDecision[1]);
      assert.ok(anchor);
      assert.equal(anchor.client_id, client.client_id);
      const action = trustDecision[2];
      assert.equal(anchor.status, action === 'revoke' ? 1 : 0);
      anchor.status = { approve: 1, reject: 2, revoke: 3 }[action];
      anchor[action === 'revoke' ? 'revoked_at' : 'resolved_at'] = new Date().toISOString();
      if (action === 'approve' && loseTrustApproval) throw new Error('HTTPS request failed or timed out');
      return response(200, anchorView(anchor));
    }
    if (url.pathname === '/admin/mtls-trust-anchors.pem') return response(200,
      anchors.filter(value => value.status === 1 && client.is_active).map(value => value.certificate_pem).join(''),
      { 'content-type': 'application/x-pem-file', 'cache-control': 'no-store' });
    throw new Error('Unexpected fixture request');
  };
  const postJson = (path, body, headers) => request(path, { method: 'POST', headers, body: JSON.stringify(body) });
  const authenticatedForm = async (path, supplied, body) => {
    assert.equal(supplied.client_id, client.client_id);
    assert.equal(supplied.client_secret, client.client_secret);
    if (!client.is_active) return response(400, { error: 'unauthorized_client' });
    if (path === '/introspect') return response(200, { active: true });
    if (body.grant_type === 'refresh_token') {
      assert.equal(refreshRevoked, true);
      return response(400, { error: 'invalid_grant' });
    }
    if (failToken) return response(503, { error: 'server_error' });
    assert.equal(body.grant_type, 'client_credentials');
    assert.equal(body.scope, 'service');
    return response(200, { access_token: 'synthetic-access-token' });
  };
  const authorize = async (supplied, current, options) => {
    assert.equal(supplied.client_id, client.client_id);
    assert.deepEqual(current, baselineSession);
    assert.equal(options.scope, 'service offline_access');
    return { code: 'synthetic-code' };
  };
  const redeem = async (supplied, authorization) => {
    assert.equal(supplied.client_id, client.client_id);
    assert.equal(authorization.code, 'synthetic-code');
    grants.push({ user_id: user.id, email: user.email, client_id: client.client_id,
      client_name: client.client_name, authorization_count: 1, last_scopes: ['service', 'offline_access'] });
    return response(200, { access_token: 'synthetic-access-token', refresh_token: randomUUID() });
  };
  const step = async (name, operation) => {
    try { await operation(); steps.push({ name, status: 'passed' }); return true; }
    catch (error) { steps.push({ name, status: 'failed', reason: error.message }); return false; }
  };
  return {
    calls, steps, accesses, anchors, grants, existingClient, existingGrant,
    get client() { return client; },
    args: { issuer, input, request, postJson, json, step, authenticatedForm, session, baselineSession,
      signingKeys: [], verifyJwt: value => assert.equal(value, 'synthetic-access-token'), authorize, redeem },
  };
}

test('administrator workflow covers access delivery, isolated grant revocation and public CA management', async () => {
  const f = fixture({ trust: true });
  await publicAdminWorkflows(f.args);
  assert.deepEqual(f.steps.filter(value => value.status === 'failed'), []);
  assert.equal(f.client.is_active, false);
  assert.deepEqual(f.accesses.map(value => value.status), [1, 2]);
  assert.equal(f.accesses[0].consumed, true);
  assert.deepEqual(f.anchors.map(value => value.status), [3, 2]);
  assert.deepEqual(f.grants, [f.existingGrant]);
  assert.equal(f.existingClient.is_active, true);
});

test('administrator workflow guards both exact account identities before mutations', async () => {
  for (const mismatch of [{ wrongAdministrator: true }, { wrongUser: true }]) {
    const f = fixture(mismatch);
    await publicAdminWorkflows(f.args);
    assert.equal(f.steps.length, 1);
    assert.equal(f.steps[0].status, 'failed');
    assert.ok(f.calls.every(value => value.method === 'GET'));
    assert.equal(f.client, undefined);
    assert.deepEqual(f.grants, [f.existingGrant]);
  }
});

test('a lost approval response still discovers and deactivates only this run client', async () => {
  const f = fixture({ loseApproval: true });
  await publicAdminWorkflows(f.args);
  assert.equal(f.steps.find(value => value.name === 'access_request_approval_and_one_time_delivery').status, 'failed');
  assert.equal(f.steps.find(value => value.name === 'admin_workflow_client_deactivation').status, 'passed');
  assert.equal(f.client.is_active, false);
  assert.equal(f.existingClient.is_active, true);
  assert.deepEqual(f.grants, [f.existingGrant]);
});

test('failed token verification still retires the new client and resolves pending owned requests', async () => {
  const f = fixture({ failToken: true });
  await publicAdminWorkflows(f.args);
  assert.equal(f.steps.find(value => value.name === 'approved_client_tokens_and_administrator_grant_revocation').status, 'failed');
  assert.equal(f.client.is_active, false);
  assert.ok(f.accesses.every(value => value.status !== 0));
  assert.deepEqual(f.grants, [f.existingGrant]);
});

test('a lost trust approval response recovers the new anchor and revokes it during cleanup', async () => {
  const f = fixture({ trust: true, loseTrustApproval: true });
  await publicAdminWorkflows(f.args);
  assert.equal(f.steps.find(value => value.name === 'owned_mtls_trust_request_review_rejection_revocation_and_export').status, 'failed');
  assert.equal(f.steps.find(value => value.name === 'admin_workflow_trust_cleanup').status, 'passed');
  assert.deepEqual(f.anchors.map(value => value.status), [3]);
  assert.equal(f.client.is_active, false);
  assert.equal(f.existingClient.is_active, true);
});
