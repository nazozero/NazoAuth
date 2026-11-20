// Offline wallet contract checks; these make no remote requests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { assertCredentialStatus, preAuthorizedCredentialSelector, withCredentialTokenCleanup } from '../test-support/public-credentials.mjs';

const issuer = 'https://credential-fixture.example';
const detail = () => ({ type: 'openid_credential', credential_configuration_id: 'fixture',
  credential_identifiers: ['opaque-issuer-selected-credential'], locations: [issuer] });

test('acceptance wallet uses the issuer response opaque identifier exclusively', () => {
  const token = { authorization_details: [detail()] };
  assert.deepEqual(preAuthorizedCredentialSelector(token, 'fixture', issuer),
    { credential_identifier: 'opaque-issuer-selected-credential' });
  assert.equal(Object.hasOwn(preAuthorizedCredentialSelector(token, 'fixture', issuer), 'credential_configuration_id'), false);
});

test('acceptance wallet refuses missing, substituted or ambiguous credential authorization', () => {
  for (const token of [{}, { authorization_details: [] },
    { authorization_details: [{ ...detail(), locations: ['https://other.example'] }] },
    { authorization_details: [{ ...detail(), credential_configuration_id: 'other' }] },
    { authorization_details: [{ ...detail(), credential_identifiers: [] }] },
    { authorization_details: [{ ...detail(), credential_identifiers: ['one', 'two'] }] },
    { authorization_details: [detail(), detail()] }]) {
    assert.throws(() => preAuthorizedCredentialSelector(token, 'fixture', issuer), /Acceptance credentials/);
  }
});

test('credential failures retain only audited diagnostic literals', () => {
  assert.throws(() => assertCredentialStatus({ status: 400, text: JSON.stringify({
    error: 'invalid_credential_request', error_description: 'Credential identifier is required for this access token.',
  }) }, 200), /HTTP 400; expected 200; invalid_credential_request; Credential identifier is required/);
  const privateBody = JSON.stringify({ error: 'private-response-token', error_description: 'private-secret-value',
    access_token: 'private-access-token' });
  assert.throws(() => assertCredentialStatus({ status: 503, text: privateBody }, 200), error =>
    error.message === 'Acceptance credentials: Credential endpoint returned HTTP 503; expected 200');
});

function cleanupFixture({ cleanupStatus = 200 } = {}) {
  const input = { issuer, wallet_client_id: 'isolated-wallet' };
  const issued = [randomUUID(), randomUUID()];
  const revoked = [];
  let next = 0;
  const grant = { method: 'POST', body: new URLSearchParams({ client_id: input.wallet_client_id,
    grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code' }).toString() };
  const request = async (path, init) => {
    if (path === '/token') return { status: 200, text: JSON.stringify({ access_token: issued[next++] }) };
    assert.equal(path, '/revoke');
    const fields = new URLSearchParams(init.body);
    assert.equal(fields.get('client_id'), input.wallet_client_id);
    assert.ok(issued.includes(fields.get('token')), 'No unrelated access token is retired');
    revoked.push(fields.get('token'));
    return { status: cleanupStatus, text: '{}' };
  };
  return { input, issued, revoked, grant, request };
}

test('credential cleanup retires immediate and pending tokens after a failed flow without masking its cause', async () => {
  for (const cleanupStatus of [200, 503]) {
    const f = cleanupFixture({ cleanupStatus });
    const original = new Error('Acceptance credentials: Deferred issuance contract failed');
    await assert.rejects(withCredentialTokenCleanup(f.input, { request: f.request }, async (_, { request }) => {
      await request('/token', f.grant);
      await request('/token', f.grant);
      throw original;
    }), error => error === original);
    assert.deepEqual(f.revoked, f.issued, 'Failure of one cleanup must not skip another known token');
  }
});

test('credential cleanup does not repeat a successful in-flow revocation', async () => {
  const f = cleanupFixture();
  const result = await withCredentialTokenCleanup(f.input, { request: f.request }, async (_, { request }) => {
    await request('/token', f.grant);
    await request('/revoke', { method: 'POST', body: new URLSearchParams({
      client_id: f.input.wallet_client_id, token: f.issued[0], token_type_hint: 'access_token' }).toString() });
    return { verified: true };
  });
  assert.deepEqual(result, { verified: true });
  assert.deepEqual(f.revoked, [f.issued[0]]);
});

test('credential cleanup failure prevents a false successful acceptance result', async () => {
  const f = cleanupFixture({ cleanupStatus: 503 });
  await assert.rejects(withCredentialTokenCleanup(f.input, { request: f.request }, async (_, { request }) => {
    await request('/token', f.grant);
    return { verified: true };
  }), /Acceptance credentials: Credential access token cleanup failed/);
  assert.deepEqual(f.revoked, [f.issued[0]]);
});

test('credential cleanup does not capture another client or a non-credential grant', async () => {
  const f = cleanupFixture();
  await withCredentialTokenCleanup(f.input, { request: f.request }, async (_, { request }) => {
    for (const body of [
      { client_id: 'another-wallet', grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code' },
      { client_id: f.input.wallet_client_id, grant_type: 'client_credentials' },
    ]) await request('/token', { method: 'POST', body: new URLSearchParams(body).toString() });
  });
  assert.deepEqual(f.revoked, []);
});
