// Offline wallet contract checks; these make no remote requests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { assertCredentialStatus, preAuthorizedCredentialSelector } from '../test-support/public-credentials.mjs';

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
