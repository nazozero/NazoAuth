// Offline orchestration regressions: no account, credential or remote request.
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import test from 'node:test';
import { publicMfa } from '../test-support/public-mfa.mjs';

function fixture({ retiredStatus = 400 } = {}) {
  const issuer = 'https://mfa-fixture.example';
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const seed = [...randomBytes(32)].map(value => alphabet[value & 31]).join('');
  const initial = Array.from({ length: 10 }, () => randomUUID());
  const replacement = Array.from({ length: 10 }, () => randomUUID());
  const calls = [], steps = [];
  let enabled = false, pending = false, remembered = false, regenerated = false, loggedOut = false;
  const response = (status, value = {}, rotate = false) => {
    const headers = new Headers();
    if (rotate) {
      headers.append('set-cookie', '__Host-nazo_session=' + randomUUID() + '; Path=/; Secure; HttpOnly');
      headers.append('set-cookie', '__Host-nazo_oauth_csrf=' + randomUUID() + '; Path=/; Secure');
    }
    return { status, text: JSON.stringify(value), headers };
  };
  const json = (value, expected = 200) => {
    if (value.status !== expected) throw new Error(`Unexpected HTTP status ${value.status}; expected ${expected}`);
    return JSON.parse(value.text);
  };
  const request = async (path, init = {}) => {
    assert.equal(new URL(path, issuer).origin, issuer);
    calls.push({ path, method: init.method || 'GET' });
    if (path === '/auth/me') return response(200, { mfa_required: pending, mfa_enabled: enabled });
    if (path === '/admin/users') return pending ? response(403, { error: 'access_denied' }) : response(200);
    throw new Error('Unexpected offline MFA fixture request');
  };
  const postJson = async (path, body, headers) => {
    calls.push({ path, method: 'POST' });
    if (path === '/auth/login') {
      pending = enabled && !remembered;
      return response(200, { mfa_required: pending }, true);
    }
    assert.ok(headers.cookie);
    assert.ok(headers['x-csrf-token']);
    if (path === '/auth/me/mfa/totp/begin') return response(200, { secret_base32: seed, digits: 6, period: 30 });
    if (path === '/auth/me/mfa/totp/confirm') {
      if (body.code === 'invalid') return response(400, { error: 'invalid_grant' });
      assert.match(body.code, /^\d{6}$/);
      enabled = true;
      return response(200, { mfa_enabled: true, backup_codes: initial }, true);
    }
    if (path === '/auth/mfa/verify') {
      if (body.code === 'invalid') return response(400, { error: 'invalid_grant' });
      assert.equal(body.code, initial[0]);
      assert.equal(body.remember_device, true);
      pending = false;
      remembered = true;
      return response(200, { success: true }, true);
    }
    if (path === '/auth/me/mfa/step-up') {
      if (body.code === initial[0]) return response(400, { error: 'invalid_grant' });
      if (body.code === initial[3] && regenerated)
        return response(retiredStatus, { error: retiredStatus === 400 ? 'invalid_grant' : 'server_error' });
      assert.equal(body.code, initial[1]);
      return response(200, { success: true }, true);
    }
    if (path === '/auth/me/mfa/backup-codes/regenerate') {
      assert.equal(body.code, initial[2]);
      regenerated = true;
      return response(200, { backup_codes: replacement }, true);
    }
    if (path === '/auth/me/mfa/disable') {
      assert.equal(body.code, replacement[0], 'Cleanup must retain the new proof before a failed negative probe');
      enabled = false;
      return response(200, { mfa_enabled: false });
    }
    if (path === '/auth/logout') {
      assert.equal(enabled, false);
      loggedOut = true;
      return response(200);
    }
    throw new Error('Unexpected offline MFA fixture action');
  };
  const step = async (name, operation) => {
    try { await operation(); steps.push({ name, status: 'passed' }); return true; }
    catch (error) { steps.push({ name, status: 'failed', reason: error.message }); return false; }
  };
  return { calls, steps, get enabled() { return enabled; }, get loggedOut() { return loggedOut; },
    args: { issuer, input: { administrator: { email: 'acceptance-admin@example.test', password: randomUUID() } },
      request, postJson, json, step } };
}

test('public MFA cleanup validates retired backup rejection and disables with the replacement proof', async () => {
  const f = fixture();
  const mfa = await publicMfa(f.args);
  await mfa.cleanup();
  assert.equal(f.steps.length, 4);
  assert.deepEqual(f.steps.filter(value => value.status === 'failed'), []);
  assert.equal(f.enabled, false);
  assert.equal(f.loggedOut, true);
});

test('a platform refusal cannot pass the retired-backup check or discard the cleanup proof', async () => {
  const f = fixture({ retiredStatus: 503 });
  const mfa = await publicMfa(f.args);
  await mfa.cleanup();
  const failures = f.steps.filter(value => value.status === 'failed');
  assert.equal(failures.length, 1);
  assert.equal(failures[0].name, 'mfa_backup_regeneration_and_retirement');
  assert.equal(failures[0].reason, 'Unexpected HTTP status 503; expected 400');
  assert.equal(f.steps.find(value => value.name === 'mfa_disable_and_session_cleanup').status, 'passed');
  assert.equal(f.enabled, false);
  assert.equal(f.loggedOut, true);
});
