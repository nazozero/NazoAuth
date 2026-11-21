// Offline stateful orchestration tests; no network or real credentials.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { publicRuntimeModules } from '../test-support/public-runtime-modules.mjs';
import { runPublicAcceptance } from '../test-support/public-acceptance.mjs';

const deviceModule = 'device_authorization';
const grantModule = 'jwt_bearer_grant';
const deviceGrant = 'urn:ietf:params:oauth:grant-type:device_code';
const jwtGrant = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
const path = '/admin/runtime-modules';

function fixture(options = {}) {
  const issuer = 'https://runtime-acceptance.example';
  const administrator = { user_id: randomUUID(), email: 'runtime-admin@example.test' };
  const deviceClient = { client_id: randomUUID(), scope: 'openid profile email offline_access', resource: 'resource://default' };
  const session = { cookie: '__Host-session=' + randomUUID(), csrf: randomUUID() };
  const foreignActor = randomUUID();
  const calls = [], steps = [], events = [], devices = new Map(), revoked = [], verified = [];
  const secrets = [session.cookie, session.csrf];
  const initialRevision = 10;
  let lostDisable = false, restoreRace = false, lostRestore = false, revokeFailed = false;
  let pendingDisableReads = 0, pendingRestoreReads = 0, pendingDrainReads = 0;
  let convergenceFailureArmed = false, convergenceFailureSent = false;
  const modules = new Map([deviceModule, grantModule].map(id => [id, {
    module_id: id, desired_state: 'enabled', resolved_enabled: true, actual_state: 'enabled',
    revision: initialRevision, transition_revision: initialRevision, applied_revision: initialRevision,
    dependencies: [], dependents: [], allowed_actions: ['disable'],
    disable_policy: id === deviceModule ? 'drain_stored_transactions:600s' : 'finish_executing_requests',
    drain_deadline: null, failure_code: null, updated_at: new Date().toISOString(),
  }]));
  if (options.initialDisabled) Object.assign(modules.get(deviceModule), {
    desired_state: 'disabled', resolved_enabled: false, actual_state: 'disabled', allowed_actions: ['enable'],
  });
  if (options.dependent) modules.get(deviceModule).dependents.push('unrelated-module');
  if (options.initialAppliedMissing) modules.get(deviceModule).applied_revision = null;
  const response = (status, body = {}) => ({ status, text: JSON.stringify(body), headers: new Headers() });
  const json = (value, expected = 200) => {
    assert.equal(value.status, expected);
    return JSON.parse(value.text);
  };
  const event = (module, before, reason, { actor = administrator.user_id, noop = false } = {}) => {
    const item = { event_id: randomUUID(), module_id: module.module_id,
      event_type: 'desired_state_changed', actor_id: actor, reason,
      before_state: before, after_state: module.desired_state, revision: module.revision,
      outcome_code: noop ? 'noop' : null, created_at: new Date().toISOString() };
    events.unshift(item);
    return item;
  };
  const foreignChange = module => {
    // A separate administrator toggled the module twice after our last read.
    module.revision += 2;
    event(module, 'enabled', 'unrelated operator update', { actor: foreignActor });
  };
  const perform = async (target, init = {}) => {
    assert.equal(new URL(target, issuer).origin, issuer);
    const method = init.method || 'GET';
    calls.push({ path: target.split('?')[0], method });
    const headers = init.headers || {};
    if (target.startsWith('/admin/') || target === '/auth/me') assert.equal(headers.cookie, session.cookie);
    if (target === '/auth/me') return response(200, { id: administrator.user_id, email: administrator.email,
      role: 'admin', admin_level: 2, mfa_enabled: true, mfa_required: false });
    if (target === path && method === 'GET') {
      if (convergenceFailureArmed && !convergenceFailureSent) {
        convergenceFailureSent = true;
        if (options.convergenceFailure === 'network') throw new Error('unsafe convergence detail ' + session.cookie);
        return response(503, { error: 'server_error' });
      }
      const items = [...modules.values()].map(item => ({ ...item }));
      if (pendingDisableReads > 0) {
        pendingDisableReads--;
        const item = items.find(item => item.module_id === grantModule);
        item.actual_state = 'draining';
        item.applied_revision = item.revision - 1;
        if (options.convergenceFailure) convergenceFailureArmed = true;
      }
      if (pendingRestoreReads > 0) {
        pendingRestoreReads--;
        const item = items.find(item => item.module_id === deviceModule);
        item.actual_state = 'starting';
        item.applied_revision = item.revision - 1;
      }
      if (pendingDrainReads > 0) {
        pendingDrainReads--;
        const item = items.find(item => item.module_id === deviceModule);
        item.actual_state = 'enabled';
        item.transition_revision = item.revision - 1;
      }
      return response(200, { items });
    }
    if (target === path + '/events?page=1&page_size=100') return response(200, {
      total: events.length, page: 1, page_size: 100, items: events.slice(0, 100),
    });
    if (target.startsWith(path + '/') && method === 'PATCH') {
      assert.equal(headers.origin, issuer);
      assert.equal(headers['x-csrf-token'], session.csrf);
      const payload = JSON.parse(init.body);
      assert.equal(payload.cascade, false);
      assert.match(payload.reason, /^public-runtime-[0-9a-f-]+ (?:device_authorization|jwt_bearer_grant) \d+$/);
      const module = modules.get(target.slice((path + '/').length));
      assert.ok(module);
      calls.at(-1).payload = payload;
      if (options.restoreRace && module.module_id === deviceModule && payload.desired_state === 'enabled' && !restoreRace) {
        restoreRace = true;
        foreignChange(module);
      }
      if (payload.expected_revision !== module.revision) return response(409, {
        error: 'revision_conflict', current_revision: module.revision,
      });
      const before = module.desired_state;
      const noop = before === payload.desired_state;
      if (!noop) {
        module.desired_state = payload.desired_state;
        module.revision++;
        module.resolved_enabled = payload.desired_state === 'enabled';
        module.actual_state = module.resolved_enabled ? 'enabled'
          : module.module_id === deviceModule ? 'draining' : 'disabled';
        module.transition_revision = module.revision;
        if (module.actual_state !== 'draining') module.applied_revision = module.revision;
        if (options.disabledAppliedStale && module.module_id === grantModule && !module.resolved_enabled)
          module.applied_revision = module.revision - 1;
        if (options.restoredAppliedMissing && module.module_id === deviceModule && module.resolved_enabled)
          module.applied_revision = null;
        if (module.module_id === grantModule && !module.resolved_enabled)
          pendingDisableReads = options.pendingDisableReads || 0;
        if (module.module_id === deviceModule && module.resolved_enabled)
          pendingRestoreReads = options.pendingRestoreReads || 0;
        if (module.module_id === deviceModule && !module.resolved_enabled)
          pendingDrainReads = options.pendingDrainReads || 0;
        module.drain_deadline = !module.resolved_enabled && module.module_id === deviceModule
          ? new Date(Date.now() + 600_000).toISOString() : null;
        module.allowed_actions = [module.resolved_enabled ? 'disable' : 'enable'];
        module.updated_at = new Date().toISOString();
      } else if (options.extendNoopDeadline) {
        module.drain_deadline = new Date(Date.parse(module.drain_deadline) + 60_000).toISOString();
      }
      const written = event(module, before, payload.reason, { noop });
      const reply = response(202, { module_id: module.module_id, desired_state: module.desired_state,
        revision: module.revision, actual_state: module.actual_state, status_url: path });
      if (module.module_id === deviceModule && payload.desired_state === 'disabled' && !noop && !lostDisable) {
        lostDisable = true;
        if (options.lostDisableEvent === 'actor') written.actor_id = foreignActor;
        if (options.lostDisableEvent === 'reason') written.reason = 'unrelated operation';
        if (options.lostDisableEvent === 'noop') written.outcome_code = 'noop';
        if (options.lostDisableEvent === 'before') written.before_state = 'disabled';
        if (options.foreignAfterDisable) foreignChange(module);
        if (options.disableFailure === 'network' || options.lostDisableEvent)
          throw new Error('unsafe transport detail ' + session.cookie);
        if (options.disableFailure === 'platform') return response(503, { error: 'server_error' });
      }
      if (module.module_id === deviceModule && payload.desired_state === 'enabled' && options.lostRestore && !lostRestore) {
        lostRestore = true;
        throw new Error('unsafe restore response ' + session.csrf);
      }
      return reply;
    }
    if (target === '/.well-known/openid-configuration') {
      const deviceEnabled = modules.get(deviceModule).desired_state === 'enabled';
      return response(200, { issuer, grant_types_supported: ['authorization_code',
        ...(deviceEnabled ? [deviceGrant] : []), ...(modules.get(grantModule).desired_state === 'enabled' ? [jwtGrant] : [])],
      ...(deviceEnabled ? { device_authorization_endpoint: issuer + '/device_authorization' } : {}) });
    }
    const form = new URLSearchParams(init.body);
    if (target === '/device_authorization') {
      assert.equal(form.get('client_id'), deviceClient.client_id);
      if (modules.get(deviceModule).desired_state !== 'enabled') return response(400, { error: 'invalid_request' });
      const value = { device_code: randomUUID(), user_code: randomUUID(), interval: 5, expires_in: 600 };
      secrets.push(value.device_code, value.user_code);
      devices.set(value.user_code, { value, state: 'pending' });
      return response(200, value);
    }
    if (target.startsWith('/device/verification?')) {
      const userCode = new URL(target, issuer).searchParams.get('user_code');
      assert.equal(headers.cookie, session.cookie);
      assert.ok(devices.has(userCode));
      return response(200, { user_code: userCode, request: { client_id: deviceClient.client_id }, csrf_token: session.csrf });
    }
    if (target === '/device/decision') {
      assert.equal(headers.cookie, session.cookie);
      assert.equal(form.get('csrf_token'), session.csrf);
      const device = devices.get(form.get('user_code'));
      assert.ok(device);
      if (device.state !== 'pending') return response(400, { error: 'invalid_request' });
      device.state = form.get('decision') === 'approve' ? 'approved' : 'denied';
      return response(200);
    }
    if (target === '/token') {
      assert.equal(form.get('grant_type'), deviceGrant);
      assert.equal(form.get('client_id'), deviceClient.client_id);
      const device = [...devices.values()].find(item => item.value.device_code === form.get('device_code'));
      assert.ok(device);
      if (device.state === 'pending') return response(400, { error: 'authorization_pending' });
      if (device.state === 'consumed') return response(400, { error: 'invalid_grant' });
      assert.equal(device.state, 'approved');
      device.state = 'consumed';
      const tokens = { access_token: randomUUID(), refresh_token: randomUUID(), id_token: randomUUID() };
      secrets.push(...Object.values(tokens));
      return response(200, tokens);
    }
    if (target === '/userinfo') {
      assert.match(headers.authorization, /^Bearer /);
      return response(200, { sub: administrator.user_id, email: administrator.email });
    }
    if (target === '/revoke') {
      assert.equal(form.get('client_id'), deviceClient.client_id);
      assert.ok(['refresh_token', 'access_token'].includes(form.get('token_type_hint')));
      if (options.revokeFailure && !revokeFailed) {
        revokeFailed = true;
        return response(503, { error: 'server_error' });
      }
      revoked.push(form.get('token'));
      return response(200);
    }
    throw new Error('Unexpected offline runtime fixture request');
  };
  const postForm = (target, fields, headers = {}) => perform(target, { method: 'POST',
    headers: { origin: issuer, ...headers }, body: new URLSearchParams(fields).toString() });
  const authenticatedForm = (target, client, fields) => {
    assert.equal(client, deviceClient, 'The existing authenticated form helper receives the selected client');
    return postForm(target, { ...fields, client_id: client.client_id });
  };
  const step = async (name, operation) => {
    try { await operation(); steps.push({ name, status: 'passed' }); return true; }
    catch (error) { steps.push({ name, status: 'failed', reason: error.message }); return false; }
  };
  const verifyJwt = (token, keys, currentIssuer, audience) => {
    assert.ok(secrets.includes(token));
    assert.equal(currentIssuer, issuer);
    assert.ok([deviceClient.client_id, deviceClient.resource].includes(audience));
    verified.push(token);
    return { sub: administrator.user_id };
  };
  return { modules, calls, steps, events, devices, revoked, verified, secrets,
    args: { issuer, input: { runtime_modules: { expected_issuer: issuer }, administrator, device_client: deviceClient },
      request: perform, postForm, authenticatedForm, json, step, session, signingKeys: [], verifyJwt } };
}

async function run(f) {
  const result = await publicRuntimeModules(f.args);
  assert.equal(result.requests, f.calls.length);
  assert.ok(result.requests <= 80);
  const output = JSON.stringify({ result, steps: f.steps });
  for (const secret of f.secrets) assert.equal(output.includes(secret), false, 'Secrets must not enter public results');
  return result;
}

test('runtime acceptance drains existing Device work, rejects admission and stale CAS, then restores both policies', async () => {
  const f = fixture();
  const result = await run(f);
  assert.equal(result.passed, true);
  assert.equal(result.operator_intervention_required, false);
  assert.equal(f.steps.length, 5);
  assert.ok(f.steps.every(step => step.status === 'passed'));
  assert.equal(result.coverage.device.same_state_noop_deadline_preserved, true);
  assert.equal(result.coverage.device.existing_transaction_completed, true);
  assert.equal(result.coverage.finish_executing_requests.metadata_disabled, true);
  assert.equal(result.coverage.device.applied_revision, result.coverage.device.reenabled_revision);
  assert.equal(result.coverage.finish_executing_requests.disabled_applied_revision,
    result.coverage.finish_executing_requests.disabled_revision);
  assert.ok(result.restoration.every(item => item.applied_revision >= item.revision));
  assert.ok(result.convergence_checks.every(check => check.attempts === 1 && check.converged));
  assert.equal(f.verified.length, 2);
  assert.equal(f.revoked.length, 2);
  for (const module of f.modules.values()) {
    assert.equal(module.desired_state, 'enabled');
    assert.equal(module.revision, 12);
    assert.equal(module.drain_deadline, null);
  }
  assert.equal(result.events.length, 4, 'Both disable and restore writes retain their attributed events');
  assert.ok([...f.devices.values()].every(item => item.state === 'consumed' || item.state === 'denied'));
});

for (const failure of ['network', 'platform']) {
  test(`a ${failure} failure after committed disable recovers ownership from the non-noop actor/reason event`, async () => {
    const f = fixture({ disableFailure: failure });
    const result = await run(f);
    assert.equal(result.passed, false, 'Recovery does not hide the failed protocol step');
    assert.equal(result.operator_intervention_required, false);
    assert.equal(result.coverage.lost_response_ownership_recovered, true);
    assert.ok(result.operations[0].reason.startsWith(result.run_id));
    assert.equal(result.operations[0].ownership_confirmed_by_event, true);
    assert.equal(f.modules.get(deviceModule).desired_state, 'enabled');
    assert.equal(f.modules.get(deviceModule).revision, 12);
    assert.equal(f.modules.get(grantModule).revision, 10);
    assert.equal(f.steps.find(step => step.name === 'runtime_modules_restore_original_state').status, 'passed');
    assert.equal([...f.devices.values()][0].state, 'denied');
  });
}

for (const mismatch of ['actor', 'reason', 'noop', 'before']) {
  test(`an unacknowledged disable with a mismatched ${mismatch} event cannot authorize restoration`, async () => {
    const f = fixture({ lostDisableEvent: mismatch });
    const result = await run(f);
    assert.equal(result.passed, false);
    assert.equal(result.operator_intervention_required, true);
    assert.equal(f.modules.get(deviceModule).desired_state, 'disabled');
    assert.equal(f.calls.filter(call => call.method === 'PATCH' && call.payload.desired_state === 'enabled').length, 0);
    assert.equal(f.steps.find(step => step.name === 'runtime_modules_restore_original_state').status, 'failed');
  });
}

test('a newer independent revision is left untouched after an acknowledged disable', async () => {
  const f = fixture({ foreignAfterDisable: true });
  const result = await run(f);
  assert.equal(result.operator_intervention_required, true);
  assert.equal(f.modules.get(deviceModule).revision, 13);
  assert.equal(f.modules.get(deviceModule).desired_state, 'disabled');
  assert.equal(f.calls.filter(call => call.method === 'PATCH' && call.payload.desired_state === 'enabled').length, 0);
});

test('a restore CAS conflict is never retried over another administrator revision and token cleanup still runs', async () => {
  const f = fixture({ restoreRace: true });
  const result = await run(f);
  assert.equal(result.passed, false);
  assert.equal(result.operator_intervention_required, true);
  const restores = f.calls.filter(call => call.method === 'PATCH' && call.payload.desired_state === 'enabled');
  assert.equal(restores.length, 1);
  assert.equal(restores[0].payload.expected_revision, 11);
  assert.equal(f.modules.get(deviceModule).revision, 13);
  assert.equal(f.revoked.length, 2);
});

test('a lost restore response is confirmed through fresh state and its own changed-state event', async () => {
  const f = fixture({ lostRestore: true });
  const result = await run(f);
  assert.equal(result.passed, true);
  assert.equal(result.operator_intervention_required, false);
  assert.equal(result.coverage.lost_response_ownership_recovered, true);
  assert.equal(f.modules.get(deviceModule).revision, 12);
  assert.equal(f.calls.filter(call => call.method === 'PATCH' && call.path.endsWith(deviceModule)
    && call.payload.desired_state === 'enabled').length, 1);
});

test('a repeated disable that extends its deadline fails acceptance and still restores the original state', async () => {
  const f = fixture({ extendNoopDeadline: true });
  const result = await run(f);
  assert.equal(result.passed, false);
  assert.equal(result.operator_intervention_required, false);
  assert.equal(f.modules.get(deviceModule).desired_state, 'enabled');
  assert.match(f.steps.find(step => step.name === 'runtime_device_drain_existing_transaction_and_cas').reason, /extended the drain deadline/);
});

test('failed token cleanup remains a failed step and does not prevent the other token revocation', async () => {
  const f = fixture({ revokeFailure: true });
  const result = await run(f);
  assert.equal(result.passed, false);
  assert.equal(result.operator_intervention_required, true);
  assert.equal(result.coverage.transaction_cleanup.issued_tokens, 2);
  assert.equal(result.coverage.transaction_cleanup.revoked_tokens, 1);
  assert.equal(f.calls.filter(call => call.path === '/revoke').length, 2);
  assert.ok([...f.modules.values()].every(module => module.desired_state === 'enabled'));
});

test('a disabled view with an older applied revision does not acknowledge completion', async () => {
  const f = fixture({ disabledAppliedStale: true });
  const result = await run(f);
  assert.equal(result.passed, false);
  assert.equal(result.operator_intervention_required, false);
  assert.match(f.steps.find(step => step.name === 'runtime_inflight_module_metadata_disable_and_restore').reason,
    /applied revision/);
  assert.equal(result.coverage.finish_executing_requests, undefined);
  assert.equal(result.convergence_checks.find(check => check.module_id === grantModule
    && check.desired_state === 'disabled').attempts, 3);
  assert.ok([...f.modules.values()].every(module => module.desired_state === 'enabled'
    && module.applied_revision >= module.revision));
});

test('successful views can poll at most three times for the same accepted revision without another CAS', async () => {
  const f = fixture({ pendingDrainReads: 2, pendingDisableReads: 2, pendingRestoreReads: 2 });
  const result = await run(f);
  assert.equal(result.passed, true);
  assert.ok(result.convergence_checks.every(check => check.attempts <= 3 && check.converged));
  assert.equal(result.convergence_checks.filter(check => check.attempts === 3).length, 3);
  assert.equal(f.calls.filter(call => call.method === 'PATCH').length, 6,
    'Convergence polling must not send another state mutation');
  assert.equal(f.revoked.length, 2);
  assert.ok(result.requests < 56, 'Normal convergence leaves the reserved cleanup budget intact');
});

for (const failure of ['network', 'platform']) {
  test(`a ${failure} failure during convergence ends that check without retrying the error`, async () => {
    const f = fixture({ pendingDisableReads: 1, convergenceFailure: failure });
    const result = await run(f);
    const check = result.convergence_checks.find(check => check.module_id === grantModule
      && check.desired_state === 'disabled');
    assert.equal(result.passed, false);
    assert.equal(check.attempts, 2);
    assert.equal(check.converged, false);
    assert.equal(result.operator_intervention_required, false, 'Finally performs a separate owned restoration');
    assert.ok([...f.modules.values()].every(module => module.desired_state === 'enabled'));
    assert.equal(f.revoked.length, 2);
  });
}

test('an enabled view without an applied revision cannot claim restoration or hide cleanup failure', async () => {
  const f = fixture({ restoredAppliedMissing: true });
  const result = await run(f);
  assert.equal(result.passed, false);
  assert.equal(result.operator_intervention_required, true);
  assert.equal(f.modules.get(deviceModule).desired_state, 'enabled');
  assert.equal(f.modules.get(deviceModule).actual_state, 'enabled');
  assert.equal(f.modules.get(deviceModule).applied_revision, null);
  assert.equal(result.restoration.find(item => item.module_id === deviceModule).restored, false);
  assert.equal(f.steps.find(step => step.name === 'runtime_modules_restore_original_state').status, 'failed');
  assert.equal(f.calls.filter(call => call.method === 'PATCH' && call.path.endsWith(deviceModule)
    && call.payload.desired_state === 'enabled').length, 1, 'Unconfirmed application does not authorize another CAS');
  assert.equal(f.revoked.length, 2, 'Token cleanup still runs when restored projection is unconfirmed');
});

for (const options of [{ initialDisabled: true }, { dependent: true }, { initialAppliedMissing: true }]) {
  test(`initial ${Object.keys(options)[0]} state is rejected before any protocol transaction or mutation`, async () => {
    const f = fixture(options);
    const result = await run(f);
    assert.equal(result.passed, false);
    assert.equal(f.calls.some(call => call.method !== 'GET'), false);
    assert.equal(f.devices.size, 0);
  });
}

test('runtime mutations require a matching explicit issuer opt-in before any HTTP request', async () => {
  const f = fixture();
  f.args.input.runtime_modules.expected_issuer = 'https://different.example';
  const result = await run(f);
  assert.equal(result.passed, false);
  assert.equal(result.requests, 0);
});

test('the main runner rejects incomplete runtime opt-in before any HTTP request', async () => {
  let calls = 0;
  const issuer = 'https://runtime-acceptance.example';
  await assert.rejects(runPublicAcceptance({ issuer, runtime_modules: { expected_issuer: issuer } },
    async () => { calls++; throw new Error('Unexpected network attempt'); }),
  /Missing explicit runtime module acceptance input/);
  assert.equal(calls, 0);
});
