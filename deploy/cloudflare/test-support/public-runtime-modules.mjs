// Explicit public acceptance only. Importing this module never makes requests.
// The caller supplies the existing redacting transport, client authentication,
// JWT verifier and an administrator session with recent interactive MFA.
import { randomUUID } from 'node:crypto';

const deviceModule = 'device_authorization';
const grantModule = 'jwt_bearer_grant';
const deviceGrant = 'urn:ietf:params:oauth:grant-type:device_code';
const jwtGrant = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
const selectedModules = [deviceModule, grantModule];
const managementPath = '/admin/runtime-modules';
const metadataPath = '/.well-known/openid-configuration';
const ensure = (condition, message) => {
  if (!condition) throw new Error('Acceptance runtime modules: ' + message);
};
const revision = value => Number.isSafeInteger(value) && value > 0;
const appliedAtLeast = (item, accepted = item.revision) => revision(item.applied_revision)
  && item.applied_revision >= accepted;

/**
 * Opt in with runtime_modules: { expected_issuer: input.issuer }. Both selected
 * modules must originally be enabled and have no dependents. At most 80 HTTP
 * calls are made, with 24 reserved for finally restoration and token cleanup.
 * Lost mutation responses require fresh state plus the matching non-noop audit
 * event before a restoration CAS; a concurrent revision is never overwritten.
 */
export async function publicRuntimeModules({
  issuer, input, request, postForm, authenticatedForm, json, step,
  session, signingKeys, verifyJwt,
}) {
  ensure(typeof step === 'function', 'Missing acceptance step recorder');
  const marker = 'public-runtime-' + randomUUID();
  const states = new Map();
  const devices = [];
  const tokens = [];
  let cleanup = false;
  let calls = 0;
  let sequence = 0;
  let originalMetadata;
  const result = { run_id: marker, passed: true, request_budget: 80, requests: 0, original: [],
    operations: [], transitions: [], events: [], convergence_checks: [], coverage: {}, restoration: [],
    operator_intervention_required: false };
  const runStep = async (name, operation) => {
    const passed = await step(name, async () => {
      try { await operation(); }
      catch (error) {
        if (error instanceof Error && error.message.startsWith('Acceptance runtime modules: ')) throw error;
        throw new Error('Acceptance runtime modules: Request or verification failed; private details omitted');
      }
    });
    if (!passed) result.passed = false;
    return passed;
  };
  const call = async operation => {
    ensure(calls < (cleanup ? 80 : 56), 'HTTP request budget exhausted');
    calls++;
    return operation();
  };
  const get = (path, init) => call(() => request(path, init));
  const form = (path, fields, headers) => call(() => postForm(path, fields, headers));
  const clientForm = (path, fields) => call(() => authenticatedForm(path, input.device_client, fields));
  const body = (response, expected = 200) => {
    ensure(response.status === expected, `Unexpected HTTP status ${response.status}; expected ${expected}`);
    return json(response, expected);
  };
  const headers = () => ({ origin: issuer, cookie: session.cookie, 'x-csrf-token': session.csrf });
  const list = async () => {
    const value = body(await get(managementPath, { headers: headers() }));
    ensure(Array.isArray(value.items) && value.items.length > 0
      && new Set(value.items.map(item => item.module_id)).size === value.items.length,
    'Invalid runtime module list');
    for (const id of selectedModules) {
      const item = value.items.find(item => item.module_id === id);
      ensure(item && revision(item.revision) && ['enabled', 'disabled'].includes(item.desired_state)
        && ['enabled', 'disabled', 'draining', 'starting', 'failed'].includes(item.actual_state)
        && Array.isArray(item.dependents) && Array.isArray(item.allowed_actions),
      'Invalid selected runtime module projection');
    }
    return new Map(value.items.map(item => [item.module_id, item]));
  };
  const events = async () => {
    const value = body(await get(managementPath + '/events?page=1&page_size=100', { headers: headers() }));
    ensure(Array.isArray(value.items) && Number.isSafeInteger(value.total)
      && value.total >= value.items.length && value.page === 1 && value.page_size === 100,
    'Invalid runtime event page');
    return value.items;
  };
  const metadata = async () => {
    const value = body(await get(metadataPath));
    ensure(value.issuer === issuer && Array.isArray(value.grant_types_supported), 'Invalid runtime discovery');
    return {
      device: value.grant_types_supported.includes(deviceGrant),
      device_endpoint: value.device_authorization_endpoint ?? null,
      jwt_bearer: value.grant_types_supported.includes(jwtGrant),
    };
  };
  const eventFor = (items, state, attempt, currentRevision) => items.find(event =>
    event.module_id === state.id && event.event_type === 'desired_state_changed'
    && event.actor_id === input.administrator.user_id && event.reason === attempt.reason
    && event.revision === currentRevision && event.before_state === attempt.before
    && event.after_state === attempt.mode && event.outcome_code !== 'noop'
    && attempt.before !== attempt.mode && currentRevision === attempt.expected + 1);
  const rememberEvent = event => {
    if (result.events.some(item => item.event_id === event.event_id)) return;
    result.events.push({ event_id: event.event_id, module_id: event.module_id,
      event_type: event.event_type, revision: event.revision, before_state: event.before_state,
      after_state: event.after_state, outcome_code: event.outcome_code,
      actor_and_reason_match_this_run: true });
  };
  const owns = async (state, current) => {
    if (state.owned?.revision === current.revision && state.owned.mode === current.desired_state) return true;
    const candidates = state.attempts.filter(attempt => attempt.mode === current.desired_state
      && attempt.expected + 1 === current.revision && attempt.before !== attempt.mode);
    if (!candidates.length) return false;
    const page = await events();
    for (const attempt of candidates) {
      const event = eventFor(page, state, attempt, current.revision);
      if (!event) continue;
      rememberEvent(event);
      state.owned = { revision: current.revision, mode: current.desired_state };
      attempt.proven_revision = current.revision;
      attempt.record.ownership_confirmed_by_event = true;
      attempt.record.observed_revision = current.revision;
      result.coverage.lost_response_ownership_recovered = true;
      return true;
    }
    return false;
  };
  const mutate = async (state, mode, expected = state.owned?.revision ?? state.original.revision, expectedStatus = 202) => {
    ensure(revision(expected) && expected < Number.MAX_SAFE_INTEGER, 'Revision cannot be represented safely');
    const before = state.owned?.mode ?? state.original.desired_state;
    const attempt = { expected, mode, before, reason: marker + ' ' + state.id + ' ' + (++sequence) };
    attempt.record = { module_id: state.id, desired_state: mode, expected_revision: expected,
      reason: attempt.reason, acknowledged: false };
    result.operations.push(attempt.record);
    state.attempts.push(attempt);
    const response = await get(managementPath + '/' + state.id, { method: 'PATCH', headers: {
      ...headers(), 'content-type': 'application/json',
    }, body: JSON.stringify({ desired_state: mode, expected_revision: expected, reason: attempt.reason, cascade: false }) });
    const value = body(response, expectedStatus);
    if (expectedStatus === 409) {
      ensure(value.error === 'revision_conflict' && value.current_revision === state.owned?.revision,
        'Stale revision did not return the current CAS conflict');
      attempt.record.rejected_revision_conflict = true;
      return value;
    }
    ensure(value.module_id === state.id && value.desired_state === mode
      && value.revision === expected + (before === mode ? 0 : 1)
      && value.status_url === managementPath, 'Invalid desired-state acknowledgement');
    state.owned = { revision: value.revision, mode };
    attempt.acknowledged_revision = value.revision;
    attempt.record.acknowledged = true;
    attempt.record.accepted_revision = value.revision;
    result.transitions.push({ module_id: state.id, desired_state: mode, revision: value.revision,
      no_op: before === mode, acknowledged: true });
    return value;
  };
  const intervention = (state, current) => {
    result.operator_intervention_required = true;
    result.restoration.push({ module_id: state.id, restored: false,
      current_revision: current?.revision ?? null, original_desired_state: state.original.desired_state,
      reason: 'ownership_or_restoration_unconfirmed_no_overwrite' });
    throw new Error('Acceptance runtime modules: Restoration ownership is unconfirmed; operator intervention required');
  };
  const restoredView = async state => {
    const check = { module_id: state.id, desired_state: state.original.desired_state,
      expected_revision: null, attempts: 0, converged: false };
    result.convergence_checks.push(check);
    for (let attempt = 1; attempt <= 3; attempt++) {
      check.attempts = attempt;
      const current = (await list()).get(state.id);
      const unchanged = current.revision === state.original.revision
        && current.desired_state === state.original.desired_state;
      if (current.desired_state !== state.original.desired_state || (!unchanged && !await owns(state, current))
        || (check.expected_revision !== null && current.revision !== check.expected_revision))
        return intervention(state, current);
      check.expected_revision = current.revision;
      check.actual_state = current.actual_state;
      check.applied_revision = current.applied_revision ?? null;
      if (current.actual_state === 'enabled' && current.resolved_enabled === true
        && current.drain_deadline == null && appliedAtLeast(current)) {
        check.converged = true;
        return current;
      }
    }
    throw new Error('Acceptance runtime modules: Restored module has not confirmed its applied revision and resumed admission');
  };
  const transitionView = async (state, accepted, expectedActual, predicate, failure) => {
    const check = { module_id: state.id, desired_state: accepted.desired_state,
      expected_revision: accepted.revision, expected_actual_state: expectedActual, attempts: 0, converged: false };
    result.convergence_checks.push(check);
    for (let attempt = 1; attempt <= 3; attempt++) {
      check.attempts = attempt;
      const current = (await list()).get(state.id);
      ensure(current.desired_state === accepted.desired_state && current.revision === accepted.revision,
        'Desired revision changed while observing transition; no retry or overwrite');
      check.actual_state = current.actual_state;
      check.applied_revision = current.applied_revision ?? null;
      if (current.actual_state === expectedActual && predicate(current)) {
        check.converged = true;
        return current;
      }
    }
    throw new Error('Acceptance runtime modules: ' + failure);
  };
  const restore = async state => {
    const current = (await list()).get(state.id);
    if (current.desired_state === state.original.desired_state) return restoredView(state);
    if (!await owns(state, current)) return intervention(state, current);
    try { await mutate(state, state.original.desired_state, current.revision); }
    catch {
      // A timeout or platform error may follow a committed CAS. Fresh state and
      // the operation's non-noop audit event resolve ownership without guessing.
      const observed = (await list()).get(state.id);
      if (observed.desired_state !== state.original.desired_state || !await owns(state, observed))
        return intervention(state, observed);
    }
    return restoredView(state);
  };
  const createDevice = async (expected = 200) => {
    const response = await clientForm('/device_authorization', {
      scope: input.device_client.scope || 'openid profile email offline_access',
      resource: input.device_client.resource || 'resource://default',
    });
    // Track an unexpectedly admitted transaction before the assertion fails so
    // finally can deny this run's transaction through the normal protocol.
    let device;
    if (response.status === 200) {
      device = body(response);
      ensure(typeof device.device_code === 'string' && typeof device.user_code === 'string',
        'Missing Device transaction identifiers');
      devices.push({ value: device, pending: true });
    }
    const value = body(response, expected);
    if (expected === 400) ensure(value.error === 'invalid_request', 'Disabled module admitted a new Device transaction');
    return device;
  };
  const decision = (device, value) => form('/device/decision', {
    user_code: device.user_code, decision: value, csrf_token: session.csrf,
  }, { cookie: session.cookie });
  const poll = device => clientForm('/token', { grant_type: deviceGrant, device_code: device.device_code });

  const ready = await runStep('runtime_modules_administrator_state_and_events', async () => {
    const origin = new URL(issuer);
    ensure(input.runtime_modules?.expected_issuer === issuer && origin.origin === issuer
      && origin.protocol === 'https:',
      'Explicit runtime issuer opt-in is required');
    ensure(input.administrator?.user_id && input.administrator?.email && input.device_client?.client_id
      && session?.cookie && session?.csrf && typeof request === 'function' && typeof postForm === 'function'
      && typeof authenticatedForm === 'function' && typeof verifyJwt === 'function' && typeof json === 'function',
    'Missing dedicated administrator or acceptance dependencies');
    const administrator = body(await get('/auth/me', { headers: headers() }));
    ensure(administrator.id === input.administrator.user_id && administrator.email === input.administrator.email
      && administrator.role === 'admin' && administrator.admin_level >= 2
      && administrator.mfa_enabled === true && administrator.mfa_required === false,
    'Session is not the dedicated MFA administrator');
    const initial = await list();
    for (const id of selectedModules) {
      const item = initial.get(id);
      ensure(item.desired_state === 'enabled' && item.actual_state === 'enabled'
        && item.resolved_enabled === true && item.dependents.length === 0
        && item.allowed_actions.includes('disable') && item.drain_deadline == null && appliedAtLeast(item),
      'Selected module must originally be enabled with its applied revision confirmed and without dependents');
    }
    ensure(/^drain_stored_transactions:[1-9][0-9]*s$/.test(initial.get(deviceModule).disable_policy),
      'Device module does not expose its stored-transaction drain policy');
    ensure(initial.get(grantModule).disable_policy === 'finish_executing_requests',
      'JWT bearer module does not expose its in-flight request policy');
    await events();
    originalMetadata = await metadata();
    ensure(originalMetadata.device && originalMetadata.device_endpoint === issuer + '/device_authorization'
      && originalMetadata.jwt_bearer, 'Initial metadata does not advertise the selected modules');
    for (const id of selectedModules) {
      const original = initial.get(id);
      states.set(id, { id, original, owned: null, attempts: [] });
      result.original.push({ module_id: id, desired_state: original.desired_state,
        revision: original.revision, disable_policy: original.disable_policy });
    }
  });
  if (!ready) { result.requests = calls; return result; }

  try {
    const devicePassed = await runStep('runtime_device_drain_existing_transaction_and_cas', async () => {
      const state = states.get(deviceModule);
      const device = await createDevice();
      ensure(body(await poll(device), 400).error === 'authorization_pending', 'Device transaction was not pending before disable');
      const disabled = await mutate(state, 'disabled');
      const draining = await transitionView(state, disabled, 'draining', view =>
        view.resolved_enabled === false && view.transition_revision === disabled.revision,
      'Existing Device transaction did not start its bounded drain');
      ensure(Number.isFinite(Date.parse(draining.drain_deadline)) && Date.parse(draining.drain_deadline) > Date.now(),
      'Existing Device transaction did not retain a bounded drain');
      const deadline = draining.drain_deadline;
      const hidden = await metadata();
      ensure(!hidden.device && hidden.device_endpoint === null && hidden.jwt_bearer,
        'Disabled Device capability remained in current metadata');
      await createDevice(400);
      const repeated = await mutate(state, 'disabled');
      const unchanged = (await list()).get(deviceModule);
      ensure(repeated.revision === disabled.revision && unchanged.revision === disabled.revision
        && unchanged.drain_deadline === deadline, 'Repeated disable changed revision or extended the drain deadline');
      await mutate(state, 'disabled', state.original.revision, 409);
      const history = await events();
      const disableAttempt = state.attempts[0];
      const changed = eventFor(history, state, disableAttempt, disabled.revision);
      ensure(changed, 'Desired-state change audit event is missing');
      rememberEvent(changed);
      ensure(history.some(event => event.module_id === state.id && event.event_type === 'desired_state_changed'
        && event.actor_id === input.administrator.user_id && event.reason === state.attempts[1].reason
        && event.revision === disabled.revision && event.outcome_code === 'noop'), 'Repeated disable did not record a no-op event');
      const view = body(await get('/device/verification?' + new URLSearchParams({ user_code: device.user_code }), {
        headers: { cookie: session.cookie },
      }));
      ensure(view.user_code === device.user_code && view.request?.client_id === input.device_client.client_id
        && view.csrf_token === session.csrf, 'Existing Device verification was not available while draining');
      ensure((await decision(device, 'approve')).status === 200, 'Existing Device approval failed while draining');
      const token = body(await poll(device));
      devices.find(item => item.value === device).pending = false;
      for (const field of ['refresh_token', 'access_token']) {
        if (typeof token[field] === 'string' && token[field]) tokens.push({ token: token[field], hint: field });
      }
      const identity = verifyJwt(token.id_token, signingKeys, issuer, input.device_client.client_id);
      verifyJwt(token.access_token, signingKeys, issuer, input.device_client.resource || 'resource://default');
      const user = body(await get('/userinfo', { headers: { authorization: 'Bearer ' + token.access_token } }));
      ensure(user.sub === identity.sub && user.email === input.administrator.email,
        'Drained Device grant belongs to a different subject');
      const reenabled = await restore(state);
      const restored = await metadata();
      ensure(restored.device && restored.device_endpoint === originalMetadata.device_endpoint,
        'Device metadata did not return after reenable');
      ensure(body(await poll(device), 400).error === 'invalid_grant', 'Consumed Device transaction accepted a replay');
      const admitted = await createDevice();
      ensure((await decision(admitted, 'deny')).status === 200, 'New Device transaction could not be denied after reenable');
      devices.find(item => item.value === admitted).pending = false;
      result.coverage.device = { disable_policy: state.original.disable_policy,
        drain_deadline: deadline, new_admission_rejected: true, existing_transaction_completed: true,
        jwt_signatures_verified: 2, same_state_noop_deadline_preserved: true,
        stale_revision_rejected: true, reenabled_admission: true,
        reenabled_revision: reenabled.revision, applied_revision: reenabled.applied_revision };
    });
    if (devicePassed) await runStep('runtime_inflight_module_metadata_disable_and_restore', async () => {
      const state = states.get(grantModule);
      const accepted = await mutate(state, 'disabled');
      const disabled = await transitionView(state, accepted, 'disabled', view =>
        view.resolved_enabled === false && appliedAtLeast(view, accepted.revision),
      'In-flight module did not confirm its applied revision and finish disabling');
      const hidden = await metadata();
      ensure(!hidden.jwt_bearer && hidden.device, 'JWT bearer metadata did not follow its disabled state');
      const reenabled = await restore(state);
      ensure((await metadata()).jwt_bearer, 'JWT bearer metadata did not return after reenable');
      result.coverage.finish_executing_requests = { module_id: grantModule, metadata_disabled: true, metadata_restored: true,
        disabled_revision: accepted.revision, disabled_applied_revision: disabled.applied_revision,
        reenabled_revision: reenabled.revision, applied_revision: reenabled.applied_revision };
    });
  } finally {
    cleanup = true;
    await runStep('runtime_modules_restore_original_state', async () => {
      let failed = false;
      for (const state of [...states.values()].reverse()) {
        try {
          const restored = await restore(state);
          result.restoration.push({ module_id: state.id, restored: true, desired_state: restored.desired_state,
            revision: restored.revision, applied_revision: restored.applied_revision, actual_state: restored.actual_state });
        } catch {
          failed = true;
          result.operator_intervention_required = true;
          if (!result.restoration.some(item => item.module_id === state.id && !item.restored))
            result.restoration.push({ module_id: state.id, restored: false, reason: 'restoration_unconfirmed' });
        }
      }
      if (!failed) {
        const finalMetadata = await metadata();
        if (finalMetadata.device !== originalMetadata.device || finalMetadata.device_endpoint !== originalMetadata.device_endpoint
          || finalMetadata.jwt_bearer !== originalMetadata.jwt_bearer) {
          result.operator_intervention_required = true;
          throw new Error('Acceptance runtime modules: Final metadata differs from the saved initial state');
        }
        const history = await events();
        for (const state of states.values()) {
          for (const attempt of state.attempts.filter(attempt => attempt.before !== attempt.mode
            && (attempt.acknowledged_revision || attempt.proven_revision))) {
            const event = eventFor(history, state, attempt, attempt.acknowledged_revision ?? attempt.proven_revision);
            ensure(event, 'Confirmed desired-state mutation is absent from the event page');
            rememberEvent(event);
          }
        }
      }
      ensure(!failed, 'Restoration was not confirmed for every selected module; operator intervention required');
    });
    await runStep('runtime_modules_transaction_and_token_cleanup', async () => {
      let failed = false;
      for (const item of devices.filter(item => item.pending)) {
        try {
          ensure((await decision(item.value, 'deny')).status === 200, 'Pending Device cleanup was not acknowledged');
          item.pending = false;
        } catch { failed = true; }
      }
      for (const item of tokens) {
        try {
          ensure((await clientForm('/revoke', { token: item.token, token_type_hint: item.hint })).status === 200,
            'Issued Device token cleanup was not acknowledged');
          item.revoked = true;
        } catch { failed = true; }
      }
      result.coverage.transaction_cleanup = { pending_devices: devices.filter(item => item.pending).length,
        issued_tokens: tokens.length, revoked_tokens: tokens.filter(item => item.revoked).length };
      if (failed) result.operator_intervention_required = true;
      ensure(!failed, 'Transaction or token cleanup failed; inspect recorded HTTP outcomes');
    });
    result.requests = calls;
  }
  return result;
}
