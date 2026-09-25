import http from 'k6/http';
import { check, fail, sleep } from 'k6';
import exec from 'k6/execution';
import { SharedArray } from 'k6/data';
import { Trend, Counter } from 'k6/metrics';
import encoding from 'k6/encoding';
import {
  bucketCount, bucketIndexAt, capIterMs, contractFromMetrics,
  createMeasurementClock, parseDurationMs, COHORT_MEASURE,
} from './measurement_clock.js';
import {
  SUBJECT_KINDS, adoptSubjectAccessToken, classifyMint,
  subjectCounters,
} from './subject_state.js';

const BASE_URL = (__ENV.BASE_URL || 'http://nazoauth:8000').replace(/\/$/, '');
const secrets = JSON.parse(open('/perf-state/secrets.json'));
const vectors = new SharedArray('flow-vectors', () => JSON.parse(open('/perf-state/vectors.json')));
const scenario = __ENV.PERF_SCENARIO || 'token_client_credentials';
const duration = __ENV.PERF_DURATION || '20s';
const executor = __ENV.PERF_EXECUTOR || '';
const rate = Number(__ENV.PERF_RATE || '0');
const timeUnit = __ENV.PERF_TIME_UNIT || '1s';
const vus = Number(__ENV.PERF_VUS || '8');
const flowVus = Number(__ENV.PERF_FLOW_VUS || __ENV.PERF_VUS || '8');
const preAllocatedVus = Number(__ENV.PERF_PRE_ALLOCATED_VUS || __ENV.PERF_FLOW_VUS || __ENV.PERF_VUS || '8');
const maxVus = Number(__ENV.PERF_MAX_VUS || Math.max(preAllocatedVus * 2, preAllocatedVus));
const iterations = Number(__ENV.PERF_ITERATIONS || '50');
const testStartedAtMs = Date.now();
// Tenant routing is Host-header based; PERF_TENANT_HOST pins requests to the
// seeded tenant while BASE_URL selects the transport address.
const TENANT_HOST = __ENV.PERF_TENANT_HOST || '';
const scenarioSteps = {
  token_client_credentials: ['token_client_credentials'],
  mtls_client_credentials: ['mtls_client_credentials'],
  par_signed_request_object: ['par_oidc'],
  metadata_jwks: ['metadata', 'jwks'],
  token_only_client_credentials: ['token_client_credentials'],
  cap_client_credentials: ['token_client_credentials'],
  cap_userinfo_pairwise: ['cap_bootstrap', 'userinfo'],
  cap_refresh_token: ['cap_bootstrap', 'token_refresh'],
  cap_token_exchange: ['cap_bootstrap', 'token_exchange'],
  cap_native_sso_fresh: ['cap_bootstrap', 'token_native_sso_fresh'],
  cap_introspect: ['cap_bootstrap', 'introspect'],
  cap_revoke: ['cap_bootstrap', 'revoke'],
  cap_authorization_code: ['par_oidc', 'authorize', 'authorize_decision', 'token_authorization_code'],
  cap_mixed: ['cap_bootstrap', 'userinfo', 'token_client_credentials', 'par_oidc',
    'authorize', 'authorize_decision', 'token_authorization_code', 'token_refresh',
    'token_exchange', 'token_native_sso_fresh'],
  oidc_cold_login_refresh: [
    'par_oidc',
    'login',
    'authorize',
    'authorize_decision',
    'token_authorization_code',
    'token_refresh',
  ],
  oidc_logged_in_authorization_code: [
    'par_oidc',
    'authorize',
    'authorize_decision',
    'token_authorization_code',
  ],
  oidc_refresh_only: ['token_refresh'],
  fapi2_full_security: [
    'par_fapi',
    'login',
    'authorize',
    'authorize_decision',
    'fapi_token_authorization_code',
    'fapi_token_refresh',
  ],
  fapi2_logged_in_high_security: [
    'par_fapi',
    'authorize',
    'authorize_decision',
    'fapi_token_authorization_code',
    'fapi_token_refresh',
  ],
  refresh_token_rotation: [
    'par_oidc',
    'login',
    'authorize',
    'authorize_decision',
    'token_authorization_code',
    'token_refresh',
  ],
  introspect_opaque_refresh_token: [
    'par_oidc',
    'login',
    'authorize',
    'authorize_decision',
    'token_authorization_code',
    'introspect',
  ],
  revoke_refresh_token: [
    'par_oidc',
    'login',
    'authorize',
    'authorize_decision',
    'token_authorization_code',
    'revoke',
  ],
  authorize_par_session: ['par_oidc', 'login', 'authorize'],
  same_user_refresh_token_rotation: [
    'par_oidc',
    'login',
    'authorize',
    'authorize_decision',
    'token_authorization_code',
    'token_refresh',
  ],
  same_user_introspect_opaque_refresh_token: [
    'par_oidc',
    'login',
    'authorize',
    'authorize_decision',
    'token_authorization_code',
    'introspect',
  ],
  same_user_authorize_par_session: ['par_oidc', 'login', 'authorize'],
  fapi2_par_jar_private_key_jwt_dpop: [
    'par_fapi',
    'login',
    'authorize',
    'authorize_decision',
    'fapi_token_authorization_code',
    'fapi_token_refresh',
  ],
  ciba_private_key_jwt_dpop_poll: [
    'ciba_backchannel_authentication',
    'ciba_user_decision_view',
    'ciba_user_decision',
    'ciba_token',
  ],
  cap_session_reads: ['auth_me', 'auth_csrf', 'me_passkeys', 'me_applications',
    'me_federation_links', 'me_access_requests', 'me_mtls_trust_requests',
    'check_session_status'],
  cap_admin_reads: ['admin_users', 'admin_clients', 'admin_client_templates',
    'admin_grants', 'admin_access_requests', 'admin_mtls_trust_requests',
    'admin_mtls_trust_anchors', 'admin_runtime_modules',
    'admin_federation_providers', 'admin_runtime_module_events'],
  cap_scim_reads: ['scim_spc', 'scim_schemas', 'scim_resourcetypes',
    'scim_users', 'scim_user'],
  cap_fapi_resource: ['cap_bootstrap', 'fapi_resource_get', 'fapi_resource_post'],
  cap_device_flow: ['device_authorization', 'device_verification',
    'device_decision', 'token_device_code'],
  cap_ciba_flow: ['ciba_backchannel_authentication', 'ciba_user_decision_view',
    'ciba_user_decision', 'ciba_token'],
  cap_public_reads: ['health', 'live', 'startup', 'captcha_config',
    'federation_providers', 'oauth_protected_resource', 'perf_metrics'],
};
const vectorStride = Math.max(iterations, 100);
const vectorOffsets = {
  par_signed_request_object: 0,
  refresh_token_rotation: vectorStride,
  introspect_opaque_refresh_token: vectorStride * 2,
  authorize_par_session: vectorStride * 3,
  fapi2_par_jar_private_key_jwt_dpop: vectorStride * 4,
  same_user_refresh_token_rotation: vectorStride * 5,
  same_user_introspect_opaque_refresh_token: vectorStride * 6,
  same_user_authorize_par_session: vectorStride * 7,
  oidc_cold_login_refresh: vectorStride * 8,
  oidc_logged_in_authorization_code: vectorStride * 9,
  oidc_refresh_only: vectorStride * 10,
  fapi2_full_security: vectorStride * 11,
  fapi2_logged_in_high_security: vectorStride * 12,
  revoke_refresh_token: vectorStride * 13,
};

export const options = {
  summaryTrendStats: ['min', 'avg', 'med', 'p(50)', 'p(90)', 'p(95)', 'p(99)', 'max'],
  // Bound metric series: exclude url/iter/vu so per-request unique query
  // strings (request_uri, jti, auth_req_id) cannot grow k6 RSS unboundedly.
  systemTags: ['check', 'error', 'error_code', 'expected_response', 'group',
    'method', 'name', 'proto', 'scenario', 'service', 'status', 'subproto',
    'tls_version'],
  scenarios: {
    [scenario]: scenarioOptions(scenario),
  },
  thresholds: thresholds(),
};

function thresholds() {
  const base = {
    checks: ['rate>0.99'],
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(99)<5000'],
  };
  for (const step of scenarioSteps[scenario] || []) {
    base[`http_req_duration{step:${step}}`] = ['p(99)<5000'];
    base[`http_req_failed{step:${step}}`] = ['rate<0.01'];
    base[`http_reqs{step:${step}}`] = ['count>=0'];
    base[`err_classified{step:${step}}`] = ['count>=0'];
  }
  return base;
}

function scenarioOptions(name) {
  if (executor === 'constant-arrival-rate') {
    if (rate <= 0) {
      throw new Error('PERF_RATE must be positive when PERF_EXECUTOR=constant-arrival-rate');
    }
    return {
      executor,
      rate,
      timeUnit,
      duration,
      preAllocatedVUs: preAllocatedVus,
      maxVUs: maxVus,
      gracefulStop: '2m',
      exec: name,
    };
  }
  if (executor === 'ramping-vus') {
    const stages = JSON.parse(__ENV.PERF_STAGES || '[]').map(([d, t]) => ({ duration: d, target: t }));
    return {
      executor: 'ramping-vus',
      startVUs: 0,
      stages,
      gracefulRampDown: '5s',
      exec: name,
    };
  }
  if (executor === 'constant-vus'
      || name === 'token_client_credentials' || name === 'mtls_client_credentials') {
    return {
      executor: 'constant-vus',
      vus,
      duration,
      exec: name,
    };
  }
  return {
    executor: 'shared-iterations',
    vus: flowVus,
    iterations,
    maxDuration: '10m',
    exec: name,
  };
}

function form(data) {
  return Object.entries(data)
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join('&');
}

function requestTags(step, extra = {}) {
  return Object.assign({ flow: scenario, step, name: step }, extra);
}

// Error classification (2026-09-17 methodology round): every failed response
// is counted once with bounded tags {step,status,err} so saturation causes are
// attributable (HTTP status, OAuth error code, timeout, limiter rejection).
const errClassified = new Counter('err_classified');
// oauth_invalid_grant on the refresh path is an expected business outcome of
// the bounded-family model (capacity eviction / spent-token replay). Count it
// separately so capacity gates evaluate unexpected errors only.
const errExpectedInvalidGrant = new Counter('err_expected_invalid_grant');

function classifyError(res) {
  if (!res) {
    return 'no_response';
  }
  if (res.status === 0) {
    return res.error_code ? `k6_error_${res.error_code}` : 'transport_timeout';
  }
  let err = '';
  try {
    err = res.json('error') || '';
  } catch (e) {}
  if (!err) {
    const match = String(res.body || '').match(/[?&]error=([a-zA-Z0-9_]+)/);
    if (match) {
      err = match[1];
    }
  }
  if (!err && res.status === 302) {
    const loc = String((res.headers && (res.headers.Location || res.headers.location)) || '');
    const match = loc.match(/[?&]error=([a-zA-Z0-9_]+)/);
    if (match) {
      err = match[1];
    }
  }
  if (err) {
    return `oauth_${err}`;
  }
  if (res.status === 429) {
    return 'rate_limited';
  }
  return `http_${res.status}`;
}

function checkErr(res, conds, stepHint) {
  const ok = check(res, conds);
  if (!ok) {
    // res.request.tags is not populated in k6 v2; derive the step from the
    // check name ("<step> <condition>") unless the caller passes it.
    const name = Object.keys(conds)[0] || '';
    const step = stepHint || (res && res.request && res.request.tags && res.request.tags.step)
      || (name.includes(' ') ? name.slice(0, name.indexOf(' ')) : name) || 'unknown';
    const err = classifyError(res);
    errClassified.add(1, {
      step,
      status: String(res ? res.status : 0),
      err,
    });
    if (err === 'oauth_invalid_grant' && step === 'refresh') {
      errExpectedInvalidGrant.add(1);
    }
    // bounded per-VU failure log: preserves status/error-body evidence in
    // run.log so saturation causes are attributable without unbounded volume.
    if ((__VU_STATE.errLogged || 0) < 40) {
      __VU_STATE.errLogged = (__VU_STATE.errLogged || 0) + 1;
      const body = res && res.body ? String(res.body).slice(0, 160).replace(/\s+/g, ' ') : '';
      console.log(`ERR_SAMPLE step=${step} status=${res ? res.status : 0} err=${err} body=${body}`);
    }
  }
  return ok;
}

function tenantHeaders(extra = {}) {
  return TENANT_HOST ? Object.assign({ Host: TENANT_HOST }, extra) : extra;
}

function formHeaders(extra = {}, tags = {}) {
  return {
    headers: tenantHeaders(Object.assign({ 'Content-Type': 'application/x-www-form-urlencoded' }, extra)),
    redirects: 0,
    tags,
  };
}

function jsonHeaders(tags = {}) {
  return {
    headers: tenantHeaders({
      'Content-Type': 'application/json',
    }),
    redirects: 0,
    tags,
  };
}

function cookieHeaderFromResponse(response) {
  const parts = [];
  for (const [name, values] of Object.entries(response.cookies || {})) {
    if (values && values.length > 0) {
      parts.push(`${name}=${values[0].value}`);
    }
  }
  return parts.join('; ');
}

function sessionHeaders() {
  return __VU_STATE.cookieHeader ? { Cookie: __VU_STATE.cookieHeader } : {};
}

function vector() {
  const offset = vectorOffsets[scenario] || 0;
  let relativeIndex = exec.scenario.iterationInTest;
  if (executor === 'constant-arrival-rate' && rate > 0 && scenario !== 'oidc_refresh_only') {
    const elapsedSeconds = Math.max(0, Math.floor((Date.now() - testStartedAtMs) / 1000));
    relativeIndex = elapsedSeconds * rate + (exec.scenario.iterationInTest % rate);
  }
  const slice = vectors.length - offset;
  if (slice <= 0) {
    fail(`flow vector pool smaller than scenario offset ${offset}; raise PERF_VECTOR_COUNT`);
  }
  const index = offset + (relativeIndex % slice);
  return vectors[index];
}

function locationHeader(response) {
  return response.headers.Location || response.headers.location || '';
}

function queryParamFromLocation(location, name) {
  const marker = `${name}=`;
  const query = location.split('?')[1] || location;
  for (const part of query.split('&')) {
    if (part.startsWith(marker)) {
      return decodeURIComponent(part.slice(marker.length));
    }
  }
  return '';
}

function selectedUser(sharedUser) {
  const users = secrets.users || [secrets.user];
  if (sharedUser || users.length === 1) {
    return users[0];
  }
  const vuIndex = Math.max((exec.vu && exec.vu.idInTest ? exec.vu.idInTest : 1) - 1, 0);
  return users[vuIndex % users.length];
}

function selectedLoggedInSession() {
  const sessions = secrets.logged_in_sessions || [];
  if (sessions.length === 0) {
    return null;
  }
  const vuIndex = Math.max((exec.vu && exec.vu.idInTest ? exec.vu.idInTest : 1) - 1, 0);
  return sessions[vuIndex % sessions.length];
}

function usePreseededSession() {
  const session = selectedLoggedInSession();
  if (!session) {
    return false;
  }
  __VU_STATE.csrf = session.csrf_token;
  __VU_STATE.cookieHeader = session.cookie_header;
  return Boolean(__VU_STATE.csrf && __VU_STATE.cookieHeader);
}

function ensureUserSession(user, cacheSession = false) {
  if (cacheSession && __VU_STATE.csrf) {
    return true;
  }
  if (cacheSession && usePreseededSession()) {
    return true;
  }
  const response = http.post(
    `${BASE_URL}/auth/login`,
    JSON.stringify({
      email: user.email,
      password: user.password,
    }),
    jsonHeaders(requestTags('login', {
      endpoint: '/auth/login',
      auth_context: 'password',
    })),
  );
  checkErr(response, {
    'login status is 200': (r) => r.status === 200,
    'login csrf cookie returned': (r) => Boolean(r.cookies.nazo_oauth_csrf && r.cookies.nazo_oauth_csrf.length),
  });
  if (response.status !== 200) {
    return false;
  }
  __VU_STATE.csrf = response.cookies.nazo_oauth_csrf[0].value;
  __VU_STATE.cookieHeader = cookieHeaderFromResponse(response);
  return true;
}

const __VU_STATE = {};

function asciiBytes(value) {
  const out = new Uint8Array(value.length);
  for (let index = 0; index < value.length; index += 1) {
    out[index] = value.charCodeAt(index);
  }
  return out;
}

function jwtPart(value) {
  return encoding.b64encode(JSON.stringify(value), 'rawurl');
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function uniqueJti(prefix) {
  return `${prefix}-${__VU}-${exec.scenario.iterationInTest}-${crypto.randomUUID()}`;
}

async function rsaSigningKey() {
  if (!__VU_STATE.rsaSigningKey) {
    __VU_STATE.rsaSigningKey = await crypto.subtle.importKey(
      'jwk',
      secrets.private_jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['sign'],
    );
  }
  return __VU_STATE.rsaSigningKey;
}

async function rsaPssSigningKey() {
  if (!__VU_STATE.rsaPssSigningKey) {
    __VU_STATE.rsaPssSigningKey = await crypto.subtle.importKey(
      'jwk',
      secrets.ps256_private_jwk,
      { name: 'RSA-PSS', hash: 'SHA-256' },
      false,
      ['sign'],
    );
  }
  return __VU_STATE.rsaPssSigningKey;
}

async function dpopSigningKey() {
  if (!__VU_STATE.dpopSigningKey) {
    __VU_STATE.dpopSigningKey = await crypto.subtle.importKey(
      'jwk',
      secrets.dpop_private_jwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign'],
    );
  }
  return __VU_STATE.dpopSigningKey;
}

async function signJwt(header, claims, key, algorithm) {
  const signingInput = `${jwtPart(header)}.${jwtPart(claims)}`;
  const signature = await crypto.subtle.sign(algorithm, key, asciiBytes(signingInput));
  return `${signingInput}.${encoding.b64encode(new Uint8Array(signature), 'rawurl')}`;
}

async function signRs256(header, claims) {
  return signJwt(
    Object.assign({ alg: 'RS256', kid: secrets.private_jwk.kid, typ: 'JWT' }, header),
    claims,
    await rsaSigningKey(),
    { name: 'RSASSA-PKCS1-v1_5' },
  );
}

async function signPs256(header, claims) {
  return signJwt(
    Object.assign({ alg: 'PS256', kid: secrets.ps256_private_jwk.kid, typ: 'JWT' }, header),
    claims,
    await rsaPssSigningKey(),
    { name: 'RSA-PSS', saltLength: 32 },
  );
}

async function signEs256(header, claims) {
  return signJwt(
    Object.assign({ alg: 'ES256' }, header),
    claims,
    await dpopSigningKey(),
    { name: 'ECDSA', hash: 'SHA-256' },
  );
}

async function clientAssertion(clientId, audience, prefix, alg = 'RS256') {
  const now = nowSeconds();
  const claims = {
    iss: clientId,
    sub: clientId,
    aud: audience,
    iat: now,
    exp: now + 240,
    jti: uniqueJti(prefix),
  };
  if (alg === 'PS256') {
    return signPs256({}, claims);
  }
  return signRs256({}, claims);
}

async function requestObject(clientId, state, nonce, codeChallenge, dpopJkt, scopeOverride) {
  const now = nowSeconds();
  const claims = {
    client_id: clientId,
    iss: clientId,
    sub: clientId,
    aud: secrets.issuer,
    iat: now,
    nbf: now,
    exp: now + 240,
    jti: uniqueJti('jar'),
    response_type: 'code',
    redirect_uri: secrets.redirect_uri,
    scope: scopeOverride || 'openid profile offline_access',
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  };
  if (dpopJkt) {
    claims.dpop_jkt = dpopJkt;
  }
  return signRs256({}, claims);
}

async function dpopProof(method, htu, prefix) {
  const now = nowSeconds();
  return signEs256(
    { typ: 'dpop+jwt', jwk: secrets.dpop_public_jwk },
    {
      htm: method,
      htu,
      iat: now,
      jti: uniqueJti(prefix),
    },
  );
}

async function cibaRequestObject(user) {
  const now = nowSeconds();
  return signPs256(
    {},
    {
      iss: secrets.clients.ciba,
      aud: secrets.issuer,
      iat: now,
      nbf: now,
      exp: now + 240,
      jti: uniqueJti('ciba-request'),
      scope: 'openid profile',
      login_hint: user.email,
      binding_message: `NazoAuth CIBA ${__VU}-${exec.scenario.iterationInTest}`,
      acr_values: '1',
      requested_expiry: 300,
    },
  );
}

async function cibaBackchannelAuthentication(user) {
  const assertion = await clientAssertion(secrets.clients.ciba, secrets.issuer, 'ciba-backchannel', 'PS256');
  const request = await cibaRequestObject(user);
  const dpop = await dpopProof('POST', `${secrets.issuer}/bc-authorize`, 'dpop-ciba-bc');
  const response = http.post(
    `${BASE_URL}/bc-authorize`,
    form({
      client_id: secrets.clients.ciba,
      client_assertion_type: secrets.client_assertion_type,
      client_assertion: assertion,
      request,
    }),
    formHeaders({ DPoP: dpop }, requestTags('ciba_backchannel_authentication', {
      endpoint: '/bc-authorize',
      grant_type: 'urn:openid:params:grant-type:ciba',
      client_profile: 'ciba-fapi-compatible',
      client_auth: 'private_key_jwt',
      request_object: 'signed',
      delivery_mode: 'poll',
    })),
  );
  checkErr(response, {
    'ciba bc status is 200': (r) => r.status === 200,
    'ciba auth_req_id returned': (r) => Boolean(r.json('auth_req_id')),
    'ciba interval returned': (r) => Number(r.json('interval')) > 0,
  });
  if (response.status !== 200) {
    fail(`ciba backchannel failed: ${response.status} ${response.body}`);
  }
  return response.json('auth_req_id');
}

function approveCiba(authReqId) {
  // Real user decision endpoints: GET /auth/ciba/{id} then POST decision with
  // the session + CSRF cookies of the hinted user.
  const view = http.get(
    `${BASE_URL}/auth/ciba/${authReqId}`,
    {
      headers: tenantHeaders(sessionHeaders()),
      redirects: 0,
      tags: requestTags('ciba_user_decision_view', { endpoint: '/auth/ciba/{id}' }),
    },
  );
  checkErr(view, {
    'ciba decision view status is 200': (r) => r.status === 200,
  });
  if (view.status !== 200) {
    fail(`ciba decision view failed: ${view.status} ${view.body}`);
  }
  const res = http.post(
    `${BASE_URL}/auth/ciba/${authReqId}`,
    JSON.stringify({ decision: 'approve', csrf_token: __VU_STATE.csrf }),
    {
      headers: tenantHeaders(Object.assign({ 'Content-Type': 'application/json' }, sessionHeaders())),
      redirects: 0,
      tags: requestTags('ciba_user_decision', { endpoint: '/auth/ciba/{id}', decision: 'approve' }),
    },
  );
  checkErr(res, {
    'ciba user decision status is 200': (r) => r.status === 200,
    'ciba user decision succeeded': (r) => r.json('success') === true,
  });
  if (res.status !== 200) {
    fail(`ciba user decision failed: ${res.status} ${res.body}`);
  }
}

async function cibaToken(authReqId) {
  const assertion = await clientAssertion(secrets.clients.ciba, secrets.issuer, 'ciba-token', 'PS256');
  const dpop = await dpopProof('POST', `${secrets.issuer}/token`, 'dpop-ciba-token');
  const response = http.post(
    `${BASE_URL}/token`,
    form({
      grant_type: 'urn:openid:params:grant-type:ciba',
      auth_req_id: authReqId,
      client_assertion_type: secrets.client_assertion_type,
      client_assertion: assertion,
    }),
    formHeaders({ DPoP: dpop }, requestTags('ciba_token', {
      endpoint: '/token',
      grant_type: 'urn:openid:params:grant-type:ciba',
      client_profile: 'ciba-fapi-compatible',
      client_auth: 'private_key_jwt',
      sender_constraint: 'dpop',
      delivery_mode: 'poll',
    })),
  );
  checkErr(response, {
    'ciba token status is 200': (r) => r.status === 200,
    'ciba token is DPoP-bound': (r) => r.json('token_type') === 'DPoP',
    'ciba access token returned': (r) => Boolean(r.json('access_token')),
  });
  if (response.status !== 200) {
    fail(`ciba token failed: ${response.status} ${response.body}`);
  }
}

async function oidcPar(v) {
  const request = await requestObject(
    secrets.clients.oidc,
    v.oidc_state,
    v.oidc_nonce,
    v.oidc_code_challenge,
    null,
  );
  const body = form({
    client_id: secrets.clients.oidc,
    client_secret: secrets.client_secret,
    request,
  });
  const response = http.post(
    `${BASE_URL}/par`,
    body,
    formHeaders({}, requestTags('par_oidc', {
      endpoint: '/par',
      client_profile: 'oidc',
      request_object: 'jar',
    })),
  );
  checkErr(response, {
    'oidc PAR status is 201': (r) => r.status === 201,
    'oidc PAR request_uri returned': (r) => Boolean(r.json('request_uri')),
  });
  if (response.status !== 201) {
    fail(`oidc PAR failed: ${response.status} ${response.body}`);
  }
  return response.json('request_uri');
}

async function fapiPar(v) {
  const request = await requestObject(
    secrets.clients.fapi,
    v.fapi_state,
    v.fapi_nonce,
    v.fapi_code_challenge,
    secrets.dpop_jkt,
  );
  const assertion = await clientAssertion(secrets.clients.fapi, secrets.issuer, 'fapi-par');
  const dpop = await dpopProof('POST', `${secrets.issuer}/par`, 'dpop-par');
  const body = form({
    client_id: secrets.clients.fapi,
    client_assertion_type: secrets.client_assertion_type,
    client_assertion: assertion,
    request,
  });
  const response = http.post(
    `${BASE_URL}/par`,
    body,
    formHeaders({ DPoP: dpop }, requestTags('par_fapi', {
      endpoint: '/par',
      client_profile: 'fapi2',
      request_object: 'jar',
      sender_constraint: 'dpop',
    })),
  );
  checkErr(response, {
    'fapi PAR status is 201': (r) => r.status === 201,
    'fapi PAR request_uri returned': (r) => Boolean(r.json('request_uri')),
  });
  if (response.status !== 201) {
    fail(`fapi PAR failed: ${response.status} ${response.body}`);
  }
  return response.json('request_uri');
}

function authorizePar(clientId, requestUri, user, cacheSession = false) {
  if (!ensureUserSession(user, cacheSession)) {
    return '';
  }
  const response = http.get(
    `${BASE_URL}/authorize?${form({ client_id: clientId, request_uri: requestUri })}`,
    {
      headers: tenantHeaders(sessionHeaders()),
      redirects: 0,
      tags: requestTags('authorize', {
        endpoint: '/authorize',
      }),
    },
  );
  checkErr(response, {
    'authorize returns request id redirect': (r) => r.status === 302 && Boolean(queryParamFromLocation(locationHeader(r), 'request_id')),
  });
  const requestId = queryParamFromLocation(locationHeader(response), 'request_id');
  if ((response.status !== 302 && response.status !== 303) || !requestId) {
    fail(`authorize failed: ${response.status} ${locationHeader(response)} ${response.body}`);
  }
  return requestId;
}

function approveAuthorization(requestId, expectedState) {
  const response = http.post(
    `${BASE_URL}/authorize/decision`,
    form({
      request_id: requestId,
      decision: 'approve',
      csrf_token: __VU_STATE.csrf,
    }),
    formHeaders(sessionHeaders(), requestTags('authorize_decision', {
      endpoint: '/authorize/decision',
    })),
  );
  const location = locationHeader(response);
  checkErr(response, {
    'authorization decision returns code redirect': (r) => (r.status === 302 || r.status === 303) && location.includes('code='),
    'authorization state roundtrips': () => location.includes(`state=${encodeURIComponent(expectedState)}`),
  });
  if (response.status !== 302 && response.status !== 303) {
    fail(`authorization decision failed: ${response.status} ${response.body}`);
  }
  return queryParamFromLocation(location, 'code');
}

function tokenAuthorizationCode(v, code) {
  const response = http.post(
    `${BASE_URL}/token`,
    form({
      grant_type: 'authorization_code',
      client_id: secrets.clients.oidc,
      client_secret: secrets.client_secret,
      code,
      redirect_uri: secrets.redirect_uri,
      code_verifier: v.pkce_verifier,
    }),
    formHeaders({}, requestTags('token_authorization_code', {
      endpoint: '/token',
      grant_type: 'authorization_code',
      client_profile: 'oidc',
    })),
  );
  checkErr(response, {
    'authorization_code token status is 200': (r) => r.status === 200,
    'authorization_code refresh token returned': (r) => Boolean(r.json('refresh_token')),
  });
  if (response.status !== 200) {
    fail(`authorization_code token failed: ${response.status} ${response.body}`);
  }
  return response.json();
}

async function fapiTokenAuthorizationCode(v, code) {
  const assertion = await clientAssertion(secrets.clients.fapi, secrets.issuer, 'fapi-token');
  const dpop = await dpopProof('POST', `${secrets.issuer}/token`, 'dpop-token');
  const response = http.post(
    `${BASE_URL}/token`,
    form({
      grant_type: 'authorization_code',
      code,
      redirect_uri: secrets.redirect_uri,
      code_verifier: v.fapi_pkce_verifier,
      client_assertion_type: secrets.client_assertion_type,
      client_assertion: assertion,
    }),
    formHeaders({ DPoP: dpop }, requestTags('fapi_token_authorization_code', {
      endpoint: '/token',
      grant_type: 'authorization_code',
      client_profile: 'fapi2',
      client_auth: 'private_key_jwt',
      sender_constraint: 'dpop',
    })),
  );
  checkErr(response, {
    'fapi authorization_code token status is 200': (r) => r.status === 200,
    'fapi token is DPoP-bound': (r) => r.json('token_type') === 'DPoP',
    'fapi refresh token returned': (r) => Boolean(r.json('refresh_token')),
  });
  if (response.status !== 200) {
    fail(`fapi authorization_code token failed: ${response.status} ${response.body}`);
  }
  return response.json();
}

export function token_client_credentials() {
  const response = http.post(
    `${BASE_URL}/token`,
    form({
      grant_type: 'client_credentials',
      client_id: secrets.clients.client_credentials,
      client_secret: secrets.client_secret,
      scope: 'profile',
    }),
    formHeaders({}, requestTags('token_client_credentials', {
      endpoint: '/token',
      grant_type: 'client_credentials',
      client_auth: 'client_secret_post',
    })),
  );
  checkErr(response, {
    'client_credentials status is 200': (r) => r.status === 200,
    'client_credentials access token returned': (r) => Boolean(r.json('access_token')),
  });
}

export function token_only_client_credentials() {
  token_client_credentials();
}

export function mtls_client_credentials() {
  const response = http.post(
    `${BASE_URL}/token`,
    form({
      grant_type: 'client_credentials',
      client_id: secrets.clients.mtls,
      scope: 'profile',
    }),
    formHeaders({
      'client-cert': `:${secrets.mtls_x5c}:`,
    }, requestTags('mtls_client_credentials', {
      endpoint: '/token',
      grant_type: 'client_credentials',
      client_auth: 'tls_client_auth',
      sender_constraint: 'mtls',
    })),
  );
  checkErr(response, {
    'mtls client_credentials status is 200': (r) => r.status === 200,
    'mtls client_credentials access token returned': (r) => Boolean(r.json('access_token')),
  });
}

export async function introspect_opaque_refresh_token() {
  await introspectOpaqueRefreshToken(false);
}

export function metadata_jwks() {
  const metadata = http.get(
    `${BASE_URL}/.well-known/openid-configuration`,
    {
      headers: tenantHeaders(),
      redirects: 0,
      tags: requestTags('metadata', {
        endpoint: '/.well-known/openid-configuration',
      }),
    },
  );
  checkErr(metadata, {
    'metadata status is 200': (r) => r.status === 200,
    'metadata issuer returned': (r) => Boolean(r.json('issuer')),
  });
  if (metadata.status !== 200) {
    fail(`metadata failed: ${metadata.status} ${metadata.body}`);
  }

  const jwks = http.get(
    `${BASE_URL}/jwks.json`,
    {
      headers: tenantHeaders(),
      redirects: 0,
      tags: requestTags('jwks', {
        endpoint: '/jwks.json',
      }),
    },
  );
  checkErr(jwks, {
    'jwks status is 200': (r) => r.status === 200,
    'jwks keys returned': (r) => Array.isArray(r.json('keys')),
  });
  if (jwks.status !== 200) {
    fail(`jwks failed: ${jwks.status} ${jwks.body}`);
  }
}

async function introspectOpaqueRefreshToken(sharedUser) {
  const user = selectedUser(sharedUser);
  const v = vector();
  const requestUri = await oidcPar(v);
  const requestId = authorizePar(secrets.clients.oidc, requestUri, user);
  if (!requestId) {
    return;
  }
  const code = approveAuthorization(requestId, v.oidc_state);
  const tokens = tokenAuthorizationCode(v, code);
  const response = http.post(
    `${BASE_URL}/introspect`,
    form({
      token: tokens.refresh_token,
      client_id: secrets.clients.oidc,
      client_secret: secrets.client_secret,
    }),
    formHeaders({}, requestTags('introspect', {
      endpoint: '/introspect',
      token_type: 'opaque_refresh_token',
      client_profile: 'oidc',
    })),
  );
  checkErr(response, {
    'refresh token introspection status is 200': (r) => r.status === 200,
    'refresh token introspection active': (r) => r.json('active') === true,
  });
}

export async function refresh_token_rotation() {
  await refreshTokenRotation(false);
}

async function refreshTokenRotation(sharedUser) {
  const user = selectedUser(sharedUser);
  const v = vector();
  const requestUri = await oidcPar(v);
  const requestId = authorizePar(secrets.clients.oidc, requestUri, user);
  if (!requestId) {
    return;
  }
  const code = approveAuthorization(requestId, v.oidc_state);
  const tokens = tokenAuthorizationCode(v, code);
  const response = http.post(
    `${BASE_URL}/token`,
    form({
      grant_type: 'refresh_token',
      client_id: secrets.clients.oidc,
      client_secret: secrets.client_secret,
      refresh_token: tokens.refresh_token,
    }),
    formHeaders({}, requestTags('token_refresh', {
      endpoint: '/token',
      grant_type: 'refresh_token',
      client_profile: 'oidc',
    })),
  );
  checkErr(response, {
    'refresh_token rotation status is 200': (r) => r.status === 200,
    'refresh_token rotation returns new refresh token': (r) => Boolean(r.json('refresh_token')),
  });
}

export async function oidc_cold_login_refresh() {
  await refreshTokenRotation(false);
}

export async function revoke_refresh_token() {
  const user = selectedUser(false);
  const v = vector();
  const requestUri = await oidcPar(v);
  const requestId = authorizePar(secrets.clients.oidc, requestUri, user);
  if (!requestId) {
    return;
  }
  const code = approveAuthorization(requestId, v.oidc_state);
  const tokens = tokenAuthorizationCode(v, code);
  const response = http.post(
    `${BASE_URL}/revoke`,
    form({
      token: tokens.refresh_token,
      client_id: secrets.clients.oidc,
      client_secret: secrets.client_secret,
    }),
    formHeaders({}, requestTags('revoke', {
      endpoint: '/revoke',
      token_type: 'refresh_token',
      client_profile: 'oidc',
    })),
  );
  checkErr(response, {
    'refresh token revoke status is 200': (r) => r.status === 200,
  });
  if (response.status !== 200) {
    fail(`refresh token revoke failed: ${response.status} ${response.body}`);
  }
}

export async function oidc_logged_in_authorization_code() {
  const user = selectedUser(false);
  const v = vector();
  const requestUri = await oidcPar(v);
  const requestId = authorizePar(secrets.clients.oidc, requestUri, user, true);
  if (!requestId) {
    return;
  }
  const code = approveAuthorization(requestId, v.oidc_state);
  tokenAuthorizationCode(v, code);
}

function seededOidcRefreshToken() {
  const tokens = secrets.oidc_refresh_tokens || [];
  if (tokens.length === 0) {
    fail('oidc_refresh_only requires pre-seeded OIDC refresh tokens');
  }
  const vuIndex = Math.max((exec.vu && exec.vu.idInTest ? exec.vu.idInTest : 1) - 1, 0);
  return tokens[vuIndex % tokens.length];
}

export async function oidc_refresh_only() {
  if (!__VU_STATE.refreshToken) {
    __VU_STATE.refreshToken = seededOidcRefreshToken();
  }
  const response = http.post(
    `${BASE_URL}/token`,
    form({
      grant_type: 'refresh_token',
      client_id: secrets.clients.oidc,
      client_secret: secrets.client_secret,
      refresh_token: __VU_STATE.refreshToken,
    }),
    formHeaders({}, requestTags('token_refresh', {
      endpoint: '/token',
      grant_type: 'refresh_token',
      client_profile: 'oidc',
      load_model: 'refresh_only',
    })),
  );
  checkErr(response, {
    'refresh-only rotation status is 200': (r) => r.status === 200,
    'refresh-only rotation returns new refresh token': (r) => Boolean(r.json('refresh_token')),
  });
  if (response.status !== 200) {
    fail(`refresh-only token failed: ${response.status} ${response.body}`);
  }
  __VU_STATE.refreshToken = response.json('refresh_token');
}

export async function par_signed_request_object() {
  await oidcPar(vector());
}

export async function authorize_par_session() {
  await authorizeParSession(false);
}

async function authorizeParSession(sharedUser) {
  const user = selectedUser(sharedUser);
  const v = vector();
  const requestUri = await oidcPar(v);
  const requestId = authorizePar(secrets.clients.oidc, requestUri, user);
  check({ requestId }, {
    'authorize PAR session request id returned': (value) => Boolean(value.requestId),
  });
}

export async function fapi2_par_jar_private_key_jwt_dpop() {
  const user = selectedUser(false);
  const v = vector();
  const requestUri = await fapiPar(v);
  const requestId = authorizePar(secrets.clients.fapi, requestUri, user);
  if (!requestId) {
    return;
  }
  const code = approveAuthorization(requestId, v.fapi_state);
  const tokens = await fapiTokenAuthorizationCode(v, code);
  const assertion = await clientAssertion(secrets.clients.fapi, secrets.issuer, 'fapi-refresh');
  const dpop = await dpopProof('POST', `${secrets.issuer}/token`, 'dpop-refresh');
  const response = http.post(
    `${BASE_URL}/token`,
    form({
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token,
      client_assertion_type: secrets.client_assertion_type,
      client_assertion: assertion,
    }),
    formHeaders({ DPoP: dpop }, requestTags('fapi_token_refresh', {
      endpoint: '/token',
      grant_type: 'refresh_token',
      client_profile: 'fapi2',
      client_auth: 'private_key_jwt',
      sender_constraint: 'dpop',
    })),
  );
  checkErr(response, {
    'fapi DPoP refresh status is 200': (r) => r.status === 200,
    'fapi DPoP refresh returns DPoP token': (r) => r.json('token_type') === 'DPoP',
  });
  if (response.status !== 200) {
    fail(`fapi refresh failed: ${response.status} ${response.body}`);
  }
}

export async function fapi2_full_security() {
  await fapi2_par_jar_private_key_jwt_dpop();
}

export async function fapi2_logged_in_high_security() {
  const user = selectedUser(false);
  const v = vector();
  const requestUri = await fapiPar(v);
  const requestId = authorizePar(secrets.clients.fapi, requestUri, user, true);
  if (!requestId) {
    return;
  }
  const code = approveAuthorization(requestId, v.fapi_state);
  const tokens = await fapiTokenAuthorizationCode(v, code);
  const assertion = await clientAssertion(secrets.clients.fapi, secrets.issuer, 'fapi-refresh');
  const dpop = await dpopProof('POST', `${secrets.issuer}/token`, 'dpop-refresh');
  const response = http.post(
    `${BASE_URL}/token`,
    form({
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token,
      client_assertion_type: secrets.client_assertion_type,
      client_assertion: assertion,
    }),
    formHeaders({ DPoP: dpop }, requestTags('fapi_token_refresh', {
      endpoint: '/token',
      grant_type: 'refresh_token',
      client_profile: 'fapi2',
      client_auth: 'private_key_jwt',
      sender_constraint: 'dpop',
    })),
  );
  checkErr(response, {
    'fapi logged-in DPoP refresh status is 200': (r) => r.status === 200,
    'fapi logged-in DPoP refresh returns DPoP token': (r) => r.json('token_type') === 'DPoP',
  });
  if (response.status !== 200) {
    fail(`fapi logged-in refresh failed: ${response.status} ${response.body}`);
  }
}

export async function ciba_private_key_jwt_dpop_poll() {
  const user = selectedUser(false);
  const authReqId = await cibaBackchannelAuthentication(user);
  approveCiba(authReqId);
  await cibaToken(authReqId);
}

export async function same_user_refresh_token_rotation() {
  await refreshTokenRotation(true);
}

export async function same_user_introspect_opaque_refresh_token() {
  await introspectOpaqueRefreshToken(true);
}

export async function same_user_authorize_par_session() {
  await authorizeParSession(true);
}

export default function () {
  fail('PERF_SCENARIO must select a named scenario exec function');
}

// --- capacity/stress scenarios (perf/capacity-stress-20260915) ---

// Warmup/measure split: ops whose iteration entered the scenario-level
// measurement window are recorded into cap_measure_* metrics, so
// bootstrap/login and ramp noise stay out of percentiles.
const CAP_WARMUP_MS = Number(__ENV.CAP_WARMUP_MS || '15000');
// Optional hard-isolated measurement window for diagnostics: warmup ends at
// CAP_WARMUP_MS, VUs idle through the gap, measurement starts at
// CAP_MEASURE_START_MS. 0 disables the gap (legacy two-phase mode).
const CAP_MEASURE_START_MS = Number(__ENV.CAP_MEASURE_START_MS || '0');
// The measurement window opens MEASURE_OFFSET_MS after the scenario starts:
// warmup for standard runs, CAP_MEASURE_START_MS when a gap is configured.
const MEASURE_OFFSET_MS = CAP_MEASURE_START_MS > 0 ? CAP_MEASURE_START_MS : CAP_WARMUP_MS;
const CAP_DURATION_MS = parseDurationMs(duration);
const capClock = createMeasurementClock({
  durationMs: CAP_DURATION_MS,
  measureOffsetMs: MEASURE_OFFSET_MS,
  bucketMs: Number(__ENV.CAP_BUCKET_MS || '60000'),
  vuInitMs: testStartedAtMs,
});

// Workload lifecycle phase — deliberately on the VU-local init clock.
// capRefreshOp consults it to decide whether a missing token may be re-minted
// (warmup) or must surface as a local no-request failure (measure), and the
// optional gap phase idles VUs. Measurement membership is NOT decided here;
// it is the scenario-clock cohort computed in capRun.
function capPhase() {
  const t = Date.now() - testStartedAtMs;
  if (CAP_MEASURE_START_MS <= 0) {
    return t < CAP_WARMUP_MS ? 'warmup' : 'measure';
  }
  if (t < CAP_WARMUP_MS) {
    return 'warmup';
  }
  if (t < CAP_MEASURE_START_MS) {
    return 'gap';
  }
  return 'measure';
}
const capLatency = new Trend('cap_measure_ms', true);
const capOps = new Counter('cap_measure_ops');
const capErrs = new Counter('cap_measure_errors');
// Per-minute measure buckets (cap_m1_*, cap_m2_*, ...) let steady-state and
// recovery runs report drift without per-request logs. The bucket count is
// derived from the configured duration on the scenario clock; the last bucket
// is an explicit overflow slot for post-window completions.
const CAP_BUCKET_MS = Number(__ENV.CAP_BUCKET_MS || '60000');
const CAP_BUCKETS = bucketCount(CAP_DURATION_MS, MEASURE_OFFSET_MS, CAP_BUCKET_MS);
const capBucketLatency = [];
const capBucketOps = [];
const capBucketErrs = [];
// Entry-bucketed begins let the report compute per-minute drops
// (scheduled_i - begin_i); subject lifecycle counters expose the
// 240s re-bootstrap herd and whether refresh responses carry the
// fixture forward.
const capBucketBegins = [];
const capBucketSubject = {};
for (const kind of SUBJECT_KINDS) {
  capBucketSubject[kind] = [];
}
for (let i = 0; i < CAP_BUCKETS; i += 1) {
  capBucketLatency.push(new Trend(`cap_m${i + 1}_ms`, true));
  capBucketOps.push(new Counter(`cap_m${i + 1}_ops`));
  capBucketErrs.push(new Counter(`cap_m${i + 1}_errors`));
  capBucketBegins.push(new Counter(`cap_m${i + 1}_iter_begin`));
  for (const kind of SUBJECT_KINDS) {
    capBucketSubject[kind].push(
      new Counter(`cap_m${i + 1}_subject_${kind}`));
  }
}

// Subject lifecycle event: global counter always; the 60s measurement
// bucket only when the event lands inside [measure_start, measure_end).
// Warmup bootstraps land in bucket -1 and stay out of the per-minute
// evidence by design.
function capSubjectEvent(kind) {
  subjectCounters[kind].add(1);
  const idx = bucketIndexAt(
    Date.now(), capClock.window().startMs, CAP_BUCKET_MS, CAP_BUCKETS);
  if (idx >= 0) {
    capBucketSubject[kind][idx].add(1);
  }
}

function capWarmedUp() {
  return Date.now() - testStartedAtMs >= CAP_WARMUP_MS;
}

// Ops return true/false, or a { capOutcome } object for classified exits:
// local_no_request (no HTTP request was ever sent), expected_rejection
// (protocol-correct rejection such as bounded-family invalid_grant).
function capOutcomeOf(result, threw) {
  if (threw) {
    return 'unexpected';
  }
  if (result && typeof result === 'object' && result.capOutcome) {
    return result.capOutcome;
  }
  return result ? 'success' : 'unexpected';
}

async function capRun(prepare, op) {
  const entryMs = Date.now();
  // Workload lifecycle phase on the VU-local clock — unchanged semantics:
  // gap idles, warmup executes unmeasured, measure executes measured.
  const phase = capPhase();
  const lw = phase === 'measure';
  // Measurement cohort on the scenario clock: identical origin for every VU,
  // so VUs spawned mid-run join the same [start, end) window immediately.
  const cohort = capClock.begin(entryMs, lw);
  if (cohort === COHORT_MEASURE) {
    const bidx = bucketIndexAt(
      entryMs, capClock.window().startMs, CAP_BUCKET_MS, CAP_BUCKETS);
    if (bidx >= 0) {
      capBucketBegins[bidx].add(1);
    }
  }
  if (phase === 'gap') {
    sleep(0.2);
    capClock.end(cohort, lw, 'gap_idle');
    return;
  }
  const measuring = cohort === COHORT_MEASURE;
  try {
    await prepare();
  } catch (e) {
    capClock.end(cohort, lw, 'prepare_failed');
    if (measuring) {
      capOps.add(1);
      capErrs.add(1);
    }
    return;
  }
  const t0 = Date.now();
  let result;
  let threw = false;
  try {
    result = await op();
  } catch (e) {
    threw = true;
  }
  const endMs = Date.now();
  const outcome = capOutcomeOf(result, threw);
  capClock.end(cohort, lw, outcome);
  if (!measuring) {
    return;
  }
  const opMs = endMs - t0;
  capIterMs.add(endMs - entryMs);
  capLatency.add(opMs);
  capOps.add(1);
  const idx = bucketIndexAt(endMs, capClock.window().startMs, CAP_BUCKET_MS, CAP_BUCKETS);
  if (idx >= 0) {
    capBucketLatency[idx].add(opMs);
    capBucketOps[idx].add(1);
    if (outcome !== 'success') {
      capBucketErrs[idx].add(1);
    }
  }
  if (outcome !== 'success') {
    capErrs.add(1);
  }
}

// Vectors are only consumed during per-VU bootstrap and authorization-code ops;
// wrapping keeps constant-vus runs from exhausting the fixed pool.
function capVector() {
  return vectors[(exec.scenario.iterationInTest + __VU * 7919) % vectors.length];
}

// One logged-in authorization_code issuance per VU. With sso=true the request
// adds device_sso scope so the response also carries id_token + device_secret.
const CAP_SUBJECT_AT_MAX_AGE_MS = 240000;

async function capMintSubjectTokens(withSso, force = false) {
  const mintKind = classifyMint(
    __VU_STATE, Date.now(), CAP_SUBJECT_AT_MAX_AGE_MS);
  if (!force
      && mintKind === 'fresh'
      && (!withSso || __VU_STATE.ssoDeviceSecret)) {
    return;
  }
  const user = selectedUser(false);
  const v = capVector();
  const request = await requestObject(
    secrets.clients.oidc, v.oidc_state, v.oidc_nonce, v.oidc_code_challenge, null,
    withSso ? 'openid profile offline_access device_sso' : null);
  const parResponse = http.post(
    `${BASE_URL}/par`,
    form({ client_id: secrets.clients.oidc, client_secret: secrets.client_secret, request }),
    formHeaders({}, requestTags('cap_bootstrap', { endpoint: '/par' })),
  );
  if (parResponse.status !== 201) {
    fail(`cap bootstrap PAR failed: ${parResponse.status} ${parResponse.body}`);
  }
  const requestId = authorizePar(secrets.clients.oidc, parResponse.json('request_uri'), user, true);
  if (!requestId) {
    fail('cap bootstrap authorize failed');
  }
  const code = approveAuthorization(requestId, v.oidc_state);
  const tokens = tokenAuthorizationCode(v, code);
  __VU_STATE.subjectAt = tokens.access_token;
  __VU_STATE.subjectAtMintedAt = Date.now();
  capSubjectEvent(
    mintKind === 'initial_mint' ? 'initial_mint' : 'expired_reauth');
  if (tokens.refresh_token) {
    __VU_STATE.refreshToken = tokens.refresh_token;
  }
  if (withSso) {
    __VU_STATE.ssoIdToken = tokens.id_token;
    __VU_STATE.ssoDeviceSecret = tokens.device_secret;
    if (!__VU_STATE.ssoIdToken || !__VU_STATE.ssoDeviceSecret) {
      fail('cap bootstrap did not return id_token/device_secret');
    }
  }
}

function capUserinfoOp() {
  const response = http.get(
    `${BASE_URL}/userinfo`,
    {
      headers: tenantHeaders({ Authorization: `Bearer ${__VU_STATE.subjectAt}` }),
      redirects: 0,
      tags: requestTags('userinfo', { endpoint: '/userinfo', subject_token: 'access_token' }),
    },
  );
  return checkErr(response, {
    'userinfo status is 200': (r) => r.status === 200,
    'userinfo subject returned': (r) => Boolean(r.json('sub')),
  });
}

function capClientCredentialsOp() {
  const response = http.post(
    `${BASE_URL}/token`,
    form({
      grant_type: 'client_credentials',
      client_id: secrets.clients.client_credentials,
      client_secret: secrets.client_secret,
      scope: 'profile',
    }),
    formHeaders({}, requestTags('token_client_credentials', {
      endpoint: '/token', grant_type: 'client_credentials', client_auth: 'client_secret_post',
    })),
  );
  return checkErr(response, { 'client_credentials status is 200': (r) => r.status === 200 });
}

function capAuthorizationCodeOp() {
  const user = selectedUser(false);
  const v = capVector();
  return (async () => {
    const requestUri = await oidcPar(v);
    const requestId = authorizePar(secrets.clients.oidc, requestUri, user, true);
    if (!requestId) {
      fail('cap authorize failed');
    }
    const code = approveAuthorization(requestId, v.oidc_state);
    const tokens = tokenAuthorizationCode(v, code);
    return Boolean(tokens && tokens.access_token);
  })();
}

async function capRefreshOp() {
  if (!__VU_STATE.refreshToken) {
    if (capPhase() === 'measure') {
      // Measurement must only rotate: re-minting would mix bootstrap SQL into
      // the measured statement window. A missing family mid-measure is a
      // local no-request failure — no HTTP request is sent, so it must never
      // be read as a successful or HTTP-rejected operation.
      return { capOutcome: 'local_no_request' };
    }
    // A dead/rotated family must not be replayed; mint a fresh one through the
    // real authorization-code flow instead of reusing the seeded token.
    await capMintSubjectTokens(false, true);
  }
  const response = http.post(
    `${BASE_URL}/token`,
    form({
      grant_type: 'refresh_token',
      client_id: secrets.clients.oidc,
      client_secret: secrets.client_secret,
      refresh_token: __VU_STATE.refreshToken,
    }),
    formHeaders({}, requestTags('token_refresh', {
      endpoint: '/token', grant_type: 'refresh_token', client_profile: 'oidc',
    })),
  );
  const ok = checkErr(response, { 'refresh status is 200': (r) => r.status === 200 });
  if (response.status === 200 && response.json('refresh_token')) {
    __VU_STATE.refreshToken = response.json('refresh_token');
  } else {
    __VU_STATE.refreshToken = null;
  }
  if (response.status === 200 && adoptSubjectAccessToken(
      __VU_STATE, response.json('access_token'), Date.now())) {
    capSubjectEvent('refresh_update');
  }
  if (ok) {
    return true;
  }
  return {
    capOutcome: classifyError(response) === 'oauth_invalid_grant'
      ? 'expected_rejection' : 'unexpected',
  };
}

function capTokenExchangeOp() {
  const response = http.post(
    `${BASE_URL}/token`,
    form({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      client_id: secrets.clients.oidc,
      client_secret: secrets.client_secret,
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      subject_token: __VU_STATE.subjectAt,
      audience: 'resource://default',
      scope: 'profile',
    }),
    formHeaders({}, requestTags('token_exchange', {
      endpoint: '/token', grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    })),
  );
  return checkErr(response, {
    'token_exchange status is 200': (r) => r.status === 200,
    'token_exchange access token returned': (r) => Boolean(r.json('access_token')),
  });
}

function capNativeSsoOp() {
  const response = http.post(
    `${BASE_URL}/token`,
    form({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      client_id: secrets.clients.oidc,
      client_secret: secrets.client_secret,
      subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
      subject_token: __VU_STATE.ssoIdToken,
      actor_token_type: 'urn:openid:params:token-type:device-secret',
      actor_token: __VU_STATE.ssoDeviceSecret,
      audience: secrets.issuer,
    }),
    formHeaders({}, requestTags('token_native_sso_fresh', {
      endpoint: '/token', grant_type: 'native_sso_fresh',
    })),
  );
  checkErr(response, {
    'native_sso status is 200': (r) => r.status === 200,
    'native_sso device secret returned': (r) => Boolean(r.json('device_secret')),
  });
  const ok = response.status === 200;
  if (ok) {
    if (response.json('device_secret')) {
      __VU_STATE.ssoDeviceSecret = response.json('device_secret');
    }
    if (response.json('id_token')) {
      __VU_STATE.ssoIdToken = response.json('id_token');
    }
  }
  return ok;
}

async function capIntrospectOp() {
  if (!__VU_STATE.refreshToken) {
    await capMintSubjectTokens(false, true);
  }
  const response = http.post(
    `${BASE_URL}/introspect`,
    form({
      token: __VU_STATE.refreshToken,
      client_id: secrets.clients.oidc,
      client_secret: secrets.client_secret,
    }),
    formHeaders({}, requestTags('introspect', {
      endpoint: '/introspect',
      token_type: 'opaque_refresh_token',
      client_profile: 'oidc',
    })),
  );
  return checkErr(response, {
    'cap introspection status is 200': (r) => r.status === 200,
    'cap introspection active': (r) => r.json('active') === true,
  });
}

async function capRevokeOp() {
  if (!__VU_STATE.refreshToken) {
    await capMintSubjectTokens(false, true);
  }
  const doomed = __VU_STATE.refreshToken;
  __VU_STATE.refreshToken = null;
  const response = http.post(
    `${BASE_URL}/revoke`,
    form({
      token: doomed,
      client_id: secrets.clients.oidc,
      client_secret: secrets.client_secret,
    }),
    formHeaders({}, requestTags('revoke', {
      endpoint: '/revoke',
      token_type: 'opaque_refresh_token',
      client_profile: 'oidc',
    })),
  );
  return checkErr(response, {
    'cap revoke status is 200': (r) => r.status === 200,
  });
}

export async function cap_introspect() {
  return capRun(() => capMintSubjectTokens(false), capIntrospectOp);
}

export async function cap_revoke() {
  return capRun(() => capMintSubjectTokens(false), capRevokeOp);
}

export async function cap_client_credentials() {
  await capRun(async () => {}, capClientCredentialsOp);
}

export async function cap_userinfo_pairwise() {
  await capRun(async () => capMintSubjectTokens(false), capUserinfoOp);
}

export async function cap_refresh_token() {
  await capRun(async () => {}, capRefreshOp);
}

export async function cap_token_exchange() {
  await capRun(async () => capMintSubjectTokens(false), capTokenExchangeOp);
}

export async function cap_native_sso_fresh() {
  await capRun(async () => capMintSubjectTokens(true), capNativeSsoOp);
}

// authorization_code capacity: full logged-in PAR->authorize->decision->redeem.
export async function cap_authorization_code() {
  await capRun(async () => {}, capAuthorizationCodeOp);
}

// Synthetic mix: userinfo 30% / client_credentials 25% / authorization_code 15%
// / refresh_token 15% / token_exchange 15%. The native_sso module is disabled
// in the oauth2-baseline perf profile, so the mix stays on enabled grant paths.
async function capMixedOp() {
  const roll = Math.random() * 100;
  if (roll < 30) {
    await capMintSubjectTokens(false);
    return capUserinfoOp();
  }
  if (roll < 55) {
    return capClientCredentialsOp();
  }
  if (roll < 70) {
    return capAuthorizationCodeOp();
  }
  if (roll < 85) {
    return capRefreshOp();
  }
  await capMintSubjectTokens(false);
  return capTokenExchangeOp();
}

export async function cap_mixed() {
  await capRun(async () => {}, capMixedOp);
}


// --- extended endpoint coverage (2026-09-17 methodology round) ---

function sessionGet(path, step, extra = {}) {
  return http.get(
    `${BASE_URL}${path}`,
    {
      headers: tenantHeaders(sessionHeaders()),
      redirects: 0,
      tags: requestTags(step, Object.assign({ endpoint: path }, extra)),
    },
  );
}

function useSession(session) {
  if (!session) {
    fail('required session fixture missing from secrets');
  }
  __VU_STATE.cookieHeader = session.cookie_header;
  __VU_STATE.csrf = session.csrf_token;
}

function capSessionReadsOp() {
  useSession(selectedLoggedInSession());
  const roll = Math.random() * 100;
  if (roll < 22) {
    return checkErr(sessionGet('/auth/me', 'auth_me'), { 'auth_me 200': (r) => r.status === 200 });
  }
  if (roll < 34) {
    return checkErr(sessionGet('/auth/csrf', 'auth_csrf'), { 'auth_csrf 200': (r) => r.status === 200 });
  }
  if (roll < 46) {
    return checkErr(sessionGet('/auth/me/passkeys', 'me_passkeys'), { 'me_passkeys 200': (r) => r.status === 200 });
  }
  if (roll < 60) {
    return checkErr(sessionGet('/auth/me/applications', 'me_applications'), { 'me_applications 200': (r) => r.status === 200 });
  }
  if (roll < 72) {
    return checkErr(sessionGet('/auth/me/federation/links', 'me_federation_links'), { 'me_federation_links 200': (r) => r.status === 200 });
  }
  if (roll < 84) {
    return checkErr(sessionGet('/auth/me/access-requests', 'me_access_requests'), { 'me_access_requests 200': (r) => r.status === 200 });
  }
  if (roll < 94) {
    return checkErr(sessionGet('/auth/me/mtls-trust-requests', 'me_mtls_trust_requests'), { 'me_mtls_trust_requests 200': (r) => r.status === 200 });
  }
  return checkErr(sessionGet(`/check_session/status?client_id=${secrets.clients.oidc}&origin=${encodeURIComponent(secrets.issuer)}&session_state=perf`, 'check_session_status'), { 'check_session_status 200': (r) => r.status === 200 });
}

export async function cap_session_reads() {
  await capRun(async () => {}, capSessionReadsOp);
}

function capAdminReadsOp() {
  useSession(secrets.admin_session);
  const roll = Math.random() * 100;
  if (roll < 18) {
    return checkErr(sessionGet('/admin/users', 'admin_users'), { 'admin_users 200': (r) => r.status === 200 });
  }
  if (roll < 34) {
    return checkErr(sessionGet('/admin/clients', 'admin_clients'), { 'admin_clients 200': (r) => r.status === 200 });
  }
  if (roll < 44) {
    return checkErr(sessionGet('/admin/clients/templates', 'admin_client_templates'), { 'admin_client_templates 200': (r) => r.status === 200 });
  }
  if (roll < 54) {
    return checkErr(sessionGet('/admin/grants', 'admin_grants'), { 'admin_grants 200': (r) => r.status === 200 });
  }
  if (roll < 64) {
    return checkErr(sessionGet('/admin/access-requests', 'admin_access_requests'), { 'admin_access_requests 200': (r) => r.status === 200 });
  }
  if (roll < 74) {
    return checkErr(sessionGet('/admin/mtls-trust-requests', 'admin_mtls_trust_requests'), { 'admin_mtls_trust_requests 200': (r) => r.status === 200 });
  }
  if (roll < 82) {
    return checkErr(sessionGet('/admin/mtls-trust-anchors.pem', 'admin_mtls_trust_anchors'), { 'admin_mtls_trust_anchors 200': (r) => r.status === 200 });
  }
  if (roll < 90) {
    return checkErr(sessionGet('/admin/runtime-modules', 'admin_runtime_modules'), { 'admin_runtime_modules 200': (r) => r.status === 200 });
  }
  if (roll < 96) {
    return checkErr(sessionGet('/admin/federation/providers', 'admin_federation_providers'), { 'admin_federation_providers 200': (r) => r.status === 200 });
  }
  return checkErr(sessionGet('/admin/runtime-modules/events', 'admin_runtime_module_events'), { 'admin_runtime_module_events 200': (r) => r.status === 200 });
}

export async function cap_admin_reads() {
  await capRun(async () => {}, capAdminReadsOp);
}

function scimGet(path, step) {
  return http.get(
    `${BASE_URL}${path}`,
    {
      headers: tenantHeaders({ Authorization: `Bearer ${secrets.scim_token}` }),
      redirects: 0,
      tags: requestTags(step, { endpoint: path }),
    },
  );
}

function capScimReadsOp() {
  const roll = Math.random() * 100;
  if (roll < 20) {
    return checkErr(scimGet('/scim/v2/ServiceProviderConfig', 'scim_spc'), { 'scim_spc 200': (r) => r.status === 200 });
  }
  if (roll < 38) {
    return checkErr(scimGet('/scim/v2/Schemas', 'scim_schemas'), { 'scim_schemas 200': (r) => r.status === 200 });
  }
  if (roll < 52) {
    return checkErr(scimGet('/scim/v2/ResourceTypes', 'scim_resourcetypes'), { 'scim_resourcetypes 200': (r) => r.status === 200 });
  }
  if (roll < 84) {
    return checkErr(scimGet('/scim/v2/Users?count=10', 'scim_users'), { 'scim_users 200': (r) => r.status === 200 });
  }
  return checkErr(scimGet(`/scim/v2/Users/${secrets.scim_user_id}`, 'scim_user'), { 'scim_user 200': (r) => r.status === 200 });
}

export async function cap_scim_reads() {
  await capRun(async () => {}, capScimReadsOp);
}

// /fapi/resource needs a DPoP-bound access token plus a DPoP proof carrying
// the ath hash; mint once per VU through the FAPI client_credentials grant.
async function capMintFapiResourceToken() {
  if (__VU_STATE.fapiAt && Date.now() - (__VU_STATE.fapiAtMintedAt || 0) < 240000) {
    return;
  }
  const assertion = await clientAssertion(secrets.clients.fapi, secrets.issuer, 'fapi-resource-cc', 'PS256');
  const dpop = await dpopProof('POST', `${secrets.issuer}/token`, 'dpop-fapi-resource-token');
  const response = http.post(
    `${BASE_URL}/token`,
    form({
      grant_type: 'client_credentials',
      client_id: secrets.clients.fapi,
      client_assertion_type: secrets.client_assertion_type,
      client_assertion: assertion,
      scope: 'profile',
      resource: 'resource://default',
    }),
    formHeaders({ DPoP: dpop }, requestTags('cap_bootstrap', {
      endpoint: '/token', grant_type: 'client_credentials', client_profile: 'fapi2', sender_constraint: 'dpop',
    })),
  );
  if (!checkErr(response, { 'fapi resource token bootstrap 200': (r) => r.status === 200 })) {
    fail(`fapi resource token bootstrap failed: ${response.status} ${response.body}`);
  }
  __VU_STATE.fapiAt = response.json('access_token');
  __VU_STATE.fapiAtMintedAt = Date.now();
}

async function dpopAth(accessToken) {
  const digest = await crypto.subtle.digest('SHA-256', asciiBytes(accessToken).buffer);
  return encoding.b64encode(new Uint8Array(digest), 'rawurl');
}

async function fapiResourceRequest(method, path, step, nonce) {
  const htu = `${secrets.issuer}${path}`;
  const at = __VU_STATE.fapiAt;
  const ath = await dpopAth(at);
  const claims = {
    htm: method,
    htu,
    iat: nowSeconds(),
    jti: uniqueJti(`dpop-${step}`),
    ath,
  };
  if (nonce) {
    claims.nonce = nonce;
  }
  const proof = await signEs256({ typ: 'dpop+jwt', jwk: secrets.dpop_public_jwk }, claims);
  const params = {
    headers: tenantHeaders({
      Authorization: `DPoP ${at}`,
      DPoP: proof,
      'Content-Type': 'application/json',
    }),
    redirects: 0,
    tags: requestTags(step, { endpoint: path }),
  };
  return method === 'GET'
    ? http.get(`${BASE_URL}${path}`, params)
    : http.post(`${BASE_URL}${path}`, '{}', params);
}

async function capFapiResourceOp() {
  await capMintFapiResourceToken();
  const usePost = Math.random() < 0.4;
  const method = usePost ? 'POST' : 'GET';
  const step = usePost ? 'fapi_resource_post' : 'fapi_resource_get';
  let response = await fapiResourceRequest(method, '/fapi/resource', step, null);
  if (response.status === 401) {
    const nonce = response.headers['DPoP-Nonce'] || response.headers['dpop-nonce'];
    if (nonce) {
      response = await fapiResourceRequest(method, '/fapi/resource', step, nonce);
    }
  }
  return checkErr(response, {
    [`${step} 200`]: (r) => r.status === 200 && Boolean(r.json('sub')),
  });
}

export async function cap_fapi_resource() {
  await capRun(async () => {}, capFapiResourceOp);
}

async function capDeviceFlowOp() {
  const session = selectedLoggedInSession();
  const authz = http.post(
    `${BASE_URL}/device_authorization`,
    form({
      client_id: secrets.clients.device,
      client_secret: secrets.client_secret,
      scope: 'openid profile',
    }),
    formHeaders({}, requestTags('device_authorization', {
      endpoint: '/device_authorization', client_profile: 'device',
    })),
  );
  if (!checkErr(authz, {
    'device_authorization 200': (r) => r.status === 200 && Boolean(r.json('device_code')),
  })) {
    return false;
  }
  const userCode = authz.json('user_code');
  const deviceCode = authz.json('device_code');
  useSession(session);
  const view = http.get(
    `${BASE_URL}/device/verification?${form({ user_code: userCode })}`,
    {
      headers: tenantHeaders(sessionHeaders()),
      redirects: 0,
      tags: requestTags('device_verification', { endpoint: '/device/verification' }),
    },
  );
  checkErr(view, { 'device_verification 200': (r) => r.status === 200 });
  const decision = http.post(
    `${BASE_URL}/device/decision`,
    form({ user_code: userCode, decision: 'approve', csrf_token: __VU_STATE.csrf }),
    formHeaders(sessionHeaders(), requestTags('device_decision', {
      endpoint: '/device/decision', decision: 'approve',
    })),
  );
  if (!checkErr(decision, { 'device_decision 200': (r) => r.status === 200 })) {
    return false;
  }
  const token = http.post(
    `${BASE_URL}/token`,
    form({
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      device_code: deviceCode,
      client_id: secrets.clients.device,
      client_secret: secrets.client_secret,
    }),
    formHeaders({}, requestTags('token_device_code', {
      endpoint: '/token', grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    })),
  );
  return checkErr(token, {
    'device token 200': (r) => r.status === 200 && Boolean(r.json('access_token')),
  });
}

export async function cap_device_flow() {
  await capRun(async () => {}, capDeviceFlowOp);
}

async function capCibaFlowOp() {
  useSession(selectedLoggedInSession());
  const user = selectedUser(false);
  const authReqId = await cibaBackchannelAuthentication(user);
  approveCiba(authReqId);
  await cibaToken(authReqId);
  return true;
}

export async function cap_ciba_flow() {
  await capRun(async () => {}, capCibaFlowOp);
}

function publicGet(path, step) {
  return http.get(
    `${BASE_URL}${path}`,
    {
      headers: tenantHeaders(),
      redirects: 0,
      tags: requestTags(step, { endpoint: path }),
    },
  );
}

function capPublicReadsOp() {
  const roll = Math.random() * 100;
  if (roll < 16) {
    return checkErr(publicGet('/health', 'health'), { 'health 200': (r) => r.status === 200 });
  }
  if (roll < 30) {
    return checkErr(publicGet('/live', 'live'), { 'live 200': (r) => r.status === 200 });
  }
  if (roll < 42) {
    return checkErr(publicGet('/startup', 'startup'), { 'startup 200': (r) => r.status === 200 });
  }
  if (roll < 56) {
    return checkErr(publicGet('/auth/captcha-config', 'captcha_config'), { 'captcha_config 200': (r) => r.status === 200 });
  }
  if (roll < 72) {
    return checkErr(publicGet('/auth/federation/providers', 'federation_providers'), { 'federation_providers 200': (r) => r.status === 200 });
  }
  if (roll < 88) {
    return checkErr(publicGet('/.well-known/oauth-protected-resource', 'oauth_protected_resource'), { 'opr 200': (r) => r.status === 200 });
  }
  return checkErr(publicGet('/__perf/metrics', 'perf_metrics'), { 'perf_metrics 200': (r) => r.status === 200 });
}

export async function cap_public_reads() {
  await capRun(async () => {}, capPublicReadsOp);
}

// handleSummary writes the k6 summary object to PERF_SUMMARY_EXPORT (the same
// {root_group, metrics, ...} shape --summary-export produces) so tagged
// err_classified subseries survive into the evidence bundle; a dedicated
// err-classification file is written alongside for the runner/report.
export function handleSummary(data) {
  const outputs = {};
  const summaryPath = __ENV.PERF_SUMMARY_EXPORT;
  // Attach the measurement contract only when this scenario really ran the
  // cap-window protocol (cap_window_measure_start_ms gauge emitted). A
  // non-capRun scenario must not carry a contract shell whose bounds are
  // all null — evaluators take a present-but-empty contract as real.
  if ((data.metrics || {}).cap_window_measure_start_ms) {
    data.measurement_contract = contractFromMetrics(data.metrics, {
      warmupMs: CAP_WARMUP_MS,
      measureStartMs: CAP_MEASURE_START_MS,
    });
  }
  if (summaryPath) {
    outputs[summaryPath] = JSON.stringify(data);
  }
  const errPath = __ENV.PERF_ERR_DETAIL;
  if (errPath) {
    const detail = {};
    for (const name of Object.keys(data.metrics || {})) {
      if (name === 'err_classified' || name.startsWith('err_classified{') || name.startsWith('err_cls_')) {
        detail[name] = data.metrics[name].values;
      }
    }
    outputs[errPath] = JSON.stringify(detail, null, 1);
  }
  return outputs;
}
