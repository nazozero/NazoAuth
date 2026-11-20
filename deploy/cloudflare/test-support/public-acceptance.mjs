import {
  constants, createHash, createPrivateKey, createPublicKey, generateKeyPairSync,
  randomBytes, randomUUID, sign, verify,
} from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

const encoded = value => Buffer.from(value).toString('base64url');
const digest = value => createHash('sha256').update(value).digest();
const uuidBytes = value => Buffer.from(value.replaceAll('-', ''), 'hex');
const jwtAssertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const ensure = (value, reason) => { if (!value) throw new Error(reason); };
const publicErrorCodes = new Set([
  'invalid_request', 'invalid_scope', 'invalid_grant', 'invalid_client', 'unauthorized_client',
  'unsupported_grant_type', 'invalid_client_metadata', 'invalid_redirect_uri', 'invalid_target',
  'server_error', 'temporarily_unavailable', 'login_required', 'interaction_required', 'consent_required',
  'use_dpop_nonce', 'invalid_dpop_proof', 'authorization_pending', 'slow_down', 'access_denied',
  'expired_token', 'invalid_request_object', 'invalid_request_uri', 'invalid_token',
]);
function publicErrorCode(text) {
  try {
    const code = JSON.parse(text).error;
    return publicErrorCodes.has(code) ? code : undefined;
  } catch { return undefined; }
}

// The synthetic authenticator belongs to acceptance tests. The server continues
// to parse and verify all WebAuthn messages through the shared nazo-passkey code.
function cborHeader(type, length) {
  if (length < 24) return Buffer.from([(type << 5) | length]);
  if (length < 256) return Buffer.from([(type << 5) | 24, length]);
  const result = Buffer.alloc(3);
  result[0] = (type << 5) | 25;
  result.writeUInt16BE(length, 1);
  return result;
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
  throw new Error('Unsupported synthetic authenticator value');
}

function signJwt(header, claims, key) {
  const input = [header, claims].map(value => encoded(JSON.stringify(value))).join('.');
  let signature;
  if (header.alg === 'ES256') {
    signature = sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' });
  } else if (header.alg === 'RS256') {
    signature = sign('RSA-SHA256', Buffer.from(input), key);
  } else if (header.alg === 'PS256') {
    signature = sign('sha256', Buffer.from(input), {
      key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32,
    });
  } else if (header.alg === 'EdDSA') {
    signature = sign(null, Buffer.from(input), key);
  } else {
    throw new Error('Acceptance input specifies an unsupported assertion algorithm');
  }
  return `${input}.${encoded(signature)}`;
}

function verifyJwt(jwt, keys, issuer, audience) {
  ensure(typeof jwt === 'string', 'Missing signed JWT');
  const parts = jwt.split('.');
  ensure(parts.length === 3, 'Expected a compact signed JWT');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
  const jwk = keys.find(key => key.kid === header.kid && (!key.alg || key.alg === header.alg));
  ensure(jwk, 'JWT key is absent from the public JWKS');
  const key = createPublicKey({ key: jwk, format: 'jwk' });
  const data = Buffer.from(parts[0] + '.' + parts[1]);
  const signature = Buffer.from(parts[2], 'base64url');
  const algorithms = { RS256: 'RSA-SHA256', RS384: 'RSA-SHA384', RS512: 'RSA-SHA512', ES256: 'sha256', ES384: 'sha384', ES512: 'sha512' };
  let valid = false;
  if (header.alg.startsWith('ES') && algorithms[header.alg]) {
    valid = verify(algorithms[header.alg], data, { key, dsaEncoding: 'ieee-p1363' }, signature);
  } else if (header.alg.startsWith('RS') && algorithms[header.alg]) {
    valid = verify(algorithms[header.alg], data, key, signature);
  } else if (header.alg === 'PS256') {
    valid = verify('sha256', data, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature);
  } else if (header.alg === 'EdDSA') {
    valid = verify(null, data, key, signature);
  }
  ensure(valid, 'JWT signature verification failed');
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
  ensure(claims.iss === issuer, 'JWT issuer mismatch');
  ensure(Number.isFinite(claims.exp) && claims.exp > Date.now() / 1000, 'JWT is expired or has no expiry');
  if (audience) ensure([claims.aud].flat().includes(audience), 'JWT audience mismatch');
  return claims;
}

function clientAuthentication(client, issuer) {
  if (client.private_key_jwk) {
    const now = Math.floor(Date.now() / 1000);
    const key = createPrivateKey({ key: client.private_key_jwk, format: 'jwk' });
    return {
      fields: {
        client_id: client.client_id, client_assertion_type: jwtAssertionType,
        client_assertion: signJwt({
          alg: client.algorithm || 'ES256', typ: 'JWT',
          ...(client.private_key_jwk.kid ? { kid: client.private_key_jwk.kid } : {}),
        }, { iss: client.client_id, sub: client.client_id, aud: issuer, iat: now, exp: now + 120, jti: randomUUID() }, key),
      }, headers: {},
    };
  }
  if (client.client_secret) {
    // OAuth HTTP Basic uses form-encoding before joining the credentials.
    const component = value => new URLSearchParams({ value }).toString().slice(6);
    return { fields: {}, headers: { authorization: 'Basic ' + Buffer.from(
      component(client.client_id) + ':' + component(client.client_secret),
    ).toString('base64') } };
  }
  return { fields: { client_id: client.client_id }, headers: {} };
}

export async function runPublicAcceptance(input, fetchRequest = fetch, saveAuthenticator) {
  const origin = new URL(input.issuer);
  ensure(origin.protocol === 'https:' && origin.pathname === '/' && !origin.search && !origin.hash,
    'Acceptance requires a canonical HTTPS issuer origin');
  ensure(!origin.username && !origin.password, 'Issuer must not contain credentials');
  const issuer = origin.origin;
  if (input.workload) {
    ensure(input.private_key_client, 'Missing private-key client for the service workload');
    for (const field of ['requests', 'concurrency']) {
      ensure(input.workload[field] === undefined || (Number.isSafeInteger(input.workload[field]) && input.workload[field] > 0),
        'Invalid service workload size');
    }
  }
  for (const module of input.modules || []) {
    if (['jwt_bearer_grant', 'http_message_signatures'].includes(module)) {
      ensure(input.private_key_client, 'Missing private-key acceptance client for selected module');
    }
    if (module === 'native_sso') {
      ensure(input.browser_client && input.native_sso?.source_client && input.native_sso?.destination_client,
        'Missing Native SSO source or destination acceptance client');
    }
    if (module === 'device_authorization') {
      ensure(input.browser_client && input.device_client, 'Missing Device authorization acceptance client');
    }
    if (module === 'dynamic_client_registration') {
      ensure(input.dcr_initial_access_token, 'Missing dynamic registration initial access token');
    }
  }
  const runId = 'nazo-acceptance-' + randomUUID();
  const startedAt = new Date().toISOString();
  const requests = [];
  const steps = [];
  let signingKeys = [];
  let session;
  let authenticator;
  let http1102 = 0;
  let networkErrors = 0;
  let phase = 'protocol';
  let workload;

  async function persistAuthenticator() {
    if (!saveAuthenticator) return;
    await saveAuthenticator({
      issuer, tenant_id: input.tenant_id, user_id: input.user.user_id,
      credential_id: authenticator.id, counter: authenticator.counter,
      private_key_jwk: authenticator.privateKey.export({ format: 'jwk' }),
    });
  }

  async function request(path, init = {}) {
    ensure(path.startsWith('/') && !path.startsWith('//'), 'Acceptance request must stay on the issuer');
    const started = performance.now();
    const record = { path: path.split('?')[0], method: init.method || 'GET', phase, at: new Date().toISOString() };
    requests.push(record);
    try {
      const response = await fetchRequest(issuer + path, {
        ...init, redirect: 'manual', signal: AbortSignal.timeout(60_000),
        headers: { ...init.headers, 'x-nazo-acceptance': runId, 'x-nazo-acceptance-phase': phase },
      });
      const text = await response.text();
      record.status = response.status;
      if (response.status >= 400) record.oauth_error = publicErrorCode(text);
      record.cf_ray = response.headers.get('cf-ray');
      record.latency_ms = +(performance.now() - started).toFixed(2);
      if (response.status >= 500 && /\b1102\b/.test(text)
        && /(?:Worker exceeded resource limits|error\s*(?:code\s*[:=]?\s*)?1102\b)/i.test(text)) {
        record.cloudflare_error = 1102;
        http1102++;
      }
      // Response bodies can contain credentials. Keep them in memory only and
      // never include them in thrown errors or the acceptance report.
      return { status: response.status, headers: response.headers, text };
    } catch {
      record.latency_ms = +(performance.now() - started).toFixed(2);
      record.network_error = true;
      networkErrors++;
      throw new Error('HTTPS request failed or timed out');
    }
  }
  const json = (response, status = 200) => {
    const code = publicErrorCode(response.text);
    ensure(response.status === status, `Unexpected HTTP status ${response.status}; expected ${status}${code ? '; ' + code : ''}`);
    try { return JSON.parse(response.text); } catch { throw new Error('Response is not valid JSON'); }
  };
  const postJson = (path, body, headers = {}) => request(path, {
    method: 'POST', headers: { 'content-type': 'application/json', origin: issuer, ...headers }, body: JSON.stringify(body),
  });
  const postForm = (path, body, headers = {}) => request(path, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', origin: issuer, ...headers },
    body: new URLSearchParams(body).toString(),
  });
  const authenticatedForm = (path, client, fields, headers = {}) => {
    const auth = clientAuthentication(client, issuer);
    return postForm(path, { ...fields, ...auth.fields }, { ...auth.headers, ...headers });
  };
  async function step(name, run) {
    const started = performance.now();
    try {
      await run();
      steps.push({ name, status: 'passed', duration_ms: +(performance.now() - started).toFixed(2) });
      return true;
    } catch (error) {
      // All errors generated here use fixed descriptions and HTTP status only.
      // Native crypto/JSON exceptions can contain source text, so omit them.
      steps.push({ name, status: 'failed', duration_ms: +(performance.now() - started).toFixed(2),
        reason: error instanceof Error && /^(Unexpected HTTP|Missing |Expected |JWT |HTTPS |Acceptance |Issuer |No |Invalid |Authorization |Consent |Passkey |Replay |Revocation |Logout |Introspection |Token |DPoP |Discovery |Password |Session )/.test(error.message)
          ? error.message : 'Step failed; no response body or secret recorded' });
      return false;
    }
  }
  const cookieSession = response => {
    const cookies = response.headers.getSetCookie();
    ensure(cookies.length === 2, 'Session and CSRF cookies must remain separate');
    const body = json(response);
    ensure(body.csrf_token, 'Session response must include a CSRF token');
    return { cookie: cookies.map(value => value.split(';')[0]).join('; '), csrf: body.csrf_token };
  };

  async function authorize(client, currentSession, { pushed = false, signed = false, requestObject = false, dpopThumbprint, authorizationDetails, scope } = {}) {
    const verifier = encoded(randomBytes(32));
    const state = randomUUID();
    const nonce = randomUUID();
    const redirectUri = client.redirect_uri;
    ensure(typeof redirectUri === 'string', 'Missing registered browser redirect URI');
    let fields = {
      response_type: 'code', client_id: client.client_id, redirect_uri: redirectUri,
      scope: scope || client.scope || 'openid profile email offline_access',
      code_challenge: encoded(digest(verifier)), code_challenge_method: 'S256', state, nonce,
      ...(signed ? { response_mode: 'jwt' } : {}), ...(dpopThumbprint ? { dpop_jkt: dpopThumbprint } : {}),
      ...(authorizationDetails ? { authorization_details: JSON.stringify(authorizationDetails) } : {}),
    };
    if (requestObject) {
      ensure(client.request_private_key_jwk, 'Missing Request Object signing key for acceptance client');
      const now = Math.floor(Date.now() / 1000);
      const key = client.request_private_key_jwk;
      const jwt = signJwt({ alg: key.alg || 'ES256', typ: 'oauth-authz-req+jwt', kid: key.kid }, {
        ...fields, iss: client.client_id, aud: issuer, iat: now, nbf: now, exp: now + 120, jti: randomUUID(),
      }, createPrivateKey({ key, format: 'jwk' }));
      fields = { client_id: client.client_id, response_type: 'code', redirect_uri: redirectUri, state, request: jwt };
    }
    const originalFields = fields;
    if (pushed) {
      const par = json(await authenticatedForm('/par', client, fields), 201);
      ensure(par.request_uri && par.expires_in > 0, 'Missing pushed authorization request');
      fields = { client_id: client.client_id, request_uri: par.request_uri };
    }
    let response = await request('/authorize?' + new URLSearchParams(fields), { headers: { cookie: currentSession.cookie } });
    ensure(response.status === 302, 'Authorization did not redirect');
    let location = new URL(response.headers.get('location'), issuer);
    if (location.pathname === '/consent') {
      const consent = json(await request('/authorize/consent?' + new URLSearchParams({ request_id: location.searchParams.get('request_id') }), {
        headers: { cookie: currentSession.cookie },
      }));
      ensure(consent.client_id === client.client_id && consent.csrf_token === currentSession.csrf, 'Consent identity or CSRF mismatch');
      response = await postForm('/authorize/decision', {
        request_id: consent.request_id, decision: 'approve', csrf_token: currentSession.csrf,
      }, { cookie: currentSession.cookie });
      ensure(response.status === 303, 'Consent did not redirect');
      location = new URL(response.headers.get('location'), issuer);
    }
    ensure(location.origin + location.pathname === new URL(redirectUri).origin + new URL(redirectUri).pathname,
      'Authorization redirect does not match the registered client');
    const result = signed ? verifyJwt(location.searchParams.get('response'), signingKeys, issuer, client.client_id)
      : Object.fromEntries(location.searchParams);
    ensure(result.state === state && result.code, 'Authorization response code or state missing');
    return { code: result.code, verifier, nonce, redirectUri, originalFields,
      sessionState: result.session_state || location.searchParams.get('session_state') };
  }
  const redeem = (client, authorization, headers) => authenticatedForm('/token', client, {
    grant_type: 'authorization_code', code: authorization.code,
    code_verifier: authorization.verifier, redirect_uri: authorization.redirectUri,
  }, headers);
  async function passkeyLogin() {
    const begin = json(await postJson('/auth/passkey/begin', { email: input.user.email }));
    authenticator.counter++;
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(authenticator.counter);
    // Persist the next counter before sending the assertion. A retry after a
    // lost response must not reuse a counter accepted by the remote verifier.
    await persistAuthenticator();
    const data = Buffer.concat([digest(origin.hostname), Buffer.from([0x05]), counter]);
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: begin.publicKey.challenge, origin: issuer, crossOrigin: false }));
    const payload = {
      ceremony_id: begin.ceremony_id,
      response: { id: authenticator.id, rawId: authenticator.id, type: 'public-key', response: {
        authenticatorData: encoded(data), clientDataJSON: encoded(clientData),
        signature: encoded(sign('sha256', Buffer.concat([data, digest(clientData)]), authenticator.privateKey)),
        userHandle: encoded(Buffer.concat([uuidBytes(input.tenant_id), uuidBytes(input.user.user_id)])),
      } },
    };
    const response = await postJson('/auth/passkey/finish', payload);
    const current = cookieSession(response);
    ensure([400, 401].includes((await postJson('/auth/passkey/finish', payload)).status), 'Replay was not rejected by the Passkey protocol');
    const me = json(await request('/auth/me', { headers: { cookie: current.cookie } }));
    ensure(me.email === input.user.email, 'Passkey session belongs to a different user');
    return current;
  }

  const discoveryPassed = await step('discovery_and_jwks', async () => {
    const metadata = json(await request(input.browser_client ? '/.well-known/openid-configuration' : '/.well-known/oauth-authorization-server'));
    ensure(metadata.issuer === issuer, 'Discovery issuer mismatch');
    const jwksUrl = new URL(metadata.jwks_uri);
    ensure(jwksUrl.origin === issuer, 'Discovery JWKS leaves the issuer');
    signingKeys = json(await request(jwksUrl.pathname)).keys;
    ensure(Array.isArray(signingKeys) && signingKeys.length && signingKeys.every(key => !key.d), 'Invalid public JWKS');
    const disabled = await postJson('/auth/login', {});
    ensure(disabled.status === 404, 'Password login should be disabled in the selected Free profile');
  });

  const serviceClient = input.service_client || input.private_key_client;
  if (discoveryPassed && serviceClient) await step('client_credentials_introspection_and_revocation', async () => {
    const client = serviceClient;
    const token = json(await authenticatedForm('/token', client, { grant_type: 'client_credentials', scope: client.scope || 'service' }));
    verifyJwt(token.access_token, signingKeys, issuer);
    const active = json(await authenticatedForm('/introspect', client, { token: token.access_token }));
    ensure(active.active === true, 'Introspection must accept the issued service token');
    ensure((await authenticatedForm('/revoke', client, { token: token.access_token, token_type_hint: 'access_token' })).status === 200,
      'Revocation failed for the service token');
    ensure(json(await authenticatedForm('/introspect', client, { token: token.access_token })).active === false,
      'Revocation did not make the service token inactive');
  });

  if (discoveryPassed && input.private_key_client) await step('private_key_jwt_and_assertion_replay', async () => {
    const client = input.private_key_client;
    const auth = clientAuthentication(client, issuer);
    const body = { grant_type: 'client_credentials', scope: client.scope || 'service', ...auth.fields };
    const token = json(await postForm('/token', body));
    verifyJwt(token.access_token, signingKeys, issuer);
    const replay = await postForm('/token', body);
    ensure(json(replay, 400).error === 'invalid_client', 'Replay accepted for private_key_jwt assertion');
    ensure((await authenticatedForm('/revoke', client, { token: token.access_token, token_type_hint: 'access_token' })).status === 200,
      'Revocation failed for private_key_jwt token');
  });

  if (discoveryPassed && input.modules?.includes('dynamic_client_registration')) {
    await step('dynamic_registration_policy_rotation_and_deactivation', async () => {
      const metadata = {
        client_name: 'Worker acceptance ' + runId, redirect_uris: [], response_types: [],
        grant_types: ['client_credentials'], token_endpoint_auth_method: 'client_secret_basic', scope: 'service',
      };
      const initialHeaders = { authorization: 'Bearer ' + input.dcr_initial_access_token };
      const configurationPath = registration => {
        const uri = new URL(registration.registration_client_uri);
        ensure(uri.origin === issuer && uri.pathname.startsWith('/register/'), 'Invalid client configuration URI');
        return uri.pathname;
      };
      const deleteRegistration = registration => request(configurationPath(registration), {
        method: 'DELETE', headers: { authorization: 'Bearer ' + registration.registration_access_token },
      });
      const rejected = async (body, expectedStatus, headers = initialHeaders) => {
        const response = await postJson('/register', body, headers);
        if (response.status === 201) {
          // Even a policy failure only creates test-owned metadata. Retire it
          // before reporting the unexpected admission.
          const unexpected = json(response, 201);
          if (unexpected.registration_access_token) await deleteRegistration(unexpected);
        }
        const error = json(response, expectedStatus);
        ensure(error.error === (expectedStatus === 401 ? 'invalid_token' : 'invalid_client_metadata')
          && !error.client_id && !error.registration_access_token, 'Authorization admitted unsupported client metadata');
      };
      await rejected({ ...metadata, client_name: metadata.client_name + ' no-iat' }, 401, {});
      for (const [name, unsupported] of [
        ['remote-jwks', { jwks_uri: 'https://unconfigured-acceptance.example/jwks.json' }],
        ['backchannel', { backchannel_logout_uri: 'https://unconfigured-acceptance.example/logout' }],
        ['mtls', { token_endpoint_auth_method: 'tls_client_auth', tls_client_auth_subject_dn: 'CN=acceptance' }],
        ['grant', { grant_types: ['urn:openid:params:grant-type:ciba'] }],
      ]) {
        await rejected({ ...metadata, ...unsupported, client_name: metadata.client_name + ' ' + name }, 400);
      }
      let registration = json(await postJson('/register', metadata, initialHeaders), 201);
      ensure(registration.client_id && registration.client_secret && registration.registration_access_token,
        'Missing issued dynamic client credentials');
      const path = configurationPath(registration);
      let deleted = false;
      try {
        const read = json(await request(path, { headers: { authorization: 'Bearer ' + registration.registration_access_token } }));
        ensure(read.client_id === registration.client_id && read.client_name === metadata.client_name && !read.client_secret,
          'Invalid dynamic client read projection');
        const originalClient = { client_id: registration.client_id, client_secret: registration.client_secret, scope: 'service' };
        const token = json(await authenticatedForm('/token', originalClient, { grant_type: 'client_credentials', scope: 'service' }));
        verifyJwt(token.access_token, signingKeys, issuer);
        ensure(json(await authenticatedForm('/introspect', originalClient, { token: token.access_token })).active === true,
          'Introspection denied dynamically registered service client');
        ensure((await authenticatedForm('/revoke', originalClient, { token: token.access_token })).status === 200,
          'Revocation failed for dynamic client token');
        const oldRegistrationToken = registration.registration_access_token;
        const updated = json(await request(path, {
          method: 'PUT', headers: { ...initialHeaders, authorization: 'Bearer ' + oldRegistrationToken,
            origin: issuer, 'content-type': 'application/json' },
          body: JSON.stringify({ ...metadata, client_id: registration.client_id,
            client_secret: registration.client_secret, client_name: metadata.client_name + ' updated' }),
        }));
        registration = updated;
        ensure(updated.registration_access_token && updated.registration_access_token !== oldRegistrationToken
          && updated.client_secret && updated.client_secret !== originalClient.client_secret,
        'Token registration update did not rotate both credentials');
        ensure((await request(path, { headers: { authorization: 'Bearer ' + oldRegistrationToken } })).status === 401,
          'Replay accepted for a replaced registration access token');
        ensure((await authenticatedForm('/token', originalClient, { grant_type: 'client_credentials', scope: 'service' })).status === 401,
          'Token endpoint accepted the replaced dynamic client secret');
        const currentClient = { client_id: updated.client_id, client_secret: updated.client_secret, scope: 'service' };
        const current = json(await authenticatedForm('/token', currentClient, { grant_type: 'client_credentials', scope: 'service' }));
        verifyJwt(current.access_token, signingKeys, issuer);
        ensure((await deleteRegistration(registration)).status === 204, 'Revocation failed for dynamic client registration');
        deleted = true;
        ensure((await request(path, { headers: { authorization: 'Bearer ' + registration.registration_access_token } })).status === 401,
          'Revocation left the dynamic client configuration active');
        ensure(json(await authenticatedForm('/token', currentClient, { grant_type: 'client_credentials', scope: 'service' }), 400).error === 'unauthorized_client',
          'Token endpoint accepted a deactivated dynamic client');
      } finally {
        if (!deleted) ensure((await deleteRegistration(registration)).status === 204, 'Revocation failed while cleaning up dynamic acceptance client');
      }
    });
  }

  if (discoveryPassed && input.private_key_client && input.modules?.includes('jwt_bearer_grant')) {
    await step('jwt_bearer_grant_single_use_and_subject_binding', async () => {
      const client = input.private_key_client;
      const now = Math.floor(Date.now() / 1000);
      const signingKey = createPrivateKey({ key: client.private_key_jwk, format: 'jwk' });
      const grant = subject => signJwt({ alg: client.algorithm || 'ES256', kid: client.private_key_jwk.kid,
        typ: 'oauth-jwt-bearer+jwt' }, {
        iss: client.client_id, sub: subject, aud: issuer, iat: now, exp: now + 120, jti: randomUUID(),
      }, signingKey);
      const grantAssertion = grant(client.client_id);
      const fields = { grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: grantAssertion, scope: client.scope || 'service' };
      const results = await Promise.all(Array.from({ length: 4 }, () => authenticatedForm('/token', client, fields)));
      ensure(results.filter(response => response.status === 200).length === 1 && results.every(response => [200, 400].includes(response.status)),
        'Replay race did not have exactly one JWT bearer grant winner');
      const token = json(results.find(response => response.status === 200));
      ensure(verifyJwt(token.access_token, signingKeys, issuer).sub === client.client_id && !token.refresh_token,
        'Token from JWT bearer grant has the wrong subject or lifetime class');
      const wrongSubject = grant('different-acceptance-client');
      ensure(json(await authenticatedForm('/token', client, { ...fields, assertion: wrongSubject }), 400).error === 'invalid_grant',
        'Token grant accepted a foreign asserted subject');
      ensure((await authenticatedForm('/revoke', client, { token: token.access_token })).status === 200,
        'Revocation failed for JWT bearer grant');
    });
  }

  if (discoveryPassed && serviceClient && input.modules?.includes('token_exchange')) {
    await step('token_exchange_target_scope_and_revocation', async () => {
      const client = input.exchange_client || serviceClient;
      const original = json(await authenticatedForm('/token', client, { grant_type: 'client_credentials', scope: client.scope || 'service' }));
      const originalClaims = verifyJwt(original.access_token, signingKeys, issuer);
      const fields = { grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        subject_token: original.access_token, subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        resource: client.resource || 'resource://default', scope: client.scope || 'service' };
      const exchanged = json(await authenticatedForm('/token', client, fields));
      const claims = verifyJwt(exchanged.access_token, signingKeys, issuer, fields.resource);
      ensure(exchanged.issued_token_type === 'urn:ietf:params:oauth:token-type:access_token' && !exchanged.refresh_token,
        'Token exchange returned an unexpected token type');
      ensure(claims.sub === originalClaims.sub, 'Token exchange changed the local subject');
      ensure(json(await authenticatedForm('/token', client, { ...fields, scope: fields.scope + ' ungranted-acceptance-scope' }), 400).error === 'invalid_scope',
        'Token exchange allowed scope escalation');
      ensure(json(await authenticatedForm('/token', client, { ...fields, resource: 'https://unregistered-acceptance.example' }), 400).error === 'invalid_target',
        'Token exchange allowed an unregistered target');
      ensure((await authenticatedForm('/revoke', client, { token: original.access_token })).status === 200, 'Revocation failed before exchange rejection');
      ensure(json(await authenticatedForm('/token', client, fields), 400).error === 'invalid_grant', 'Token exchange accepted revoked source token');
      ensure((await authenticatedForm('/revoke', client, { token: exchanged.access_token })).status === 200, 'Revocation failed after exchange');
    });
  }

  if (discoveryPassed && input.private_key_client && input.modules?.includes('http_message_signatures')) {
    await step('http_message_request_response_signatures_and_replay', async () => {
      const client = input.private_key_client;
      ensure((client.algorithm || 'ES256') === 'ES256', 'Acceptance HTTP signature fixture requires a P-256 key');
      const token = json(await authenticatedForm('/token', client, { grant_type: 'client_credentials', scope: client.scope || 'service' }));
      const authorization = 'Bearer ' + token.access_token;
      const target = issuer + '/fapi/resource';
      const params = `("@method" "@target-uri" "authorization");created=${Math.floor(Date.now() / 1000)};keyid="${client.private_key_jwk.kid}";alg="ecdsa-p256-sha256";tag="fapi-2-request"`;
      const signatureBase = `"@method": GET\n"@target-uri": ${target}\n"authorization": ${authorization}\n"@signature-params": ${params}`;
      const key = createPrivateKey({ key: client.private_key_jwk, format: 'jwk' });
      const signature = sign('sha256', Buffer.from(signatureBase), { key, dsaEncoding: 'ieee-p1363' }).toString('base64');
      const headers = { authorization, 'signature-input': 'sig1=' + params, signature: `sig1=:${signature}:` };
      const response = await request('/fapi/resource', { headers });
      ensure(response.status === 200, 'Token protected resource rejected a valid HTTP message signature');
      const contentDigest = `sha-256=:${digest(response.text).toString('base64')}:`;
      ensure(response.headers.get('content-digest') === contentDigest, 'Invalid signed response content digest');
      const returnedInput = response.headers.get('signature-input');
      const returnedSignature = response.headers.get('signature');
      ensure(returnedInput && returnedSignature, 'Missing signed resource response headers');
      const returnedParams = returnedInput.slice(returnedInput.indexOf('=') + 1);
      const components = returnedParams.slice(1, returnedParams.indexOf(')')).match(/"[^"]+"(?:;req)?/g);
      const mandatory = ['"@status"', '"content-digest"', '"content-type"', '"x-fapi-interaction-id"',
        '"@method";req', '"@target-uri";req', '"signature-input";req', '"signature";req'];
      ensure(components && mandatory.every(component => components.includes(component)),
        'Missing mandatory signed response components');
      const derived = { '"@status"': String(response.status), '"@method";req': 'GET', '"@target-uri";req': target };
      const base = components.map(component => {
        const field = /^"([^"@]+)"(;req)?$/.exec(component);
        const value = derived[component] ?? (field
          ? field[2] ? headers[field[1]] : response.headers.get(field[1]) : undefined);
        ensure(typeof value === 'string' && value.length > 0, 'Invalid signed response component');
        return `${component}: ${value}`;
      }).concat(`"@signature-params": ${returnedParams}`).join('\n');
      const kid = /;keyid="([^"]+)"/.exec(returnedParams)?.[1];
      const alg = /;alg="([^"]+)"/.exec(returnedParams)?.[1];
      const publicKey = createPublicKey({ key: signingKeys.find(key => key.kid === kid), format: 'jwk' });
      ensure(['ed25519', 'ecdsa-p256-sha256', 'rsa-v1_5-sha256', 'rsa-pss-sha512'].includes(alg), 'Invalid signed response algorithm');
      const options = alg === 'ecdsa-p256-sha256' ? { key: publicKey, dsaEncoding: 'ieee-p1363' }
        : alg === 'rsa-pss-sha512' ? { key: publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 64 } : publicKey;
      ensure(verify(alg === 'ed25519' ? null : alg === 'rsa-pss-sha512' ? 'sha512' : 'sha256', Buffer.from(base), options,
        Buffer.from(/=:(.+):/.exec(returnedSignature)?.[1] || '', 'base64')), 'Invalid HTTP response signature');
      ensure((await request('/fapi/resource', { headers })).status === 401, 'Replay accepted for HTTP message signature');
      ensure((await authenticatedForm('/revoke', client, { token: token.access_token })).status === 200, 'Revocation failed after signed resource access');
    });
  }

  if (discoveryPassed && input.browser_client) {
    await step('same_origin_browser_pages_and_token_preflight', async () => {
      for (const path of ['/auth', '/auth/setup', '/consent']) {
        const page = await request(path);
        ensure(page.status === 200 && page.headers.get('content-type')?.includes('text/html')
          && page.headers.get('cache-control') === 'no-store'
          && page.headers.get('content-security-policy')?.includes("frame-ancestors 'none'"),
        'Invalid browser page response or security policy');
      }
      const preflight = await request('/token', { method: 'OPTIONS', headers: { origin: issuer,
        'access-control-request-method': 'POST', 'access-control-request-headers': 'content-type,dpop' } });
      ensure(preflight.status === 204 && preflight.headers.get('access-control-allow-origin') === issuer,
        'Authorization token preflight rejected the configured issuer origin');
    });
    const enrolled = await step(input.authenticator ? 'synthetic_passkey_login_with_existing_credential' : 'synthetic_passkey_enrollment_and_login', async () => {
      ensure(input.user?.user_id && input.user?.email && input.tenant_id,
        'Missing dedicated acceptance user input');
      if (input.authenticator) {
        const saved = input.authenticator;
        ensure(saved.issuer === issuer && saved.tenant_id === input.tenant_id && saved.user_id === input.user.user_id,
          'Passkey state belongs to a different issuer or acceptance identity');
        ensure(typeof saved.credential_id === 'string' && Number.isSafeInteger(saved.counter) && saved.counter >= 0,
          'Passkey state is malformed');
        authenticator = { id: saved.credential_id, counter: saved.counter,
          privateKey: createPrivateKey({ key: saved.private_key_jwk, format: 'jwk' }) };
        session = await passkeyLogin();
        return;
      }
      ensure(input.enrollment?.token, 'Missing dedicated acceptance enrollment ticket');
      const initial = cookieSession(await request('/auth/setup/claim', {
        method: 'POST', headers: { origin: issuer, authorization: 'Bearer ' + input.enrollment.token },
      }));
      ensure((await request('/auth/me', { headers: { cookie: initial.cookie } })).status === 401,
        'Session for enrollment must not authorize ordinary login');
      ensure((await request('/auth/setup/claim', {
        method: 'POST', headers: { origin: issuer, authorization: 'Bearer ' + input.enrollment.token },
      })).status === 403, 'Replay accepted for enrollment ticket');
      const begin = json(await postJson('/auth/me/passkeys/registration/begin', { label: runId }, {
        cookie: initial.cookie, 'x-csrf-token': initial.csrf,
      }));
      const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const jwk = pair.publicKey.export({ format: 'jwk' });
      const credentialId = randomBytes(32);
      authenticator = { id: encoded(credentialId), privateKey: pair.privateKey, counter: 0 };
      const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
      const data = Buffer.concat([digest(origin.hostname), Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16),
        Buffer.from([0, credentialId.length]), credentialId, cose]);
      const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: begin.publicKey.challenge, origin: issuer, crossOrigin: false }));
      const payload = { ceremony_id: begin.ceremony_id, response: {
        id: authenticator.id, rawId: authenticator.id, type: 'public-key', response: {
          clientDataJSON: encoded(clientData), attestationObject: encoded(cbor(new Map([
            ['fmt', 'none'], ['authData', data], ['attStmt', new Map()],
          ]))),
        },
      } };
      ensure(json(await postJson('/auth/me/passkeys/registration/finish', payload, {
        cookie: initial.cookie, 'x-csrf-token': initial.csrf,
      }), 201).credential_id === authenticator.id, 'Passkey registration returned a different credential');
      await persistAuthenticator();
      ensure([400, 401, 409].includes((await postJson('/auth/me/passkeys/registration/finish', payload, {
        cookie: initial.cookie, 'x-csrf-token': initial.csrf,
      })).status), 'Replay was not rejected by the Passkey registration protocol');
      session = await passkeyLogin();
    });
    if (enrolled) {
      await step('profile_update_validation_and_csrf', async () => {
        const before = json(await request('/auth/me', { headers: { cookie: session.cookie } }));
        const patch = (body, csrf = session.csrf) => request('/auth/me', {
          method: 'PATCH', headers: { origin: issuer, cookie: session.cookie,
            'x-csrf-token': csrf, 'content-type': 'application/json' }, body: JSON.stringify(body),
        });
        ensure(json(await patch({ display_name: 'not-authorized' }, 'incorrect-csrf'), 400).error === 'invalid_request',
          'Session profile update accepted a wrong CSRF token');
        const changed = json(await patch({ display_name: 'Worker acceptance', locale: 'en-US', zoneinfo: 'Asia/Shanghai' }));
        ensure(changed.id === before.id && changed.email === before.email && changed.display_name === 'Worker acceptance',
          'Session profile update changed identity or lost the requested profile');
        ensure((await patch({ zoneinfo: 'Invalid/Acceptance_Zone' })).status === 400,
          'Invalid profile timezone was accepted');
        const current = json(await request('/auth/me', { headers: { cookie: session.cookie } }));
        ensure(current.display_name === 'Worker acceptance' && current.zoneinfo === 'Asia/Shanghai',
          'Invalid profile update changed persisted data');
      });
      await step('authorization_code_pkce_userinfo_refresh_revocation', async () => {
        const client = input.browser_client;
        const auth = await authorize(client, session);
        const token = json(await redeem(client, auth));
        const id = verifyJwt(token.id_token, signingKeys, issuer, client.client_id);
        ensure(id.nonce === auth.nonce, 'JWT ID token nonce mismatch');
        verifyJwt(token.access_token, signingKeys, issuer);
        const user = json(await request('/userinfo', { headers: { authorization: 'Bearer ' + token.access_token } }));
        ensure(user.sub === id.sub, 'JWT subject differs from UserInfo');
        if ((client.scope || 'openid profile email offline_access').split(' ').includes('email')) {
          ensure(user.email === input.user.email, 'Token returned a different UserInfo identity');
        }
        const rotated = json(await authenticatedForm('/token', client, { grant_type: 'refresh_token', refresh_token: token.refresh_token }));
        ensure(rotated.refresh_token && rotated.refresh_token !== token.refresh_token, 'Token refresh did not rotate');
        ensure((await authenticatedForm('/revoke', client, { token: rotated.access_token, token_type_hint: 'access_token' })).status === 200, 'Revocation failed');
        ensure((await request('/userinfo', { headers: { authorization: 'Bearer ' + rotated.access_token } })).status === 401,
          'Revocation did not deny UserInfo');
        ensure((await redeem(client, auth)).status === 400, 'Replay accepted for authorization code');
      });
      if (input.modules?.includes('request_objects')) await step('par_and_jarm', async () => {
        const auth = await authorize(input.browser_client, session, { pushed: true, signed: input.modules.includes('jarm') });
        const token = json(await redeem(input.browser_client, auth));
        verifyJwt(token.id_token, signingKeys, issuer, input.browser_client.client_id);
      });
      if (input.modules?.includes('request_objects') && input.browser_client.request_private_key_jwk) {
        await step('inline_signed_request_object_and_replay', async () => {
          const client = input.browser_client;
          const authorization = await authorize(client, session, { requestObject: true });
          const token = json(await redeem(client, authorization));
          ensure(verifyJwt(token.id_token, signingKeys, issuer, client.client_id).nonce === authorization.nonce,
            'JWT Request Object nonce did not reach the issued ID token');
          const replay = await request('/authorize?' + new URLSearchParams(authorization.originalFields), {
            headers: { cookie: session.cookie },
          });
          ensure(replay.status === 302, 'Replay of a Request Object did not return an authorization error redirect');
          const location = new URL(replay.headers.get('location'), issuer);
          ensure(location.origin + location.pathname === new URL(client.redirect_uri).origin + new URL(client.redirect_uri).pathname
            && location.searchParams.get('error') === 'invalid_request_object' && !location.searchParams.has('code'),
          'Replay accepted for a signed Request Object');
          ensure((await authenticatedForm('/revoke', client, { token: token.refresh_token, token_type_hint: 'refresh_token' })).status === 200,
            'Revocation failed after inline Request Object');
        });
      }
      if (input.modules?.includes('authorization_details')) await step('rar_consent_token_and_refresh', async () => {
        const client = input.browser_client;
        const details = [{ type: 'account_information', actions: ['read'], locations: ['https://accounts.example'] }];
        const auth = await authorize(client, session, { pushed: input.modules.includes('request_objects'), authorizationDetails: details });
        const token = json(await redeem(client, auth));
        const claims = verifyJwt(token.access_token, signingKeys, issuer);
        ensure(isDeepStrictEqual(token.authorization_details, details) && isDeepStrictEqual(claims.authorization_details, details),
          'Token authorization details changed after consent');
        const refreshed = json(await authenticatedForm('/token', client, { grant_type: 'refresh_token', refresh_token: token.refresh_token }));
        ensure(isDeepStrictEqual(refreshed.authorization_details, details), 'Token refresh lost authorization details');
        ensure((await authenticatedForm('/revoke', client, { token: refreshed.refresh_token, token_type_hint: 'refresh_token' })).status === 200,
          'Revocation failed after RAR refresh');
      });
      await step('concurrent_single_use_code_and_refresh', async () => {
        const client = input.browser_client;
        const concurrency = Math.min(Math.max(input.race_concurrency || 4, 2), 16);
        const code = await authorize(client, session);
        const responses = await Promise.all(Array.from({ length: concurrency }, () => redeem(client, code)));
        ensure(responses.filter(response => response.status === 200).length === 1 && responses.every(response => [200, 400].includes(response.status)),
          'Replay race did not have exactly one successful code redemption');
        const fresh = json(await redeem(client, await authorize(client, session)));
        const refreshes = await Promise.all(Array.from({ length: concurrency }, () => authenticatedForm('/token', client, {
          grant_type: 'refresh_token', refresh_token: fresh.refresh_token,
        })));
        ensure(refreshes.filter(response => response.status === 200).length === 1 && refreshes.every(response => [200, 400].includes(response.status)),
          'Replay race did not have exactly one successful refresh rotation');
      });
      if (input.dpop_client) await step('dpop_nonce_binding_and_replay', async () => {
        const client = input.dpop_client;
        const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
        const jwk = pair.publicKey.export({ format: 'jwk' });
        const jkt = encoded(digest(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })));
        const authorization = await authorize(client, session, { dpopThumbprint: jkt });
        const proof = (method, path, extra = {}) => signJwt({ typ: 'dpop+jwt', alg: 'ES256', jwk }, {
          htm: method, htu: issuer + path, iat: Math.floor(Date.now() / 1000), jti: randomUUID(), ...extra,
        }, pair.privateKey);
        const challenge = await redeem(client, authorization, { dpop: proof('POST', '/token') });
        ensure(json(challenge, 400).error === 'use_dpop_nonce', 'DPoP nonce challenge missing');
        const signed = proof('POST', '/token', { nonce: challenge.headers.get('dpop-nonce') });
        const token = json(await redeem(client, authorization, { dpop: signed }));
        ensure(token.token_type === 'DPoP', 'DPoP token type mismatch');
        ensure((await redeem(client, authorization, { dpop: signed })).status === 400, 'Replay accepted for DPoP token proof');
        ensure((await request('/userinfo', { headers: { authorization: 'Bearer ' + token.access_token } })).status === 401,
          'DPoP-bound token accepted as a bearer token');
        const resourceChallenge = await request('/userinfo', { headers: {
          authorization: 'DPoP ' + token.access_token, dpop: proof('GET', '/userinfo', { ath: encoded(digest(token.access_token)) }),
        } });
        ensure(json(resourceChallenge, 401).error === 'use_dpop_nonce', 'DPoP resource nonce challenge missing');
        const resourceProof = proof('GET', '/userinfo', { ath: encoded(digest(token.access_token)), nonce: resourceChallenge.headers.get('dpop-nonce') });
        json(await request('/userinfo', { headers: { authorization: 'DPoP ' + token.access_token, dpop: resourceProof } }));
        ensure((await request('/userinfo', { headers: { authorization: 'DPoP ' + token.access_token, dpop: resourceProof } })).status === 401,
          'Replay accepted for DPoP resource proof');
      });
      if (input.modules?.includes('device_authorization')) await step('device_pending_slowdown_approval_denial_and_single_use', async () => {
        const client = input.device_client;
        const create = () => authenticatedForm('/device_authorization', client, {
          scope: client.scope || 'openid profile email offline_access', resource: client.resource || 'resource://default',
        });
        const poll = device => authenticatedForm('/token', client, {
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: device.device_code,
        });
        const decision = (device, value, csrf = session.csrf) => postForm('/device/decision', {
          user_code: device.user_code, decision: value, csrf_token: csrf,
        }, { cookie: session.cookie });
        const device = json(await create());
        ensure(device.device_code && device.user_code && device.interval > 0 && device.expires_in > 0,
          'Missing Device authorization response fields');
        const verificationUri = new URL(device.verification_uri_complete);
        ensure(verificationUri.origin === issuer && verificationUri.searchParams.get('user_code') === device.user_code,
          'Invalid Device verification URI');
        const page = await request(verificationUri.pathname + verificationUri.search);
        ensure(page.status === 200 && page.headers.get('content-type')?.includes('text/html'),
          'Authorization Device page did not resolve on the issuer');
        ensure((await request('/device.js')).status === 200, 'Authorization Device page script was unavailable');
        ensure(json(await poll(device), 400).error === 'authorization_pending', 'Token Device grant did not remain pending');
        ensure(json(await poll(device), 400).error === 'slow_down', 'Token Device grant did not enforce polling interval');
        const view = json(await request('/device/verification?' + new URLSearchParams({ user_code: device.user_code }), {
          headers: { cookie: session.cookie },
        }));
        ensure(view.user_code === device.user_code && view.request?.client_id === client.client_id && view.csrf_token === session.csrf,
          'Invalid Device verification view');
        ensure(json(await decision(device, 'approve', 'incorrect-csrf'), 400).error === 'invalid_request',
          'Session Device decision accepted a wrong CSRF token');
        ensure((await decision(device, 'approve')).status === 200, 'Authorization Device approval failed');
        const results = await Promise.all(Array.from({ length: 4 }, () => poll(device)));
        ensure(results.filter(response => response.status === 200).length === 1 && results.every(response => [200, 400].includes(response.status)),
          'Replay race did not have exactly one Device grant winner');
        const token = json(results.find(response => response.status === 200));
        const id = verifyJwt(token.id_token, signingKeys, issuer, client.client_id);
        const user = json(await request('/userinfo', { headers: { authorization: 'Bearer ' + token.access_token } }));
        ensure(user.sub === id.sub && user.email === input.user.email, 'Token Device grant bound a different user');
        ensure((await poll(device)).status === 400, 'Replay accepted for a consumed Device code');
        const denied = json(await create());
        ensure((await decision(denied, 'deny')).status === 200, 'Authorization Device denial failed');
        ensure(json(await poll(denied), 400).error === 'access_denied', 'Token Device grant ignored denial');
        ensure((await authenticatedForm('/revoke', client, { token: token.refresh_token, token_type_hint: 'refresh_token' })).status === 200,
          'Revocation failed after Device grant');
      });
      if (input.modules?.includes('native_sso') && input.native_sso) await step('native_sso_fresh_exchange_and_source_revocation', async () => {
        const { source_client: sourceClient, destination_client: destinationClient } = input.native_sso;
        const authorization = await authorize(sourceClient, session, { scope: 'openid profile email offline_access device_sso' });
        const source = json(await redeem(sourceClient, authorization));
        const sourceClaims = verifyJwt(source.id_token, signingKeys, issuer, sourceClient.client_id);
        ensure(source.device_secret && source.refresh_token && sourceClaims.ds_hash === encoded(digest(source.device_secret)),
          'Token Native SSO device-secret binding missing');
        const fields = { grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange', audience: issuer,
          subject_token: source.id_token, subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
          actor_token: source.device_secret, actor_token_type: 'urn:openid:params:token-type:device-secret',
          scope: 'openid offline_access device_sso' };
        const first = json(await authenticatedForm('/token', destinationClient, fields));
        const second = json(await authenticatedForm('/token', destinationClient, fields));
        ensure(first.device_secret && first.refresh_token && second.refresh_token && first.refresh_token !== second.refresh_token,
          'Token Native SSO exchange did not issue fresh destination credentials');
        const destinationClaims = verifyJwt(first.id_token, signingKeys, issuer, destinationClient.client_id);
        ensure(destinationClaims.sub === sourceClaims.sub, 'Token Native SSO changed the subject');
        ensure(json(await authenticatedForm('/token', destinationClient, { ...fields, actor_token: encoded(randomBytes(32)) }), 400).error === 'invalid_grant',
          'Token Native SSO accepted an unbound device secret');
        ensure((await authenticatedForm('/revoke', sourceClient, { token: source.refresh_token, token_type_hint: 'refresh_token' })).status === 200,
          'Revocation failed for Native SSO source family');
        ensure(json(await authenticatedForm('/token', destinationClient, fields), 400).error === 'invalid_grant',
          'Token Native SSO accepted a revoked source family');
      });
      if (input.modules?.includes('session_management')) await step('session_management_and_rp_initiated_logout', async () => {
        const client = input.browser_client;
        const authorization = await authorize(client, session);
        ensure(authorization.sessionState, 'Session state is missing from authorization response');
        const token = json(await redeem(client, authorization));
        const iframe = await request('/check_session');
        ensure(iframe.status === 200 && iframe.headers.get('cache-control') === 'no-store', 'Session iframe was unavailable or cacheable');
        const statusPath = '/check_session/status?' + new URLSearchParams({
          client_id: client.client_id, origin: new URL(client.redirect_uri).origin, session_state: authorization.sessionState,
        });
        ensure(json(await request(statusPath, { headers: { cookie: session.cookie } })).status === 'unchanged',
          'Session state changed before logout');
        const logout = await postForm('/logout', {
          id_token_hint: token.id_token, ...(client.post_logout_redirect_uri ? { post_logout_redirect_uri: client.post_logout_redirect_uri } : {}),
          state: randomUUID(),
        }, { cookie: session.cookie });
        ensure([200, 302, 303].includes(logout.status) && logout.headers.getSetCookie().some(value => value.includes('Max-Age=0')),
          'Logout did not terminate the OP session');
        if (input.modules.includes('frontchannel_logout') && client.frontchannel_logout_uri) {
          ensure(logout.status === 200 && logout.text.includes(client.frontchannel_logout_uri) && logout.text.includes('sid='),
            'Logout response did not include the registered front-channel RP');
        }
        ensure(json(await request(statusPath, { headers: { cookie: session.cookie } })).status === 'changed',
          'Session state did not change after logout');
        session = await passkeyLogin();
      });
      await step('logout_and_session_invalidation', async () => {
        const response = await request('/auth/logout', { method: 'POST', headers: {
          origin: issuer, cookie: session.cookie, 'x-csrf-token': session.csrf,
        } });
        ensure(response.status === 200 && response.headers.getSetCookie().some(value => value.includes('Max-Age=0')), 'Logout did not clear cookies');
        ensure((await request('/auth/me', { headers: { cookie: session.cookie } })).status === 401, 'Logout did not invalidate the session');
      });
    }
  }

  if (discoveryPassed && input.workload) await step('service_client_credentials_workload', async () => {
    const requested = Math.min(input.workload.requests ?? 128, 256);
    const concurrency = Math.min(input.workload.concurrency ?? 8, 16);
    const warm = Math.min(16, requested);
    const client = input.private_key_client;
    workload = { requested, concurrency, signed_successes: 0, failures: 0, phases: [] };
    for (const [name, count, width] of [
      ['warm_serial', warm, 1], ['concurrent', requested - warm, concurrency],
    ]) {
      if (!count) continue;
      phase = name;
      const started = performance.now();
      const result = { phase: name, requests: count, concurrency: width, signed_successes: 0, failures: 0 };
      let cursor = 0;
      await Promise.all(Array.from({ length: Math.min(width, count) }, async () => {
        while (cursor < count) {
          cursor++;
          try {
            const token = json(await authenticatedForm('/token', client, {
              grant_type: 'client_credentials', scope: client.scope || 'service',
            }));
            verifyJwt(token.access_token, signingKeys, issuer, client.resource);
            result.signed_successes++;
          } catch {
            result.failures++;
          }
        }
      }));
      const phaseRequests = requests.filter(request => request.phase === name);
      result.duration_ms = +(performance.now() - started).toFixed(2);
      result.cloudflare_1102 = phaseRequests.filter(request => request.cloudflare_error === 1102).length;
      result.network_errors = phaseRequests.filter(request => request.network_error).length;
      result.status_counts = {};
      for (const request of phaseRequests) {
        const status = String(request.status || 'network_error');
        result.status_counts[status] = (result.status_counts[status] || 0) + 1;
      }
      workload.signed_successes += result.signed_successes;
      workload.failures += result.failures;
      workload.phases.push(result);
    }
    phase = 'protocol';
    ensure(workload.failures === 0, 'Token workload had failed responses or signature verification');
  });

  const statusCounts = {};
  for (const request of requests) {
    const status = String(request.status || 'network_error');
    statusCounts[status] = (statusCounts[status] || 0) + 1;
  }
  return {
    issuer, run_id: runId, started_at: startedAt, finished_at: new Date().toISOString(),
    authenticator: input.browser_client ? 'synthetic P-256; real-device confirmation remains separate' : 'not used',
    failed: steps.some(step => step.status === 'failed'), steps,
    http: { requests: requests.length, status_counts: statusCounts, cloudflare_1102: http1102, network_errors: networkErrors },
    cpu: { source: 'separate Cloudflare invocation telemetry', measured: false },
    ...(workload ? { workload } : {}),
    requests,
  };
}
