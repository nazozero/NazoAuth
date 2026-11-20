// Importing this module does not make requests. The caller supplies the same-
// origin, redacting recorder and an explicitly provisioned acceptance account.
import {
  constants, createHash, createPrivateKey, createPublicKey, randomBytes,
  randomUUID, sign, verify,
} from 'node:crypto';

const ensure = (condition, message) => { if (!condition) throw new Error(message); };
const encoded = value => Buffer.from(value).toString('base64url');
const digest = value => createHash('sha256').update(value).digest('base64url');
const userSchema = 'urn:ietf:params:scim:schemas:core:2.0:User';
const patchSchema = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const cibaGrant = 'urn:openid:params:grant-type:ciba';
const eventTypes = [
  'urn:ietf:params:scim:event:prov:create:notice',
  'urn:ietf:params:scim:event:prov:put:notice',
  'urn:ietf:params:scim:event:prov:patch:notice',
  'urn:ietf:params:scim:event:prov:activate',
  'urn:ietf:params:scim:event:prov:deactivate',
  'urn:ietf:params:scim:event:prov:delete',
];
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function signRequest(claims, privateKey, kid) {
  const input = [{ alg: 'ES256', typ: 'oauth-authz-req+jwt', kid }, claims]
    .map(value => encoded(JSON.stringify(value))).join('.');
  return input + '.' + encoded(sign('sha256', Buffer.from(input), {
    key: privateKey, dsaEncoding: 'ieee-p1363',
  }));
}

// SETs intentionally have no exp claim. Validate their own profile instead of
// weakening the access/ID token verifier used by the main acceptance runner.
export function verifyScimSecurityEvent(token, { keys, issuer, audience, id, earliest }) {
  ensure(typeof token === 'string', 'Expected a signed security event');
  const parts = token.split('.');
  ensure(parts.length === 3, 'Expected a compact security event');
  let header;
  let claims;
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url'));
    claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
  } catch { throw new Error('Invalid security event JSON'); }
  ensure(header.typ === 'secevent+jwt' && !header.crit && typeof header.kid === 'string',
    'Invalid security event JOSE profile');
  const algorithms = {
    RS256: 'RSA-SHA256', RS384: 'RSA-SHA384', RS512: 'RSA-SHA512',
    ES256: 'sha256', ES384: 'sha384', ES512: 'sha512', PS256: 'sha256', EdDSA: null,
  };
  ensure(Object.hasOwn(algorithms, header.alg), 'Invalid security event signing algorithm');
  const matches = keys.filter(key => key.kid === header.kid && (!key.alg || key.alg === header.alg));
  ensure(matches.length === 1 && !matches[0].d, 'Missing unambiguous public security event key');
  const key = createPublicKey({ key: matches[0], format: 'jwk' });
  const data = Buffer.from(parts[0] + '.' + parts[1]);
  const signature = Buffer.from(parts[2], 'base64url');
  let options = key;
  if (header.alg.startsWith('ES')) options = { key, dsaEncoding: 'ieee-p1363' };
  if (header.alg === 'PS256') options = { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 };
  ensure(verify(algorithms[header.alg], data, options, signature), 'JWT security event signature verification failed');
  ensure(claims.iss === issuer && Array.isArray(claims.aud) && claims.aud.includes(audience),
    'JWT security event issuer or audience mismatch');
  ensure(uuid.test(claims.jti) && claims.jti === id && uuid.test(claims.txn),
    'JWT security event identity mismatch');
  ensure(Number.isSafeInteger(claims.iat) && claims.iat >= earliest
    && claims.iat <= Math.floor(Date.now() / 1000) + 5, 'JWT security event time is invalid');
  ensure(claims.sub_id?.format === 'scim' && /^\/Users\/[0-9a-f-]{36}$/i.test(claims.sub_id.uri),
    'JWT security event subject is invalid');
  ensure(claims.events && !Array.isArray(claims.events) && typeof claims.events === 'object'
    && Object.keys(claims.events).length > 0
    && Object.keys(claims.events).every(type => eventTypes.includes(type)), 'JWT security event type is invalid');
  return claims;
}

/**
 * Requires the main runner's request/json/step helpers. CIBA mTLS requests opt
 * into the caller's actual certificate-bearing transport with nazo_mtls=true;
 * they never substitute caller-controlled headers for trusted ingress facts.
 * Only newly created synthetic targets and the explicit administrator fixture
 * are mutated. Bodies, issued credentials, codes and event tokens stay local.
 */
export async function publicIdentityServices({
  issuer, input, request, postJson, postForm, json, step, authenticatedForm,
  session, baselineSession, signingKeys, verifyJwt,
}) {
  ensure(typeof request === 'function' && typeof step === 'function', 'Missing identity acceptance recorder');
  ensure(input.administrator?.user_id && input.administrator?.email && session?.cookie && session?.csrf,
    'Missing dedicated identity acceptance administrator');
  const runId = randomUUID();
  const headers = { origin: issuer, cookie: session.cookie, 'x-csrf-token': session.csrf };
  const write = (path, body, method = 'PATCH') => request(path, {
    method, headers: { ...headers, 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  const status = (response, expected) => ensure(response.status === expected,
    `Unexpected HTTP status ${response.status}; expected ${expected}`);
  let administrator;
  const ready = await step('identity_services_administrator_session', async () => {
    administrator = json(await request('/auth/me', { headers: { cookie: session.cookie } }));
    ensure(administrator.id === input.administrator.user_id && administrator.email === input.administrator.email
      && administrator.role === 'admin' && administrator.admin_level >= 2
      && administrator.mfa_enabled === true && !administrator.mfa_required,
    'Session does not belong to the dedicated MFA administrator');
  });
  if (!ready) return;

  await step('authorized_applications_projection', async () => {
    const current = baselineSession || session;
    const account = json(await request('/auth/me', { headers: { cookie: current.cookie } }));
    const applications = json(await request('/auth/me/applications', { headers: { cookie: current.cookie } }));
    ensure(Array.isArray(applications.items) && applications.total === applications.items.length
      && account.authorized_app_count === applications.total, 'Invalid authorized applications projection');
    ensure(applications.items.every(item => typeof item.client_id === 'string'
      && typeof item.client_name === 'string' && Array.isArray(item.last_scopes)
      && Number.isSafeInteger(item.authorization_count) && item.authorization_count > 0
      && Number.isFinite(Date.parse(item.last_authorized_at))), 'Invalid authorized application history');
    status(await request('/auth/me/applications'), 401);
  });

  await step('administrator_user_creation_policy_update_and_deactivation', async () => {
    const email = 'worker-admin-target-' + runId + '@example.com';
    let target;
    let targetPath;
    let disabled = false;
    try {
      target = json(await postJson('/admin/users', { email, password: encoded(randomBytes(36)) }, headers), 201);
      ensure(uuid.test(target.id) && target.id !== administrator.id && target.id !== input.user?.user_id
        && target.email === email && target.role === 'user' && target.is_active === true,
      'Invalid synthetic administrator-created user');
      const path = '/admin/users/' + target.id;
      targetPath = path;
      const raised = json(await write(path, { role: 'admin', admin_level: 1 }));
      ensure(raised.id === target.id && raised.role === 'admin' && raised.admin_level === 1,
        'Invalid administrator role update');
      ensure(json(await write(path, { role: 'admin', admin_level: administrator.admin_level }), 403).error === 'access_denied',
        'Authorization allowed an equal-level administrator assignment');
      const lowered = json(await write(path, { role: 'user', admin_level: 0 }));
      ensure(lowered.id === target.id && lowered.role === 'user', 'Invalid administrator role downgrade');
      const result = json(await write(path, { is_active: false }));
      disabled = result.id === target.id && result.is_active === false;
      ensure(disabled, 'Revocation did not deactivate the synthetic user');
    } finally {
      if (targetPath && !disabled) {
        const result = json(await write(targetPath, { is_active: false }));
        ensure(result.id === target.id && result.is_active === false, 'Revocation failed while cleaning up synthetic user');
      }
    }
  });

  await step('administrator_client_creation_update_and_token_revocation', async () => {
    let client;
    let clientPath;
    let disabled = false;
    try {
      client = json(await postJson('/admin/clients', {
        client_name: 'Worker acceptance admin ' + runId, client_type: 'confidential',
        redirect_uris: [], scopes: ['service'], allowed_audiences: ['resource://default'],
        grant_types: ['client_credentials'], token_endpoint_auth_method: 'client_secret_basic',
      }, headers), 201);
      ensure(client.client_id && client.client_secret && client.is_active === true
        && client.client_name === 'Worker acceptance admin ' + runId,
        'Missing synthetic administrator-created client credentials');
      const path = '/admin/clients/' + encodeURIComponent(client.client_id);
      clientPath = path;
      const read = json(await request(path, { headers: { cookie: session.cookie } }));
      ensure(read.client_id === client.client_id && !read.client_secret, 'Invalid administrator client read projection');
      const updated = json(await write(path, { client_name: 'Worker acceptance updated ' + runId }));
      ensure(updated.client_id === client.client_id && updated.client_name === 'Worker acceptance updated ' + runId,
        'Invalid administrator client update');
      const token = json(await authenticatedForm('/token', client, { grant_type: 'client_credentials', scope: 'service' }));
      verifyJwt(token.access_token, signingKeys, issuer);
      ensure(json(await authenticatedForm('/introspect', client, { token: token.access_token })).active === true,
        'Introspection denied the administrator-created client token');
      const result = json(await write(path, { is_active: false }));
      disabled = result.client_id === client.client_id && result.is_active === false;
      ensure(disabled, 'Revocation did not deactivate the synthetic client');
      ensure(json(await authenticatedForm('/token', client, { grant_type: 'client_credentials', scope: 'service' }), 400).error === 'unauthorized_client',
        'Revocation left the deactivated client authorized to mint tokens');
    } finally {
      if (clientPath && !disabled) {
        const result = json(await write(clientPath, { is_active: false }));
        ensure(result.is_active === false, 'Revocation failed while cleaning up synthetic client');
      }
    }
  });

  if (input.modules?.includes('ciba')) await step('ciba_mtls_signed_request_poll_decisions_and_single_use', async () => {
    ensure(input.dcr_initial_access_token && input.mtls?.subject_dn && input.mtls?.public_jwk
      && input.mtls?.private_key_pem && input.mtls?.certificate_pem && input.mtls?.thumbprint,
    'Missing actual mTLS transport fixture for the native FAPI CIBA profile');
    const privateKey = createPrivateKey(input.mtls.private_key_pem);
    const publicJwk = createPublicKey(privateKey).export({ format: 'jwk' });
    ensure(publicJwk.kty === 'EC' && publicJwk.crv === 'P-256'
      && publicJwk.x === input.mtls.public_jwk.x && publicJwk.y === input.mtls.public_jwk.y,
    'Invalid CIBA signing key fixture');
    publicJwk.kid = 'worker-ciba-' + runId;
    publicJwk.alg = 'ES256';
    publicJwk.use = 'sig';
    const mtlsPost = (path, fields) => request(path, {
      method: 'POST', nazo_mtls: true,
      headers: { origin: issuer, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(fields).toString(),
    });
    let registration;
    let configurationPath;
    try {
      registration = json(await postJson('/register', {
        client_name: 'Worker acceptance CIBA ' + runId, redirect_uris: [], grant_types: [cibaGrant],
        token_endpoint_auth_method: 'tls_client_auth', tls_client_auth_subject_dn: input.mtls.subject_dn,
        tls_client_certificate_bound_access_tokens: true, scope: 'openid profile',
        backchannel_token_delivery_mode: 'poll', backchannel_authentication_request_signing_alg: 'ES256',
        id_token_signed_response_alg: 'ES256', jwks: { keys: [publicJwk] },
      }, { authorization: 'Bearer ' + input.dcr_initial_access_token }), 201);
      const location = new URL(registration.registration_client_uri);
      ensure(location.origin === issuer && location.pathname === '/register/' + encodeURIComponent(registration.client_id)
        && registration.registration_access_token, 'Invalid CIBA client registration');
      configurationPath = location.pathname;
      const clientId = registration.client_id;
      // DCR metadata cannot grant administrator-owned cross-device permission.
      // Give only this newly created client that permission through the normal
      // recent-MFA administrator endpoint before exercising the CIBA protocol.
      const adminPath = '/admin/clients/' + encodeURIComponent(clientId);
      const registeredClient = json(await request(adminPath, { headers: { cookie: session.cookie } }));
      ensure(registeredClient.client_id === clientId
        && registeredClient.client_name === 'Worker acceptance CIBA ' + runId
        && registeredClient.security_policy?.version === 1, 'Invalid CIBA administrator policy projection');
      const admittedClient = json(await write(adminPath, {
        security_policy: { ...registeredClient.security_policy, allow_cross_device_flows: true },
      }));
      ensure(admittedClient.security_policy.allow_cross_device_flows === true,
        'Authorization did not grant the synthetic CIBA client cross-device permission');
      ensure(json(await postForm('/token', { client_id: clientId, grant_type: cibaGrant, auth_req_id: 'not-issued' }), 400).error === 'invalid_client',
        'Authorization admitted mTLS client authentication without a certificate');
      const begin = async () => {
        const now = Math.floor(Date.now() / 1000);
        const object = signRequest({ iss: clientId, aud: issuer, iat: now, nbf: now, exp: now + 120,
          jti: randomUUID(), scope: 'openid profile', login_hint: administrator.email,
          binding_message: 'Workers-' + runId.slice(0, 8), requested_expiry: 300,
        }, privateKey, publicJwk.kid);
        const result = json(await mtlsPost('/bc-authorize', { client_id: clientId, request: object }));
        ensure(result.auth_req_id && result.interval > 0 && result.expires_in > 0, 'Missing CIBA authorization request');
        return result;
      };
      const poll = transaction => mtlsPost('/token', { client_id: clientId, grant_type: cibaGrant, auth_req_id: transaction.auth_req_id });
      const decision = async (transaction, value) => {
        const path = '/auth/ciba/' + encodeURIComponent(transaction.auth_req_id);
        const view = json(await request(path, { headers: { cookie: session.cookie } }));
        ensure(view.auth_req_id === transaction.auth_req_id && view.csrf_token === session.csrf
          && view.request?.client_id === clientId && view.request.scopes.includes('openid'), 'Invalid CIBA verification projection');
        ensure(json(await postJson(path, { decision: value, csrf_token: session.csrf }, headers)).success === true,
          'Consent did not complete the CIBA decision');
      };
      const approved = await begin();
      const initialPolls = await Promise.all([poll(approved), poll(approved)]);
      const pollErrors = initialPolls.map(response => json(response, 400).error).sort();
      ensure(pollErrors.join(',') === 'authorization_pending,slow_down', 'Invalid CIBA pending state or poll throttling');
      await decision(approved, 'approve');
      const token = json(await poll(approved));
      const access = verifyJwt(token.access_token, signingKeys, issuer);
      const identity = verifyJwt(token.id_token, signingKeys, issuer, clientId);
      ensure(identity.sub && access.sub === identity.sub && access.cnf?.['x5t#S256'] === input.mtls.thumbprint,
        'Token CIBA subject or mTLS binding mismatch');
      ensure(json(await mtlsPost('/introspect', { client_id: clientId, token: token.access_token })).active === true,
        'Introspection denied the approved CIBA token');
      const userinfo = json(await request('/userinfo', { nazo_mtls: true,
        headers: { authorization: 'Bearer ' + token.access_token } }));
      ensure(userinfo.sub === identity.sub, 'Token CIBA userinfo subject mismatch');
      ensure(json(await request('/userinfo', { headers: { authorization: 'Bearer ' + token.access_token } }), 401).error === 'invalid_token',
        'Authorization accepted a certificate-bound access token without its certificate');
      ensure(json(await poll(approved), 400).error === 'invalid_grant', 'Replay accepted for consumed CIBA authorization');
      status(await mtlsPost('/revoke', { client_id: clientId, token: token.access_token }), 200);
      const denied = await begin();
      await decision(denied, 'deny');
      ensure(json(await poll(denied), 400).error === 'access_denied', 'Consent denial did not reject CIBA issuance');
    } finally {
      if (configurationPath && registration?.registration_access_token) {
        status(await request(configurationPath, { method: 'DELETE',
          headers: { authorization: 'Bearer ' + registration.registration_access_token } }), 204);
      }
    }
  });

  if (input.modules?.includes('scim')) {
    let subjectId;
    const earliest = Math.floor(Date.now() / 1000) - 5;
    const scimHeaders = { authorization: 'Bearer ' + input.scim?.token, 'content-type': 'application/scim+json' };
    const scimWrite = (path, body, method) => request(path, {
      method, headers: { ...scimHeaders, origin: issuer }, body: JSON.stringify(body),
    });
    const mutationPassed = await step('scim_user_create_replace_patch_deactivate_and_delete', async () => {
      ensure(input.scim?.token, 'Missing dedicated SCIM acceptance credential');
      const discovery = json(await request('/scim/v2/ServiceProviderConfig', { headers: scimHeaders }));
      ensure(discovery.patch?.supported === true, 'Discovery does not advertise SCIM PATCH');
      status(await request('/scim/v2/Users'), 401);
      const email = 'worker-scim-' + runId + '@example.com';
      const metadata = { schemas: [userSchema], userName: email, active: true,
        emails: [{ value: email, primary: true }], name: { givenName: 'Workers', familyName: 'Acceptance' } };
      let deleted = false;
      try {
        const created = json(await postJson('/scim/v2/Users', metadata, scimHeaders), 201);
        ensure(uuid.test(created.id) && created.id !== administrator.id && created.id !== input.user?.user_id
          && created.userName === email && created.active === true,
          'Invalid SCIM-created test subject');
        subjectId = created.id;
        const path = '/scim/v2/Users/' + subjectId;
        const read = json(await request(path, { headers: scimHeaders }));
        ensure(read.id === subjectId && read.userName === email && read.active === true, 'Invalid SCIM user readback');
        const query = new URLSearchParams({ filter: 'userName eq "' + email + '"', count: '10' });
        const listed = json(await request('/scim/v2/Users?' + query, { headers: scimHeaders }));
        ensure(listed.totalResults === 1 && listed.Resources?.[0]?.id === subjectId, 'Invalid SCIM filtered list');
        const replaced = json(await scimWrite(path, { ...metadata, name: { givenName: 'Updated', familyName: 'Acceptance' } }, 'PUT'));
        ensure(replaced.id === subjectId && replaced.name?.givenName === 'Updated', 'Invalid SCIM replacement');
        const patched = json(await scimWrite(path, { schemas: [patchSchema], Operations: [
          { op: 'replace', path: 'active', value: false },
          { op: 'replace', path: 'name.familyName', value: 'Deactivated' },
        ] }, 'PATCH'));
        ensure(patched.id === subjectId && patched.active === false && patched.name?.familyName === 'Deactivated',
          'Revocation did not apply the SCIM deactivation');
        status(await request(path, { method: 'DELETE', headers: scimHeaders }), 204);
        deleted = true;
        status(await request(path, { headers: scimHeaders }), 404);
      } finally {
        if (subjectId && !deleted) status(await request('/scim/v2/Users/' + subjectId, { method: 'DELETE', headers: scimHeaders }), 204);
      }
    });
    if (input.modules.includes('scim_security_events')) await step('scim_security_events_signature_subject_and_ack', async () => {
      ensure(mutationPassed && subjectId && input.scim.audience, 'Missing successful SCIM mutations or event receiver');
      const poll = body => postJson('/scim/v2/SecurityEvents', body, { authorization: scimHeaders.authorization });
      const response = json(await poll({ maxEvents: 100, returnImmediately: true }));
      ensure(response.sets && typeof response.moreAvailable === 'boolean', 'Invalid SCIM security event page');
      const selected = [];
      const observed = new Set();
      for (const [id, token] of Object.entries(response.sets)) {
        const claims = verifyScimSecurityEvent(token, { keys: signingKeys, issuer, audience: input.scim.audience,
          id, earliest: 0 });
        if (claims.sub_id.uri !== '/Users/' + subjectId) continue;
        ensure(claims.iat >= earliest, 'JWT security event predates its test subject');
        selected.push(id);
        for (const type of Object.keys(claims.events)) observed.add(type);
      }
      ensure([eventTypes[0], eventTypes[1], eventTypes[2], eventTypes[4], eventTypes[5]].every(type => observed.has(type)),
        'Missing signed SCIM mutation events for the synthetic subject');
      const acknowledged = json(await poll({ maxEvents: 100, returnImmediately: true, ack: selected }));
      ensure(selected.every(id => !Object.hasOwn(acknowledged.sets, id)), 'Replay returned acknowledged security events');
      const repeated = json(await poll({ maxEvents: 100, returnImmediately: true, ack: selected }));
      ensure(selected.every(id => !Object.hasOwn(repeated.sets, id)), 'Replay returned security events after an idempotent ACK');
    });
  }

  await step('avatar_multipart_upload_binary_read_and_delete', async () => {
    ensure(!administrator.avatar_url, 'Session acceptance administrator already has an avatar');
    const capability = json(await request('/auth/me/avatar/uploads', { headers: { cookie: session.cookie } }));
    ensure(capability.upload_mode === 'multipart', 'Missing multipart avatar storage');
    const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Wl6ZQAAAABJRU5ErkJggg==', 'base64');
    let attempted = false;
    try {
      const body = new FormData();
      body.append('avatar', new Blob([png], { type: 'image/png' }), 'acceptance.png');
      attempted = true;
      const uploaded = json(await request('/auth/me/avatar', { method: 'POST', headers, body }));
      ensure(uploaded.id === administrator.id && uploaded.avatar_url, 'Invalid avatar account projection');
      const read = await request('/auth/me/avatar', { headers: { cookie: session.cookie } });
      status(read, 200);
      ensure(read.headers.get('content-type') === 'image/png' && read.headers.get('x-content-type-options') === 'nosniff'
        && read.headers.get('cache-control')?.includes('no-store') && digest(read.bytes) === digest(png),
      'Invalid avatar binary readback or response protection');
      const deleted = json(await request('/auth/me/avatar', { method: 'DELETE', headers }));
      ensure(deleted.id === administrator.id && !deleted.avatar_url, 'Revocation did not remove the test avatar');
      attempted = false;
      status(await request('/auth/me/avatar', { headers: { cookie: session.cookie } }), 404);
    } finally {
      if (attempted) json(await request('/auth/me/avatar', { method: 'DELETE', headers }));
    }
  });
}
