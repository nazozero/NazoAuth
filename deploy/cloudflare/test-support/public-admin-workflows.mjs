// Importing this helper performs no I/O. All HTTP traffic uses the main
// runner's same-origin recorder; credentials and response bodies stay local.
import { createHash, randomUUID, X509Certificate } from 'node:crypto';

const ensure = (value, message) => { if (!value) throw new Error('Acceptance ' + message); };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const fingerprint = pem => createHash('sha256').update(new X509Certificate(pem).raw).digest('hex');

/**
 * session is the dedicated administrator's recent-MFA session;
 * baselineSession belongs to the explicit ordinary input.user fixture.
 * authorize/redeem are the main runner's existing PKCE and consent helpers.
 * Optional input.mtls_trust_anchors contains two distinct, temporary CA public
 * PEMs. This verifies trust management, not Cloudflare client-certificate
 * ingress or a TLS handshake against the D1 trust bundle.
 */
export async function publicAdminWorkflows({
  issuer, input, request, postJson, json, step, authenticatedForm,
  session, baselineSession, signingKeys, verifyJwt, authorize, redeem,
}) {
  ensure(typeof request === 'function' && typeof step === 'function', 'missing administrator workflow recorder');
  const headers = current => ({ origin: issuer, cookie: current.cookie, 'x-csrf-token': current.csrf });
  let admin;
  let user;
  const ready = await step('admin_workflow_identity_guards', async () => {
    ensure(uuid.test(input.administrator?.user_id) && input.administrator?.email
      && uuid.test(input.user?.user_id) && input.user?.email
      && session?.cookie && session?.csrf && baselineSession?.cookie && baselineSession?.csrf
      && input.administrator.user_id !== input.user.user_id,
    'missing distinct dedicated administrator and ordinary user fixtures');
    admin = json(await request('/auth/me', { headers: { cookie: session.cookie } }));
    user = json(await request('/auth/me', { headers: { cookie: baselineSession.cookie } }));
    ensure(admin.id === input.administrator.user_id && admin.email === input.administrator.email
      && admin.role === 'admin' && admin.admin_level >= 1 && admin.mfa_enabled === true
      && admin.mfa_required === false, 'administrator session identity or MFA state differs');
    ensure(user.id === input.user.user_id && user.email === input.user.email && user.role === 'user'
      && user.mfa_required === false && user.id !== admin.id, 'ordinary user session identity differs');
    ensure(typeof authorize === 'function' && typeof redeem === 'function', 'missing shared authorization helpers');
  });
  if (!ready) return;

  const runId = randomUUID();
  const siteName = 'Workers access approval ' + runId;
  const deniedSiteName = 'Workers access rejection ' + runId;
  const clientName = 'Workers approved client ' + runId;
  const redirectUri = 'https://client.example/acceptance/' + runId;
  const userHeaders = headers(baselineSession);
  const adminHeaders = headers(session);
  const getUserRequests = async () => {
    const page = json(await request('/auth/me/access-requests', { headers: userHeaders }));
    ensure(Array.isArray(page.items), 'invalid access request list');
    return page.items;
  };
  const postUser = (path, body) => postJson(path, body, userHeaders);
  const postAdmin = (path, body) => postJson(path, body, adminHeaders);
  const patchClient = (id, body) => request('/admin/clients/' + encodeURIComponent(id), {
    method: 'PATCH', headers: { ...adminHeaders, 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  const ownClient = value => value && typeof value.client_id === 'string'
    && value.client_id.length > 0 && value.client_id.length <= 128 && value.client_name === clientName
    && value.client_type === 'confidential' && value.token_endpoint_auth_method === 'client_secret_basic'
    && value.redirect_uris?.length === 1 && value.redirect_uris[0] === redirectUri;
  const pages = async (path, predicate) => {
    for (let page = 1; page <= 50; page++) {
      const result = json(await request(path + '?' + new URLSearchParams({ page, page_size: 100 }), { headers: adminHeaders }));
      ensure(Array.isArray(result.items) && Number.isSafeInteger(result.total), 'invalid administrator list');
      const found = result.items.filter(predicate);
      ensure(found.length <= 1, 'ambiguous synthetic administrator target');
      if (found.length) return found[0];
      if (page * 100 >= result.total) return undefined;
    }
    throw new Error('Acceptance administrator listing exceeds the fixture bound');
  };
  let client;
  let approvalAttempted = false;
  let requestAttempted = false;
  let trustAttempted = false;
  const metadata = {
    client_name: clientName, client_type: 'confidential', redirect_uris: [redirectUri],
    scopes: ['service', 'offline_access'], allowed_audiences: ['resource://default'],
    grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
    token_endpoint_auth_method: 'client_secret_basic', security_policy: { version: 1 },
  };

  try {
    const delivered = await step('access_request_approval_and_one_time_delivery', async () => {
      const prior = await getUserRequests();
      ensure(!prior.some(value => value.status === 0), 'ordinary fixture already has an unrelated pending request');
      requestAttempted = true;
      const body = { site_name: siteName, site_url: redirectUri, request_description: 'Isolated Workers acceptance request ' + runId };
      const created = json(await postUser('/auth/me/access-requests', body), 201);
      ensure(uuid.test(created.id) && created.site_name === siteName && created.status === 0,
        'invalid newly created access request');
      ensure(json(await postUser('/auth/me/access-requests', body), 409).error === 'invalid_request',
        'duplicate pending access request was admitted');
      const pending = await pages('/admin/access-requests', value => value.id === created.id);
      ensure(pending?.user_id === user.id && pending.site_name === siteName && pending.status === 0,
        'administrator access request projection differs');
      const path = '/admin/access-requests/' + created.id + '/approve';
      ensure((await postUser(path, metadata)).status === 403, 'ordinary user approved an access request');
      ensure((await postJson(path, metadata, { origin: issuer, cookie: session.cookie })).status === 403,
        'access approval accepted missing CSRF proof');
      approvalAttempted = true;
      const approved = json(await postAdmin(path, metadata));
      ensure(approved.id === created.id && approved.user_id === user.id && approved.status === 1
        && uuid.test(approved.approved_client_id) && !Object.hasOwn(approved, 'client_secret'),
      'invalid access approval or credentials disclosed to reviewer');
      const available = (await getUserRequests()).find(value => value.id === created.id);
      ensure(available?.delivery_available === true && available.status === 1,
        'approved access request has no available credential delivery');
      ensure(json(await postAdmin('/auth/me/access-delivery', { request_id: created.id }), 404).error === 'invalid_request',
        'another account consumed the requester credential delivery');
      const receipt = json(await postUser('/auth/me/access-delivery', { request_id: created.id }));
      ensure(ownClient(receipt) && receipt.request_id === created.id && receipt.user_id === user.id
        && typeof receipt.client_secret === 'string' && receipt.client_secret.length > 0
        && typeof receipt.read_once_notice === 'string', 'invalid requester credential delivery');
      client = { ...receipt, redirect_uri: redirectUri, scope: 'service offline_access' };
      ensure(json(await postUser('/auth/me/access-delivery', { request_id: created.id }), 404).error === 'invalid_request',
        'credential delivery replay was accepted');
      ensure((await getUserRequests()).find(value => value.id === created.id)?.delivery_available !== true,
        'consumed credential delivery remains available');
      const view = json(await request('/admin/clients/' + encodeURIComponent(client.client_id), { headers: adminHeaders }));
      ensure(ownClient(view) && view.is_active === true && !Object.hasOwn(view, 'client_secret'),
        'approved client projection or secret visibility differs');
    });
    if (!delivered) return;

    await step('approved_client_tokens_and_administrator_grant_revocation', async () => {
      const serviceToken = json(await authenticatedForm('/token', client, { grant_type: 'client_credentials', scope: 'service' }));
      verifyJwt(serviceToken.access_token, signingKeys, issuer);
      ensure(json(await authenticatedForm('/introspect', client, { token: serviceToken.access_token })).active === true,
        'approved client service token is inactive');
      const authorization = await authorize(client, baselineSession, { scope: 'service offline_access' });
      const tokens = json(await redeem(client, authorization));
      verifyJwt(tokens.access_token, signingKeys, issuer);
      ensure(typeof tokens.refresh_token === 'string' && tokens.refresh_token.length > 0,
        'approved client did not issue a refresh token');
      const grant = await pages('/admin/grants', value => value.client_id === client.client_id && value.user_id === user.id);
      ensure(grant?.email === user.email && grant.client_name === clientName && grant.authorization_count >= 1
        && grant.last_scopes.includes('service'), 'synthetic grant is absent from administrator projection');
      const target = { client_id: client.client_id, user_id: user.id };
      ensure((await postUser('/admin/grants/revoke', target)).status === 403, 'ordinary user reached administrator grant revocation');
      const revoked = json(await postAdmin('/admin/grants/revoke', target));
      ensure(revoked.removed_grants === 1 && revoked.revoked_refresh_tokens >= 1,
        'administrator grant revocation did not remove the synthetic authorization');
      ensure(!await pages('/admin/grants', value => value.client_id === client.client_id && value.user_id === user.id),
        'revoked synthetic grant is still listed');
      ensure(json(await authenticatedForm('/token', client, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token }), 400).error === 'invalid_grant',
        'administrator grant revocation left the refresh token usable');
    });

    await step('access_request_rejection_has_no_credential_delivery', async () => {
      const created = json(await postUser('/auth/me/access-requests', {
        site_name: deniedSiteName, site_url: redirectUri, request_description: 'Isolated rejection case ' + runId,
      }), 201);
      ensure(uuid.test(created.id) && created.site_name === deniedSiteName && created.status === 0,
        'invalid rejection fixture access request');
      const path = '/admin/access-requests/' + created.id + '/reject';
      const denied = json(await postAdmin(path, { admin_note: 'Acceptance rejection ' + runId }));
      ensure(denied.id === created.id && denied.user_id === user.id && denied.status === 2 && denied.approved_client_id === null,
        'access request rejection did not persist');
      ensure(json(await postUser('/auth/me/access-delivery', { request_id: created.id }), 404).error === 'invalid_request',
        'rejected access request exposed credentials');
      ensure(json(await postAdmin(path, { admin_note: 'Repeated rejection' }), 409).error === 'invalid_request',
        'access request rejection replay was accepted');
    });

    if (input.mtls_trust_anchors) await step('owned_mtls_trust_request_review_rejection_revocation_and_export', async () => {
      ensure(Array.isArray(input.mtls_trust_anchors) && input.mtls_trust_anchors.length === 2,
        'mTLS management requires two temporary public CA certificates');
      const certificates = input.mtls_trust_anchors.map(pem => new X509Certificate(pem));
      ensure(certificates.every(value => value.ca && Date.parse(value.validFrom) <= Date.now()
        && Date.parse(value.validTo) > Date.now()), 'mTLS management fixture is not a current CA certificate');
      const fingerprints = input.mtls_trust_anchors.map(fingerprint);
      ensure(new Set(fingerprints).size === 2, 'mTLS management requires different CA fingerprints');
      const updated = json(await patchClient(client.client_id, { require_mtls_bound_tokens: true }));
      ensure(ownClient(updated) && updated.require_mtls_bound_tokens === true, 'owned client mTLS policy was not stored');
      trustAttempted = true;
      const create = async index => {
        const created = json(await postUser('/auth/me/mtls-trust-requests', {
          client_id: client.client_id, certificate_pem: input.mtls_trust_anchors[index],
        }), 201);
        ensure(uuid.test(created.id) && created.client_id === client.client_id && created.user_id === user.id
          && created.status === 0 && created.certificate_sha256 === fingerprints[index], 'invalid owned trust request');
        return created;
      };
      const anchor = await create(0);
      const path = '/admin/mtls-trust-requests/' + anchor.id;
      ensure((await postUser(path + '/approve', {})).status === 403, 'requester approved their trust request');
      const approved = json(await postAdmin(path + '/approve', { admin_note: 'Acceptance CA approval' }));
      ensure(approved.id === anchor.id && approved.status === 1 && approved.resolved_at,
        'independent administrator did not approve the owned CA');
      const rejected = await create(1);
      const denied = json(await postAdmin('/admin/mtls-trust-requests/' + rejected.id + '/reject', { admin_note: 'Acceptance CA rejection' }));
      ensure(denied.id === rejected.id && denied.status === 2, 'CA rejection did not persist');
      const bundle = await request('/admin/mtls-trust-anchors.pem', { headers: adminHeaders });
      ensure(bundle.status === 200 && bundle.headers.get('content-type')?.startsWith('application/x-pem-file')
        && bundle.headers.get('cache-control')?.includes('no-store')
        && bundle.text.includes(approved.certificate_pem) && !bundle.text.includes(rejected.certificate_pem),
      'trust bundle does not distinguish approved and rejected CAs');
      const listed = await pages('/admin/mtls-trust-requests', value => value.id === anchor.id);
      ensure(listed?.status === 1 && listed.client_id === client.client_id, 'approved CA is absent from administrator list');
      const revoked = json(await postAdmin(path + '/revoke', { reason: 'Acceptance CA cleanup' }));
      ensure(revoked.id === anchor.id && revoked.status === 3 && revoked.revoked_at, 'CA revocation did not persist');
      const retiredBundle = await request('/admin/mtls-trust-anchors.pem', { headers: adminHeaders });
      ensure(retiredBundle.status === 200 && !retiredBundle.text.includes(approved.certificate_pem),
        'revoked CA remains in the exported trust bundle');
    });
  } finally {
    // Recover only exact per-run names after a lost response. Never clean up
    // an existing fixture client, another user's grant, or an unrelated request.
    if (approvalAttempted) await step('admin_workflow_client_deactivation', async () => {
      const owned = await pages('/admin/clients', value => value.client_name === clientName);
      if (!owned) {
        const approved = (await getUserRequests()).some(value => value.site_name === siteName && value.status === 1);
        ensure(!client && !approved, 'approved synthetic client is absent from cleanup projection');
        return;
      }
      ensure(ownClient(owned), 'synthetic client cleanup identity differs');
      client ||= owned;
      const disabled = json(await patchClient(owned.client_id, { is_active: false }));
      ensure(ownClient(disabled) && disabled.is_active === false, 'synthetic client deactivation failed');
      if (client.client_secret) ensure(json(await authenticatedForm('/token', client, {
        grant_type: 'client_credentials', scope: 'service',
      }), 400).error === 'unauthorized_client', 'deactivated synthetic client can still issue tokens');
    });
    if (trustAttempted && client) await step('admin_workflow_trust_cleanup', async () => {
      const view = json(await request('/auth/me/mtls-trust-requests', { headers: userHeaders }));
      ensure(Array.isArray(view.items), 'invalid trust cleanup projection');
      for (const anchor of view.items.filter(value => value.client_id === client.client_id)) {
        ensure(uuid.test(anchor.id) && anchor.user_id === user.id, 'trust cleanup owner differs');
        const path = '/admin/mtls-trust-requests/' + anchor.id;
        if (anchor.status === 0) ensure(json(await postAdmin(path + '/reject', { admin_note: 'Acceptance cleanup' })).status === 2,
          'pending trust cleanup failed');
        if (anchor.status === 1) ensure(json(await postAdmin(path + '/revoke', { reason: 'Acceptance cleanup' })).status === 3,
          'approved trust cleanup failed');
      }
    });
    if (requestAttempted) await step('admin_workflow_pending_request_cleanup', async () => {
      const owned = (await getUserRequests()).filter(value => [siteName, deniedSiteName].includes(value.site_name));
      for (const pending of owned.filter(value => value.status === 0)) {
        ensure(uuid.test(pending.id), 'pending cleanup request identity differs');
        const result = json(await postAdmin('/admin/access-requests/' + pending.id + '/reject', { admin_note: 'Acceptance cleanup' }));
        ensure(result.id === pending.id && result.user_id === user.id && result.status === 2, 'pending request cleanup failed');
      }
    });
  }
}
