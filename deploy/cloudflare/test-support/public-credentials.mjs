// Explicitly invoked acceptance wallet; importing this module never makes a
// request. Production signing, proof verification and trust remain in Rust.
import {
  createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey,
  diffieHellman, generateKeyPairSync, randomBytes, randomUUID, sign, verify, X509Certificate,
} from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

const encode = value => Buffer.from(value).toString('base64url');
const sha256 = value => createHash('sha256').update(value).digest();
// These messages are fixed acceptance assertions, never response bodies or
// key material. Keep their safe prefix visible through the runner's redactor.
const ensure = (condition, message) => { if (!condition) throw new Error('Acceptance credentials: ' + message); };
const integer = value => { const bytes = Buffer.alloc(4); bytes.writeUInt32BE(value); return bytes; };
const jsonPart = value => JSON.parse(Buffer.from(value, 'base64url'));
const credentialErrors = new Set([
  'invalid_request', 'invalid_token', 'invalid_grant', 'invalid_client', 'unauthorized_client',
  'invalid_credential_request', 'unknown_credential_configuration', 'unknown_credential_identifier',
  'invalid_proof', 'invalid_nonce', 'invalid_encryption_parameters', 'credential_request_denied',
  'insufficient_scope', 'server_error', 'temporarily_unavailable',
]);
const credentialDescriptions = new Set([
  'Credential request body is malformed.', 'Encrypted credential request is malformed.',
  'Exactly one credential identifier is required.', 'Credential identifier is required for this access token.',
  'Credential identifier is not authorized.', 'Credential configuration is not authorized.',
  'Credential configuration is unknown.', 'Credential proof is missing.', 'Credential proof is invalid.',
  'Credential proof nonce is invalid.', 'Credential holder binding is invalid.',
  'Credential response encryption requires an encrypted request.',
  'Credential request encryption is invalid.', 'Credential response encryption parameters are unsupported.',
  'Credential response encryption key is invalid.', 'Credential issuance is not authorized.',
  'Credential authorization provenance is missing.', 'Access token is revoked.', 'Access token is invalid.',
  'Access token subject is inactive.', 'Credential proof validation is unavailable.', 'Credential issuance failed.',
]);

export function assertCredentialStatus(response, expected) {
  if (response.status === expected) return;
  let body;
  try { body = JSON.parse(response.text); } catch {}
  const safe = [credentialErrors.has(body?.error) && body.error,
    credentialDescriptions.has(body?.error_description) && body.error_description].filter(Boolean);
  ensure(false, `Credential endpoint returned HTTP ${response.status}; expected ${expected}${safe.length ? '; ' + safe.join('; ') : ''}`);
}

export function preAuthorizedCredentialSelector(token, configuration, issuer) {
  // The issuer's opaque token-response identifier is authoritative. A wallet
  // must not reconstruct it or substitute the configuration id when provided.
  const details = token.authorization_details;
  ensure(Array.isArray(details), 'Token response omitted credential authorization details');
  const matches = details.filter(detail => detail.type === 'openid_credential'
    && detail.credential_configuration_id === configuration && detail.locations?.includes(issuer));
  ensure(matches.length === 1 && Array.isArray(matches[0].credential_identifiers)
    && matches[0].credential_identifiers.length === 1
    && typeof matches[0].credential_identifiers[0] === 'string' && matches[0].credential_identifiers[0].length > 0,
  'Token response did not identify one authorized credential for this issuer');
  return { credential_identifier: matches[0].credential_identifiers[0] };
}

// Observe only tokens returned to this explicit acceptance wallet. Keep the
// protocol exchange untouched and retire known tokens through its public API,
// including when issuance or deferred polling fails after a successful grant.
export async function withCredentialTokenCleanup(input, options, run) {
  const request = options.request;
  ensure(typeof request === 'function', 'A same-origin acceptance recorder is required');
  const tokens = new Set();
  const recordedRequest = async (path, init = {}) => {
    const response = await request(path, init);
    if (input.wallet_client_id && init.method === 'POST' && typeof init.body === 'string'
      && response.status === 200) {
      const fields = new URLSearchParams(init.body);
      if (fields.get('client_id') === input.wallet_client_id) {
        if (path === '/token' && fields.get('grant_type') === 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
          let granted;
          try { granted = JSON.parse(response.text); } catch {}
          if (typeof granted?.access_token === 'string' && granted.access_token) tokens.add(granted.access_token);
        } else if (path === '/revoke') tokens.delete(fields.get('token'));
      }
    }
    return response;
  };
  let failed = false;
  try {
    return await run(input, { ...options, request: recordedRequest });
  } catch (error) {
    failed = true;
    throw error;
  } finally {
    let cleanupFailed = false;
    for (const token of tokens) {
      try {
        const response = await request('/revoke', { method: 'POST',
          headers: { origin: input.issuer, 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ client_id: input.wallet_client_id, token, token_type_hint: 'access_token' }).toString() });
        assertCredentialStatus(response, 200);
      } catch { cleanupFailed = true; }
    }
    // Every cleanup attempt still passes through the redacted HTTP recorder.
    // A secondary refusal must not replace the original issuance diagnostic.
    if (cleanupFailed && !failed) ensure(false, 'Credential access token cleanup failed');
  }
}

function signEs256(header, claims, privateKey) {
  const input = [header, claims].map(value => encode(JSON.stringify(value))).join('.');
  return input + '.' + encode(sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' }));
}

export function createCredentialWallet(privateJwk) {
  const privateKey = privateJwk ? createPrivateKey({ key: privateJwk, format: 'jwk' })
    : generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;
  const publicKey = createPublicKey(privateKey);
  const jwk = publicKey.export({ format: 'jwk' });
  ensure(jwk.kty === 'EC' && jwk.crv === 'P-256', 'Acceptance wallet requires P-256');
  return { privateKey, publicKey, jwk };
}

export function credentialProof(wallet, issuer, nonce, clientId) {
  return signEs256({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: wallet.jwk }, {
    aud: issuer, nonce, iat: Math.floor(Date.now() / 1000),
    ...(clientId ? { iss: clientId } : {}),
  }, wallet.privateKey);
}

// Independent client verification pins the explicitly supplied acceptance CA.
// No certificate from a response becomes a trust anchor by being present.
export function verifyCertificateJwt(jwt, { issuer, trustAnchorPem, typ }) {
  const parts = jwt.split('.');
  ensure(parts.length === 3, 'Expected signed compact JWT');
  const header = jsonPart(parts[0]);
  ensure(header.alg === 'ES256' && header.typ === typ, 'Unexpected credential JWT profile');
  ensure(Array.isArray(header.x5c) && header.x5c.length > 0 && header.x5c.length <= 8, 'Missing certificate chain');
  const chain = header.x5c.map(value => new X509Certificate(Buffer.from(value, 'base64')));
  const anchor = new X509Certificate(trustAnchorPem);
  const currentTime = Date.now();
  for (const certificate of [...chain, anchor]) {
    ensure(Date.parse(certificate.validFrom) <= currentTime && currentTime < Date.parse(certificate.validTo), 'Expired or future certificate');
  }
  ensure(chain[0].checkHost(new URL(issuer).hostname, { subject: 'never', wildcards: false }), 'Certificate SAN does not bind the issuer');
  for (let index = 0; index < chain.length - 1; index++) {
    ensure(chain[index + 1].ca && chain[index].checkIssued(chain[index + 1])
      && chain[index].verify(chain[index + 1].publicKey), 'Certificate chain verification failed');
  }
  const last = chain.at(-1);
  ensure(anchor.ca && (last.raw.equals(anchor.raw) || (last.checkIssued(anchor) && last.verify(anchor.publicKey))), 'Certificate chain misses the pinned anchor');
  ensure(verify('sha256', Buffer.from(parts[0] + '.' + parts[1]),
    { key: chain[0].publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(parts[2], 'base64url')), 'Credential JWT signature is invalid');
  const claims = jsonPart(parts[1]);
  const now = currentTime / 1000;
  ensure(Number.isFinite(claims.exp) && claims.exp > now && (!claims.nbf || claims.nbf <= now + 1), 'Credential JWT time bounds are invalid');
  return { header, claims, certificateIdentity: 'sha256:' + encode(sha256(chain[0].raw)) };
}

export function verifyIssuedSdJwt(encoded, wallet, { issuer, trustAnchorPem, vct, expectedClaims }) {
  const parts = encoded.split('~');
  ensure(parts.length >= 2 && parts.at(-1) === '', 'Issued SD-JWT must have no holder presentation yet');
  const verified = verifyCertificateJwt(parts[0], { issuer, trustAnchorPem, typ: 'dc+sd-jwt' });
  const claims = verified.claims;
  ensure(claims.iss === issuer && claims.vct === vct && claims._sd_alg === 'sha-256', 'Credential issuer, type or disclosure algorithm mismatch');
  ensure(claims.cnf?.jwk && ['kty', 'crv', 'x', 'y'].every(name => claims.cnf.jwk[name] === wallet.jwk[name]), 'Credential holder key mismatch');
  const digests = new Set(claims._sd ?? []);
  const disclosed = {};
  for (const encodedDisclosure of parts.slice(1, -1)) {
    const hash = encode(sha256(encodedDisclosure));
    ensure(digests.delete(hash), 'Disclosure is duplicate or not authenticated by the issuer');
    const disclosure = jsonPart(encodedDisclosure);
    ensure(Array.isArray(disclosure) && disclosure.length === 3 && typeof disclosure[1] === 'string', 'Unexpected issuer disclosure');
    const name = disclosure[1];
    ensure(!Object.hasOwn(disclosed, name) && !Object.hasOwn(claims, name)
      && !['__proto__', 'prototype', 'constructor'].includes(name), 'Disclosure replaces a reserved claim');
    Object.defineProperty(disclosed, name, { value: disclosure[2], enumerable: true });
  }
  ensure(digests.size === 0, 'Issuer response omitted a disclosure');
  if (expectedClaims) ensure(isDeepStrictEqual(disclosed, expectedClaims), 'Issued claims differ from the approved dataset');
  return { claims, disclosed, certificateIdentity: verified.certificateIdentity };
}

export function sdJwtPresentation(wallet, credential, request) {
  ensure(credential.endsWith('~'), 'Credential is not an unbound issued SD-JWT');
  return credential + signEs256({ alg: 'ES256', typ: 'kb+jwt' }, {
    aud: request.client_id, nonce: request.nonce, iat: Math.floor(Date.now() / 1000),
    sd_hash: encode(sha256(credential)),
  }, wallet.privateKey);
}

function contentKey(privateKey, publicJwk, algorithm) {
  const shared = diffieHellman({ privateKey, publicKey: createPublicKey({ key: publicJwk, format: 'jwk' }) });
  const bits = algorithm === 'A128GCM' ? 128 : 256;
  return sha256(Buffer.concat([integer(1), shared, integer(algorithm.length), Buffer.from(algorithm),
    integer(0), integer(0), integer(bits)])).subarray(0, bits / 8);
}

export function encryptCredentialEnvelope(payload, recipientJwk, enc = 'A256GCM') {
  ensure(['A128GCM', 'A256GCM'].includes(enc) && recipientJwk.kty === 'EC' && recipientJwk.crv === 'P-256', 'Unsupported acceptance JWE profile');
  const ephemeral = createCredentialWallet();
  const header = encode(JSON.stringify({ alg: 'ECDH-ES', enc, cty: 'json', epk: ephemeral.jwk,
    ...(recipientJwk.kid ? { kid: recipientJwk.kid } : {}) }));
  const key = contentKey(ephemeral.privateKey, recipientJwk, enc);
  const iv = randomBytes(12);
  const cipher = createCipheriv(enc === 'A128GCM' ? 'aes-128-gcm' : 'aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(header));
  const plaintext = Buffer.from(typeof payload === 'string' ? payload : JSON.stringify(payload));
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  key.fill(0);
  return [header, '', encode(iv), encode(encrypted), encode(cipher.getAuthTag())].join('.');
}

export function decryptCredentialEnvelope(encoded, wallet) {
  const parts = encoded.split('.');
  ensure(parts.length === 5 && parts[1] === '', 'Malformed credential JWE');
  const header = jsonPart(parts[0]);
  ensure(header.alg === 'ECDH-ES' && ['A128GCM', 'A256GCM'].includes(header.enc)
    && !header.crit && !header.zip && !header.apu && !header.apv, 'Unsupported credential JWE profile');
  const key = contentKey(wallet.privateKey, header.epk, header.enc);
  const decipher = createDecipheriv(header.enc === 'A128GCM' ? 'aes-128-gcm' : 'aes-256-gcm', key, Buffer.from(parts[2], 'base64url'));
  decipher.setAAD(Buffer.from(parts[0]));
  decipher.setAuthTag(Buffer.from(parts[4], 'base64url'));
  const plaintext = Buffer.concat([decipher.update(Buffer.from(parts[3], 'base64url')), decipher.final()]);
  key.fill(0);
  return JSON.parse(plaintext);
}

/**
 * `request(path, init)` is the existing redacting acceptance recorder and returns
 * {status, headers, text}. No bearer token, JWK private material or credential
 * is returned in the public result. `saveWallet` must write a private artifact.
 * Dataset preparation may be skipped only for an already provisioned fixture.
 */
export function runPublicCredentials(input, options = {}) {
  return withCredentialTokenCleanup(input, options, runPublicCredentialsFlow);
}

async function runPublicCredentialsFlow(input, { request, session, saveWallet } = {}) {
  ensure(typeof request === 'function', 'A same-origin acceptance recorder is required');
  const issuer = new URL(input.issuer).origin;
  ensure(input.issuer === issuer && input.trust_anchor_pem && input.configuration_id && input.vct,
    'Credential acceptance fixture is incomplete');
  const json = (response, status = 200) => {
    assertCredentialStatus(response, status);
    try { return JSON.parse(response.text); } catch { throw new Error('Acceptance credentials: Credential endpoint returned invalid JSON'); }
  };
  const status = assertCredentialStatus;
  const post = (path, body, headers = {}, form = false) => request(path, {
    method: 'POST', headers: { origin: issuer, 'content-type': form ? 'application/x-www-form-urlencoded' : 'application/json', ...headers },
    body: form ? new URLSearchParams(body).toString() : JSON.stringify(body),
  });
  const wallet = createCredentialWallet(input.holder_private_jwk);
  if (saveWallet) await saveWallet({ issuer, configuration_id: input.configuration_id,
    holder_private_jwk: wallet.privateKey.export({ format: 'jwk' }) });
  const dataset = input.claims ?? { given_name: 'Workers', family_name: 'Acceptance' };
  if (!input.dataset_prepared) {
    ensure(session?.cookie && session?.csrf, 'An administrator session with recent MFA is required for dataset preparation');
    for (const configuration of new Set([input.configuration_id, input.deferred_configuration_id].filter(Boolean))) {
      const path = '/admin/openid4vci/credential-datasets/' + encodeURIComponent(input.subject_id) + '/' + encodeURIComponent(configuration);
      json(await request(path, { method: 'PUT', headers: { cookie: session.cookie, 'x-csrf-token': session.csrf,
        origin: issuer, 'content-type': 'application/json' }, body: JSON.stringify({ claims: dataset }) }));
      ensure(isDeepStrictEqual(json(await request(path, { headers: { cookie: session.cookie } })).claims, dataset), 'Dataset readback differs');
    }
  }
  const grant = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
  const preAuthorizedGrant = async configuration => {
    const offerBody = { subject_id: input.subject_id, credential_configuration_ids: [configuration],
      grant_types: [grant], tx_code: randomBytes(8).toString('hex'), expires_in: 300 };
    status(await post('/openid4vci/offers', offerBody), 401);
    const offer = json(await post('/openid4vci/offers', offerBody, { authorization: 'Bearer ' + input.issuer_management_token }));
    const offerUrl = new URL(offer.credential_offer_uri);
    ensure(offerUrl.origin === issuer, 'Credential offer escaped the issuer');
    const fetchedOffer = json(await request(offerUrl.pathname));
    ensure(isDeepStrictEqual(fetchedOffer, offer.credential_offer), 'Offer readback differs');
    const code = offer.credential_offer.grants[grant]['pre-authorized_code'];
    const tokenBody = { grant_type: grant, 'pre-authorized_code': code, tx_code: offerBody.tx_code,
      ...(input.wallet_client_id ? { client_id: input.wallet_client_id } : {}) };
    status(await post('/token', { ...tokenBody, tx_code: 'incorrect-test-code' }, {}, true), 400);
    const token = json(await post('/token', tokenBody, {}, true));
    status(await post('/token', tokenBody, {}, true), 400);
    return token;
  };
  const token = await preAuthorizedGrant(input.configuration_id);
  const authorization = { authorization: 'Bearer ' + token.access_token };
  const nonce = json(await request('/openid4vci/nonce', { method: 'POST' })).c_nonce;
  const credentialBody = { ...preAuthorizedCredentialSelector(token, input.configuration_id, issuer),
    proofs: { jwt: [credentialProof(wallet, issuer, nonce, input.wallet_client_id)] } };
  const issued = json(await post('/openid4vci/credential', credentialBody, authorization));
  const credential = issued.credentials?.[0]?.credential;
  ensure(typeof credential === 'string', 'Issuer did not return an SD-JWT credential');
  const verified = verifyIssuedSdJwt(credential, wallet, { issuer, trustAnchorPem: input.trust_anchor_pem,
    vct: input.vct, expectedClaims: dataset });
  const retried = json(await post('/openid4vci/credential', credentialBody, authorization));
  ensure(isDeepStrictEqual(retried, issued), 'Credential retry did not retain the exact issued response');
  if (saveWallet) await saveWallet({ issuer, configuration_id: input.configuration_id,
    holder_private_jwk: wallet.privateKey.export({ format: 'jwk' }), credential });
  const notification = { notification_id: issued.notification_id, event: 'credential_accepted' };
  status(await post('/openid4vci/notification', notification, authorization), 204);
  status(await post('/openid4vci/notification', notification, authorization), 204);

  let deferredSummary;
  if (input.deferred_configuration_id) {
    const metadata = json(await request('/.well-known/openid-credential-issuer'));
    ensure(metadata.credential_issuer === issuer
      && metadata.credential_configurations_supported?.[input.deferred_configuration_id], 'Deferred configuration is not advertised');
    const encryptionKey = metadata.credential_request_encryption?.jwks?.keys?.find(key => key.kid === 'openid4vci-request-encryption');
    ensure(encryptionKey?.alg === 'ECDH-ES', 'Credential request encryption key is not advertised');
    const encryptionWallet = createCredentialWallet();
    const encryption = { jwk: { ...encryptionWallet.jwk, use: 'enc', alg: 'ECDH-ES' }, enc: 'A256GCM' };
    const deferredToken = await preAuthorizedGrant(input.deferred_configuration_id);
    const headers = { authorization: 'Bearer ' + deferredToken.access_token };
    const encryptedPost = (path, body) => request(path, { method: 'POST',
      headers: { origin: issuer, 'content-type': 'application/jwt', ...headers },
      body: encryptCredentialEnvelope(body, encryptionKey) });
    const encryptedJson = (response, expected) => {
      status(response, expected);
      return decryptCredentialEnvelope(response.text, encryptionWallet);
    };
    const prepare = async () => {
      const nonce = json(await request('/openid4vci/nonce', { method: 'POST' })).c_nonce;
      const body = { ...preAuthorizedCredentialSelector(deferredToken, input.deferred_configuration_id, issuer),
        proofs: { jwt: [credentialProof(wallet, issuer, nonce, input.wallet_client_id)] },
        credential_response_encryption: encryption };
      // The native profile requires encrypted transport when requesting an
      // encrypted response. This rejection must leave the proof usable.
      const rejected = json(await post('/openid4vci/credential', body, headers), 400);
      ensure(rejected.error === 'invalid_encryption_parameters', 'Plaintext response-encryption request was not rejected');
      const response = await encryptedPost('/openid4vci/credential', body);
      const pending = encryptedJson(response, 202);
      ensure(typeof pending.transaction_id === 'string' && !pending.credentials, 'Deferred preparation returned no transaction');
      const retry = await encryptedPost('/openid4vci/credential', body);
      status(retry, 202);
      ensure(retry.text === response.text, 'Initial deferred retry changed the exact encrypted response');
      return { body, response, pending };
    };
    const prepared = await prepare();
    const pollBody = { transaction_id: prepared.pending.transaction_id, credential_response_encryption: encryption };
    let completed, completionResponse, pendingPolls = 0;
    for (let attempt = 0; attempt < 6; attempt++) {
      completionResponse = await encryptedPost('/openid4vci/deferred_credential', pollBody);
      if (completionResponse.status === 200) {
        completed = encryptedJson(completionResponse, 200);
        break;
      }
      const pending = encryptedJson(completionResponse, 202);
      ensure(pending.transaction_id === prepared.pending.transaction_id, 'Deferred poll changed its transaction');
      ensure(Number.isSafeInteger(pending.interval) && pending.interval >= 1 && pending.interval <= 5,
        'Unexpected deferred polling interval');
      pendingPolls++;
      await new Promise(resolve => setTimeout(resolve, pending.interval * 1000));
    }
    ensure(completed?.credentials?.length === 1, 'Deferred issuance did not complete within its polling budget');
    verifyIssuedSdJwt(completed.credentials[0].credential, wallet, { issuer, trustAnchorPem: input.trust_anchor_pem,
      vct: input.deferred_vct ?? input.vct, expectedClaims: dataset });
    const finalRetry = await encryptedPost('/openid4vci/deferred_credential', pollBody);
    status(finalRetry, 200);
    ensure(finalRetry.text === completionResponse.text, 'Deferred completion retry changed the exact encrypted response');
    const initialRetry = await encryptedPost('/openid4vci/credential', prepared.body);
    status(initialRetry, 202);
    ensure(initialRetry.text === prepared.response.text, 'Completing deferred issuance replaced its original accepted response');
    const deferredNotification = { notification_id: completed.notification_id, event: 'credential_accepted' };
    status(await post('/openid4vci/notification', deferredNotification, headers), 204);
    status(await post('/openid4vci/notification', deferredNotification, headers), 204);
    deferredSummary = { configuration_id: input.deferred_configuration_id, accepted_202: true,
      completed_200: true, pending_polls: pendingPolls, encrypted_request_response: true,
      exact_initial_retry: true, exact_completion_retry: true, notifications: true };
    if (input.wallet_client_id) {
      const revoked = await prepare();
      status(await post('/revoke', { client_id: input.wallet_client_id, token: deferredToken.access_token,
        token_type_hint: 'access_token' }, {}, true), 200);
      const denied = await encryptedPost('/openid4vci/deferred_credential', {
        transaction_id: revoked.pending.transaction_id, credential_response_encryption: encryption });
      ensure(json(denied, 401).error === 'invalid_token', 'Revoked token retained access to a pending deferred credential');
      const deniedRetry = await encryptedPost('/openid4vci/deferred_credential', pollBody);
      ensure(json(deniedRetry, 401).error === 'invalid_token', 'Revoked token retained access to an exact completed response');
      deferredSummary.revocation_rejected_pending_and_completed = true;
    }
  }

  const create = { create_request_jti: randomUUID(), wallet_authorization_endpoint: input.wallet_authorization_endpoint,
    dcql_query: { credentials: [{ id: 'pid', format: 'dc+sd-jwt', meta: { vct_values: [input.vct] }, require_cryptographic_holder_binding: true }] },
    client_id_prefix: 'x509_san_dns', request_method: 'request_uri_signed_post', response_mode: 'direct_post.jwt' };
  const management = { authorization: 'Bearer ' + input.verifier_management_token };
  status(await post('/openid4vp/presentations', create), 401);
  const presentation = json(await post('/openid4vp/presentations', create, management));
  ensure(json(await post('/openid4vp/presentations', create, management)).transaction_id === presentation.transaction_id, 'Presentation create retry changed the transaction');
  const walletNonce = encode(randomBytes(24));
  const signed = await post('/openid4vp/request/' + presentation.transaction_id, { wallet_nonce: walletNonce }, {}, true);
  status(signed, 200);
  const verifierRequest = verifyCertificateJwt(signed.text, { issuer, trustAnchorPem: input.trust_anchor_pem, typ: 'oauth-authz-req+jwt' }).claims;
  ensure(verifierRequest.wallet_nonce === walletNonce && verifierRequest.client_id === 'x509_san_dns:' + new URL(issuer).hostname, 'Presentation request identity or wallet nonce mismatch');
  const responseUrl = new URL(verifierRequest.response_uri);
  ensure(responseUrl.origin === issuer && responseUrl.pathname === '/openid4vp/response/' + presentation.transaction_id, 'Presentation response escaped its transaction');
  const responseKey = verifierRequest.client_metadata?.jwks?.keys?.[0];
  ensure(responseKey?.alg === 'ECDH-ES', 'Presentation response key is unavailable');
  const vpToken = { pid: [sdJwtPresentation(wallet, credential, verifierRequest)] };
  status(await post(responseUrl.pathname, { response: encryptCredentialEnvelope({ state: 'wrong-state', vp_token: vpToken }, responseKey) }, {}, true), 400);
  json(await post(responseUrl.pathname, { response: encryptCredentialEnvelope({ state: verifierRequest.state, vp_token: vpToken }, responseKey) }, {}, true));
  const result = json(await request('/openid4vp/result/' + presentation.transaction_id, { headers: management }));
  ensure(result.transaction_id === presentation.transaction_id && result.credentials?.length === 1
    && result.credentials[0].issuer === issuer && result.credentials[0].credential_type === input.vct
    && Object.entries(dataset).every(([name, value]) => isDeepStrictEqual(result.credentials[0].claims[name], value)),
  'Verified presentation result differs from the issued dataset');
  return { configuration_id: input.configuration_id, issuer, credential_type: input.vct,
    certificate_identity: verified.certificateIdentity, issuance: true, exact_response_retry: true,
    preauthorized_replay_rejected: true, notifications: true, signed_request: true,
    encrypted_presentation: true, holder_binding: true, verified_claims: true,
    ...(deferredSummary ? { deferred: deferredSummary } : {}) };
}

// Adapter for the main runner's existing request/step/session boundaries.
// Keep the issuer fixture under input.digital_credentials; management tokens
// and wallet material never become fields in the public acceptance report.
export async function publicCredentials({ issuer, request, step, input, session, saveWallet }) {
  if (!input.digital_credentials) return;
  let summary;
  await step('OpenID4VCI issuance and OpenID4VP encrypted presentation', async () => {
    summary = await runPublicCredentials({ issuer, ...input.digital_credentials }, { request, session, saveWallet });
  });
  if (input.digital_credentials.mdoc) {
    const { runPublicMdoc } = await import('./public-mdoc.mjs');
    await step('OpenID4VCI mdoc issuance and OpenID4VP selective presentation', async () => {
      const mdoc = await runPublicMdoc({ issuer, ...input.digital_credentials, ...input.digital_credentials.mdoc },
        { request, session, saveWallet });
      summary = { ...summary, mdoc };
    });
  }
  return summary;
}
