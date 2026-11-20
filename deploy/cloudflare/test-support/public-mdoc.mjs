// Independent acceptance wallet for the deliberately small P-256 mdoc fixture.
// This is not a general PKI or mdoc implementation. Production policy and
// authorization stay in the shared Rust services and nazo-mdoc.
import { createHash, randomBytes, randomUUID, sign, verify, X509Certificate } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import {
  createCredentialWallet, credentialProof, encryptCredentialEnvelope, verifyCertificateJwt,
} from './public-credentials.mjs';

const ensure = (condition, message) => { if (!condition) throw new Error(message); };
const sha256 = value => createHash('sha256').update(value).digest();
const b64 = value => Buffer.from(value).toString('base64url');
const rawBytes = new WeakMap();
const utf8 = new TextDecoder('utf-8', { fatal: true });

export class CborTag {
  constructor(tag, value) { this.tag = tag; this.value = value; }
}

class RawCbor {
  constructor(bytes) { this.bytes = bytes; }
}

function preserved(value) {
  const bytes = rawBytes.get(value);
  ensure(bytes, 'CBOR value has no original encoding');
  return new RawCbor(bytes);
}

function head(major, value) {
  ensure(Number.isSafeInteger(value) && value >= 0, 'Unsupported CBOR integer');
  if (value < 24) return Buffer.from([(major << 5) | value]);
  const length = value <= 0xff ? 1 : value <= 0xffff ? 2 : value <= 0xffffffff ? 4 : 8;
  const result = Buffer.alloc(1 + length);
  result[0] = (major << 5) | ({ 1: 24, 2: 25, 4: 26, 8: 27 })[length];
  if (length === 8) result.writeBigUInt64BE(BigInt(value), 1);
  else result.writeUIntBE(value, 1, length);
  return result;
}

export function encodeMdocCbor(value) {
  if (value instanceof RawCbor) return value.bytes;
  if (value instanceof CborTag) return Buffer.concat([head(6, value.tag), encodeMdocCbor(value.value)]);
  if (value === null) return Buffer.from([0xf6]);
  if (typeof value === 'boolean') return Buffer.from([value ? 0xf5 : 0xf4]);
  if (typeof value === 'number') return value < 0 ? head(1, -1 - value) : head(0, value);
  if (typeof value === 'string') {
    const bytes = Buffer.from(value);
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return Buffer.concat([head(2, value.length), value]);
  }
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(encodeMdocCbor)]);
  if (value instanceof Map) return Buffer.concat([head(5, value.size),
    ...[...value].flatMap(([key, item]) => [encodeMdocCbor(key), encodeMdocCbor(item)])]);
  throw new Error('Unsupported acceptance CBOR value');
}

// Bounded, definite-length fixture decoder. Original signed byte strings and
// tag-24 items are retained, so the wallet never reconstructs a digest input.
export function decodeMdocCbor(input) {
  const bytes = Buffer.from(input);
  ensure(bytes.length > 0 && bytes.length <= 1024 * 1024, 'CBOR fixture exceeds its size bound');
  let offset = 0, nodes = 0;
  const read = depth => {
    ensure(depth <= 32 && ++nodes <= 16384 && offset < bytes.length, 'Malformed or excessive CBOR');
    const start = offset, first = bytes[offset++], major = first >> 5, additional = first & 31;
    let length;
    if (additional < 24) length = additional;
    else {
      const width = ({ 24: 1, 25: 2, 26: 4, 27: 8 })[additional];
      ensure(width && offset + width <= bytes.length, 'Indefinite or truncated CBOR is unsupported');
      const integer = width === 8 ? bytes.readBigUInt64BE(offset) : BigInt(bytes.readUIntBE(offset, width));
      ensure(integer <= BigInt(Number.MAX_SAFE_INTEGER), 'CBOR integer exceeds the wallet profile');
      length = Number(integer);
      offset += width;
      ensure(length >= ({ 1: 24, 2: 256, 4: 65536, 8: 4294967296 })[width], 'Non-minimal CBOR length');
    }
    let value;
    if (major === 0 || major === 1) value = major === 0 ? length : -1 - length;
    else if (major === 2 || major === 3) {
      ensure(offset + length <= bytes.length, 'Truncated CBOR string');
      const content = bytes.subarray(offset, offset + length);
      offset += length;
      value = major === 2 ? content : utf8.decode(content);
    } else if (major === 4) {
      ensure(length <= 4096, 'Excessive CBOR array');
      value = Array.from({ length }, () => read(depth + 1));
    } else if (major === 5) {
      ensure(length <= 4096, 'Excessive CBOR map');
      value = new Map();
      for (let index = 0; index < length; index++) {
        const key = read(depth + 1);
        ensure((typeof key === 'string' || Number.isSafeInteger(key)) && !value.has(key), 'Unsupported or duplicate CBOR map key');
        value.set(key, read(depth + 1));
      }
    } else if (major === 6) {
      ensure([0, 24, 1004].includes(length), 'Unsupported fixture CBOR tag');
      value = new CborTag(length, read(depth + 1));
    } else {
      ensure(additional === 20 || additional === 21 || additional === 22, 'Unsupported CBOR simple value');
      value = additional === 22 ? null : additional === 21;
    }
    if (value && typeof value === 'object') rawBytes.set(value, bytes.subarray(start, offset));
    return value;
  };
  const value = read(0);
  ensure(offset === bytes.length, 'Trailing CBOR bytes');
  return value;
}

function map(value, message) { ensure(value instanceof Map, message); return value; }
function taggedBytes(value) {
  ensure(value instanceof CborTag && value.tag === 24 && Buffer.isBuffer(value.value), 'Expected encoded CBOR tag 24');
  return value.value;
}
function claimsJson(value) {
  if (value instanceof CborTag) {
    ensure([0, 1004].includes(value.tag) && typeof value.value === 'string', 'Unsupported mdoc claim tag');
    return value.value;
  }
  if (Buffer.isBuffer(value)) return b64(value);
  if (Array.isArray(value)) return value.map(claimsJson);
  if (value instanceof Map) return Object.fromEntries([...value].map(([name, child]) => {
    ensure(typeof name === 'string' && !['__proto__', 'prototype', 'constructor'].includes(name), 'Reserved mdoc claim name');
    return [name, claimsJson(child)];
  }));
  return value;
}

function verifyFixtureChain(encoded, { issuer, trustAnchorPem, now }) {
  const values = Buffer.isBuffer(encoded) ? [encoded] : encoded;
  ensure(Array.isArray(values) && values.length > 0 && values.length <= 8
    && values.every(Buffer.isBuffer), 'Invalid mdoc x5chain');
  const chain = values.map(der => new X509Certificate(der));
  const anchor = new X509Certificate(trustAnchorPem);
  ensure(anchor.ca && !chain.some(certificate => certificate.raw.equals(anchor.raw)), 'mdoc x5chain must exclude its pinned root');
  for (const certificate of [...chain, anchor]) {
    ensure(Date.parse(certificate.validFrom) <= now && now < Date.parse(certificate.validTo), 'mdoc certificate time bounds failed');
  }
  const leaf = chain[0];
  ensure(!leaf.ca && leaf.checkHost(new URL(issuer).hostname, { subject: 'never', wildcards: false }), 'mdoc DS does not bind the fixture issuer');
  ensure(leaf.keyUsage?.includes('1.0.18013.5.1.2'), 'mdoc document-signing EKU is missing');
  for (let index = 0; index < chain.length; index++) {
    const parent = chain[index + 1] ?? anchor;
    ensure(parent.ca && chain[index].checkIssued(parent) && chain[index].verify(parent.publicKey), 'mdoc chain does not reach its pinned IACA');
  }
  ensure(anchor.checkIssued(anchor) && anchor.verify(anchor.publicKey), 'Pinned IACA is not self-signed');
  return leaf;
}

export function verifyIssuedMdoc(encoded, wallet, { issuer, trustAnchorPem, doctype, expectedClaims, now = Date.now() }) {
  ensure(typeof encoded === 'string' && /^[A-Za-z0-9_-]+$/.test(encoded), 'mdoc credential is not base64url');
  const bytes = Buffer.from(encoded, 'base64url');
  ensure(b64(bytes) === encoded, 'Non-canonical mdoc base64url');
  const issuerSigned = map(decodeMdocCbor(bytes), 'Expected IssuerSigned, not a DeviceResponse');
  const auth = issuerSigned.get('issuerAuth');
  ensure(Array.isArray(auth) && auth.length === 4 && Buffer.isBuffer(auth[0])
    && Buffer.isBuffer(auth[2]) && Buffer.isBuffer(auth[3]) && auth[3].length === 64, 'Malformed mdoc issuer authentication');
  const protectedHeaders = map(decodeMdocCbor(auth[0]), 'Invalid COSE protected headers');
  const unprotected = map(auth[1], 'Invalid COSE unprotected headers');
  ensure(protectedHeaders.size === 1 && protectedHeaders.get(1) === -7 && !unprotected.has(1), 'Unexpected mdoc COSE algorithm');
  const leaf = verifyFixtureChain(unprotected.get(33), { issuer, trustAnchorPem, now });
  ensure(verify('sha256', encodeMdocCbor(['Signature1', auth[0], Buffer.alloc(0), auth[2]]),
    { key: leaf.publicKey, dsaEncoding: 'ieee-p1363' }, auth[3]), 'mdoc issuer signature is invalid');
  const mso = map(decodeMdocCbor(taggedBytes(decodeMdocCbor(auth[2]))), 'Invalid MSO');
  ensure(mso.get('version') === '1.0' && mso.get('digestAlgorithm') === 'SHA-256'
    && mso.get('docType') === doctype, 'mdoc type or digest profile mismatch');
  const validity = map(mso.get('validityInfo'), 'Missing MSO validity');
  const times = Object.fromEntries(['signed', 'validFrom', 'validUntil'].map(name => {
    const value = validity.get(name);
    ensure(value instanceof CborTag && value.tag === 0 && typeof value.value === 'string', 'Invalid MSO timestamp');
    const timestamp = Date.parse(value.value);
    ensure(Number.isFinite(timestamp), 'Invalid MSO time');
    return [name, timestamp];
  }));
  ensure(times.signed <= now + 1000 && times.validFrom <= now + 1000 && now < times.validUntil
    && times.signed <= times.validFrom && times.validFrom < times.validUntil
    && times.signed >= Date.parse(leaf.validFrom) && times.signed <= Date.parse(leaf.validTo), 'MSO validity bounds failed');
  const device = map(map(mso.get('deviceKeyInfo'), 'Missing device-key info').get('deviceKey'), 'Missing COSE device key');
  ensure(device.get(1) === 2 && device.get(-1) === 1 && Buffer.isBuffer(device.get(-2))
    && Buffer.isBuffer(device.get(-3)) && b64(device.get(-2)) === wallet.jwk.x
    && b64(device.get(-3)) === wallet.jwk.y, 'MSO holder key differs from the proof key');
  const digests = map(mso.get('valueDigests'), 'Missing MSO value digests');
  const namespaces = map(issuerSigned.get('nameSpaces'), 'Missing issued namespaces');
  const disclosed = {};
  for (const [namespace, items] of namespaces) {
    ensure(typeof namespace === 'string' && Array.isArray(items) && items.length > 0, 'Invalid issued namespace');
    const expected = map(digests.get(namespace), 'Namespace is not signed by the MSO');
    const used = new Set(), claims = new Map();
    for (const encodedItem of items) {
      const item = map(decodeMdocCbor(taggedBytes(encodedItem)), 'Invalid IssuerSignedItem');
      const id = item.get('digestID'), name = item.get('elementIdentifier'), random = item.get('random');
      ensure(Number.isSafeInteger(id) && id >= 0 && !used.has(id) && typeof name === 'string'
        && !claims.has(name) && Buffer.isBuffer(random) && random.length >= 16, 'Duplicate or invalid issuer item');
      const digest = expected.get(id);
      ensure(Buffer.isBuffer(digest) && digest.length === 32 && sha256(rawBytes.get(encodedItem)).equals(digest), 'mdoc disclosed item digest is invalid');
      used.add(id);
      claims.set(name, item.get('elementValue'));
    }
    ensure(used.size === expected.size, 'Issued fixture omitted one of its signed elements');
    Object.defineProperty(disclosed, namespace, { value: claimsJson(claims), enumerable: true });
  }
  ensure(namespaces.size === digests.size, 'Issued fixture omitted a namespace');
  if (expectedClaims) ensure(isDeepStrictEqual(disclosed, expectedClaims), 'mdoc claims differ from the approved dataset');
  return { issuerSigned, doctype, disclosed, certificateIdentity: 'sha256:' + b64(sha256(leaf.raw)),
    issuerIdentity: b64(sha256(leaf.raw)) };
}

export function mdocSessionTranscript(request) {
  ensure(typeof request.client_id === 'string' && typeof request.nonce === 'string'
    && typeof request.response_uri === 'string', 'Incomplete mdoc presentation request');
  let thumbprint = null;
  if (request.response_mode === 'direct_post.jwt') {
    const keys = request.client_metadata?.jwks?.keys;
    ensure(Array.isArray(keys) && keys.length === 1 && keys[0].kty === 'EC'
      && keys[0].crv === 'P-256', 'Missing verifier encryption-key binding');
    const { crv, kty, x, y } = keys[0];
    ensure(typeof x === 'string' && typeof y === 'string', 'Invalid verifier EC key');
    thumbprint = sha256(JSON.stringify({ crv, kty, x, y }));
  } else ensure(request.response_mode === 'direct_post', 'Unsupported mdoc response mode');
  const handover = sha256(encodeMdocCbor([request.client_id, request.nonce, thumbprint, request.response_uri]));
  return [null, null, ['OpenID4VPHandover', handover]];
}

// Selection changes only unsigned framing; each retained issuer item and the
// issuer COSE object use their original encoded bytes.
export function mdocPresentation(wallet, verified, request, selectedClaims) {
  let issuerSigned = preserved(verified.issuerSigned);
  if (selectedClaims) {
    const namespaces = new Map();
    for (const [namespace, names] of Object.entries(selectedClaims)) {
      const original = verified.issuerSigned.get('nameSpaces').get(namespace);
      ensure(Array.isArray(original) && names.length > 0 && new Set(names).size === names.length, 'Invalid mdoc claim selection');
      const items = original.filter(item => names.includes(decodeMdocCbor(taggedBytes(item)).get('elementIdentifier')));
      ensure(items.length === names.length, 'Requested mdoc claim is missing');
      namespaces.set(namespace, items.map(preserved));
    }
    issuerSigned = new Map([['issuerAuth', preserved(verified.issuerSigned.get('issuerAuth'))], ['nameSpaces', namespaces]]);
  }
  const deviceNamespaces = new CborTag(24, encodeMdocCbor(new Map()));
  const authentication = new CborTag(24, encodeMdocCbor([
    'DeviceAuthentication', mdocSessionTranscript(request), verified.doctype, deviceNamespaces,
  ]));
  const protectedHeaders = encodeMdocCbor(new Map([[1, -7]]));
  const signatureInput = encodeMdocCbor(['Signature1', protectedHeaders, Buffer.alloc(0), encodeMdocCbor(authentication)]);
  const signature = sign('sha256', signatureInput, { key: wallet.privateKey, dsaEncoding: 'ieee-p1363' });
  return b64(encodeMdocCbor(new Map([
    ['version', '1.0'], ['status', 0], ['documents', [new Map([
      ['docType', verified.doctype], ['issuerSigned', issuerSigned],
      ['deviceSigned', new Map([['nameSpaces', deviceNamespaces],
        ['deviceAuth', new Map([['deviceSignature', [protectedHeaders, new Map(), null, signature]]])]])],
    ])]],
  ])));
}

export async function runPublicMdoc(input, { request, session, saveWallet } = {}) {
  ensure(typeof request === 'function', 'A same-origin acceptance recorder is required');
  const issuer = new URL(input.issuer).origin;
  const configuration = input.mdoc_configuration_id ?? input.configuration_id;
  ensure(input.issuer === issuer && configuration && input.doctype && input.trust_anchor_pem
    && input.claims && input.wallet_client_id, 'mdoc acceptance fixture is incomplete');
  const status = (response, expected) => ensure(response.status === expected,
    `mdoc endpoint returned HTTP ${response.status}; expected ${expected}`);
  const json = (response, expected = 200) => {
    status(response, expected);
    try { return JSON.parse(response.text); } catch { throw new Error('mdoc endpoint returned invalid JSON'); }
  };
  const post = (path, body, headers = {}, form = false) => request(path, { method: 'POST',
    headers: { origin: issuer, 'content-type': form ? 'application/x-www-form-urlencoded' : 'application/json', ...headers },
    body: form ? new URLSearchParams(body).toString() : JSON.stringify(body) });
  const metadata = json(await request('/.well-known/openid-credential-issuer'));
  const advertised = metadata.credential_configurations_supported?.[configuration];
  ensure(advertised?.format === 'mso_mdoc' && advertised.doctype === input.doctype
    && isDeepStrictEqual(advertised.credential_signing_alg_values_supported, [-7]), 'mdoc metadata does not advertise its COSE profile');
  if (!input.dataset_prepared) {
    ensure(session?.cookie && session?.csrf, 'mdoc dataset preparation requires an administrator with recent MFA');
    const path = '/admin/openid4vci/credential-datasets/' + encodeURIComponent(input.subject_id) + '/' + encodeURIComponent(configuration);
    json(await request(path, { method: 'PUT', headers: { cookie: session.cookie, 'x-csrf-token': session.csrf,
      origin: issuer, 'content-type': 'application/json' }, body: JSON.stringify({ claims: input.claims }) }));
    ensure(isDeepStrictEqual(json(await request(path, { headers: { cookie: session.cookie } })).claims, input.claims), 'mdoc dataset readback differs');
  }
  const wallet = createCredentialWallet(input.holder_private_jwk);
  if (saveWallet) await saveWallet({ issuer, configuration_id: configuration,
    holder_private_jwk: wallet.privateKey.export({ format: 'jwk' }) });
  const grant = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
  const offerBody = { subject_id: input.subject_id, credential_configuration_ids: [configuration],
    grant_types: [grant], tx_code: randomBytes(8).toString('hex'), expires_in: 300 };
  const offer = json(await post('/openid4vci/offers', offerBody, { authorization: 'Bearer ' + input.issuer_management_token }));
  const tokenBody = { grant_type: grant, client_id: input.wallet_client_id, tx_code: offerBody.tx_code,
    'pre-authorized_code': offer.credential_offer.grants[grant]['pre-authorized_code'] };
  const token = json(await post('/token', tokenBody, {}, true));
  status(await post('/token', tokenBody, {}, true), 400);
  const authorization = { authorization: 'Bearer ' + token.access_token };
  const nonce = json(await request('/openid4vci/nonce', { method: 'POST' })).c_nonce;
  const body = { credential_configuration_id: configuration,
    proofs: { jwt: [credentialProof(wallet, issuer, nonce, input.wallet_client_id)] } };
  const issued = json(await post('/openid4vci/credential', body, authorization));
  const credential = issued.credentials?.[0]?.credential;
  const verified = verifyIssuedMdoc(credential, wallet, { issuer, trustAnchorPem: input.trust_anchor_pem,
    doctype: input.doctype, expectedClaims: input.claims });
  ensure(isDeepStrictEqual(json(await post('/openid4vci/credential', body, authorization)), issued), 'mdoc issuance retry changed its exact response');
  if (saveWallet) await saveWallet({ issuer, configuration_id: configuration,
    holder_private_jwk: wallet.privateKey.export({ format: 'jwk' }), credential });
  status(await post('/openid4vci/notification', { notification_id: issued.notification_id,
    event: 'credential_accepted' }, authorization), 204);
  let crlChecked = false;
  if (input.crl_publication_id && input.crl_sha256) {
    const response = await request('/.well-known/mdoc/' + input.crl_publication_id + '.crl');
    status(response, 200);
    ensure(response.headers.get('content-type')?.startsWith('application/pkix-crl')
      && Buffer.isBuffer(response.bytes) && b64(sha256(response.bytes)) === input.crl_sha256,
    'Published CRL differs from the independently authenticated offline fixture');
    crlChecked = true;
  }
  const management = { authorization: 'Bearer ' + input.verifier_management_token };
  const createRequest = async selectedClaims => {
    const claims = selectedClaims ? Object.entries(selectedClaims).flatMap(([namespace, names]) =>
      names.map(name => ({ path: [namespace, name] }))) : undefined;
    const create = { create_request_jti: randomUUID(), wallet_authorization_endpoint: input.wallet_authorization_endpoint,
      dcql_query: { credentials: [{ id: 'mdl', format: 'mso_mdoc', meta: { doctype_value: input.doctype },
        require_cryptographic_holder_binding: true, ...(claims ? { claims } : {}) }] },
      client_id_prefix: 'x509_san_dns', request_method: 'request_uri_signed_post', response_mode: 'direct_post.jwt' };
    const presentation = json(await post('/openid4vp/presentations', create, management));
    const walletNonce = b64(randomBytes(24));
    const signed = await post('/openid4vp/request/' + presentation.transaction_id, { wallet_nonce: walletNonce }, {}, true);
    status(signed, 200);
    const verifiedRequest = verifyCertificateJwt(signed.text, { issuer, trustAnchorPem: input.trust_anchor_pem, typ: 'oauth-authz-req+jwt' }).claims;
    ensure(verifiedRequest.wallet_nonce === walletNonce && verifiedRequest.client_id === 'x509_san_dns:' + new URL(issuer).hostname,
      'mdoc verifier request identity or wallet nonce mismatch');
    const responseUrl = new URL(verifiedRequest.response_uri);
    ensure(responseUrl.origin === issuer && responseUrl.pathname === '/openid4vp/response/' + presentation.transaction_id,
      'mdoc verifier response escaped its transaction');
    const key = verifiedRequest.client_metadata?.jwks?.keys?.[0];
    ensure(key?.alg === 'ECDH-ES', 'mdoc response encryption key is unavailable');
    return { id: presentation.transaction_id, request: verifiedRequest, path: responseUrl.pathname, key };
  };
  const submit = (transaction, vp) => post(transaction.path, { response: encryptCredentialEnvelope({
    state: transaction.request.state, vp_token: { mdl: [vp] },
  }, transaction.key) }, {}, true);
  const transaction = await createRequest();
  status(await submit(transaction, mdocPresentation(wallet, verified, { ...transaction.request, nonce: randomUUID() })), 400);
  status(await submit(transaction, mdocPresentation(createCredentialWallet(), verified, transaction.request)), 400);
  const fullPresentation = mdocPresentation(wallet, verified, transaction.request);
  const altered = decodeMdocCbor(Buffer.from(fullPresentation, 'base64url'));
  const alteredItems = altered.get('documents')[0].get('issuerSigned').get('nameSpaces');
  const alteredItem = [...alteredItems.values()].flat().find(item =>
    typeof decodeMdocCbor(taggedBytes(item)).get('elementValue') === 'string');
  ensure(alteredItem, 'mdoc fixture needs one text claim for the signed-digest rejection');
  const changedClaim = decodeMdocCbor(taggedBytes(alteredItem));
  changedClaim.set('elementValue', changedClaim.get('elementValue') + '-modified');
  alteredItem.value = encodeMdocCbor(changedClaim);
  status(await submit(transaction, b64(encodeMdocCbor(altered))), 400);
  json(await submit(transaction, fullPresentation));
  const result = json(await request('/openid4vp/result/' + transaction.id, { headers: management }));
  ensure(result.credentials?.length === 1 && result.credentials[0].format === 'mso_mdoc'
    && result.credentials[0].issuer === verified.issuerIdentity && result.credentials[0].credential_type === input.doctype
    && isDeepStrictEqual(result.credentials[0].claims, input.claims), 'Verified mdoc result differs from the approved dataset');
  status(await submit(transaction, fullPresentation), 400);
  const namespace = 'org.iso.18013.5.1';
  const selected = input.selected_claims ?? { [namespace]: ['family_name'] };
  const selectiveTransaction = await createRequest(selected);
  json(await submit(selectiveTransaction, mdocPresentation(wallet, verified, selectiveTransaction.request, selected)));
  const selective = json(await request('/openid4vp/result/' + selectiveTransaction.id, { headers: management }));
  const expectedSelected = Object.fromEntries(Object.entries(selected).map(([ns, names]) =>
    [ns, Object.fromEntries(names.map(name => [name, input.claims[ns][name]]))]));
  ensure(selective.credentials?.length === 1 && isDeepStrictEqual(selective.credentials[0].claims, expectedSelected),
    'Selective mdoc presentation disclosed additional or incorrect claims');
  return { configuration_id: configuration, credential_type: input.doctype,
    certificate_identity: verified.certificateIdentity, issuer_signature: true, signed_item_digests: true,
    holder_key_binding: true, exact_response_retry: true, encrypted_presentation: true,
    incorrect_session_and_holder_rejected: true, modified_signed_claim_rejected: true, presentation_replay_rejected: true,
    selective_disclosure: true, ...(crlChecked ? { published_crl_matches_verified_fixture: true } : {}) };
}
