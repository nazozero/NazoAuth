import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CborTag, decodeMdocCbor, encodeMdocCbor, mdocPresentation, mdocSessionTranscript,
} from '../test-support/public-mdoc.mjs';
import { createCredentialWallet } from '../test-support/public-credentials.mjs';

// OpenID4VP 1.0 Final redirect vector, also exercised independently by the
// repository's pinned nazo-mdoc tests/session_final.rs.
const request = {
  client_id: 'x509_san_dns:example.com',
  nonce: 'exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA',
  response_uri: 'https://example.com/response', response_mode: 'direct_post.jwt',
  client_metadata: { jwks: { keys: [{ kty: 'EC', crv: 'P-256',
    x: 'DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0',
    y: 'XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc',
  }] } },
};

test('acceptance CBOR retains fixture types and RFC 8949 integer boundaries', () => {
  const vector = new Map([['dates', [new CborTag(0, '2026-11-20T00:00:00Z'), new CborTag(1004, '1990-01-01')]],
    ['values', [null, false, true, -7, 23, 24, 255, 256, 65535, 65536, 4294967296, Number.MAX_SAFE_INTEGER]],
    ['bytes', Buffer.from([0, 128, 255])]]);
  assert.deepEqual(decodeMdocCbor(encodeMdocCbor(vector)), vector);
  assert.equal(encodeMdocCbor(new CborTag(24, encodeMdocCbor(new Map()))).toString('hex'), 'd81841a0');
  assert.equal(encodeMdocCbor(new Map([[1, -7]])).toString('hex'), 'a10126');
});

test('acceptance CBOR rejects duplicate keys, truncation, indefinite lengths and ambiguous input', () => {
  for (const hex of ['a201000101', 'a2617800617801', '9fff', '1817', '1900ff', '1b0020000000000000',
    '18', '62fffe', '5861', 'f600', 'f7', 'fa00000000', 'd9010040']) {
    assert.throws(() => decodeMdocCbor(Buffer.from(hex, 'hex')), undefined, hex);
  }
  assert.throws(() => decodeMdocCbor(Buffer.concat([Buffer.alloc(34, 0x81), Buffer.from([0xf6])])));
  assert.throws(() => encodeMdocCbor(1.5));
});

test('mdoc handover matches the Final redirect vector and ignores optional JWK metadata', () => {
  const expected = '83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac';
  assert.equal(encodeMdocCbor(mdocSessionTranscript(request)).toString('hex'), expected);
  const extended = structuredClone(request);
  Object.assign(extended.client_metadata.jwks.keys[0], { kid: 'optional-key-id', alg: 'ECDH-ES', use: 'enc' });
  assert.equal(encodeMdocCbor(mdocSessionTranscript(extended)).toString('hex'), expected);
});

test('mdoc handover binds every request parameter and the actual encryption key', () => {
  const original = encodeMdocCbor(mdocSessionTranscript(request));
  for (const member of ['client_id', 'nonce', 'response_uri']) {
    assert.notDeepEqual(encodeMdocCbor(mdocSessionTranscript({ ...request, [member]: request[member] + 'x' })), original);
  }
  const other = structuredClone(request);
  other.client_metadata.jwks.keys[0] = createCredentialWallet().jwk;
  assert.notDeepEqual(encodeMdocCbor(mdocSessionTranscript(other)), original);
  assert.notDeepEqual(encodeMdocCbor(mdocSessionTranscript({ ...request, response_mode: 'direct_post' })), original);
  assert.throws(() => mdocSessionTranscript({ ...request, client_metadata: {} }));
});

test('selective mdoc presentation preserves issuer bytes and carries a detached holder signature', () => {
  const item = (id, name) => new CborTag(24, encodeMdocCbor(new Map([
    ['elementValue', name + '-fixture'], ['random', Buffer.alloc(16, id)], ['digestID', id], ['elementIdentifier', name],
  ])));
  const first = item(0, 'given_name'), second = item(1, 'family_name');
  const auth = [Buffer.from('a10126', 'hex'), new Map([[33, Buffer.from('fixture-certificate')]]), Buffer.from('fixture-payload'), Buffer.alloc(64, 1)];
  const issuerSigned = decodeMdocCbor(encodeMdocCbor(new Map([
    ['nameSpaces', new Map([['org.iso.18013.5.1', [first, second]]])], ['issuerAuth', auth],
  ])));
  const verified = { issuerSigned, doctype: 'org.iso.18013.5.1.mDL' };
  const result = decodeMdocCbor(Buffer.from(mdocPresentation(createCredentialWallet(), verified, request,
    { 'org.iso.18013.5.1': ['family_name'] }), 'base64url'));
  assert.equal(result.get('version'), '1.0');
  assert.equal(result.get('status'), 0);
  const document = result.get('documents')[0];
  assert.deepEqual(encodeMdocCbor(document.get('issuerSigned').get('issuerAuth')), encodeMdocCbor(auth));
  const items = document.get('issuerSigned').get('nameSpaces').get('org.iso.18013.5.1');
  assert.equal(items.length, 1);
  assert.deepEqual(encodeMdocCbor(items[0]), encodeMdocCbor(second));
  const device = document.get('deviceSigned');
  assert.equal(encodeMdocCbor(device.get('nameSpaces')).toString('hex'), 'd81841a0');
  const signature = device.get('deviceAuth').get('deviceSignature');
  assert.equal(signature[2], null);
  assert.equal(signature[3].length, 64);
  assert.throws(() => mdocPresentation(createCredentialWallet(), verified, request,
    { 'org.iso.18013.5.1': ['missing'] }));
});
