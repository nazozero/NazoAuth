import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { test } from 'node:test';
import { runPublicAcceptance } from '../test-support/public-acceptance.mjs';

test('public runner records actual 1102 without copying response secrets or estimating CPU', async () => {
  const secret = 'private-response-body-that-must-stay-private';
  const result = await runPublicAcceptance({ issuer: 'https://acceptance.example' }, async (_url, init) => {
    assert.equal(init.redirect, 'manual');
    assert.match(init.headers['x-nazo-acceptance'], /^nazo-acceptance-/);
    return new Response('<title>Worker exceeded resource limits</title><span>Error code</span><span>1102</span>' + secret,
      { status: 500, headers: { 'cf-ray': 'test-request' } });
  });
  assert.equal(result.failed, true);
  assert.equal(result.http.cloudflare_1102, 1);
  assert.equal(result.requests[0].cloudflare_error, 1102);
  assert.equal(result.cpu.measured, false);
  assert.equal(JSON.stringify(result).includes(secret), false);
});

test('public runner distinguishes generic failures, request latency and platform CPU', async () => {
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' });
  const result = await runPublicAcceptance({ issuer: 'https://acceptance.example' }, async url => {
    if (url.endsWith('/.well-known/oauth-authorization-server')) return Response.json({
      issuer: 'https://acceptance.example', jwks_uri: 'https://acceptance.example/jwks.json',
    });
    if (url.endsWith('/jwks.json')) return Response.json({ keys: [key] });
    return new Response('Service unavailable', { status: 503 });
  });
  assert.equal(result.failed, true);
  assert.equal(result.http.requests, 3);
  assert.equal(result.http.cloudflare_1102, 0);
  assert.equal(result.http.status_counts['503'], 1);
  assert.equal(result.cpu.measured, false);
  assert.ok(result.requests.every(request => Number.isFinite(request.latency_ms)));
});

test('network errors never expose exception details or become successful zero-CPU invocations', async () => {
  const secret = 'secret-in-network-exception';
  const result = await runPublicAcceptance({ issuer: 'https://acceptance.example' }, async () => { throw new Error(secret); });
  assert.equal(result.failed, true);
  assert.equal(result.http.network_errors, 1);
  assert.equal(result.http.cloudflare_1102, 0);
  assert.equal(result.cpu.measured, false);
  assert.equal(JSON.stringify(result).includes(secret), false);
});

test('optional workload bounds requests and concurrency and counts signature failures separately', async () => {
  const issuer = 'https://acceptance.example';
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const privateJwk = { ...pair.privateKey.export({ format: 'jwk' }), kid: 'client' };
  const publicJwk = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'issuer', alg: 'ES256' };
  const assertions = new Set();
  const revoked = new Set();
  let sequence = 0;
  let active = 0;
  let maximumActive = 0;
  let concurrentRequest = 0;
  const signedToken = () => {
    const input = [{ alg: 'ES256', kid: 'issuer' }, { iss: issuer, sub: 'client', aud: 'resource://default',
      exp: Math.floor(Date.now() / 1000) + 3600, jti: String(++sequence) }]
      .map(value => Buffer.from(JSON.stringify(value)).toString('base64url')).join('.');
    return input + '.' + sign('sha256', Buffer.from(input), { key: pair.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  };
  const result = await runPublicAcceptance({ issuer, private_key_client: {
    client_id: 'client', private_key_jwk: privateJwk, resource: 'resource://default',
  }, workload: { requests: 300, concurrency: 100 } }, async (url, init) => {
    const path = new URL(url).pathname;
    if (path === '/.well-known/oauth-authorization-server') return Response.json({ issuer, jwks_uri: issuer + '/jwks.json' });
    if (path === '/jwks.json') return Response.json({ keys: [publicJwk] });
    if (path === '/auth/login') return new Response(null, { status: 404 });
    const fields = new URLSearchParams(init.body);
    if (path === '/introspect') return Response.json({ active: !revoked.has(fields.get('token')) });
    if (path === '/revoke') { revoked.add(fields.get('token')); return new Response(null, { status: 200 }); }
    assert.equal(path, '/token');
    const assertion = fields.get('client_assertion');
    if (assertions.has(assertion)) return Response.json({ error: 'invalid_client' }, { status: 400 });
    assertions.add(assertion);
    const phase = init.headers['x-nazo-acceptance-phase'];
    active++;
    maximumActive = Math.max(maximumActive, active);
    await new Promise(resolve => setTimeout(resolve, 1));
    active--;
    const invalidSignature = phase === 'concurrent' && concurrentRequest++ === 0;
    return Response.json({ access_token: invalidSignature ? 'invalid-signed-token' : signedToken(), token_type: 'Bearer' });
  });
  assert.equal(result.workload.requested, 256);
  assert.equal(result.workload.concurrency, 16);
  assert.ok(maximumActive <= 16 && maximumActive > 1);
  assert.equal(result.workload.signed_successes, 255);
  assert.equal(result.workload.failures, 1);
  assert.equal(result.workload.phases[0].requests, 16);
  assert.equal(result.workload.phases[0].signed_successes, 16);
  assert.equal(result.workload.phases[1].requests, 240);
  assert.equal(result.workload.phases[1].status_counts['200'], 240);
  assert.equal(result.workload.phases[1].cloudflare_1102, 0);
  assert.equal(result.cpu.measured, false);
  assert.equal(result.failed, true);
});
