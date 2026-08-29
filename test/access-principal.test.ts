/**
 * Principal handling in the Access verifier.
 *
 * The full signature path needs a real Cloudflare assertion and is exercised
 * against the live endpoint. What is tested here is the configuration contract:
 * the two services must not be able to accept each other's kind of credential.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createAccessVerifier, AccessConfigError } from '../src/shared/access.js';

const TEAM = 'https://example.cloudflareaccess.com';
const AUD = 'a'.repeat(64);

test('a user-principal verifier is the default', () => {
  const v = createAccessVerifier({ teamDomain: TEAM, aud: AUD });
  assert.equal(v.issuer, TEAM);
  assert.equal(v.jwksUrl, `${TEAM}/cdn-cgi/access/certs`);
});

test('a service-principal verifier accepts a pinned common name', () => {
  const v = createAccessVerifier({
    teamDomain: TEAM,
    aud: AUD,
    principal: 'service',
    expectedCommonName: 'abc123.access',
  });
  assert.equal(v.issuer, TEAM);
});

test('pinning a common name on a user application is a configuration error', () => {
  assert.throws(
    () => createAccessVerifier({ teamDomain: TEAM, aud: AUD, principal: 'user', expectedCommonName: 'abc.access' }),
    AccessConfigError,
  );
});

test('misconfiguration throws rather than defaulting to open', () => {
  assert.throws(() => createAccessVerifier({ teamDomain: undefined, aud: AUD }), AccessConfigError);
  assert.throws(() => createAccessVerifier({ teamDomain: TEAM, aud: undefined }), AccessConfigError);
  assert.throws(() => createAccessVerifier({ teamDomain: TEAM, aud: 'too-short' }), AccessConfigError);
  assert.throws(() => createAccessVerifier({ teamDomain: 'http://insecure.example.com', aud: AUD }), AccessConfigError);
});

test('a missing assertion is rejected without throwing', async () => {
  const v = createAccessVerifier({ teamDomain: TEAM, aud: AUD, principal: 'service' });
  const res = await v.verify({ headers: {} } as never);
  assert.deepEqual(res, { ok: false, reason: 'missing token' });
});
