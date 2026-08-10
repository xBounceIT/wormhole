import assert from 'node:assert/strict';
import test from 'node:test';
import {
  isMatchingOAuthRedirect,
  isSameCertificateHostname,
  tunnelAuthPartition,
} from '../electron/tunnel-auth.ts';

const redirect = 'http://localhost:2023/';

test('OAuth callback matching accepts only the configured loopback endpoint', () => {
  assert.equal(isMatchingOAuthRedirect(new URL('http://localhost:2023/?code=ok'), redirect), true);
  assert.equal(
    isMatchingOAuthRedirect(new URL('http://localhost:2023/other?code=no'), redirect),
    false,
  );
  assert.equal(
    isMatchingOAuthRedirect(new URL('http://localhost:20230/?code=no'), redirect),
    false,
  );
  assert.equal(
    isMatchingOAuthRedirect(new URL('http://localhost:2023@attacker.test/?code=no'), redirect),
    false,
  );
  assert.equal(
    isMatchingOAuthRedirect(new URL('https://localhost:2023/?code=no'), redirect),
    false,
  );
});

test('VPN browser authentication uses isolated persistent provider profiles', () => {
  assert.equal(
    tunnelAuthPartition({ completion: 'cookie' }),
    'persist:wormhole-tunnel-auth-fortinet',
  );
  assert.equal(
    tunnelAuthPartition({ completion: 'oauth-code' }),
    'persist:wormhole-tunnel-auth-azure',
  );
  assert.equal(
    new Set([
      tunnelAuthPartition({ completion: 'cookie' }),
      tunnelAuthPartition({
        completion: 'query-token',
        origin: 'https://firebox.example.test',
        ignoreCertificateErrors: false,
      }),
      tunnelAuthPartition({ completion: 'oauth-code' }),
    ]).size,
    3,
  );
});

test('WatchGuard browser profiles isolate cached certificate decisions by origin and policy', () => {
  const verified = tunnelAuthPartition({
    completion: 'query-token',
    origin: 'https://firebox.example.test',
    ignoreCertificateErrors: false,
  });
  assert.equal(
    verified,
    tunnelAuthPartition({
      completion: 'query-token',
      origin: 'https://FIREBOX.example.test:443/ignored-path',
      ignoreCertificateErrors: false,
    }),
  );
  assert.notEqual(
    verified,
    tunnelAuthPartition({
      completion: 'query-token',
      origin: 'https://firebox.example.test',
      ignoreCertificateErrors: true,
    }),
  );
  assert.notEqual(
    verified,
    tunnelAuthPartition({
      completion: 'query-token',
      origin: 'https://other-firebox.example.test',
      ignoreCertificateErrors: false,
    }),
  );
});

test('certificate host matching normalizes DNS spelling and IPv6 brackets without broadening scope', () => {
  assert.equal(isSameCertificateHostname('FIREBOX.EXAMPLE.TEST', 'firebox.example.test'), true);
  assert.equal(isSameCertificateHostname('firebox.example.test.', 'firebox.example.test'), true);
  assert.equal(isSameCertificateHostname('2001:db8::1', '[2001:db8::1]'), true);
  assert.equal(isSameCertificateHostname('[2001:DB8::1]', '[2001:db8::1]'), true);
  assert.equal(
    isSameCertificateHostname('firebox.example.test.evil', 'firebox.example.test'),
    false,
  );
  assert.equal(isSameCertificateHostname('2001:db8::2', '[2001:db8::1]'), false);
});
