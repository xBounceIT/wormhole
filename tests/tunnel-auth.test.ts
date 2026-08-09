import assert from 'node:assert/strict';
import test from 'node:test';
import { isMatchingOAuthRedirect, tunnelAuthPartition } from '../electron/tunnel-auth.ts';

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
  assert.equal(tunnelAuthPartition('cookie'), 'persist:wormhole-tunnel-auth-fortinet');
  assert.equal(tunnelAuthPartition('query-token'), 'persist:wormhole-tunnel-auth-watchguard');
  assert.equal(tunnelAuthPartition('oauth-code'), 'persist:wormhole-tunnel-auth-azure');
  assert.equal(
    new Set([
      tunnelAuthPartition('cookie'),
      tunnelAuthPartition('query-token'),
      tunnelAuthPartition('oauth-code'),
    ]).size,
    3,
  );
});
