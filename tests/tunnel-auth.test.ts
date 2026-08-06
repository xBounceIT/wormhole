import assert from 'node:assert/strict';
import test from 'node:test';
import { isMatchingOAuthRedirect } from '../electron/tunnel-auth.ts';

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
