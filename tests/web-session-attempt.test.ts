import assert from 'node:assert/strict';
import test from 'node:test';
import { savedConnectionAddressForEditor } from '../src/web-address.ts';
import { WebSessionAttemptTracker } from '../electron/web-session-attempt.ts';
import { webTargetURLMatchesEndpoint } from '../electron/web-target-validation.ts';

test('web session attempts are invalidated when a tab closes before its open completes', () => {
  const attempts = new WebSessionAttemptTracker();
  const opening = attempts.begin('web-1');

  attempts.cancel('web-1');
  const reopened = attempts.begin('web-1');

  assert.equal(attempts.isCurrent('web-1', opening), false);
  assert.equal(attempts.isCurrent('web-1', reopened), true);
});

test('web session attempts use last-request-wins semantics for a retry', () => {
  const attempts = new WebSessionAttemptTracker();
  const first = attempts.begin('web-1');
  const retry = attempts.begin('web-1');

  assert.equal(attempts.isCurrent('web-1', first), false);
  assert.equal(attempts.isCurrent('web-1', retry), true);
});

test('bulk cancellation invalidates every in-flight session without reusing generations', () => {
  const attempts = new WebSessionAttemptTracker();
  const first = attempts.begin('first');
  const second = attempts.begin('second');

  attempts.cancelAll();

  assert.equal(attempts.isCurrent('first', first), false);
  assert.equal(attempts.isCurrent('second', second), false);
  assert.ok(attempts.begin('first') > first);
});

test('credential editor reset invalidates an in-flight Bitwarden search', () => {
  const attempts = new WebSessionAttemptTracker();
  const searching = attempts.begin('credential-search');

  attempts.cancel('credential-search');

  assert.equal(attempts.isCurrent('credential-search', searching), false);
});

test('saved web addresses restore their context path in the shared connection editor', () => {
  assert.equal(
    savedConnectionAddressForEditor(
      'https',
      'appliance.example.test',
      '/admin/dashboard?tab=network#routes',
    ),
    'appliance.example.test/admin/dashboard?tab=network#routes',
  );
  assert.equal(
    savedConnectionAddressForEditor('http', 'appliance.example.test'),
    'appliance.example.test',
  );
  assert.equal(
    savedConnectionAddressForEditor('ssh', 'server.example.test', '/must-not-leak'),
    'server.example.test',
  );
});

test('web target validation accepts canonical DNS and IPv6 endpoint spellings', () => {
  assert.equal(
    webTargetURLMatchesEndpoint(new URL('https://example.test:8443/admin'), {
      protocol: 'https',
      host: 'Example.Test',
      port: 8443,
    }),
    true,
  );
  assert.equal(
    webTargetURLMatchesEndpoint(new URL('https://[fd00::1]:443/admin'), {
      protocol: 'https',
      host: 'fd00::1',
      port: 443,
    }),
    true,
  );
  assert.equal(
    webTargetURLMatchesEndpoint(new URL('https://xn--bcher-kva.example/admin'), {
      protocol: 'https',
      host: 'BÜCHER.example',
      port: 443,
    }),
    true,
  );
});

test('web target validation rejects endpoint and credential mismatches', () => {
  const endpoint = { protocol: 'https' as const, host: 'example.test', port: 8443 };
  assert.equal(
    webTargetURLMatchesEndpoint(new URL('https://example.test:9443/admin'), endpoint),
    false,
  );
  assert.equal(
    webTargetURLMatchesEndpoint(new URL('https://other.example.test:8443/admin'), endpoint),
    false,
  );
  assert.equal(
    webTargetURLMatchesEndpoint(new URL('https://user@example.test:8443/admin'), endpoint),
    false,
  );
});
