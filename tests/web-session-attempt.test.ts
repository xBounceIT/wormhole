import assert from 'node:assert/strict';
import test from 'node:test';
import { WebSessionAttemptTracker } from '../electron/web-session-attempt.ts';

test('web session attempts are invalidated when a tab closes before its open completes', () => {
  const attempts = new WebSessionAttemptTracker();
  const opening = attempts.begin('web-1');

  attempts.cancel('web-1');

  assert.equal(attempts.isCurrent('web-1', opening), false);
});

test('web session attempts use last-request-wins semantics for a retry', () => {
  const attempts = new WebSessionAttemptTracker();
  const first = attempts.begin('web-1');
  const retry = attempts.begin('web-1');

  assert.equal(attempts.isCurrent('web-1', first), false);
  assert.equal(attempts.isCurrent('web-1', retry), true);
});

test('credential editor reset invalidates an in-flight Bitwarden search', () => {
  const attempts = new WebSessionAttemptTracker();
  const searching = attempts.begin('credential-search');

  attempts.cancel('credential-search');

  assert.equal(attempts.isCurrent('credential-search', searching), false);
});
