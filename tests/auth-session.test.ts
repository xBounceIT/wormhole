import assert from 'node:assert/strict';
import test from 'node:test';
import { AuthSession } from '../electron/auth-session.ts';

test('configured authentication starts locked until a native verification succeeds', () => {
  const session = new AuthSession();

  assert.throws(() => session.requireUnlocked(), /state is not initialized/);
  assert.equal(session.isAccessAllowed, false);
  session.remember({ configured: true }, false);
  assert.throws(() => session.requireUnlocked(), /Authentication is required/);
  assert.equal(session.isAccessAllowed, false);

  session.markUnlocked();
  assert.doesNotThrow(() => session.requireUnlocked());
  assert.equal(session.isAccessAllowed, true);
});

test('locking a configured session blocks workspace access again', () => {
  const session = new AuthSession();

  session.remember({ configured: true }, true);
  session.lock();
  session.remember({ configured: true }, false);
  assert.throws(() => session.requireUnlocked(), /Authentication is required/);
  assert.equal(session.isAccessAllowed, false);
});

test('authorized settings transitions preserve the current unlocked session', () => {
  const session = new AuthSession();

  session.remember({ configured: false }, false);
  session.remember({ configured: true }, true);
  assert.doesNotThrow(() => session.requireUnlocked());

  session.remember({ configured: true }, false);
  assert.doesNotThrow(() => session.requireUnlocked());
});

test('a newly enabled configuration starts locked after a disabled transition', () => {
  const session = new AuthSession();

  session.remember({ configured: true }, true);
  session.remember({ configured: false }, false);
  session.remember({ configured: true }, false);
  assert.throws(() => session.requireUnlocked(), /Authentication is required/);
});

test('unlock listeners fire once when access crosses the locked boundary', () => {
  const session = new AuthSession();
  let notifications = 0;
  const unsubscribe = session.onUnlocked(() => notifications++);

  session.remember({ configured: true }, false);
  assert.equal(notifications, 0);

  session.markUnlocked();
  session.markUnlocked();
  assert.equal(notifications, 1);

  session.lock();
  session.markUnlocked();
  assert.equal(notifications, 2);

  unsubscribe();
  session.lock();
  session.markUnlocked();
  assert.equal(notifications, 2);
});
