import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import { AuthSession } from '../electron/auth-session.ts';
import { authenticationIdleSeconds } from '../src/auth-idle.ts';

test('IPC verification handlers reject results invalidated by a concurrent idle lock', async () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const serializeSource = source.slice(
    source.indexOf('function serializeAuthOperation'),
    source.indexOf('function serializeAuthStateMutation'),
  );
  for (const channel of ['startup:unlock', 'auth:verify', 'auth:hello-verify']) {
    for (const outcome of [
      'current',
      'failed',
      'lock',
      'relock',
      'queued-lock',
      'queued-relock',
      ...(channel === 'auth:hello-verify' ? ['abort'] : []),
    ]) {
      const session = new AuthSession();
      session.remember({ configured: true }, outcome === 'lock' || outcome === 'queued-lock');
      const queued = outcome.startsWith('queued-');
      let releaseQueue!: () => void;
      const initialQueue = queued
        ? new Promise<void>((resolve) => {
            releaseQueue = resolve;
          })
        : Promise.resolve();
      let backendCalls = 0;
      const controller = new AbortController();
      let finish!: (value: { succeeded: boolean; workspace?: object }) => void;
      let started!: () => void;
      const ready = new Promise<void>((resolve) => {
        started = resolve;
      });
      let handler!: (event: object, request: object) => Promise<{ succeeded: boolean }>;
      const first = source.indexOf(`ipcMain.handle('${channel}'`);
      const last = source.indexOf('ipcMain.handle(', first + 1);
      assert.ok(first >= 0 && last > first);
      runInNewContext(
        stripTypeScriptTypes(
          `let authOperationQueue = initialQueue;\n${serializeSource}\n${source.slice(first, last)}`,
        ),
        {
          ipcMain: {
            handle: (_channel: string, callback: typeof handler) => {
              handler = callback;
            },
          },
          process: { platform: 'win32' },
          initialQueue,
          ensureAuthSession: async () => {},
          authSession: session,
          currentAuthState: { configured: true, mode: 'windowsHello' },
          BrowserWindow: {
            fromWebContents: () => ({
              isDestroyed: () => false,
              isVisible: () => true,
              focus: () => {},
            }),
          },
          nativeWindowHandle: () => '123',
          backendTimeoutMs: 30_000,
          mcpApprovalWindowCoordinator: {
            runPreemptibleOperation: (operation: (signal: AbortSignal) => unknown) =>
              operation(controller.signal),
          },
          runWithNativeAuthenticationWindow: (_owner: unknown, operation: () => unknown) =>
            operation(),
          runBackend: () => {
            backendCalls++;
            if (queued) return Promise.resolve({ succeeded: true, workspace: {} });
            return new Promise((resolve) => {
              finish = resolve;
              started();
            });
          },
        },
      );
      const pending = handler({ sender: {} }, {});
      if (queued) {
        session.lock();
        releaseQueue();
        await assert.rejects(pending, /locked during verification/, `${channel}: ${outcome}`);
        assert.equal(backendCalls, 0, 'a stale queued request must not start native verification');
        assert.equal(session.isAccessAllowed, false);
        continue;
      }
      await ready;
      if (outcome === 'lock' || outcome === 'relock') session.lock();
      if (outcome === 'abort') controller.abort();
      finish({
        succeeded: outcome !== 'failed',
        ...(channel === 'startup:unlock' && outcome !== 'failed' ? { workspace: {} } : {}),
      });
      if (outcome === 'lock' || outcome === 'relock') {
        await assert.rejects(pending, /locked during verification/, `${channel}: ${outcome}`);
      } else {
        const result = await pending;
        assert.equal(result.succeeded, outcome === 'current', `${channel}: ${outcome}`);
      }
      assert.equal(session.isAccessAllowed, outcome === 'current', `${channel}: ${outcome}`);
    }
  }
});

test('biometric unlock starts a fresh idle period without requiring keyboard or mouse input', () => {
  const unlocked = 600_000;
  assert.equal(authenticationIdleSeconds(600, unlocked, unlocked, unlocked), 0);
  assert.equal(authenticationIdleSeconds(615, unlocked, unlocked, unlocked + 15_000), 15);
  assert.equal(authenticationIdleSeconds(660, unlocked, unlocked, unlocked + 60_000), 60);
  // Preserve app inactivity locking even while the user works in another application.
  assert.equal(authenticationIdleSeconds(0, unlocked, unlocked, unlocked + 60_000), 60);
  assert.equal(authenticationIdleSeconds(2, unlocked + 58_000, unlocked, unlocked + 60_000), 2);
  assert.equal(authenticationIdleSeconds(600, unlocked, unlocked, unlocked - 1_000), 0);
});

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
  const epoch = session.authorizationEpoch;
  session.lock();
  assert.equal(session.authorizationEpoch, epoch + 1);
  session.remember({ configured: true }, false);
  assert.throws(() => session.requireUnlocked(), /Authentication is required/);
  assert.equal(session.isAccessAllowed, false);
  assert.equal(session.authorizationEpoch, epoch + 1);
});

test('verification started before a new lock cannot reopen the session', () => {
  for (const initiallyUnlocked of [true, false]) {
    const session = new AuthSession();
    session.remember({ configured: true }, initiallyUnlocked);
    const verificationEpoch = session.authorizationEpoch;
    session.lock();
    assert.throws(() => session.markUnlocked(verificationEpoch), /locked during verification/);
    assert.equal(session.isAccessAllowed, false);
    session.markUnlocked(session.authorizationEpoch);
    assert.equal(session.isAccessAllowed, true);
  }
});

test('an authorized-to-locked settings transition invalidates in-flight work', () => {
  const session = new AuthSession();

  session.remember({ configured: false }, false);
  const epoch = session.authorizationEpoch;
  session.remember({ configured: true }, false);

  assert.equal(session.authorizationEpoch, epoch + 1);
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
