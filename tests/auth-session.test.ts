import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import { EventEmitter } from 'node:events';
import { Session } from 'node:inspector/promises';
import { coverageThreshold } from '../scripts/test-coverage.ts';
import { AuthSession } from '../electron/auth-session.ts';
import { authenticationIdleSeconds } from '../src/auth-idle.ts';

// main.ts is a process entrypoint, so measure its isolated production handlers
// with V8 directly, as the renderer harness does for the authentication modal.
async function measureHandlerCoverage(
  context: { diagnostic(message: string): void; after(callback: () => void): void },
  filename: string,
  scope?: { start: number; end: number },
) {
  // A second precise profiler resets Node's global module coverage counters.
  // Normal auth tests enforce handler coverage; the coverage run owns its profiler.
  if (process.execArgv.includes('--experimental-test-coverage') || process.env.NODE_V8_COVERAGE) {
    context.diagnostic(
      'Precise handler coverage is enforced by the normal authentication test run.',
    );
    return async () => {};
  }
  const session = new Session();
  session.connect();
  context.after(() => session.disconnect());
  await session.post('Profiler.enable');
  await session.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  return async () => {
    const coverage = await session.post('Profiler.takePreciseCoverage');
    const blocks = new Map<string, number>();
    for (const script of coverage.result.filter((script) => script.url === filename)) {
      for (const fn of script.functions) {
        for (const range of fn.ranges) {
          if (scope && (range.startOffset < scope.start || range.endOffset > scope.end)) continue;
          const key = `${range.startOffset}:${range.endOffset}`;
          blocks.set(key, (blocks.get(key) ?? 0) + range.count);
        }
      }
    }
    assert.ok(blocks.size > 0, `Missing V8 coverage for ${filename}`);
    const percent = (100 * [...blocks.values()].filter((count) => count > 0).length) / blocks.size;
    context.diagnostic(`${filename}: V8 block coverage ${percent.toFixed(2)}%`);
    assert.ok(percent >= coverageThreshold, `${filename} coverage is below ${coverageThreshold}%`);
    await session.post('Profiler.stopPreciseCoverage');
  };
}

test('backend keeps idle-lock Hello alive until native completion or owner cancellation', async (context) => {
  const filename = 'wormhole-auth-backend-runner.js';
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const runner = source.slice(
    source.indexOf('async function runBackend'),
    source.indexOf('// ---- update checks / downloads ----'),
  );
  const script = stripTypeScriptTypes(`${runner}\nrunBackend`);
  // Existing argument and stream plumbing is outside this change. Measure the
  // modified timeout block, including its process kill and rejection callback.
  const finishCoverage = await measureHandlerCoverage(context, filename, {
    start: script.indexOf('    const timeout ='),
    end: script.indexOf('    const abort ='),
  });
  for (const outcome of [
    'success',
    'failure',
    'cancel',
    'timeout',
    'availability',
    'backup',
    'aborted',
    'invalid',
    'oversized',
    'spawn-error',
    'stdin-error',
    'stdout-limit',
  ]) {
    const child = new EventEmitter() as EventEmitter & {
      stdout: EventEmitter & { setEncoding: () => void };
      stderr: EventEmitter & { setEncoding: () => void };
      stdin: EventEmitter & { end: () => void };
      kill: () => void;
    };
    child.stdout = Object.assign(new EventEmitter(), { setEncoding: () => {} });
    child.stderr = Object.assign(new EventEmitter(), { setEncoding: () => {} });
    child.stdin = Object.assign(new EventEmitter(), { end: () => {} });
    let kills = 0;
    child.kill = () => {
      kills++;
    };
    let timer: (() => void) | undefined;
    let duration: number | undefined;
    let spawns = 0;
    const controller = new AbortController();
    const run = runInNewContext(
      script,
      {
        AbortSignal,
        Buffer,
        backendTimeoutMs: 30_000,
        backupTimeoutMs: 120_000,
        backendMaxRequestBytes: 1024,
        backendMaxBuffer: 1024,
        backendPath: () => 'backend',
        wormholeDatabasePath: () => 'database',
        electronUserDataPath: () => 'profile',
        process: {},
        spawn: () => {
          spawns++;
          return child;
        },
        setTimeout: (callback: () => void, milliseconds: number) => {
          timer = callback;
          duration = milliseconds;
          return 1;
        },
        clearTimeout: () => {
          timer = undefined;
        },
      },
      { filename },
    );
    if (outcome === 'aborted') controller.abort();
    const operation =
      outcome === 'availability'
        ? 'auth-hello-status'
        : outcome === 'backup'
          ? 'backup-export'
          : outcome === 'timeout'
            ? 'auth-verify'
            : 'auth-hello-verify';
    const pending = run(
      operation,
      outcome === 'oversized' ? 'x'.repeat(1024) : {},
      30_000,
      controller.signal,
    );
    if (['aborted', 'oversized'].includes(outcome)) {
      await assert.rejects(pending, outcome === 'aborted' ? /cancelled/ : /too large/);
      assert.equal(spawns, 0);
      continue;
    }
    if (['timeout', 'availability', 'backup'].includes(outcome)) {
      assert.equal(duration, outcome === 'backup' ? 120_000 : 30_000);
      timer!();
      await assert.rejects(pending, /did not respond in time/);
      assert.equal(kills, 1);
      continue;
    }
    assert.equal(
      timer,
      undefined,
      'interactive Hello must survive both 30- and 45-second deadlines',
    );
    if (outcome === 'cancel') {
      controller.abort();
      assert.equal(kills, 1);
      child.emit('close', 0);
      await assert.rejects(pending, /cancelled/);
    } else if (outcome === 'failure') {
      child.stderr.emit('data', 'native failure');
      child.emit('close', 1);
      await assert.rejects(pending, /native failure/);
    } else if (outcome === 'spawn-error' || outcome === 'stdin-error') {
      (outcome === 'spawn-error' ? child : child.stdin).emit('error', new Error('process failed'));
      await assert.rejects(pending, /process failed/);
    } else if (outcome === 'stdout-limit') {
      child.stdout.emit('data', 'x'.repeat(1025));
      await assert.rejects(pending, /too much data/);
      assert.equal(kills, 1);
    } else {
      child.stdout.emit('data', outcome === 'invalid' ? '{' : '{"succeeded":true}');
      child.emit('close', 0);
      if (outcome === 'invalid') await assert.rejects(pending, /invalid data/);
      else assert.equal((await pending).succeeded, true);
      assert.equal(kills, 0);
    }
  }
  await finishCoverage();
});

test('IPC verification handlers reject results invalidated by a concurrent idle lock', async (context) => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const serializeSource = source.slice(
    source.indexOf('function serializeAuthOperation'),
    source.indexOf('function serializeAuthStateMutation'),
  );
  const helloStart = source.indexOf("ipcMain.handle('auth:hello-verify'");
  const helloScript = stripTypeScriptTypes(
    `let authOperationQueue = initialQueue;\n${serializeSource}\n${source.slice(helloStart, source.indexOf('ipcMain.handle(', helloStart + 1))}`,
  );
  const filename = 'wormhole-auth-hello-handler.js';
  const finishCoverage = await measureHandlerCoverage(context, filename, {
    start: helloScript.indexOf('      const ownerLifetime ='),
    end: helloScript.length,
  });
  for (const channel of ['startup:unlock', 'auth:verify', 'auth:hello-verify']) {
    for (const outcome of [
      'current',
      'failed',
      'lock',
      'relock',
      'queued-lock',
      'queued-relock',
      ...(channel === 'auth:hello-verify'
        ? ['abort', 'reload', 'destroy', 'error', 'abort-error']
        : []),
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
      const sender = new EventEmitter();
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
          AbortController,
          AbortSignal,
          authLockRequested: false,
          activeHelloVerification: undefined,
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
          runBackend: (
            _operation: unknown,
            _request: unknown,
            _timeout: unknown,
            signal?: AbortSignal,
          ) => {
            backendCalls++;
            if (queued) return Promise.resolve({ succeeded: true, workspace: {} });
            return new Promise((resolve, reject) => {
              finish = resolve;
              started();
              if (outcome === 'error') reject(new Error('native failure'));
              signal?.addEventListener(
                'abort',
                () => {
                  if (outcome === 'abort-error') reject(new Error('cancelled'));
                  else resolve({ succeeded: true });
                },
                { once: true },
              );
            });
          },
        },
        { filename: channel === 'auth:hello-verify' ? filename : channel },
      );
      const pending = handler({ sender }, {});
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
      if (outcome === 'abort' || outcome === 'abort-error') controller.abort();
      if (outcome === 'reload') sender.emit('did-start-loading');
      if (outcome === 'destroy') sender.emit('destroyed');
      if (outcome !== 'error') {
        finish({
          succeeded: outcome !== 'failed',
          ...(channel === 'startup:unlock' && outcome !== 'failed' ? { workspace: {} } : {}),
        });
      }
      if (outcome === 'error') {
        await assert.rejects(pending, /native failure/);
      } else if (outcome === 'lock' || outcome === 'relock') {
        await assert.rejects(pending, /locked during verification/, `${channel}: ${outcome}`);
      } else {
        const result = await pending;
        assert.equal(result.succeeded, outcome === 'current', `${channel}: ${outcome}`);
      }
      assert.equal(session.isAccessAllowed, outcome === 'current', `${channel}: ${outcome}`);
      assert.equal(sender.listenerCount('destroyed'), 0);
      assert.equal(sender.listenerCount('did-start-loading'), 0);
    }
  }
  await finishCoverage();
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

test('idle lock cancels an earlier Hello before draining security mutations and permits a fresh unlock', async () => {
  type IpcHandler = (event: object, request?: object) => Promise<{ succeeded: boolean }>;
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const serialization = source.slice(
    source.indexOf('function serializeAuthOperation'),
    source.indexOf('async function runAuthorizedOperation'),
  );
  const handlersSource = source.slice(
    source.indexOf("ipcMain.handle('auth:update-settings'"),
    source.indexOf("ipcMain.handle('auth:system-idle'"),
  );
  for (const scenario of ['confirmation', 'queued-settings', 'starting-verification']) {
    const session = new AuthSession();
    session.remember({ configured: true }, true);
    const sender = new EventEmitter();
    const handlers = new Map<string, IpcHandler>();
    let helloCalls = 0;
    let firstSignal: AbortSignal | undefined;
    let holdHello = false;
    let pauseNextEnsure: (() => Promise<void>) | undefined;
    let start!: () => void;
    const started = new Promise<void>((resolve) => {
      start = resolve;
    });
    let releaseHelloStart!: () => void;
    let delayedHelloStart = false;
    const blockedStart = new Promise<void>((resolve) => {
      releaseHelloStart = resolve;
    });
    const context = runInNewContext(
      stripTypeScriptTypes(`
      let authOperationQueue = Promise.resolve();
      let authStateMutationQueue = Promise.resolve();
      let authLockRequested = false;
      let activeHelloVerification;
      ${serialization}
      ${handlersSource}
      ({ get lockRequested() { return authLockRequested; }, get activeHello() { return activeHelloVerification; } })
    `),
      {
        ipcMain: {
          handle: (channel: string, handler: IpcHandler) => handlers.set(channel, handler),
        },
        process: { platform: 'win32' },
        AbortController,
        AbortSignal,
        authSession: session,
        currentAuthState: { configured: true, mode: 'windowsHello' },
        ensureAuthSession: async () => {
          if (pauseNextEnsure) {
            const pause = pauseNextEnsure;
            pauseNextEnsure = undefined;
            await pause();
          }
          if (scenario === 'starting-verification' && !delayedHelloStart) {
            delayedHelloStart = true;
            start();
            await blockedStart;
          }
        },
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
            operation(new AbortController().signal),
        },
        runWithNativeAuthenticationWindow: (_owner: unknown, operation: () => unknown) =>
          operation(),
        runBackend: (
          _operation: unknown,
          _request: unknown,
          _timeout: unknown,
          signal: AbortSignal,
        ) => {
          helloCalls++;
          if (!holdHello && (helloCalls > 1 || scenario === 'starting-verification'))
            return Promise.resolve({ succeeded: true });
          firstSignal = signal;
          start();
          return new Promise((_resolve, reject) =>
            signal.addEventListener('abort', () => reject(new Error('cancelled')), { once: true }),
          );
        },
        cancelAllUserOperations: () => {},
        backupImportSelections: new WeakMap(),
        sshPrivateKeySelections: new WeakMap(),
        mremoteImportAnalysis: new WeakMap(),
        mremoteImportSelections: new WeakMap(),
        sshBackend: {
          prepareForLock: () => {},
          closeAllSftp: () => {},
          cancelPendingConnections: () => {},
          setMcpLocked: async () => {},
        },
        webSurfaces: { hideAll: () => {} },
        nativeBackend: undefined,
        rdpClient: undefined,
        cancelPreparingRdpStarts: () => {},
      },
    );
    const hello = handlers.get('auth:hello-verify')!;
    const oldConfirmation = hello({ sender });
    await started;
    const queuedSettings =
      scenario === 'queued-settings'
        ? handlers.get('auth:update-settings')!({ sender }, {}).then(
            () => {
              throw new Error('settings changed during lock');
            },
            (error) => assert.match(error.message, /Authentication is required/),
          )
        : Promise.resolve();
    const locked = handlers.get('auth:lock')!({ sender });
    assert.equal(context.lockRequested, true);
    if (scenario === 'starting-verification') releaseHelloStart();
    else
      assert.equal(
        firstSignal?.aborted,
        true,
        'locking must cancel Hello before waiting for queued settings',
      );
    assert.equal((await oldConfirmation).succeeded, false);
    await queuedSettings;
    await locked;
    assert.equal(session.isAccessAllowed, false);
    assert.equal(context.activeHello, undefined);
    assert.equal(sender.listenerCount('destroyed'), 0);
    assert.equal(sender.listenerCount('did-start-loading'), 0);
    assert.equal(
      (await hello({ sender })).succeeded,
      true,
      'the new lock must allow a fresh verification',
    );
    assert.equal(session.isAccessAllowed, true);
    assert.equal(helloCalls, scenario === 'starting-verification' ? 1 : 2);
    if (scenario === 'confirmation') {
      let releaseLock!: () => void;
      let lockReady!: () => void;
      const lockStarted = new Promise<void>((resolve) => {
        lockReady = resolve;
      });
      const lockPause = new Promise<void>((resolve) => {
        releaseLock = resolve;
      });
      pauseNextEnsure = () => {
        lockReady();
        return lockPause;
      };
      const firstLock = handlers.get('auth:lock')!({ sender });
      await lockStarted;
      await handlers.get('auth:lock')!({ sender });
      holdHello = true;
      const nextHelloStarted = new Promise<void>((resolve) => {
        start = resolve;
      });
      const staleUnlock = hello({ sender });
      await nextHelloStarted;
      releaseLock();
      await firstLock;
      assert.equal(
        firstSignal?.aborted,
        true,
        'the final lock transition must cancel verification started between overlapping locks',
      );
      assert.equal((await staleUnlock).succeeded, false);
      assert.equal(session.isAccessAllowed, false);
    }
  }
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
