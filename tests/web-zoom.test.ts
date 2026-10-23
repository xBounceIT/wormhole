import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import test from 'node:test';
import vm from 'node:vm';
import { adjustWebZoom } from '../electron/web-zoom.ts';
import { AuthSession } from '../electron/auth-session.ts';

const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
const slice = (from: string, to: string) => {
  const start = source.indexOf(from);
  const end = source.indexOf(to, start);
  assert.ok(start >= 0 && end > start);
  return source.slice(start, end);
};

test('web zoom changes in ten percentage point steps without accumulating rounding errors', () => {
  let factor = 1;
  const contents = {
    getZoomFactor: () => factor,
    setZoomFactor: (value: number) => {
      factor = value;
    },
  };
  adjustWebZoom(contents, 'zoom-in');
  assert.equal(factor, 1.1);
  adjustWebZoom(contents, 'zoom-in');
  assert.equal(factor, 1.2);
  adjustWebZoom(contents, 'zoom-out');
  assert.equal(factor, 1.1);
  adjustWebZoom(contents, 'zoom-out');
  assert.equal(factor, 1);
  adjustWebZoom(contents, 'zoom-out');
  assert.equal(factor, 0.9);

  for (let index = 0; index < 100; index++) adjustWebZoom(contents, 'zoom-in');
  assert.equal(factor, 3);
  for (let index = 0; index < 100; index++) adjustWebZoom(contents, 'zoom-out');
  assert.equal(factor, 0.5);
  adjustWebZoom(contents, 'zoom-in');
  assert.equal(factor, 0.6, 'zoom can move away from the lower limit');
});

test('web command validation accepts zoom commands and rejects malformed IPC requests', () => {
  const validate = vm.runInNewContext(
    stripTypeScriptTypes(
      `const sshMaxSessionIdLength = 128;
      ${slice('function isRecord(', 'function parseBackupPasswordRequest(')}
      ${slice('function isSshSessionId(', 'function isUuid(')}
      ${slice('function isWebCommandRequest(', 'function isTreeTooltipRequest(')}
      isWebCommandRequest;`,
    ),
  );
  for (const operation of ['back', 'forward', 'reload', 'stop', 'zoom-in', 'zoom-out']) {
    assert.equal(validate({ sessionId: 'session', operation }), true);
  }
  for (const request of [
    null,
    {},
    { sessionId: '', operation: 'zoom-in' },
    { sessionId: ' session ', operation: 'zoom-out' },
    { sessionId: 'x'.repeat(129), operation: 'zoom-in' },
    { sessionId: 'session', operation: 'zoom' },
    { sessionId: 'session', operation: 1 },
    { sessionId: 'session', operation: { toString: () => 'zoom-in' } },
  ]) {
    assert.equal(validate(request), false);
  }
});

function commandHarness(
  afterPopupInput: (operation: () => Promise<void>) => Promise<void> = (operation) => operation(),
) {
  const authSession = new AuthSession();
  authSession.remember({ configured: true }, true);
  const manager = vm.runInNewContext(
    stripTypeScriptTypes(
      `${slice('function isAuthorizationEpochCurrent(', 'function requireAuthorizationEpoch(')}
      new (class { ${slice('  async command(owner:', '  async openBitwardenPopup(')} })()`,
    ),
    {
      adjustWebZoom,
      authSession,
      afterBitwardenPopupInputEvent: afterPopupInput,
    },
  );
  let factor = 1;
  const operations: string[] = [];
  const owner = {};
  const record = {
    owner,
    disposed: false,
    view: {
      webContents: {
        getZoomFactor: () => factor,
        setZoomFactor: (value: number) => {
          factor = value;
        },
        navigationHistory: {
          canGoBack: () => true,
          goBack: () => operations.push('back'),
          canGoForward: () => true,
          goForward: () => operations.push('forward'),
        },
        stop: () => operations.push('stop'),
        reload: () => operations.push('reload'),
      },
    },
  };
  const surfaces = new Map([['session', record]]);
  Object.assign(manager, {
    surfaces,
    bitwardenPopups: new Map(),
    sendEvent: () => {},
  });
  return { manager, owner, record, surfaces, operations, authSession, factor: () => factor };
}

test('session commands zoom the owned page without reloading or changing navigation commands', async () => {
  const harness = commandHarness();
  for (const operation of ['zoom-in', 'zoom-out']) {
    await harness.manager.command(harness.owner, { sessionId: 'session', operation });
    assert.equal(harness.factor(), operation === 'zoom-in' ? 1.1 : 1);
  }
  assert.deepEqual(harness.operations, []);
  for (const operation of ['back', 'forward', 'stop', 'reload']) {
    await harness.manager.command(harness.owner, { sessionId: 'session', operation });
  }
  assert.deepEqual(harness.operations, ['back', 'forward', 'stop', 'reload']);
});

test('zoom ignores missing, disposed, and foreign sessions, including after popup dismissal', async () => {
  const harness = commandHarness();
  await harness.manager.command({}, { sessionId: 'session', operation: 'zoom-in' });
  await harness.manager.command(harness.owner, { sessionId: 'missing', operation: 'zoom-in' });
  harness.record.disposed = true;
  await harness.manager.command(harness.owner, { sessionId: 'session', operation: 'zoom-in' });
  assert.equal(harness.factor(), 1);

  harness.record.disposed = false;
  harness.manager.bitwardenPopups.set('session', {});
  let dismiss!: () => void;
  harness.manager.closeBitwardenPopup = () =>
    new Promise<void>((resolve) => {
      dismiss = resolve;
    });
  const pending = harness.manager.command(harness.owner, {
    sessionId: 'session',
    operation: 'zoom-in',
  });
  assert.equal(harness.factor(), 1, 'zoom waits for popup input to finish');
  harness.surfaces.delete('session');
  dismiss();
  await pending;
  assert.equal(harness.factor(), 1, 'a closed session must not be zoomed after an await');
});

test('a command waiting for popup dismissal cannot act on a reconnected session', async () => {
  const harness = commandHarness();
  const replacement = commandHarness();
  harness.manager.bitwardenPopups.set('session', {});
  let dismiss!: () => void;
  harness.manager.closeBitwardenPopup = () =>
    new Promise<void>((resolve) => {
      dismiss = resolve;
    });

  const pending = harness.manager.command(harness.owner, {
    sessionId: 'session',
    operation: 'zoom-in',
  });
  harness.record.disposed = true;
  harness.surfaces.set('session', { ...replacement.record, owner: harness.owner });
  dismiss();
  await pending;

  assert.equal(harness.factor(), 1, 'the old page stays disposed');
  assert.equal(replacement.factor(), 1, 'a queued zoom must not affect the new page');
});

test('zoom continues after popup dismissal when the original session is still live', async () => {
  const harness = commandHarness();
  harness.manager.bitwardenPopups.set('session', {});
  harness.manager.closeBitwardenPopup = async () => {
    harness.manager.bitwardenPopups.delete('session');
  };
  await harness.manager.command(harness.owner, { sessionId: 'session', operation: 'zoom-in' });
  assert.equal(harness.factor(), 1.1);
});

test('locking invalidates a zoom waiting for popup dismissal even if the app unlocks again', async () => {
  for (const unlockAgain of [false, true]) {
    const harness = commandHarness();
    harness.manager.bitwardenPopups.set('session', {});
    let dismiss!: () => void;
    harness.manager.closeBitwardenPopup = () =>
      new Promise<void>((resolve) => {
        dismiss = resolve;
      });
    const pending = harness.manager.command(harness.owner, {
      sessionId: 'session',
      operation: 'zoom-in',
    });
    harness.authSession.lock();
    if (unlockAgain) harness.authSession.markUnlocked();
    dismiss();
    await pending;
    assert.equal(harness.factor(), 1, 'a stale authorization must not perform a browser command');
  }
});

test('deferred popup dismissal cannot close a popup owned by a replacement session', async () => {
  let dispatch!: () => Promise<void>;
  const harness = commandHarness(
    (operation) =>
      new Promise<void>((resolve) => {
        dispatch = async () => {
          await operation();
          resolve();
        };
      }),
  );
  harness.manager.bitwardenPopups.set('session', {});
  let closed = false;
  harness.manager.closeBitwardenPopup = async () => {
    closed = true;
  };
  const pending = harness.manager.command(harness.owner, {
    sessionId: 'session',
    operation: 'zoom-in',
  });
  harness.surfaces.set('session', { ...harness.record });
  await dispatch();
  await pending;
  assert.equal(closed, false, 'a stale command must not dismiss the new session popup');
  assert.equal(harness.factor(), 1);
});
