import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import vm from 'node:vm';
import {
  afterBitwardenPopupInputEvent,
  closeBitwardenPopupContents,
  flushAndCloseBitwardenPopupContents,
  prepareBitwardenPopupStorage,
} from '../electron/bitwarden-popup-lifecycle.ts';
import {
  BitwardenStorageCheckpointError,
  synchronizeBitwardenStorage,
} from '../electron/bitwarden-storage-sync.ts';
import { McpApprovalWindowCoordinator } from '../electron/mcp-approval-window.ts';
import { KeyedSingleFlight } from '../electron/keyed-single-flight.ts';
import {
  isPointInsideBitwardenAnchor,
  positionBitwardenPopup,
} from '../electron/bitwarden-popup-layout.ts';

// Exercise the actual main-process opening path with native surfaces replaced by event emitters.
// Electron's entrypoint cannot be imported into node:test without starting the whole application.
function popupHarness({
  hydrated = true,
  failSync = true,
  authorized = true,
  failNavigation = false,
  checkpointFailure = true,
  synchronize,
  flush,
  dialogClosed = Promise.resolve(),
}: {
  hydrated?: boolean;
  failSync?: boolean;
  authorized?: boolean;
  failNavigation?: boolean;
  checkpointFailure?: boolean;
  synchronize?: () => Promise<void>;
  flush?: () => Promise<void>;
  dialogClosed?: Promise<void>;
} = {}) {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const start = source.indexOf('  async openBitwardenPopup(');
  const end = source.indexOf('  private serializeBitwardenStorage', start);
  assert.ok(start >= 0 && end > start);
  const events: unknown[] = [];
  const dialogs: unknown[] = [];
  const warnings: unknown[] = [];
  const coordinator = new McpApprovalWindowCoordinator();
  let flushes = 0;
  const background = {};
  let visible = false;
  let loaded = false;
  const contents = () =>
    Object.assign(new EventEmitter(), {
      isDestroyed: () => false,
      setWindowOpenHandler: () => {},
      close: () => {},
      send: (_channel: string, event: unknown) => events.push(event),
      loadURL: async () => {
        loaded = true;
        if (failNavigation) throw new Error('navigation failed');
      },
    });
  const owner = Object.assign(new EventEmitter(), {
    webContents: contents(),
    isDestroyed: () => false,
    getContentSize: () => [1024, 768],
    contentView: { addChildView: () => {}, removeChildView: () => {} },
  });
  const context = {
    WebContentsView: class {
      webContents = contents();
      setBounds() {}
      setVisible(value: boolean) {
        visible = value;
      }
    },
    authSession: { authorizationEpoch: 1 },
    isAuthorizationEpochCurrent: () => authorized,
    mcpApprovalWindowCoordinator: coordinator,
    bitwardenExtensionHostMaxListeners: 50,
    bitwardenBrowserNavigationTimeoutMs: 15000,
    withBitwardenBrowserTimeout: (operation: Promise<unknown>) => operation,
    afterBitwardenPopupInputEvent,
    prepareBitwardenPopupStorage,
    BitwardenStorageCheckpointError,
    closeBitwardenPopupContents,
    flushAndCloseBitwardenPopupContents,
    isPointInsideBitwardenAnchor,
    positionBitwardenPopup,
    URL,
    console: { warn: (...args: unknown[]) => warnings.push(args) },
    showCoordinatedMessageBox: (_owner: unknown, options: unknown) =>
      coordinator.runNativeDialog(async () => {
        dialogs.push(options);
        await dialogClosed;
      }),
  };
  const manager = vm.runInNewContext(
    stripTypeScriptTypes(`new (class { ${source.slice(start, end)} })()`),
    context,
  );
  Object.assign(manager, {
    bitwardenPopupOpens: new KeyedSingleFlight(),
    bitwardenPopupRequest: undefined,
    surfaces: new Map([
      [
        'session',
        {
          owner,
          disposed: false,
          view: { webContents: contents() },
          bitwarden: { partition: 'persist:test', popupUrl: 'chrome-extension://test/popup.html' },
        },
      ],
    ]),
    bitwardenPopups: new Map(),
    bitwardenPopupDismissHandlers: new Map(),
    activeBitwardenSessions: new Map(),
    initializedBitwardenStorage: new WeakSet(hydrated ? [background] : []),
    bitwardenBackgroundContents: () => background,
    synchronizeBitwardenStorageInBridge: async () => {
      if (synchronize) return synchronize();
      if (failSync)
        throw checkpointFailure
          ? new BitwardenStorageCheckpointError()
          : new Error('private vault data');
    },
    synchronizeBitwardenStorageInContents: async () => {
      flushes++;
      if (flush) return flush();
      throw new Error('private vault data');
    },
  });
  return {
    open: (sessionId = 'session') =>
      manager.openBitwardenPopup({
        sessionId,
        anchor: { x: 20, y: 20, width: 28, height: 28 },
      }),
    events,
    dialogs,
    warnings,
    coordinator,
    lock: () => {
      authorized = false;
    },
    dismiss: () => manager.closeBitwardenPopup('session', false),
    flushes: () => flushes,
    visible: () => visible,
    loaded: () => loaded,
    addSession: (id: string) => manager.surfaces.set(id, { ...manager.surfaces.get('session') }),
    disposeSession: () => {
      manager.surfaces.get('session').disposed = true;
    },
    popupIds: () => [...manager.bitwardenPopups.keys()],
  };
}

test('the newest popup request wins while an older request waits for another popup to flush', async () => {
  let finishFlush!: () => void;
  const harness = popupHarness({
    flush: () =>
      new Promise<void>((resolve) => {
        finishFlush = resolve;
      }),
  });
  harness.addSession('old');
  harness.addSession('newest');
  assert.equal((await harness.open('old')).open, true);
  const pending = harness.open();
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(harness.flushes(), 1);
  assert.equal((await harness.open('newest')).open, true);
  finishFlush();
  assert.equal((await pending).open, false);
  assert.deepEqual(harness.popupIds(), ['newest']);
});

test('a disposed or canceled tab cannot attach a popup after waiting for another popup to close', async () => {
  for (const cancel of ['dispose', 'dismiss']) {
    let finishFlush!: () => void;
    const harness = popupHarness({
      flush: () =>
        new Promise<void>((resolve) => {
          finishFlush = resolve;
        }),
    });
    harness.addSession('old');
    await harness.open('old');
    const pending = harness.open();
    await new Promise<void>((resolve) => setImmediate(resolve));
    if (cancel === 'dispose') harness.disposeSession();
    else await harness.dismiss();
    finishFlush();
    assert.equal((await pending).open, false);
    assert.deepEqual(harness.popupIds(), []);
  }
});

test('main process shows the HTTPS popup when a restored background checkpoint fails', async () => {
  for (const failSync of [true, false]) {
    const harness = popupHarness({ failSync });
    assert.equal((await harness.open()).open, true);
    assert.equal(harness.visible(), true);
    assert.equal(harness.loaded(), true);
    assert.deepEqual(
      harness.events.map((event) => JSON.parse(JSON.stringify(event))),
      [{ sessionId: 'session', open: true }],
    );
    assert.equal(harness.dialogs.length, 0);
  }
});

test('main process reports preparation and navigation failures without revealing vault details', async () => {
  for (const options of [
    { hydrated: false },
    { failNavigation: true },
    { checkpointFailure: false },
  ]) {
    const harness = popupHarness(options);
    assert.equal((await harness.open()).open, false);
    assert.equal(harness.visible(), false);
    assert.equal(harness.dialogs.length, 1);
    assert.match(JSON.stringify(harness.dialogs), /Could not open Bitwarden/);
    assert.doesNotMatch(JSON.stringify(harness.dialogs), /private vault data|navigation failed/);
    assert.doesNotMatch(JSON.stringify(harness.warnings), /private vault data|navigation failed/);
    assert.equal(harness.flushes(), 0, 'a failed hidden popup must not repeat storage work');
  }
});

test('a canceled popup attempt does not show a late failure dialog', async () => {
  let reject!: (error: Error) => void;
  const harness = popupHarness({
    synchronize: () =>
      new Promise<void>((_resolve, fail) => {
        reject = fail;
      }),
  });
  const opening = harness.open();
  await new Promise<void>((resolve) => setImmediate(resolve));
  await harness.dismiss();
  reject(new Error('private vault data'));
  assert.equal((await opening).open, false);
  assert.equal(harness.dialogs.length, 0);
  assert.equal(harness.warnings.length, 0);
  assert.equal(harness.visible(), false);
  assert.equal(harness.loaded(), false);
});

test('a popup failure dialog stays coordinated and coalesces clicks until dismissed', async () => {
  let closeDialog!: () => void;
  const harness = popupHarness({
    hydrated: false,
    dialogClosed: new Promise<void>((resolve) => {
      closeDialog = resolve;
    }),
  });
  let completed = false;
  const first = harness.open().then(() => {
    completed = true;
  });
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(harness.dialogs.length, 1);
  assert.equal(completed, false);
  const second = harness.open();
  await harness.coordinator.beginApproval('approval');
  let presented = false;
  harness.coordinator.presentApprovalWhenNativeDialogsClose('approval', () => {
    presented = true;
  });
  assert.equal(presented, false);
  closeDialog();
  await Promise.all([first, second]);
  assert.equal(presented, true);
  assert.equal(harness.dialogs.length, 1);
});

test('pending approvals suppress both popup presentation and error dialogs', async () => {
  for (const hydrated of [true, false]) {
    const harness = popupHarness({ hydrated });
    await harness.coordinator.beginApproval('approval');
    assert.equal((await harness.open()).open, false);
    assert.equal(harness.visible(), false);
    assert.equal(harness.dialogs.length, 0);
  }
});

test('losing authorization prevents the popup and its failure dialog from appearing', async () => {
  for (const hydrated of [true, false]) {
    const harness = popupHarness({ authorized: false, hydrated });
    assert.equal((await harness.open()).open, false);
    assert.equal(harness.visible(), false);
    assert.equal(harness.dialogs.length, 0);
  }
});

test('lock or approval arriving during storage preparation prevents late popup presentation', async () => {
  for (const interrupt of ['lock', 'approval']) {
    let finish!: () => void;
    const harness = popupHarness({
      flush: async () => {},
      synchronize: () =>
        new Promise<void>((resolve) => {
          finish = resolve;
        }),
    });
    const opening = harness.open();
    await new Promise<void>((resolve) => setImmediate(resolve));
    if (interrupt === 'lock') harness.lock();
    else await harness.coordinator.beginApproval('approval');
    finish();
    assert.equal((await opening).open, false);
    assert.equal(harness.visible(), false);
    assert.equal(harness.dialogs.length, 0);
    assert.deepEqual(harness.popupIds(), []);
  }
});

test('main storage wrapper preserves only classified checkpoint failures', async () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const start = source.indexOf('  private async synchronizeBitwardenStorageCore(');
  const end = source.indexOf('  private bitwardenBackgroundContents(', start);
  assert.ok(start >= 0 && end > start);
  const contents = { isDestroyed: () => false };
  for (const failure of [new BitwardenStorageCheckpointError(), new Error('private vault data')]) {
    const manager = vm.runInNewContext(
      stripTypeScriptTypes(`new (class { ${source.slice(start, end)} })()`),
      {
        electronSession: { fromPartition: () => ({ storagePath: 'test-profile' }) },
        synchronizeBitwardenStorage: async () => {
          throw failure;
        },
        BitwardenStorageCheckpointError,
      },
    );
    Object.assign(manager, {
      serializeBitwardenStorage: (operation: () => Promise<unknown>) => operation(),
      initializedBitwardenStorage: new WeakSet([contents]),
    });
    await assert.rejects(
      manager.synchronizeBitwardenStorageCore('test', contents),
      (error: unknown) => {
        assert.equal(
          error instanceof BitwardenStorageCheckpointError,
          failure instanceof BitwardenStorageCheckpointError,
        );
        assert.doesNotMatch(String(error), /private vault data/);
        return true;
      },
    );
  }
});

test('popup opens after hydration even when the protected checkpoint cannot be saved', async () => {
  let hydrated = false;
  let live = { localJson: '{}', sessionJson: '{}' };
  const saved = {
    localJson: '{"account":"remembered"}',
    sessionJson: '{}',
    revision: 4,
    profileRevision: 0,
    restore: false,
    durable: true,
  };
  await prepareBitwardenPopupStorage(
    () =>
      synchronizeBitwardenStorage(
        {
          read: async () => saved,
          capture: async () => live,
          restore: async (snapshot) => {
            live = snapshot;
          },
          hydrated: () => {
            hydrated = true;
          },
          commit: async () => ({ ...saved, durable: false }),
          flush: async () => {},
        },
        true,
      ),
    (error) => error instanceof BitwardenStorageCheckpointError && hydrated,
  );
  assert.equal(hydrated, true);
  assert.equal(live.localJson, saved.localJson);
});

test('popup preparation waits for successful storage synchronization', async () => {
  let finish!: () => void;
  let completed = false;
  const pending = prepareBitwardenPopupStorage(
    () =>
      new Promise<void>((resolve) => {
        finish = resolve;
      }),
    () => assert.fail('successful synchronization needs no fallback'),
  ).then(() => {
    completed = true;
  });
  await Promise.resolve();
  assert.equal(completed, false);
  finish();
  await pending;
  assert.equal(completed, true);
});

test('an initialized background remains accessible during a checkpoint failure', async () => {
  await prepareBitwardenPopupStorage(
    async () => {
      throw new BitwardenStorageCheckpointError();
    },
    (error) => error instanceof BitwardenStorageCheckpointError,
  );
});

test('failed initial hydration blocks popup editing and sanitizes extension errors', async () => {
  await assert.rejects(
    prepareBitwardenPopupStorage(
      async () => {
        throw new Error('private vault data');
      },
      () => false,
    ),
    { message: 'Bitwarden could not restore its saved browser session. Please try again.' },
  );
});

test('popup teardown waits until the current Blink input event has completed', async () => {
  let ran = false;
  const pending = afterBitwardenPopupInputEvent(async () => {
    ran = true;
  });
  assert.equal(ran, false);
  await pending;
  assert.equal(ran, true);
});

test('closing is a no-op after Bitwarden has destroyed its popup contents', () => {
  assert.doesNotThrow(() => closeBitwardenPopupContents({ webContents: undefined }));
});

test('closing ignores contents that Electron already marked as destroyed', () => {
  let closes = 0;
  closeBitwardenPopupContents({
    webContents: {
      isDestroyed: () => true,
      close: () => {
        closes += 1;
      },
    },
  });
  assert.equal(closes, 0);
});

test('closing live popup contents happens exactly once', () => {
  let closes = 0;
  closeBitwardenPopupContents({
    webContents: {
      isDestroyed: () => false,
      close: () => {
        closes += 1;
      },
    },
  });
  assert.equal(closes, 1);
});

test('closing tolerates Electron invalidating the view during inspection', () => {
  assert.doesNotThrow(() =>
    closeBitwardenPopupContents({
      webContents: {
        isDestroyed: () => {
          throw new TypeError('target closed');
        },
        close: () => assert.fail('destroyed popup must not be closed again'),
      },
    }),
  );
});

test('popup storage finishes flushing before its live contents close', async () => {
  let closes = 0;
  let finishFlush!: () => void;
  const flushPending = new Promise<void>((resolve) => {
    finishFlush = resolve;
  });
  const popup = {
    webContents: {
      isDestroyed: () => false,
      close: () => {
        closes += 1;
      },
    },
  };

  const closing = flushAndCloseBitwardenPopupContents(popup, () => flushPending);
  await Promise.resolve();
  assert.equal(closes, 0);

  finishFlush();
  assert.equal(await closing, true);
  assert.equal(closes, 1);
});

test('popup contents still close when their storage flush fails', async () => {
  let closes = 0;
  const popup = {
    webContents: {
      isDestroyed: () => false,
      close: () => {
        closes += 1;
      },
    },
  };

  await assert.rejects(
    flushAndCloseBitwardenPopupContents(popup, async () => {
      throw new Error('capture failed');
    }),
    /capture failed/,
  );
  assert.equal(closes, 1);
});

test('destroyed popup contents request a storage fallback without flushing', async () => {
  let flushes = 0;
  const flushed = await flushAndCloseBitwardenPopupContents(
    {
      webContents: {
        isDestroyed: () => true,
        close: () => assert.fail('destroyed popup must not be closed again'),
      },
    },
    async () => {
      flushes += 1;
    },
  );

  assert.equal(flushed, false);
  assert.equal(flushes, 0);
});

test('popup invalidation during flush inspection requests the storage fallback', async () => {
  let flushes = 0;
  const flushed = await flushAndCloseBitwardenPopupContents(
    {
      webContents: {
        isDestroyed: () => {
          throw new TypeError('target closed');
        },
        close: () => assert.fail('invalidated popup must not be closed again'),
      },
    },
    async () => {
      flushes += 1;
    },
  );

  assert.equal(flushed, false);
  assert.equal(flushes, 0);
});
