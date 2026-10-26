import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import vm from 'node:vm';
import { Session as InspectorSession } from 'node:inspector/promises';
import { before, after } from 'node:test';
import { coverageThreshold } from '../scripts/test-coverage.ts';
import {
  afterBitwardenPopupInputEvent,
  BitwardenBrowserFailure,
  describeBitwardenBrowserFailure,
  closeBitwardenPopupContents,
  flushAndCloseBitwardenPopupContents,
  prepareBitwardenPopupStorage,
} from '../electron/bitwarden-popup-lifecycle.ts';
import {
  BitwardenStorageCheckpointError,
  checkpointBitwardenStorageBeforeClose,
  synchronizeBitwardenStorage,
} from '../electron/bitwarden-storage-sync.ts';
import { McpApprovalWindowCoordinator } from '../electron/mcp-approval-window.ts';
import { KeyedSingleFlight } from '../electron/keyed-single-flight.ts';
import { ExtensionMutationGuard } from '../electron/extension-mutation-guard.ts';
import { KeyedTaskTracker } from '../electron/keyed-task-tracker.ts';
import {
  isPointInsideBitwardenAnchor,
  positionBitwardenPopup,
} from '../electron/bitwarden-popup-layout.ts';

let profiler: InspectorSession | undefined;
before(async () => {
  if (process.execArgv.includes('--experimental-test-coverage') || process.env.NODE_V8_COVERAGE)
    return;
  profiler = new InspectorSession();
  profiler.connect();
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
});

after(async () => {
  if (!profiler) return;
  try {
    const coverage = await profiler.post('Profiler.takePreciseCoverage');
    const blocks = new Map<string, number>();
    for (const script of coverage.result.filter((item) =>
      [
        'wormhole-bitwarden-popup.js',
        'wormhole-bitwarden-storage-core.js',
        'wormhole-bitwarden-storage-bridge.js',
        'wormhole-bitwarden-update.js',
      ].includes(item.url),
    )) {
      const scopes = script.functions
        .filter((fn) =>
          [
            'openBitwardenPopupCore',
            'synchronizeBitwardenStorageCore',
            'synchronizeBitwardenStorageInBridge',
            'reportBitwardenBrowserFailure',
            'runBitwardenExtensionMutation',
            'flushBitwardenBackgroundStorage',
            'unloadBitwardenExtensionsForUpdate',
            'checkpointAndUnloadBitwardenProfile',
            'retireBitwardenProfile',
            'checkpointBitwardenStorage',
          ].includes(fn.functionName),
        )
        .map((fn) => fn.ranges[0]);
      for (const fn of script.functions) {
        if (
          !scopes.some(
            (scope) =>
              fn.ranges[0].startOffset >= scope.startOffset &&
              fn.ranges[0].endOffset <= scope.endOffset,
          )
        )
          continue;
        for (const range of fn.ranges) {
          const key = `${script.url}:${range.startOffset}:${range.endOffset}`;
          blocks.set(key, (blocks.get(key) ?? 0) + range.count);
        }
      }
    }
    assert.ok(blocks.size > 0);
    const percent = (100 * [...blocks.values()].filter((value) => value > 0).length) / blocks.size;
    console.log(`Bitwarden popup preparation: V8 block coverage ${percent.toFixed(2)}%`);
    assert.ok(
      percent >= coverageThreshold,
      `Bitwarden popup coverage is below ${coverageThreshold}%`,
    );
    await profiler.post('Profiler.stopPreciseCoverage');
  } finally {
    profiler.disconnect();
  }
});

function updateHarness(mode = 'merge', idle: Promise<void> = Promise.resolve()) {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const method = (start: string, end: string) => {
    const from = source.indexOf(start);
    const to = source.indexOf(end, from);
    assert.ok(from >= 0 && to > from);
    return source.slice(from, to);
  };
  const code = [
    method('  private reportBitwardenBrowserFailure(', '  async closeBitwardenPopup('),
    method('  private serializeBitwardenStorage', '  private bitwardenBackgroundContents('),
    method('  async runBitwardenExtensionMutation', '  close(sessionId:'),
    method('  private async retireBitwardenProfile(', '  private dispose('),
  ].join('\n');
  const events: string[] = [];
  const reports: unknown[] = [];
  const warnings: unknown[] = [];
  const unloaded = new Set<string>();
  const live = new Map([
    ['first', '{"account":"saved"}'],
    ['second', '{"account":"saved"}'],
  ]);
  const persisted = new Map<string, string>();
  const revisions = new Map([
    ['first', 0],
    ['second', 0],
  ]);
  const commits = new Map<string, number>();
  const history: string[] = [];
  const change = (partition: string) => {
    if (unloaded.has(partition)) return;
    revisions.set(partition, revisions.get(partition)! + 1);
    live.set(partition, JSON.stringify({ account: 'changed', revision: revisions.get(partition) }));
  };
  const contents = ['first', 'second'].map((partition) => ({
    partition,
    destroyed: false,
    isDestroyed() {
      return this.destroyed || mode === 'disappeared' || unloaded.has(partition);
    },
    getType: () => 'backgroundPage',
  }));
  const currentContents = new Map([
    ['first', contents[0]],
    ['second', contents[1]],
  ]);
  const accepted = {
    localJson: '{"account":"saved"}',
    sessionJson: '{"token":"newer"}',
    revision: 5,
    profileRevision: mode === 'unacknowledged' ? 4 : 5,
    restore: !mode.startsWith('matched'),
    durable: mode !== 'unpersisted',
  };
  const matchedState = new Map<string, typeof accepted>();
  const manager = vm.runInNewContext(
    stripTypeScriptTypes(`new (class { ${code} })()`),
    {
      Error,
      BitwardenStorageCheckpointError,
      describeBitwardenBrowserFailure,
      synchronizeBitwardenStorage,
      checkpointBitwardenStorageBeforeClose,
      waitForBitwardenBackgroundStorage: async (contents: {
        partition: string;
        destroyed: boolean;
      }) => {
        if (mode === 'unready') throw new Error('private details timed out');
        if (mode === 'dead-ready-next-unload-failure' && contents.partition === 'first') {
          contents.destroyed = true;
          throw new Error('Bitwarden storage page closed');
        }
      },
      readBitwardenStorageRevision: async (contents: {
        partition: string;
        isDestroyed(): boolean;
      }) => {
        if (contents.isDestroyed()) throw new Error('Bitwarden storage page closed');
        return revisions.get(contents.partition)!;
      },
      validateBitwardenBrowserStorageSnapshot: (value: unknown) => value,
      captureBitwardenExtensionStorage: async (contents: { partition: string }) => {
        events.push('capture');
        return { localJson: live.get(contents.partition)!, sessionJson: '{"token":"older"}' };
      },
      restoreBitwardenExtensionStorage: async () => {
        events.push('restore');
      },
      markBitwardenStorageRevision: async () => {
        assert.ok(
          mode.startsWith('matched'),
          'an unconsumed merge must not advance the native marker',
        );
        events.push('marker');
      },
      electronSession: {
        fromPartition: (partition: string) => ({
          storagePath: partition,
          flushStorageData: () => {},
          cookies: { flushStore: async () => {} },
          extensions: {
            removeExtension: () => {
              if (
                mode === 'unload-failure' ||
                (mode === 'dead-ready-next-unload-failure' && partition === 'second')
              )
                throw new Error('private extension path');
              events.push(`unload:${partition}`);
              history.push(`unload:${partition}`);
              unloaded.add(partition);
            },
          },
        }),
      },
      runBitwardenBackend: async (
        action: string,
        values: { profilePath?: string; localJson?: string },
      ) => {
        if (action === 'bitwarden.browser-failure') {
          reports.push(values);
          return;
        }
        events.push(action);
        history.push(`${action.endsWith('-read') ? 'read' : 'commit'}:${values.profilePath}`);
        if (action === 'bitwarden.browser-storage-read') {
          if (mode === 'read-failure' && values.profilePath === 'second')
            throw new Error('private vault data');
          if (mode === 'between-profiles' && values.profilePath === 'second') change('first');
          if (mode.startsWith('matched'))
            return (
              matchedState.get(values.profilePath!) ?? {
                ...accepted,
                sessionJson: '{"token":"older"}',
                revision: 4,
                profileRevision: 4,
              }
            );
          return { ...accepted, revision: 4, profileRevision: 4, durable: true };
        }
        const partition = values.profilePath!;
        commits.set(partition, (commits.get(partition) ?? 0) + 1);
        if (accepted.durable) persisted.set(partition, values.localJson!);
        if (
          (((mode === 'during-save' || mode === 'matched-during-save') &&
            commits.get(partition) === 1) ||
            mode === 'endless' ||
            mode === 'matched-endless') &&
          partition === 'first'
        )
          change(partition);
        if (
          (mode === 'replaced' || mode === 'died-during-save') &&
          partition === 'first' &&
          commits.get(partition) === 1
        ) {
          contents[0].destroyed = true;
          if (mode === 'replaced') {
            change(partition);
            currentContents.set('first', { ...contents[0], destroyed: false });
          }
        }
        if (mode.startsWith('matched')) {
          const previous = matchedState.get(partition) ?? {
            ...accepted,
            sessionJson: '{"token":"older"}',
            revision: 4,
            profileRevision: 4,
          };
          const revision = previous.revision + (previous.localJson === values.localJson ? 0 : 1);
          const next = {
            ...previous,
            localJson: values.localJson!,
            revision,
            profileRevision: revision,
          };
          matchedState.set(partition, next);
          return next;
        }
        return { ...accepted, localJson: values.localJson };
      },
      console: {
        error: (...args: unknown[]) => warnings.push(args),
        warn: (...args: unknown[]) => warnings.push(args),
      },
    },
    { filename: 'wormhole-bitwarden-update.js' },
  );
  const storageTasks = new KeyedTaskTracker<string>();
  const waitForAllIdle = storageTasks.waitForAllIdle.bind(storageTasks);
  storageTasks.waitForAllIdle = async () => {
    await idle;
    await waitForAllIdle();
  };
  Object.assign(manager, {
    bitwardenStorageQueue: Promise.resolve(),
    bitwardenStorageTasks: storageTasks,
    retiringBitwardenProfiles: new Set(),
    bitwardenExtensionMutation: new ExtensionMutationGuard(),
    initializedBitwardenStorage: new WeakSet(contents),
    extensionIds: new Map([
      ['first', 'test'],
      ['second', 'test'],
    ]),
    extensionLoadKeys: new Map([
      ['first', 'old'],
      ['second', 'old'],
    ]),
    extensionPopupPaths: new Map([
      ['first', 'popup.html'],
      ['second', 'popup.html'],
    ]),
    isBitwardenProfileUnused: (partition: string) =>
      mode !== 'became-active' || partition !== 'second',
    bitwardenBackgroundContents: (partition: string) =>
      mode === 'missing' || (mode === 'dead-ready-next-unload-failure' && partition === 'second')
        ? undefined
        : currentContents.get(partition),
    bitwardenStoragePaused: false,
  });
  if (mode === 'not-saved') manager.synchronizeBitwardenStorageCore = async () => false;
  return {
    manager,
    events,
    reports,
    warnings,
    live,
    persisted,
    revisions,
    commits,
    history,
    unloaded,
    update: (
      operation: () => Promise<void> = async () => {
        events.push('install');
      },
    ) => manager.runBitwardenExtensionMutation(operation),
  };
}

test('the extension update checkpoints every acknowledged profile before replacing the bundle', async () => {
  const harness = updateHarness();
  await harness.update();
  assert.equal(
    harness.events.filter((event) => event === 'bitwarden.browser-storage-capture').length,
    2,
  );
  assert.equal(harness.events.at(-1), 'install');
  assert.equal(harness.events.includes('restore'), false);
  assert.ok(harness.history.indexOf('commit:first') < harness.history.indexOf('unload:first'));
  assert.ok(harness.history.indexOf('unload:first') < harness.history.indexOf('read:second'));
  assert.deepEqual(harness.events.slice(-2), ['unload:second', 'install']);
  assert.equal(harness.manager.extensionIds.size, 0);
  assert.equal(harness.manager.extensionLoadKeys.size, 0);
  assert.equal(harness.manager.extensionPopupPaths.size, 0);
  assert.equal(harness.reports.length, 0);
  assert.equal(harness.manager.bitwardenStoragePaused, false);
});

for (const mode of ['during-save', 'between-profiles']) {
  test(`update preserves mutations for the ${mode} interleaving`, async () => {
    const harness = updateHarness(mode);
    await harness.update();
    assert.equal(
      harness.persisted.get('first'),
      harness.live.get('first'),
      `${mode}: unloading discarded a late mutation`,
    );
    assert.ok(
      harness.history.indexOf('unload:first') < harness.history.indexOf('read:second'),
      'each saved host must stop before another profile can delay its unload',
    );
  });
}

test('an endlessly changing background remains loaded and prevents replacing the bundle', async () => {
  const harness = updateHarness('endless');
  await assert.rejects(harness.update(), /changed|conflict/);
  assert.equal(harness.events.includes('install'), false);
  assert.equal(harness.unloaded.has('first'), false);
  assert.equal(harness.commits.get('first'), 3);
});

test('a new accepted mutation owns its pause before the previous caller resumes', async () => {
  const harness = updateHarness();
  // Production main and ExtensionMutationGuard share a Promise realm. A VM-only method
  // adds thenable-assimilation turns which can accidentally hide the handoff race.
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const start = source.indexOf('  async runBitwardenExtensionMutation');
  const end = source.indexOf('  private async flushBitwardenBackgroundStorage', start);
  const Host = new Function(
    `return ${stripTypeScriptTypes(`(class { ${source.slice(start, end)} })`)}`,
  )();
  harness.manager.runBitwardenExtensionMutation = Host.prototype.runBitwardenExtensionMutation;
  let finishFirst!: () => void;
  let finishSecond!: () => void;
  const first = harness.update(
    () =>
      new Promise<void>((resolve) => {
        finishFirst = resolve;
      }),
  );
  await new Promise<void>((resolve) => setImmediate(resolve));
  finishFirst();
  for (let turn = 0; turn < 8 && !harness.manager.bitwardenExtensionMutation.canAutoMutate; turn++)
    await Promise.resolve();
  assert.equal(harness.manager.bitwardenExtensionMutation.canAutoMutate, true);
  const second = harness.update(
    () =>
      new Promise<void>((resolve) => {
        finishSecond = resolve;
      }),
  );
  try {
    await Promise.resolve();
    assert.equal(
      harness.manager.bitwardenStoragePaused,
      true,
      'the older caller released the newer mutation pause',
    );
  } finally {
    await new Promise<void>((resolve) => setImmediate(resolve));
    finishSecond();
    await Promise.all([first, second]);
  }
});

test('a dead earlier profile cannot mislabel a later native unload failure as a readiness failure', async () => {
  const harness = updateHarness('dead-ready-next-unload-failure');
  await assert.rejects(harness.update(), /Diagnostic code: checkpoint\/failed/);
  assert.equal(harness.events.includes('install'), false);
  assert.equal(harness.unloaded.has('first'), true);
  assert.equal(harness.unloaded.has('second'), false);
});

test('ordinary profile retirement also checkpoints a refresh arriving during its save', async () => {
  const harness = updateHarness('matched-during-save');
  await harness.manager.retireBitwardenProfile('first');
  assert.equal(
    harness.persisted.get('first'),
    harness.live.get('first'),
    'the ordinary close path discarded a refresh before the update could start',
  );
  assert.equal(harness.unloaded.has('first'), true);
});

test('ordinary retirement retains a continuously changing host for a later retry', async () => {
  const harness = updateHarness('matched-endless');
  await assert.rejects(harness.manager.retireBitwardenProfile('first'), /changed|conflict/);
  assert.equal(harness.unloaded.has('first'), false);
});

test('update and ordinary retirement share the saved state and unload each host only once', async () => {
  const harness = updateHarness('matched-during-save');
  await Promise.all([harness.manager.retireBitwardenProfile('first'), harness.update()]);
  assert.equal(harness.persisted.get('first'), harness.live.get('first'));
  assert.equal(harness.events.filter((event) => event === 'unload:first').length, 1);
  assert.equal(harness.events.filter((event) => event === 'unload:second').length, 1);
  assert.equal(harness.manager.retiringBitwardenProfiles.size, 0);
  assert.equal(harness.manager.extensionIds.size, 0);
});

test('an already reconciled profile is marked and unloaded before the update', async () => {
  const harness = updateHarness('matched');
  await harness.update();
  assert.equal(harness.events.filter((event) => event === 'marker').length, 2);
  assert.deepEqual(harness.events.slice(-2), ['unload:second', 'install']);
});

test('an ordinary checkpoint still reconciles live state while update checkpoints can accept a saved merge', async () => {
  const harness = updateHarness();
  await assert.rejects(
    harness.manager.checkpointBitwardenStorage(),
    /Diagnostic code: restore\/conflict/,
  );
  const restores = harness.events.filter((event) => event === 'restore').length;
  assert.equal(restores, 6);
  await harness.update();
  assert.equal(harness.events.filter((event) => event === 'restore').length, restores);
  assert.equal(harness.events.at(-1), 'install');
});

test('a disappeared background does not block an update and a live unsaved profile still does', async () => {
  for (const mode of ['missing', 'disappeared', 'died-during-save', 'not-saved']) {
    const harness = updateHarness(mode);
    if (mode === 'not-saved') {
      await assert.rejects(harness.update(), /Diagnostic code: checkpoint\/closed/);
      assert.equal(harness.events.includes('install'), false);
    } else {
      await harness.update();
      assert.equal(harness.events.at(-1), 'install');
    }
  }
});

test('failed or unacknowledged saves block replacement and report a sanitized cause', async () => {
  for (const [mode, code] of [
    ['unpersisted', 'commit/unavailable'],
    ['unacknowledged', 'restore/conflict'],
    ['read-failure', 'read/failed'],
    ['replaced', 'checkpoint/conflict'],
    ['unready', 'background/timeout'],
  ]) {
    const harness = updateHarness(mode);
    await assert.rejects(harness.update(), (error: unknown) => {
      assert.ok(error instanceof Error || String(error).includes('Error:'));
      assert.ok(String(error).includes(`Diagnostic code: ${code}`));
      return true;
    });
    assert.equal(harness.events.includes('install'), false);
    assert.equal(
      harness.unloaded.has('second'),
      false,
      'the failed or unprocessed profile must remain available',
    );
    assert.equal(
      harness.unloaded.has('first'),
      mode === 'read-failure',
      'only an already saved stable profile may close before a later failure',
    );
    assert.equal(harness.reports.length, 1);
    assert.deepEqual(JSON.parse(JSON.stringify(harness.reports[0])), { value: code });
    assert.doesNotMatch(JSON.stringify(harness.warnings), /private vault data/);
    assert.equal(harness.manager.bitwardenStoragePaused, false);
    assert.equal(harness.manager.bitwardenExtensionMutation.canAutoMutate, true);
  }
});

test('an active profile or failed native unload prevents replacing the extension files', async () => {
  for (const mode of ['became-active', 'unload-failure']) {
    const harness = updateHarness(mode);
    await assert.rejects(
      harness.update(),
      /could not be prepared for the update.*checkpoint\/failed/,
    );
    assert.equal(harness.events.includes('install'), false);
    assert.equal(
      harness.events.some((event) => event.startsWith('unload:')),
      false,
    );
    assert.equal(harness.manager.extensionIds.size, 2);
    assert.equal(harness.manager.bitwardenStoragePaused, false);
    assert.doesNotMatch(JSON.stringify(harness.warnings), /private extension path/);
  }
});

test('pending storage and failed installers cannot leave the mutation guard or checkpoint pause stuck', async () => {
  let finish!: () => void;
  const harness = updateHarness(
    'merge',
    new Promise<void>((resolve) => {
      finish = resolve;
    }),
  );
  const pending = harness.update(async () => {
    throw new Error('installer failed');
  });
  const rejected = assert.rejects(pending, /installer failed/);
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(harness.manager.bitwardenStoragePaused, true);
  assert.deepEqual(harness.events, []);
  await assert.rejects(harness.update(), /Close every HTTPS tab/);
  assert.equal(
    harness.manager.bitwardenStoragePaused,
    true,
    'a rejected second update must not release the first update pause',
  );
  finish();
  await rejected;
  assert.equal(harness.manager.bitwardenStoragePaused, false);
  assert.equal(harness.manager.bitwardenExtensionMutation.canAutoMutate, true);
  const release = harness.manager.bitwardenExtensionMutation.reserveUse();
  await assert.rejects(harness.update(), /Close every HTTPS tab/);
  assert.equal(harness.manager.bitwardenStoragePaused, false);
  release();
  await harness.update();
  assert.equal(harness.events.at(-1), 'install');
});

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
  failReport = false,
}: {
  hydrated?: boolean;
  failSync?: boolean;
  authorized?: boolean;
  failNavigation?: boolean;
  checkpointFailure?: boolean;
  synchronize?: () => Promise<void>;
  flush?: () => Promise<void>;
  dialogClosed?: Promise<void>;
  failReport?: boolean;
} = {}) {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const start = source.indexOf('  async openBitwardenPopup(');
  const end = source.indexOf('  private serializeBitwardenStorage', start);
  assert.ok(start >= 0 && end > start);
  const events: unknown[] = [];
  const dialogs: unknown[] = [];
  const warnings: unknown[] = [];
  const reports: unknown[] = [];
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
    describeBitwardenBrowserFailure,
    prepareBitwardenPopupStorage,
    BitwardenStorageCheckpointError,
    closeBitwardenPopupContents,
    flushAndCloseBitwardenPopupContents,
    isPointInsideBitwardenAnchor,
    positionBitwardenPopup,
    URL,
    console: {
      warn: (...args: unknown[]) => warnings.push(args),
      error: (...args: unknown[]) => warnings.push(args),
    },
    runBitwardenBackend: async (...args: unknown[]) => {
      reports.push(args);
      if (failReport) throw new Error('private report failure');
    },
    showCoordinatedMessageBox: (_owner: unknown, options: unknown) =>
      coordinator.runNativeDialog(async () => {
        dialogs.push(options);
        await dialogClosed;
      }),
  };
  const manager = vm.runInNewContext(
    stripTypeScriptTypes(`new (class { ${source.slice(start, end)} })()`),
    context,
    { filename: 'wormhole-bitwarden-popup.js' },
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
    reports,
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
    switchTab: () => {
      manager.surfaces.get('session').view = { webContents: contents() };
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

test('a popup waiting for storage cannot appear over a different browser tab', async () => {
  let finish!: () => void;
  const harness = popupHarness({
    synchronize: () =>
      new Promise<void>((resolve) => {
        finish = resolve;
      }),
    flush: async () => {},
  });
  const pending = harness.open();
  await new Promise<void>((resolve) => setImmediate(resolve));
  harness.switchTab();
  finish();
  assert.equal((await pending).open, false);
  assert.deepEqual(harness.popupIds(), []);
  assert.equal(harness.dialogs.length, 0);
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
    assert.equal(harness.reports.length, 1);
    assert.deepEqual(JSON.parse(JSON.stringify(harness.reports[0])), [
      'bitwarden.browser-failure',
      { value: options.failNavigation ? 'popup/failed' : 'prepare/failed' },
      5000,
    ]);
    assert.match(JSON.stringify(harness.dialogs), /Diagnostic code:/);
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
  assert.equal(harness.reports.length, 0);
  assert.equal(harness.visible(), false);
  assert.equal(harness.loaded(), false);
});

test('a failed diagnostic write cannot suppress popup failure feedback or leak its error', async () => {
  const harness = popupHarness({ failReport: true, checkpointFailure: false });
  assert.equal((await harness.open()).open, false);
  assert.equal(harness.dialogs.length, 1);
  assert.equal(harness.reports.length, 1);
  assert.doesNotMatch(JSON.stringify(harness.warnings), /private/);
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
        describeBitwardenBrowserFailure,
      },
      { filename: 'wormhole-bitwarden-storage-core.js' },
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

test('main storage preparation preserves the exact failing stage without exposing backend or vault details', async () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const start = source.indexOf('  private async synchronizeBitwardenStorageCore(');
  const end = source.indexOf('  private bitwardenBackgroundContents(', start);
  for (const failed of [
    'none',
    'profile',
    'background',
    'migrations',
    'read',
    'capture',
    'restore',
    'restored-migrations',
    'commit',
    'flush',
    'marker',
    'destroyed',
  ]) {
    const events: string[] = [];
    let live = { localJson: '{}', sessionJson: '{}' };
    let migrations = 0;
    const contents = { isDestroyed: () => failed === 'destroyed', getType: () => 'backgroundPage' };
    const initialized = new WeakSet();
    const step = (stage: string) => {
      events.push(stage);
      if (failed === stage) throw new Error('private vault value');
    };
    const shared = {
      localJson: '{"account":"remembered"}',
      sessionJson: '{}',
      revision: 1,
      profileRevision: 0,
      restore: false,
      durable: true,
    };
    const manager = vm.runInNewContext(
      stripTypeScriptTypes(`new (class { ${source.slice(start, end)} })()`),
      {
        electronSession: {
          fromPartition: () => ({
            storagePath: failed === 'profile' ? '' : 'test-profile',
            flushStorageData: () => step('flush'),
            cookies: { flushStore: async () => {} },
          }),
        },
        waitForBitwardenBackgroundStorage: async () => step('background'),
        prepareBitwardenStorageMigrations: async () =>
          step(++migrations === 1 ? 'migrations' : 'restored-migrations'),
        synchronizeBitwardenStorage,
        validateBitwardenBrowserStorageSnapshot: (snapshot: unknown) => snapshot,
        runBitwardenBackend: async (
          action: string,
          values: { localJson: string; sessionJson: string },
        ) => {
          step(action.endsWith('-read') ? 'read' : 'commit');
          return action.endsWith('-read') ? shared : { ...shared, ...values, revision: 2 };
        },
        captureBitwardenExtensionStorage: async () => {
          step('capture');
          return { ...live };
        },
        restoreBitwardenExtensionStorage: async (_contents: unknown, snapshot: typeof live) => {
          step('restore');
          live = { localJson: snapshot.localJson, sessionJson: snapshot.sessionJson };
        },
        markBitwardenStorageRevision: async () => step('marker'),
        BitwardenStorageCheckpointError,
        describeBitwardenBrowserFailure,
      },
      { filename: 'wormhole-bitwarden-storage-core.js' },
    );
    Object.assign(manager, {
      serializeBitwardenStorage: (operation: () => Promise<unknown>) => operation(),
      initializedBitwardenStorage: initialized,
    });
    if (failed === 'none' || failed === 'destroyed') {
      assert.equal(
        await manager.synchronizeBitwardenStorageCore('test', contents),
        failed === 'none',
      );
      if (failed === 'none') {
        assert.ok(events.indexOf('background') < events.indexOf('capture'));
        assert.deepEqual(live, { localJson: shared.localJson, sessionJson: shared.sessionJson });
        assert.ok(initialized.has(contents));
      } else assert.deepEqual(events, []);
    } else {
      await assert.rejects(
        manager.synchronizeBitwardenStorageCore('test', contents),
        (error: unknown) => {
          if (failed === 'marker') assert.ok(error instanceof BitwardenStorageCheckpointError);
          else {
            assert.ok(error instanceof BitwardenBrowserFailure);
            assert.equal(error.stage, failed === 'restored-migrations' ? 'migrations' : failed);
          }
          assert.doesNotMatch(String(error), /private/);
          return true;
        },
      );
    }
  }
});

test('the storage bridge waits for background readiness and falls back only when the background disappears', async () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const start = source.indexOf('  private async synchronizeBitwardenStorageInBridge(');
  const end = source.indexOf('  private synchronizeBitwardenStorageInContents(', start);
  for (const scenario of [
    'delayed',
    'disappeared',
    'absent',
    'unready',
    'checkpoint',
    'bridge-checkpoint',
    'navigation',
    'closed',
    'attach',
  ]) {
    let allocated = 0,
      closed = 0,
      removed = 0,
      synchronized = 0;
    let destroyed = false;
    let ready!: () => void;
    const pending = new Promise<void>((resolve) => {
      ready = resolve;
    });
    const background = { isDestroyed: () => destroyed, executeJavaScript: async () => false };
    const manager = vm.runInNewContext(
      stripTypeScriptTypes(`new (class { ${source.slice(start, end)} })()`),
      {
        URL,
        bitwardenExtensionHostMaxListeners: 50,
        bitwardenBrowserNavigationTimeoutMs: 15000,
        withBitwardenBrowserTimeout: (operation: Promise<unknown>) => operation,
        waitForBitwardenBackgroundStorage: async () => {
          await pending;
          if (scenario === 'unready' || scenario === 'disappeared')
            throw new Error('private vault data');
        },
        BitwardenStorageCheckpointError,
        describeBitwardenBrowserFailure,
        closeBitwardenPopupContents,
        WebContentsView: class {
          constructor() {
            allocated++;
          }
          setVisible() {}
          setBounds() {}
          webContents = {
            setMaxListeners() {},
            loadURL: async () => {
              if (scenario === 'navigation') throw new Error('private URL');
            },
            isDestroyed: () => false,
            close: () => {
              closed++;
            },
          };
        },
      },
      { filename: 'wormhole-bitwarden-storage-bridge.js' },
    );
    Object.assign(manager, {
      bitwardenStorageTasks: {
        run: (_partition: string, operation: () => Promise<unknown>) => operation(),
      },
      bitwardenBackgroundContents: () =>
        ['absent', 'bridge-checkpoint', 'navigation', 'closed', 'attach'].includes(scenario)
          ? undefined
          : background,
      synchronizeBitwardenStorageCore: async () => {
        synchronized++;
        if (scenario.endsWith('checkpoint')) throw new BitwardenStorageCheckpointError();
        return scenario !== 'closed';
      },
    });
    const operation = manager.synchronizeBitwardenStorageInBridge(
      {
        contentView: {
          addChildView: () => {
            if (scenario === 'attach') throw new Error('private owner');
          },
          removeChildView: () => {
            removed++;
          },
        },
      },
      'persist:test',
      'chrome-extension://test/popup.html',
    );
    // Register the rejection handler before releasing readiness or native navigation.
    const checked = [
      'unready',
      'checkpoint',
      'bridge-checkpoint',
      'navigation',
      'closed',
      'attach',
    ].includes(scenario)
      ? assert.rejects(operation, (error: unknown) => {
          if (scenario.endsWith('checkpoint'))
            assert.ok(error instanceof BitwardenStorageCheckpointError);
          else {
            assert.ok(error instanceof BitwardenBrowserFailure);
            assert.equal(error.stage, scenario === 'unready' ? 'background' : 'bridge');
          }
          assert.doesNotMatch(String(error), /private/);
          return true;
        })
      : operation;
    await new Promise<void>((resolve) => setImmediate(resolve));
    if (scenario === 'delayed') {
      assert.equal(allocated, 0);
      assert.equal(synchronized, 0);
    }
    if (scenario === 'disappeared') destroyed = true;
    ready();
    await checked;
    const usedBridge = !['delayed', 'unready', 'checkpoint'].includes(scenario);
    assert.equal(allocated, usedBridge ? 1 : 0);
    assert.equal(closed, usedBridge ? 1 : 0);
    assert.equal(removed, usedBridge ? 1 : 0);
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
    { message: 'Bitwarden browser operation failed (prepare/failed).' },
  );
});

test('browser failure classifications preserve the failing stage and discard arbitrary details', async () => {
  for (const [message, reason] of [
    ['private vault data', 'failed'],
    ['private value timed out', 'timeout'],
    ['private value page closed', 'closed'],
    ['private value unavailable', 'unavailable'],
    ['private value changed during synchronization', 'conflict'],
  ]) {
    const failure = describeBitwardenBrowserFailure(new Error(message), 'capture');
    assert.equal(failure.code, `capture/${reason}`);
    assert.doesNotMatch(JSON.stringify(failure) + String(failure), /private/);
    assert.equal(describeBitwardenBrowserFailure(failure, 'prepare'), failure);
    await assert.rejects(
      prepareBitwardenPopupStorage(
        async () => {
          throw failure;
        },
        () => false,
      ),
      (error: unknown) => error === failure,
    );
  }
  assert.equal(
    describeBitwardenBrowserFailure({ message: 'private value' }, 'popup').code,
    'popup/failed',
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
