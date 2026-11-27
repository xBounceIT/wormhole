import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import { Session } from 'node:inspector/promises';
import { coverageThreshold } from '../scripts/test-coverage.ts';
import { declarations } from './fixtures/main-source.ts';
import {
  registerSharedAuthenticationIpc,
  registerSharedAdminRecoveryIpc,
  registerSharedCatalogIpc,
  registerSharedNodeEditIpc,
  registerSharedCertificateRenewalIpc,
  registerSharedChangesIpc,
  registerSharedConnectionContextIpc,
  registerSharedRecoveryBackupIpc,
  registerSharedRecoveryInspectionIpc,
} from '../electron/vault-shared-ipc.ts';

test('shared node edit confirmation belongs to the current catalog document', async () => {
  const sender = new EventEmitter();
  const event = { sender };
  const parent = { isDestroyed: () => false };
  let view: 'current' | 'navigate' | 'missing' = 'current';
  let opens = 0;
  let handle: any;
  registerSharedNodeEditIpc({
    ipc: {
      handle(channel, handler) {
        assert.equal(channel, 'vault:shared-node-edit');
        handle = handler;
      },
    },
    parent: () => (view === 'missing' ? null : (parent as any)),
    trusted: (value) => value === event,
    host: {
      async sharedNodeEdit(_request, current, confirm) {
        if (view === 'navigate') sender.emit('did-start-navigation', {}, '', false, true);
        await confirm({} as any, current, async () => true);
        return { status: 'unavailable' };
      },
    },
    dialog: {
      open: (async (owner, current, mode) => {
        assert.equal(owner, parent);
        assert.equal(current(), true);
        assert.equal(mode, 'edit-shared-node');
        opens++;
        return null;
      }) as any,
    },
  });
  await assert.rejects(handle({ sender: new EventEmitter() }, {}));
  await assert.rejects(handle(event, {}, {}));
  for (const state of ['missing', 'navigate'] as const) {
    view = state;
    await assert.rejects(handle(event, {}));
  }
  view = 'current';
  assert.deepEqual(await handle(event, {}), { status: 'unavailable' });
  assert.equal(opens, 1);
  assert.deepEqual(sender.eventNames(), []);
});

test('archive inspection opens only from an unchanged empty workspace document', async () => {
  let handle: any,
    opens = 0;
  let mode = 'empty';
  const sender = new EventEmitter();
  const event = { sender };
  const parent = {} as any;
  registerSharedRecoveryInspectionIpc({
    ipc: {
      handle: (channel, handler) => {
        assert.equal(channel, 'vault:prepare-shared-workspace-restore');
        handle = handler;
      },
    } as any,
    trusted: (value) => value === event,
    parent: () => (mode === 'destroyed' ? null : parent),
    host: {
      startup: async () => {
        if (mode === 'navigation') sender.emit('did-start-navigation', {}, '', false, true);
        return { newWorkspace: mode !== 'selected', slots: null, cosmetics: { theme: 'system' } };
      },
    },
    dialog: {
      open: async (owner, current, join, restart, purpose) => {
        opens++;
        assert.equal(owner, parent);
        assert.ok(current());
        assert.equal(join, undefined);
        assert.equal(restart, false);
        assert.equal(purpose, 'restore');
        return undefined;
      },
    },
  });
  await assert.rejects(handle(event, { password: Uint8Array.of(1) }));
  for (mode of ['selected', 'navigation', 'destroyed']) await assert.rejects(handle(event, null));
  assert.equal(opens, 0);
  mode = 'empty';
  assert.equal(await handle(event, null), undefined);
  assert.equal(opens, 1);
  assert.equal(sender.eventNames().length, 0);
});

test('workspace backup only opens for the bound ordinary document', async () => {
  let handle: any;
  let opens = 0;
  const sender = new EventEmitter();
  const event = { sender };
  let trusted = true;
  let destroyed = false;
  const parent = { isDestroyed: () => destroyed } as any;
  const operation = {
    authenticationRequired: false,
    submit: async () => assert.fail('The ordinary renderer cannot submit an export.'),
  };
  registerSharedRecoveryBackupIpc({
    ipc: {
      handle: (channel, handler) => {
        assert.equal(channel, 'vault:open-shared-recovery-backup');
        handle = handler;
      },
    } as any,
    trusted: (owner) => trusted && owner === event,
    parent: () => parent,
    host: {
      openSharedRecoveryBackup: async (current, open) => {
        assert.ok(current());
        await open(current, operation);
        assert.equal(current(), false);
      },
    },
    dialog: {
      openBackup: async (owner, current, exportOperation) => {
        opens++;
        assert.equal(owner, parent);
        assert.equal(exportOperation, operation);
        sender.emit('did-start-navigation', {}, '', false, false);
        assert.ok(current());
        sender.emit('did-start-navigation', {}, '', false, true);
        assert.equal(current(), false);
      },
    },
  });
  await assert.rejects(handle(event, { path: '/forged.json' }));
  destroyed = true;
  await assert.rejects(handle(event, null));
  destroyed = false;
  trusted = false;
  await assert.rejects(handle(event, null));
  trusted = true;
  assert.equal(await handle(event, null), undefined);
  assert.equal(opens, 1);
  assert.equal(sender.eventNames().length, 0);
});

test('recovery admission expires when its parent document navigates', async () => {
  for (const lose of ['before', 'after', 'none']) {
    let handle: any;
    const sender = new EventEmitter();
    const navigate = () => sender.emit('did-start-navigation', {}, '', false, true);
    let activations = 0,
      stops = 0;
    registerSharedAdminRecoveryIpc({
      ipc: {
        handle: (_name, handler) => {
          handle = handler;
        },
      } as any,
      trusted: () => true,
      parent: () => ({}) as any,
      host: {
        startup: async () => {
          if (lose === 'before') navigate();
          return { newWorkspace: true, slots: null, cosmetics: { theme: 'system' } };
        },
        isSharedWorkspace: true,
        unlockedWorkspaceId: 'workspace',
        stop: async () => {
          stops++;
        },
      },
      dialog: {
        open: async () => {
          if (lose === 'after') navigate();
          return { admitted: true, orgEscrow: true, lockedMemory: true, tls: 'verified' };
        },
      },
      activate: () => {
        activations++;
      },
    });
    await assert.rejects(handle({ sender }, { path: '/forged' }));
    if (lose === 'none') assert.equal((await handle({ sender }, null)).admitted, true);
    else await assert.rejects(handle({ sender }, null));
    assert.equal(activations, lose === 'none' ? 1 : 0);
    assert.equal(stops, lose === 'after' ? 1 : 0);
    assert.equal(sender.eventNames().length, 0);
  }
});

test('signed TLS export accepts a picker capability and refuses a renderer pathname', async () => {
  const handlers = new Map<string, any>();
  const sender = new EventEmitter();
  const event = { sender };
  let chosen = 0,
    published = 0,
    trusted = true;
  registerSharedCertificateRenewalIpc({
    ipc: { handle: (channel, handle) => handlers.set(channel, handle) } as any,
    trusted: () => trusted,
    pickTLSExport: async (owner) => {
      assert.equal(owner, event);
      chosen++;
      return null;
    },
    host: {
      exportSharedTLSBundle: async (choose, accepted) => {
        assert.ok(accepted());
        const value = await choose();
        assert.ok(accepted());
        if (value !== null) published++;
        return null;
      },
    } as any,
  });
  const request = handlers.get('vault:shared-tls-export');
  await assert.rejects(request(event, { path: 'renderer.whtls' }));
  await assert.rejects(request(event));
  assert.equal(chosen, 0);
  assert.equal(await request(event, null), null);
  trusted = false;
  await assert.rejects(request(event, null));
  assert.equal(chosen, 1);
  assert.equal(published, 0);
  assert.equal(sender.eventNames().length, 0);
});

test('recovery kit refresh uses only the current document’s native pickers', async () => {
  const handlers = new Map<string, any>();
  const sender = new EventEmitter();
  const event = { sender };
  const intents: string[] = [];
  let navigate = false;
  registerSharedCertificateRenewalIpc({
    ipc: { handle: (channel, handle) => handlers.set(channel, handle) } as any,
    trusted: (owner) => owner === event,
    pickRecoveryKit: async (owner, intent) => {
      assert.equal(owner, event);
      intents.push(intent);
      if (navigate) sender.emit('did-start-navigation', {}, '', false, true);
      return `C:\\test\\${intent}.whrecovery`;
    },
    host: {
      refreshSharedRecoveryKit: async (choose, accepted) => {
        assert.ok(accepted());
        assert.equal(await choose('open'), 'C:\\test\\open.whrecovery');
        if (!accepted()) throw Error('owner lost');
        assert.equal(await choose('save'), 'C:\\test\\save.whrecovery');
        return 'updated';
      },
    } as any,
  });
  const request = handlers.get('vault:shared-recovery-kit-refresh');
  await assert.rejects(request(event, { source: 'forged.whrecovery' }));
  await assert.rejects(request(event, null, 'forged.whrecovery'));
  await assert.rejects(request({ sender }, null));
  assert.deepEqual(intents, []);
  assert.equal(await request(event, null), 'updated');
  navigate = true;
  await assert.rejects(request(event, null));
  assert.deepEqual(intents, ['open', 'save', 'open']);
  assert.equal(sender.eventNames().length, 0);
});

test('shared catalog IPC binds each request to the current main document and removes listeners', async () => {
  let changesHandler: any;
  const sender = new EventEmitter();
  registerSharedChangesIpc({
    ipc: {
      handle: (name, fn) => {
        assert.equal(name, 'vault:shared-changes');
        changesHandler = fn;
      },
    } as any,
    trusted: () => true,
    host: {
      sharedChanges: async (value, accepted) => {
        assert.deepEqual(value, { epoch: '0', changeSeq: '0' });
        assert.ok(accepted());
        return { epoch: '1', changeSeq: '0', reset: true, nodes: [] };
      },
    },
  });
  assert.equal((await changesHandler({ sender }, { epoch: '0', changeSeq: '0' })).reset, true);
  assert.equal(sender.eventNames().length, 0);
  for (const mode of [
    'success',
    'navigation',
    'subframe',
    'crash',
    'destroyed',
    'untrusted',
    'throws',
  ]) {
    const sender = new EventEmitter();
    let handler: any,
      calls = 0;
    registerSharedCatalogIpc({
      ipc: {
        handle: (name: string, fn: unknown) => {
          assert.equal(name, 'vault:shared-catalog');
          handler = fn;
        },
      } as any,
      trusted: () => {
        if (mode === 'throws') throw Error();
        return mode !== 'untrusted';
      },
      host: {
        sharedCatalog: async (_value, accepted) => {
          calls++;
          assert.equal(accepted(), true);
          if (mode === 'navigation' || mode === 'subframe')
            sender.emit('did-start-navigation', {}, '', false, mode !== 'subframe');
          if (mode === 'crash') sender.emit('render-process-gone');
          if (mode === 'destroyed') sender.emit('destroyed');
          if (!accepted()) throw Error('owner lost');
          return { epoch: '1', changeSeq: '0', nodes: [], next: null };
        },
      },
    });
    await assert.rejects(handler({ sender }));
    await assert.rejects(handler({ sender }, {}, {}));
    const pending = handler({ sender }, {});
    if (['success', 'subframe'].includes(mode)) assert.equal((await pending).epoch, '1');
    else await assert.rejects(pending);
    assert.equal(calls, ['untrusted', 'throws'].includes(mode) ? 0 : 1);
    assert.equal(sender.eventNames().length, 0);
  }
});

test('shared application IPC captures owner before startup and returns metadata only', async (t) => {
  const profiler = new Session();
  profiler.connect();
  t.after(() => profiler.disconnect());
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  for (const mode of [
    'admit',
    'join',
    'join-completed',
    'initial',
    'initial-pending',
    'initial-completed',
    'recover',
    'cancel',
    'untrusted',
    'throw-trust',
    'no-parent',
    'local',
    'navigate-startup',
    'crash-startup',
    'navigate-result',
    'recovered-stale',
    'subframe',
    'locked',
    'local-owner',
    'activate-error',
    'activate-navigation',
    'activate-lock',
  ]) {
    const sender = new EventEmitter();
    let handler: any,
      opened = 0,
      stopped = 0,
      activated = 0,
      workspace: string | undefined = 'remote-workspace';
    const navigation = () =>
      sender.emit('did-start-navigation', {}, 'same-document', false, mode !== 'subframe');
    registerSharedAuthenticationIpc({
      ipc: {
        handle: (_name, fn) => {
          handler = fn;
        },
      } as any,
      trusted: () => {
        if (mode === 'throw-trust') throw Error('destroyed');
        return mode !== 'untrusted';
      },
      parent: () => (mode === 'no-parent' ? null : ({} as any)),
      activate: () => {
        activated++;
        if (mode === 'activate-error') throw Error('activation failed');
        if (mode === 'activate-navigation') navigation();
        if (mode === 'activate-lock') workspace = undefined;
      },
      host: {
        isSharedWorkspace: mode !== 'local-owner',
        get unlockedWorkspaceId() {
          return mode === 'locked' ? undefined : workspace;
        },
        startup: async () => {
          if (mode === 'navigate-startup' || mode === 'subframe') navigation();
          if (mode === 'crash-startup') sender.emit('render-process-gone');
          if (mode === 'initial')
            return { slots: null, cosmetics: { theme: 'system' }, newWorkspace: true } as any;
          return {
            ...(mode === 'join' || mode === 'initial-pending'
              ? { sharedJoin: { lastLoginName: 'alice', serverDisplayName: 'Team' } }
              : {}),
            shared:
              mode === 'local' || mode === 'join' || mode === 'initial-pending'
                ? undefined
                : { lastLoginName: 'alice', serverDisplayName: 'Team' },
          } as any;
        },
        stop: async () => {
          stopped++;
        },
      },
      dialog: {
        open: async (_parent, accepted, operation) => {
          opened++;
          assert.equal(accepted(), true);
          assert.equal(
            operation,
            mode === 'initial'
              ? 'join-initial'
              : mode === 'join' || mode === 'initial-pending'
                ? 'recover-enrollment'
                : mode === 'recover'
                  ? 'recover-password'
                  : 'admit',
          );
          if (mode === 'navigate-result' || mode === 'recovered-stale') navigation();
          return mode === 'cancel'
            ? null
            : mode === 'recover' || mode === 'recovered-stale'
              ? { recovered: true }
              : { admitted: true, lockedMemory: true, orgEscrow: true, tls: 'off' };
        },
      },
    });
    const event = { sender };
    await assert.rejects(handler(event));
    await assert.rejects(handler(event, 'bad'));
    await assert.rejects(handler(event, 'admit', { password: new Uint8Array(1) }));
    const pending = handler(
      event,
      mode.startsWith('initial')
        ? 'join-initial'
        : mode === 'join' || mode === 'join-completed'
          ? 'recover-enrollment'
          : mode === 'recover'
            ? 'recover-password'
            : 'admit',
    );
    if (
      [
        'untrusted',
        'throw-trust',
        'no-parent',
        'local',
        'navigate-startup',
        'crash-startup',
        'navigate-result',
        'recovered-stale',
        'locked',
        'local-owner',
        'activate-error',
        'activate-navigation',
        'activate-lock',
      ].includes(mode)
    )
      await assert.rejects(pending);
    else
      assert.deepEqual(
        await pending,
        mode === 'cancel'
          ? null
          : mode === 'recover'
            ? { recovered: true }
            : { admitted: true, lockedMemory: true, orgEscrow: true, tls: 'off' },
      );
    assert.equal(
      stopped,
      [
        'navigate-result',
        'locked',
        'local-owner',
        'activate-error',
        'activate-navigation',
        'activate-lock',
      ].includes(mode)
        ? 1
        : 0,
    );
    assert.equal(
      activated,
      [
        'admit',
        'join',
        'join-completed',
        'initial',
        'initial-pending',
        'initial-completed',
        'subframe',
        'activate-error',
        'activate-navigation',
        'activate-lock',
      ].includes(mode)
        ? 1
        : 0,
    );
    assert.equal(
      opened,
      [
        'admit',
        'join',
        'join-completed',
        'initial',
        'initial-pending',
        'initial-completed',
        'recover',
        'cancel',
        'navigate-result',
        'recovered-stale',
        'subframe',
        'locked',
        'local-owner',
        'activate-error',
        'activate-navigation',
        'activate-lock',
      ].includes(mode)
        ? 1
        : 0,
    );
    assert.equal(sender.eventNames().length, 0);
  }
  const report = await profiler.post('Profiler.takePreciseCoverage');
  const ranges = report.result
    .filter((script) => script.url.endsWith('/electron/vault-shared-ipc.ts'))
    .flatMap((script) => {
      const boundary = script.functions.find(
        (fn) => fn.functionName === 'registerSharedAuthenticationIpc',
      )!.ranges[0].startOffset;
      return script.functions
        .flatMap((fn) => fn.ranges)
        .filter((range) => range.startOffset >= boundary);
    });
  assert.ok(ranges.length > 0);
  const percent = (100 * ranges.filter((range) => range.count > 0).length) / ranges.length;
  t.diagnostic(`shared authentication IPC: ${percent.toFixed(2)}% V8 blocks`);
  assert.ok(percent >= coverageThreshold);
});

test('shared preload restricts capabilities and wipes its IPC factors on success and failure', async (t) => {
  const profiler = new Session();
  profiler.connect();
  t.after(() => profiler.disconnect());
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  const source = stripTypeScriptTypes(
    readFileSync(new URL('../electron/vault-shared-preload.cts', import.meta.url), 'utf8'),
  ).replace(/^import .*?;\s*/m, '');
  for (const fail of [false, true]) {
    let api: any;
    const calls: unknown[][] = [];
    runInNewContext(
      source,
      {
        contextBridge: {
          exposeInMainWorld: (name: string, value: unknown) => {
            assert.equal(name, 'vaultSharedAuthentication');
            api = value;
          },
        },
        ipcRenderer: {
          invoke: async (...args: unknown[]) => {
            calls.push(args);
            if (args[0] === 'vault-shared:submit') {
              const v = args[1] as any;
              assert.equal(v.password[0], 7);
              assert.equal(v.ask?.[0], 9);
              if (fail) throw Error('unavailable');
            }
            return true;
          },
        },
      },
      { filename: 'wormhole-shared-preload.js' },
    );
    assert.deepEqual(Object.keys(api).sort(), [
      'cancel',
      'context',
      'inspectInvitation',
      'openInvitation',
      'openResetOffer',
      'selectTLSUpdate',
      'submit',
    ]);
    await api.context();
    await api.cancel();
    await api.inspectInvitation('WHINV2-public');
    await api.openInvitation();
    await api.openResetOffer();
    assert.deepEqual(calls.at(-1), ['vault-shared:open-reset-offer']);
    await api.selectTLSUpdate('choose');
    assert.deepEqual(calls.at(-1), ['vault-shared:tls-update', 'choose']);
    const input = {
      password: new Uint8Array([7]),
      ask: new Uint8Array(32).fill(9),
      code: new Uint8Array(16).fill(8),
    };
    if (fail) await assert.rejects(api.submit(input));
    else assert.equal(await api.submit(input), true);
    assert.equal(input.password[0], 0);
    assert.ok(input.ask.every((n) => n === 0));
    assert.ok(input.code.every((n) => n === 0));
    assert.deepEqual(
      calls.map((c) => c[0]),
      [
        'vault-shared:context',
        'vault-shared:cancel',
        'vault-shared:invitation',
        'vault-shared:open-invitation',
        'vault-shared:open-reset-offer',
        'vault-shared:tls-update',
        'vault-shared:submit',
      ],
    );
  }
  const report = await profiler.post('Profiler.takePreciseCoverage');
  const scripts = report.result.filter((script) => script.url === 'wormhole-shared-preload.js');
  assert.ok(scripts.length > 0);
  const ranges = scripts.flatMap((script) => script.functions.flatMap((fn) => fn.ranges));
  const coverage = (100 * ranges.filter((range) => range.count > 0).length) / ranges.length;
  t.diagnostic(`shared preload: ${coverage.toFixed(2)}% V8 blocks`);
  assert.ok(coverage >= coverageThreshold);
});

test('production wiring selects shared startup before local unlock and packages the protected dialog', () => {
  const read = (p: string) => readFileSync(new URL('../' + p, import.meta.url), 'utf8');
  const main = read('electron/main.ts'),
    startup = read('src/main.tsx');
  assert.ok(startup.indexOf('if (vault.shared)') < startup.indexOf('if (vault.slots)'));
  assert.match(main, /registerSharedAuthenticationIpc\(\{[\s\S]*?dialog: vaultSharedDialog/);
  const registration = main.slice(
    main.indexOf('registerSharedAuthenticationIpc({'),
    main.indexOf('registerSharedCatalogIpc({'),
  );
  assert.match(
    registration,
    /activate: \(\) => \{\s*rememberAuthState\(vaultAuthState\(\), false\);\s*authSession\.markUnlocked\(\);/,
  );
  assert.doesNotMatch(read('electron/preload.cts'), /sharedRuntime|shared-runtime/);
  assert.equal(main.match(/vaultSharedDialog.cancel\(\)/g)?.length, 2);
  assert.match(
    read('electron/preload.cts'),
    /authenticateSharedVault:[\s\S]*?invoke\('vault:shared-authenticate', mode\)/,
  );
  assert.match(read('vite.config.ts'), /vaultShared:.*vault-shared.html/);
  assert.match(read('vault-shared.html'), /connect-src 'none'/);
  assert.match(read('src/vault-shared.ts'), /mountSharedAuthenticationScreen\(card, api\)/);
});

test('main broadcasts payload-free hints only to owned live windows and tolerates closure', async (t) => {
  const profiler = new Session();
  profiler.connect();
  t.after(() => profiler.disconnect());
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const begin = source.indexOf('onSharedCatalogChanged: () => {'),
    end = source.indexOf('onUnavailable:', begin);
  assert.ok(begin > 0 && end > begin);
  const calls: unknown[][] = [];
  const window = (destroyed = false, contentsDestroyed = false, throws = false) => ({
    isDestroyed: () => destroyed,
    webContents: {
      isDestroyed: () => contentsDestroyed,
      send: (...args: unknown[]) => {
        if (throws) throw Error('closed');
        calls.push(args);
      },
    },
  });
  const windows = [
    window(true),
    window(false, true),
    window(false, false, true),
    window(),
    window(),
  ];
  const owned = new Set(windows.slice(0, 4));
  const checked: string[] = [];
  runInNewContext(
    stripTypeScriptTypes(declarations(source, ['broadcastVaultChange'])) +
      '\n({' +
      source.slice(begin, end) +
      '}).onSharedCatalogChanged(); broadcastVaultChange("vault:profile-changed");',
    {
      BrowserWindow: { getAllWindows: () => windows },
      windowCloseCoordinators: owned,
      vaultWebConnections: { verifyViews: async () => checked.push('web') },
      sealedSerial: { verifySharedUse: async () => checked.push('serial') },
    },
    { filename: 'wormhole-catalog-broadcast.js' },
  );
  assert.deepEqual(calls, [['vault:shared-catalog-changed'], ['vault:profile-changed']]);
  assert.deepEqual(checked, ['web', 'serial']);
  const preload = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
  const a = preload.indexOf('  onSharedCatalogChanged:'),
    b = preload.indexOf('  readVaultBitwardenInstallation:', a);
  assert.ok(a > 0 && b > a);
  let listener: (...args: unknown[]) => void = () => {};
  let removed = false,
    called = 0;
  const api = runInNewContext(
    stripTypeScriptTypes('({' + preload.slice(a, b) + '})'),
    {
      ipcRenderer: {
        on: (name: string, fn: typeof listener) => {
          assert.equal(name, 'vault:shared-catalog-changed');
          listener = fn;
        },
        removeListener: (name: string, fn: typeof listener) => {
          assert.equal(name, 'vault:shared-catalog-changed');
          assert.equal(fn, listener);
          removed = true;
        },
      },
    },
    { filename: 'wormhole-catalog-preload.js' },
  );
  const remove = api.onSharedCatalogChanged((...args: unknown[]) => {
    assert.equal(args.length, 0);
    called++;
  });
  listener({ discard: 'private' });
  remove();
  assert.equal(called, 1);
  assert.equal(removed, true);
  const report = await profiler.post('Profiler.takePreciseCoverage');
  for (const name of ['wormhole-catalog-broadcast.js', 'wormhole-catalog-preload.js']) {
    const ranges = report.result
      .filter((s) => s.url === name)
      .flatMap((s) => s.functions.flatMap((f) => f.ranges));
    assert.ok(ranges.length > 0);
    const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
    t.diagnostic(name + ': ' + percent.toFixed(2) + '% V8 blocks');
    assert.ok(percent >= coverageThreshold);
  }
});

test('shared connection context IPC retains trusted-document guards and exact arity', async () => {
  const sender = new EventEmitter();
  let handler: any,
    calls = 0,
    trusted = true;
  registerSharedConnectionContextIpc({
    ipc: {
      handle: (name, fn) => {
        assert.equal(name, 'vault:shared-connection-context');
        handler = fn;
      },
    } as any,
    trusted: () => trusted,
    host: {
      sharedConnectionContext: async (value, accepted) => {
        calls++;
        assert.ok(accepted());
        return { nodeId: (value as any).nodeId, protocol: 0 };
      },
    },
  });
  const request = { nodeId: '11111111-1111-4111-8111-111111111111' };
  assert.deepEqual(await handler({ sender }, request), { ...request, protocol: 0 });
  assert.equal(sender.eventNames().length, 0);
  await assert.rejects(handler({ sender }));
  await assert.rejects(handler({ sender }, request, request));
  trusted = false;
  await assert.rejects(handler({ sender }, request));
  assert.equal(calls, 1);
});
