import assert from 'node:assert/strict';
import test from 'node:test';
import { registerVaultProtectionIpc } from '../electron/vault-protection-ipc.ts';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { stripTypeScriptTypes } from 'node:module';
import { declarations, mainSyntax, visitSyntax } from './fixtures/main-source.ts';
import { Session } from 'node:inspector/promises';
import { coverageThreshold } from '../scripts/test-coverage.ts';
const profiler = new Session();
const externalCoverage =
  process.execArgv.includes('--experimental-test-coverage') || !!process.env.NODE_V8_COVERAGE;
if (!externalCoverage) {
  profiler.connect();
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
}
function fixture(mode = '', allowDatabaseEncryption = false) {
  const handlers = new Map<string, any>();
  let trusted = true,
    allowed = true,
    canStart = true;
  const calls: string[] = [];
  let finish!: (v: boolean) => void;
  const startup: any =
    mode === 'slots' || mode.startsWith('rotation')
      ? {
          slots: { vaultId: 'local-vault', encrypted: mode === 'rotation-encrypted' },
          ...(mode === 'rotation-pending' ? { rotation: { pending: true } } : {}),
        }
      : mode === 'shared'
        ? { shared: {} }
        : mode === 'empty'
          ? { newWorkspace: true }
          : {};
  const event: any = {};
  const parent: any = {};
  const host: any = {
    unlockedWorkspaceId:
      mode.startsWith('rotation') && mode !== 'rotation-locked' ? 'local-vault' : undefined,
    startup: async () => {
      calls.push('startup');
      if (mode === 'startup-error') throw Error('private');
      if (mode === 'late-lock') allowed = false;
      if (mode === 'late-shutdown') canStart = false;
      if (mode === 'late-navigation') trusted = false;
      return startup;
    },
    stop: async () => {
      calls.push('stop');
      if (mode === 'stop-error') throw Error('private');
    },
    protection: async () => ({ protected: mode === 'upgrade-protected' }),
  };
  if (mode.startsWith('upgrade')) {
    startup.unprotected = { vaultId: 'local-vault' };
    host.unlockedWorkspaceId = mode === 'upgrade-locked' ? undefined : 'local-vault';
  }
  registerVaultProtectionIpc({
    ipc: {
      handle: (channel, fn) => {
        handlers.set(channel, fn);
      },
    },
    host,
    allowDatabaseEncryption,
    restartUpgrade: () => calls.push('restart-upgrade'),
    dialog: {
      open: async (p, accepted) => {
        assert.equal(p, parent);
        assert.equal(accepted(), true);
        calls.push('dialog');
        if (mode === 'dialog-error') throw Error('private');
        return mode !== 'cancel';
      },
    },
    rootDialog: {
      open: async (p, accepted, encryptDatabase) => {
        assert.equal(p, parent);
        assert.ok(accepted());
        calls.push(encryptDatabase ? 'encrypt-dialog' : 'root-dialog');
        if (mode === 'rotation-late-navigation') trusted = false;
        return mode !== 'rotation-cancel';
      },
    },
    trusted: () => {
      if (mode === 'trust-error') throw Error('private');
      return trusted;
    },
    parent: () => (mode === 'no-parent' ? undefined : parent),
    requireAccess: () => {
      calls.push('access');
      if (!allowed || mode === 'locked') throw Error('private');
    },
    canStart: () => canStart && mode !== 'shutdown',
    hold: () => {
      calls.push('hold');
      return () => calls.push('release');
    },
    quiesce: async (p, retainOwner) => {
      assert.equal(p, parent);
      assert.equal(retainOwner, mode.startsWith('rotation'));
      calls.push('quiesce');
      if (mode === 'quiesce-error') throw Error('private');
      if (mode === 'late-quiesce') trusted = false;
      if (mode === 'deferred') return new Promise((r) => (finish = r));
      return mode !== 'preflight-cancel';
    },
    restart: () => {
      calls.push('restart');
      if (mode === 'restart-error') throw Error('private');
    },
    fatal: () => {
      calls.push('fatal');
    },
  });
  return {
    call: (...args: any[]) => handlers.get('vault:protect-existing')(event, ...args),
    encrypt: (...args: any[]) => handlers.get('vault:encrypt-database')(event, ...args),
    encryptionAvailable: (...args: any[]) =>
      handlers.get('vault:database-encryption-available')(event, ...args),
    calls,
    resolve: () => finish(true),
  };
}

test('database encryption is a gated Settings action with a pinned local owner and dialog mode', async () => {
  const eligible = fixture('rotation', true);
  assert.equal(await eligible.encryptionAvailable(), true);
  assert.equal(await eligible.encryptionAvailable({ path: 'private.db' }), false);
  await assert.rejects(eligible.encrypt({ encryptDatabase: false }));
  assert.ok(!eligible.calls.includes('hold'));
  eligible.calls.length = 0;
  assert.equal(await eligible.encrypt(), true);
  assert.deepEqual(eligible.calls, [
    'access',
    'startup',
    'access',
    'hold',
    'quiesce',
    'encrypt-dialog',
    'stop',
    'restart',
  ]);
  for (const denied of [
    fixture('rotation'),
    fixture('rotation-locked', true),
    fixture('rotation-encrypted', true),
    fixture('rotation-pending', true),
    fixture('shared', true),
    fixture('startup-error', true),
    fixture('late-lock', true),
  ]) {
    assert.equal(await denied.encryptionAvailable(), false);
    await assert.rejects(denied.encrypt());
    assert.ok(!denied.calls.includes('hold'));
  }
});
test('protection opt-in stops services before the protected dialog and restarts after confirm or cancel', async () => {
  for (const mode of ['', 'cancel']) {
    const f = fixture(mode);
    assert.equal(await f.call(), mode !== 'cancel');
    assert.deepEqual(f.calls, [
      'access',
      'startup',
      'access',
      'hold',
      'quiesce',
      'dialog',
      'stop',
      'restart',
    ]);
  }
  const f = fixture('preflight-cancel');
  assert.equal(await f.call(), false);
  assert.equal(f.calls.at(-1), 'release');
  assert.ok(!f.calls.includes('stop') && !f.calls.includes('restart'));
});

test('existing Settings protection action selects isolated upgrade only for an authenticated Unprotected owner', async () => {
  const f = fixture('upgrade');
  assert.equal(await f.call(), true);
  assert.equal(f.calls.includes('dialog'), false);
  assert.equal(f.calls.includes('root-dialog'), false);
  assert.ok(f.calls.indexOf('stop') < f.calls.indexOf('restart-upgrade'));
  assert.equal(f.calls.includes('release'), false);
  for (const mode of ['upgrade-protected', 'upgrade-locked']) {
    const f = fixture(mode);
    await assert.rejects(f.call());
    assert.equal(f.calls.includes('quiesce'), false);
    assert.equal(f.calls.includes('restart-upgrade'), false);
  }
});

test('root protection preserves the native owner for enrollment and stops it before restart', async () => {
  for (const mode of ['rotation', 'rotation-cancel']) {
    const f = fixture(mode);
    assert.equal(await f.call(), mode === 'rotation');
    assert.deepEqual(f.calls, [
      'access',
      'startup',
      'access',
      'hold',
      'quiesce',
      'root-dialog',
      'stop',
      'restart',
    ]);
  }
  for (const mode of ['rotation-locked', 'rotation-pending']) {
    const f = fixture(mode);
    await assert.rejects(f.call());
    assert.ok(!f.calls.includes('hold'));
  }
  const lost = fixture('rotation-late-navigation');
  await assert.rejects(lost.call());
  assert.ok(lost.calls.includes('stop') && lost.calls.includes('fatal'));
  assert.ok(!lost.calls.includes('restart') && !lost.calls.includes('release'));
});
test('protection refuses caller authority, stale authorization and ineligible workspaces', async () => {
  for (const mode of [
    'slots',
    'shared',
    'empty',
    'no-parent',
    'locked',
    'shutdown',
    'startup-error',
    'late-lock',
    'late-shutdown',
    'late-navigation',
    'trust-error',
  ]) {
    const f = fixture(mode);
    await assert.rejects(f.call(), /^Error: Workspace protection unavailable\.$/);
    assert.ok(
      !f.calls.includes('hold') && !f.calls.includes('dialog') && !f.calls.includes('restart'),
    );
  }
  const f = fixture();
  await assert.rejects(f.call({ path: 'untrusted', proof: 'untrusted' }));
  assert.deepEqual(f.calls, []);
});
test('uncertain shutdown or dialog failure retains authorization barrier and exits without relaunch', async () => {
  for (const mode of [
    'quiesce-error',
    'late-quiesce',
    'dialog-error',
    'stop-error',
    'restart-error',
  ]) {
    const f = fixture(mode);
    await assert.rejects(f.call(), /Workspace protection unavailable/);
    assert.ok(f.calls.includes('fatal'));
    assert.ok(!f.calls.includes('release'));
    if (mode !== 'restart-error') assert.ok(!f.calls.includes('restart'));
  }
  const f = fixture('deferred');
  const first = f.call();
  await new Promise(setImmediate);
  await assert.rejects(f.call());
  f.resolve();
  assert.equal(await first, true);
  assert.equal(f.calls.filter((x) => x === 'quiesce').length, 1);
});
test('main wires preflight, browser flush, teardown and strict native cleanup before migration setup', async () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  let registration: any, optionsDeclaration: any;
  visitSyntax(mainSyntax(source), (n) => {
    if (n.type === 'CallExpression' && n.callee.name === 'registerVaultProtectionIpc')
      registration = n;
    if (
      n.type === 'VariableDeclaration' &&
      n.declarations.some((d: any) => d.id.name === 'vaultProtectionOptions')
    )
      optionsDeclaration = n;
  });
  assert.ok(registration);
  assert.ok(optionsDeclaration);
  const registrationSource =
    source.slice(optionsDeclaration.start, optionsDeclaration.end) +
    '\n' +
    source.slice(registration.start, registration.end);
  const calls: string[] = [];
  let options: any,
    edits = true,
    confirm = true;
  const window: any = {};
  const context: any = {
    registerVaultProtectionIpc: (v: any) => (options = v),
    ipcMain: {},
    vaultBackend: {},
    vaultMigrationSetupDialog: {},
    vaultOSMigrationDialog: {},
    vaultRootSetupDialog: {},
    vaultUpgradeSetupDialog: {},
    isTrustedVaultSender: () => true,
    isQuitting: false,
    authLockRequested: false,
    quitCleanupStarted: false,
    nativeResourceShutdownPromise: undefined,
    authSession: { requireUnlocked() {}, holdLock() {} },
    BrowserWindow: { fromWebContents: () => window, getAllWindows: () => [window] },
    windowCloseCoordinators: new Map([[window, { connectedSessionCount: 1 }]]),
    sshBackend: {
      prepareEditClose: async () => {
        calls.push('prepare');
        return edits;
      },
      finishEditClose: async () => {
        calls.push('finish');
      },
    },
    requestRendererCloseConfirmation: async () => {
      calls.push('confirm');
      return confirm;
    },
    webSurfaces: {
      flushAndCloseAll: async () => {
        calls.push('browser');
      },
    },
    withBitwardenBrowserTimeout: (v: any) => v,
    requestRendererTeardown: async () => {
      calls.push('renderer');
    },
    shutdownNativeResources: async () => {
      calls.push('native');
    },
    shutdownNativeResourcesRetainingVault: async () => {
      calls.push('native-retained');
    },
    app: { relaunch: () => calls.push('relaunch'), exit: (v: number) => calls.push('exit' + v) },
    process: { argv: ['exe', 'app'] },
    dialog: { showErrorBox: () => calls.push('error') },
  };
  runInNewContext(stripTypeScriptTypes(registrationSource), context, {
    filename: 'vault-protection-main.js',
  });
  assert.ok(options.trusted({ sender: {} }));
  assert.equal(options.osDialog, context.vaultOSMigrationDialog);
  assert.equal(options.parent({ sender: {} }), window);
  options.requireAccess();
  options.hold();
  assert.ok(options.canStart());
  context.isQuitting = true;
  assert.equal(options.canStart(), false);
  assert.equal(options.trusted({ sender: {} }), false);
  context.isQuitting = false;
  context.quitCleanupStarted = true;
  assert.equal(options.canStart(), false);
  context.quitCleanupStarted = false;
  assert.ok(await options.quiesce(window));
  assert.deepEqual(calls, ['prepare', 'confirm', 'finish', 'browser', 'renderer', 'native']);
  calls.length = 0;
  assert.ok(await options.quiesce(window, true));
  assert.deepEqual(calls, [
    'prepare',
    'confirm',
    'finish',
    'browser',
    'renderer',
    'native-retained',
  ]);
  calls.length = 0;
  edits = false;
  assert.equal(await options.quiesce(window), false);
  assert.deepEqual(calls, ['prepare']);
  calls.length = 0;
  edits = true;
  confirm = false;
  assert.equal(await options.quiesce(window), false);
  assert.deepEqual(calls, ['prepare', 'confirm']);
  options.restart();
  assert.deepEqual(calls.slice(-2), ['relaunch', 'exit0']);
  let upgradeArgs: any;
  context.app.relaunch = (value: any) => {
    upgradeArgs = value.args;
  };
  context.process.argv = ['exe', 'app', '--prepare-vault-protection', '--safe'];
  options.restartUpgrade();
  assert.deepEqual(Array.from(upgradeArgs), ['app', '--safe', '--prepare-vault-protection']);
  options.fatal();
  assert.deepEqual(calls.slice(-2), ['error', 'exit1']);
  const shutdown = declarations(source, [
    'nativeResourceShutdownPromise',
    'nativeResourceShutdownRetainsVault',
    'shutdownNativeResources',
    'shutdownNativeResourcesRetainingVault',
    'shutdownNativeResourceOwner',
  ]);
  for (const failure of [
    '',
    'ssh',
    'sealed-ssh',
    'serial',
    'vault',
    'shared-setup',
    'bitwarden-cli',
  ]) {
    let vaultStops = 0;
    const fail = (name: string) => async () => {
      if (name === failure) throw Error('private');
    };
    const native: any = {
      vaultLockMonitor: { deactivate() {} },
      vncSessionAttempts: { cancelAll() {} },
      cancelPreparingRdpStarts() {},
      serialBackend: undefined,
      sealedSerial: { closeAll: fail('serial') },
      stopVaultVncSessions: fail('vnc'),
      stopVaultBitwardenCLIUnlock: fail('bitwarden-cli'),
      stopVaultRdpSessions: fail('rdp'),
      vaultWebIpc: { closeAll: fail('web') },
      vaultSshIpc: { closeAll: fail('sealed-ssh') },
      sshBackend: { dispose: fail('ssh'), backendStopped() {} },
      rdpClient: undefined,
      vaultBackend: {
        stop: async () => {
          vaultStops++;
          await fail('vault')();
        },
      },
      vaultCreateDialog: { cancel: fail('create') },
      vaultMigrationSetupDialog: { cancel: fail('migration') },
      vaultOSMigrationDialog: { cancel: fail('os-migration') },
      vaultRootSetupDialog: { cancel: fail('root') },
      vaultUpgradeSetupDialog: { cancel: fail('upgrade') },
      vaultReauthenticationDialog: { cancel: fail('reauth') },
      vaultSharedDialog: { cancel: fail('shared') },
      vaultSharedSetupDialog: { cancel: fail('shared-setup') },
      vaultNotesDialog: { cancel() {} },
      vaultCredentialsDialog: { cancel() {} },
      vaultLinuxClipboard: undefined,
      vaultTunnelDialog: { cancel: fail('tunnel') },
      releaseAllRdpTunnels: fail('lease'),
      nativeBackend: { stop: fail('backend') },
      webSurfaces: { backendStopped() {} },
      rdpTunnelLeases: new Map(),
      rdpTunnelLeaseSessions: new Map(),
      console: { warn() {} },
    };
    const [fn, retained] = runInNewContext(
      stripTypeScriptTypes(shutdown) +
        ';[shutdownNativeResources,shutdownNativeResourcesRetainingVault]',
      native,
      { filename: 'vault-root-retirement-main.js' },
    );
    if (failure) await assert.rejects(fn(), /shutdown/);
    else await fn();
    assert.equal(vaultStops, 1);
    if (failure && failure !== 'vault') await assert.rejects(retained(), /shutdown/);
    else await retained();
    assert.equal(vaultStops, 1, 'retained quiescence stopped the source root');
    const pending = retained();
    assert.equal(retained(), pending);
    const escalated = fn();
    assert.equal(fn(), escalated);
    assert.equal(retained(), escalated);
    if (failure && failure !== 'vault') await assert.rejects(pending, /shutdown/);
    else await pending;
    if (failure) await assert.rejects(escalated);
    else await escalated;
    assert.equal(vaultStops, 2, 'full shutdown did not retire a retained root');
  }
  const preload = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
  assert.match(
    preload,
    /protectExistingWorkspace: \(\) => ipcRenderer.invoke\('vault:protect-existing'\)/,
  );
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  assert.match(app, /Protect workspace and restart/);
  assert.match(app, /Stored secrets currently rely on your operating system account/);
  assert.match(app, /<Badge variant="secondary">Off<\/Badge>/);
});

for (const [caption, operation, failure] of [
  [
    'Protect workspace and restart',
    'protectExistingWorkspace',
    'Workspace protection could not be prepared.',
  ],
  [
    'Change vault password and recovery key',
    'protectExistingWorkspace',
    'Vault protection could not be prepared.',
  ],
  [
    'Encrypt the vault database',
    'encryptVaultDatabase',
    'Database encryption could not be prepared.',
  ],
])
  test(
    'settings action confines busy/error state and calls only the no-argument bridge: ' + caption,
    async () => {
      const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
      let button: any;
      visitSyntax(mainSyntax(source, true), (n) => {
        if (
          n.type === 'JSXElement' &&
          n.children.some((c: any) => c.type === 'JSXText' && c.value.trim() === caption)
        )
          button = n;
      });
      assert.ok(button);
      const attributes = button.openingElement.attributes;
      assert.equal(
        attributes.find((a: any) => a.name?.name === 'disabled').value.expression.name,
        'securityBusy',
      );
      const callback = attributes.find((a: any) => a.name?.name === 'onClick').value.expression;
      for (const reject of [false, true]) {
        const busy: boolean[] = [],
          errors: string[] = [];
        let calls = 0;
        const fn = runInNewContext(
          stripTypeScriptTypes('(' + source.slice(callback.start, callback.end) + ')'),
          {
            setSecurityBusy: (v: boolean) => busy.push(v),
            setSecurityError: (v: string) => errors.push(v),
            window: {
              wormhole: {
                [operation]: async (...args: any[]) => {
                  assert.deepEqual(args, []);
                  calls++;
                  if (reject) throw Error('private');
                  return false;
                },
              },
            },
          },
        );
        fn();
        await new Promise(setImmediate);
        assert.equal(calls, 1);
        assert.deepEqual(busy, [true, false]);
        assert.deepEqual(errors, reject ? ['', failure] : ['']);
      }
      if (caption.startsWith('Change')) {
        let section: any;
        visitSyntax(mainSyntax(source, true), (n) => {
          if (
            n.type === 'JSXElement' &&
            n.openingElement.name.name === 'SettingsSection' &&
            n.start < button.start &&
            n.end > button.end
          )
            section = n;
        });
        assert.ok(section);
        const markup = source.slice(section.start, section.end);
        assert.match(markup, /securityError \? \(/);
        assert.match(markup, /role="alert"/);
      }
    },
  );

test('root setup preload confines current factors to its dedicated channels and erases failures', async () => {
  const source = stripTypeScriptTypes(
    readFileSync(new URL('../electron/vault-root-setup-preload.cts', import.meta.url), 'utf8'),
  ).replace(/^import .*?;\s*/gms, '');
  for (const failure of [false, true]) {
    let api: any;
    const calls: any[] = [];
    runInNewContext(
      source,
      {
        Uint8Array,
        process: { platform: 'win32' },
        contextBridge: {
          exposeInMainWorld: (name: string, value: any) => {
            assert.equal(name, 'vaultCreate');
            api = value;
          },
        },
        ipcRenderer: {
          invoke: (channel: string, ...args: any[]) => {
            calls.push([channel, structuredClone(args)]);
            if (failure) throw Error('invoke failed');
            return Promise.resolve();
          },
        },
      },
      { filename: 'vault-root-preload.js' },
    );
    const input = { password: new Uint8Array([1]), publicKey: new Uint8Array(32).fill(2) },
      authentication = {
        vaultId: 'vault',
        slotId: 'slot',
        kind: 'password',
        factor: new Uint8Array([3]),
      },
      proof = { enrollmentId: 'id', groups: new Uint8Array(10).fill(65) };
    for (const call of [
      () => api.rotationContext(),
      () => api.begin(input, undefined, authentication),
      () => api.confirm(proof),
      () => api.cancel(),
    ]) {
      if (failure) assert.throws(call, /invoke failed/);
      else await call();
    }
    assert.deepEqual(
      calls.map((c) => c[0]),
      [
        'vault-rotation-setup:context',
        'vault-rotation-setup:begin',
        'vault-rotation-setup:confirm',
        'vault-rotation-setup:cancel',
      ],
    );
    assert.deepEqual([...calls[1][1][0].authentication.factor], [3]);
    for (const factor of [input.password, input.publicKey, authentication.factor, proof.groups])
      assert.ok(factor.every((x) => x === 0));
    assert.deepEqual(Object.keys(api).sort(), [
      'begin',
      'cancel',
      'confirm',
      'contentProtectionAvailable',
      'rotationContext',
    ]);
  }
});
test('setup preload sends snapshots through only dedicated channels and wipes borrowed factors on invoke failure', async () => {
  const source = stripTypeScriptTypes(
    readFileSync(new URL('../electron/vault-migration-setup-preload.cts', import.meta.url), 'utf8'),
  ).replace(/^import .*?;\s*/gms, '');
  for (const failure of [false, true]) {
    let api: any;
    const calls: any[] = [];
    runInNewContext(source, {
      Uint8Array,
      process: { platform: 'win32' },
      contextBridge: {
        exposeInMainWorld: (name: string, value: any) => {
          assert.equal(name, 'vaultCreate');
          api = value;
        },
      },
      ipcRenderer: {
        invoke: (channel: string, ...args: any[]) => {
          calls.push([channel, structuredClone(args)]);
          if (failure) throw Error('invoke failed');
          return Promise.resolve();
        },
      },
    });
    const input = { password: new Uint8Array([1]), publicKey: new Uint8Array(32).fill(2) },
      legacy = { legacyMethod: 'pin', legacyFactor: new Uint8Array([3]) },
      confirm = { enrollmentId: 'id', groups: new Uint8Array(10).fill(65) };
    for (const call of [
      () => api.migrationContext(),
      () => api.begin(input, legacy),
      () => api.confirm(confirm),
      () => api.cancel(),
    ]) {
      if (failure) assert.throws(call, /invoke failed/);
      else await call();
    }
    assert.deepEqual(
      calls.map((c) => c[0]),
      [
        'vault-migration-setup:context',
        'vault-migration-setup:begin',
        'vault-migration-setup:confirm',
        'vault-migration-setup:cancel',
      ],
    );
    assert.deepEqual([...calls[1][1][0].legacyFactor], [3]);
    assert.ok(
      input.password.every((x) => x === 0) &&
        input.publicKey.every((x) => x === 0) &&
        legacy.legacyFactor.every((x) => x === 0) &&
        confirm.groups.every((x) => x === 0),
    );
    assert.deepEqual(Object.keys(api).sort(), [
      'begin',
      'cancel',
      'confirm',
      'contentProtectionAvailable',
      'migrationContext',
    ]);
  }
});

test('legacy startup preparation requires its exclusive hint, never grants app access and joins cleanup before restart', async () => {
  for (const mode of [
    '',
    'protected',
    'policy',
    'not-legacy',
    'owner',
    'navigation',
    'cancel',
    'preflight',
    'stop-error',
    'duplicate',
    'payload',
  ]) {
    const handlers = new Map<string, any>(),
      calls: string[] = [];
    let trusted = true,
      release!: () => void;
    const startup: any =
      mode === 'not-legacy'
        ? { osMigration: {} }
        : { legacy: { unprotectedAllowed: mode !== 'policy' } };
    const host: any = {
      unlockedWorkspaceId: mode === 'owner' ? 'unexpected' : undefined,
      startup: async () => startup,
      stop: async () => {
        calls.push('stop');
        if (mode === 'stop-error') throw Error('private');
      },
    };
    const dialog = (kind: string) => ({
      open: async () => {
        calls.push(kind);
        if (mode === 'navigation') trusted = false;
        if (mode === 'duplicate')
          await new Promise<void>((yes) => {
            release = yes;
          });
        return mode !== 'cancel';
      },
    });
    registerVaultProtectionIpc({
      ipc: {
        handle: (name, fn) => {
          handlers.set(name, fn);
        },
      },
      host,
      dialog: dialog('password'),
      osDialog: dialog('os'),
      trusted: () => trusted,
      parent: () => ({}) as any,
      requireAccess: () => {
        throw Error('No application grant.');
      },
      canStart: () => true,
      hold: () => {
        calls.push('hold');
        return () => calls.push('release');
      },
      quiesce: async () => {
        calls.push('quiesce');
        return mode !== 'preflight';
      },
      restart: () => {
        calls.push('restart');
      },
      fatal: () => {
        calls.push('fatal');
      },
    });
    const fn = handlers.get(
      mode === 'protected' ? 'vault:prepare-legacy' : 'vault:prepare-legacy-os',
    );
    const pending = fn({}, ...(mode === 'payload' ? [{}] : []));
    if (mode === 'duplicate') {
      await new Promise(setImmediate);
      await assert.rejects(handlers.get('vault:prepare-legacy')({}));
      release();
    }
    if (['policy', 'not-legacy', 'owner', 'navigation', 'stop-error', 'payload'].includes(mode))
      await assert.rejects(pending);
    else assert.equal(await pending, !['cancel', 'preflight'].includes(mode));
    if (['policy', 'not-legacy', 'owner', 'payload'].includes(mode)) assert.deepEqual(calls, []);
    else if (mode === 'preflight') assert.deepEqual(calls, ['hold', 'quiesce', 'release']);
    else if (mode === 'navigation' || mode === 'stop-error') {
      assert.ok(
        calls.includes('fatal') && !calls.includes('restart') && !calls.includes('release'),
      );
    } else {
      assert.deepEqual(calls, [
        'hold',
        'quiesce',
        mode === 'protected' ? 'password' : 'os',
        'stop',
        'restart',
      ]);
      assert.equal(host.unlockedWorkspaceId, undefined);
    }
  }
});

test('actual main protection registration meets the project coverage threshold', async (t) => {
  if (externalCoverage) return;
  try {
    const result = await profiler.post('Profiler.takePreciseCoverage');
    for (const url of [
      'vault-protection-main.js',
      'vault-root-retirement-main.js',
      'vault-root-preload.js',
    ]) {
      const blocks = result.result
        .filter((s) => s.url === url)
        .flatMap((s) => s.functions)
        .flatMap((f) => f.ranges);
      assert.ok(blocks.length, url);
      const measured = (100 * blocks.filter((r) => r.count > 0).length) / blocks.length;
      t.diagnostic(url + ': ' + measured.toFixed(2) + '% V8 blocks');
      assert.ok(measured >= coverageThreshold, url);
    }
    const ranges = result.result
      .filter((s) =>
        [
          'vault-protection-main.js',
          'vault-root-retirement-main.js',
          'vault-root-preload.js',
        ].includes(s.url),
      )
      .flatMap((s) => s.functions)
      .flatMap((f) => f.ranges);
    assert.ok(ranges.length);
    const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
    t.diagnostic('Main protection registration: ' + percent.toFixed(2) + '% V8 blocks');
    assert.ok(percent >= coverageThreshold);
  } finally {
    profiler.disconnect();
  }
});
