import assert from 'node:assert/strict';
import test from 'node:test';
import { Session } from 'node:inspector/promises';
import { mountVaultLegacyStartup } from '../src/vault-legacy-startup.ts';
import { mountVaultOSMigrationScreen } from '../src/vault-os-migration-screen.ts';
import { parseVaultStartup } from '../electron/vault-contract.ts';
import { coverageThreshold } from '../scripts/test-coverage.ts';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import { VaultBackendHost } from '../electron/vault-host.ts';
import { prepareVaultMigrationBoot } from '../electron/vault-migration-boot.ts';
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseVaultMigrationContext } from '../electron/vault-migration-setup.ts';

class Element extends EventTarget {
  children: Element[] = [];
  textContent = '';
  value = '';
  disabled = false;
  hidden = false;
  attributes = new Map<string, string>();
  readonly tag: string;
  constructor(tag: string) {
    super();
    this.tag = tag;
  }
  setAttribute(key: string, value: string) {
    this.attributes.set(key, value);
  }
  append(...children: Element[]) {
    if (this.tag === 'select' && !this.children.length) this.value = children[0].value;
    this.children.push(...children);
  }
  replaceChildren(...children: Element[]) {
    this.children = children;
  }
}
const tick = () => new Promise(setImmediate),
  profiler = new Session();
const external =
  process.execArgv.includes('--experimental-test-coverage') || !!process.env.NODE_V8_COVERAGE;
if (!external) {
  profiler.connect();
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
}
const base = { slots: null, cosmetics: { theme: 'system' }, newWorkspace: false };
test('legacy startup hint is exclusive, bounded, public metadata', () => {
  for (const allowed of [true, false]) {
    const valid = { ...base, legacy: { unprotectedAllowed: allowed } };
    assert.deepEqual(parseVaultStartup(valid), valid);
    for (const extra of [
      { legacy: {} },
      { legacy: { unprotectedAllowed: 1 } },
      { legacy: { unprotectedAllowed: true, trusted: true } },
      { slots: {} },
      { newWorkspace: true },
      { unprotectedAllowed: true },
      { shared: {} },
      { osMigration: {} },
      { migration: {} },
      { rotation: {} },
      { upgrade: {} },
      { unprotected: {} },
    ])
      assert.equal(parseVaultStartup({ ...valid, ...extra }), undefined);
  }
});

test('legacy denial is pinned before readiness and cannot be cleared by process replacement or changed public metadata', async () => {
  const startup: any = { ...base, legacy: { unprotectedAllowed: true } };
  const boot = prepareVaultMigrationBoot({
    app: {
      isReady: () => false,
      requestSingleInstanceLock: () => true,
      getPath: () => 'original',
      setPath: () => assert.fail('preparation must retain the original profile'),
    } as any,
    executable: () => 'native',
    databasePath: 'db',
    probe: () => ({ status: 0, stdout: JSON.stringify(startup) }),
  });
  assert.equal(boot.legacyMigrationRequired, true);
  assert.equal(boot.migrationSessionData, undefined);
  let selected = 0;
  const host = new VaultBackendHost(
    () => ({ startup: async () => startup, lock: async () => {} }) as any,
    () => true,
    undefined,
    () => {
      selected++;
    },
  );
  assert.equal(host.requiresLegacyMigration, false);
  await host.startup();
  assert.equal(host.requiresLegacyMigration, true);
  assert.equal(host.isVaultWorkspace, false);
  assert.equal(host.unlockedWorkspaceId, undefined);
  assert.equal(selected, 1);
  await host.stop();
  delete startup.legacy;
  await host.startup();
  assert.equal(host.requiresLegacyMigration, true);
  assert.equal(selected, 1);
  await host.stop();
  const pinned = new VaultBackendHost(
    () => assert.fail('denial does not require a native process'),
    () => true,
    undefined,
    undefined,
    true,
  );
  assert.equal(pinned.requiresLegacyMigration, true);
});

test('visual changelog claims require the same trusted window through authentication', async () => {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const start = main.indexOf("  ipcMain.handle('visual-changelog:claim'");
  const end = main.indexOf("  ipcMain.handle('update:check'", start);
  assert.ok(start >= 0 && end > start);
  let handler!: (event: object, slides: unknown) => Promise<unknown>;
  let trusted = true,
    authorized = true,
    navigate = false;
  const calls: string[] = [];
  const event = {};
  runInNewContext(stripTypeScriptTypes(main.slice(start, end)), {
    ipcMain: {
      handle: (_key: string, callback: typeof handler) => {
        handler = callback;
      },
    },
    isTrustedVaultSender: (source: object) => source === event && trusted,
    serializeAuthOperation: (check: () => Promise<void>) => check(),
    requireWorkspaceAuth: async () => {
      if (!authorized) throw Error('locked');
      if (navigate) trusted = false;
    },
    app: { getVersion: () => '2.5.0' },
    runBackend: (name: string, request: unknown) => {
      calls.push(name, JSON.stringify(request));
      return true;
    },
  });
  await assert.rejects(handler(event, 'true'));
  await assert.rejects(handler({}, true));
  authorized = false;
  await assert.rejects(handler(event, true), /locked/);
  authorized = true;
  navigate = true;
  await assert.rejects(handler(event, true));
  assert.deepEqual(calls, []);
  trusted = true;
  navigate = false;
  assert.equal(await handler(event, true), true);
  assert.deepEqual(calls, [
    'visual-changelog-claim',
    JSON.stringify({ appVersion: '2.5.0', hasChangelog: true }),
  ]);
});

test('actual main legacy process gate rejects all data access before spawn and preserves capability probes', async () => {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const start = main.indexOf('async function runBackend<T>('),
    end = main.indexOf('  const args = [', start);
  assert.ok(start >= 0 && end > start);
  const gate = stripTypeScriptTypes(
    main.slice(start, end) + '\nreturn "capability"; } runBackend;',
  );
  for (const native of [false, true]) {
    const vaultBackend = {
      isVaultWorkspace: native,
      requiresLegacyMigration: true,
      unlockedWorkspaceId: '',
    };
    const call = runInNewContext(gate, { backendTimeoutMs: 1, vaultBackend });
    await assert.rejects(call('visual-changelog-claim'));
    vaultBackend.unlockedWorkspaceId = 'unlocked';
    if (native) assert.equal(await call('visual-changelog-claim'), 'capability');
    else await assert.rejects(call('visual-changelog-claim'));
    for (const operation of [
      'startup',
      'workspace',
      'settings-read',
      'auth-status',
      'auth-secret-verify',
      'migrate',
    ])
      await assert.rejects(call(operation));
    assert.equal(await call('tunnel-capabilities'), 'capability');
    await assert.rejects(call('tunnel-capabilities', undefined, undefined, { aborted: true }));
  }
});

test('OS setup preload exposes only fixed old-factor channels and erases proof on invoke errors', async () => {
  const source = stripTypeScriptTypes(
    readFileSync(new URL('../electron/vault-os-migration-preload.cts', import.meta.url), 'utf8'),
  ).replace(/^import .*?;\s*/gms, '');
  for (const failure of [false, true]) {
    let api: any;
    const channels: string[] = [];
    runInNewContext(
      source,
      {
        Uint8Array,
        ArrayBuffer,
        process: { platform: 'win32' },
        contextBridge: {
          exposeInMainWorld: (name: string, value: any) => {
            assert.equal(name, 'vaultOSMigration');
            api = value;
          },
        },
        ipcRenderer: {
          invoke: (channel: string, input: any) => {
            channels.push(channel);
            if (input) assert.deepEqual([...input.legacyFactor], [1, 2, 3]);
            if (failure) throw Error('private');
            return Promise.resolve();
          },
        },
      },
      { filename: 'vault-os-migration-preload.js' },
    );
    const input = { legacyMethod: 'pin', legacyFactor: new Uint8Array([1, 2, 3]) };
    for (const invoke of [() => api.context(), () => api.prepare(input), () => api.cancel()]) {
      if (failure) assert.throws(invoke);
      else await invoke();
    }
    assert.ok(input.legacyFactor.every((b) => b === 0));
    assert.deepEqual(channels, [
      'vault-os-migration-setup:context',
      'vault-os-migration-setup:begin',
      'vault-os-migration-setup:cancel',
    ]);
    assert.deepEqual(Object.keys(api).sort(), [
      'cancel',
      'contentProtectionAvailable',
      'context',
      'prepare',
    ]);
  }
});

test('actual main OS preparation window pins its dedicated preload and local production or development document', () => {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const first = main.indexOf('const vaultOSMigrationDialog ='),
    last = main.indexOf('const vaultRootSetupDialog =', first);
  assert.ok(first >= 0 && last > first);
  for (const rendererUrl of [undefined, 'http://localhost:5173', 'http://localhost:5173/'])
    for (const packaged of [false, true]) {
      let options: any;
      const host = {},
        ipc = {};
      runInNewContext(
        stripTypeScriptTypes(main.slice(first, last)),
        {
          VaultMigrationSetupDialog: class {
            constructor(value: any) {
              options = value;
            }
          },
          createThemedVaultWindow: (value: any) => value,
          vaultBackend: host,
          ipcMain: ipc,
          rendererUrl,
          app: { isPackaged: packaged },
          URL,
          path,
          pathToFileURL,
          __dirname: path.resolve('dist-electron'),
        },
        { filename: 'vault-os-setup-main.js' },
      );
      assert.equal(options.host, host);
      assert.equal(options.ipc, ipc);
      assert.equal(options.mode, 'os-migration');
      assert.equal(options.preload, path.resolve('dist-electron/vault-os-migration-preload.cjs'));
      assert.equal(
        options.url,
        rendererUrl && !packaged
          ? 'http://localhost:5173/vault-create.html'
          : pathToFileURL(path.resolve('dist/vault-create.html')).href,
      );
      const value = {};
      assert.equal(options.createWindow(value), value);
    }
});

test('actual protected entrypoint routes OS setup exclusively and renders bounded context failures with cancellation', async () => {
  const source = stripTypeScriptTypes(
    readFileSync(new URL('../src/vault-create.ts', import.meta.url), 'utf8'),
  ).replace(/^import .*?;\s*/gms, '');
  for (const mode of [
    'os',
    'os-invalid',
    'os-error',
    'os-cancel-error',
    'create',
    'migration',
    'rotation',
    'upgrade',
    'old-error',
    'absent',
    'no-card',
  ]) {
    const card = new Element('section'),
      calls: string[] = [];
    let dispose: (() => void) | undefined;
    const osApi = {
      context: async () => {
        if (mode === 'os-error') throw Error('private');
        return mode === 'os-invalid' || mode === 'os-cancel-error'
          ? { methods: ['untrusted'] }
          : { methods: ['none'] };
      },
      cancel: async () => {
        calls.push('cancel');
        if (mode === 'os-cancel-error') throw Error('private');
      },
    };
    const api: any = {
      cancel: async () => {
        calls.push('old-cancel');
      },
    };
    if (mode === 'migration') api.migrationContext = async () => ({ methods: ['pin'] });
    if (mode === 'rotation') api.rotationContext = async () => ({ slots: {} });
    if (mode === 'upgrade') api.upgradeContext = async () => ({});
    if (mode === 'old-error')
      api.migrationContext = async () => {
        throw Error('private');
      };
    runInNewContext(
      source,
      {
        window: {
          vaultCreate: mode === 'absent' ? undefined : api,
          ...(mode.startsWith('os') ? { vaultOSMigration: osApi } : {}),
          addEventListener: (name: string, fn: () => void) => {
            assert.equal(name, 'pagehide');
            dispose = fn;
          },
        },
        document: {
          querySelector: () => (mode === 'no-card' ? null : card),
          createElement: (tag: string) => new Element(tag),
        },
        parseVaultMigrationContext,
        parseVaultRootEnrollmentContext: (v: unknown) => v,
        parseVaultUpgradeContext: (v: unknown) => v,
        mountVaultOSMigrationScreen: (_card: unknown, bridge: unknown, context: any) => {
          assert.equal(_card, card);
          assert.equal(bridge, osApi);
          assert.deepEqual(context.methods, ['none']);
          calls.push('os');
          return () => calls.push('disposed');
        },
        mountVaultCreateScreen: (_card: unknown, bridge: unknown) => {
          assert.equal(bridge, api);
          calls.push('old');
        },
      },
      { filename: 'vault-create-entry.js' },
    );
    await tick();
    if (mode === 'os') {
      assert.deepEqual(calls, ['os']);
      dispose!();
      assert.equal(calls.at(-1), 'disposed');
    } else if (mode.startsWith('os-') || mode === 'old-error') {
      assert.equal(calls.length, 0);
      assert.ok(!card.children[0].textContent.includes('private'));
      card.children.find((e) => e.tag === 'button')!.dispatchEvent(new Event('click'));
      await tick();
      assert.equal(calls[0], mode === 'old-error' ? 'old-cancel' : 'cancel');
    } else assert.deepEqual(calls, mode === 'absent' || mode === 'no-card' ? [] : ['old']);
  }
});

test('legacy startup selects fixed protected-window actions and handles disposal and retry without loading data', async (t) => {
  const original = globalThis.document;
  globalThis.document = { createElement: (tag: string) => new Element(tag) } as any;
  t.after(() => {
    globalThis.document = original;
  });
  for (const allow of [true, false])
    for (const mode of ['protect', 'skip', 'cancel', 'error', 'disposed', 'disposed-error']) {
      const card = new Element('section');
      let calls = 0,
        ready = 0,
        resolve!: (value: boolean) => void,
        reject!: (error: Error) => void;
      const run = () => {
        calls++;
        return new Promise<boolean>((yes, no) => {
          resolve = yes;
          reject = no;
        });
      };
      const dispose = mountVaultLegacyStartup(
        card as any,
        {
          prepareLegacyVault: () => {
            assert.ok(mode !== 'skip' || !allow);
            return run();
          },
          prepareLegacyUnprotectedVault: () => {
            assert.ok(allow && mode === 'skip');
            return run();
          },
          markStartupReady: () => {
            ready++;
          },
        },
        allow,
      );
      const buttons = card.children.filter((e) => e.tag === 'button'),
        status = card.children.find((e) => e.attributes.get('role') === 'status')!;
      assert.equal(buttons.length, allow ? 2 : 1);
      const button = buttons[mode === 'skip' && allow ? 1 : 0];
      button.dispatchEvent(new Event('click'));
      button.dispatchEvent(new Event('click'));
      assert.equal(calls, 1);
      assert.equal(ready, 1);
      assert.ok(buttons.every((b) => b.disabled));
      if (mode.startsWith('disposed')) dispose();
      if (mode.endsWith('error')) reject(Error('private native diagnostic'));
      else resolve(mode !== 'cancel');
      await tick();
      assert.ok(!status.textContent.includes('private'));
      if (mode === 'error') {
        assert.equal(button.disabled, false);
        button.dispatchEvent(new Event('click'));
        resolve(true);
        await tick();
        assert.equal(calls, 2);
      } else assert.equal(button.disabled, mode !== 'cancel');
      dispose();
      const before = calls;
      button.dispatchEvent(new Event('click'));
      assert.equal(calls, before);
    }
});

test('OS preparation screen clears old proof, supports PIN/password alternatives, cancellation and late completion', async (t) => {
  const original = globalThis.document;
  globalThis.document = { createElement: (tag: string) => new Element(tag) } as any;
  t.after(() => {
    globalThis.document = original;
  });
  for (const mode of [
    'none',
    'pin',
    'password',
    'alternatives',
    'oversize',
    'error',
    'cancel',
    'cancel-error',
    'late',
    'late-error',
  ]) {
    const card = new Element('section');
    let calls = 0,
      cancels = 0,
      bytes: Uint8Array | undefined,
      resolve!: () => void,
      reject!: (error: Error) => void;
    const methods =
      mode === 'none' ? ['none'] : mode === 'alternatives' ? ['password', 'pin'] : ['password'];
    if (mode === 'pin') methods[0] = 'pin';
    const dispose = mountVaultOSMigrationScreen(
      card as any,
      {
        contentProtectionAvailable: mode !== 'none',
        context: async () => ({ methods: methods as any }),
        prepare: async (input) => {
          calls++;
          bytes = input.legacyFactor;
          assert.equal(input.legacyMethod, methods[0]);
          assert.deepEqual(Object.keys(input).sort(), ['legacyFactor', 'legacyMethod']);
          if (mode.startsWith('late'))
            await new Promise<void>((yes, no) => {
              resolve = yes;
              reject = no;
            });
          if (mode === 'error') throw Error('private');
        },
        cancel: async () => {
          cancels++;
          if (mode === 'cancel-error') throw Error('private');
        },
      },
      { methods: methods as any },
    );
    const form = card.children.find((e) => e.tag === 'form')!,
      [method, label, status, submit, cancel] = form.children,
      field = label.children[0];
    assert.equal(label.hidden, mode === 'none');
    if (mode !== 'none') {
      form.dispatchEvent(new Event('submit', { cancelable: true }));
      assert.equal(calls, 0);
      field.value = 'old proof';
      if (mode === 'alternatives') {
        method.value = 'pin';
        method.dispatchEvent(new Event('change'));
        assert.equal(field.value, '');
        method.value = 'password';
        method.dispatchEvent(new Event('change'));
      }
      field.value = mode === 'oversize' ? '界'.repeat(400) : 'old proof';
      field.dispatchEvent(new Event('input'));
    }
    if (mode.startsWith('cancel')) {
      cancel.dispatchEvent(new Event('click'));
      await tick();
      assert.equal(cancels, 1);
      assert.equal(field.value, '');
      if (mode === 'cancel-error') assert.match(status.textContent, /could not be confirmed/);
    } else {
      form.dispatchEvent(new Event('submit', { cancelable: true }));
      form.dispatchEvent(new Event('submit', { cancelable: true }));
      assert.equal(field.value, '');
      if (mode.startsWith('late')) {
        dispose();
        if (mode === 'late-error') reject(Error('private'));
        else resolve();
      }
      await tick();
      assert.equal(calls, mode === 'oversize' ? 0 : 1);
      if (bytes) assert.ok(bytes.every((b) => b === 0));
      assert.ok(!status.textContent.includes('private'));
      assert.equal(submit.disabled, true);
    }
    dispose();
    const count = calls;
    form.dispatchEvent(new Event('submit', { cancelable: true }));
    assert.equal(calls, count);
  }
});

test('legacy startup and protected preparation meet measured coverage', async (t) => {
  if (external) return;
  try {
    const result = await profiler.post('Profiler.takePreciseCoverage');
    for (const file of [
      'vault-legacy-startup.ts',
      'vault-os-migration-screen.ts',
      'vault-os-migration-preload.js',
      'vault-create-entry.js',
      'vault-os-setup-main.js',
    ]) {
      const ranges = result.result
        .filter((s) => s.url.endsWith('/' + file) || s.url === file)
        .flatMap((s) => s.functions)
        .flatMap((f) => f.ranges);
      assert.ok(ranges.length, file);
      const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
      t.diagnostic(file + ': ' + percent.toFixed(2) + '% V8 blocks');
      assert.ok(percent >= coverageThreshold, file);
    }
  } finally {
    profiler.disconnect();
  }
});
