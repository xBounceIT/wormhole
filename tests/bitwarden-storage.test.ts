import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { transformWithOxc } from 'vite';
import {
  captureBitwardenExtensionStorage,
  restoreBitwardenExtensionStorage,
} from '../electron/bitwarden-storage.ts';

type StorageValues = Record<string, unknown>;
type BackgroundMemory = {
  store: Record<string, string>;
  save(key: string, value: unknown): Promise<void>;
  remove(key: string): Promise<void>;
};

class FakeMemoryStorage {
  values: StorageValues;
  connections = 0;
  disconnections = 0;
  mutations = 0;
  response: 'normal' | 'invalid-keys' | 'invalid-json' | 'disconnect' = 'normal';

  constructor(values: StorageValues = {}) {
    this.values = { ...values };
  }

  connect = ({ name }: { name: string }) => {
    assert.equal(name, 'session');
    this.connections += 1;
    let closed = false;
    const messages: ((message: Record<string, unknown>) => void)[] = [];
    const disconnects: (() => void)[] = [];
    const receive = (message: Record<string, unknown>) => {
      if (!closed) for (const listener of messages) listener(message);
    };
    const disconnect = () => {
      if (closed) return;
      closed = true;
      this.disconnections += 1;
      for (const listener of disconnects) listener();
    };
    setImmediate(() => {
      if (this.response === 'disconnect') {
        disconnect();
        return;
      }
      receive({ originator: 'untrusted', action: 'initialization', data: ['ignored'] });
      receive({
        originator: 'background',
        action: 'initialization',
        data: this.response === 'invalid-keys' ? [123] : Object.keys(this.values),
      });
    });
    return {
      onMessage: {
        addListener: (listener: (message: Record<string, unknown>) => void) =>
          messages.push(listener),
      },
      onDisconnect: { addListener: (listener: () => void) => disconnects.push(listener) },
      disconnect,
      postMessage: (message: { id: string; action: string; key: string; data?: string }) => {
        setImmediate(() => {
          let value: unknown = null;
          if (message.action === 'get') value = this.values[message.key] ?? null;
          if (message.action === 'save') {
            this.mutations += 1;
            const value: unknown = JSON.parse(message.data!);
            if (value == null) delete this.values[message.key];
            else this.values[message.key] = value;
          }
          if (message.action === 'remove') {
            this.mutations += 1;
            delete this.values[message.key];
          }
          receive({ originator: 'background', action: 'subject_update', data: {} });
          receive({ originator: 'background', id: 'unknown', data: 'null' });
          receive({
            originator: 'background',
            id: message.id,
            data: this.response === 'invalid-json' ? 'invalid' : JSON.stringify(value),
          });
        });
      },
    };
  };
}

class FakeExtensionContents {
  private readonly context: vm.Context;
  destroyed = false;
  delayLocalCapture = false;
  localFailure?: 'get' | 'set' | 'remove';
  finishLocalCapture?: () => void;
  readonly returnedSnapshots: unknown[] = [];
  readonly localStates: StorageValues[] = [];
  readonly sessionStates: StorageValues[] = [];

  constructor(
    localValues: StorageValues,
    memory = new FakeMemoryStorage(),
    nativeSession?: StorageValues,
    backgroundMemory?: BackgroundMemory,
  ) {
    const local = { ...localValues };
    const runtime = { lastError: null as { message: string } | null, connect: memory.connect };
    const storageArea = (values: StorageValues) => {
      const changed = () =>
        (values === local ? this.localStates : this.sessionStates).push({ ...values });
      const failed = (operation: 'get' | 'set' | 'remove', callback: () => void) => {
        if (values !== local || this.localFailure !== operation) return false;
        runtime.lastError = { message: `local ${operation} failed` };
        callback();
        runtime.lastError = null;
        return true;
      };
      return {
        clear(callback: () => void) {
          for (const key of Object.keys(values)) delete values[key];
          changed();
          callback();
        },
        remove(keys: string | string[], callback: () => void) {
          if (failed('remove', callback)) return;
          for (const key of typeof keys === 'string' ? [keys] : keys) delete values[key];
          changed();
          callback();
        },
        get: (_keys: null, callback: (value: StorageValues) => void) => {
          if (failed('get', () => callback({}))) return;
          if (this.delayLocalCapture && values === local) {
            this.finishLocalCapture = () => callback({ ...values });
          } else {
            callback({ ...values });
          }
        },
        set(value: StorageValues, callback: () => void) {
          if (failed('set', callback)) return;
          Object.assign(values, value);
          changed();
          callback();
        },
      };
    };
    this.context = vm.createContext({
      TextEncoder,
      Promise: class UnsupportedPagePromise {
        constructor() {
          throw new Error('The storage bridge must not use the extension page Promise.');
        }
      },
      chrome: {
        runtime,
        storage: {
          local: storageArea(local),
          ...(nativeSession ? { session: storageArea(nativeSession) } : {}),
        },
      },
      ...(backgroundMemory
        ? { bitwardenMain: { memoryStorageForStateProviders: backgroundMemory } }
        : {}),
    });
  }

  executeJavaScript<T>(script: string): Promise<T> {
    const result = vm.runInContext(script, this.context) as T;
    if (result && typeof result === 'object') this.returnedSnapshots.push(result);
    return globalThis.Promise.resolve(result);
  }

  pendingPageKeys(): string[] {
    return vm.runInContext(
      'Object.keys(globalThis).filter(key => key.startsWith("__wormholeBitwarden"))',
      this.context,
    );
  }

  isDestroyed(): boolean {
    return this.destroyed;
  }
}

test('Bitwarden storage capture does not depend on the popup Promise implementation', async () => {
  const contents = new FakeExtensionContents({ account: 'encrypted-value', revision: 7 });

  const snapshot = await captureBitwardenExtensionStorage(contents);

  assert.deepEqual(JSON.parse(snapshot.localJson), {
    account: 'encrypted-value',
    revision: 7,
  });
  assert.deepEqual(JSON.parse(snapshot.sessionJson), {});
});

test('Bitwarden storage restore replaces MV2 memory without chrome.storage.session', async () => {
  const contents = new FakeExtensionContents({ stale: true });

  await restoreBitwardenExtensionStorage(contents, {
    localJson: JSON.stringify({ account: 'restored', revision: 8 }),
    sessionJson: JSON.stringify({ session: 'restored' }),
  });
  const snapshot = await captureBitwardenExtensionStorage(contents);

  assert.deepEqual(JSON.parse(snapshot.localJson), { account: 'restored', revision: 8 });
  assert.deepEqual(JSON.parse(snapshot.sessionJson), { session: 'restored' });
});

test('MV2 vault session survives popup closure and restores into another profile', async () => {
  const memory = new FakeMemoryStorage({
    account: { status: 'unlocked' },
    key: { encrypted: 'test' },
  });
  const popup = new FakeExtensionContents({ account: 'logged-in' }, memory);
  const captured = await captureBitwardenExtensionStorage(popup);
  popup.destroyed = true;

  const nextMemory = new FakeMemoryStorage({ staleAccount: true });
  const reopened = new FakeExtensionContents({ stale: true }, nextMemory);
  await restoreBitwardenExtensionStorage(reopened, captured);
  assert.deepEqual(await captureBitwardenExtensionStorage(reopened), captured);
  assert.deepEqual(nextMemory.values, memory.values);
  assert.equal(memory.connections, memory.disconnections);
  assert.equal(nextMemory.connections, nextMemory.disconnections);
});

test('native session storage captures and restores without using the MV2 port', async () => {
  const memory = new FakeMemoryStorage();
  const contents = new FakeExtensionContents({}, memory, { stale: true });
  await restoreBitwardenExtensionStorage(contents, {
    localJson: '{}',
    sessionJson: '{"key":"native"}',
  });
  assert.deepEqual(JSON.parse((await captureBitwardenExtensionStorage(contents)).sessionJson), {
    key: 'native',
  });
  assert.equal(memory.connections, 0);
});

test('MV2 null session values follow Bitwarden removal semantics', async () => {
  const memory = new FakeMemoryStorage({ removed: 'stale', kept: 'live' });
  const contents = new FakeExtensionContents({}, memory);
  await restoreBitwardenExtensionStorage(contents, {
    localJson: '{}',
    sessionJson: '{"removed":null,"kept":"live"}',
  });
  assert.deepEqual(JSON.parse((await captureBitwardenExtensionStorage(contents)).sessionJson), {
    kept: 'live',
  });
});

test('restoring an existing account never publishes a temporary logged-out local state', async () => {
  const contents = new FakeExtensionContents({
    activeAccountId: 'account',
    token: 'old',
    stale: true,
  });
  await restoreBitwardenExtensionStorage(contents, {
    localJson: '{"activeAccountId":"account","token":"new"}',
    sessionJson: '{}',
  });
  assert.ok(contents.localStates.length > 0);
  assert.ok(contents.localStates.every((state) => state.activeAccountId === 'account'));
  assert.deepEqual(JSON.parse((await captureBitwardenExtensionStorage(contents)).localJson), {
    activeAccountId: 'account',
    token: 'new',
  });
});

test('restoring an unchanged snapshot does not invalidate live account or session observers', async () => {
  const memory = new FakeMemoryStorage({ key: 'live' });
  const contents = new FakeExtensionContents({ activeAccountId: 'account' }, memory);
  const snapshot = await captureBitwardenExtensionStorage(contents);
  await restoreBitwardenExtensionStorage(contents, snapshot);
  assert.deepEqual(contents.localStates, []);
  assert.equal(memory.mutations, 0);
  const native = new FakeExtensionContents({ activeAccountId: 'account' }, undefined, {
    key: 'live',
  });
  await restoreBitwardenExtensionStorage(native, await captureBitwardenExtensionStorage(native));
  assert.deepEqual(native.localStates, []);
  assert.deepEqual(native.sessionStates, []);
});

for (const operation of ['get', 'set', 'remove'] as const) {
  test(`restore propagates local ${operation} failures`, async () => {
    const contents = new FakeExtensionContents({ stale: true });
    contents.localFailure = operation;
    await assert.rejects(
      restoreBitwardenExtensionStorage(contents, {
        localJson: '{"activeAccountId":"account"}',
        sessionJson: '{}',
      }),
      new RegExp(`local ${operation} failed`),
    );
  });
}

test('a failed MV2 session restore never publishes an authenticated disk account', async () => {
  const memory: BackgroundMemory = {
    store: {},
    save: () => Promise.reject(new Error('test-private-value')),
    remove: () => Promise.resolve(),
  };
  const contents = new FakeExtensionContents({}, undefined, undefined, memory);
  await assert.rejects(
    restoreBitwardenExtensionStorage(contents, {
      localJson: '{"activeAccountId":"account"}',
      sessionJson: '{"key":"live"}',
    }),
    /memory storage update failed/,
  );
  assert.deepEqual(contents.localStates, []);
});

test('logout can remove MV2 memory whose old value cannot be decoded', async () => {
  const memory: BackgroundMemory = {
    store: { stale: 'invalid-json' },
    save: () => Promise.resolve(),
    remove: (key) => {
      delete memory.store[key];
      return Promise.resolve();
    },
  };
  const background = new FakeExtensionContents(
    { activeAccountId: 'old' },
    undefined,
    undefined,
    memory,
  );
  await restoreBitwardenExtensionStorage(background, { localJson: '{}', sessionJson: '{}' });
  assert.deepEqual(memory.store, {});
  const foreground = new FakeMemoryStorage({ stale: 'old' });
  foreground.response = 'invalid-json';
  await restoreBitwardenExtensionStorage(new FakeExtensionContents({}, foreground), {
    localJson: '{}',
    sessionJson: '{}',
  });
  assert.deepEqual(foreground.values, {});
  assert.equal(foreground.connections, foreground.disconnections);
});

test('a late background memory restore cannot publish disk state after its deadline', async (context) => {
  context.mock.timers.enable({ apis: ['Date', 'setTimeout'] });
  let finish!: () => void;
  const memory: BackgroundMemory = {
    store: {},
    save: () =>
      new Promise<void>((resolve) => {
        finish = resolve;
      }),
    remove: () => Promise.resolve(),
  };
  const contents = new FakeExtensionContents({}, undefined, undefined, memory);
  const rejected = assert.rejects(
    restoreBitwardenExtensionStorage(contents, {
      localJson: '{"activeAccountId":"account"}',
      sessionJson: '{"key":"live"}',
    }),
    /timed out/,
  );
  await new Promise<void>((resolve) => setImmediate(resolve));
  context.mock.timers.tick(10_000);
  await rejected;
  finish();
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.deepEqual(contents.localStates, []);
  assert.deepEqual(Array.from(contents.pendingPageKeys()), []);
});

for (const [response, expected] of [
  ['invalid-keys', /invalid keys/],
  ['invalid-json', /JSON/],
  ['disconnect', /disconnected before completion/],
] as const) {
  test(`MV2 capture rejects ${response} and disconnects its port`, async () => {
    const memory = new FakeMemoryStorage({ key: true });
    memory.response = response;
    await assert.rejects(
      captureBitwardenExtensionStorage(new FakeExtensionContents({}, memory)),
      expected,
    );
    assert.equal(memory.connections, memory.disconnections);
  });
}

test('capture rejects oversized session memory and closes its port', async () => {
  const memory = new FakeMemoryStorage({ key: 'x'.repeat(8 * 1024 * 1024) });
  const contents = new FakeExtensionContents({}, memory);
  await assert.rejects(captureBitwardenExtensionStorage(contents), /safety limit/);
  assert.ok(contents.returnedSnapshots.every((value) => JSON.stringify(value).length < 1024));
  assert.equal(memory.connections, memory.disconnections);
});

for (const operation of ['capture', 'restore'] as const) {
  test(`${operation} timeout covers an unresponsive extension renderer`, async (context) => {
    context.mock.timers.enable({ apis: ['Date', 'setTimeout'] });
    let calls = 0;
    const contents = {
      isDestroyed: () => false,
      executeJavaScript: () => {
        calls += 1;
        return new Promise<never>(() => {});
      },
    };
    const pending =
      operation === 'capture'
        ? captureBitwardenExtensionStorage(contents)
        : restoreBitwardenExtensionStorage(contents, { localJson: '{}', sessionJson: '{}' });
    const result = assert.rejects(pending, /timed out/);
    context.mock.timers.tick(10_000);
    await result;
    assert.ok(calls <= 2, 'cleanup must also be bounded');
  });
}

test('the same deadline bounds an unresponsive storage poll', async (context) => {
  context.mock.timers.enable({ apis: ['Date', 'setTimeout'] });
  let calls = 0;
  const contents = {
    isDestroyed: () => false,
    executeJavaScript: () => {
      calls += 1;
      return calls === 2 ? new Promise<never>(() => {}) : Promise.resolve(true);
    },
  };
  const result = assert.rejects(captureBitwardenExtensionStorage(contents), /timed out/);
  await new Promise<void>((resolve) => setImmediate(resolve));
  context.mock.timers.tick(10_000);
  await result;
  assert.equal(calls, 3);
});

test('cleanup dispatch failure does not mask the original storage error', async () => {
  let calls = 0;
  const contents = {
    isDestroyed: () => false,
    executeJavaScript: () => {
      calls += 1;
      if (calls === 1) return Promise.resolve(true);
      throw new Error(calls === 2 ? 'original capture failure' : 'cleanup failure');
    },
  };
  await assert.rejects(captureBitwardenExtensionStorage(contents), /original capture failure/);
  assert.equal(calls, 3);
});

test('UTF-8 local storage is bounded inside the page before it crosses IPC', async () => {
  const contents = new FakeExtensionContents({ account: '€'.repeat(3 * 1024 * 1024) });
  await assert.rejects(captureBitwardenExtensionStorage(contents), /safety limit/);
  assert.ok(contents.returnedSnapshots.every((value) => JSON.stringify(value).length < 1024));
});

test('late storage callbacks cannot recreate a timed-out session snapshot', async (context) => {
  context.mock.timers.enable({ apis: ['Date', 'setTimeout'] });
  const contents = new FakeExtensionContents({ account: 'test-private-value' });
  contents.delayLocalCapture = true;
  const result = assert.rejects(captureBitwardenExtensionStorage(contents), /timed out/);
  // Allow the launch and the first poll to resolve before advancing the deadline.
  await new Promise<void>((resolve) => setImmediate(resolve));
  context.mock.timers.tick(10_000);
  await result;
  contents.finishLocalCapture!();
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.deepEqual(Array.from(contents.pendingPageKeys()), []);
});

test('a popup destroyed before capture reports that its storage page closed', async () => {
  const contents = new FakeExtensionContents({});
  contents.destroyed = true;
  await assert.rejects(captureBitwardenExtensionStorage(contents), /page closed/);
});

test('Electron MV2 background and reopened popups share the restored vault session', async (context) => {
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-bitwarden-storage-'));
  const source = readFileSync(new URL('../electron/bitwarden-storage.ts', import.meta.url), 'utf8');
  const compiled = await transformWithOxc(source, 'bitwarden-storage.ts', { target: 'es2022' });
  const require = createRequire(import.meta.url);
  const { ELECTRON_RUN_AS_NODE: _electronRunAsNode, ...environment } = process.env;
  try {
    writeFileSync(join(directory, 'storage.mjs'), compiled.code);
    writeFileSync(
      join(directory, 'manifest.json'),
      JSON.stringify({
        name: 'MV2 vault storage regression',
        version: '1.0.0',
        manifest_version: 2,
        permissions: ['storage'],
        background: { page: 'background.html', persistent: true },
        browser_action: { default_popup: 'popup.html' },
      }),
    );
    writeFileSync(join(directory, 'background.html'), '<script src="background.js"></script>');
    writeFileSync(join(directory, 'popup.html'), '<!doctype html><title>Vault popup</title>');
    // Match Bitwarden's MV2 SerializedMemoryStorageService and ForegroundMemoryStorageService
    // protocol while exercising Electron's real storage callbacks, ports, and popup teardown.
    writeFileSync(
      join(directory, 'background.js'),
      `
      const memory = {
        store: {},
        mutations: 0,
        save(key, value) {
          if (value == null) return this.remove(key);
          this.mutations++;
          this.store[key] = JSON.stringify(value);
          return Promise.resolve();
        },
        remove(key) { this.mutations++; delete this.store[key]; return Promise.resolve(); },
      };
      globalThis.bitwardenMain = { memoryStorageForStateProviders: memory };
      globalThis.accountObserver = { active: null, lost: 0, missingToken: 0 };
      // Bitwarden's AbstractChromeStorageService ignores bulk writes as storage reseeding.
      chrome.storage.local.onChanged.addListener(changes => {
        if (Object.keys(changes).length !== 1 || !changes.activeAccountId) return;
        const active = changes.activeAccountId.newValue;
        if (!active) globalThis.accountObserver.lost++;
        else if (!memory.store.sessionKey) globalThis.accountObserver.missingToken++;
        globalThis.accountObserver.active = active ?? null;
      });
      chrome.runtime.onConnect.addListener(port => {
        if (port.name !== 'session') return;
        port.onMessage.addListener(message => {
          if (message.originator !== 'foreground') return;
          let result = null;
          if (message.action === 'get') result = JSON.parse(memory.store[message.key] ?? 'null');
          if (message.action === 'save') memory.save(message.key, JSON.parse(message.data));
          if (message.action === 'remove') memory.remove(message.key);
          port.postMessage({ originator: 'background', id: message.id, data: JSON.stringify(result) });
        });
        port.postMessage({ originator: 'background', action: 'initialization', data: Object.keys(memory.store) });
      });
    `,
    );
    const harness = join(directory, 'test.cjs');
    writeFileSync(
      harness,
      `
      const assert = require('node:assert/strict');
      const { app, BrowserWindow, WebContentsView, session, webContents } = require('electron');
      const { pathToFileURL } = require('node:url');
      const { ElectronChromeExtensions } = require(${JSON.stringify(require.resolve('electron-chrome-extensions'))});
      app.setPath('userData', __dirname);
      app.setPath('sessionData', __dirname);
      app.whenReady().then(async () => {
        const storage = await import(pathToFileURL(${JSON.stringify(join(directory, 'storage.mjs'))}));
        const owner = new BrowserWindow({ show: false });
        try {
          const extensions = new Map();
          const prepared = async partition => {
            const browser = session.fromPartition(partition);
            if (!extensions.has(partition)) {
              new ElectronChromeExtensions({ session: browser, license: 'GPL-3.0' });
              extensions.set(partition, await browser.extensions.loadExtension(__dirname));
            }
            const extension = extensions.get(partition);
            const popup = new WebContentsView({ webPreferences: { partition, sandbox: true } });
            owner.contentView.addChildView(popup);
            await popup.webContents.loadURL('chrome-extension://' + extension.id + '/popup.html');
            const background = webContents.getAllWebContents().find(contents =>
              contents.session === browser && contents.getType() === 'backgroundPage');
            assert.ok(background);
            return { popup, background };
          };
          const snapshot = { localJson: '{"activeAccountId":"signed-in","token":"test-only"}', sessionJson: '{"vaultStatus":"unlocked","sessionKey":"test-only"}' };
          const first = await prepared('persist:vault-first');
          await storage.restoreBitwardenExtensionStorage(first.background, snapshot);
          const observer = () => first.background.executeJavaScript('JSON.stringify(globalThis.accountObserver)');
          assert.deepEqual(JSON.parse(await observer()), { active: 'signed-in', lost: 0, missingToken: 0 });
          const mutations = await first.background.executeJavaScript('globalThis.bitwardenMain.memoryStorageForStateProviders.mutations');
          await storage.restoreBitwardenExtensionStorage(first.background, snapshot);
          assert.equal(await first.background.executeJavaScript('globalThis.bitwardenMain.memoryStorageForStateProviders.mutations'), mutations);
          assert.deepEqual(JSON.parse(await observer()), { active: 'signed-in', lost: 0, missingToken: 0 });
          assert.deepEqual(await storage.captureBitwardenExtensionStorage(first.popup.webContents), snapshot);
          owner.contentView.removeChildView(first.popup);
          first.popup.webContents.close();
          assert.equal(first.background.isDestroyed(), false);
          const captured = await storage.captureBitwardenExtensionStorage(first.background);
          assert.deepEqual(captured, snapshot);

          const second = await prepared('persist:vault-second');
          await storage.restoreBitwardenExtensionStorage(second.popup.webContents, captured);
          assert.deepEqual(await storage.captureBitwardenExtensionStorage(second.background), snapshot);
          owner.contentView.removeChildView(second.popup);
          second.popup.webContents.close();
          const reopened = await prepared('persist:vault-second');
          assert.deepEqual(await storage.captureBitwardenExtensionStorage(reopened.popup.webContents), snapshot);
          // A real logout must replace the memory snapshot, including removal of old keys.
          await storage.restoreBitwardenExtensionStorage(reopened.background, { localJson: '{}', sessionJson: '{}' });
          assert.deepEqual(await storage.captureBitwardenExtensionStorage(reopened.popup.webContents), { localJson: '{}', sessionJson: '{}' });
          console.log('MV2 vault state survived popup teardown, another profile, and reopening; logout cleared it.');
        } finally { owner.destroy(); }
        app.quit();
      }).catch(error => { console.error(error); app.exit(1); });
    `,
    );
    const electron = require('electron') as string;
    const needsDisplay = process.platform === 'linux' && !environment.DISPLAY;
    const { stdout } = await promisify(execFile)(
      needsDisplay ? 'xvfb-run' : electron,
      needsDisplay ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
      { env: { ...environment, NODE_ENV: 'test' }, timeout: 60_000, windowsHide: true },
    );
    context.diagnostic(stdout.trim());
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
