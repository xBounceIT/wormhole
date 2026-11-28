import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import { Session } from 'node:inspector/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { VaultSshCredentialsDialog } from '../electron/vault-ssh-credentials-dialog.ts';
import { sshRequest, sshBundle } from './fixtures/vault-ssh.ts';
import { declarations } from './fixtures/main-source.ts';
const target = 'file:///app/dist/vault-ssh-credentials.html';
class Window extends EventEmitter {
  destroyed = false;
  failDestroy = false;
  options: any;
  webContents: any = Object.assign(new EventEmitter(), {
    mainFrame: { url: target },
    setWindowOpenHandler() {},
    session: Object.assign(new EventEmitter(), {
      setPermissionRequestHandler() {},
      setPermissionCheckHandler() {},
      webRequest: { onBeforeRequest() {} },
    }),
  });
  isDestroyed() {
    return this.destroyed;
  }
  setMenu() {}
  setContentProtection() {}
  isContentProtected() {
    return true;
  }
  show() {}
  async loadURL() {}
  destroy() {
    if (this.failDestroy) throw Error('private destroy diagnostic');
    this.destroyed = true;
    this.emit('closed');
  }
}

test('SSH credential document binds session cancellation and acknowledges only closed ciphertext entry', async () => {
  const q = sshRequest(),
    b = sshBundle(q).binding;
  const context = {
    plan: {
      host: {
        binding: b,
        fileId: randomUUID(),
        revision: 'a'.repeat(64),
        fingerprint: 'SHA256:' + Buffer.alloc(32).toString('base64').slice(0, -1),
      },
      mode: 'account',
      autoSudo: false,
      sftpOnly: false,
    },
    route: null,
    endpoint: '',
    publicKey: q.publicKey,
  };
  const handlers = new Map<string, any>(),
    parent = new Window();
  let child: Window;
  const dialog = new VaultSshCredentialsDialog({
    ipc: { handle: (name, fn) => handlers.set(name, fn) } as any,
    createWindow: (options) => {
      child = new Window();
      child.options = options;
      return child as any;
    },
    url: target,
    preload: 'ssh.cjs',
  });
  await dialog.cancelSession(q.sessionId);
  await assert.rejects(dialog.open(parent as any, () => true, null, new AbortController().signal));
  const opening = dialog.open(parent as any, () => true, context, new AbortController().signal);
  void opening.catch(() => {});
  await new Promise(setImmediate);
  const event = { sender: child!.webContents, senderFrame: child!.webContents.mainFrame };
  assert.equal(child!.options.webPreferences.sandbox, true);
  assert.equal(child!.options.webPreferences.nodeIntegration, false);
  assert.equal(
    handlers.get('vault-ssh-credentials:context')(event).plan.host.binding.sessionId,
    q.sessionId,
  );
  assert.throws(
    () =>
      handlers.get('vault-ssh-credentials:context')({
        sender: parent.webContents,
        senderFrame: parent.webContents.mainFrame,
      }),
    /Invalid/,
  );
  assert.throws(
    () => handlers.get('vault-ssh-credentials:submit')(event, { password: 'private' }),
    /Invalid/,
  );
  await dialog.cancelSession(randomUUID());
  assert.equal(child!.destroyed, false);
  const envelope = {
    formatVersion: 1,
    suiteId: 2,
    enc: Buffer.alloc(32).toString('base64'),
    ciphertext: Buffer.alloc(40).toString('base64'),
  };
  assert.equal(handlers.get('vault-ssh-credentials:submit')(event, envelope), true);
  assert.equal(child!.destroyed, true);
  assert.deepEqual(await opening, envelope);
  const cancelled = dialog.open(parent as any, () => true, context, new AbortController().signal);
  void cancelled.catch(() => {});
  await dialog.cancelSession(q.sessionId);
  await assert.rejects(cancelled, /cancelled/);
  const failed = dialog.open(parent as any, () => true, context, new AbortController().signal);
  void failed.catch(() => {});
  child!.failDestroy = true;
  await assert.rejects(dialog.cancelSession(q.sessionId), /shutdown could not be confirmed/);
  await assert.rejects(failed, /could not be closed/);
  await assert.rejects(dialog.cancelSession(q.sessionId), /shutdown could not be confirmed/);
  child!.failDestroy = false;
  await dialog.cancelSession(q.sessionId);
});

test('actual SSH credential main, preload and entry use the dedicated document and exact four-method bridge', async (t) => {
  const profiler = new Session();
  profiler.connect();
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  t.after(() => profiler.disconnect());
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const code = stripTypeScriptTypes(
    declarations(main, ['vaultSshCredentialsDialog']) + '\nvaultSshCredentialsDialog;',
  );
  for (const rendererUrl of [undefined, 'http://localhost:5173', 'http://localhost:5173/'])
    for (const isPackaged of [false, true]) {
      const capture = runInNewContext(
        code,
        {
          VaultSshCredentialsDialog: class {
            options: any;
            constructor(o: any) {
              this.options = o;
            }
          },
          createApplicationWindow: (options: any) => ({ options }),
          ipcMain: {},
          rendererUrl,
          app: { isPackaged },
          URL,
          path,
          pathToFileURL,
          __dirname: 'C:/app/electron',
        },
        { filename: 'wormhole-ssh-document-main.js' },
      );
      const expected =
        rendererUrl && !isPackaged
          ? 'http://localhost:5173/vault-ssh-credentials.html'
          : pathToFileURL(
              path.resolve('C:/app/electron', '..', 'dist', 'vault-ssh-credentials.html'),
            ).href;
      assert.equal(capture.options.url, expected);
      assert.equal(
        capture.options.preload,
        path.join('C:/app/electron', 'vault-ssh-credentials-preload.cjs'),
      );
      assert.deepEqual(capture.options.createWindow({ width: 510 }).options, { width: 510 });
    }
  const preload = stripTypeScriptTypes(
    readFileSync(new URL('../electron/vault-ssh-credentials-preload.cts', import.meta.url), 'utf8'),
  ).replace(/import\s*{\s*contextBridge,\s*ipcRenderer\s*}\s*from 'electron';/, '');
  for (const platform of ['win32', 'linux']) {
    let api: any;
    const calls: any[] = [];
    runInNewContext(
      preload,
      {
        process: { platform },
        contextBridge: {
          exposeInMainWorld: (name: string, value: any) => {
            assert.equal(name, 'vaultSshCredentials');
            api = value;
          },
        },
        ipcRenderer: {
          invoke: (...args: any[]) => {
            calls.push(args);
            return Promise.resolve(true);
          },
        },
      },
      { filename: 'wormhole-ssh-document-preload.js' },
    );
    assert.deepEqual(Object.keys(api).sort(), [
      'cancel',
      'contentProtectionAvailable',
      'context',
      'submit',
    ]);
    assert.equal(api.contentProtectionAvailable, platform !== 'linux');
    await api.context();
    const envelope = { ciphertext: 'opaque' };
    await api.submit(envelope);
    await api.cancel();
    assert.deepEqual(calls, [
      ['vault-ssh-credentials:context'],
      ['vault-ssh-credentials:submit', envelope],
      ['vault-ssh-credentials:cancel'],
    ]);
  }
  const entry = stripTypeScriptTypes(
    readFileSync(new URL('../src/vault-ssh-credentials.ts', import.meta.url), 'utf8'),
  ).replace(/^import[^;]+;/, '');
  for (const hasApi of [false, true])
    for (const card of [null, {}]) {
      const api = {};
      let mounts = 0;
      runInNewContext(
        entry,
        {
          window: { vaultSshCredentials: hasApi ? api : undefined },
          document: { querySelector: () => card },
          mountVaultSshCredentialsScreen: (node: any, bridge: any) => {
            assert.equal(node, card);
            assert.equal(bridge, api);
            mounts++;
          },
        },
        { filename: 'wormhole-ssh-document-entry.js' },
      );
      assert.equal(mounts, hasApi && card ? 1 : 0);
    }
  const report = await profiler.post('Profiler.takePreciseCoverage');
  const scripts = report.result.filter((s) => s.url.startsWith('wormhole-ssh-document-'));
  assert.equal(new Set(scripts.map((s) => s.url)).size, 3);
  const ranges = scripts.flatMap((s) => s.functions.flatMap((f) => f.ranges));
  const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
  t.diagnostic(`SSH document main/preload/entry ${percent.toFixed(2)}% V8 blocks`);
  assert.ok(percent >= 80);
});
