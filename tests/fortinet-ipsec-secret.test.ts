import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire, stripTypeScriptTypes } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { runInNewContext } from 'node:vm';
import * as path from 'node:path';
import test from 'node:test';
import {
  fortinetIPsecSecretChannel,
  prepareFortinetIPsecWrite,
  promptFortinetIPsecSecret,
  validFortinetIPsecSecret,
} from '../electron/fortinet-ipsec-secret.ts';

function fixture(options: { loadFailure?: boolean; setupFailure?: boolean } = {}) {
  const ipc = new EventEmitter();
  const contents = Object.assign(new EventEmitter(), {
    mainFrame: {},
    session: {
      setPermissionRequestHandler(handler: (...args: any[]) => void) {
        if (options.setupFailure) throw new Error('native window closed during setup');
        permission = handler;
      },
    },
    setWindowOpenHandler(handler: () => unknown) {
      popup = handler;
    },
  });
  let permission!: (...args: any[]) => void;
  let popup!: () => unknown;
  let authorized = true;
  let destroyed = false;
  let presented = 0;
  let forgotten = 0;
  let configuration: any;
  let url = '';
  const window = Object.assign(new EventEmitter(), {
    webContents: contents,
    isDestroyed: () => destroyed,
    destroy() {
      destroyed = true;
      window.emit('closed');
    },
    async loadURL(value: string) {
      url = value;
      if (options.loadFailure) throw new Error('private diagnostic');
    },
  });
  const promise = promptFortinetIPsecSecret({
    createWindow: (value) => {
      configuration = value;
      return window as any;
    },
    ipc: ipc as any,
    preload: '/secure/preload.cjs',
    isAuthorized: () => authorized,
    present: () => {
      presented++;
    },
    forget: () => {
      forgotten++;
    },
  });
  return {
    promise,
    ipc,
    window,
    contents,
    setAuthorized: (value: boolean) => {
      authorized = value;
    },
    send: (message: unknown, sender: unknown = contents, frame: unknown = contents.mainFrame) =>
      ipc.emit(fortinetIPsecSecretChannel, { sender, senderFrame: frame }, message),
    get state() {
      return { destroyed, presented, forgotten, configuration, url, permission, popup };
    },
  };
}

test('native key validation bounds UTF-8 bytes and rejects empty/control values', () => {
  for (const value of [
    null,
    undefined,
    42,
    '',
    ' ',
    '\nkey',
    'key\0',
    'x'.repeat(4097),
    'é'.repeat(2049),
  ])
    assert.equal(validFortinetIPsecSecret(value), false);
  for (const value of [' key with spaces ', 'x'.repeat(4096), 'é'.repeat(2048)])
    assert.equal(validFortinetIPsecSecret(value), true);
});

test('only native replacement values enter the backend write; preservation contains no PSK', async () => {
  const request = { name: 'VPN', kind: 9, settings: { Host: 'vpn.test', HasPreSharedKey: true } };
  let prompts = 0;
  const prompt = async () => {
    prompts++;
    return ' native key ';
  };
  assert.deepEqual((await prepareFortinetIPsecWrite(request, prompt)).settings, {
    Host: 'vpn.test',
    PreSharedKey: ' native key ',
  });
  const edit = { ...request, id: 'saved' };
  assert.deepEqual(await prepareFortinetIPsecWrite(edit, prompt), edit);
  assert.equal(prompts, 1);
  const replaced = await prepareFortinetIPsecWrite(
    { ...edit, settings: { ...edit.settings, ReplacePreSharedKey: true } },
    prompt,
  );
  assert.deepEqual(replaced.settings, { Host: 'vpn.test', PreSharedKey: ' native key ' });
  assert.equal(prompts, 2);
  assert.equal(
    await prepareFortinetIPsecWrite({ ...request, kind: 2 }, prompt).then((value) => value.kind),
    2,
  );
  await assert.rejects(
    prepareFortinetIPsecWrite(request, async () => ''),
    /invalid/,
  );
  await assert.rejects(
    prepareFortinetIPsecWrite(request, async () => {
      throw new Error('cancelled');
    }),
    /cancelled/,
  );
  assert.equal('PreSharedKey' in request.settings, false);
});

test('secure window accepts only its own main frame and releases every listener', async () => {
  const f = fixture();
  f.window.emit('ready-to-show');
  assert.equal(f.state.presented, 1);
  assert.equal(f.state.configuration.webPreferences.sandbox, true);
  assert.equal(f.state.configuration.webPreferences.contextIsolation, true);
  assert.equal(f.state.configuration.webPreferences.nodeIntegration, false);
  assert.equal(f.state.configuration.webPreferences.devTools, false);
  assert.match(f.state.configuration.webPreferences.partition, /^wormhole-ipsec-key-/);
  assert.deepEqual(f.state.popup(), { action: 'deny' });
  f.state.permission(null, 'clipboard-read', (allowed: boolean) => assert.equal(allowed, false));
  let blocked = false;
  f.contents.emit('will-navigate', {
    preventDefault() {
      blocked = true;
    },
  });
  assert.equal(blocked, true);
  f.send({ value: 'foreign' }, {}, f.contents.mainFrame);
  f.send({ value: 'subframe' }, f.contents, {});
  f.send({ value: 'native-only-key' });
  assert.equal(await f.promise, 'native-only-key');
  assert.equal(f.state.destroyed, true);
  assert.equal(f.state.forgotten, 1);
  assert.equal(f.ipc.listenerCount(fortinetIPsecSecretChannel), 0);
  assert.equal(f.state.url.includes('native-only-key'), false);
  f.window.emit('ready-to-show');
  assert.equal(f.state.presented, 1);
});

test('native key entry fails closed on cancellation, invalid messages, crashes and auth loss', async () => {
  for (const mode of ['cancel', 'invalid', 'closed', 'crash', 'auth']) {
    const f = fixture();
    const rejected = assert.rejects(f.promise, /cancelled|invalid/);
    if (mode === 'closed') f.window.emit('closed');
    else if (mode === 'crash') f.contents.emit('render-process-gone');
    else {
      if (mode === 'auth') f.setAuthorized(false);
      f.send(
        mode === 'cancel' ? { cancelled: true } : mode === 'invalid' ? null : { value: 'key' },
      );
    }
    await rejected;
    assert.equal(f.state.destroyed, true);
    assert.equal(f.ipc.listenerCount(fortinetIPsecSecretChannel), 0);
  }
  const f = fixture({ loadFailure: true });
  await assert.rejects(f.promise, /Could not open the secure key window/);
  assert.equal(f.state.destroyed, true);
  const setup = fixture({ setupFailure: true });
  await assert.rejects(setup.promise, /Could not open the secure key window/);
  assert.equal(setup.state.destroyed, true);
  assert.equal(setup.ipc.listenerCount(fortinetIPsecSecretChannel), 0);
});

test('native input expires and closes when workspace authorization changes', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  for (const authLoss of [false, true]) {
    const f = fixture();
    const rejected = assert.rejects(f.promise, /cancelled/);
    if (authLoss) f.setAuthorized(false);
    t.mock.timers.tick(authLoss ? 250 : 120_000);
    await rejected;
    assert.equal(f.state.destroyed, true);
  }
  await assert.rejects(
    promptFortinetIPsecSecret({ isAuthorized: () => false } as any),
    /Authentication/,
  );
});

test('native preload clears uncontrolled input and exposes no application bridge', () => {
  const source = readFileSync(
    new URL('../electron/fortinet-ipsec-secret-preload.cts', import.meta.url),
    'utf8',
  );
  assert.ok(source.includes(fortinetIPsecSecretChannel));
  assert.match(source, /input\.value = ''/);
  assert.doesNotMatch(source, /contextBridge|console\.|location\.|localStorage|sessionStorage/);
});

test('native save rechecks authorization and clears the transient PSK on success and failure', async () => {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const source = stripTypeScriptTypes(
    main.slice(
      main.indexOf('async function saveTunnelWithNativeSecret('),
      main.indexOf('function registerIpcHandlers('),
    ),
  );
  for (const mode of ['success', 'auth-loss', 'backend-error', 'queued']) {
    let native: any;
    let writes = 0;
    let prompts = 0;
    let release!: () => void;
    const queue =
      mode === 'queued'
        ? new Promise<void>((resolve) => {
            release = resolve;
          })
        : Promise.resolve();
    const save = runInNewContext(`${source}\nsaveTunnelWithNativeSecret`, {
      authSession: { authorizationEpoch: 7 },
      tunnelBrowserAuthQueue: queue,
      path,
      __dirname: '/electron',
      BrowserWindow: { getFocusedWindow: () => undefined, getAllWindows: () => [] },
      ipcMain: {},
      prepareFortinetIPsecWrite: async (...args: Parameters<typeof prepareFortinetIPsecWrite>) => {
        native = await prepareFortinetIPsecWrite(...args);
        return native;
      },
      promptFortinetIPsecSecret: async (options: any) => {
        prompts++;
        assert.ok(options.preload.endsWith('fortinet-ipsec-secret-preload.cjs'));
        return 'transient-key';
      },
      isAuthorizationEpochCurrent: () => mode !== 'auth-loss',
      requireAuthorizationEpoch: (epoch: number) => {
        assert.equal(epoch, 7);
        if (mode === 'auth-loss') throw new Error('auth lost');
      },
      mcpApprovalWindowCoordinator: {},
      runBackend: async (_operation: string, request: any) => {
        writes++;
        assert.equal(request.settings.PreSharedKey, 'transient-key');
        if (mode === 'backend-error') throw new Error('backend error');
        return { settings: { HasPreSharedKey: true } };
      },
      parseTunnelDetailsResponse: (value: any) => value,
    });
    const promise = save('tunnel-create', { name: 'VPN', kind: 9, settings: { Host: 'vpn.test' } });
    if (mode === 'queued') {
      await Promise.resolve();
      assert.equal(prompts, 0);
      assert.equal(writes, 0);
      release();
    }
    if (mode === 'success' || mode === 'queued')
      assert.deepEqual((await promise).settings, { HasPreSharedKey: true });
    else await assert.rejects(promise, /auth lost|backend error/);
    assert.equal('PreSharedKey' in native.settings, false);
    assert.equal(writes, mode === 'auth-loss' ? 0 : 1);
    assert.equal(prompts, 1);
  }
  assert.match(main, /saveTunnelWithNativeSecret\('tunnel-create', request\)/);
  assert.match(main, /saveTunnelWithNativeSecret\('tunnel-update', request\)/);
});

test('real sandboxed Chromium fits PSK/PEM controls and exposes no application bridge', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-ipsec-key-'));
  try {
    const helper = readFileSync(
      new URL('../electron/fortinet-ipsec-secret.ts', import.meta.url),
      'utf8',
    );
    const preload = readFileSync(
      new URL('../electron/fortinet-ipsec-secret-preload.cts', import.meta.url),
      'utf8',
    );
    writeFileSync(join(directory, 'helper.mjs'), stripTypeScriptTypes(helper));
    writeFileSync(
      join(directory, 'preload.cjs'),
      stripTypeScriptTypes(preload).replace(
        "import { ipcRenderer } from 'electron';",
        "const { ipcRenderer } = require('electron');",
      ),
    );
    const harness = join(directory, 'main.cjs');
    writeFileSync(
      harness,
      `
const { app, BrowserWindow, ipcMain } = require('electron');
const assert = require('node:assert/strict');
app.setPath('userData', ${JSON.stringify(directory)});
app.on('window-all-closed', () => {});
app.whenReady().then(async () => {
  const { promptFortinetIPsecSecret } = await import(${JSON.stringify(pathToFileURL(join(directory, 'helper.mjs')).href)});
  for (const kind of ['PreSharedKey', 'ClientKey']) {
  const key = await promptFortinetIPsecSecret({
    kind,
    createWindow(options) {
      const window = new BrowserWindow(options);
      window.webContents.once('did-finish-load', () => window.webContents.executeJavaScript(\`
        if (window.wormhole !== undefined || window.require !== undefined) throw Error('privileged bridge exposed');
        if (document.querySelector('footer').getBoundingClientRect().bottom > window.innerHeight) throw Error('credential buttons are clipped');
        document.querySelector('#secret').value = '-----BEGIN FIXTURE-----';
        document.querySelector('form').requestSubmit();
      \`).catch(error => { console.error(error.message); app.exit(1); }));
      return window;
    },
    ipc: ipcMain, preload: ${JSON.stringify(join(directory, 'preload.cjs'))},
    isAuthorized: () => true, present() {}, forget() {},
  });
  assert.equal(key, '-----BEGIN FIXTURE-----');
  assert.equal(BrowserWindow.getAllWindows().length, 0);
  }
  console.log('Native key isolation passed');
  app.quit();
}).catch(error => { console.error(error.message); app.exit(1); });`,
    );
    const electron = createRequire(import.meta.url)('electron') as string;
    const { ELECTRON_RUN_AS_NODE: _runAsNode, ...environment } = process.env;
    const headless = process.platform === 'linux' && !environment.DISPLAY;
    const result = await promisify(execFile)(
      headless ? 'xvfb-run' : electron,
      headless ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
      { env: { ...environment, NODE_ENV: 'test' }, windowsHide: true, timeout: 20000 },
    );
    assert.match(result.stdout, /Native key isolation passed/);
  } finally {
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});

test('PSK/password and certificate save flows collect only active secrets outside the editor', async () => {
  const request = { name: 'IPsec', kind: 9, settings: { AuthMethod: 0, UserAuth: 2 } };
  const asked: string[] = [];
  const saved = await prepareFortinetIPsecWrite(request, async (kind) => {
    asked.push(kind!);
    return 'native-secret';
  });
  assert.deepEqual(asked, ['PreSharedKey', 'Password']);
  assert.equal(saved.settings.Password, 'native-secret');
  const certificate = await prepareFortinetIPsecWrite(
    { ...request, settings: { AuthMethod: 1, UserAuth: 0 } },
    async (kind) => (kind === 'CaCert' ? '' : '-----BEGIN FIXTURE-----'),
  );
  assert.equal(certificate.settings.PreSharedKey, undefined);
  assert.equal(certificate.settings.ClientKey, '-----BEGIN FIXTURE-----');
  const preserved = await prepareFortinetIPsecWrite(
    {
      ...request,
      id: 'saved',
      settings: {
        AuthMethod: 1,
        UserAuth: 2,
        HasClientCert: true,
        HasClientKey: true,
        HasCaCert: true,
        HasPassword: true,
        HasPreSharedKey: true,
      },
    },
    async () => {
      throw Error('unexpected prompt');
    },
  );
  assert.equal(preserved.settings.HasPreSharedKey, undefined);
  assert.equal(preserved.settings.HasPassword, true);
  const systemCa = await prepareFortinetIPsecWrite(
    {
      ...request,
      id: 'saved',
      settings: { AuthMethod: 1, UserAuth: 0, HasClientCert: true, HasClientKey: true },
    },
    async () => {
      throw Error('unexpected CA prompt');
    },
  );
  assert.equal(systemCa.settings.CaCert, '');
  assert.equal(validFortinetIPsecSecret('', 'CaCert'), true);
  for (const kind of ['ClientCert', 'ClientKey', 'CaCert']) {
    assert.equal(validFortinetIPsecSecret('wrong', kind), false);
    assert.equal(validFortinetIPsecSecret('-----BEGIN ' + 'a'.repeat(131072), kind), false);
    assert.equal(validFortinetIPsecSecret(null, kind), false);
  }
});
