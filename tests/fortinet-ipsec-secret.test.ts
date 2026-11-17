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
  parseFortinetIPsecCredentials,
  prepareFortinetIPsecWrite,
  promptFortinetIPsecSecret,
} from '../electron/fortinet-ipsec-secret.ts';
import {
  parseTunnelDetailsResponse,
  parseTunnelWriteRequest,
  type TunnelWriteRequest,
} from '../electron/tunnel-test-contract.ts';

const fortinetIPsecSecretChannel = 'fortinet-ipsec:secret-response';

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
  const window = Object.assign(new EventEmitter(), {
    webContents: contents,
    isDestroyed: () => destroyed,
    destroy() {
      destroyed = true;
      window.emit('closed');
    },
    async loadURL() {
      if (options.loadFailure) throw new Error('private diagnostic');
    },
  });
  const promise = promptFortinetIPsecSecret({
    kind: 'ClientKey',
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
      return { destroyed, presented, forgotten, configuration, permission, popup };
    },
  };
}

test('inline credentials keep valid Unicode and reject malformed or oversized IPC inputs', () => {
  for (const value of [
    null,
    undefined,
    42,
    '',
    ' ',
    '\u0085',
    '\u2028',
    '\uD800',
    'unpaired\uDFFF',
    '\nkey',
    'key\0',
    'x'.repeat(4097),
    'é'.repeat(2049),
  ])
    assert.throws(
      () => parseFortinetIPsecCredentials(9, { Password: value }),
      /valid Fortinet IPsec/,
    );
  for (const value of [
    ' key with spaces ',
    'key\u2028with\u2029separators',
    '\uFEFF',
    '🔒',
    'x'.repeat(4096),
    'é'.repeat(2048),
  ])
    assert.deepEqual(parseFortinetIPsecCredentials(9, { Password: value }), { Password: value });
  for (const input of [null, [], new Map([['Password', 'key']]), 'key', { ClientKey: 'key' }])
    assert.throws(() => parseFortinetIPsecCredentials(9, input), /valid Fortinet IPsec/);
  assert.throws(
    () => parseFortinetIPsecCredentials(2, { Password: 'key' }),
    /valid Fortinet IPsec/,
  );
});

test('inline values replace saved credentials and omitted values preserve them on edit', async () => {
  const request = { name: 'VPN', kind: 9, settings: { Host: 'vpn.test', HasPreSharedKey: true } };
  const prompt = async () => {
    throw new Error('unexpected prompt');
  };
  const credentials = { PreSharedKey: ' native key ' };
  const settings = { Host: 'vpn.test', PreSharedKey: ' native key ' };
  assert.deepEqual(
    (await prepareFortinetIPsecWrite(request, prompt, credentials)).settings,
    settings,
  );
  const edit = { ...request, id: 'saved' };
  assert.deepEqual(await prepareFortinetIPsecWrite(edit, prompt), edit);
  assert.deepEqual((await prepareFortinetIPsecWrite(edit, prompt, credentials)).settings, settings);
  await assert.rejects(prepareFortinetIPsecWrite(request, prompt), /gateway PSK in the editor/);
  await assert.rejects(
    prepareFortinetIPsecWrite(
      { ...edit, settings: { ...edit.settings, ReplacePreSharedKey: true } },
      prompt,
    ),
    /gateway PSK in the editor/,
  );
  await assert.rejects(
    prepareFortinetIPsecWrite(
      { ...edit, settings: { ...edit.settings, UserAuth: 2 } },
      prompt,
      credentials,
    ),
    /user password in the editor/,
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
  const key = '-----BEGIN PRIVATE KEY-----\nnative-only-key\n-----END PRIVATE KEY-----';
  f.send({ value: key });
  assert.equal(await f.promise, key);
  assert.equal(f.state.destroyed, true);
  assert.equal(f.state.forgotten, 1);
  assert.equal(f.ipc.listenerCount(fortinetIPsecSecretChannel), 0);
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

test('VPN writes use the editor credentials and refuse a save after authorization is lost', async () => {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const writes = new Map<string, (...args: unknown[]) => Promise<unknown>>();
  const handlers = ['create', 'update'].map((action) => {
    const start = main.indexOf("ipcMain.handle('tunnel:" + action + "'");
    return main.slice(start, main.indexOf('\n  });', start) + '\n  });'.length);
  });
  const nativeSave = main.slice(
    main.indexOf('async function saveTunnelWithNativeSecret('),
    main.indexOf('function registerIpcHandlers('),
  );
  const id = '11111111-2222-3333-4444-555555555555';
  const saves: { operation: string; request: TunnelWriteRequest }[] = [];
  const authSession = { authorizationEpoch: 7 };
  let resumeCertificates!: () => void;
  let failSave = false;
  runInNewContext(stripTypeScriptTypes(nativeSave + handlers.join('\n')), {
    authSession,
    tunnelBrowserAuthQueue: new Promise<void>((resolve) => {
      resumeCertificates = resolve;
    }),
    __dirname: '/electron',
    path,
    BrowserWindow: { getFocusedWindow: () => undefined, getAllWindows: () => [] },
    mcpApprovalWindowCoordinator: {},
    ipcMain: { handle: writes.set.bind(writes) },
    parseTunnelWriteRequest,
    parseTunnelDetailsResponse,
    parseFortinetIPsecCredentials,
    prepareFortinetIPsecWrite,
    serializeAuthOperation: (operation: () => Promise<unknown>) => operation(),
    requireWorkspaceAuth: async () => {},
    isAuthorizationEpochCurrent: (epoch: number) => authSession.authorizationEpoch === epoch,
    requireAuthorizationEpoch: (epoch: number) => {
      if (authSession.authorizationEpoch !== epoch) throw new Error('Authentication expired');
    },
    promptFortinetIPsecSecret: async (options: { kind: string; isAuthorized: () => boolean }) => {
      assert.ok(options.isAuthorized());
      assert.ok(['ClientCert', 'ClientKey', 'CaCert'].includes(options.kind));
      if (options.kind !== 'CaCert') return '-----BEGIN FIXTURE-----';
      authSession.authorizationEpoch++;
      return '';
    },
    runBackend: async (operation: string, request: TunnelWriteRequest) => {
      saves.push({ operation, request: structuredClone(request) });
      if (failSave) throw new Error('VPN save failed');
      return { id, name: request.name, kind: request.kind, settings: { HasPreSharedKey: true } };
    },
  });

  class Input {
    value: string;
    constructor(value: string) {
      this.value = value;
    }
  }
  const psk = new Input(' key ');
  const password = new Input('user-password');
  class Form {
    querySelector(selector: string) {
      return new Map([
        ['#tunnel-ipsec-PreSharedKey', psk],
        ['#tunnel-ipsec-Password', password],
      ]).get(selector);
    }
  }
  const preload = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
  let api!: NonNullable<Window['wormhole']>;
  const ipcRenderer = {
    invoke(channel: string, ...args: unknown[]) {
      const handler = writes.get(channel);
      assert.ok(handler, 'Missing IPC handler: ' + channel);
      return handler({}, ...structuredClone(args));
    },
  };
  runInNewContext(stripTypeScriptTypes(preload).replace(/^import .* from 'electron';/, ''), {
    HTMLInputElement: Input,
    HTMLFormElement: Form,
    document: {
      getElementById: (name: string) => (name === 'tunnel-editor-form' ? new Form() : null),
    },
    process: { isMainFrame: true },
    ipcRenderer,
    contextBridge: {
      exposeInMainWorld: (name: string, bridge: typeof api) => {
        if (name === 'wormhole') api = bridge;
      },
    },
  });
  const request = { kind: 9, name: 'VPN', settings: { UserAuth: 2 } };
  const created = await api.createTunnel(request);
  assert.deepEqual(created.settings, { HasPreSharedKey: true });
  assert.deepEqual(saves.at(-1), {
    operation: 'tunnel-create',
    request: {
      ...request,
      settings: { UserAuth: 2, PreSharedKey: ' key ', Password: 'user-password' },
    },
  });

  psk.value = '';
  const edit = { ...request, id, settings: { ...request.settings, HasPreSharedKey: true } };
  await api.updateTunnel(edit);
  assert.deepEqual(saves.at(-1), {
    operation: 'tunnel-update',
    request: { ...edit, settings: { ...edit.settings, Password: 'user-password' } },
  });
  password.value = 'x'.repeat(4097);
  await assert.rejects(async () => api.updateTunnel(edit), /credential is too long/);
  assert.equal(saves.length, 2);

  failSave = true;
  password.value = 'ignored-by-ssl';
  await assert.rejects(api.createTunnel({ ...request, kind: 2 }), /VPN save failed/);
  assert.deepEqual(saves.at(-1)?.request.settings, request.settings);

  const queued = api.createTunnel({ ...request, settings: { AuthMethod: 1 } });
  await new Promise((resolve) => setImmediate(resolve));
  resumeCertificates();
  await assert.rejects(queued, /Authentication expired/);
  assert.equal(saves.length, 3);
});

test('real sandboxed Chromium fits PEM controls and exposes no application bridge', async () => {
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
      ) +
        "\nipcRenderer.on('wormhole-test-submit', () => document.querySelector('form').requestSubmit());\n",
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
  for (const kind of ['ClientKey', 'CaCert']) {
  const pem = kind === 'ClientKey' ? ['-----BEGIN FIXTURE-----', 'pem-body', '-----END FIXTURE-----'].join('\\n') : '';
  const result = await promptFortinetIPsecSecret({
    kind,
    createWindow(options) {
      const window = new BrowserWindow(options);
      window.webContents.once('did-finish-load', () => window.webContents.executeJavaScript(\`
        if (window.wormhole !== undefined || window.require !== undefined) throw Error('privileged bridge exposed');
        if (document.querySelector('footer').getBoundingClientRect().bottom > window.innerHeight) throw Error('credential buttons are clipped');
        document.querySelector('#secret').value = \${JSON.stringify(pem)};
      \`).then(() => {
        // Receive the assertion result before submission destroys the frame.
        window.webContents.send('wormhole-test-submit');
      }).catch(error => { console.error(error.message); app.exit(1); }));
      return window;
    },
    ipc: ipcMain, preload: ${JSON.stringify(join(directory, 'preload.cjs'))},
    isAuthorized: () => true, present() {}, forget() {},
  });
  assert.equal(result, pem);
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

test('IPsec save forwards only active credentials and keeps the native certificate prompts', async () => {
  const request = { name: 'IPsec', kind: 9, settings: { AuthMethod: 0, UserAuth: 2 } };
  const credentials = { PreSharedKey: 'gateway-key', Password: 'user-password' };
  const certificate = await prepareFortinetIPsecWrite(
    { ...request, settings: { AuthMethod: 1, UserAuth: 0 } },
    async (kind) => (kind === 'CaCert' ? '' : `-----BEGIN ${kind}-----`),
    credentials,
  );
  assert.deepEqual(certificate.settings, {
    AuthMethod: 1,
    UserAuth: 0,
    ClientCert: '-----BEGIN ClientCert-----',
    ClientKey: '-----BEGIN ClientKey-----',
    CaCert: '',
  });
  for (const pem of ['invalid PEM', '-----BEGIN ' + 'a'.repeat(131072)])
    await assert.rejects(
      prepareFortinetIPsecWrite(
        { ...request, settings: { AuthMethod: 1, UserAuth: 0 } },
        async () => pem,
      ),
      /credential is invalid/,
    );
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
});
