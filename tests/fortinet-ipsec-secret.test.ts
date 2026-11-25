import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire, stripTypeScriptTypes } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { setImmediate } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { runInNewContext } from 'node:vm';
import * as path from 'node:path';
import test from 'node:test';
import { AuthSession } from '../electron/auth-session.ts';
import {
  FortinetIPsecCredentialDrafts,
  FortinetIPsecEntryCancelled,
  isFortinetIPsecEditableSecret,
  prepareFortinetIPsecWrite,
  promptFortinetIPsecSecret,
} from '../electron/fortinet-ipsec-secret.ts';
import {
  isTunnelIdentifier,
  parseTunnelDetailsResponse,
  parseTunnelWriteRequest,
  type TunnelWriteRequest,
} from '../electron/tunnel-test-contract.ts';

const fortinetIPsecSecretChannel = 'fortinet-ipsec:secret-response';

function fixture(
  options: {
    kind?: Parameters<typeof promptFortinetIPsecSecret>[0]['kind'];
    loadFailure?: boolean;
    setupFailure?: boolean;
  } = {},
) {
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
    kind: options.kind ?? 'ClientKey',
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

test('the isolated password window preserves valid Unicode and rejects invalid native responses', async () => {
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
  ]) {
    const f = fixture({ kind: 'Password' });
    const rejected = assert.rejects(f.promise, /credential is invalid/);
    f.send({ value });
    await rejected;
  }
  for (const value of [
    ' key with spaces ',
    'key\u2028with\u2029separators',
    '\uFEFF',
    '🔒',
    'x'.repeat(4096),
    'é'.repeat(2048),
  ]) {
    const f = fixture({ kind: 'PreSharedKey' });
    f.send({ value });
    assert.equal(await f.promise, value);
  }
});

test('credential drafts are bound to one workspace, editor and authorization epoch', async () => {
  const discarded: string[] = [];
  const drafts = new FortinetIPsecCredentialDrafts((id) => discarded.push(id));
  const owner = {} as Electron.WebContents;
  const other = {} as Electron.WebContents;
  const id = 'draft-id';
  let reference = '';
  assert.equal(
    await drafts.enter(owner, id, 1, 'PreSharedKey', async (value) => {
      reference = value;
    }),
    true,
  );
  assert.equal(
    await drafts.enter(owner, id, 1, 'PreSharedKey', async () => {
      throw new FortinetIPsecEntryCancelled();
    }),
    false,
  );
  assert.deepEqual(drafts.read(owner, id, 1), { PreSharedKey: reference });
  assert.throws(() => drafts.read(other, id, 1), /draft expired/);
  assert.throws(() => drafts.read(owner, 'other-editor', 1), /draft expired/);
  assert.throws(() => drafts.read(owner, id, 2), /draft expired/);

  let resolveEntry!: () => void;
  let canFinish!: () => boolean;
  let pendingReference = '';
  const pending = drafts.enter(owner, id, 1, 'Password', (value, isCurrent) => {
    pendingReference = value;
    canFinish = isCurrent;
    return new Promise((resolve) => {
      resolveEntry = resolve;
    });
  });
  assert.equal(canFinish(), true);
  await assert.rejects(
    drafts.enter(owner, id, 1, 'Password', async () => {}),
    /already open/,
  );
  assert.throws(() => drafts.read(owner, id, 1), /before saving/);
  drafts.discard(owner, 'other-editor');
  assert.equal(canFinish(), true);
  drafts.clear();
  assert.equal(canFinish(), false);
  resolveEntry();
  assert.equal(await pending, false);
  assert.ok(discarded.includes(pendingReference));
  assert.throws(() => drafts.read(owner, id, 1), /draft expired/);
});

test('a draft reference satisfies the credential requirement without going into the settings', async () => {
  const request = { name: 'VPN', kind: 9, settings: { Host: 'vpn.test', HasPreSharedKey: true } };
  const prompt = async () => {
    throw new Error('unexpected prompt');
  };
  const credentials = { PreSharedKey: 'draft-ref' };
  const settings = { Host: 'vpn.test' };
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

test('the workspace bridge collects draft status and saves without prompting for PSK or password', async () => {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const handlers = new Map<string, (...args: unknown[]) => unknown>();
  const registrations = [
    'create',
    'update',
    'enter-ipsec-credential',
    'discard-ipsec-credentials',
  ].map((action) => {
    const start = main.indexOf("ipcMain.handle('tunnel:" + action + "'");
    return main.slice(start, main.indexOf('\n  });', start) + '\n  });'.length);
  });
  const nativeSave = main.slice(
    main.indexOf('function queueFortinetIPsecSecret('),
    main.indexOf('function registerIpcHandlers('),
  );
  const nativeBackend = main.slice(
    main.indexOf('class NativeBackendProcess'),
    main.indexOf('let nativeBackend:'),
  );
  const authorization = main.slice(
    main.indexOf('function serializeAuthOperation<'),
    main.indexOf('function serializeAuthStateMutation<'),
  );
  const id = '11111111-2222-3333-4444-555555555555';
  const draftId = '11111111-2222-3333-4444-555555555556';
  const saves: {
    action: string;
    ipsecWrite: TunnelWriteRequest;
    ipsecReferences: Record<string, string>;
  }[] = [];
  const staged: { reference: string; field: string; secret: string }[] = [];
  const authSession = new AuthSession();
  authSession.remember({ configured: true }, true);
  const sender = Object.assign(new EventEmitter(), { mainFrame: {} });
  const event = { sender, senderFrame: sender.mainFrame };
  const owner = { isDestroyed: () => false };
  const opened: string[] = [];
  let failSave = false;
  let replyToSave: (() => void) | undefined;
  let delaySave = false;
  const timers = new Set<() => void>();
  const stdout = Object.assign(new EventEmitter(), { setEncoding: () => {} });
  const child = Object.assign(new EventEmitter(), {
    stdout,
    stdin: Object.assign(new EventEmitter(), {
      write(payload: string) {
        const { id: commandId, ...message } = JSON.parse(payload);
        const reply = (response: object) =>
          stdout.emit('data', `${JSON.stringify({ id: commandId, ...response })}\n`);
        if (message.action === 'tunnel.ipsec-stage') {
          staged.push({
            reference: message.sessionId,
            field: message.ipsecField,
            secret: Buffer.from(message.ipsecSecret, 'base64').toString('utf8'),
          });
          reply({ ok: true });
          return;
        }
        saves.push(message);
        const respond = () =>
          reply(
            failSave
              ? { ok: false, error: 'VPN save failed' }
              : {
                  ok: true,
                  result: {
                    id,
                    name: message.ipsecWrite.name,
                    kind: 9,
                    settings: { HasPreSharedKey: true },
                  },
                },
          );
        if (delaySave) replyToSave = respond;
        else respond();
      },
    }),
  });

  const script = stripTypeScriptTypes(`
    let authOperationQueue = Promise.resolve();
    ${authorization}
    ${nativeBackend}
    const service = new NativeBackendProcess();
    const getNativeBackend = () => service;
    ${nativeSave}
    ${registrations.join('\n')}
    serializeAuthOperation;
  `);
  const runWhileSaving = runInNewContext(
    script,
    {
      authSession,
      authLockRequested: false,
      fortinetIPsecDrafts: new FortinetIPsecCredentialDrafts(() => {}),
      FortinetIPsecEntryCancelled,
      tunnelBrowserAuthQueue: Promise.resolve(),
      __dirname: '/electron',
      path,
      BrowserWindow: {
        fromWebContents: (contents: unknown) => (contents === sender ? owner : undefined),
      },
      windowCloseCoordinators: new Map([[owner, {}]]),
      mcpApprovalWindowCoordinator: {},
      AbortController,
      Buffer,
      backendTimeoutMs: 30_000,
      nativeBackendCommandTimeoutMs: 30_000,
      nativeBackendLineLimit: 64 * 1024,
      setTimeout: (expire: () => void) => {
        timers.add(expire);
        return expire;
      },
      clearTimeout: (expire: () => void) => timers.delete(expire),
      TunnelFailureRegistry: class {
        failAll() {}
      },
      TunnelBrowserPromptTracker: class {
        clear() {}
      },
      backendPath: () => 'backend',
      observeBackendProcess: () => {},
      recordDiagnostic: () => {},
      reportWarning: () => {},
      wormholeDatabasePath: () => 'database',
      electronUserDataPath: () => 'profile',
      spawn: () => {
        queueMicrotask(() => child.emit('spawn'));
        return child;
      },
      ipcMain: { handle: handlers.set.bind(handlers) },
      isTunnelIdentifier,
      isFortinetIPsecEditableSecret,
      parseTunnelWriteRequest,
      parseTunnelDetailsResponse,
      prepareFortinetIPsecWrite,
      requireWorkspaceAuth: async () => authSession.requireUnlocked(),
      isAuthorizationEpochCurrent: (epoch: number) => authSession.authorizationEpoch === epoch,
      requireAuthorizationEpoch: (epoch: number) => {
        if (authSession.authorizationEpoch !== epoch) throw new Error('Authentication expired');
      },
      promptFortinetIPsecSecret: async (options: { kind: string; isAuthorized: () => boolean }) => {
        assert.ok(options.isAuthorized());
        opened.push(options.kind);
        if (options.kind === 'PreSharedKey') return ' gateway-key ';
        if (options.kind === 'Password') return 'vpn-password';
        if (options.kind !== 'CaCert') return '-----BEGIN FIXTURE-----';
        authSession.lock();
        authSession.markUnlocked();
        return '';
      },
      runBackend: async () => {
        throw new Error('Unexpected save without Go draft references');
      },
    },
    { filename: 'wormhole-ipsec-save.js' },
  );

  const preload = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
  let api!: NonNullable<Window['wormhole']>;
  runInNewContext(stripTypeScriptTypes(preload).replace(/^import .* from 'electron';/, ''), {
    process: { isMainFrame: true },
    ipcRenderer: {
      invoke: async (channel: string, ...args: unknown[]) => {
        const handler = handlers.get(channel);
        assert.ok(handler, 'Missing IPC handler: ' + channel);
        return structuredClone(await handler(event, ...structuredClone(args)));
      },
    },
    contextBridge: {
      exposeInMainWorld: (name: string, bridge: typeof api) => {
        if (name === 'wormhole') api = bridge;
      },
    },
  });

  const request = { kind: 9, name: 'VPN', settings: { UserAuth: 2 } };
  await assert.rejects(api.createTunnel(request), /gateway PSK in the editor/);
  const enter = handlers.get('tunnel:enter-ipsec-credential')!;
  await assert.rejects(
    enter({ ...event, senderFrame: {} }, draftId, 'Password'),
    /editor is unavailable/,
  );
  await assert.rejects(enter(event, draftId, 'ClientKey'), /credential request is invalid/);
  assert.deepEqual(opened, []);

  assert.equal(await api.enterFortinetIPsecCredential(draftId, 'PreSharedKey'), true);
  assert.equal(await api.enterFortinetIPsecCredential(draftId, 'Password'), true);
  assert.deepEqual(
    staged.map(({ field, secret }) => [field, secret]),
    [
      ['PreSharedKey', ' gateway-key '],
      ['Password', 'vpn-password'],
    ],
  );
  failSave = true;
  await assert.rejects(api.createTunnel(request, draftId), /VPN save failed/);
  failSave = false;
  delaySave = true;
  const inFlight = api.createTunnel(request, draftId);
  let settled = false;
  void inFlight.then(
    () => {
      settled = true;
    },
    () => {
      settled = true;
    },
  );
  await setImmediate();
  assert.ok(replyToSave);
  for (const expire of timers) expire();
  await setImmediate();
  assert.equal(settled, false, 'a slow save must still await the service result');
  let authorizationQueueAvailable = false;
  void runWhileSaving(() => {
    authorizationQueueAvailable = true;
  });
  await setImmediate();
  assert.equal(authorizationQueueAvailable, true);
  authSession.lock();
  replyToSave();
  await setImmediate();
  assert.equal(settled, false, 'a committed save must not return workspace data while locked');
  authSession.markUnlocked();
  authSession.lock();
  await setImmediate();
  assert.equal(settled, false, 'relocking before delivery must keep the result pending');
  authSession.markUnlocked();
  const created = await inFlight;
  delaySave = false;
  assert.equal(sender.listenerCount('did-start-loading'), 0);
  assert.equal(sender.listenerCount('destroyed'), 0);
  assert.deepEqual(created.settings, { HasPreSharedKey: true });
  assert.deepEqual(saves.at(-1), {
    action: 'tunnel.ipsec-create',
    ipsecWrite: request,
    ipsecReferences: {
      PreSharedKey: staged[0].reference,
      Password: staged[1].reference,
    },
  });
  await assert.rejects(api.createTunnel(request, draftId), /draft expired/);
  await assert.rejects(
    handlers.get('tunnel:create')!(event, request, { PreSharedKey: 'injected' }),
    /draft is invalid/,
  );

  const edit = { ...request, id, settings: { UserAuth: 2, HasPreSharedKey: true } };
  assert.equal(await api.enterFortinetIPsecCredential(draftId, 'Password'), true);
  await api.updateTunnel(edit, draftId);
  assert.deepEqual(saves.at(-1), {
    action: 'tunnel.ipsec-update',
    ipsecWrite: edit,
    ipsecReferences: { Password: staged[2].reference },
  });
  assert.deepEqual(opened, ['PreSharedKey', 'Password', 'Password']);

  await api.enterFortinetIPsecCredential(draftId, 'PreSharedKey');
  await api.discardFortinetIPsecCredentials(draftId);
  await assert.rejects(api.createTunnel(request, draftId), /draft expired/);
  await assert.rejects(api.createTunnel({ ...request, kind: 2 }, draftId), /draft is invalid/);

  await assert.rejects(
    api.createTunnel({ ...request, settings: { AuthMethod: 1 } }),
    /Authentication expired/,
  );
  assert.equal(saves.length, 3);

  await api.enterFortinetIPsecCredential(draftId, 'PreSharedKey');
  await api.enterFortinetIPsecCredential(draftId, 'Password');
  delaySave = true;
  replyToSave = undefined;
  const navigatedSave = api.createTunnel(request, draftId);
  const navigated = assert.rejects(navigatedSave, /editor is unavailable/);
  await setImmediate();
  assert.ok(replyToSave);
  authSession.lock();
  replyToSave();
  await setImmediate();
  sender.emit('did-start-loading');
  await navigated;
  assert.equal(sender.listenerCount('destroyed'), 0);
  authSession.markUnlocked();

  await api.enterFortinetIPsecCredential(draftId, 'PreSharedKey');
  await api.enterFortinetIPsecCredential(draftId, 'Password');
  replyToSave = undefined;
  const disconnectedSave = api.createTunnel(request, draftId);
  const stopped = assert.rejects(disconnectedSave, /Wormhole service stopped/);
  await setImmediate();
  assert.ok(replyToSave);
  child.emit('close', null);
  await stopped;
});

test('real Chromium credential prompts are separate from the workspace and expose no bridge', async () => {
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
  const workspace = new BrowserWindow({ show: false });
  await workspace.loadURL('data:text/html,<h1>VPN editor</h1>');
  for (const [kind, secret] of [
    ['PreSharedKey', ' gateway key '],
    ['Password', 'vpn password'],
    ['ClientKey', ['-----BEGIN FIXTURE-----', 'pem-body', '-----END FIXTURE-----'].join('\\n')],
    ['CaCert', ''],
  ]) {
  const result = await promptFortinetIPsecSecret({
    kind,
    parent: workspace,
    createWindow(options) {
      const window = new BrowserWindow(options);
      window.webContents.once('did-finish-load', () => window.webContents.executeJavaScript(\`
        if (window.wormhole !== undefined || window.require !== undefined) throw Error('privileged bridge exposed');
        if (document.querySelector('footer').getBoundingClientRect().bottom > window.innerHeight) throw Error('credential buttons are clipped');
        const field = document.querySelector('#secret');
        field.value = \${JSON.stringify(secret)};
      \`).then(() => {
        // Receive the assertion result before submission destroys the frame.
        window.webContents.send('wormhole-test-submit');
      }).catch(error => { console.error(error.message); app.exit(1); }));
      return window;
    },
    ipc: ipcMain, preload: ${JSON.stringify(join(directory, 'preload.cjs'))},
    isAuthorized: () => true, present() {}, forget() {},
  });
  assert.equal(result, secret);
  assert.deepEqual(BrowserWindow.getAllWindows(), [workspace]);
  assert.equal(await workspace.webContents.executeJavaScript("document.querySelector('#secret') === null"), true);
  }
  workspace.destroy();
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
