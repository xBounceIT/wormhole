import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { VaultTunnelBrowserDialog } from '../electron/vault-tunnel-browser-dialog.ts';
import { tunnelBrowserContext as context } from './fixtures/vault-tunnel-browser.ts';
import { parseVaultTunnelBrowserEnvelope } from '../electron/vault-tunnel-browser.ts';
const tick = () => new Promise(setImmediate);
let nextID = 1;
class Window extends EventEmitter {
  destroyed = false;
  shown = false;
  protected = false;
  protectionWorks = true;
  loadError = false;
  destroyFails = false;
  cleanupFails = '';
  loads: string[] = [];
  clears: string[] = [];
  webContents: any = new EventEmitter();
  request: any;
  permission: any;
  permissionCheck: any;
  popup: any;
  constructor() {
    super();
    this.webContents.id = nextID++;
    this.webContents.session = new EventEmitter();
    this.webContents.setWindowOpenHandler = (fn: any) => (this.popup = fn);
    const clear = (name: string) => async () => {
      this.clears.push(name);
      if (this.cleanupFails === name) throw Error('private cleanup failure');
    };
    Object.assign(this.webContents.session, {
      setPermissionRequestHandler: (fn: any) => (this.permission = fn),
      setPermissionCheckHandler: (fn: any) => (this.permissionCheck = fn),
      webRequest: { onBeforeRequest: (fn: any) => (this.request = fn) },
      closeAllConnections: clear('connections'),
      clearStorageData: clear('storage'),
      clearCache: clear('cache'),
      clearAuthCache: clear('auth'),
    });
  }
  isDestroyed() {
    return this.destroyed;
  }
  setMenu() {}
  setContentProtection(v: boolean) {
    this.protected = v;
  }
  isContentProtected() {
    return this.protected && this.protectionWorks;
  }
  destroy() {
    if (this.destroyFails) throw Error('private destroy failure');
    if (!this.destroyed) {
      this.destroyed = true;
      this.emit('closed');
    }
  }
  show() {
    this.shown = true;
  }
  async loadURL(url: string) {
    this.loads.push(url);
    if (this.loadError) {
      this.webContents.emit('did-fail-load', {}, -105, 'private', url, true);
      throw Error('private URL failure');
    }
  }
}
function fixture(mode = '', storage?: any) {
  const parent = new Window(),
    children: Window[] = [],
    options: any[] = [];
  let allowed = true;
  const dialog = new VaultTunnelBrowserDialog({
    createWindow: (o) => {
      const child = new Window();
      if (mode === 'load') child.loadError = true;
      if (mode === 'protect') child.protectionWorks = false;
      if (mode === 'pending-load') child.loadURL = () => new Promise(() => {});
      children.push(child);
      options.push(o);
      return child as any;
    },
    platform: mode === 'linux' ? 'linux' : 'win32',
    storage,
    ...(mode === 'present' ? { present: (w: any) => w.show(), forget: () => {} } : {}),
  });
  const open = (c = context(), signal = new AbortController()) => {
    const promise = dialog.open(parent as any, () => allowed, c, signal.signal);
    void promise.catch(() => {});
    return { c, signal, promise };
  };
  const request = (
    url: string,
    resourceType = 'mainFrame',
    webContentsId = children.at(-1)!.webContents.id,
  ) => {
    let result: any;
    children.at(-1)!.request({ url, resourceType, webContentsId }, (v: any) => (result = v));
    return result;
  };
  return { dialog, parent, children, options, open, request, deny: () => (allowed = false) };
}
test('SAML browser has no app bridge, intercepts callback before HTTP and confirms complete cleanup', async () => {
  const f = fixture('present'),
    a = f.open();
  await tick();
  const child = f.children[0],
    prefs = f.options[0].webPreferences;
  assert.equal(child.shown, true);
  assert.equal(child.protected, true);
  assert.equal(prefs.preload, undefined);
  assert.deepEqual(
    { ...prefs, partition: '' },
    {
      partition: '',
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      webSecurity: true,
      devTools: false,
      spellcheck: false,
    },
  );
  assert.match(prefs.partition, /^vault-tunnel-browser-/);
  assert.deepEqual(f.request('https://idp.test/login'), { cancel: false });
  assert.deepEqual(f.request('wss://idp.test/socket', 'webSocket'), { cancel: false });
  assert.deepEqual(f.request('data:image/png;base64,AA', 'image'), { cancel: false });
  for (const url of [
    'http://idp.test/',
    'file:///secret',
    'https://u:p@idp.test/',
    'https://vpn.test:1002/',
    'https://vpn.test.:1001/',
    'wss://vpn.test:1002/',
    '%',
  ])
    assert.deepEqual(f.request(url), { cancel: true });
  let granted = true;
  child.permission(null, 'camera', (v: boolean) => (granted = v));
  assert.equal(granted, false);
  assert.equal(child.permissionCheck(), false);
  let prevented = 0;
  const event = { preventDefault: () => prevented++ };
  child.webContents.session.emit('will-download', event);
  child.webContents.emit('context-menu', event);
  child.webContents.emit('before-input-event', event, { key: 'F12' });
  child.webContents.emit('before-input-event', event, { key: 'p', control: true });
  child.webContents.emit('before-input-event', event, { key: 'a' });
  assert.equal(prevented, 4);
  const callback = a.c.callbackURL + '?tokenid=' + 'ab'.repeat(16);
  assert.deepEqual(f.request(callback, 'subFrame'), { cancel: true });
  assert.deepEqual(f.request(callback, 'mainFrame', -1), { cancel: true });
  assert.equal(child.destroyed, false);
  assert.deepEqual(f.request(callback), { cancel: true });
  assert.deepEqual(f.request(callback), { cancel: true });
  const sealed = await a.promise;
  assert.ok(parseVaultTunnelBrowserEnvelope(sealed));
  assert.equal(child.destroyed, true);
  assert.deepEqual(child.clears, ['connections', 'storage', 'cache', 'auth']);
  await f.dialog.cancelChallenge(a.c);
  assert.equal(f.parent.listenerCount('closed'), 0);
  assert.equal(f.parent.webContents.listenerCount('did-start-navigation'), 0);
});
test('IPsec custody completes before its fresh callback token leaves the owning browser', async () => {
  let finishRestore!: () => void,
    finishCapture!: () => void,
    offline = true;
  const calls: string[] = [];
  const f = fixture('', () => ({
      get isOffline() {
        return offline;
      },
      permitsRequest: () => !offline,
      restore: () =>
        new Promise<void>((resolve) => {
          finishRestore = () => {
            offline = false;
            resolve();
          };
        }),
      capture: () => {
        calls.push('capture');
        offline = true;
        return new Promise<void>((resolve) => {
          finishCapture = resolve;
        });
      },
      close: async () => {
        calls.push('close');
      },
    })),
    a = f.open();
  f.children[0].emit('ready-to-show');
  assert.equal(f.children[0].shown, false);
  assert.equal(f.request('https://idp.test/').cancel, true);
  finishRestore();
  await tick();
  assert.equal(f.children[0].shown, true);
  assert.deepEqual(f.request(a.c.callbackURL + '?tokenid=' + 'ab'.repeat(16)), { cancel: true });
  while (!finishCapture) await tick();
  assert.equal(f.children[0].destroyed, false);
  finishCapture();
  assert.ok(parseVaultTunnelBrowserEnvelope(await a.promise));
  assert.equal(f.children[0].destroyed, true);
  assert.ok(calls.includes('close'));
});
test('SAML navigation, popups and TLS exceptions stay scoped to the original gateway and document', async () => {
  for (const mode of ['redirect', 'navigate', 'popup']) {
    const f = fixture(),
      a = f.open();
    await tick();
    const child = f.children[0];
    let allowed: any,
      prevented = 0;
    for (const [url, expected] of [
      ['https://vpn.test:1001/saml', true],
      ['https://vpn.test:1002/saml', false],
      ['https://idp.test/', false],
      ['%', false],
    ] as const) {
      child.webContents.emit(
        'certificate-error',
        { preventDefault: () => {} },
        url,
        'private',
        {},
        (v: any) => (allowed = v),
      );
      assert.equal(allowed, expected);
    }
    assert.deepEqual(child.popup({ url: 'https://idp.test/login' }), { action: 'deny' });
    assert.equal(child.loads.at(-1), 'https://idp.test/login');
    assert.deepEqual(child.popup({ url: 'file:///secret' }), { action: 'deny' });
    assert.deepEqual(child.popup({ url: '%' }), { action: 'deny' });
    const raw = a.c.callbackURL + '?tokenid=' + 'cd'.repeat(16);
    if (mode === 'popup') assert.deepEqual(child.popup({ url: raw }), { action: 'deny' });
    else
      child.webContents.emit(mode === 'redirect' ? 'will-redirect' : 'will-navigate', {
        isMainFrame: true,
        url: raw,
        preventDefault: () => prevented++,
      });
    assert.ok(parseVaultTunnelBrowserEnvelope(await a.promise));
    if (mode !== 'popup') assert.equal(prevented, 1);
  }
  const f = fixture(),
    a = f.open({ ...context(), ignoreCertificateErrors: false });
  await tick();
  let allowed = true;
  f.children[0].webContents.emit(
    'certificate-error',
    { preventDefault: () => {} },
    a.c.startURL,
    '',
    {},
    (v: boolean) => (allowed = v),
  );
  assert.equal(allowed, false);
  await f.dialog.cancelChallenge(a.c);
  await assert.rejects(a.promise);
});
test('SAML lifetime cancels on owner loss, malformed callback, navigation, abort and native failures', async (t) => {
  for (const mode of [
    'abort',
    'parent',
    'parent-nav',
    'parent-crash',
    'child',
    'child-crash',
    'load',
    'protect',
    'linux',
    'stale',
    'bad-token',
    'bad-path',
    'bad-nav',
    'bad-frame-nav',
    'failed-load',
    'timeout',
  ]) {
    const f = fixture(mode),
      a = f.open();
    await tick();
    const child = f.children[0];
    if (mode === 'abort') a.signal.abort();
    if (mode === 'parent') f.parent.destroy();
    if (mode === 'parent-crash') f.parent.webContents.emit('render-process-gone');
    if (mode === 'parent-nav') {
      f.parent.webContents.emit('did-start-navigation', {}, '', false, false);
      assert.equal(child.destroyed, false);
      f.parent.webContents.emit('did-start-navigation', {}, '', false, true);
    }
    if (mode === 'child') child.destroy();
    if (mode === 'child-crash') child.webContents.emit('render-process-gone');
    if (mode === 'linux') {
      assert.equal(child.protected, false);
      await f.dialog.cancelChallenge(a.c);
    }
    if (mode === 'stale') {
      f.deny();
      f.request(a.c.callbackURL + '?tokenid=' + 'ab'.repeat(16));
    }
    if (mode === 'bad-token') f.request(a.c.callbackURL + '?tokenid=bad');
    if (mode === 'bad-path') f.request(a.c.callbackURL + 'other?tokenid=' + 'ab'.repeat(16));
    if (mode === 'bad-nav' || mode === 'bad-frame-nav')
      child.webContents.emit(mode === 'bad-nav' ? 'will-navigate' : 'will-frame-navigate', {
        isMainFrame: true,
        url: 'file:///private',
        preventDefault: () => {},
      });
    if (mode === 'failed-load') {
      child.webContents.emit('did-fail-load', {}, -3, 'private', 'https://idp.test', true);
      assert.equal(child.destroyed, false);
      child.webContents.emit('did-fail-load', {}, -200, 'private', 'https://idp.test', true);
    }
    if (mode === 'timeout') {
      await f.dialog.cancelChallenge(a.c);
      await assert.rejects(a.promise);
      t.mock.timers.enable({ apis: ['setTimeout'] });
      const next = f.open();
      t.mock.timers.tick(300000);
      await assert.rejects(next.promise);
      t.mock.timers.reset();
      continue;
    }
    await assert.rejects(a.promise, /unavailable/);
    assert.equal(child.destroyed, true, mode);
  }
});
test('unconfirmed SAML destruction or storage cleanup blocks all admission until explicit matching retry', async () => {
  for (const mode of ['destroy', 'connections', 'storage', 'cache', 'auth']) {
    const f = fixture(),
      a = f.open();
    await tick();
    const child = f.children[0];
    if (mode === 'destroy') child.destroyFails = true;
    else child.cleanupFails = mode;
    await assert.rejects(f.dialog.cancelChallenge(a.c));
    await assert.rejects(a.promise);
    await assert.rejects(f.open().promise);
    child.destroyFails = false;
    child.cleanupFails = '';
    await f.dialog.cancelChallenge(a.c);
    const b = f.open();
    await tick();
    await f.dialog.cancelChallenge(b.c);
    await assert.rejects(b.promise);
  }
});
test('SAML partitions are independent even for repeated native challenge IDs and bounded admission', async () => {
  const f = fixture(),
    a = f.open(),
    b = f.open({ ...context(), challengeId: a.c.challengeId });
  await tick();
  assert.notEqual(f.options[0].webPreferences.partition, f.options[1].webPreferences.partition);
  await assert.rejects(f.open(a.c).promise);
  await f.dialog.cancelChallenge({ ...context(), challengeId: a.c.challengeId });
  assert.equal(f.children[0].destroyed, false);
  await assert.rejects(f.dialog.cancelChallenge({} as any));
  const pending = Array.from({ length: 30 }, () => f.open());
  await assert.rejects(f.open().promise);
  await Promise.all([a, b, ...pending].map((v) => f.dialog.cancelChallenge(v.c)));
  await Promise.all([a, b, ...pending].map((v) => assert.rejects(v.promise)));
  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(f.open(context(), aborted).promise);
  f.parent.destroy();
  await assert.rejects(f.open().promise);
});

test('owner retirement during native storage cleanup cannot return a late SAML envelope', async () => {
  const f = fixture(),
    a = f.open();
  await tick();
  let release!: () => void, entered!: () => void;
  const begun = new Promise<void>((r) => (entered = r)),
    wait = new Promise<void>((r) => (release = r));
  f.children[0].webContents.session.clearStorageData = async () => {
    entered();
    await wait;
  };
  f.request(a.c.callbackURL + '?tokenid=' + 'ab'.repeat(16));
  await begun;
  f.deny();
  release();
  await assert.rejects(a.promise);
  assert.equal(f.children[0].destroyed, true);
});

test('SAML login appears before a pending page load finishes and never appears after cancellation', async () => {
  const f = fixture('pending-load'),
    a = f.open();
  await tick();
  assert.equal(f.children[0].shown, false);
  f.children[0].emit('ready-to-show');
  assert.equal(f.children[0].shown, true);
  await f.dialog.cancelChallenge(a.c);
  await assert.rejects(a.promise);
  const next = f.open();
  await tick();
  await f.dialog.cancelChallenge(next.c);
  await assert.rejects(next.promise);
  f.children[1].emit('ready-to-show');
  assert.equal(f.children[1].shown, false);
});
