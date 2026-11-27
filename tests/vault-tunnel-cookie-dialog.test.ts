import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { VaultTunnelBrowserDialog } from '../electron/vault-tunnel-browser-dialog.ts';
import { tunnelCookieContext as context } from './fixtures/vault-tunnel-cookie.ts';
import { parseVaultTunnelCookieEnvelope } from '../electron/vault-tunnel-cookie.ts';
import { randomUUID } from 'node:crypto';
const tick = () => new Promise(setImmediate);

test('fallback cookie dialog passes a detached pair to storage and rejects a substituted active source before opening', async () => {
  const parent = new Window(),
    child = new Window(),
    c = context();
  const primary = { ...c.binding, kind: 9, requestId: randomUUID(), tunnelConfigId: randomUUID() };
  const pair = { primary, fallback: { ...c.binding } };
  const request = {
    workspaceId: primary.workspaceId,
    nodeId: primary.nodeId,
    sessionId: primary.sessionId,
    requestId: primary.requestId,
    epoch: primary.epoch,
    credentialOverride: '',
  };
  let source: any,
    opens = 0;
  const dialog = new VaultTunnelBrowserDialog({
    createWindow: () => {
      opens++;
      return child as any;
    },
    platform: 'win32',
    storage: (options) => {
      source = options;
      return {
        isOffline: false,
        permitsRequest: () => true,
        restore: async () => {},
        capture: async () => {},
        close: async () => {},
      };
    },
  });
  for (const bad of [null, {}, { ...pair, fallback: { ...pair.fallback, rowVersion: '99' } }])
    await assert.rejects(
      dialog.open(parent as any, () => true, c, new AbortController().signal, request, bad as any),
      /unavailable/,
    );
  assert.equal(opens, 0);
  const controller = new AbortController();
  const promise = dialog.open(parent as any, () => true, c, controller.signal, request, pair);
  const rejected = assert.rejects(promise);
  const expected = structuredClone(pair);
  pair.primary.host = 'replacement';
  assert.deepEqual(source.fallback, expected);
  assert.deepEqual(source.request, request);
  await tick();
  controller.abort();
  await rejected;
  assert.equal(opens, 1);
});
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
  headers: any;
  permission: any;
  permissionCheck: any;
  popup: any;
  constructor() {
    super();
    this.webContents.id = nextID++;
    this.webContents.session = new EventEmitter();
    this.webContents.session.cookies = new EventEmitter();
    this.webContents.setWindowOpenHandler = (fn: any) => (this.popup = fn);
    const clear = (name: string) => async () => {
      this.clears.push(name);
      if (this.cleanupFails === name) throw Error('private cleanup failure');
    };
    Object.assign(this.webContents.session, {
      setPermissionRequestHandler: (fn: any) => (this.permission = fn),
      setPermissionCheckHandler: (fn: any) => (this.permissionCheck = fn),
      webRequest: {
        onBeforeRequest: (fn: any) => (this.request = fn),
        onHeadersReceived: (fn: any) => (this.headers = fn),
      },
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
function fixture(
  storage?: any,
  challenge = context() as import('../electron/vault-tunnel-cookie.ts').VaultTunnelCookieContext,
) {
  const parent = new Window(),
    child = new Window();
  let allowed = true;
  const dialog = new VaultTunnelBrowserDialog({
    createWindow: () => child as any,
    platform: 'win32',
    storage,
  });
  const c = challenge,
    controller = new AbortController(),
    promise = dialog.open(parent as any, () => allowed, c, controller.signal);
  void promise.catch(() => {});
  const headers = (value = 'issued-cookie', extra: any = {}) => {
    let result: any;
    child.headers(
      {
        url: c.startURL,
        webContentsId: child.webContents.id,
        statusCode: 200,
        responseHeaders: {
          'Set-Cookie': ['SVPNCOOKIE=' + value + '; HttpOnly; Path=/remote/; Secure'],
        },
        ...extra,
      },
      (r: any) => (result = r),
    );
    return result;
  };
  const commit = (value = 'issued-cookie', extra: any = {}, removed = false) =>
    child.webContents.session.cookies.emit(
      'changed',
      {},
      {
        name: 'SVPNCOOKIE',
        value,
        httpOnly: true,
        domain: 'vpn.test',
        hostOnly: true,
        path: '/remote/',
        ...extra,
      },
      'explicit',
      removed,
    );
  return {
    parent,
    child,
    dialog,
    c,
    controller,
    promise,
    headers,
    commit,
    deny: () => (allowed = false),
  };
}
test('Fortinet callback seals only an owned gateway redirect and blocks the loopback request', async () => {
  const { cookieName: _, ...base } = context();
  const challenge = {
    ...base,
    completion: 'fortinet-ssl' as const,
    startURL: 'https://vpn.test/remote/saml/start?redirect=1',
  };
  const target = 'https://127.0.0.1:8020/?id=transient';
  const source = 'https://vpn.test/remote/saml/login';
  const launch = () => fixture(undefined, challenge);
  const f = launch();
  await tick();
  const details = {
    url: source,
    webContentsId: f.child.webContents.id,
    resourceType: 'mainFrame',
    statusCode: 302,
    responseHeaders: { Location: [target] },
  };
  for (const invalid of [
    { url: 'https://idp.test/remote/saml/login' },
    { url: 'https://vpn.test/other' },
    { webContentsId: -1 },
    { resourceType: 'subFrame' },
    { statusCode: 200 },
  ]) {
    assert.deepEqual(f.headers('', { ...details, ...invalid }), { cancel: false });
  }
  let decision;
  f.child.request(
    { url: target, webContentsId: f.child.webContents.id, resourceType: 'mainFrame' },
    (r: unknown) => (decision = r),
  );
  assert.deepEqual(decision, { cancel: true });
  assert.deepEqual(f.child.popup({ url: target }), { action: 'deny' });
  f.commit();
  await tick();
  assert.equal(f.child.destroyed, false);
  assert.deepEqual(f.headers('', details), { cancel: true });
  assert.ok(parseVaultTunnelCookieEnvelope(await f.promise));
  assert.deepEqual(f.child.loads, [challenge.startURL]);

  const ambiguous = launch();
  await tick();
  ambiguous.headers('', {
    ...details,
    webContentsId: ambiguous.child.webContents.id,
    responseHeaders: { Location: [target, target] },
  });
  await assert.rejects(ambiguous.promise);

  const navigated = launch();
  await tick();
  const navigate = (issuer: string, url: string) => {
    let blocked = false;
    navigated.child.webContents.emit('will-navigate', {
      url,
      initiator: { url: issuer },
      isMainFrame: true,
      preventDefault() {
        blocked = true;
      },
    });
    assert.equal(blocked, true);
  };
  navigate('https://foreign.test/', target);
  assert.equal(navigated.child.destroyed, false);
  navigate(source, target);
  assert.ok(parseVaultTunnelCookieEnvelope(await navigated.promise));
});

test('SSL browser seals only the cookie committed after a gateway-issued HttpOnly response', async () => {
  const f = fixture();
  await tick();
  assert.equal(f.child.shown, true);
  assert.equal(f.child.protected, true);
  f.commit();
  await tick();
  assert.equal(f.child.destroyed, false);
  for (const extra of [
    { url: 'https://idp.test/login' },
    { webContentsId: -1 },
    { statusCode: 401 },
  ]) {
    f.headers('issued-cookie', extra);
    f.commit();
    await tick();
    assert.equal(f.child.destroyed, false);
  }
  assert.deepEqual(f.headers(), { cancel: false });
  for (const extra of [
    { name: 'OTHER' },
    { httpOnly: false },
    { domain: 'foreign.test' },
    { domain: undefined },
    { path: '/other' },
    { path: '/remote/saml/st' },
    { value: 'foreign-cookie' },
  ]) {
    f.commit('issued-cookie', extra);
    await tick();
    assert.equal(f.child.destroyed, false);
  }
  f.commit('issued-cookie', {}, true);
  await tick();
  assert.equal(f.child.destroyed, false);
  f.commit();
  const sealed = await f.promise;
  assert.ok(parseVaultTunnelCookieEnvelope(sealed));
  assert.equal(f.child.destroyed, true);
  assert.deepEqual(f.child.clears, ['connections', 'storage', 'cache', 'auth']);
  assert.equal(f.child.webContents.session.cookies.listenerCount('changed'), 0);
  await f.dialog.cancelChallenge(f.c);
});

test('custody restore gates presentation/network and capture completes before returning a fresh bearer', async () => {
  let restore!: () => void,
    capture!: () => void,
    offline = true;
  const calls: string[] = [];
  const f = fixture(() => ({
    get isOffline() {
      return offline;
    },
    permitsRequest: () => !offline,
    restore: () =>
      new Promise<void>((resolve) => {
        restore = () => {
          offline = false;
          resolve();
        };
      }),
    capture: () => {
      calls.push('capture');
      offline = true;
      return new Promise<void>((resolve) => {
        capture = resolve;
      });
    },
    close: async () => {
      calls.push('close');
    },
  }));
  f.child.emit('ready-to-show');
  assert.equal(f.child.shown, false);
  assert.deepEqual(f.child.loads, []);
  let request: any;
  f.child.request(
    { url: 'https://idp.test/', webContentsId: f.child.webContents.id, resourceType: 'mainFrame' },
    (r: any) => {
      request = r;
    },
  );
  assert.equal(request.cancel, true);
  restore();
  await tick();
  assert.equal(f.child.shown, true);
  assert.deepEqual(f.child.loads, [f.c.startURL]);
  f.headers();
  f.commit();
  while (!capture) await tick();
  assert.equal(f.child.destroyed, false);
  assert.deepEqual(calls, ['capture']);
  capture();
  assert.ok(parseVaultTunnelCookieEnvelope(await f.promise));
  assert.equal(f.child.destroyed, true);
  assert.ok(calls.includes('close'));
});

test('late restore, failed capture and uncertain custody cleanup cannot publish or free the wrong actor', async () => {
  for (const mode of ['late', 'capture', 'cleanup']) {
    let release!: () => void,
      fails = mode === 'cleanup';
    const f = fixture(() => ({
      isOffline: true,
      permitsRequest: () => false,
      restore: () =>
        mode === 'late'
          ? new Promise<void>((r) => {
              release = r;
            })
          : Promise.resolve(),
      capture: async () => {
        if (mode === 'capture') throw Error('private fixture');
      },
      close: async () => {
        if (fails) throw Error('private cleanup');
      },
    }));
    if (mode === 'late') {
      const pending = f.dialog.cancelChallenge(f.c);
      await tick();
      assert.equal(f.child.destroyed, true);
      release();
      await pending;
      assert.deepEqual(f.child.loads, []);
    } else if (mode === 'capture') {
      await tick();
      f.headers();
      f.commit();
    } else {
      await tick();
      await assert.rejects(f.dialog.cancelChallenge(f.c));
      fails = false;
      await f.dialog.cancelChallenge(f.c);
    }
    await assert.rejects(f.promise);
    assert.equal(f.child.destroyed, true);
  }
});
test('native storage invalidation retires the owning browser immediately', async () => {
  let failed!: () => void;
  const f = fixture((options: any) => {
    failed = options.failed;
    return {
      isOffline: false,
      permitsRequest: () => true,
      restore: async () => {},
      capture: async () => {},
      close: async () => {},
    };
  });
  await tick();
  failed();
  await assert.rejects(f.promise);
  assert.equal(f.child.destroyed, true);
});
test('cookie replacement and deletion clear eligibility and cannot consume an older value', async () => {
  const f = fixture();
  await tick();
  f.headers('old');
  f.headers('', { responseHeaders: { 'set-cookie': ['SVPNCOOKIE=; HttpOnly; Max-Age=0'] } });
  f.commit('old');
  await tick();
  assert.equal(f.child.destroyed, false);
  f.headers('old', { responseHeaders: { 'set-cookie': ['SVPNCOOKIE=old; HttpOnly; Max-Age=0'] } });
  f.commit('old');
  await tick();
  assert.equal(f.child.destroyed, false);
  f.headers('new');
  f.commit('old');
  await tick();
  assert.equal(f.child.destroyed, false);
  f.commit('new');
  assert.ok(parseVaultTunnelCookieEnvelope(await f.promise));
  const parent = fixture();
  await tick();
  parent.headers();
  parent.commit('issued-cookie', { domain: '.vpn.test', hostOnly: false, path: '/' });
  assert.ok(parseVaultTunnelCookieEnvelope(await parent.promise));
});
test('cookie cancellation and late events retire the original owner without leaking profiles', async () => {
  for (const mode of ['abort', 'parent', 'stale', 'headers-error', 'storage']) {
    const f = fixture();
    await tick();
    f.headers();
    if (mode === 'abort') f.controller.abort();
    if (mode === 'parent') f.parent.destroy();
    if (mode === 'stale') {
      f.deny();
      f.commit();
      await f.dialog.cancelChallenge(f.c);
    }
    if (mode === 'headers-error') {
      f.child.headers(
        {
          webContentsId: f.child.webContents.id,
          statusCode: 200,
          get url() {
            throw Error('private');
          },
        },
        () => {},
      );
    }
    if (mode === 'storage') {
      f.child.cleanupFails = 'storage';
      await assert.rejects(f.dialog.cancelChallenge(f.c));
      f.child.cleanupFails = '';
      await f.dialog.cancelChallenge(f.c);
    }
    await assert.rejects(f.promise);
    f.commit();
    assert.equal(f.child.destroyed, true);
    assert.equal(f.child.webContents.session.cookies.listenerCount('changed'), 0);
  }
});
