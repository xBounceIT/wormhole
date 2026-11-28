import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { VaultCreateDialog } from '../electron/vault-create-dialog.ts';
const target = 'file:///app/dist/vault-create.html';
const response = {
  enrollmentId: '11111111-1111-4111-8111-111111111111',
  vaultId: '22222222-2222-4222-8222-222222222222',
  groups: [1, 2],
  bundle: {},
};
const begin = () => ({
  password: new Uint8Array([1, 2, 3]),
  publicKey: new Uint8Array(32).fill(4),
});
const confirm = () => ({
  enrollmentId: response.enrollmentId,
  groups: new Uint8Array(10).fill(65),
});
const tick = () => new Promise(setImmediate);
function deferred() {
  let resolve!: (value: any) => void;
  const promise = new Promise<any>((yes) => (resolve = yes));
  return { promise, resolve };
}
class Window extends EventEmitter {
  destroyed = false;
  shown = false;
  protected = false;
  protectionWorks = true;
  loadError = false;
  permission: any;
  permissionCheck: any;
  network: any;
  popup: any;
  webContents: any = new EventEmitter();
  constructor() {
    super();
    this.webContents.mainFrame = { url: target };
    this.webContents.setWindowOpenHandler = (fn: any) => (this.popup = fn);
    this.webContents.session = new EventEmitter();
    Object.assign(this.webContents.session, {
      setPermissionRequestHandler: (fn: any) => (this.permission = fn),
      setPermissionCheckHandler: (fn: any) => (this.permissionCheck = fn),
      webRequest: { onBeforeRequest: (fn: any) => (this.network = fn) },
    });
  }
  isDestroyed() {
    return this.destroyed;
  }
  setMenu() {}
  setContentProtection(value: boolean) {
    this.protected = value;
  }
  isContentProtected() {
    return this.protected && this.protectionWorks;
  }
  destroy() {
    if (!this.destroyed) {
      this.destroyed = true;
      this.emit('closed');
    }
  }
  show() {
    this.shown = true;
  }
  async loadURL() {
    if (this.loadError) throw Error('load failed');
  }
}
function setup(mode = '') {
  const handlers = new Map<string, any>(),
    parent = new Window(),
    child = new Window();
  let accepted = true,
    stops = 0,
    activated = 0,
    options: any;
  const host: any = {
    isVaultWorkspace: false,
    unlockedWorkspaceId: undefined,
    beginEnrollment: async () => response,
    confirmEnrollment: async () => {
      host.unlockedWorkspaceId = response.vaultId;
      return { unlocked: true, lockedMemory: true };
    },
    stop: async () => {
      stops++;
      host.unlockedWorkspaceId = undefined;
      if (mode === 'stop-error') throw Error('private diagnostic');
    },
  };
  if (mode === 'load-error') child.loadError = true;
  if (mode === 'no-protection') child.protectionWorks = false;
  const dialog = new VaultCreateDialog({
    host,
    platform: mode === 'linux' ? 'linux' : 'win32',
    ipc: {
      handle: (name: string, fn: any) => {
        handlers.set(name, fn);
      },
    } as any,
    createWindow: (value) => {
      options = value;
      return child as any;
    },
    url: target,
    preload: '/app/vault-create-preload.cjs',
    activate: () => {
      activated++;
      if (mode === 'activate-error') throw Error('private diagnostic');
    },
  });
  const event = { sender: child.webContents, senderFrame: child.webContents.mainFrame };
  return {
    dialog,
    parent,
    child,
    host,
    event,
    handlers,
    open: () => dialog.open(parent as any, () => accepted),
    deny: () => (accepted = false),
    get stops() {
      return stops;
    },
    get activated() {
      return activated;
    },
    get options() {
      return options;
    },
    call: (name: string, ...args: any[]) =>
      handlers.get('vault-enrollment:' + name)(event, ...args),
  };
}
test('creation dialog confines IPC, navigation, network, permissions and window lifetime', async () => {
  const f = setup(),
    result = f.open();
  await tick();
  assert.ok(f.child.shown && f.child.protected && f.dialog.active);
  await assert.rejects(f.open());
  assert.equal(f.options.webPreferences.sandbox, true);
  assert.equal(f.options.webPreferences.nodeIntegration, false);
  assert.equal(f.options.webPreferences.devTools, false);
  assert.ok(!f.options.webPreferences.partition.startsWith('persist:'));
  assert.equal(f.child.popup().action, 'deny');
  assert.equal(f.child.permissionCheck(), false);
  let permission = true;
  f.child.permission(null, null, (v: boolean) => (permission = v));
  assert.equal(permission, false);
  for (const event of ['will-navigate', 'will-frame-navigate', 'context-menu']) {
    let prevented = false;
    f.child.webContents.emit(event, { preventDefault: () => (prevented = true) });
    assert.ok(prevented);
  }
  for (const [input, blocked] of [
    [{ key: 'F5' }, true],
    [{ key: 'P', control: true }, true],
    [{ key: 's', meta: true }, true],
    [{ key: 'a' }, false],
  ] as const) {
    let prevented = false;
    f.child.webContents.emit(
      'before-input-event',
      { preventDefault: () => (prevented = true) },
      input,
    );
    assert.equal(prevented, blocked);
  }
  let prevented = false;
  f.child.webContents.session.emit('will-download', { preventDefault: () => (prevented = true) });
  assert.ok(prevented);
  for (const [url, cancel] of [
    ['file:///app/dist/assets/view.js', false],
    ['file://remote.example/app/dist/assets/view.js', true],
    ['file:///app/other.html', true],
    ['https://evil.example/', true],
    ['not a URL', true],
  ] as const) {
    let actual;
    f.child.network({ url }, (v: any) => (actual = v.cancel));
    assert.equal(actual, cancel);
  }
  for (const bad of [
    { sender: f.parent.webContents, senderFrame: f.parent.webContents.mainFrame },
    { sender: f.child.webContents, senderFrame: { url: target } },
    {
      sender: f.child.webContents,
      senderFrame: {
        get url() {
          throw Error('destroyed');
        },
      },
    },
  ]) {
    const input = begin();
    await assert.rejects(f.handlers.get('vault-enrollment:begin')(bad, input));
    assert.ok(input.password.every((x) => x === 0));
  }
  await assert.rejects(f.call('cancel', 1));
  await assert.rejects(f.call('confirm', confirm()));
  const input = begin();
  await f.call('begin', input);
  assert.ok(input.password.every((x) => x === 0));
  await assert.rejects(f.call('begin', begin()));
  await assert.rejects(f.call('confirm', { ...confirm(), enrollmentId: response.vaultId }));
  await f.call('confirm', confirm());
  assert.equal(await result, true);
  assert.equal(f.activated, 1);
  assert.equal(f.stops, 0);
  assert.equal(f.dialog.active, false);
  await f.dialog.cancel();
});
test('creation failure, cancellation and owner loss retire pending keys', async () => {
  for (const mode of [
    'cancel',
    'parent-close',
    'renderer-gone',
    'reload',
    'load-error',
    'no-protection',
    'activate-error',
    'stop-error',
    'lost-parent',
  ]) {
    const f = setup(mode),
      result = f.open();
    const checked = mode === 'stop-error' ? assert.rejects(result, /shutdown/) : result;
    await tick();
    if (mode === 'cancel' || mode === 'stop-error') await f.call('cancel');
    if (mode === 'parent-close') f.parent.destroy();
    if (mode === 'renderer-gone') f.child.webContents.emit('render-process-gone');
    if (mode === 'reload')
      f.child.webContents.emit('did-start-navigation', {}, target, false, true);
    if (mode === 'lost-parent') {
      f.deny();
      await assert.rejects(f.call('begin', begin()));
      await f.dialog.cancel();
    }
    if (mode === 'activate-error') {
      await f.call('begin', begin());
      await f.call('confirm', confirm());
    }
    const outcome = await checked;
    if (mode !== 'stop-error') assert.equal(outcome, false);
    assert.equal(f.stops, 1);
    assert.ok(f.child.destroyed);
    assert.equal(f.dialog.active, false);
  }
});
test('busy or late requests cannot reopen a closed creation dialog', async () => {
  for (const operation of ['begin', 'confirm']) {
    const f = setup(),
      result = f.open();
    await tick();
    if (operation === 'confirm') await f.call('begin', begin());
    const pending = deferred();
    f.host[operation === 'begin' ? 'beginEnrollment' : 'confirmEnrollment'] = () => pending.promise;
    const request = f.call(operation, operation === 'begin' ? begin() : confirm());
    const rejected = assert.rejects(request, /closed/);
    await assert.rejects(f.call(operation, operation === 'begin' ? begin() : confirm()));
    await assert.rejects(f.call(operation, operation === 'begin' ? begin() : confirm()));
    await f.dialog.cancel();
    assert.equal(await result, false);
    pending.resolve(operation === 'begin' ? response : { unlocked: true, lockedMemory: true });
    await rejected;
    assert.equal(f.activated, 0);
  }
  const f = setup();
  f.host.isVaultWorkspace = true;
  await assert.rejects(f.open());
  f.host.isVaultWorkspace = false;
  f.parent.destroy();
  await assert.rejects(f.open());
});

test('Linux creation keeps the isolated flow without calling unsupported capture APIs', async () => {
  const f = setup('linux');
  f.child.setContentProtection = () => {
    throw Error('unsupported API');
  };
  f.child.isContentProtected = () => {
    throw Error('unsupported API');
  };
  const result = f.open();
  await tick();
  assert.ok(f.child.shown);
  assert.equal(f.options.webPreferences.sandbox, true);
  await f.call('begin', begin());
  await f.call('confirm', confirm());
  assert.equal(await result, true);
  assert.equal(f.activated, 1);
});
