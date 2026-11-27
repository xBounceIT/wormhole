import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { VaultRdpCredentialsDialog } from '../electron/vault-rdp-credentials-dialog.ts';
import { rdpRequest, rdpBundle } from './fixtures/vault-rdp.ts';
const target = 'file:///app/dist/vault-rdp-credentials.html';
const tick = () => new Promise(setImmediate);
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
    options: any;
  if (mode === 'load') child.loadError = true;
  if (mode === 'protect') child.protectionWorks = false;
  if (mode === 'destroy')
    child.destroy = () => {
      throw Error('private destroy failure');
    };
  const dialog = new VaultRdpCredentialsDialog({
    ipc: { handle: (name, fn) => handlers.set(name, fn) } as any,
    createWindow: (o) => {
      options = o;
      return child as any;
    },
    url: target,
    preload: 'password.cjs',
    platform: mode === 'linux' ? 'linux' : 'win32',
  });
  const q = rdpRequest(),
    context = { binding: rdpBundle(q).binding, publicKey: q.publicKey },
    envelope = rdpBundle(q).bundle,
    signal = new AbortController(),
    event = { sender: child.webContents, senderFrame: child.webContents.mainFrame };
  const open = () => dialog.open(parent as any, () => accepted, context, signal.signal);
  const invoke = (channel: string, args: unknown[] = [], source: any = event) =>
    handlers.get('vault-rdp-credentials:' + channel)(source, ...args);
  return {
    dialog,
    parent,
    child,
    event,
    context,
    envelope,
    signal,
    open,
    invoke,
    deny: () => (accepted = false),
    get options() {
      return options;
    },
  };
}
test('protected RDP window admits one exact main document and one ciphertext submission', async () => {
  const f = setup(),
    result = f.open();
  await tick();
  assert.equal(f.child.shown, true);
  assert.equal(f.child.protected, true);
  assert.deepEqual(f.options.webPreferences, {
    preload: 'password.cjs',
    partition: f.options.webPreferences.partition,
    contextIsolation: true,
    sandbox: true,
    nodeIntegration: false,
    webSecurity: true,
    devTools: false,
    spellcheck: false,
  });
  assert.match(f.options.webPreferences.partition, /^vault-rdp-credentials-/);
  const context = f.invoke('context');
  assert.deepEqual(context, f.context);
  context.binding.host = 'changed';
  assert.equal(f.invoke('context').binding.host, 'host.example');
  await assert.rejects(f.open(), /unavailable/);
  for (const source of [
    { sender: f.parent.webContents, senderFrame: f.parent.webContents.mainFrame },
    { ...f.event, senderFrame: { url: target } },
    { ...f.event, senderFrame: null },
  ])
    for (const channel of ['context', 'submit', 'cancel'])
      assert.throws(
        () => f.invoke(channel, channel === 'submit' ? [f.envelope] : [], source),
        /Invalid/,
      );
  f.event.senderFrame.url = 'file:///other.html';
  assert.throws(() => f.invoke('context'), /Invalid/);
  f.event.senderFrame.url = target;
  for (const args of [[], [null], [{ ...f.envelope, password: 'secret' }], [f.envelope, 'extra']])
    assert.throws(() => f.invoke('submit', args), /Invalid/);
  assert.throws(() => f.invoke('context', ['extra']), /Invalid/);
  assert.throws(() => f.invoke('cancel', ['extra']), /Invalid/);
  assert.equal(f.invoke('submit', [f.envelope]), true);
  assert.deepEqual(await result, f.envelope);
  assert.equal(f.child.destroyed, true);
  assert.throws(() => f.invoke('submit', [f.envelope]), /Invalid/);
  assert.equal(f.parent.listenerCount('closed'), 0);
  assert.equal(f.parent.webContents.listenerCount('did-start-navigation'), 0);
  f.dialog.cancel();
});
test('password window cancellation scrubs its document on navigation, lock, crashes, timeout and failures', async (t) => {
  for (const mode of [
    'cancel',
    'api',
    'abort',
    'parent',
    'parent-nav',
    'parent-crash',
    'child',
    'child-nav',
    'child-crash',
    'load',
    'protect',
    'stale',
    'destroy',
    'timeout',
  ]) {
    const f = setup(mode),
      result = f.open();
    void result.catch(() => {});
    await tick();
    if (mode === 'cancel') f.dialog.cancel();
    if (mode === 'api') f.invoke('cancel');
    if (mode === 'abort') f.signal.abort();
    if (mode === 'parent') f.parent.emit('closed');
    if (mode === 'parent-nav') {
      f.parent.webContents.emit('did-start-navigation', {}, '', false, false);
      assert.equal(f.child.destroyed, false);
      f.parent.webContents.emit('did-start-navigation', {}, '', false, true);
    }
    if (mode === 'parent-crash') f.parent.webContents.emit('render-process-gone');
    if (mode === 'child') f.child.destroy();
    if (mode === 'child-nav') f.child.webContents.emit('did-start-navigation', {}, '', false, true);
    if (mode === 'child-crash') f.child.webContents.emit('render-process-gone');
    if (mode === 'stale') {
      f.deny();
      assert.throws(() => f.invoke('context'), /Invalid/);
      f.dialog.cancel();
    }
    if (mode === 'destroy') {
      assert.throws(
        () =>
          f.invoke('context', [], {
            get sender() {
              throw Error('gone');
            },
          }),
        /Invalid/,
      );
      await assert.rejects(f.dialog.cancel(), /shutdown could not be confirmed/);
    }
    if (mode === 'timeout') {
      f.dialog.cancel();
      await assert.rejects(result);
      t.mock.timers.enable({ apis: ['setTimeout'] });
      const next = setup();
      const pending = next.open();
      void pending.catch(() => {});
      t.mock.timers.tick(300000);
      await assert.rejects(pending, /cancelled/);
      t.mock.timers.reset();
      continue;
    }
    await assert.rejects(result, mode === 'destroy' ? /closed/ : /cancelled/);
    if (mode === 'destroy') await assert.rejects(f.open(), /unavailable/);
    else assert.equal(f.child.destroyed, true, mode);
  }
  const f = setup('linux'),
    result = f.open();
  await tick();
  assert.equal(f.child.protected, false);
  f.dialog.cancel();
  await assert.rejects(result);
  const denied = setup();
  denied.deny();
  await assert.rejects(denied.open());
  const aborted = setup();
  aborted.signal.abort();
  await assert.rejects(aborted.open());
  const parent = setup();
  parent.parent.destroy();
  await assert.rejects(parent.open());
});

test('unconfirmed password document destruction blocks acknowledgement and repeated shutdown', async () => {
  const f = setup('destroy'),
    pending = f.open();
  void pending.catch(() => {});
  await tick();
  assert.throws(() => f.invoke('submit', [f.envelope]), /could not be closed/);
  await assert.rejects(pending, /could not be closed/);
  await assert.rejects(f.dialog.cancel(), /shutdown could not be confirmed/);
  await assert.rejects(f.open(), /unavailable/);
});

test('an unconfirmed destroy without an exception cannot acknowledge an RDP envelope', async () => {
  const f = setup(),
    pending = f.open();
  void pending.catch(() => {});
  await tick();
  f.child.destroy = () => {};
  assert.throws(() => f.invoke('submit', [f.envelope]), /could not be closed/);
  await assert.rejects(pending, /could not be closed/);
  await assert.rejects(f.dialog.cancel(), /shutdown could not be confirmed/);
});
