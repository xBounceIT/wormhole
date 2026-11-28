import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { VaultTunnelAuthenticationDialog } from '../electron/vault-tunnel-authentication-dialog.ts';
import {
  tunnelAuthenticationContext as context,
  tunnelAuthenticationEnvelope as envelope,
} from './fixtures/vault-tunnel-authentication.ts';
const target = 'file:///app/dist/vault-tunnel-authentication.html';
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

function setup() {
  const handlers = new Map<string, any>(),
    children: Window[] = [],
    parent = new Window();
  let failCreate = false;
  const dialog = new VaultTunnelAuthenticationDialog({
    ipc: { handle: (name, fn) => handlers.set(name, fn) } as any,
    createWindow: () => {
      if (failCreate) throw Error('private failure');
      const child = new Window();
      children.push(child);
      return child as any;
    },
    url: target,
    preload: 'authentication.cjs',
    platform: 'win32',
  });
  const open = (c = context(), signal = new AbortController(), accepted = () => true) => {
    const promise = dialog.open(parent as any, accepted, c, signal.signal);
    void promise.catch(() => {});
    return { c, signal, promise };
  };
  const invoke = (channel: string, args: unknown[] = [], child = children.at(-1)!) =>
    handlers.get('vault-tunnel-authentication:' + channel)(
      { sender: child.webContents, senderFrame: child.webContents.mainFrame },
      ...args,
    );
  return {
    dialog,
    children,
    parent,
    open,
    invoke,
    failCreate: () => {
      failCreate = true;
    },
  };
}
test('VPN prompts serialize, return only ciphertext and a document cancel preserves other attempts', async () => {
  const f = setup(),
    a = f.open(),
    b = f.open(),
    c = f.open();
  await tick();
  assert.equal(f.children.length, 1);
  assert.equal(f.children[0].shown, true);
  assert.deepEqual(f.invoke('context'), a.c);
  assert.throws(() => f.invoke('submit', [{ ...envelope(), password: 'never' }]), /Invalid/);
  await f.invoke('cancel');
  await assert.rejects(a.promise, /cancelled/);
  await tick();
  assert.equal(f.children.length, 2);
  assert.deepEqual(f.invoke('context'), b.c);
  assert.equal(f.invoke('submit', [envelope()]), true);
  assert.deepEqual(await b.promise, envelope());
  await tick();
  assert.equal(f.children.length, 3);
  assert.deepEqual(f.invoke('context'), c.c);
  await f.dialog.cancel();
  await assert.rejects(c.promise);
  assert.ok(f.children.every((w) => w.destroyed));
});
test('queued cancellation completes immediately and exact challenge cancellation does not close another window', async () => {
  const f = setup(),
    a = f.open(),
    b = f.open(),
    c = f.open();
  await tick();
  b.signal.abort();
  await assert.rejects(b.promise, /cancelled/);
  assert.equal(f.children.length, 1);
  await f.dialog.cancelChallenge({ ...a.c, challengeId: context().challengeId });
  assert.equal(f.children[0].destroyed, false);
  await assert.rejects(f.dialog.cancelChallenge({} as any), /context unavailable/);
  // Parsing normalizes reordered binding properties before comparison.
  const reordered = {
    ...a.c,
    binding: Object.fromEntries(Object.entries(a.c.binding).reverse()),
  } as typeof a.c;
  await f.dialog.cancelChallenge(reordered);
  await assert.rejects(a.promise);
  await tick();
  assert.equal(f.children.length, 2);
  assert.deepEqual(f.invoke('context'), c.c);
  await f.dialog.cancel();
  await assert.rejects(c.promise);
});
test('immediate global or challenge cancellation cannot open a selected prompt afterward', async () => {
  for (const mode of ['global', 'challenge', 'abort']) {
    const f = setup(),
      a = f.open();
    if (mode === 'global') await f.dialog.cancel();
    if (mode === 'challenge') await f.dialog.cancelChallenge(a.c);
    if (mode === 'abort') a.signal.abort();
    await assert.rejects(a.promise);
    await tick();
    assert.equal(f.children.length, 1);
    assert.ok(f.children[0].destroyed);
  }
  const f = setup(),
    a = f.open(),
    b = f.open();
  await f.dialog.cancel();
  await Promise.all([assert.rejects(a.promise), assert.rejects(b.promise)]);
  await tick();
  assert.equal(f.children.length, 1);
});
test('failed native destruction quarantines the actor until explicit matching shutdown succeeds', async () => {
  const f = setup(),
    a = f.open();
  await tick();
  const child = f.children[0],
    destroy = child.destroy.bind(child);
  child.destroy = () => {
    throw Error('private destroy failure');
  };
  await assert.rejects(f.dialog.cancelChallenge(a.c), /shutdown could not be confirmed/);
  await assert.rejects(a.promise, /could not be closed/);
  await assert.rejects(f.open().promise, /unavailable/);
  await tick();
  assert.equal(f.children.length, 1);
  child.destroy = destroy;
  await f.dialog.cancelChallenge(a.c);
  const b = f.open();
  await tick();
  assert.equal(f.children.length, 2);
  await f.dialog.cancel();
  await assert.rejects(b.promise);
});
test('invalid, stale, failed creation and full queues reject without exposing factors', async () => {
  const f = setup();
  await assert.rejects(
    f.dialog.open(f.parent as any, () => true, {}, new AbortController().signal),
  );
  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(f.open(context(), aborted).promise);
  const a = f.open(),
    stale = f.open(context(), new AbortController(), () => false);
  await f.dialog.cancelChallenge(a.c);
  await assert.rejects(a.promise);
  await assert.rejects(stale.promise);
  await tick();
  f.failCreate();
  await assert.rejects(f.open().promise, /unavailable/);
  const q = setup(),
    first = q.open(),
    pending = Array.from({ length: 128 }, () => q.open());
  await assert.rejects(q.open().promise, /unavailable/);
  await q.dialog.cancel();
  await assert.rejects(first.promise);
  await Promise.all(pending.map((e) => assert.rejects(e.promise)));
  const dead = setup();
  dead.parent.destroy();
  await assert.rejects(dead.open().promise);
});
