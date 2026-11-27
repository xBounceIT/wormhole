import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { VaultReauthenticationDialog } from '../electron/vault-reauth-dialog.ts';
const target = 'file:///app/dist/vault-reauth.html';
const tick = () => new Promise(setImmediate);
const id = '11111111-1111-4111-8111-111111111111',
  slot = '22222222-2222-4222-8222-222222222222';
const descriptor = {
  formatVersion: 1,
  vaultId: id,
  encrypted: false,
  slots: [{ id: slot, kind: 'password', preset: 'kdf-v1' }],
} as const;
const factor = () => ({
  vaultId: id,
  slotId: slot,
  kind: 'password',
  factor: new Uint8Array([1, 2, 3]),
});
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
    calls = 0,
    borrowed: Uint8Array | undefined,
    complete: (value: unknown) => void = () => {};
  if (mode === 'load-error') child.loadError = true;
  if (mode === 'protection') child.protectionWorks = false;
  const dialog = new VaultReauthenticationDialog({
    ipc: {
      handle: (name, fn) => {
        handlers.set(name, fn);
      },
    } as any,
    createWindow: () => child as any,
    stop: async () => {
      stops++;
      if (mode === 'stop-error') throw Error('native diagnostic');
    },
    url: target,
    preload: 'preload',
    platform: 'win32',
  });
  const event = { sender: child.webContents, senderFrame: child.webContents.mainFrame };
  return {
    dialog,
    parent,
    child,
    event,
    handlers,
    deny: () => {
      accepted = false;
    },
    get stops() {
      return stops;
    },
    get calls() {
      return calls;
    },
    get borrowed() {
      return borrowed;
    },
    complete: (value: unknown) => complete(value),
    open: (
      signal?: AbortSignal,
      operation: 'folder-save' | 'migration-resume' | 'rotation-resume' = 'folder-save',
    ) =>
      dialog.open(
        parent as any,
        () => accepted,
        operation,
        descriptor as any,
        async (input) => {
          calls++;
          borrowed = input.factor;
          if (mode === 'wrong' && calls === 1) throw Error('wrong factor');
          if (['pending', 'stop-error', 'late-error'].includes(mode))
            return new Promise((resolve, reject) => {
              complete =
                mode === 'late-error' ? () => reject(Error('private diagnostic')) : resolve;
            });
          return { saved: true };
        },
        signal,
      ),
    call: (name: string, ...args: any[]) => handlers.get('vault-reauth:' + name)(event, ...args),
  };
}
test('fresh dialog confines factor submission to a current main-owned action', async () => {
  const f = setup('wrong'),
    result = f.open();
  await tick();
  assert.ok(f.child.shown && f.child.protected);
  assert.equal(f.call('context').operation, 'folder-save');
  assert.throws(() => f.call('context', {}));
  await assert.rejects(f.open());
  for (const event of [
    { sender: f.parent.webContents, senderFrame: f.parent.webContents.mainFrame },
    { sender: f.child.webContents, senderFrame: { url: target } },
  ]) {
    const input = factor();
    await assert.rejects(f.handlers.get('vault-reauth:submit')(event, input));
    assert.ok(input.factor.every((x) => x === 0));
  }
  await assert.rejects(f.call('submit', { ...factor(), vaultId: slot }));
  await assert.rejects(f.call('submit', { ...factor(), slotId: id }));
  await assert.rejects(f.call('cancel', {}));
  let input = factor();
  assert.equal(await f.call('submit', input), false);
  assert.ok(input.factor.every((x) => x === 0));
  assert.ok(f.borrowed!.every((x) => x === 0));
  input = factor();
  assert.equal(await f.call('submit', input), true);
  assert.deepEqual(await result, { saved: true });
  assert.ok(f.child.destroyed);
  assert.equal(f.stops, 0);
  await f.dialog.cancel();
  await assert.rejects(f.call('submit', factor()));
});
test('fresh dialog cancellation and owner loss clear factors and retire pending actions', async () => {
  for (const mode of [
    'cancel',
    'parent',
    'child',
    'reload',
    'navigate-parent',
    'load-error',
    'protection',
    'pending',
    'stop-error',
    'late-error',
  ]) {
    const f = setup(mode),
      result = f.open(),
      checked = assert.rejects(result, /cancelled/);
    await tick();
    let submission: Promise<any> | undefined;
    if (['pending', 'stop-error', 'late-error'].includes(mode)) {
      submission = f.call('submit', factor());
      await tick();
      await assert.rejects(f.call('submit', factor()));
    }
    if (mode === 'parent') f.parent.destroy();
    else if (mode === 'child') f.child.destroy();
    else if (mode === 'reload')
      f.child.webContents.emit('did-start-navigation', {}, target, false, true);
    else if (mode === 'navigate-parent')
      f.parent.webContents.emit('did-start-navigation', {}, target, false, true);
    else await f.dialog.cancel();
    if (submission) {
      f.complete({ saved: true });
      assert.equal(await submission, false);
      assert.equal(f.stops, 1);
      assert.ok(f.borrowed!.every((x) => x === 0));
    }
    await checked;
    assert.ok(f.child.destroyed);
  }
  const f = setup();
  f.deny();
  await assert.rejects(f.open());
  const g = setup(),
    result = g.open(),
    checked = assert.rejects(result);
  await tick();
  g.deny();
  await assert.rejects(g.call('submit', factor()));
  await g.dialog.cancel();
  await checked;
});

test('fresh authentication is cancelled by its owning SSH attempt signal', async () => {
  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(setup().open(aborted.signal), /unavailable/);
  for (const mode of ['', 'pending']) {
    const f = setup(mode),
      controller = new AbortController();
    const pending = f.open(controller.signal),
      checked = assert.rejects(pending, /cancelled/);
    await tick();
    const submit = mode === 'pending' ? f.call('submit', factor()) : undefined;
    await tick();
    controller.abort();
    await checked;
    if (submit) {
      f.complete({ saved: true });
      assert.equal(await submit, false);
    }
    assert.ok(f.child.destroyed);
    assert.equal(f.stops, mode === 'pending' ? 1 : 0);
  }
});

test('migration prompt keeps its busy deadline separate from the input deadline', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  for (const operation of ['migration-resume', 'rotation-resume'] as const) {
    const f = setup('pending');
    const result = f.open(undefined, operation);
    await tick();
    const submission = f.handlers.get('vault-reauth:submit')!(f.event, factor());
    await tick();
    t.mock.timers.tick(5 * 60_000 + 1);
    assert.equal(f.child.destroyed, false);
    assert.equal(f.stops, 0);
    f.complete({ migrated: true });
    assert.equal(await submission, true);
    assert.deepEqual(await result, { migrated: true });
    t.mock.timers.tick(40 * 60_000);
    assert.equal(f.stops, 0);
  }
});
