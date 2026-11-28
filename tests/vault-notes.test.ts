import { createNotesRecipient } from '../src/vault-notes-recipient.ts';
import { VaultBackendHost } from '../electron/vault-host.ts';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { VaultCredentialsDialog } from '../electron/vault-credentials-dialog.ts';
import { VaultNotesDialog } from '../electron/vault-notes-dialog.ts';
import {
  parseVaultNotesSelection,
  parseVaultNotesContext,
  parseVaultNotesRequest,
  parseVaultNotesDisplay,
  notesCiphertext,
} from '../electron/vault-notes.ts';
const target = 'file:///app/dist/vault-notes.html';
const context = {
  workspaceId: '11111111-1111-4111-8111-111111111111',
  nodeId: '22222222-2222-4222-8222-222222222222',
  requestId: '33333333-3333-4333-8333-333333333333',
  rowVersion: '1',
};
const publicKey = Buffer.alloc(32, 1).toString('base64');
const selection = { nodeId: context.nodeId, rowVersion: '1' };
const response = {
  ...context,
  bundle: {
    formatVersion: 1,
    suiteId: 2,
    enc: publicKey,
    ciphertext: Buffer.alloc(32).toString('base64'),
  },
};
const tick = () => new Promise(setImmediate);
test('notes contracts bind exact selections and reject malformed or excessive ciphertext', () => {
  assert.deepEqual(parseVaultNotesSelection(selection), selection);
  assert.deepEqual(parseVaultNotesContext(context), context);
  assert.deepEqual(parseVaultNotesRequest({ ...context, publicKey }), { ...context, publicKey });
  assert.deepEqual(parseVaultNotesDisplay(response, context), response);
  assert.deepEqual(parseVaultNotesDisplay(response, { ...context, publicKey } as any), response);
  for (const bad of [
    null,
    [],
    {},
    { ...selection, notes: 'secret' },
    { ...selection, rowVersion: '0' },
    { ...selection, rowVersion: '01' },
    { ...selection, rowVersion: '9223372036854775808' },
    { ...selection, nodeId: 'bad' },
  ])
    assert.equal(parseVaultNotesSelection(bad), undefined);
  for (const bad of [
    null,
    { ...context, extra: true },
    { ...context, workspaceId: 'bad' },
    { ...context, requestId: 'bad' },
    { ...context, rowVersion: '0' },
  ])
    assert.equal(parseVaultNotesContext(bad), undefined);
  for (const bad of [
    null,
    { ...context },
    { ...context, publicKey: 'bad' },
    { ...context, publicKey, extra: 1 },
    { ...context, publicKey, rowVersion: '0' },
  ])
    assert.equal(parseVaultNotesRequest(bad), undefined);
  for (const bad of [
    null,
    { ...response, extra: 1 },
    ...Object.keys(context).map((key) => ({ ...response, [key]: 'bad' })),
    ...['formatVersion', 'suiteId', 'enc', 'ciphertext'].map((key) => ({
      ...response,
      bundle: { ...response.bundle, [key]: 'bad' },
    })),
    { ...response, bundle: null },
    { ...response, bundle: { ...response.bundle, notes: 'secret' } },
  ])
    assert.equal(parseVaultNotesDisplay(bad, context), undefined);
  for (const size of [16, 17, 18, 65552])
    assert.equal(notesCiphertext(Buffer.alloc(size).toString('base64'))?.length, size);
  for (const bad of [
    null,
    '',
    '!'.repeat(24),
    Buffer.alloc(15).toString('base64'),
    Buffer.alloc(65553).toString('base64'),
    'A'.repeat(87405),
  ])
    assert.equal(notesCiphertext(bad), undefined);
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

function setup(mode = '', credentials = false) {
  const parent = new Window(),
    child = new Window(),
    handlers = new Map<string, any>();
  let accepted = true,
    options: any,
    calls = 0,
    authParent: any,
    authAccepted: (() => boolean) | undefined;
  const host: any = {
    unlockedWorkspaceId: context.workspaceId,
    displayNotes: async (request: any) => {
      calls++;
      return { ...request, bundle: response.bundle };
    },
  };
  if (mode === 'load') child.loadError = true;
  if (mode === 'protection') child.protectionWorks = false;
  host.displayCredentials = host.displayNotes;
  const Dialog = credentials ? VaultCredentialsDialog : VaultNotesDialog;
  const dialog = new Dialog({
    authenticate: (parent: any, accepted: () => boolean) => {
      authParent = parent;
      authAccepted = accepted;
      return async () => {
        throw Error('unused fixture authentication');
      };
    },
    host,
    linuxClipboard:
      mode === 'linux' ? { copy: (...args: any[]) => host.copyCredential(...args) } : undefined,
    ipc: { handle: (name: string, fn: any) => handlers.set(name, fn) } as any,
    createWindow: (value) => {
      options = value;
      return child as any;
    },
    url: target,
    preload: '/app/notes.cjs',
    platform: mode.startsWith('linux') ? 'linux' : mode === 'macos' ? 'darwin' : 'win32',
  });
  const event: any = { sender: child.webContents, senderFrame: child.webContents.mainFrame };
  return {
    dialog,
    parent,
    child,
    host,
    event,
    handlers,
    open: (value: any = selection) => dialog.open(parent as any, () => accepted, value),
    deny: () => {
      accepted = false;
    },
    get authParent() {
      return authParent;
    },
    get authAccepted() {
      return authAccepted;
    },
    get calls() {
      return calls;
    },
    get options() {
      return options;
    },
  };
}
test('notes dialog restricts sender, recipient, navigation and one-use reads', async () => {
  const f = setup(),
    opened = f.open();
  await tick();
  assert.equal(f.child.shown, true);
  assert.equal(f.child.protected, true);
  assert.equal(f.options.webPreferences.sandbox, true);
  assert.equal(f.options.webPreferences.nodeIntegration, false);
  assert.ok(!f.options.webPreferences.partition.startsWith('persist:'));
  const ctx = f.handlers.get('vault-notes:context'),
    read = f.handlers.get('vault-notes:read'),
    close = f.handlers.get('vault-notes:close');
  const actual = ctx(f.event);
  assert.equal(actual.nodeId, context.nodeId);
  assert.equal(actual.rowVersion, '1');
  actual.nodeId = 'changed';
  assert.equal(ctx(f.event).nodeId, context.nodeId);
  for (const bad of [{ ...f.event, sender: {} }, { ...f.event, senderFrame: {} }, {}]) {
    assert.throws(() => ctx(bad));
    await assert.rejects(read(bad, publicKey));
    assert.throws(() => close(bad));
  }
  assert.throws(() => ctx(f.event, 1));
  assert.throws(() => close(f.event, 1));
  await assert.rejects(read(f.event));
  await assert.rejects(read(f.event, publicKey, 1));
  await assert.rejects(read(f.event, 'bad'));
  f.child.webContents.mainFrame.url = 'file:///evil';
  assert.throws(() => ctx(f.event));
  f.child.webContents.mainFrame.url = target;
  const value = await read(f.event, publicKey);
  assert.equal(value.nodeId, context.nodeId);
  assert.equal(f.calls, 1);
  await assert.rejects(read(f.event, publicKey));
  await assert.rejects(f.open());
  assert.equal(f.child.popup().action, 'deny');
  assert.equal(f.child.permissionCheck(), false);
  f.child.permission(null, null, (allowed: boolean) => assert.equal(allowed, false));
  for (const [url, cancel] of [
    ['file:///app/dist/a.js', false],
    ['https://evil/a', true],
    ['file:///app/private', true],
    ['not url', true],
    ['file://evil/app/dist/a', true],
  ])
    f.child.network({ url }, (result: any) => assert.equal(result.cancel, cancel));
  for (const name of ['will-navigate', 'will-frame-navigate', 'context-menu']) {
    let blocked = false;
    f.child.webContents.emit(name, {
      preventDefault: () => {
        blocked = true;
      },
    });
    assert.equal(blocked, true);
  }
  let download = false;
  f.child.webContents.session.emit('will-download', { preventDefault: () => (download = true) });
  assert.equal(download, true);
  for (const key of ['F5', 'F12', 'r', 'p', 's', 'x']) {
    let blocked = false;
    f.child.webContents.emit(
      'before-input-event',
      { preventDefault: () => (blocked = true) },
      { key, control: true },
    );
    assert.equal(blocked, key !== 'x');
  }
  close(f.event);
  await opened;
  assert.equal(f.child.destroyed, true);
  assert.equal(f.parent.listenerCount('closed'), 0);
  assert.equal(f.parent.webContents.listenerCount('did-start-navigation'), 0);
  f.dialog.cancel();
});
test('notes windows close on owner loss, navigation, crash and expiration', async (t) => {
  for (const mode of [
    'load',
    'protection',
    'linux',
    'parent-close',
    'parent-crash',
    'parent-navigation',
    'child-crash',
    'child-navigation',
    'child-close',
    'untrusted',
    'owner',
    'pending',
    'expired',
  ]) {
    const f = setup(mode);
    let release: any;
    if (mode === 'pending')
      f.host.displayNotes = () => new Promise((resolve) => (release = resolve));
    if (mode === 'expired') t.mock.timers.enable({ apis: ['setTimeout'] });
    const opened = f.open();
    const failure =
      mode === 'load' || mode === 'protection'
        ? assert.rejects(opened, /could not be opened/)
        : undefined;
    await tick();
    if (failure) {
      await failure;
      assert.equal(f.child.destroyed, true);
      continue;
    }
    if (mode === 'linux') {
      assert.equal(f.child.protected, false);
      f.dialog.cancel();
    }
    if (mode === 'parent-close') f.parent.destroy();
    if (mode === 'parent-crash') f.parent.webContents.emit('render-process-gone');
    if (mode === 'parent-navigation') {
      f.parent.webContents.emit('did-start-navigation', {}, '', false, false);
      assert.equal(f.child.destroyed, false);
      f.parent.webContents.emit('did-start-navigation', {}, '', false, true);
    }
    if (mode === 'child-navigation')
      f.child.webContents.emit('did-start-navigation', {}, '', false, true);
    if (mode === 'child-crash') f.child.webContents.emit('render-process-gone');
    if (mode === 'child-close') f.child.destroy();
    if (mode === 'untrusted' || mode === 'owner') {
      if (mode === 'untrusted') f.deny();
      else f.host.unlockedWorkspaceId = undefined;
      assert.throws(() => f.handlers.get('vault-notes:context')(f.event));
      f.dialog.cancel();
    }
    if (mode === 'pending') {
      const pending = f.handlers.get('vault-notes:read')(f.event, publicKey);
      f.dialog.cancel();
      release(response);
      await assert.rejects(pending, /unavailable/);
    }
    if (mode === 'expired') {
      t.mock.timers.tick(300000);
      t.mock.timers.reset();
    }
    await opened;
    assert.equal(f.child.destroyed, true);
  }
  for (const mode of ['invalid', 'locked', 'parent', 'denied']) {
    const f = setup();
    if (mode === 'locked') f.host.unlockedWorkspaceId = undefined;
    if (mode === 'parent') f.parent.destroy();
    if (mode === 'denied') f.deny();
    await assert.rejects(f.open(mode === 'invalid' ? {} : selection));
  }
  const f = setup();
  f.host.displayNotes = async () => {
    throw Error('private');
  };
  const opened = f.open();
  await assert.rejects(
    f.handlers.get('vault-notes:read')(f.event, publicKey),
    (error) => !String(error).includes('private'),
  );
  f.dialog.cancel();
  await opened;
});

test('notes recipient authenticates context, consumes its private key and rejects malformed plaintext', async () => {
  await assert.rejects(createNotesRecipient({} as any));
  for (const mode of [
    'valid',
    'empty',
    'utf8',
    'nul',
    'oversized',
    'context',
    'ciphertext',
    'disposed',
    'late',
    'domain',
  ]) {
    const r = await createNotesRecipient(context);
    const suite = new CipherSuite({
      kem: new DhkemX25519HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Aes256Gcm(),
    });
    const publicKey = await suite.kem.deserializePublicKey(Buffer.from(r.publicKey, 'base64'));
    const parts = [context.workspaceId, context.nodeId, context.requestId, context.rowVersion];
    const info = Buffer.concat([
      Buffer.from(mode === 'domain' ? 'wormhole/v1/recovery-display' : 'wormhole/v1/notes-display'),
      ...parts.flatMap((value) => {
        const length = Buffer.alloc(4);
        length.writeUInt32BE(value.length);
        return [length, Buffer.from(value)];
      }),
    ]);
    const sender = await suite.createSenderContext({ recipientPublicKey: publicKey, info });
    const text =
      mode === 'empty'
        ? new Uint8Array()
        : mode === 'utf8'
          ? new Uint8Array([255])
          : new TextEncoder().encode(
              mode === 'nul'
                ? 'x\0'
                : mode === 'oversized'
                  ? 'x'.repeat(16385)
                  : 'note <script>literal</script> 🌍',
            );
    const result = {
      ...context,
      bundle: {
        formatVersion: 1,
        suiteId: 2,
        enc: Buffer.from(sender.enc).toString('base64'),
        ciphertext: Buffer.from(await sender.seal(text)).toString('base64'),
      },
    };
    if (mode === 'context') result.nodeId = context.requestId;
    if (mode === 'ciphertext') result.bundle.ciphertext = Buffer.alloc(32).toString('base64');
    if (mode === 'disposed') r.dispose();
    const pending = r.open(result);
    if (mode === 'late') r.dispose();
    if (mode === 'valid' || mode === 'empty') {
      const opened = await pending;
      assert.deepEqual(opened, text);
      opened.fill(0);
    } else await assert.rejects(pending);
    await assert.rejects(r.open(result), /closed/);
    r.dispose();
  }
});
test('notes host never starts a locked owner or delivers a late response after lock', async () => {
  let calls = 0,
    release: any,
    delayed = false;
  const client: any = {
    unlock: async () => ({ unlocked: true, lockedMemory: true }),
    security: async () => ({
      sequence: '1',
      workspace: 'default',
      user: 'default',
      os: 'default',
      effective: 'default',
      source: 'workspace',
    }),
    lock: async () => {},
    displayNotes: async () => {
      calls++;
      if (delayed) await new Promise((resolve) => (release = resolve));
      return response;
    },
  };
  const host = new VaultBackendHost(
      () => client,
      () => true,
    ),
    request = { ...context, publicKey };
  await assert.rejects(host.displayNotes(null), /Invalid/);
  await assert.rejects(host.displayNotes(request), /locked/);
  assert.equal(host.hasOwner, false);
  await host.unlock({
    vaultId: context.workspaceId,
    slotId: context.nodeId,
    kind: 'password',
    factor: new Uint8Array([1]),
  });
  await assert.rejects(host.displayNotes({ ...request, workspaceId: context.nodeId }), /locked/);
  assert.deepEqual(await host.displayNotes(request), response);
  assert.equal(calls, 1);
  delayed = true;
  const pending = host.displayNotes(request);
  await host.stop();
  release();
  await assert.rejects(pending, /locked/);
});

test('credentials dialog isolates recipient channel and exact request from the ordinary renderer', async () => {
  const f = setup('', true),
    opened = f.open();
  await tick();
  assert.equal(f.options.title, 'Connection credentials');
  assert.ok(f.options.webPreferences.partition.startsWith('vault-credentials-'));
  assert.equal(f.handlers.has('vault-notes:read'), false);
  const read = f.handlers.get('vault-credentials:read'),
    ctx = f.handlers.get('vault-credentials:context');
  await assert.rejects(read({ ...f.event, sender: f.parent.webContents }, publicKey));
  const captured = ctx(f.event),
    result = await read(f.event, publicKey);
  assert.equal(result.nodeId, captured.nodeId);
  assert.equal(result.requestId, captured.requestId);
  assert.equal(f.authParent, f.child);
  assert.equal(f.authAccepted!(), true);
  await assert.rejects(read(f.event, publicKey));
  f.dialog.cancel();
  await opened;
  assert.equal(f.authAccepted!(), false);
});

test('credential clipboard IPC binds displayed selection and rejects concurrent, stale and foreign requests', async () => {
  for (const mode of ['', 'macos', 'linux']) {
    const f = setup(mode, true),
      opened = f.open();
    await tick();
    const copy = f.handlers.get('vault-credentials:copy');
    await assert.rejects(copy(f.event, 'secret'), /Invalid/);
    await f.handlers.get('vault-credentials:read')(f.event, publicKey);
    let calls = 0,
      release!: () => void,
      delay = false,
      reject = false;
    f.host.copyCredential = async (request: any, _auth: any, accepted: () => boolean) => {
      calls++;
      assert.deepEqual(request, {
        ...selection,
        workspaceId: context.workspaceId,
        field: 'secret',
      });
      assert.equal(accepted(), true);
      if (delay) await new Promise<void>((resolve) => (release = resolve));
      if (reject) throw Error('private backend diagnostic');
      return { expiresInSeconds: 20 };
    };
    for (const args of [
      [],
      ['secret', 'extra'],
      ['privateKey'],
      [null],
      [{ field: 'secret', value: 'plaintext' }],
    ])
      await assert.rejects(copy(f.event, ...args), /Invalid/);
    await assert.rejects(copy({ ...f.event, senderFrame: {} }, 'secret'), /Invalid/);
    assert.deepEqual(await copy(f.event, 'secret'), { expiresInSeconds: 20 });
    assert.equal(f.authParent, f.child);
    reject = true;
    await assert.rejects(copy(f.event, 'secret'), /Secure copy is unavailable/);
    reject = false;
    delay = true;
    const pending = copy(f.event, 'secret');
    await tick();
    await assert.rejects(copy(f.event, 'secret'), /Invalid/);
    assert.equal(calls, 3);
    f.dialog.cancel();
    release();
    await assert.rejects(pending, /Secure copy is unavailable/);
    await opened;
    await assert.rejects(copy(f.event, 'secret'), /Invalid/);
  }
  assert.equal(setup().handlers.has('vault-notes:copy'), false);
});

test('Linux credential dialog fails closed if its main clipboard service is unavailable', async () => {
  const f = setup('linux-no-clipboard', true),
    opened = f.open();
  await tick();
  await f.handlers.get('vault-credentials:read')(f.event, publicKey);
  await assert.rejects(
    f.handlers.get('vault-credentials:copy')(f.event, 'secret'),
    /Secure copy is unavailable/,
  );
  f.dialog.cancel();
  await opened;
});
