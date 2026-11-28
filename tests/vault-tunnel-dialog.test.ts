import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import { VaultTunnelDialog } from '../electron/vault-tunnel-dialog.ts';
import { createTunnelEditorRecipient } from '../src/vault-tunnel-recipient.ts';
import { createNotesRecipient } from '../src/vault-notes-recipient.ts';
const target = 'file:///app/dist/vault-tunnel.html';
const workspace = '11111111-1111-4111-8111-111111111111';
const id = '22222222-2222-4222-8222-222222222222';
const requestId = '33333333-3333-4333-8333-333333333333';
const selection = { id, rowVersion: '1' };
const saved = { id, rowVersion: '2', updated: true };
const publicKey = Buffer.alloc(32, 1).toString('base64');
const bundle = {
  formatVersion: 1,
  suiteId: 2,
  enc: publicKey,
  ciphertext: Buffer.alloc(32).toString('base64'),
};
const tick = () => new Promise(setImmediate);
function input(draft = false): any {
  return {
    metadata: { id: draft ? '' : id, name: 'Original', kind: 1 },
    rowVersion: draft ? '0' : '1',
    forgetHostKey: false,
    patch: new TextEncoder().encode('{"Password":"secret"}'),
  };
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
  const parent = new Window(),
    child = new Window(),
    handlers = new Map<string, any>();
  let accepted = true,
    calls = 0,
    stops = 0,
    options: any,
    submitted: any;
  const imports: any[] = [],
    discards: any[] = [];
  let releaseRead!: () => void, releaseSave!: () => void, releaseStop!: () => void;
  if (mode === 'load') child.loadError = true;
  if (mode === 'protection') child.protectionWorks = false;
  const host: any = {
    unlockedWorkspaceId: workspace,
    workspace: async () => {
      if (mode === 'references-pending') await new Promise<void>((r) => (releaseRead = r));
      if (mode === 'references-failure') throw Error('private references');
      return {
        tree: [
          {
            id: requestId,
            name: 'Folder',
            kind: 'folder',
            children: [
              { id, name: 'SSH', kind: 'connection', protocol: 'ssh' },
              { id: workspace, name: 'RDP', kind: 'connection', protocol: 'rdp' },
            ],
          },
        ],
        tunnels: [
          { id, name: 'SSL', kind: 'Fortinet' },
          { id: workspace, name: 'IPsec', kind: 'Fortinet IPsec' },
        ],
        credentialOptions: { ssh: [{ id: workspace, name: 'Key', private: 'not projected' }] },
      };
    },
    stageTunnelImport: async (value: any, current: any) => {
      imports.push(value);
      assert.equal(current(), true);
      if (mode === 'import-pending') await new Promise<void>((r) => (releaseRead = r));
      if (mode === 'import-failure') throw Error('private import diagnostic');
      return {
        workspaceId: value.workspaceId,
        editorId: value.editorId,
        importId: value.importId,
        kind: value.kind,
        bundle,
      };
    },
    discardTunnelImport: async (value: any) => {
      discards.push(value);
      if (mode === 'discard-pending') await new Promise<void>((r) => (releaseRead = r));
      if (mode === 'discard-failure') throw Error('private discard diagnostic');
      return { discarded: true };
    },
    displayTunnelEditor: async (value: any) => {
      calls++;
      assert.equal(value.tunnelId, id);
      assert.equal(value.rowVersion, '1');
      assert.equal(value.workspaceId, workspace);
      assert.equal(value.publicKey, publicKey);
      if (mode === 'read-pending') await new Promise<void>((r) => (releaseRead = r));
      if (mode === 'read-failure') throw Error('private backend diagnostic');
      const { publicKey: _key, ...context } = value;
      return { ...context, bundle };
    },
    editTunnel: async (value: any, confirm: any, current: any) => {
      calls++;
      submitted = value;
      assert.equal(current(), true);
      assert.equal(new TextDecoder().decode(value.patch), '{"Password":"secret"}');
      if (mode === 'save-failure') throw Error('private backend diagnostic');
      if (['save-pending', 'stop-pending', 'stop-failure', 'late-save-error'].includes(mode))
        await new Promise<void>((r) => (releaseSave = r));
      if (mode === 'late-save-error') throw Error('private backend diagnostic');
      if (mode === 'confirm')
        await confirm('tunnel-edit', { vaultId: workspace }, async () => saved);
      return saved;
    },
    stop: async () => {
      stops++;
      host.unlockedWorkspaceId = undefined;
      if (mode === 'stop-pending') await new Promise<void>((r) => (releaseStop = r));
      if (mode === 'stop-failure') throw Error('private stop diagnostic');
    },
  };
  const dialog = new VaultTunnelDialog({
    colorScheme: () => 'oled',
    host,
    pickImport: async (owner, format) => {
      assert.equal(owner, child);
      assert.equal(format, 'openvpn');
      if (mode === 'picker-pending') await new Promise<void>((r) => (releaseRead = r));
      if (mode === 'picker-failure') throw Error('private picker diagnostic');
      return mode === 'picker-cancel' ? null : '/picked/profile.ovpn';
    },
    capabilities: async () => {
      if (mode === 'capabilities-pending') await new Promise<void>((r) => (releaseRead = r));
      if (mode === 'capabilities-failure') throw Error('private probe error');
      return { openVpn: true };
    },
    ipc: { handle: (name: string, handler: any) => handlers.set(name, handler) } as any,
    createWindow: (value) => {
      options = value;
      return child as any;
    },
    confirm: (owner, current) => async (operation, descriptor, submit) => {
      assert.equal(owner, child);
      assert.equal(current(), true);
      assert.equal(operation, 'tunnel-edit');
      assert.equal(descriptor.vaultId, workspace);
      return submit({
        vaultId: workspace,
        slotId: requestId,
        kind: 'password',
        factor: new Uint8Array([1]),
      });
    },
    url: target,
    preload: '/app/tunnel.cjs',
    platform: mode === 'linux' ? 'linux' : 'win32',
  });
  const event: any = { sender: child.webContents, senderFrame: child.webContents.mainFrame };
  return {
    parent,
    child,
    imports,
    discards,
    host,
    dialog,
    event,
    handlers,
    open: (value: any = selection) => dialog.open(parent as any, () => accepted, value),
    deny: () => {
      accepted = false;
    },
    releaseRead: () => releaseRead(),
    releaseSave: () => releaseSave(),
    releaseStop: () => releaseStop(),
    get calls() {
      return calls;
    },
    get stops() {
      return stops;
    },
    get options() {
      return options;
    },
    get submitted() {
      return submitted;
    },
    invoke: (name: string, ...args: unknown[]) =>
      handlers.get('vault-tunnel:' + name)(event, ...args),
  };
}

test('isolated tunnel dialog binds recipient and patch to the opening document and revision', async () => {
  const f = setup('confirm'),
    opened = f.open();
  await tick();
  assert.equal(f.child.shown, true);
  assert.equal(f.child.protected, true);
  assert.equal(f.options.webPreferences.sandbox, true);
  assert.deepEqual(f.options.webPreferences.additionalArguments, ['--wormhole-appearance=oled']);
  assert.equal(f.options.webPreferences.contextIsolation, true);
  assert.equal(f.options.webPreferences.nodeIntegration, false);
  assert.equal(f.options.webPreferences.devTools, false);
  assert.ok(!f.options.webPreferences.partition.startsWith('persist:'));
  const context = f.invoke('context');
  assert.deepEqual(context.selection, selection);
  context.selection.id = 'changed';
  assert.deepEqual(f.invoke('context').selection, selection);
  assert.equal(context.workspaceId, workspace);
  assert.throws(() => f.invoke('context', 1));
  for (const bad of [{}, { ...f.event, sender: {} }, { ...f.event, senderFrame: {} }]) {
    assert.throws(() => f.handlers.get('vault-tunnel:context')(bad));
    await assert.rejects(f.handlers.get('vault-tunnel:read')(bad, publicKey));
    const value = input();
    await assert.rejects(f.handlers.get('vault-tunnel:save')(bad, value));
    assert.ok(value.patch.every((b: number) => b === 0));
    await assert.rejects(f.handlers.get('vault-tunnel:close')(bad));
  }
  await assert.rejects(f.invoke('save', input()), /Invalid/);
  await assert.rejects(f.invoke('read'));
  await assert.rejects(f.invoke('read', publicKey, 1));
  await assert.rejects(f.invoke('read', 'bad'));
  f.child.webContents.mainFrame.url = 'file:///evil';
  assert.throws(() => f.invoke('context'));
  f.child.webContents.mainFrame.url = target;
  assert.equal((await f.invoke('read', publicKey)).tunnelId, id);
  await assert.rejects(f.invoke('read', publicKey), /Invalid/);
  for (const bad of [
    null,
    { ...input(), rowVersion: '2' },
    { ...input(), metadata: { ...input().metadata, id: requestId } },
  ])
    await assert.rejects(f.invoke('save', bad), /Invalid/);
  await assert.rejects(f.invoke('save', input(), 1), /Invalid/);
  await assert.rejects(f.invoke('close', 1), /Invalid/);
  const value = input();
  assert.equal(await f.invoke('save', value), true);
  assert.deepEqual(await opened, saved);
  assert.equal(f.stops, 0);
  assert.ok(value.patch.every((b: number) => b === 0));
  assert.ok(f.submitted.patch.every((b: number) => b === 0));
  assert.equal(f.child.destroyed, true);
  assert.equal(f.parent.listenerCount('closed'), 0);
  assert.equal(f.parent.webContents.listenerCount('did-start-navigation'), 0);
  await f.dialog.cancel();
});

test('draft editor requires an exact draft and closes after one save', async () => {
  const f = setup(),
    opened = f.open(null);
  await tick();
  assert.equal(f.invoke('context').selection, null);
  await assert.rejects(f.invoke('read', publicKey));
  await assert.rejects(f.invoke('save', input()));
  await assert.rejects(f.open(null));
  assert.equal(await f.invoke('save', input(true)), true);
  assert.deepEqual(await opened, saved);
  assert.equal(f.calls, 1);
  await assert.rejects(f.invoke('save', input(true)));
});

test('failed tunnel reads and saves expose fixed errors and clear consumed patches', async () => {
  const read = setup('read-failure'),
    opened = read.open();
  await assert.rejects(
    read.invoke('read', publicKey),
    (error) => !String(error).includes('private'),
  );
  await assert.rejects(read.invoke('save', input()));
  await read.dialog.cancel();
  assert.equal(await opened, null);
  assert.equal(read.stops, 0);
  const f = setup('save-failure'),
    opening = f.open(null);
  for (let i = 0; i < 2; i++) {
    const value = input(true);
    assert.equal(await f.invoke('save', value), false);
    assert.ok(value.patch.every((b: number) => b === 0));
    assert.ok(f.submitted.patch.every((b: number) => b === 0));
  }
  await f.invoke('close');
  assert.equal(await opening, null);
  assert.equal(f.stops, 0);
});

test('tunnel dialog cancels on owner loss, navigation, crash, expiry and load failures', async (t) => {
  for (const mode of [
    'parent-close',
    'parent-navigation',
    'parent-crash',
    'child-navigation',
    'child-crash',
    'child-close',
    'expired',
    'load',
    'protection',
    'linux',
    'denied-loaded',
    'locked-loaded',
  ]) {
    const f = setup(mode);
    if (mode === 'expired') t.mock.timers.enable({ apis: ['setTimeout'] });
    const opened = f.open();
    const checked = ['load', 'protection'].includes(mode) ? assert.rejects(opened) : opened;
    if (mode === 'denied-loaded') f.deny();
    if (mode === 'locked-loaded') f.host.unlockedWorkspaceId = undefined;
    await tick();
    if (mode === 'parent-close') f.parent.destroy();
    if (mode === 'parent-crash') f.parent.webContents.emit('render-process-gone');
    if (mode === 'child-crash') f.child.webContents.emit('render-process-gone');
    if (mode === 'child-close') f.child.destroy();
    if (mode === 'parent-navigation' || mode === 'child-navigation') {
      const contents = mode === 'parent-navigation' ? f.parent.webContents : f.child.webContents;
      contents.emit('did-start-navigation', {}, target, false, false);
      assert.equal(f.child.destroyed, false);
      contents.emit('did-start-navigation', {}, target, false, true);
    }
    if (mode === 'linux') {
      assert.equal(f.child.protected, false);
      await f.dialog.cancel();
    }
    if (mode === 'expired') {
      t.mock.timers.tick(300000);
      t.mock.timers.reset();
    }
    await checked;
    assert.equal(f.child.destroyed, true);
    assert.equal(f.stops, 0);
  }
  for (const mode of ['invalid', 'locked', 'parent', 'denied']) {
    const f = setup();
    if (mode === 'locked') f.host.unlockedWorkspaceId = undefined;
    if (mode === 'parent') f.parent.destroy();
    if (mode === 'denied') f.deny();
    await assert.rejects(f.open(mode === 'invalid' ? {} : selection));
  }
  const f = setup(),
    opened = f.open();
  await tick();
  Object.defineProperty(f.child.webContents, 'mainFrame', {
    get() {
      throw Error('destroyed');
    },
  });
  assert.throws(() => f.invoke('context'));
  await f.dialog.cancel();
  await opened;
});

test('cancellation during save retires the native owner and waits for confirmed exit', async () => {
  for (const mode of ['save-pending', 'stop-pending', 'stop-failure', 'late-save-error']) {
    const f = setup(mode),
      opened = f.open(null);
    const checked =
      mode === 'stop-failure' ? assert.rejects(opened, /shutdown could not be confirmed/) : opened;
    const value = input(true),
      pending = f.invoke('save', value);
    await tick();
    await assert.rejects(f.invoke('save', input(true)), /Invalid/);
    const closing = f.dialog.cancel();
    const again = f.dialog.cancel();
    assert.equal(again, closing);
    await tick();
    assert.equal(f.stops, 1);
    if (mode === 'stop-pending') {
      assert.equal(f.child.destroyed, true);
      await assert.rejects(f.open());
      f.releaseStop();
    }
    await closing;
    await checked;
    f.releaseSave();
    assert.equal(await pending, false);
    assert.equal(f.stops, 1);
    assert.ok(f.submitted.patch.every((b: number) => b === 0));
    assert.ok(value.patch.every((b: number) => b === 0));
    assert.equal(f.child.destroyed, true);
  }
});

test('pending reads cannot authorize save or return after the document is closed', async () => {
  const f = setup('read-pending'),
    opened = f.open();
  const pending = f.invoke('read', publicKey),
    checked = assert.rejects(pending, /unavailable/);
  await assert.rejects(f.invoke('save', input()), /Invalid/);
  await f.dialog.cancel();
  await opened;
  f.releaseRead();
  await checked;
  assert.equal(f.stops, 0);
});

test('authority loss during save also retires an owner when no close event has arrived', async () => {
  const f = setup('save-pending'),
    opened = f.open(null),
    pending = f.invoke('save', input(true));
  await tick();
  f.deny();
  f.releaseSave();
  assert.equal(await pending, false);
  assert.equal(await opened, null);
  assert.equal(f.stops, 1);
});

test('tunnel recipient authenticates every context field and rejects replay, tampering and late open', async () => {
  const context = { workspaceId: workspace, tunnelId: id, requestId, rowVersion: '1' };
  await assert.rejects(createTunnelEditorRecipient({} as any));
  for (const mode of [
    'valid',
    'max',
    'shape',
    'domain',
    'workspaceId',
    'tunnelId',
    'requestId',
    'rowVersion',
    'ciphertext',
    'disposed',
    'late',
  ]) {
    const r = await createTunnelEditorRecipient(context);
    const suite = new CipherSuite({
      kem: new DhkemX25519HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Aes256Gcm(),
    });
    const publicKey = await suite.kem.deserializePublicKey(Buffer.from(r.publicKey, 'base64'));
    const fields = [context.workspaceId, context.tunnelId, context.requestId, context.rowVersion];
    const info = Buffer.concat([
      Buffer.from(mode === 'domain' ? 'wormhole/v1/notes-display' : 'wormhole/v1/tunnel-editor'),
      ...fields.flatMap((value) => {
        const size = Buffer.alloc(4);
        size.writeUInt32BE(value.length);
        return [size, Buffer.from(value)];
      }),
    ]);
    const sender = await suite.createSenderContext({ recipientPublicKey: publicKey, info });
    const plain =
      mode === 'max'
        ? new Uint8Array(512 * 1024).fill(32)
        : new TextEncoder().encode('{"settings":{"Host":"gateway"}}');
    const value: any = {
      ...context,
      bundle: {
        formatVersion: 1,
        suiteId: 2,
        enc: Buffer.from(sender.enc).toString('base64'),
        ciphertext: Buffer.from(await sender.seal(plain)).toString('base64'),
      },
    };
    if (Object.hasOwn(context, mode)) value[mode] = 'wrong';
    if (mode === 'shape') value.extra = true;
    if (mode === 'ciphertext') value.bundle.ciphertext = Buffer.alloc(32).toString('base64');
    if (mode === 'disposed') r.dispose();
    const pending = r.open(value);
    if (mode === 'late') r.dispose();
    if (mode === 'valid' || mode === 'max') {
      const opened = await pending;
      assert.deepEqual(opened, plain);
      opened.fill(0);
    } else await assert.rejects(pending);
    await assert.rejects(r.open(value), /closed/);
    r.dispose();
  }
});

test('notes recipient wipes plaintext if disposed between shared decrypt and purpose validation', async (t) => {
  const context = { workspaceId: workspace, nodeId: id, requestId, rowVersion: '1' };
  const r = await createNotesRecipient(context),
    raw = new TextEncoder().encode('private note');
  t.mock.method(CipherSuite.prototype, 'open', () => Promise.resolve(raw.buffer));
  const pending = r.open({ ...context, bundle });
  queueMicrotask(() => r.dispose());
  await assert.rejects(pending);
  assert.ok(raw.every((byte) => byte === 0));
});

test('tunnel references are public SSH identities bound to the live editor', async () => {
  const f = setup(),
    opened = f.open(null);
  assert.deepEqual(await f.invoke('references'), {
    connections: [{ id, name: 'SSH' }],
    credentials: [{ id: workspace, name: 'Key' }],
    tunnels: [{ id, name: 'SSL' }],
  });
  await assert.rejects(f.invoke('references', true));
  await f.dialog.cancel();
  await opened;
  await assert.rejects(f.invoke('references'));
  for (const mode of ['references-pending', 'references-failure']) {
    const g = setup(mode),
      opening = g.open(null);
    const request = g.invoke('references');
    const rejected = assert.rejects(request, /Tunnel references are unavailable/);
    if (mode === 'references-pending') {
      await tick();
      await g.dialog.cancel();
      g.releaseRead();
    }
    await rejected;
    await g.dialog.cancel();
    await opening;
  }
});

test('protected capability probing fails closed and discards replies after close', async () => {
  for (const mode of ['normal', 'capabilities-failure', 'capabilities-pending']) {
    const f = setup(mode),
      opened = f.open(null);
    await assert.rejects(f.invoke('capabilities', true));
    const pending = f.invoke('capabilities');
    if (mode === 'capabilities-pending') {
      const rejected = assert.rejects(pending, /closed/);
      await tick();
      await f.dialog.cancel();
      f.releaseRead();
      await rejected;
    } else assert.deepEqual(await pending, { openVpn: mode === 'normal' });
    await f.dialog.cancel();
    await opened;
    await assert.rejects(f.invoke('capabilities'));
  }
});

const importChoice = () => ({ importId: requestId, kind: 1, format: 'openvpn', publicKey });
test('protected picker pins imports to main context and attaches only its staged identity on save', async () => {
  const f = setup(),
    opened = f.open(null);
  await tick();
  const ctx = f.invoke('context');
  const result = await f.invoke('import', importChoice());
  assert.deepEqual(f.imports[0], {
    ...importChoice(),
    workspaceId: workspace,
    editorId: ctx.requestId,
    tunnelId: '',
    rowVersion: '0',
    path: '/picked/profile.ovpn',
  });
  assert.equal(result.path, undefined);
  const foreign = input(true);
  foreign.importId = requestId;
  foreign.editorId = requestId;
  await assert.rejects(f.invoke('save', foreign), /Invalid/);
  assert.ok(foreign.patch.every((b: number) => b === 0));
  const changed = input(true);
  changed.metadata.kind = 2;
  await assert.rejects(f.invoke('save', changed), /Invalid/);
  assert.equal(await f.invoke('save', input(true)), true);
  assert.deepEqual(await opened, saved);
  assert.equal(f.submitted.editorId, ctx.requestId);
  assert.equal(f.submitted.importId, requestId);
  assert.equal(f.discards.length, 0);
});
test('imports reject extra paths, wrong senders and unread existing editors; failed selection preserves the form', async () => {
  const f = setup(),
    opened = f.open();
  await tick();
  await assert.rejects(f.invoke('import', importChoice()), /Invalid/);
  await assert.rejects(f.invoke('discard-import'), /Invalid/);
  await f.invoke('read', publicKey);
  for (const bad of [
    null,
    { ...importChoice(), path: '/attacker' },
    { ...importChoice(), kind: 0 },
  ])
    await assert.rejects(f.invoke('import', bad), /Invalid/);
  await assert.rejects(f.invoke('import', importChoice(), 'extra'), /Invalid/);
  await assert.rejects(f.invoke('discard-import', 'extra'), /Invalid/);
  const badEvent = { ...f.event, senderFrame: { url: target } };
  await assert.rejects(f.handlers.get('vault-tunnel:import')(badEvent, importChoice()), /Invalid/);
  await assert.rejects(f.handlers.get('vault-tunnel:discard-import')(badEvent), /Invalid/);
  await f.invoke('import', importChoice());
  assert.equal(f.imports[0].tunnelId, id);
  assert.equal(f.imports[0].rowVersion, '1');
  await f.invoke('discard-import');
  assert.equal(f.discards.length, 1);
  const changed = input();
  changed.metadata.kind = 2;
  assert.equal(await f.invoke('save', changed), true);
  await opened;
  assert.equal(f.submitted.importId, undefined);
  for (const mode of ['picker-cancel', 'picker-failure', 'import-failure']) {
    const v = setup(mode),
      open = v.open(null);
    await tick();
    if (mode === 'picker-cancel') assert.equal(await v.invoke('import', importChoice()), null);
    else
      await assert.rejects(
        v.invoke('import', importChoice()),
        /^Error: The profile could not be imported/,
      );
    await v.invoke('close');
    await open;
    assert.equal(v.stops, 0);
  }
});
test('pending imports exclude mutations and owner cancellation waits for retirement', async () => {
  for (const mode of ['picker-pending', 'import-pending', 'discard-pending']) {
    const f = setup(mode),
      opened = f.open(null);
    await tick();
    const pending =
      mode === 'discard-pending' ? f.invoke('discard-import') : f.invoke('import', importChoice());
    const checked = assert.rejects(pending);
    await tick();
    await assert.rejects(f.invoke('import', importChoice()), /Invalid/);
    await assert.rejects(f.invoke('discard-import'), /Invalid/);
    await assert.rejects(f.invoke('save', input(true)), /Invalid/);
    await f.dialog.cancel();
    assert.equal(f.stops, 1);
    assert.equal(await opened, null);
    f.releaseRead();
    await checked;
    assert.equal(f.imports.length, mode === 'import-pending' ? 1 : 0);
  }
});
test('normal close discards staged imports and failed discard retires the native owner', async () => {
  for (const mode of ['', 'discard-failure']) {
    for (const explicit of [false, true]) {
      const f = setup(mode),
        opened = f.open(null);
      await tick();
      await f.invoke('import', importChoice());
      if (explicit) {
        if (mode) await assert.rejects(f.invoke('discard-import'), /discard failed/);
        else await f.invoke('discard-import');
      }
      await f.dialog.cancel();
      assert.equal(await opened, null);
      assert.equal(f.discards.length, 1);
      assert.equal(f.discards[0].importId, '');
      assert.equal(f.stops, mode ? 1 : 0);
    }
  }
});

test('re-import failure retains the preceding staged identity until a successful replacement', async () => {
  const f = setup(),
    opened = f.open(null);
  await tick();
  await f.invoke('import', importChoice());
  const stage = f.host.stageTunnelImport;
  f.host.stageTunnelImport = async () => {
    throw Error('bad replacement');
  };
  await assert.rejects(
    f.invoke('import', { ...importChoice(), importId: id }),
    /could not be imported/,
  );
  // A failed save must preserve the original import for a fresh-auth retry.
  const edit = f.host.editTunnel;
  f.host.editTunnel = async (value: any) => {
    assert.equal(value.importId, requestId);
    throw Error('save failed');
  };
  assert.equal(await f.invoke('save', input(true)), false);
  f.host.stageTunnelImport = stage;
  await f.invoke('import', { ...importChoice(), importId: id });
  f.host.editTunnel = edit;
  assert.equal(await f.invoke('save', input(true)), true);
  await opened;
  assert.equal(f.submitted.importId, id);
});
