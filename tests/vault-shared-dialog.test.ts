import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { resolve } from 'node:path';
import { VaultSharedAuthenticationDialog } from '../electron/vault-shared-dialog.ts';
import { SharedReenrollmentPending } from '../electron/vault-shared-unlock.ts';
const target = 'file:///app/dist/vault-shared.html';
const tick = () => new Promise(setImmediate);
const vaultId = '11111111-1111-4111-8111-111111111111',
  slotId = '22222222-2222-4222-8222-222222222222';
const metadata = () => ({
  slots: {
    formatVersion: 1,
    vaultId,
    encrypted: true,
    slots: [{ id: slotId, kind: 'password', preset: 'kdf-v1' }],
  },
  cosmetics: { theme: 'system' },
  newWorkspace: false,
  shared: { lastLoginName: 'alice', serverDisplayName: 'Team' },
});
const factors = () => ({
  vaultId,
  slotId,
  password: new Uint8Array([1, 2, 3]),
  ask: new Uint8Array(32).fill(5),
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
function fixture(
  mode = '',
  pickTLSUpdate?: () => Promise<string | null>,
  pickResetOffer?: () => Promise<string | null>,
) {
  const handlers = new Map<string, any>(),
    parent = new Window(),
    child = new Window();
  let accepted = true,
    stops = 0,
    calls = 0,
    borrowed: ReturnType<typeof factors> | undefined;
  let release: (value?: unknown) => void = () => {};
  let windowOptions: any;
  let tlsUpdatePath: string | undefined;
  const invoke = async (
    value: ReturnType<typeof factors>,
    version: string,
    current: () => boolean,
  ) => {
    borrowed = value;
    calls++;
    assert.equal(version, '2.2.0');
    assert.equal(current(), true);
    assert.deepEqual([...value.password], [1, 2, 3]);
    assert.ok(value.ask.every((n) => n === 5));
    assert.deepEqual(Object.keys(value).sort(), ['ask', 'password', 'slotId', 'vaultId']);
    if (mode === 'wrong' && calls === 1) throw Error('private error');
    if (mode === 'completed') throw Error('lost admission response');
    if (mode === 'stale') accepted = false;
    if (['pending', 'stop-error'].includes(mode))
      await new Promise((resolve) => {
        release = resolve;
      });
  };
  if (mode === 'load') child.loadError = true;
  if (mode === 'protection') child.protectionWorks = false;
  const dialog = new VaultSharedAuthenticationDialog({
    ipc: {
      handle: (name, fn) => {
        handlers.set(name, fn);
      },
    } as any,
    createWindow: (options) => {
      windowOptions = options;
      return child as any;
    },
    host: {
      startup: async () => {
        if (mode === 'initial-clean')
          return { slots: null, cosmetics: { theme: 'system' }, newWorkspace: true } as any;
        const value: any = metadata();
        if (mode !== 'completed') {
          value.sharedJoin = value.shared;
          delete value.shared;
        }
        return value;
      },
      sharedUnlock: async (value, version, current, path) => {
        await invoke(value as any, version, current);
        tlsUpdatePath = path;
        return { admitted: true, lockedMemory: false, orgEscrow: true, tls: 'off' };
      },
      sharedRecoverPassword: async (value, version, current) => {
        await invoke(value as any, version, current);
        return { recovered: true };
      },
      sharedRecoverEnrollment: async (value, version, current) => {
        await invoke(value as any, version, current);
        if (mode === 'reset-recovery' && calls === 1) throw new SharedReenrollmentPending();
        return { admitted: true, lockedMemory: false, orgEscrow: true, tls: 'off' };
      },
      sharedContinueEnrollment: async (value: any, version, current) => {
        const { code, acknowledgeTLSOff, ...factors } = value;
        assert.ok(code.every((n: number) => n === 6));
        assert.equal(acknowledgeTLSOff, true);
        await invoke(factors as any, version, current);
        return { admitted: true, lockedMemory: true, orgEscrow: true, tls: 'off' };
      },
      sharedJoinInitial: async (value: any, version: string, current: () => boolean) => {
        borrowed = value;
        calls++;
        assert.equal(version, '2.2.0');
        assert.equal(current(), true);
        assert.ok(value.code.every((n: number) => n === 6));
        assert.deepEqual(Object.keys(value).sort(), [
          'acknowledgeTLSOff',
          'ask',
          'code',
          'deviceName',
          'invitation',
          'password',
        ]);
        if (mode === 'initial-unknown' || mode === 'initial-clean') throw Error('lost response');
        if (mode === 'initial-pending')
          await new Promise((resolve) => {
            release = resolve;
          });
        return { admitted: true, lockedMemory: true, orgEscrow: true, tls: 'off' };
      },
      sharedRedeemAccountReset: async (path, value: any, version, current) => {
        assert.equal(path, resolve('selected.whreset'));
        assert.equal(version, '2.2.0');
        assert.equal(current(), true);
        assert.ok(value.code.every((byte: number) => byte === 6));
        assert.ok(value.ask.every((byte: number) => byte === 5));
        borrowed = value;
        calls++;
        if (mode === 'reset-awaiting') throw new SharedReenrollmentPending();
        return { admitted: true, lockedMemory: true, orgEscrow: true, tls: 'verified' };
      },
      inspectSharedInvitation: async (invitation: string, current: () => boolean) => {
        assert.equal(current(), true);
        if (mode === 'initial-reader-pending')
          await new Promise((resolve) => {
            release = resolve;
          });
        return { invitation, workspaceId: vaultId, loginName: 'alice', tls: 'off' } as any;
      },
      readSharedInvitationFile: async (path: string, current: () => boolean) => {
        assert.equal(path, 'C:\\selected.whinv');
        assert.equal(current(), true);
        return {
          invitation: 'WHINV2-file',
          workspaceId: vaultId,
          loginName: 'alice',
          tls: 'verified',
        };
      },
      stop: async () => {
        stops++;
        if (mode === 'stop-error') throw Error('private diagnostic');
      },
    },
    url: target,
    preload: 'vault-shared-preload.cjs',
    appVersion: '2.2.0',
    platform: 'win32',
    pickInvitation: async () => {
      if (mode === 'initial-file-cancel') return null;
      if (mode === 'initial-file-pending')
        await new Promise((resolve) => {
          release = resolve;
        });
      return 'C:\\selected.whinv';
    },
    pickTLSUpdate,
    pickResetOffer,
  });
  const event = { sender: child.webContents, senderFrame: child.webContents.mainFrame };
  return {
    dialog,
    parent,
    child,
    handlers,
    event,
    release: () => release(),
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
    get tlsUpdatePath() {
      return tlsUpdatePath;
    },
    get windowOptions() {
      return windowOptions;
    },
    open: (
      kind: 'admit' | 'recover-password' | 'recover-enrollment' | 'join-initial' = 'admit',
      startup: any = metadata(),
    ) => dialog.open(parent as any, () => accepted, kind, startup as any),
    call: (name: string, ...args: unknown[]) =>
      handlers.get('vault-shared:' + name)(event, ...args),
  };
}
const fresh = () => ({ slots: null, cosmetics: { theme: 'system' }, newWorkspace: true });

for (const mode of ['tighten-profile', 'trust-ssh-host', 'edit-shared-node'] as const)
  test(
    mode + ' uses the protected device prompt and permits retry after a rejected factor',
    async () => {
      const f = fixture();
      let attempts = 0;
      const result = f.dialog.open(
        f.parent as any,
        () => true,
        mode,
        metadata() as any,
        async (input, current) => {
          assert.equal(current(), true);
          assert.equal(input.vaultId, vaultId);
          assert.equal(input.slotId, slotId);
          assert.ok(input.ask?.every((byte) => byte === 5));
          if (++attempts === 1) throw Error('Incorrect factor');
          return true;
        },
      );
      await tick();
      assert.equal((await f.call('context')).mode, mode);
      assert.equal(f.child.protected, true);
      for (const success of [false, true]) {
        const input = factors();
        assert.equal(await f.call('submit', input), success);
        assert.ok(
          input.password.every((byte) => byte === 0) && input.ask.every((byte) => byte === 0),
        );
        assert.equal(f.child.destroyed, success);
      }
      assert.equal(await result, true);
      assert.equal(f.calls, 0);
    },
  );

test('retiring the SSH route closes only its pending device prompt', async () => {
  const f = fixture(),
    route = new AbortController();
  const open = () =>
    f.dialog.open(
      f.parent as any,
      () => true,
      'trust-ssh-host',
      metadata() as any,
      async () => assert.fail('retired route requested verification'),
      route.signal,
    );
  const pending = open();
  await tick();
  route.abort();
  assert.equal(await pending, null);
  assert.ok(f.child.destroyed);
  await assert.rejects(open());
  assert.equal(f.calls, 0);
});

test('reset file selection is scoped to the original protected document', async () => {
  const path = resolve('selected.whreset');
  let picked: string | null = path;
  const f = fixture('initial-clean', undefined, async () => picked);
  const outcome = f.open('join-initial', fresh());
  const input = () => ({
    kind: 'account-reset',
    code: new Uint8Array(16).fill(6),
    ask: new Uint8Array(32).fill(5),
    password: new Uint8Array([1, 2, 3]),
    deviceName: 'Device',
  });
  const noFile = input();
  await assert.rejects(f.call('submit', noFile));
  assert.ok(
    [noFile.code, noFile.ask, noFile.password].every((bytes) => bytes.every((b) => b === 0)),
  );
  await assert.rejects(f.call('open-reset-offer', path));
  assert.equal(await f.call('open-reset-offer'), true);
  const injected = { ...input(), offerPath: path };
  await assert.rejects(f.call('submit', injected));
  assert.equal(f.calls, 0);
  picked = null;
  assert.equal(await f.call('open-reset-offer'), false);
  await assert.rejects(f.call('submit', input()));
  picked = resolve('selected.txt');
  await assert.rejects(f.call('open-reset-offer'));
  picked = path;
  assert.equal(await f.call('open-reset-offer'), true);
  assert.equal(await f.call('submit', input()), true);
  assert.equal(f.calls, 1);
  assert.deepEqual(await outcome, {
    admitted: true,
    lockedMemory: true,
    orgEscrow: true,
    tls: 'verified',
  });
  assert.ok(f.borrowed?.password.every((b) => b === 0));
  await assert.rejects(f.call('open-reset-offer'));
});

test('protected reset registration stays locked and can be resumed after activation', async () => {
  const initial = fixture('reset-awaiting', undefined, async () => resolve('selected.whreset'));
  const pending = initial.open('join-initial', fresh());
  const input = {
    kind: 'account-reset',
    code: new Uint8Array(16).fill(6),
    ask: new Uint8Array(32).fill(5),
    password: new Uint8Array([1, 2, 3]),
    deviceName: 'Device',
  };
  assert.equal(await initial.call('open-reset-offer'), true);
  assert.equal(await initial.call('submit', input), 'awaiting-activation');
  assert.equal(initial.child.destroyed, false);
  assert.ok([input.password, input.code, input.ask].every((bytes) => bytes.every((b) => b === 0)));
  await assert.rejects(initial.call('submit', input));
  await initial.call('cancel');
  assert.equal(await pending, null);

  const recovery = fixture('reset-recovery');
  const { shared, ...m } = metadata();
  const result = recovery.open('recover-enrollment', {
    ...m,
    sharedJoin: { ...shared, canContinue: true, accountReset: true },
  });
  assert.equal(await recovery.call('submit', factors()), 'awaiting-activation');
  assert.equal(recovery.child.destroyed, false);
  assert.equal(await recovery.call('submit', factors()), true);
  assert.equal((await result)?.admitted, true);
});

test('trust update selection stays in main and is bound to the live admission dialog', async () => {
  const path = resolve('selected.whtls');
  let selected: string | null = path;
  let calls = 0;
  const f = fixture('', async () => {
    calls++;
    return selected;
  });
  const admission = f.open();
  await tick();
  await assert.rejects(f.call('tls-update', 'choose', path));
  await assert.rejects(f.call('tls-update', path));
  await assert.rejects(
    f.handlers.get('vault-shared:tls-update')(
      { sender: f.parent.webContents, senderFrame: f.parent.webContents.mainFrame },
      'choose',
    ),
  );
  assert.equal(calls, 0);
  assert.equal(await f.call('tls-update', 'choose'), true);
  selected = null;
  assert.equal(await f.call('tls-update', 'choose'), true);
  assert.equal(await f.call('tls-update', 'clear'), false);
  assert.equal(await f.call('tls-update', 'choose'), false);
  selected = resolve('unexpected.json');
  await assert.rejects(f.call('tls-update', 'choose'));
  selected = path;
  assert.equal(await f.call('tls-update', 'choose'), true);
  const forged = { ...factors(), tlsUpdatePath: resolve('attacker.whtls') };
  await assert.rejects(f.call('submit', forged));
  assert.ok(forged.password.every((n) => n === 0));
  assert.equal(await f.call('submit', factors()), true);
  assert.equal((await admission)?.admitted, true);
  assert.equal(f.tlsUpdatePath, path);

  let finishPick!: (value: string | null) => void;
  const pending = fixture('', () => new Promise((resolve) => (finishPick = resolve)));
  const interrupted = pending.open();
  await tick();
  const selection = pending.call('tls-update', 'choose');
  await assert.rejects(pending.call('submit', factors()));
  pending.deny();
  finishPick(path);
  await assert.rejects(selection);
  await pending.dialog.cancel();
  assert.equal(await interrupted, null);

  const recovery = fixture('', async () => path);
  const recovering = recovery.open('recover-password');
  await tick();
  await assert.rejects(recovery.call('tls-update', 'choose'));
  await recovery.dialog.cancel();
  assert.equal(await recovering, null);
});
test('only a continuation-capable pending selection accepts code in the protected recovery dialog', async () => {
  for (const allowed of [false, true]) {
    const f = fixture(),
      m: any = metadata();
    m.sharedJoin = { ...m.shared, ...(allowed ? { canContinue: true } : {}) };
    delete m.shared;
    const result = f.open('recover-enrollment', m);
    await tick();
    const input = { ...factors(), code: new Uint8Array(16).fill(6), acknowledgeTLSOff: true };
    if (allowed) {
      assert.equal(await f.call('submit', input), true);
      assert.equal((await result)?.admitted, true);
      assert.equal(f.calls, 1);
    } else {
      await assert.rejects(f.call('submit', input));
      assert.equal(f.calls, 0);
      await f.dialog.cancel();
      await result;
    }
    assert.ok(input.code.every((n) => n === 0));
    assert.ok(input.password.every((n) => n === 0));
  }
});
const initialFactors = () => ({
  invitation: 'WHINV2-public',
  code: new Uint8Array(16).fill(6),
  password: new Uint8Array([1, 2, 3]),
  ask: new Uint8Array(32).fill(5),
  deviceName: 'Device',
  acknowledgeTLSOff: true,
});

test('initial invitation dialog keeps paths in main and admits through the fixed protected operation', async () => {
  const f = fixture('initial'),
    result = f.open('join-initial', fresh());
  await tick();
  assert.equal(f.call('context').mode, 'join-initial');
  assert.equal(f.windowOptions.height, 840);
  const inspected = await f.call('invitation', 'WHINV2-public');
  assert.equal(inspected.tls, 'off');
  const file = await f.call('open-invitation');
  assert.equal(file.invitation, 'WHINV2-file');
  assert.equal(file.path, undefined);
  await assert.rejects(f.call('invitation', 'token', 'extra'));
  await assert.rejects(f.call('open-invitation', 'C:\\attacker'));
  const refused = initialFactors();
  await assert.rejects(
    f.handlers.get('vault-shared:submit')(
      { sender: f.parent.webContents, senderFrame: f.parent.webContents.mainFrame },
      refused,
    ),
  );
  assert.ok(
    refused.code.every((n) => n === 0) &&
      refused.password.every((n) => n === 0) &&
      refused.ask.every((n) => n === 0),
  );
  const input = initialFactors();
  assert.equal(await f.call('submit', input), true);
  assert.deepEqual(await result, {
    admitted: true,
    lockedMemory: true,
    orgEscrow: true,
    tls: 'off',
  });
  assert.ok(
    input.code.every((n) => n === 0) && (f.borrowed as any).code.every((n: number) => n === 0),
  );
});

test('initial invitation unknown outcomes close the form for native startup recovery and clean failures permit retry', async () => {
  for (const mode of ['initial-unknown', 'initial-clean']) {
    const f = fixture(mode),
      result = f.open('join-initial', fresh());
    await tick();
    assert.equal(await f.call('submit', initialFactors()), false);
    if (mode === 'initial-unknown') {
      assert.equal(await result, null);
      assert.equal(f.stops, 1);
    } else {
      assert.equal(f.child.destroyed, false);
      await f.dialog.cancel();
      assert.equal(await result, null);
    }
  }
});

test('initial invitation cancellation erases in-flight code and rejects late file or metadata responses', async () => {
  for (const mode of [
    'initial-pending',
    'initial-reader-pending',
    'initial-file-pending',
    'initial-file-cancel',
  ]) {
    const f = fixture(mode),
      result = f.open('join-initial', fresh());
    await tick();
    const call =
      mode === 'initial-pending'
        ? f.call('submit', initialFactors())
        : mode === 'initial-reader-pending'
          ? f.call('invitation', 'WHINV2-public')
          : f.call('open-invitation');
    void call.catch(() => undefined);
    await tick();
    if (mode === 'initial-file-cancel') {
      assert.equal(await call, null);
      await f.dialog.cancel();
      assert.equal(await result, null);
      continue;
    }
    await f.dialog.cancel();
    assert.equal(await result, null);
    assert.equal(f.stops, 1);
    if (mode === 'initial-pending')
      assert.ok((f.borrowed as any).code.every((n: number) => n === 0));
    f.release();
    if (mode === 'initial-reader-pending') await assert.rejects(call);
    else assert.equal(await call, mode === 'initial-pending' ? false : null);
  }
  const ordinary = fixture(),
    result = ordinary.open();
  await tick();
  await assert.rejects(ordinary.call('invitation', 'WHINV2-public'));
  await assert.rejects(ordinary.call('open-invitation'));
  const input = initialFactors();
  await assert.rejects(ordinary.call('submit', input));
  assert.ok(input.code.every((n) => n === 0));
  await ordinary.dialog.cancel();
  assert.equal(await result, null);
});

test('completed enrollment after a lost reply closes the stale fixed-mode dialog for a fresh sign-in', async () => {
  const f = fixture('completed'),
    startup: any = metadata();
  startup.sharedJoin = startup.shared;
  delete startup.shared;
  const result = f.open('recover-enrollment', startup);
  await tick();
  assert.equal(await f.call('submit', factors()), false);
  assert.equal(await result, null);
  assert.equal(f.child.destroyed, true);
  assert.equal(f.stops, 1);
  assert.ok(f.borrowed!.password.every((b) => b === 0) && f.borrowed!.ask.every((b) => b === 0));
});

test('shared dialog confines factors and fixed operation to its isolated document', async () => {
  for (const kind of ['admit', 'recover-password', 'recover-enrollment'] as const) {
    const f = fixture('wrong'),
      startup: any = metadata(),
      hints = kind === 'recover-enrollment' ? 'sharedJoin' : 'shared';
    if (kind === 'recover-enrollment') {
      startup.sharedJoin = startup.shared;
      delete startup.shared;
    }
    const result = f.open(kind, startup);
    startup[hints].lastLoginName = 'mutated';
    await tick();
    assert.ok(f.child.protected && f.child.shown);
    assert.equal(f.windowOptions.webPreferences.sandbox, true);
    assert.equal(f.windowOptions.webPreferences.nodeIntegration, false);
    assert.ok(!f.windowOptions.webPreferences.partition.startsWith('persist:'));
    assert.equal(f.call('context').startup[hints].lastLoginName, 'alice');
    assert.equal(f.call('context').mode, kind);
    assert.throws(() => f.call('context', {}));
    await assert.rejects(f.open());
    for (const event of [
      { sender: f.parent.webContents, senderFrame: f.parent.webContents.mainFrame },
      { sender: f.child.webContents, senderFrame: { url: target } },
    ]) {
      const input = factors();
      await assert.rejects(f.handlers.get('vault-shared:submit')(event, input));
      assert.ok(input.password.every((n) => n === 0) && input.ask.every((n) => n === 0));
    }
    for (const extra of [
      { vaultId: slotId },
      { slotId: vaultId },
      { appVersion: 'attacker' },
      {},
    ]) {
      const input = { ...factors(), ...extra };
      if (Object.keys(extra).length) await assert.rejects(f.call('submit', input));
      else assert.equal(await f.call('submit', input), false);
      assert.ok(input.password.every((n) => n === 0) && input.ask.every((n) => n === 0));
    }
    await assert.rejects(f.call('cancel', {}));
    assert.equal(await f.call('submit', factors()), true);
    assert.deepEqual(
      await result,
      kind !== 'recover-password'
        ? { admitted: true, lockedMemory: false, orgEscrow: true, tls: 'off' }
        : { recovered: true },
    );
    assert.ok(f.borrowed!.password.every((n) => n === 0) && f.borrowed!.ask.every((n) => n === 0));
    assert.ok(f.child.destroyed);
    assert.equal(f.stops, 0);
    await f.dialog.cancel();
  }
});
test('shared dialog cancels stale and pending requests, consumes factors and never reports local unlock', async () => {
  for (const mode of [
    'cancel',
    'parent',
    'child',
    'navigate',
    'reload',
    'load',
    'protection',
    'pending',
    'stop-error',
    'stale',
  ]) {
    const f = fixture(mode),
      result = f.open();
    const checked =
      mode === 'stop-error' ? assert.rejects(result, /cleanup could not be confirmed/) : result;
    await tick();
    let submission: Promise<unknown> | undefined;
    if (['pending', 'stop-error', 'stale'].includes(mode)) {
      submission = f.call('submit', factors());
      await tick();
      if (mode !== 'stale') await assert.rejects(f.call('submit', factors()));
    }
    if (mode === 'parent') f.parent.destroy();
    else if (mode === 'child') f.child.destroy();
    else if (mode === 'navigate')
      f.parent.webContents.emit('did-start-navigation', {}, target, false, true);
    else if (mode === 'reload')
      f.child.webContents.emit('did-start-navigation', {}, target, false, true);
    else await f.dialog.cancel();
    if (submission) {
      assert.ok(
        f.borrowed!.password.every((n) => n === 0) && f.borrowed!.ask.every((n) => n === 0),
      );
      f.release();
      assert.equal(await submission, false);
      assert.equal(f.stops, 1);
    }
    if (mode === 'stop-error') await checked;
    else assert.equal(await checked, null);
    assert.ok(f.child.destroyed);
  }
  const f = fixture();
  f.deny();
  await assert.rejects(f.open());
  const g = fixture();
  await assert.rejects(g.open('admit', { ...metadata(), shared: undefined } as any));
  await assert.rejects(
    g.open('admit', { ...metadata(), slots: { ...metadata().slots, slots: [] } }),
  );
  await assert.rejects(g.open('invalid' as any));
});
