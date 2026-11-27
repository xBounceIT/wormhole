import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { VaultMigrationSetupDialog } from '../electron/vault-migration-setup-dialog.ts';
const target = 'file:///app/dist/vault-create.html';
const response = {
  enrollmentId: '11111111-1111-4111-8111-111111111111',
  vaultId: '22222222-2222-4222-8222-222222222222',
  groups: [1, 2],
  bundle: {},
};
const begin = () => ({
  legacyMethod: 'password',
  legacyFactor: new Uint8Array([4, 5, 6]),
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
function setup(mode = '', rotation = false, upgrade = false, osMigration = false) {
  const handlers = new Map<string, any>(),
    parent = new Window(),
    child = new Window();
  let accepted = true,
    stops = 0,
    options: any;
  const host: any = {
    isVaultWorkspace: false,
    unlockedWorkspaceId: undefined,
    migrationSetupContext: async () => ({ methods: ['password', 'pin'] }),
    beginMigrationSetup: async () => response,
    confirmMigrationSetup: async () => ({
      prepared: true,
      restartRequired: true,
      vaultId: response.vaultId,
    }),
    stop: async () => {
      stops++;
      host.unlockedWorkspaceId = undefined;
      if (mode === 'stop-error') throw Error('private diagnostic');
    },
  };
  if (rotation) {
    host.isVaultWorkspace = true;
    host.unlockedWorkspaceId = response.vaultId;
    host.rootRotationSetupContext = async () => ({
      slots: {
        formatVersion: 1,
        vaultId: response.vaultId,
        encrypted: false,
        slots: [{ id: response.enrollmentId, kind: 'password', preset: 'kdf-v1' }],
      },
    });
    host.beginRootRotationSetup = host.beginMigrationSetup;
    host.confirmRootRotationSetup = async () => {
      host.unlockedWorkspaceId = undefined;
      return { prepared: true, restartRequired: true, vaultId: response.vaultId };
    };
  }
  if (upgrade) {
    host.isVaultWorkspace = true;
    host.upgradeSetupContext = async () => ({ vaultId: response.vaultId });
    host.beginUpgradeSetup = host.beginMigrationSetup;
    host.confirmUpgradeSetup = host.confirmMigrationSetup;
  }
  if (osMigration) {
    host.osMigrationContext = host.migrationSetupContext;
    host.prepareOSMigration = async () => ({
      prepared: true,
      restartRequired: true,
      vaultId: response.vaultId,
    });
  }
  if (mode === 'load-error') child.loadError = true;
  if (mode === 'no-protection') child.protectionWorks = false;
  const dialog = new VaultMigrationSetupDialog({
    mode: osMigration ? 'os-migration' : upgrade ? 'upgrade' : rotation ? 'rotation' : 'migration',
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
  });
  const event = { sender: child.webContents, senderFrame: child.webContents.mainFrame };
  return {
    dialog,
    parent,
    child,
    host,
    event,
    handlers,
    open: (encryptDatabase = false) => dialog.open(parent as any, () => accepted, encryptDatabase),
    deny: () => (accepted = false),
    get stops() {
      return stops;
    },
    get options() {
      return options;
    },
    call: (name: string, ...args: any[]) =>
      handlers.get(
        (osMigration
          ? 'vault-os-migration-setup:'
          : upgrade
            ? 'vault-upgrade-setup:'
            : rotation
              ? 'vault-rotation-setup:'
              : 'vault-migration-setup:') + name,
      )(event, ...args),
  };
}

test('OS migration dialog verifies only old proof and joins preparation exit without enrollment or activation', async () => {
  for (const mode of ['', 'cancel', 'late-navigation', 'native-error', 'duplicate', 'late-owner']) {
    const f = setup('', false, false, true),
      result = f.open(),
      wait = deferred();
    await tick();
    assert.deepEqual(await f.call('context'), { methods: ['password', 'pin'] });
    assert.equal(f.handlers.has('vault-os-migration-setup:confirm'), false);
    let proof: Uint8Array | undefined;
    f.host.prepareOSMigration = async (input: any) => {
      proof = input.legacyFactor;
      if (mode === 'native-error') throw Error('private');
      if (mode === 'duplicate' || mode === 'late-navigation') await wait.promise;
      if (mode === 'late-owner') f.host.unlockedWorkspaceId = response.vaultId;
      return { prepared: true, restartRequired: true, vaultId: response.vaultId };
    };
    const input = () => ({ legacyMethod: 'pin', legacyFactor: new Uint8Array([1, 2, 3]) });
    const wrong = input();
    await assert.rejects(
      f.handlers.get('vault-os-migration-setup:begin')({ sender: f.parent.webContents }, wrong),
    );
    assert.ok(wrong.legacyFactor.every((b) => b === 0));
    if (mode === 'cancel') await f.call('cancel');
    else {
      const value = input(),
        pending = f.call('begin', value);
      if (mode === 'duplicate') {
        await assert.rejects(f.call('begin', input()));
        await assert.rejects(f.call('context'));
        wait.resolve(undefined);
      } else if (mode === 'late-navigation') {
        f.parent.webContents.emit('did-start-navigation', {}, target, false, true);
        wait.resolve(undefined);
      }
      if (mode === 'native-error' || mode === 'late-navigation') await assert.rejects(pending);
      else await pending;
      assert.ok(value.legacyFactor.every((b) => b === 0));
      assert.ok(proof!.every((b) => b === 0));
      if (mode === 'native-error') await f.call('cancel');
    }
    assert.equal(await result, mode === '' || mode === 'duplicate');
    assert.equal(f.stops, 1);
    assert.equal(f.child.destroyed, true);
    assert.equal(f.host.unlockedWorkspaceId, undefined);
  }
});

test('ownerless upgrade dialog requires its bound source context and never activates an owner', async () => {
  for (const mode of ['success', 'wrong-source', 'cancel', 'navigation']) {
    const f = setup('', false, true),
      result = f.open();
    await tick();
    const input = () => ({ password: new Uint8Array([1]), publicKey: new Uint8Array(32).fill(4) });
    await assert.rejects(f.call('begin', input()));
    assert.deepEqual(await f.call('context'), { vaultId: response.vaultId });
    if (mode === 'wrong-source') {
      f.host.beginUpgradeSetup = async () => ({ ...response, vaultId: response.enrollmentId });
      await assert.rejects(f.call('begin', input()));
    } else {
      await f.call('begin', input());
      if (mode === 'cancel') await f.call('cancel');
      else if (mode === 'navigation')
        f.parent.webContents.emit('did-start-navigation', {}, target, false, true);
      else await f.call('confirm', confirm());
    }
    assert.equal(await result, mode === 'success');
    assert.equal(f.host.unlockedWorkspaceId, undefined);
    assert.equal(f.stops, 1);
    assert.equal(f.child.destroyed, true);
  }
});

test('migration setup uses only its protected dialog, wipes proof and stops without activating', async () => {
  const f = setup(),
    result = f.open();
  await tick();
  assert.ok(f.child.shown && f.child.protected);
  assert.ok(!f.options.webPreferences.partition.startsWith('persist:'));
  assert.deepEqual(await f.call('context'), { methods: ['password', 'pin'] });
  await assert.rejects(f.call('context', 1));
  await assert.rejects(f.open());
  for (const event of [
    { sender: f.parent.webContents, senderFrame: f.parent.webContents.mainFrame },
    { sender: f.child.webContents, senderFrame: { url: target } },
  ]) {
    const input = begin();
    await assert.rejects(f.handlers.get('vault-migration-setup:begin')(event, input));
    for (const key of ['password', 'publicKey', 'legacyFactor'] as const)
      assert.ok(input[key].every((x) => x === 0));
  }
  await assert.rejects(f.call('confirm', confirm()));
  await assert.rejects(f.call('cancel', 1));
  const input = begin();
  await f.call('begin', input);
  for (const key of ['password', 'publicKey', 'legacyFactor'] as const)
    assert.ok(input[key].every((x) => x === 0));
  await assert.rejects(f.call('context'));
  await assert.rejects(f.call('begin', begin()));
  await assert.rejects(f.call('confirm', { ...confirm(), enrollmentId: response.vaultId }));
  const proof = confirm();
  await f.call('confirm', proof);
  assert.ok(proof.groups.every((x) => x === 0));
  assert.equal(await result, true);
  assert.equal(f.stops, 1);
  assert.equal(f.host.unlockedWorkspaceId, undefined);
  assert.equal(f.dialog.active, false);
  await f.dialog.cancel();
});

test('root setup binds current factors to captured slots and retires after confirmation', async () => {
  const f = setup('', true),
    result = f.open();
  await tick();
  const request = () => ({
    password: new Uint8Array([1, 2, 3]),
    publicKey: new Uint8Array(32).fill(4),
    authentication: {
      vaultId: response.vaultId,
      slotId: response.enrollmentId,
      kind: 'password',
      factor: new Uint8Array([6, 7]),
    },
  });
  await assert.rejects(f.call('begin', request()));
  const context = await f.call('context');
  assert.equal(context.slots.vaultId, response.vaultId);
  for (const key of ['vaultId', 'slotId', 'kind']) {
    const value = request();
    (value.authentication as any)[key] = key === 'kind' ? 'recovery-code' : response.vaultId;
    if (key === 'vaultId') value.authentication.vaultId = response.enrollmentId;
    await assert.rejects(f.call('begin', value));
    assert.ok(value.authentication.factor.every((x) => x === 0));
    assert.ok(value.password.every((x) => x === 0));
  }
  const input = request();
  await f.call('begin', input);
  assert.ok(input.authentication.factor.every((x) => x === 0));
  await assert.rejects(f.call('context'));
  const proof = confirm();
  await f.call('confirm', proof);
  assert.equal(await result, true);
  assert.equal(f.stops, 1);
  assert.ok(proof.groups.every((x) => x === 0));
});

test('only the main-owned database encryption dialog can select conversion', async () => {
  const f = setup('', true),
    result = f.open(true);
  await tick();
  assert.equal(f.options.title, 'Encrypt the vault database');
  const request = () => ({
    password: new Uint8Array([1, 2, 3]),
    publicKey: new Uint8Array(32).fill(4),
    authentication: {
      vaultId: response.vaultId,
      slotId: response.enrollmentId,
      kind: 'password',
      factor: new Uint8Array([6, 7]),
    },
  });
  const context = f.host.rootRotationSetupContext;
  f.host.rootRotationSetupContext = async () => ({
    slots: { ...(await context()).slots, vaultId: response.enrollmentId },
  });
  await assert.rejects(f.call('context'), /context changed/);
  f.host.rootRotationSetupContext = async () => ({
    slots: { ...(await context()).slots, encrypted: true },
  });
  await assert.rejects(f.call('context'), /context changed/);
  f.host.rootRotationSetupContext = context;
  assert.deepEqual(await f.call('context'), { ...(await context()), encryptDatabase: true });
  const forged = { ...request(), encryptDatabase: false };
  await assert.rejects(f.call('begin', forged));
  assert.ok(forged.authentication.factor.every((x) => x === 0));
  assert.ok(forged.password.every((x) => x === 0));
  f.host.beginRootRotationSetup = async (_input: unknown, encryptDatabase: boolean) => {
    assert.equal(encryptDatabase, true);
    return response;
  };
  await f.call('begin', request());
  await f.call('confirm', confirm());
  assert.equal(await result, true);
  await assert.rejects(setup().open(true));
});

test('root setup cancels pending operations and refuses shared or locked owners', async () => {
  for (const mode of ['cancel', 'navigation', 'late-context']) {
    const f = setup('', true),
      result = f.open();
    await tick();
    let pending: ReturnType<typeof deferred> | undefined, rejected: Promise<unknown> | undefined;
    if (mode === 'late-context') {
      pending = deferred();
      f.host.rootRotationSetupContext = () => pending!.promise;
      rejected = assert.rejects(f.call('context'), /closed/);
      await assert.rejects(f.call('context'));
    }
    if (mode === 'navigation')
      f.parent.webContents.emit('did-start-navigation', {}, target, false, true);
    else await f.dialog.cancel();
    assert.equal(await result, false);
    if (pending) {
      pending.resolve({ slots: {} });
      await rejected;
    }
    assert.equal(f.stops, 1);
  }
  const f = setup('', true);
  f.host.isSharedWorkspace = true;
  await assert.rejects(f.open());
  f.host.isSharedWorkspace = false;
  f.host.unlockedWorkspaceId = undefined;
  await assert.rejects(f.open());
});
test('migration setup retires on navigation, lost owner, load error and failed cleanup', async () => {
  for (const mode of [
    'cancel',
    'parent-close',
    'parent-navigation',
    'parent-gone',
    'child-gone',
    'child-reload',
    'load-error',
    'no-protection',
    'lost-parent',
    'stop-error',
    'linux',
  ]) {
    const f = setup(mode),
      result = f.open();
    const checked = mode === 'stop-error' ? assert.rejects(result, /shutdown/) : result;
    await tick();
    if (['cancel', 'stop-error', 'linux'].includes(mode)) await f.call('cancel');
    if (mode === 'parent-close') f.parent.destroy();
    if (mode === 'parent-navigation') {
      f.parent.webContents.emit('did-start-navigation', {}, target, false, false);
      assert.ok(f.dialog.active);
      f.parent.webContents.emit('did-start-navigation', {}, target, false, true);
    }
    if (mode === 'parent-gone') f.parent.webContents.emit('render-process-gone');
    if (mode === 'child-gone') f.child.webContents.emit('render-process-gone');
    if (mode === 'child-reload')
      f.child.webContents.emit('did-start-navigation', {}, target, false, true);
    if (mode === 'lost-parent') {
      f.deny();
      await assert.rejects(f.call('context'));
      await f.dialog.cancel();
    }
    const outcome = await checked;
    if (mode !== 'stop-error') assert.equal(outcome, false);
    assert.equal(f.stops, 1);
    assert.ok(f.child.destroyed);
    assert.equal(f.parent.webContents.listenerCount('did-start-navigation'), 0);
  }
  const f = setup();
  f.host.isVaultWorkspace = true;
  await assert.rejects(f.open());
  f.host.isVaultWorkspace = false;
  f.parent.destroy();
  await assert.rejects(f.open());
});
test('late and overlapping context, begin and confirmation cannot revive a retired dialog', async () => {
  for (const operation of ['context', 'begin', 'confirm']) {
    const f = setup(),
      result = f.open();
    await tick();
    if (operation === 'confirm') await f.call('begin', begin());
    const pending = deferred();
    f.host[
      operation === 'context'
        ? 'migrationSetupContext'
        : operation === 'begin'
          ? 'beginMigrationSetup'
          : 'confirmMigrationSetup'
    ] = () => pending.promise;
    const args = operation === 'context' ? [] : [operation === 'begin' ? begin() : confirm()];
    const request = f.call(operation, ...args);
    const rejected = assert.rejects(request, /closed/);
    await assert.rejects(f.call('context'));
    await assert.rejects(f.call('begin', begin()));
    await f.dialog.cancel();
    assert.equal(await result, false);
    pending.resolve(
      operation === 'context'
        ? { methods: ['none'] }
        : operation === 'begin'
          ? response
          : { prepared: true, restartRequired: true, vaultId: response.vaultId },
    );
    await rejected;
  }
  for (const mode of ['wrong-result', 'unexpected-owner']) {
    const f = setup(),
      result = f.open();
    await tick();
    await f.call('begin', begin());
    f.host.confirmMigrationSetup = async () => {
      if (mode === 'unexpected-owner') f.host.unlockedWorkspaceId = response.vaultId;
      return { vaultId: mode === 'wrong-result' ? 'wrong' : response.vaultId };
    };
    if (mode === 'wrong-result') await assert.rejects(f.call('confirm', confirm()));
    else await f.call('confirm', confirm());
    assert.equal(await result, false);
    assert.equal(f.stops, 1);
  }
});
