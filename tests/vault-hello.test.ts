import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import type { BrowserWindow, IpcMain, IpcMainInvokeEvent } from 'electron';
import type { VaultDescriptor } from '../electron/vault-contract.ts';
import { registerVaultPresenceIpc } from '../electron/vault-presence-ipc.ts';
import type { VaultPresenceChange, VaultPresenceUnlockResult } from '../electron/vault-presence.ts';
import { VaultBackendHost, type VaultPresenceAuthentication } from '../electron/vault-host.ts';
import type { VaultUnlockInput } from '../electron/vault-unlock.ts';

const vaultId = '11111111-1111-4111-8111-111111111111';
const passwordId = '22222222-2222-4222-8222-222222222222';
const helloId = '33333333-3333-4333-8333-333333333333';
const touchId = '44444444-4444-4444-8444-444444444444';
const selection = { vaultId, slotId: helloId };
const touchSelection = { vaultId, slotId: touchId };
const unlocked = { unlocked: true, lockedMemory: true } as const;
const factor = (): VaultUnlockInput => ({
  vaultId,
  slotId: passwordId,
  kind: 'password',
  factor: new Uint8Array([1, 2, 3]),
});

const descriptors = (hello: boolean, touch: boolean): VaultDescriptor => ({
  formatVersion: 6,
  vaultId,
  encrypted: false,
  slots: [
    { id: passwordId, kind: 'password', preset: 'kdf-v1' },
    ...(hello ? [{ id: helloId, kind: 'hello' as const }] : []),
    ...(touch ? [{ id: touchId, kind: 'touch-id' as const }] : []),
  ],
});

class Owner extends EventEmitter {
  webContents = new EventEmitter();
  isDestroyed = () => false;
  isEnabled = () => true;
  focusCount = 0;
  focus() {
    this.focusCount++;
  }
}

function fixture(platform: NodeJS.Platform = 'win32') {
  const owner = new Owner();
  const expected = platform === 'darwin' ? 'touch-id' : 'hello';
  let hasHello = true,
    hasTouchID = true,
    protectedVault = true,
    shared = false;
  let trusted = true,
    locks = 0,
    activations = 0,
    prompts = 0,
    descriptions = 0;
  let confirm: VaultPresenceAuthentication = async (_operation, _descriptor, submit) =>
    submit(factor(), expected === 'hello' ? '57' : undefined);
  let native: () => Promise<VaultPresenceUnlockResult> = async () => unlocked;
  const operations: string[] = [];
  const host = new VaultBackendHost(
    () =>
      ({
        startup: async () => ({
          slots: descriptors(hasHello, hasTouchID),
          ...(shared ? { shared: {} } : {}),
        }),
        describe: async () => {
          descriptions++;
          return descriptors(hasHello, hasTouchID);
        },
        protection: async () => ({ protected: protectedVault }),
        unlock: async () => unlocked,
        unlockPresence: async (kind: string, request: typeof selection, hwnd?: string) => {
          prompts++;
          assert.equal(kind, expected);
          assert.deepEqual(request, kind === 'hello' ? selection : touchSelection);
          assert.equal(hwnd, kind === 'hello' ? '314' : undefined);
          return native();
        },
        presenceAvailability: async (kind: string) => {
          assert.equal(kind, expected);
          return 'ready';
        },
        enrollPresence: async (kind: string, hwnd: string | undefined, input: VaultUnlockInput) => {
          operations.push('enroll');
          assert.equal(kind, expected);
          assert.equal(hwnd, kind === 'hello' ? '57' : undefined);
          assert.deepEqual([...input.factor], [1, 2, 3]);
          if (kind === 'hello') hasHello = true;
          else hasTouchID = true;
          return { enrolled: true };
        },
        removePresence: async (kind: string, slot: string, input: VaultUnlockInput) => {
          operations.push('remove');
          assert.equal(kind, expected);
          assert.equal(slot, kind === 'hello' ? helloId : touchId);
          assert.deepEqual([...input.factor], [1, 2, 3]);
          if (kind === 'hello') hasHello = false;
          else hasTouchID = false;
          return { removed: true, keyDeleted: false };
        },
        security: async () => ({ effective: 'default' }),
        lock: async () => {
          locks++;
        },
      }) as never,
    () => true,
  );
  const handlers = new Map<
    string,
    (event: IpcMainInvokeEvent, ...args: unknown[]) => Promise<unknown>
  >();
  registerVaultPresenceIpc({
    ipc: {
      handle: (name, handler) => {
        handlers.set(name, handler);
      },
    } as Pick<IpcMain, 'handle'>,
    host,
    trusted: () => trusted,
    owner: () => owner as unknown as BrowserWindow,
    nativeHandle: (window) => {
      assert.equal(platform, 'win32');
      assert.equal(window, owner);
      return '314';
    },
    confirm:
      (window, accepted) =>
      (operation, descriptor, submit): Promise<VaultPresenceChange> => {
        assert.equal(window, owner);
        assert.equal(accepted(), true);
        return confirm(operation, descriptor, submit);
      },
    unlocked: () => {
      activations++;
    },
    platform,
  });
  return {
    owner,
    host,
    operations,
    invoke: (channel: string, ...args: unknown[]) =>
      handlers.get(`vault:presence-${channel}`)!({} as IpcMainInvokeEvent, ...args),
    setTrusted: (value: boolean) => {
      trusted = value;
    },
    setProtected: (value: boolean) => {
      protectedVault = value;
    },
    setShared: () => {
      shared = true;
    },
    setConfirm: (value: VaultPresenceAuthentication) => {
      confirm = value;
    },
    setNative: (value: typeof native) => {
      native = value;
    },
    counts: () => ({ activations, descriptions, locks, prompts }),
  };
}

test('native startup accepts only the enrolled slot and supports cancellation and retry', async () => {
  const f = fixture();
  await f.host.startup();
  f.setTrusted(false);
  await assert.rejects(f.invoke('unlock', selection), /Invalid/);
  await assert.rejects(f.invoke('status'), /Invalid/);
  f.setTrusted(true);
  for (const value of [
    null,
    { ...selection, ownerWindow: '57' },
    { ...selection, factor: new Uint8Array([42]) },
  ])
    await assert.rejects(f.invoke('unlock', value), /Invalid/);
  await assert.rejects(f.invoke('unlock', selection, '314'), /Invalid/);
  await assert.rejects(f.invoke('unlock', { vaultId, slotId: passwordId }), /slot unavailable/);
  f.setNative(async () => ({ status: 'remote-desktop' }));
  assert.deepEqual(await f.invoke('unlock', selection), { status: 'remote-desktop' });
  assert.equal(f.host.unlockedWorkspaceId, undefined);
  assert.equal(f.counts().activations, 0);
  f.setNative(async () => unlocked);
  assert.deepEqual(await f.invoke('unlock', selection), unlocked);
  assert.equal(f.host.unlockedWorkspaceId, vaultId);
  assert.equal(f.counts().activations, 1);
  assert.equal(f.owner.focusCount, 3);
  assert.equal(f.owner.webContents.listenerCount('did-start-navigation'), 0);
});

test('losing the startup owner retires an in-flight biometric request and prevents activation', async () => {
  for (const [platform, event] of [
    ['win32', 'closed'],
    ['win32', 'render-process-gone'],
    ['win32', 'did-start-navigation'],
    ['darwin', 'closed'],
  ] as const) {
    const f = fixture(platform);
    await f.host.startup();
    const native = Promise.withResolvers<VaultPresenceUnlockResult>();
    const started = Promise.withResolvers<void>();
    f.setNative(() => {
      started.resolve();
      return native.promise;
    });
    const attempt = f.invoke('unlock', platform === 'win32' ? selection : touchSelection);
    await started.promise;
    await assert.rejects(f.host.unlock(factor()), /already in progress/);
    f.owner.webContents.emit('did-start-navigation', { isMainFrame: false });
    assert.equal(f.counts().locks, 0);
    if (event === 'closed') f.owner.emit(event);
    else f.owner.webContents.emit(event, { isMainFrame: true });
    assert.equal(f.counts().locks, 1);
    native.resolve(unlocked);
    await assert.rejects(attempt, /no longer available/);
    assert.equal(f.counts().activations, 0);
    assert.equal(f.host.unlockedWorkspaceId, undefined);
    assert.equal(f.owner.webContents.listenerCount('render-process-gone'), 0);
  }
});

test('settings require fresh software authentication in Default and use the committed Hello slot', async () => {
  const f = fixture();
  assert.equal(await f.invoke('status'), null);
  await assert.rejects(f.invoke('configure', 'remove'), /settings unavailable/);
  await f.host.unlock(factor());
  f.setProtected(false);
  assert.equal(await f.invoke('status'), null);
  await assert.rejects(f.invoke('configure', 'enroll'), /Protected local vault/);
  assert.equal(f.counts().descriptions, 0);
  f.setProtected(true);
  assert.deepEqual(await f.invoke('status'), { enrolled: true, availability: 'ready' });
  await assert.rejects(f.invoke('status', 1), /Invalid/);
  await assert.rejects(f.invoke('configure', { action: 'remove', slotId: passwordId }), /Invalid/);
  await assert.rejects(f.invoke('configure', 'enroll'), /already enrolled/);
  let confirmations = 0;
  f.setConfirm(async (operation, descriptor, submit) => {
    confirmations++;
    assert.equal(operation, confirmations === 1 ? 'hello-remove' : 'hello-enroll');
    assert.equal(descriptor.vaultId, vaultId);
    const wrong = { ...factor(), slotId: helloId };
    await assert.rejects(submit(wrong, '57'), /locked/);
    assert.deepEqual([...wrong.factor], [0, 0, 0]);
    const auth = factor();
    const result = await submit(auth, '57');
    assert.deepEqual([...auth.factor], [0, 0, 0]);
    return result;
  });
  assert.deepEqual(await f.invoke('configure', 'remove'), { removed: true, keyDeleted: false });
  await assert.rejects(f.invoke('configure', 'remove'), /slot unavailable/);
  assert.deepEqual(await f.invoke('status'), { enrolled: false, availability: 'ready' });
  assert.deepEqual(await f.invoke('configure', 'enroll'), { enrolled: true });
  assert.deepEqual(f.operations, ['remove', 'enroll']);
  assert.equal(confirmations, 2);
});

test('Windows Hello endpoints respect platform and local workspace scope', async () => {
  const linux = fixture('linux');
  assert.equal(await linux.invoke('status'), null);
  assert.deepEqual(await linux.invoke('unlock', selection), { status: 'unavailable' });
  await assert.rejects(linux.invoke('configure', 'remove'), /Invalid/);
  const f = fixture();
  f.setShared();
  await f.host.startup();
  await assert.rejects(f.invoke('unlock', selection), /enrollment is pending/);
  assert.equal(f.counts().prompts, 0);
});

test('macOS IPC exclusively uses Touch ID and a live requesting window', async () => {
  const f = fixture('darwin');
  await f.host.startup();
  await assert.rejects(f.invoke('unlock', selection), /slot unavailable/);
  await assert.rejects(f.invoke('unlock', { ...touchSelection, kind: 'touch-id' }), /Invalid/);
  f.setNative(async () => ({ status: 'canceled' }));
  assert.deepEqual(await f.invoke('unlock', touchSelection), { status: 'canceled' });
  assert.equal(f.host.unlockedWorkspaceId, undefined);
  f.setNative(async () => unlocked);
  assert.deepEqual(await f.invoke('unlock', touchSelection), unlocked);
  assert.equal(f.host.unlockedWorkspaceId, vaultId);
  assert.equal(f.owner.focusCount, 0);
  let confirmations = 0;
  f.setConfirm(async (operation, descriptor, submit) => {
    assert.equal(operation, confirmations++ === 0 ? 'touch-id-remove' : 'touch-id-enroll');
    assert.equal(descriptor.vaultId, vaultId);
    const auth = factor();
    const result = await submit(auth);
    assert.deepEqual([...auth.factor], [0, 0, 0]);
    return result;
  });
  assert.deepEqual(await f.invoke('status'), { availability: 'ready', enrolled: true });
  assert.deepEqual(await f.invoke('configure', 'remove'), { removed: true, keyDeleted: false });
  assert.deepEqual(await f.invoke('status'), { availability: 'ready', enrolled: false });
  assert.deepEqual(await f.invoke('configure', 'enroll'), { enrolled: true });
  assert.deepEqual(f.operations, ['remove', 'enroll']);
});
