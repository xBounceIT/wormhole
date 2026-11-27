import assert from 'node:assert/strict';
import test from 'node:test';
import {
  registerVaultMigrationIpc,
  registerVaultRootRotationIpc,
} from '../electron/vault-migration-ipc.ts';

const id = '11111111-1111-4111-8111-111111111111';
const startup = () => ({
  slots: { formatVersion: 1, vaultId: id, encrypted: false, slots: [] },
  migration: { pending: true },
  cosmetics: { theme: 'system' },
  newWorkspace: false,
});
function fixture(mode = '', kind: 'migration' | 'rotation' = 'migration') {
  let handler: any,
    trusted = true,
    opens = 0,
    stopped = 0,
    retired = 0,
    activated = 0;
  const event: any = {};
  const host: any = {
    unlockedWorkspaceId: undefined,
    startup: async () => {
      if (mode === 'startup error') throw Error('private startup diagnostic');
      if (mode === 'late startup') trusted = false;
      const hints =
        kind === 'migration'
          ? startup()
          : {
              ...startup(),
              slots: { ...startup().slots, formatVersion: 3 },
              migration: undefined,
              rotation: { pending: true },
            };
      return mode === 'no migration'
        ? { ...hints, [kind]: undefined }
        : mode === 'wrong maintenance'
          ? startup()
          : hints;
    },
    resumeMigration: async () => {
      assert.equal(kind, 'migration');
      host.unlockedWorkspaceId = mode === 'wrong owner' ? 'other' : id;
      return { unlocked: true };
    },
    resumeRootRotation: async () => {
      assert.equal(kind, 'rotation');
      host.unlockedWorkspaceId = mode === 'wrong owner' ? 'other' : id;
      return { unlocked: true };
    },
    stop: async () => {
      stopped++;
      host.unlockedWorkspaceId = undefined;
      if (mode === 'cleanup failure') throw Error('private native cleanup error');
    },
  };
  (kind === 'migration' ? registerVaultMigrationIpc : registerVaultRootRotationIpc)({
    ipc: {
      handle: (_channel, fn) => {
        assert.equal(_channel, `vault:${kind}-resume`);
        handler = fn;
      },
    },
    host,
    dialog: {
      open: async (_parent, accepted, operation, slots, submit) => {
        opens++;
        assert.equal(operation, `${kind}-resume`);
        assert.equal(slots.vaultId, id);
        assert.equal(accepted(), true);
        if (mode === 'cancel') throw Error('private cancellation');
        await submit({ vaultId: id, slotId: id, kind: 'password', factor: new Uint8Array([1]) });
        if (mode === 'late owner' || mode === 'cleanup failure') trusted = false;
        return {} as any;
      },
    },
    parent: () => {
      if (mode === 'parent error') throw Error('private native window diagnostic');
      return mode === 'no parent' ? undefined : ({} as any);
    },
    trusted: () => {
      if (mode === 'throws') throw Error('destroyed');
      return trusted;
    },
    quiesced: () => mode !== 'not restarted',
    activate: () => {
      activated++;
      if (mode === 'activation failure') throw Error('partial auth activation');
      if (mode === 'activation invalidates') trusted = false;
    },
    retire: async () => {
      retired++;
      if (mode === 'cleanup failure') throw Error('private lock error');
    },
  });
  return {
    invoke: (...args: unknown[]) => handler(event, ...args),
    state: () => ({ opens, stopped, retired, activated }),
    host,
  };
}

test('migration IPC opens only a captured protected operation after a native restart', async () => {
  const f = fixture();
  assert.equal(await f.invoke(), true);
  assert.deepEqual(f.state(), { opens: 1, stopped: 0, retired: 0, activated: 1 });
  for (const mode of [
    'no migration',
    'late startup',
    'no parent',
    'throws',
    'not restarted',
    'cancel',
    'startup error',
    'parent error',
  ]) {
    const f = fixture(mode);
    await assert.rejects(f.invoke(), /unavailable/);
    assert.equal(f.state().activated, 0);
  }
  const rejected = fixture();
  await assert.rejects(rejected.invoke({ factor: 'untrusted', quiesced: true }), /unavailable/);
  assert.equal(rejected.state().opens, 0);
});

test('rotation IPC captures only new-factor resume and retires lost or partially activated ownership', async () => {
  const success = fixture('', 'rotation');
  assert.equal(await success.invoke(), true);
  assert.deepEqual(success.state(), { opens: 1, stopped: 0, retired: 0, activated: 1 });
  for (const mode of [
    'no migration',
    'wrong maintenance',
    'late startup',
    'no parent',
    'throws',
    'not restarted',
    'cancel',
    'startup error',
    'parent error',
    'wrong owner',
  ]) {
    const f = fixture(mode, 'rotation');
    await assert.rejects(f.invoke(), /unavailable/);
    assert.equal(f.state().activated, 0);
  }
  const extra = fixture('', 'rotation');
  await assert.rejects(extra.invoke({ factor: 'secret', quiesced: true }), /unavailable/);
  assert.equal(extra.state().opens, 0);
  for (const mode of [
    'late owner',
    'activation failure',
    'activation invalidates',
    'cleanup failure',
  ]) {
    const f = fixture(mode, 'rotation');
    await assert.rejects(f.invoke(), /unavailable|shutdown could not be confirmed/);
    assert.equal(f.state().retired, 1);
    assert.equal(f.state().stopped, 1);
  }
});

test('duplicate resume requests cannot open two protected prompts or retire the first owner', async () => {
  for (const kind of ['migration', 'rotation'] as const) {
    const f = fixture('', kind);
    const first = f.invoke();
    await assert.rejects(f.invoke(), /unavailable/);
    assert.equal(await first, true);
    assert.deepEqual(f.state(), { opens: 1, stopped: 0, retired: 0, activated: 1 });
  }
});

test('migration IPC retires committed ownership after lost trust or partial activation', async () => {
  for (const mode of ['late owner', 'activation failure', 'activation invalidates']) {
    const f = fixture(mode);
    await assert.rejects(f.invoke(), /unavailable/);
    assert.equal(f.state().retired, 1);
    assert.equal(f.state().stopped, 1);
    assert.equal(f.host.unlockedWorkspaceId, undefined);
  }
  const f = fixture('wrong owner');
  await assert.rejects(f.invoke(), /unavailable/);
  assert.equal(f.state().activated, 0);
  assert.equal(f.state().stopped, 0);
  const failed = fixture('cleanup failure');
  await assert.rejects(failed.invoke(), /shutdown could not be confirmed/);
  assert.equal(failed.state().retired, 1);
  assert.equal(failed.state().stopped, 1);
});
