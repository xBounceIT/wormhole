import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { VaultBitwardenSynchronizer } from '../electron/vault-bitwarden-sync.ts';
import { VaultBackendHost } from '../electron/vault-host.ts';
import type { BrowserTransferClient } from '../electron/vault-bitwarden-native.ts';
import type { BitwardenExtensionBridge } from '../electron/vault-bitwarden-bridge-contract.ts';
import type {
  BrowserTransferContext,
  BrowserTransferManifest,
  BrowserTransferPacket,
} from '../electron/vault-bitwarden-transfer.ts';

const tick = () => new Promise<void>((resolve) => setImmediate(resolve));
function fixture(restores = [false], bytes = 14) {
  const owner = { workspaceId: randomUUID(), profileId: randomUUID(), epoch: 2 };
  const fileId = randomUUID(),
    calls: string[] = [];
  let c: BrowserTransferContext,
    revision = '0',
    round = 0,
    current = true;
  const manifest = (): BrowserTransferManifest => ({
    bytes,
    revision,
    restore: restores[round - 1] ?? false,
  });
  const packet = (direction: 'capture' | 'restore', index: number): BrowserTransferPacket => {
    const m =
      direction === 'capture'
        ? { bytes: 14, revision: c.sourceRevision, restore: false }
        : manifest();
    const size = Math.min(4 * 1024 * 1024, m.bytes - index * 4 * 1024 * 1024);
    return {
      context: c,
      direction,
      manifest: m,
      index,
      bundle: {
        formatVersion: 1,
        suiteId: 2,
        enc: Buffer.alloc(32, 3).toString('base64'),
        ciphertext: Buffer.alloc(size + 16, 4).toString('base64'),
      },
    };
  };
  const client: BrowserTransferClient = {
    beginBitwardenTransfer: async (q) => {
      calls.push('begin');
      c = {
        ...(q as any),
        fileId,
        transferId: randomUUID(),
        policySequence: '1',
        capturePublicKey: Buffer.alloc(32, 2).toString('base64'),
      };
      return c;
    },
    pushBitwardenTransfer: async () => {
      calls.push('push');
      return { accepted: true, index: 0 };
    },
    commitBitwardenTransfer: async () => {
      calls.push('commit');
      return manifest();
    },
    takeBitwardenTransfer: async (_c, index) => {
      calls.push('take');
      return packet('restore', index);
    },
    cancelBitwardenTransfer: async () => {
      calls.push('native-cancel');
      return { cancelled: true };
    },
    closeBitwardenProfile: async (id) => {
      assert.equal(id, owner.profileId);
      calls.push('profile-close');
      return { closed: true };
    },
  };
  const bridge: BitwardenExtensionBridge = {
    prepare: async () => {
      calls.push('prepare');
      round++;
      return {
        ...owner,
        requestId: randomUUID(),
        action: round === 1 ? 'hydrate' : 'capture',
        sourceRevision: revision,
        restorePublicKey: Buffer.alloc(32, 1).toString('base64'),
      };
    },
    bind: async () => {
      calls.push('bind');
      return { chunks: 1, manifest: { bytes: 14, revision: c.sourceRevision, restore: false } };
    },
    next: async () => {
      calls.push('next');
      return packet('capture', 0);
    },
    accept: async (p) => {
      calls.push('accept');
      if ((p as BrowserTransferPacket).index < Math.ceil(bytes / (4 * 1024 * 1024)) - 1)
        return { complete: false };
      return { complete: true, revision, restore: manifest().restore };
    },
    cancel: async () => {
      calls.push('browser-cancel');
      return { cancelled: true };
    },
    dispose: async () => {
      calls.push('browser-dispose');
      return { closed: true };
    },
  };
  const options = { owner, client, bridge, current: () => current };
  const sync = new VaultBitwardenSynchronizer(options);
  return {
    owner,
    client,
    bridge,
    calls,
    sync,
    options,
    lose: () => {
      current = false;
    },
    packet,
    context: () => c,
  };
}

test('coalesces checkpoints and acknowledges actual restored state with a bounded follow-up capture', async () => {
  const f = fixture([true, false]);
  const first = f.sync.synchronize();
  assert.equal(f.sync.synchronize(), first);
  assert.deepEqual(await first, { rounds: 2, checkpointPending: false });
  assert.equal(f.calls.filter((x) => x === 'begin').length, 2);
  assert.equal(f.calls.filter((x) => x === 'accept').length, 2);
  const closing = f.sync.close();
  assert.equal(f.sync.close(), closing);
  await closing;
  await f.sync.close();
  assert.equal(f.calls.filter((x) => x === 'profile-close').length, 1);
  await assert.rejects(f.sync.synchronize(), /unavailable/);
  const busy = fixture([true, true, true, false]);
  assert.deepEqual(await busy.sync.synchronize(), { rounds: 3, checkpointPending: true });
  assert.deepEqual(await busy.sync.synchronize(), { rounds: 1, checkpointPending: false });
  await busy.sync.close();
});

test('rejects foreign, malformed and extra-field metadata before a native begin', async () => {
  assert.throws(
    () => new VaultBitwardenSynchronizer({ ...fixture().options, owner: {} as any }),
    /Invalid/,
  );
  for (const change of [
    () => null,
    (q: any) => ({ ...q, profileId: randomUUID() }),
    (q: any) => ({ ...q, workspaceId: randomUUID() }),
    (q: any) => ({ ...q, epoch: 3 }),
    (q: any) => ({ ...q, raw: 'private' }),
  ]) {
    const f = fixture(),
      prepare = f.bridge.prepare;
    f.bridge.prepare = async () => change(await prepare()) as any;
    await assert.rejects(f.sync.synchronize(), /^Error: Bitwarden synchronization failed\.$/);
    assert.ok(!f.calls.includes('begin'));
    assert.ok(f.calls.includes('browser-cancel'));
    await f.sync.close();
  }
});

test('validates capture manifests, ordered ciphertext, restore manifests and exact receipts', async () => {
  const cases: Array<(f: ReturnType<typeof fixture>) => void> = [
    (f) => {
      f.bridge.bind = async () => null as any;
    },
    (f) => {
      const bind = f.bridge.bind;
      f.bridge.bind = async (c) => ({ ...(await bind(c)), chunks: 2 });
    },
    (f) => {
      const bind = f.bridge.bind;
      f.bridge.bind = async (c) => ({ ...(await bind(c)), extra: true });
    },
    (f) => {
      f.bridge.next = async () => ({ ...f.packet('capture', 0), index: 1 });
    },
    (f) => {
      f.bridge.next = async () => ({
        ...f.packet('capture', 0),
        manifest: { bytes: 15, revision: '0', restore: false },
        bundle: {
          ...f.packet('capture', 0).bundle,
          ciphertext: Buffer.alloc(31).toString('base64'),
        },
      });
    },
    (f) => {
      f.client.commitBitwardenTransfer = async () => ({ bytes: 0, revision: '0', restore: false });
    },
    (f) => {
      f.client.takeBitwardenTransfer = async () => ({
        ...f.packet('restore', 0),
        direction: 'capture',
      });
    },
    (f) => {
      f.client.takeBitwardenTransfer = async () => ({
        ...f.packet('restore', 0),
        manifest: { bytes: 14, revision: '1', restore: false },
      });
    },
    (f) => {
      f.bridge.accept = async () => ({ complete: false });
    },
    (f) => {
      f.bridge.accept = async () => ({ complete: true, revision: '1', restore: false });
    },
    (f) => {
      f.bridge.accept = async () => ({ complete: true, revision: '0', restore: true });
    },
    (f) => {
      f.bridge.accept = async () => ({
        complete: true,
        revision: '0',
        restore: false,
        raw: 'private',
      });
    },
  ];
  for (const change of cases) {
    const f = fixture();
    change(f);
    await assert.rejects(f.sync.synchronize(), /^Error: Bitwarden synchronization failed\.$/);
    assert.ok(f.calls.includes('native-cancel'));
    assert.ok(f.calls.includes('browser-cancel'));
    await f.sync.close();
  }
});

test('receives every restore chunk and rejects an early final receipt', async () => {
  const f = fixture([false], 4 * 1024 * 1024 + 14);
  assert.deepEqual(await f.sync.synchronize(), { rounds: 1, checkpointPending: false });
  assert.equal(f.calls.filter((x) => x === 'take').length, 2);
  await f.sync.close();
  const bad = fixture([false], 4 * 1024 * 1024 + 14);
  bad.bridge.accept = async () => ({ complete: true, revision: '0', restore: false });
  await assert.rejects(bad.sync.synchronize(), /failed/);
  await bad.sync.close();
});

test('authority loss at every asynchronous boundary cancels only the original native owner', async () => {
  for (const name of [
    'prepare',
    'bind',
    'next',
    'accept',
    'beginBitwardenTransfer',
    'pushBitwardenTransfer',
    'commitBitwardenTransfer',
    'takeBitwardenTransfer',
  ]) {
    const f = fixture();
    const target: any = name in f.bridge ? f.bridge : f.client;
    const invoke = target[name].bind(target);
    target[name] = async (...args: any[]) => {
      const result = await invoke(...args);
      f.lose();
      return result;
    };
    await assert.rejects(f.sync.synchronize(), /failed/);
    assert.ok(f.calls.includes('browser-cancel'));
    if (name !== 'prepare') assert.ok(f.calls.includes('native-cancel'));
    await f.sync.close();
    assert.ok(f.calls.includes('profile-close'));
  }
});

test('uncertain cleanup quarantines the document, attempts all releases and permits explicit close retry', async () => {
  const f = fixture();
  f.bridge.next = async () => {
    throw Error('private storage failure');
  };
  f.bridge.cancel = () => {
    throw Error('private cleanup failure');
  };
  await assert.rejects(f.sync.synchronize(), /cleanup is unconfirmed/);
  assert.ok(f.calls.includes('native-cancel'));
  await assert.rejects(f.sync.synchronize(), /unavailable/);
  f.bridge.dispose = () => {
    throw Error('private disposal failure');
  };
  await assert.rejects(f.sync.close(), /^Error: Bitwarden profile cleanup is unconfirmed\.$/);
  assert.ok(f.calls.includes('profile-close'));
  f.bridge.dispose = async () => ({ closed: true });
  let fail = true;
  f.client.closeBitwardenProfile = async () => {
    if (fail) throw Error('private');
    return { closed: true };
  };
  await assert.rejects(f.sync.close(), /unconfirmed/);
  fail = false;
  await f.sync.close();
});

test('close waits for a late begin cancellation before retiring the original profile', async () => {
  const f = fixture(),
    begin = f.client.beginBitwardenTransfer;
  let release!: () => void;
  f.client.beginBitwardenTransfer = async (q) => {
    await new Promise<void>((r) => {
      release = r;
    });
    return begin(q);
  };
  const running = assert.rejects(f.sync.synchronize(), /failed/);
  await tick();
  let done = false;
  const closing = f.sync.close().then(() => {
    done = true;
  });
  await tick();
  assert.equal(done, false);
  assert.ok(!f.calls.includes('profile-close'));
  release();
  await running;
  await closing;
  assert.ok(f.calls.indexOf('native-cancel') < f.calls.indexOf('profile-close'));
});

test('native file or policy substitution cannot reuse a synchronizer', async () => {
  for (const field of ['fileId', 'policySequence']) {
    const f = fixture();
    await f.sync.synchronize();
    const begin = f.client.beginBitwardenTransfer;
    f.client.beginBitwardenTransfer = async (q) => ({
      ...(await begin(q)),
      [field]: field === 'fileId' ? randomUUID() : '2',
    });
    await assert.rejects(f.sync.synchronize(), /failed/);
    await f.sync.close();
  }
});

test('host creates only authorized synchronizers and cleanup stays on its captured backend after replacement', async () => {
  const f = fixture(),
    replacement = fixture();
  const full = (client: BrowserTransferClient) => ({
    ...client,
    unlock: async () => ({ unlocked: true, lockedMemory: true }),
    security: async () => ({ effective: 'default' }),
    lock: async () => {},
  });
  let active = full(f.client),
    allowed = true;
  const host = new VaultBackendHost(
    () => active as any,
    () => true,
  );
  const create = () => host.createBitwardenSynchronizer(f.owner, f.bridge, () => allowed);
  assert.throws(create, /Invalid/);
  const unlock = () =>
    host.unlock({
      vaultId: f.owner.workspaceId,
      slotId: f.owner.profileId,
      kind: 'password',
      factor: new Uint8Array([1]),
    });
  await unlock();
  assert.throws(() => host.createBitwardenSynchronizer(null, f.bridge, () => true), /Invalid/);
  assert.throws(
    () =>
      host.createBitwardenSynchronizer(
        { ...f.owner, workspaceId: randomUUID() },
        f.bridge,
        () => true,
      ),
    /Invalid/,
  );
  allowed = false;
  assert.throws(create, /Invalid/);
  allowed = true;
  const sync = create();
  await sync.synchronize();
  await host.stop();
  active = full(replacement.client);
  await unlock();
  await assert.rejects(sync.synchronize(), /failed/);
  await sync.close();
  assert.ok(f.calls.includes('profile-close'));
  assert.ok(!replacement.calls.includes('profile-close'));
  await host.stop();
});

test('an unconfirmed late-begin cancellation cannot be mistaken for a clean exchange failure', async () => {
  const f = fixture(),
    begin = f.client.beginBitwardenTransfer;
  f.client.beginBitwardenTransfer = async (q) => {
    const c = await begin(q);
    f.lose();
    return c;
  };
  f.client.cancelBitwardenTransfer = async () => {
    throw Error('private native key release');
  };
  await assert.rejects(f.sync.synchronize(), /cleanup is unconfirmed/);
  await assert.rejects(f.sync.synchronize(), /unavailable/);
  await f.sync.close();
  assert.ok(f.calls.includes('profile-close'));
});

test('cleanup requires exact positive acknowledgements from both the extension and original native client', async () => {
  const f = fixture();
  f.bridge.next = async () => {
    throw Error('private');
  };
  f.bridge.cancel = async () => ({ cancelled: false }) as any;
  await assert.rejects(f.sync.synchronize(), /cleanup is unconfirmed/);
  f.bridge.dispose = async () => ({ closed: true, extra: true }) as any;
  await assert.rejects(f.sync.close(), /unconfirmed/);
  assert.ok(f.calls.includes('profile-close'));
  f.bridge.dispose = async () => ({ closed: true });
  f.client.closeBitwardenProfile = async () => null as any;
  await assert.rejects(f.sync.close(), /unconfirmed/);
  f.client.closeBitwardenProfile = async () => ({ closed: true });
  await f.sync.close();
});
