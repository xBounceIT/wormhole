import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from '@hpke/core';
import { createBitwardenExtensionBridge } from '../src/vault-bitwarden-extension-bridge.ts';
import {
  createBitwardenExtensionStorage,
  type ExtensionStorageArea,
  type ExtensionStorageCapture,
} from '../src/vault-bitwarden-extension-storage.ts';
import {
  parseBitwardenBridgeOwner,
  parseBitwardenBridgeReceipt,
} from '../electron/vault-bitwarden-bridge-contract.ts';
import {
  browserTransferAreaBytes,
  browserTransferChunkCount,
  browserTransferChunkSize,
  browserTransferInfo,
  encodeBrowserTransferFrame,
  decodeBrowserTransferFrame,
  type BrowserTransferContext,
  type BrowserTransferPacket,
} from '../electron/vault-bitwarden-transfer.ts';
import type { BrowserTransferRequest } from '../electron/vault-bitwarden-native.ts';

const bytes = (s: string) => new TextEncoder().encode(s),
  b64 = (v: Uint8Array) => Buffer.from(v).toString('base64');
const owner = () => ({ workspaceId: randomUUID(), profileId: randomUUID(), epoch: 2 });
const tick = () => new Promise<void>((r) => setImmediate(r));
const cipher = () =>
  new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
function storageFixture(
  local: Record<string, unknown> = {},
  session: Record<string, unknown> = {},
) {
  const area = (values: Record<string, unknown>): ExtensionStorageArea => ({
    get: (key, done) =>
      queueMicrotask(() =>
        done(
          key === null ? { ...values } : Object.hasOwn(values, key) ? { [key]: values[key] } : {},
        ),
      ),
    set: (next, done) => {
      Object.assign(values, next);
      queueMicrotask(done);
    },
    remove: (key, done) => {
      delete values[key];
      queueMicrotask(done);
    },
  });
  const actual = createBitwardenExtensionStorage({
    manifestVersion: 3,
    local: area(local),
    session: area(session),
    lastError: () => undefined,
  });
  const captured: Uint8Array[] = [],
    borrowed: Uint8Array[] = [];
  const storage = {
    capture: async (signal: AbortSignal) => {
      const state = await actual.capture(signal);
      captured.push(state.localJSON, state.sessionJSON);
      return state;
    },
    restore: async (
      state: ExtensionStorageCapture,
      witness: ExtensionStorageCapture,
      signal: AbortSignal,
    ) => {
      borrowed.push(state.localJSON, state.sessionJSON, witness.localJSON, witness.sessionJSON);
      await actual.restore(state, witness, signal);
    },
  };
  return { storage, local, session, captured, borrowed };
}
async function native(q: BrowserTransferRequest) {
  const capture = (await crypto.subtle.generateKey({ name: 'X25519' }, false, [
    'deriveBits',
  ])) as CryptoKeyPair;
  const c: BrowserTransferContext = {
    ...q,
    fileId: randomUUID(),
    transferId: randomUUID(),
    policySequence: '9223372036854775807',
    capturePublicKey: b64(new Uint8Array(await crypto.subtle.exportKey('raw', capture.publicKey))),
  };
  return { c, capture };
}
async function restorePackets(
  c: BrowserTransferContext,
  local: string,
  session: string,
  revision = '1',
  restore = true,
) {
  const raw = encodeBrowserTransferFrame(bytes(local), bytes(session)),
    manifest = { bytes: raw.length, revision, restore },
    suite = cipher(),
    packets: BrowserTransferPacket[] = [];
  const recipientPublicKey = await suite.kem.deserializePublicKey(
    Buffer.from(c.restorePublicKey, 'base64'),
  );
  try {
    for (let i = 0; i < browserTransferChunkCount(manifest); i++) {
      const length = browserTransferChunkSize(manifest, i),
        result = await suite.seal(
          { recipientPublicKey, info: browserTransferInfo(c, 'restore', manifest, i) },
          raw.subarray(i * 4194304, i * 4194304 + length),
        );
      packets.push({
        context: c,
        direction: 'restore',
        manifest,
        index: i,
        bundle: {
          formatVersion: 1,
          suiteId: 2,
          enc: b64(new Uint8Array(result.enc)),
          ciphertext: b64(new Uint8Array(result.ct)),
        },
      });
    }
    return packets;
  } finally {
    raw.fill(0);
  }
}
async function openCapture(packet: BrowserTransferPacket, key: CryptoKeyPair) {
  return new Uint8Array(
    await cipher().open(
      {
        recipientKey: key,
        enc: Buffer.from(packet.bundle.enc, 'base64'),
        info: browserTransferInfo(packet.context, 'capture', packet.manifest, packet.index),
      },
      Buffer.from(packet.bundle.ciphertext, 'base64'),
    ),
  );
}
async function ready(bridge: ReturnType<typeof createBitwardenExtensionBridge>) {
  const q = await bridge.prepare(),
    fixture = await native(q),
    ack = await bridge.bind(fixture.c);
  for (let i = 0; i < ack.chunks; i++) await bridge.next();
  return { q, ...fixture, ack };
}

test('bridge contracts accept only an exact owner and bounded public receipt', () => {
  const o = owner();
  assert.deepEqual(parseBitwardenBridgeOwner(o), o);
  for (const v of [
    null,
    [],
    {},
    { ...o, extra: true },
    { ...o, workspaceId: 'bad' },
    { ...o, profileId: 'bad' },
    { ...o, epoch: 0 },
    { ...o, epoch: '2' },
    { ...o, epoch: 2.2 },
    { ...o, epoch: Number.MAX_SAFE_INTEGER + 1 },
  ]) {
    assert.equal(parseBitwardenBridgeOwner(v), undefined);
    assert.throws(() => createBitwardenExtensionBridge(v, storageFixture().storage), /unavailable/);
  }
  for (const v of [
    { complete: false },
    { complete: true, revision: '9223372036854775807', restore: true },
  ])
    assert.deepEqual(parseBitwardenBridgeReceipt(v), v);
  for (const v of [
    null,
    [],
    {},
    { complete: false, extra: 1 },
    { complete: 'true' },
    { complete: true, revision: '01', restore: false },
    { complete: true, revision: '9223372036854775808', restore: true },
    { complete: true, revision: '1', restore: 'yes' },
  ])
    assert.equal(parseBitwardenBridgeReceipt(v), undefined);
});

test('bridge seals actual captures, conditionally applies native restore and advances only public revision', async () => {
  const f = storageFixture(
      { account: 'synthetic-private-before' },
      { token: 'synthetic-private-session' },
    ),
    o = owner(),
    bridge = createBitwardenExtensionBridge(o, f.storage);
  try {
    const q = await bridge.prepare();
    o.profileId = randomUUID();
    assert.equal(q.action, 'hydrate');
    assert.equal(q.sourceRevision, '0');
    const { c, capture } = await native(q),
      ack = await bridge.bind(c);
    assert.equal(ack.chunks, 1);
    assert.ok(f.captured.every((p) => p.every((x) => x === 0)));
    const packet = await bridge.next();
    assert.equal(JSON.stringify(packet).includes('synthetic-private'), false);
    const raw = await openCapture(packet, capture),
      actual = decodeBrowserTransferFrame(raw);
    assert.equal(
      new TextDecoder().decode(actual.localJSON),
      '{"account":"synthetic-private-before"}',
    );
    raw.fill(0);
    const wanted = await restorePackets(
      c,
      '{"account":"synthetic-private-after"}',
      '{"token":"synthetic-private-after-session"}',
    );
    assert.deepEqual(await bridge.accept(wanted[0]), {
      complete: true,
      revision: '1',
      restore: true,
    });
    assert.deepEqual(f.local, { account: 'synthetic-private-after' });
    assert.deepEqual(f.session, { token: 'synthetic-private-after-session' });
    assert.ok(f.borrowed.length === 4 && f.borrowed.every((p) => p.every((x) => x === 0)));
    await bridge.cancel();
    const next = await bridge.prepare();
    assert.equal(next.action, 'capture');
    assert.equal(next.sourceRevision, '1');
    next.sourceRevision = '9';
    assert.equal(
      (await bridge.bind((await native({ ...next, sourceRevision: '1' })).c)).manifest.revision,
      '1',
    );
  } finally {
    await bridge.dispose();
  }
});

test('no-restore receipts preserve an extension refresh and require a real next capture', async () => {
  const f = storageFixture({ token: 'old' }, {}),
    bridge = createBitwardenExtensionBridge(owner(), f.storage);
  try {
    const { c } = await ready(bridge);
    f.local.token = 'fresh';
    const packets = await restorePackets(c, '{"token":"old"}', '{}', '0', false);
    assert.deepEqual(await bridge.accept(packets[0]), {
      complete: true,
      revision: '0',
      restore: false,
    });
    assert.equal(f.local.token, 'fresh');
    assert.equal(f.borrowed.length, 0);
    const q = await bridge.prepare();
    assert.equal(q.action, 'capture');
    const fixture = await native(q);
    await bridge.bind(fixture.c);
    const raw = await openCapture(await bridge.next(), fixture.capture);
    assert.equal(
      new TextDecoder().decode(decodeBrowserTransferFrame(raw).localJSON),
      '{"token":"fresh"}',
    );
    raw.fill(0);
  } finally {
    await bridge.dispose();
  }
});

test('malformed contexts, wrong phases and tampered restore retire only their transfer', async () => {
  for (const failure of [
    'bad-bind',
    'foreign-bind',
    'bind-twice',
    'next-before-bind',
    'accept-before-capture',
    'next-twice',
    'tamper',
  ] as const) {
    const bridge = createBitwardenExtensionBridge(owner(), storageFixture().storage);
    try {
      const q = await bridge.prepare(),
        { c } = await native(q);
      if (failure === 'bad-bind') await assert.rejects(bridge.bind(null), /unavailable/);
      else if (failure === 'foreign-bind')
        await assert.rejects(bridge.bind({ ...c, requestId: randomUUID() }), /unavailable/);
      else if (failure === 'next-before-bind') await assert.rejects(bridge.next(), /unavailable/);
      else {
        await bridge.bind(c);
        if (failure === 'bind-twice') await assert.rejects(bridge.bind(c), /unavailable/);
        else if (failure === 'accept-before-capture')
          await assert.rejects(bridge.accept({}), /unavailable/);
        else {
          await bridge.next();
          if (failure === 'next-twice') await assert.rejects(bridge.next(), /unavailable/);
          else {
            const [packet] = await restorePackets(c, '{}', '{}');
            packet.bundle.ciphertext = '!';
            await assert.rejects(bridge.accept(packet), /unavailable/);
          }
        }
      }
      const retry = await bridge.prepare();
      assert.equal(retry.action, 'hydrate');
      assert.notEqual(retry.requestId, q.requestId);
    } finally {
      await bridge.dispose();
    }
  }
});

test('late capture failure cannot clear the newer completed transfer and every borrowed buffer is wiped', async () => {
  const f = storageFixture(),
    original = f.storage.capture;
  let release!: (state: ExtensionStorageCapture) => void;
  f.storage.capture = () => new Promise((r) => (release = r));
  const bridge = createBitwardenExtensionBridge(owner(), f.storage),
    q = await bridge.prepare(),
    { c } = await native(q);
  const pending = bridge.bind(c);
  await tick();
  await assert.rejects(bridge.prepare(), /unavailable/);
  await assert.rejects(bridge.next(), /unavailable/);
  await bridge.cancel();
  f.storage.capture = original;
  const newer = await ready(bridge);
  await bridge.accept((await restorePackets(newer.c, '{}', '{}', '2', true))[0]);
  const late = { localJSON: bytes('{"secret":"late"}'), sessionJSON: bytes('{}') },
    rejected = assert.rejects(pending, /unavailable/);
  release(late);
  await rejected;
  assert.ok(late.localJSON.every((x) => x === 0) && late.sessionJSON.every((x) => x === 0));
  const next = await bridge.prepare();
  assert.equal(next.action, 'capture');
  assert.equal(next.sourceRevision, '2');
  await bridge.dispose();
});

test('cancel during apply clears recipient and witness immediately and retries via hydrate', async () => {
  const f = storageFixture(),
    bridge = createBitwardenExtensionBridge(owner(), f.storage);
  let release!: () => void,
    raw: Uint8Array[] = [];
  f.storage.restore = async (state, witness) => {
    raw = [state.localJSON, state.sessionJSON, witness.localJSON, witness.sessionJSON];
    await new Promise<void>((r) => (release = r));
  };
  try {
    const { c } = await ready(bridge),
      packets = await restorePackets(c, '{"secret":"borrowed"}', '{}'),
      pending = bridge.accept(packets[0]);
    while (!release) await tick();
    await bridge.cancel();
    assert.ok(raw.every((p) => p.every((x) => x === 0)));
    const rejected = assert.rejects(pending, /unavailable/);
    release();
    await rejected;
    const next = await bridge.prepare();
    assert.equal(next.action, 'hydrate');
    assert.equal(next.sourceRevision, '0');
  } finally {
    await bridge.dispose();
  }
});

test('a failed witness copy clears its already allocated prefix and both captured areas', async (t) => {
  const local = bytes('{"token":"private-copy"}'),
    session = bytes('{}'),
    f = storageFixture();
  f.storage.capture = async () => ({ localJSON: local, sessionJSON: session });
  let copied: Uint8Array | undefined;
  const slice = Uint8Array.prototype.slice;
  t.mock.method(
    Uint8Array.prototype,
    'slice',
    function (this: Uint8Array, ...args: [number?, number?]) {
      if (this === session) throw Error('private-allocation-diagnostic');
      const out = slice.apply(this, args);
      if (this === local) copied = out;
      return out;
    },
  );
  const bridge = createBitwardenExtensionBridge(owner(), f.storage);
  try {
    const q = await bridge.prepare(),
      { c } = await native(q);
    await assert.rejects(
      bridge.bind(c),
      (e) => e instanceof Error && /unavailable/.test(e.message) && !e.message.includes('private'),
    );
    assert.ok(copied?.every((x) => x === 0));
    assert.ok(local.every((x) => x === 0) && session.every((x) => x === 0));
    assert.equal((await bridge.prepare()).action, 'hydrate');
  } finally {
    await bridge.dispose();
  }
});

test('real local deadline and permanent document disposal retire pending stages', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const bridge = createBitwardenExtensionBridge(owner(), storageFixture().storage);
  const q = await bridge.prepare();
  t.mock.timers.tick(120001);
  await assert.rejects(bridge.bind((await native(q)).c), /unavailable/);
  assert.equal((await bridge.prepare()).action, 'hydrate');
  await bridge.dispose();
  await assert.rejects(bridge.prepare(), /unavailable/);
  await assert.rejects(bridge.next(), /unavailable/);
  await assert.rejects(bridge.accept({}), /unavailable/);
  assert.deepEqual(await bridge.dispose(), { closed: true });
  assert.deepEqual(await bridge.cancel(), { cancelled: true });
});

test('late key generation after cancellation cannot replace the next recipient', async (t) => {
  const original = crypto.subtle.generateKey.bind(crypto.subtle),
    pair = await original({ name: 'X25519' }, false, ['deriveBits']);
  let resolve!: (key: CryptoKeyPair) => void,
    first = true;
  t.mock.method(crypto.subtle, 'generateKey', (...args: any[]) => {
    if (first) {
      first = false;
      return new Promise<CryptoKeyPair>((r) => (resolve = r));
    }
    return (original as any)(...args);
  });
  const bridge = createBitwardenExtensionBridge(owner(), storageFixture().storage),
    pending = bridge.prepare();
  await tick();
  await bridge.cancel();
  const rejected = assert.rejects(pending, /unavailable/),
    next = await bridge.prepare();
  resolve(pair as CryptoKeyPair);
  await rejected;
  await bridge.bind((await native(next)).c);
  await bridge.next();
  await bridge.dispose();
});

test('maximum capture and five-chunk restore expose no plaintext and finish exactly once', async () => {
  const large = 'x'.repeat(browserTransferAreaBytes - 8),
    f = storageFixture({ v: large }, { v: large }),
    bridge = createBitwardenExtensionBridge(owner(), f.storage);
  try {
    const q = await bridge.prepare(),
      { c, capture } = await native(q),
      ack = await bridge.bind(c);
    assert.equal(ack.chunks, 5);
    for (let i = 0; i < ack.chunks; i++) {
      const packet = await bridge.next(),
        opened = await openCapture(packet, capture);
      assert.equal(opened.length, browserTransferChunkSize(ack.manifest, i));
      opened.fill(0);
    }
    const json = '{"v":"' + large + '"}',
      packets = await restorePackets(c, json, json, '9223372036854775807', false);
    for (let i = 0; i < packets.length; i++)
      assert.deepEqual(
        await bridge.accept(packets[i]),
        i === 4
          ? { complete: true, revision: '9223372036854775807', restore: false }
          : { complete: false },
      );
    await assert.rejects(bridge.accept(packets[4]), /unavailable/);
    const next = await bridge.prepare();
    assert.equal(next.sourceRevision, '9223372036854775807');
    assert.equal(next.action, 'capture');
  } finally {
    await bridge.dispose();
  }
});
