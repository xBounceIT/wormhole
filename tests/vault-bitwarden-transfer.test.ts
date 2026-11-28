import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from '@hpke/core';
import {
  createBitwardenTransferCapture,
  createBitwardenTransferRecipient,
} from '../src/vault-bitwarden-transfer-recipient.ts';
import {
  browserTransferAreaBytes,
  browserTransferChunkBytes,
  browserTransferFrameBytes,
  browserTransferChunkCount,
  browserTransferChunkSize,
  browserTransferDecimal,
  browserTransferInfo,
  parseBrowserTransferContext,
  parseBrowserTransferManifest,
  parseBrowserTransferPacket,
  encodeBrowserTransferFrame,
  decodeBrowserTransferFrame,
  type BrowserTransferContext,
  type BrowserTransferManifest,
  type BrowserTransferPacket,
} from '../electron/vault-bitwarden-transfer.ts';
import { enrollmentBytes } from '../electron/vault-enrollment-contract.ts';
const encoder = new TextEncoder();
const bytes = (s: string) => encoder.encode(s);
const b64 = (raw: Uint8Array) => Buffer.from(raw).toString('base64');
const cipher = () =>
  new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
async function fixture(restorePublicKey?: string) {
  const capture = (await crypto.subtle.generateKey({ name: 'X25519' }, false, [
    'deriveBits',
  ])) as CryptoKeyPair;
  const restore = (await crypto.subtle.generateKey({ name: 'X25519' }, false, [
    'deriveBits',
  ])) as CryptoKeyPair;
  const c: BrowserTransferContext = {
    workspaceId: randomUUID(),
    fileId: randomUUID(),
    profileId: randomUUID(),
    requestId: randomUUID(),
    transferId: randomUUID(),
    epoch: 2,
    policySequence: '9223372036854775807',
    action: 'hydrate',
    sourceRevision: '1',
    capturePublicKey: b64(new Uint8Array(await crypto.subtle.exportKey('raw', capture.publicKey))),
    restorePublicKey:
      restorePublicKey ??
      b64(new Uint8Array(await crypto.subtle.exportKey('raw', restore.publicKey))),
  };
  return { c, capture, restore };
}
async function restorePacket(
  c: BrowserTransferContext,
  raw: Uint8Array,
  index = 0,
  m: BrowserTransferManifest = { bytes: raw.length, revision: '2', restore: true },
): Promise<BrowserTransferPacket> {
  const crypto = cipher(),
    pub = await crypto.kem.deserializePublicKey(enrollmentBytes(c.restorePublicKey, 32)!);
  const result = await crypto.seal(
    { recipientPublicKey: pub, info: browserTransferInfo(c, 'restore', m, index) },
    raw.subarray(
      index * browserTransferChunkBytes,
      index * browserTransferChunkBytes + browserTransferChunkSize(m, index),
    ),
  );
  return {
    context: { ...c },
    direction: 'restore',
    manifest: { ...m },
    index,
    bundle: {
      formatVersion: 1,
      suiteId: 2,
      enc: b64(new Uint8Array(result.enc)),
      ciphertext: b64(new Uint8Array(result.ct)),
    },
  };
}

test('browser transfer metadata is exact, immutable and retains every revision bit', async () => {
  const { c } = await fixture();
  const parsed = parseBrowserTransferContext(c)!;
  assert.ok(parsed);
  c.epoch = 3;
  assert.equal(parsed.epoch, 2);
  for (const field of ['workspaceId', 'fileId', 'profileId', 'requestId', 'transferId'])
    assert.equal(parseBrowserTransferContext({ ...parsed, [field]: 'bad' }), undefined);
  for (const bad of [
    { epoch: 0 },
    { epoch: 1.5 },
    { epoch: Number.MAX_SAFE_INTEGER + 1 },
    { action: 'other' },
    { policySequence: '0' },
    { sourceRevision: '01' },
    { capturePublicKey: 'bad' },
    { restorePublicKey: 'bad' },
    { password: 'secret' },
  ])
    assert.equal(parseBrowserTransferContext({ ...parsed, ...bad }), undefined);
  for (const value of [null, [], {}, undefined])
    assert.equal(parseBrowserTransferContext(value), undefined);
  for (const value of ['', '01', '+1', '-1', '1e1', '9223372036854775808', undefined, 2])
    assert.equal(browserTransferDecimal(value), false);
  assert.equal(browserTransferDecimal('0', false), false);
  assert.equal(browserTransferDecimal('9223372036854775807'), true);
  const m = { bytes: 14, revision: '1', restore: false };
  assert.ok(parseBrowserTransferManifest(m, parsed, 'capture'));
  for (const bad of [
    { bytes: 13 },
    { bytes: browserTransferFrameBytes + 1 },
    { bytes: 2.2 },
    { revision: '0' },
    { restore: true },
    { password: 'secret' },
  ])
    assert.equal(parseBrowserTransferManifest({ ...m, ...bad }, parsed, 'capture'), undefined);
  assert.equal(parseBrowserTransferManifest(m, parsed, 'bad'), undefined);
  assert.equal(parseBrowserTransferManifest(null, parsed, 'restore'), undefined);
  assert.equal(parseBrowserTransferManifest({ ...m, revision: '0' }, parsed, 'restore'), undefined);
  assert.throws(() => browserTransferInfo(null, 'capture', m, 0));
  assert.throws(() => browserTransferChunkCount({ ...m, bytes: 0 }));
  assert.throws(() => browserTransferChunkSize(m, -1));
  assert.throws(() => browserTransferChunkSize(m, 1));
  assert.throws(() => browserTransferChunkSize(m, 0.5));
  assert.equal(browserTransferChunkCount({ ...m, bytes: browserTransferFrameBytes }), 5);
  assert.equal(browserTransferChunkSize({ ...m, bytes: browserTransferFrameBytes }, 4), 10);
});

test('browser plaintext frame borrows exact JSON bytes and rejects malformed areas and lengths', () => {
  const local = bytes('{"n":9007199254740993,"unicode":"🔑"}'),
    session = bytes('{}'),
    raw = encodeBrowserTransferFrame(local, session);
  const decoded = decodeBrowserTransferFrame(raw);
  assert.deepEqual(decoded.localJSON, local);
  assert.deepEqual(decoded.sessionJSON, session);
  raw.fill(0);
  assert.ok(decoded.localJSON.every((x) => x === 0));
  for (const bad of [
    new Uint8Array(),
    bytes('[]'),
    bytes('null'),
    bytes('{} {}'),
    new Uint8Array([255, 123, 125]),
    bytes('"x"'),
    new Uint8Array(browserTransferAreaBytes + 1),
  ]) {
    assert.throws(() => encodeBrowserTransferFrame(bad, session));
    assert.throws(() => encodeBrowserTransferFrame(local, bad));
  }
  const good = encodeBrowserTransferFrame(bytes('{}'), bytes('{}'));
  for (const mutate of [
    (r: Uint8Array) => r.subarray(1),
    (r: Uint8Array) => {
      r[0] = 2;
      return r;
    },
    (r: Uint8Array) => {
      r[1] = 1;
      return r;
    },
    (r: Uint8Array) => {
      new DataView(r.buffer).setUint32(2, 0xffffffff);
      return r;
    },
    (r: Uint8Array) => {
      r[10] = 91;
      return r;
    },
    (r: Uint8Array) => {
      r[r.length - 2] = 91;
      return r;
    },
  ])
    assert.throws(() => decodeBrowserTransferFrame(mutate(good.slice())));
  assert.throws(() => decodeBrowserTransferFrame(new Uint8Array()));
});

test('capture consumes caller bytes, emits bounded opaque packets and closes after its last chunk', async () => {
  const { c, capture } = await fixture();
  const local = bytes('{"capture":"private-synthetic"}'),
    session = bytes('{"session":"temporary"}');
  const expected = encodeBrowserTransferFrame(local, session),
    sender = await createBitwardenTransferCapture(c, local, session);
  assert.ok(local.every((x) => x === 0) && session.every((x) => x === 0));
  const packet = await sender.next();
  assert.ok(parseBrowserTransferPacket(packet, c, 'capture'));
  assert.equal(JSON.stringify(packet).includes('private-synthetic'), false);
  assert.equal(sender.chunks, 1);
  const opened = new Uint8Array(
    await cipher().open(
      {
        recipientKey: capture,
        enc: enrollmentBytes(packet.bundle.enc, 32)!,
        info: browserTransferInfo(c, 'capture', packet.manifest, 0),
      },
      enrollmentBytes(packet.bundle.ciphertext, expected.length + 16)!,
    ),
  );
  assert.deepEqual(opened, expected);
  await assert.rejects(sender.next(), /closed/);
  sender.dispose();
  const failures = [
    { ...packet, password: 'secret' },
    { ...packet, direction: 'restore' },
    { ...packet, index: 1 },
    { ...packet, context: { ...c, profileId: randomUUID() } },
    { ...packet, manifest: { ...packet.manifest, bytes: 13 } },
    { ...packet, bundle: { ...packet.bundle, suiteId: 1 } },
    { ...packet, bundle: { ...packet.bundle, enc: 'bad' } },
    { ...packet, bundle: { ...packet.bundle, ciphertext: 'bad' } },
    null,
  ];
  for (const bad of failures)
    assert.equal(parseBrowserTransferPacket(bad, c, 'capture'), undefined);
  assert.equal(parseBrowserTransferPacket(packet, { ...c, epoch: 0 }, 'capture'), undefined);
});

test('recipient applies only in its isolated callback and returns public metadata with wiped borrowed bytes', async () => {
  let borrowed: Uint8Array[] = [];
  const receiver = await createBitwardenTransferRecipient((state, receipt, signal) => {
    assert.equal(signal.aborted, false);
    assert.equal(receipt.revision, '2');
    assert.equal(new TextDecoder().decode(state.localJSON), '{"restore":"private-synthetic"}');
    borrowed = [state.localJSON, state.sessionJSON];
  });
  const { c } = await fixture(receiver.publicKey);
  receiver.bind(c);
  const frame = encodeBrowserTransferFrame(bytes('{"restore":"private-synthetic"}'), bytes('{}'));
  const result = await receiver.accept(await restorePacket(c, frame));
  assert.deepEqual(result, { revision: '2', restore: true });
  assert.ok(borrowed.every((p) => p.every((x) => x === 0)));
  assert.equal(JSON.stringify(result).includes('private-synthetic'), false);
  await assert.rejects(receiver.accept(null), /closed/);
  receiver.dispose();
});

test('packet substitution, ordering, cipher failure and malformed restored JSON retire the receiver', async () => {
  for (const mode of ['context', 'direction', 'index', 'cipher', 'frame', 'length', 'manifest']) {
    let calls = 0;
    const receiver = await createBitwardenTransferRecipient(() => {
      calls++;
    });
    const { c } = await fixture(receiver.publicKey);
    receiver.bind(c);
    const frame = encodeBrowserTransferFrame(bytes('{}'), bytes('{}'));
    if (mode === 'frame') frame[10] = 91;
    const packet = await restorePacket(c, frame);
    if (mode === 'context') packet.context.transferId = randomUUID();
    if (mode === 'direction') packet.direction = 'capture';
    if (mode === 'index') packet.index = 1;
    if (mode === 'cipher') {
      const encrypted = Buffer.from(packet.bundle.ciphertext, 'base64');
      encrypted[0] ^= 1;
      packet.bundle.ciphertext = encrypted.toString('base64');
    }
    if (mode === 'length') packet.manifest.bytes++;
    if (mode === 'manifest') packet.manifest.restore = false;
    await assert.rejects(receiver.accept(packet), /could not be completed/);
    assert.equal(calls, 0);
    await assert.rejects(receiver.accept(packet), /closed/);
  }
});

test('capture failures consume inputs and recipient binding is one use', async () => {
  const { c } = await fixture();
  const abort = new AbortController();
  abort.abort();
  for (const [value, local, session, signal] of [
    [null, bytes('{}'), bytes('{}'), undefined],
    [c, bytes('[]'), bytes('{}'), undefined],
    [c, bytes('{}'), bytes('{}'), abort.signal],
  ] as const) {
    await assert.rejects(createBitwardenTransferCapture(value, local, session, signal));
    assert.ok(local.every((x) => x === 0) && session.every((x) => x === 0));
  }
  await assert.rejects(createBitwardenTransferRecipient(() => {}, abort.signal));
  const unbound = await createBitwardenTransferRecipient(() => {});
  await assert.rejects(unbound.accept(null), /closed/);
  const invalid = await createBitwardenTransferRecipient(() => {});
  assert.throws(() => invalid.bind(c));
  const receiver = await createBitwardenTransferRecipient(() => {}),
    f = await fixture(receiver.publicKey);
  receiver.bind(f.c);
  assert.throws(() => receiver.bind(f.c));
  const sender = await createBitwardenTransferCapture(c, bytes('{}'), bytes('{}'));
  sender.dispose();
  await assert.rejects(sender.next());
});

test('cancellation and a failed apply wipe restored data and prevent a successful receipt', async () => {
  for (const mode of ['abort', 'dispose', 'throw']) {
    let entered!: () => void,
      release!: () => void,
      borrowed: Uint8Array[] = [];
    const ready = new Promise<void>((r) => {
        entered = r;
      }),
      held = new Promise<void>((r) => {
        release = r;
      });
    const abort = new AbortController();
    const receiver = await createBitwardenTransferRecipient(async (state) => {
      borrowed = [state.localJSON, state.sessionJSON];
      entered();
      await held;
      if (mode === 'throw') throw Error('private callback diagnostic');
    }, abort.signal);
    const { c } = await fixture(receiver.publicKey);
    receiver.bind(c);
    const pending = receiver.accept(
      await restorePacket(c, encodeBrowserTransferFrame(bytes('{"x":"secret"}'), bytes('{}'))),
    );
    await ready;
    if (mode === 'abort') abort.abort();
    if (mode === 'dispose') receiver.dispose();
    if (mode !== 'throw')
      assert.ok(
        borrowed.every((p) => p.every((x) => x === 0)),
        'dispose must wipe borrowed bytes before the callback settles',
      );
    release();
    await assert.rejects(pending, /could not be completed/);
    assert.ok(borrowed.every((p) => p.every((x) => x === 0)));
  }
});

test('full-size transfer uses five chunks, freezes the context and rejects interleaved manifests', async () => {
  const large = bytes('{"v":"' + 'x'.repeat(browserTransferAreaBytes - 8) + '"}');
  let called = 0;
  const receiver = await createBitwardenTransferRecipient((state) => {
    called++;
    assert.equal(state.localJSON.length, browserTransferAreaBytes);
    assert.equal(state.sessionJSON.length, browserTransferAreaBytes);
  });
  const { c } = await fixture(receiver.publicKey);
  receiver.bind(c);
  const frame = encodeBrowserTransferFrame(large, large),
    manifest = { bytes: frame.length, revision: '2', restore: true };
  for (let i = 0; i < 5; i++) {
    const result = await receiver.accept(await restorePacket(c, frame, i, manifest));
    assert.equal(Boolean(result), i === 4);
  }
  assert.equal(called, 1);
  const changed = await createBitwardenTransferRecipient(() => {
    assert.fail('incomplete transfer applied');
  });
  const next = await fixture(changed.publicKey);
  changed.bind(next.c);
  await changed.accept(await restorePacket(next.c, frame, 0, manifest));
  const bad = await restorePacket(next.c, frame, 1, { ...manifest, revision: '3' });
  await assert.rejects(changed.accept(bad));
  const sender = await createBitwardenTransferCapture(c, large.slice(), large.slice());
  assert.equal(sender.chunks, 5);
  const first = await sender.next();
  first.context.epoch = 100;
  first.manifest.bytes = 14;
  const second = await sender.next();
  assert.equal(second.context.epoch, c.epoch);
  assert.equal(second.manifest.bytes, frame.length);
  sender.dispose();
});

test('capture crypto failures and concurrent calls retire pending work without returning ciphertext', async () => {
  const { c } = await fixture();
  const bad = await createBitwardenTransferCapture(
    { ...c, capturePublicKey: Buffer.alloc(32).toString('base64') },
    bytes('{}'),
    bytes('{}'),
  );
  await assert.rejects(bad.next(), /could not be encrypted/);
  await assert.rejects(bad.next(), /closed/);
  const sender = await createBitwardenTransferCapture(c, bytes('{}'), bytes('{}'));
  const first = sender.next();
  const firstObserved = assert.rejects(first, /could not be encrypted/);
  await assert.rejects(sender.next(), /closed/);
  await firstObserved;
  const abort = new AbortController(),
    cancelled = await createBitwardenTransferCapture(c, bytes('{}'), bytes('{}'), abort.signal);
  abort.abort();
  await assert.rejects(cancelled.next(), /closed/);
  const receiver = await createBitwardenTransferRecipient(() => {
      assert.fail('concurrent restore applied');
    }),
    next = await fixture(receiver.publicKey);
  receiver.bind(next.c);
  const packet = await restorePacket(next.c, encodeBrowserTransferFrame(bytes('{}'), bytes('{}')));
  const pending = receiver.accept(packet);
  const observed = assert.rejects(pending, /could not be completed/);
  await assert.rejects(receiver.accept(packet), /closed/);
  await observed;
  assert.equal(
    parseBrowserTransferManifest({ bytes: 14, revision: '1', restore: false }, null, 'capture'),
    undefined,
  );
});

test('valid-looking metadata retagging still fails HPKE authentication', async () => {
  for (const field of [
    'workspaceId',
    'fileId',
    'profileId',
    'requestId',
    'transferId',
    'epoch',
    'policySequence',
    'action',
    'sourceRevision',
    'capturePublicKey',
  ]) {
    let calls = 0;
    const receiver = await createBitwardenTransferRecipient(() => {
      calls++;
    });
    const { c } = await fixture(receiver.publicKey);
    const frame = encodeBrowserTransferFrame(bytes('{}'), bytes('{}')),
      packet = await restorePacket(c, frame);
    const altered = {
      ...c,
      [field]:
        field === 'epoch'
          ? 3
          : field === 'policySequence'
            ? '2'
            : field === 'action'
              ? 'capture'
              : field === 'sourceRevision'
                ? '0'
                : field === 'capturePublicKey'
                  ? Buffer.alloc(32, 4).toString('base64')
                  : randomUUID(),
    };
    receiver.bind(altered);
    packet.context = altered;
    assert.ok(parseBrowserTransferPacket(packet, altered, 'restore'));
    await assert.rejects(receiver.accept(packet), /could not be completed/);
    assert.equal(calls, 0);
  }
});

test('recipient factory cancellation during key creation or public export never returns a live recipient', async () => {
  for (const method of ['generateKey', 'exportKey']) {
    const subtle = crypto.subtle as unknown as Record<
      string,
      (...args: unknown[]) => Promise<unknown>
    >;
    const original = subtle[method];
    let entered!: () => void, release!: () => void;
    const ready = new Promise<void>((r) => {
        entered = r;
      }),
      held = new Promise<void>((r) => {
        release = r;
      });
    const abort = new AbortController();
    subtle[method] = async (...args: unknown[]) => {
      entered();
      await held;
      return Reflect.apply(original, crypto.subtle, args);
    };
    try {
      const pending = createBitwardenTransferRecipient(() => {
        assert.fail('cancelled factory applied data');
      }, abort.signal);
      const observed = assert.rejects(pending, /unavailable/);
      await ready;
      abort.abort();
      release();
      await observed;
    } finally {
      subtle[method] = original;
      release();
    }
  }
});
