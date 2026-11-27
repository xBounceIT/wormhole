import assert from 'node:assert/strict';
import test from 'node:test';
import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from '@hpke/core';
import {
  parseVaultVncPasswordContext,
  parseVaultVncPasswordEnvelope,
  vncPasswordInfo,
} from '../electron/vault-vnc-password.ts';
import { sealVncTemporaryPassword } from '../src/vault-vnc-password-sender.ts';
import { vncRequest, vncBundle, routedVncRequest } from './fixtures/vault-vnc.ts';
function context(routed = false) {
  const q = routed ? routedVncRequest() : vncRequest();
  return {
    binding: 'route' in q ? q.route : vncBundle(q).binding,
    publicKey: q.publicKey,
    ...('endpoint' in q ? { endpoint: q.endpoint } : {}),
  };
}
const suite = () =>
  new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });

test('temporary VNC password context is exact, immutable and uses fourteen canonical UTF-8 fields', () => {
  for (const routed of [false, true]) {
    const c = context(routed);
    c.binding.host = 'café.example';
    const parsed = parseVaultVncPasswordContext(c);
    assert.deepEqual(parsed, c);
    const b = c.binding,
      r = 'fileId' in b ? b : undefined;
    const fields = [
      b.workspaceId,
      b.nodeId,
      b.sessionId,
      b.requestId,
      'vnc',
      'café.example',
      '5900',
      b.tunnelConfigId,
      '1',
      r?.fileId ?? '',
      r ? '6' : '',
      r?.rowVersion ?? '',
      r?.configurationVersion ?? '',
      'endpoint' in c ? c.endpoint : '',
    ];
    const expected = Buffer.concat([
      Buffer.from('wormhole/v1/vnc-manual-password'),
      ...fields.flatMap((field) => {
        const bytes = Buffer.from(field),
          size = Buffer.alloc(4);
        size.writeUInt32BE(bytes.length);
        return [size, bytes];
      }),
    ]);
    assert.deepEqual(Buffer.from(vncPasswordInfo(c)), expected);
    parsed!.binding.host = 'mutated';
    assert.equal(c.binding.host, 'café.example');
  }
  const good = context();
  for (const value of [
    null,
    {},
    { ...good, extra: true },
    { ...good, publicKey: 'bad' },
    { ...good, endpoint: undefined },
    { ...good, endpoint: 'localhost:1234' },
    ...['workspaceId', 'nodeId', 'sessionId', 'requestId'].map((field) => ({
      ...good,
      binding: { ...good.binding, [field]: 'bad' },
    })),
    { ...good, binding: { ...good.binding, protocol: 'ssh' } },
    { ...good, binding: { ...good.binding, epoch: 0 } },
    { ...good, binding: { ...good.binding, epoch: 2 ** 53 } },
    { ...good, binding: { ...good.binding, host: 'bad host' } },
    { ...good, binding: { ...good.binding, useExternalClient: true } },
    { ...good, binding: { ...good.binding, port: 65536 } },
    { ...good, binding: { ...good.binding, extra: true } },
    { ...good, binding: { ...good.binding, tunnelConfigId: vncRequest().nodeId } },
  ]) {
    assert.equal(parseVaultVncPasswordContext(value), undefined);
    assert.throws(() => vncPasswordInfo(value), /Invalid/);
  }
  const routed = context(true);
  assert.equal(
    parseVaultVncPasswordContext({ ...routed, binding: { ...routed.binding, rowVersion: '0' } }),
    undefined,
  );
});

test('temporary password sealing consumes caller bytes and round-trips empty, raw and maximum passwords', async () => {
  for (const routed of [false, true])
    for (const input of [
      new Uint8Array(),
      new TextEncoder().encode('one-use-browser'),
      new Uint8Array([0, 255, 1]),
      new Uint8Array(16384).fill(7),
    ]) {
      const pair = (await crypto.subtle.generateKey({ name: 'X25519' }, false, [
          'deriveBits',
        ])) as CryptoKeyPair,
        c = context(routed);
      c.publicKey = Buffer.from(await crypto.subtle.exportKey('raw', pair.publicKey)).toString(
        'base64',
      );
      const copy = new Uint8Array(input);
      const pending = sealVncTemporaryPassword(c, copy);
      assert.ok(copy.every((v) => v === 0));
      const sealed = await pending;
      assert.deepEqual(parseVaultVncPasswordEnvelope(sealed), sealed);
      const raw = new Uint8Array(
        await suite().open(
          {
            recipientKey: pair.privateKey,
            enc: Buffer.from(sealed.enc, 'base64'),
            info: vncPasswordInfo(c),
          },
          Buffer.from(sealed.ciphertext, 'base64'),
        ),
      );
      assert.equal(raw[0], 1);
      assert.equal(raw[1], 1);
      assert.equal(new DataView(raw.buffer).getUint32(2), input.length);
      assert.deepEqual(raw.subarray(6), input);
      raw.fill(0);
      const wrong = { ...c, binding: { ...c.binding, host: 'redirect.example' } };
      await assert.rejects(
        suite().open(
          {
            recipientKey: pair.privateKey,
            enc: Buffer.from(sealed.enc, 'base64'),
            info: vncPasswordInfo(wrong),
          },
          Buffer.from(sealed.ciphertext, 'base64'),
        ),
      );
    }
});

test('password envelope rejects unsupported suites and malformed, short or oversized ciphertext', () => {
  const good = {
    formatVersion: 1 as const,
    suiteId: 2 as const,
    enc: Buffer.alloc(32).toString('base64'),
    ciphertext: Buffer.alloc(22).toString('base64'),
  };
  assert.deepEqual(parseVaultVncPasswordEnvelope(good), good);
  for (const value of [
    null,
    {},
    { ...good, extra: true },
    { ...good, formatVersion: 2 },
    { ...good, suiteId: 3 },
    { ...good, enc: 'bad' },
    { ...good, ciphertext: 'bad' },
    { ...good, ciphertext: Buffer.alloc(21).toString('base64') },
    { ...good, ciphertext: Buffer.alloc(16407).toString('base64') },
    { ...good, ciphertext: good.ciphertext + '\n' },
  ])
    assert.equal(parseVaultVncPasswordEnvelope(value), undefined);
  assert.ok(
    parseVaultVncPasswordEnvelope({ ...good, ciphertext: Buffer.alloc(16406).toString('base64') }),
  );
});

test('password sealing wipes input on invalid context, limits, cryptographic errors and cancellation', async () => {
  for (const mode of ['context', 'oversized', 'crypto', 'cancelled', 'late']) {
    const input = new Uint8Array(mode === 'oversized' ? 16385 : 8).fill(9),
      c = context(),
      abort = new AbortController();
    if (mode === 'crypto') c.publicKey = Buffer.alloc(32).toString('base64');
    if (mode === 'cancelled') abort.abort();
    const pending = sealVncTemporaryPassword(mode === 'context' ? {} : c, input, abort.signal);
    if (mode === 'late') abort.abort();
    await assert.rejects(pending, /VNC password/);
    assert.ok(input.every((v) => v === 0));
  }
  await assert.rejects(sealVncTemporaryPassword(context(), null as any), /VNC password/);
});

test('late encrypted result is discarded after the isolated password document cancels', async (t) => {
  const pair = (await crypto.subtle.generateKey({ name: 'X25519' }, false, [
      'deriveBits',
    ])) as CryptoKeyPair,
    c = context();
  c.publicKey = Buffer.from(await crypto.subtle.exportKey('raw', pair.publicKey)).toString(
    'base64',
  );
  const abort = new AbortController(),
    original = crypto.subtle.encrypt.bind(crypto.subtle);
  let entered!: () => void, release!: () => void;
  const begun = new Promise<void>((r) => (entered = r)),
    resume = new Promise<void>((r) => (release = r));
  t.mock.method(
    crypto.subtle,
    'encrypt',
    async (...args: Parameters<typeof crypto.subtle.encrypt>) => {
      entered();
      await resume;
      return original(...args);
    },
  );
  const input = new Uint8Array([1, 2, 3]),
    pending = sealVncTemporaryPassword(c, input, abort.signal);
  void pending.catch(() => {});
  await begun;
  assert.ok(input.every((v) => v === 0));
  abort.abort();
  release();
  await assert.rejects(pending, /cancelled/);
});
