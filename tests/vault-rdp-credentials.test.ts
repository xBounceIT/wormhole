import assert from 'node:assert/strict';
import test from 'node:test';
import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from '@hpke/core';
import {
  parseVaultRdpCredentialsContext,
  parseVaultRdpCredentialsEnvelope,
  rdpCredentialsInfo,
} from '../electron/vault-rdp-credentials.ts';
import { sealRdpTemporaryCredentials } from '../src/vault-rdp-credentials-sender.ts';
import { rdpRequest, rdpBundle, routedRdpRequest } from './fixtures/vault-rdp.ts';
function context(routed = false) {
  const q = routed ? routedRdpRequest() : rdpRequest();
  return {
    binding: 'route' in q ? q.route : rdpBundle(q).binding,
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

test('temporary RDP password context is exact, immutable and uses fourteen canonical UTF-8 fields', () => {
  for (const routed of [false, true]) {
    const c = context(routed);
    c.binding.host = 'café.example';
    const parsed = parseVaultRdpCredentialsContext(c);
    assert.deepEqual(parsed, c);
    const b = c.binding,
      r = 'fileId' in b ? b : undefined;
    const fields = [
      b.workspaceId,
      b.nodeId,
      b.sessionId,
      b.requestId,
      'rdp',
      'café.example',
      '3389',
      b.tunnelConfigId,
      '1',
      r?.fileId ?? '',
      r ? '6' : '',
      r?.rowVersion ?? '',
      r?.configurationVersion ?? '',
      'endpoint' in c ? c.endpoint : '',
    ];
    const expected = Buffer.concat([
      Buffer.from('wormhole/v1/rdp-manual-credentials'),
      ...fields.flatMap((field) => {
        const bytes = Buffer.from(field),
          size = Buffer.alloc(4);
        size.writeUInt32BE(bytes.length);
        return [size, bytes];
      }),
    ]);
    assert.deepEqual(Buffer.from(rdpCredentialsInfo(c)), expected);
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
    { ...good, binding: { ...good.binding, tunnelConfigId: rdpRequest().nodeId } },
  ]) {
    assert.equal(parseVaultRdpCredentialsContext(value), undefined);
    assert.throws(() => rdpCredentialsInfo(value), /Invalid/);
  }
  const routed = context(true);
  assert.equal(
    parseVaultRdpCredentialsContext({ ...routed, binding: { ...routed.binding, rowVersion: '0' } }),
    undefined,
  );
});

test('manual RDP sealing consumes all fields and preserves Unicode and explicit empty passwords', async () => {
  for (const routed of [false, true])
    for (const password of ['', 'one-use-browser', '𐀀'.repeat(4096)]) {
      const pair = (await crypto.subtle.generateKey({ name: 'X25519' }, false, [
        'deriveBits',
      ])) as CryptoKeyPair;
      const c = context(routed);
      c.publicKey = Buffer.from(await crypto.subtle.exportKey('raw', pair.publicKey)).toString(
        'base64',
      );
      const texts = ['例 user', '領域', password],
        fields = texts.map((s) => new TextEncoder().encode(s));
      const pending = sealRdpTemporaryCredentials(c, {
        username: fields[0],
        domain: fields[1],
        password: fields[2],
      });
      assert.ok(fields.every((f) => f.every((n) => n === 0)));
      const sealed = await pending;
      assert.deepEqual(parseVaultRdpCredentialsEnvelope(sealed), sealed);
      const raw = new Uint8Array(
        await suite().open(
          {
            recipientKey: pair.privateKey,
            enc: Buffer.from(sealed.enc, 'base64'),
            info: rdpCredentialsInfo(c),
          },
          Buffer.from(sealed.ciphertext, 'base64'),
        ),
      );
      assert.equal(raw[0], 1);
      assert.equal(raw[1], 1);
      let offset = 2;
      for (const text of texts) {
        const size = new DataView(raw.buffer).getUint32(offset);
        offset += 4;
        assert.equal(new TextDecoder().decode(raw.subarray(offset, offset + size)), text);
        offset += size;
      }
      assert.equal(offset, raw.length);
      raw.fill(0);
      await assert.rejects(
        suite().open(
          {
            recipientKey: pair.privateKey,
            enc: Buffer.from(sealed.enc, 'base64'),
            info: rdpCredentialsInfo({ ...c, binding: { ...c.binding, host: 'changed.example' } }),
          },
          Buffer.from(sealed.ciphertext, 'base64'),
        ),
      );
    }
});
test('RDP credentials envelope rejects malformed, unsupported or out-of-range packets', () => {
  const good = {
    formatVersion: 1,
    suiteId: 2,
    enc: Buffer.alloc(32).toString('base64'),
    ciphertext: Buffer.alloc(30).toString('base64'),
  };
  assert.deepEqual(parseVaultRdpCredentialsEnvelope(good), good);
  for (const value of [
    null,
    {},
    { ...good, extra: true },
    { ...good, formatVersion: 2 },
    { ...good, suiteId: 3 },
    { ...good, enc: 'bad' },
    { ...good, ciphertext: 'bad' },
    { ...good, ciphertext: Buffer.alloc(29).toString('base64') },
    { ...good, ciphertext: Buffer.alloc(20511).toString('base64') },
    { ...good, ciphertext: good.ciphertext + '\n' },
  ])
    assert.equal(parseVaultRdpCredentialsEnvelope(value), undefined);
  assert.ok(
    parseVaultRdpCredentialsEnvelope({
      ...good,
      ciphertext: Buffer.alloc(20510).toString('base64'),
    }),
  );
});
test('RDP sender clears every input buffer on validation, crypto and cancellation failures', async () => {
  for (const mode of [
    'context',
    'oversized-user',
    'oversized-password',
    'empty-user',
    'runes',
    'utf8',
    'nul',
    'crypto',
    'cancelled',
    'late',
  ]) {
    const c = context(),
      abort = new AbortController();
    const fields = {
      username: new TextEncoder().encode('user'),
      domain: new TextEncoder().encode('DOMAIN'),
      password: new TextEncoder().encode('private'),
    };
    if (mode === 'oversized-user') fields.username = new Uint8Array(2049).fill(97);
    if (mode === 'oversized-password') fields.password = new Uint8Array(16385).fill(97);
    if (mode === 'empty-user') fields.username = new Uint8Array();
    if (mode === 'runes') fields.domain = new Uint8Array(514).fill(97);
    if (mode === 'utf8') fields.password = new Uint8Array([255]);
    if (mode === 'nul') fields.password = new Uint8Array([97, 0]);
    if (mode === 'crypto') c.publicKey = Buffer.alloc(32).toString('base64');
    if (mode === 'cancelled') abort.abort();
    const p = sealRdpTemporaryCredentials(mode === 'context' ? {} : c, fields, abort.signal);
    if (mode === 'late') abort.abort();
    await assert.rejects(p, /RDP credential/);
    assert.ok(
      Object.values(fields).every((f) => f.every((n) => n === 0)),
      mode,
    );
  }
  await assert.rejects(sealRdpTemporaryCredentials(context(), null as any), /RDP credential/);
});
test('late RDP credential encryption cannot submit after cancellation', async (t) => {
  const pair = (await crypto.subtle.generateKey({ name: 'X25519' }, false, [
      'deriveBits',
    ])) as CryptoKeyPair,
    c = context();
  c.publicKey = Buffer.from(await crypto.subtle.exportKey('raw', pair.publicKey)).toString(
    'base64',
  );
  const abort = new AbortController();
  let entered!: () => void, release!: () => void;
  const begun = new Promise<void>((r) => (entered = r)),
    resume = new Promise<void>((r) => (release = r)),
    original = crypto.subtle.encrypt.bind(crypto.subtle);
  t.mock.method(
    crypto.subtle,
    'encrypt',
    async (...args: Parameters<typeof crypto.subtle.encrypt>) => {
      entered();
      await resume;
      return original(...args);
    },
  );
  const input = {
    username: new TextEncoder().encode('u'),
    domain: new Uint8Array(),
    password: new TextEncoder().encode('p'),
  };
  const p = sealRdpTemporaryCredentials(c, input, abort.signal);
  void p.catch(() => {});
  await begun;
  abort.abort();
  release();
  await assert.rejects(p, /cancelled/);
  assert.ok(Object.values(input).every((f) => f.every((n) => n === 0)));
});

test('RDP UTF-8 validation counts a leading BOM as a credential code point like Go', async () => {
  const pair = (await crypto.subtle.generateKey({ name: 'X25519' }, false, [
    'deriveBits',
  ])) as CryptoKeyPair;
  const c = context();
  c.publicKey = Buffer.from(await crypto.subtle.exportKey('raw', pair.publicKey)).toString(
    'base64',
  );
  for (const [field, limit] of [
    ['username', 513],
    ['domain', 513],
    ['password', 4096],
  ] as const) {
    const input = {
      username: new TextEncoder().encode('u'),
      domain: new Uint8Array(),
      password: new Uint8Array(),
    };
    input[field] = new TextEncoder().encode('\ufeff' + 'a'.repeat(limit));
    await assert.rejects(sealRdpTemporaryCredentials(c, input), /RDP credential/);
    assert.ok(Object.values(input).every((bytes) => bytes.every((value) => value === 0)));
  }
  const input = {
    username: new TextEncoder().encode('\ufeff'),
    domain: new Uint8Array(),
    password: new TextEncoder().encode('\ufeff' + 'a'.repeat(4095)),
  };
  const expected = Object.values(input).map((bytes) => new Uint8Array(bytes));
  const sealed = await sealRdpTemporaryCredentials(c, input);
  const frame = new Uint8Array(
    await suite().open(
      {
        recipientKey: pair.privateKey,
        enc: Buffer.from(sealed.enc, 'base64'),
        info: rdpCredentialsInfo(c),
      },
      Buffer.from(sealed.ciphertext, 'base64'),
    ),
  );
  let offset = 2;
  for (const bytes of expected) {
    const length = new DataView(frame.buffer).getUint32(offset);
    offset += 4;
    assert.deepEqual(frame.slice(offset, offset + length), bytes);
    offset += length;
  }
  assert.equal(offset, frame.length);
  frame.fill(0);
  expected.forEach((bytes) => bytes.fill(0));
});
