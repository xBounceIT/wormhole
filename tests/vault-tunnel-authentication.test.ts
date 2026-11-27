import assert from 'node:assert/strict';
import test from 'node:test';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import {
  parseVaultTunnelAuthenticationContext as parseContext,
  parseVaultTunnelAuthenticationChallenge as parseChallenge,
  parseVaultTunnelAuthenticationEnvelope as parseEnvelope,
  tunnelAuthenticationInfo,
} from '../electron/vault-tunnel-authentication.ts';
import { sealTunnelAuthentication } from '../src/vault-tunnel-authentication-sender.ts';
import {
  tunnelAuthenticationContext as context,
  tunnelAuthenticationEnvelope as envelope,
} from './fixtures/vault-tunnel-authentication.ts';
const suite = () =>
  new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });

test('VPN authentication context, public challenge and canonical purpose binding are exact', () => {
  const c = context(),
    b = c.binding;
  const parsed = parseContext(c)!;
  assert.deepEqual(parsed, c);
  parsed.binding.host = 'changed';
  assert.equal(c.binding.host, 'café.example');
  const fields = [
    b.workspaceId,
    b.fileId,
    b.nodeId,
    b.sessionId,
    b.requestId,
    b.protocol,
    b.host,
    String(b.port),
    String(b.epoch),
    b.tunnelConfigId,
    String(b.kind),
    b.rowVersion,
    b.configurationVersion,
    c.challengeId,
    'true',
  ];
  assert.deepEqual(
    Buffer.from(tunnelAuthenticationInfo(c)),
    Buffer.concat([
      Buffer.from('wormhole/v1/tunnel-authentication'),
      ...fields.flatMap((s) => {
        const bytes = Buffer.from(s),
          n = Buffer.alloc(4);
        n.writeUInt32BE(bytes.length);
        return [n, bytes];
      }),
    ]),
  );
  for (const value of [
    null,
    {},
    { ...c, extra: true },
    { ...c, challengeId: 'bad' },
    { ...c, publicKey: 'bad' },
    { ...c, usernameRequired: 1 },
    { ...c, binding: null },
    ...[
      { kind: 1 },
      { port: 0 },
      { epoch: 0 },
      { rowVersion: '0' },
      { useExternalClient: true },
      { extra: true },
      { host: 'bad host' },
    ].map((v) => ({ ...c, binding: { ...b, ...v } })),
  ]) {
    assert.equal(parseContext(value), undefined);
    assert.throws(() => tunnelAuthenticationInfo(value), /Invalid/);
  }
  const greeting = {
    type: 'authentication-required',
    sessionId: b.sessionId,
    challengeId: c.challengeId,
    publicKey: c.publicKey,
    usernameRequired: true,
  };
  assert.deepEqual(parseChallenge(greeting, b), c);
  for (const value of [
    null,
    {},
    { ...greeting, type: 'ready' },
    { ...greeting, sessionId: c.challengeId },
    { ...greeting, extra: true },
  ])
    assert.equal(parseChallenge(value, b), undefined);
  const sealed = envelope();
  assert.deepEqual(parseEnvelope(sealed), sealed);
  for (const value of [
    null,
    {},
    { ...sealed, extra: true },
    { ...sealed, formatVersion: 2 },
    { ...sealed, suiteId: 1 },
    { ...sealed, enc: 'bad' },
    { ...sealed, ciphertext: 1 },
    { ...sealed, ciphertext: 'bad' },
    ...[26, 8219].map((n) => ({ ...sealed, ciphertext: Buffer.alloc(n).toString('base64') })),
    { ...sealed, ciphertext: sealed.ciphertext + '\n' },
  ])
    assert.equal(parseEnvelope(value), undefined);
  for (const n of [27, 28, 29, 8218])
    assert.ok(parseEnvelope({ ...sealed, ciphertext: Buffer.alloc(n).toString('base64') }));
});

test('VPN factors are consumed synchronously, frame UTF-8 and remain bound to one route challenge', async () => {
  for (const required of [true, false])
    for (const max of [false, true]) {
      const pair = await suite().kem.generateKeyPair(),
        c = context();
      c.usernameRequired = required;
      c.publicKey = Buffer.from(await suite().kem.serializePublicKey(pair.publicKey)).toString(
        'base64',
      );
      const name = Buffer.from(required ? (max ? 'u'.repeat(4096) : 'utente-é') : ''),
        password = Buffer.from(max ? 'p'.repeat(4096) : 'password-é');
      const expected = Buffer.concat([name, password]),
        n = name.length,
        p = password.length;
      const pending = sealTunnelAuthentication(c, name, password);
      assert.ok(name.every((v) => v === 0) && password.every((v) => v === 0));
      const sealed = await pending;
      assert.deepEqual(parseEnvelope(sealed), sealed);
      const opened = new Uint8Array(
        await suite().open(
          {
            recipientKey: pair.privateKey,
            enc: Buffer.from(sealed.enc, 'base64'),
            info: tunnelAuthenticationInfo(c),
          },
          Buffer.from(sealed.ciphertext, 'base64'),
        ),
      );
      assert.deepEqual([...opened.subarray(0, 2)], [1, 1]);
      assert.equal(new DataView(opened.buffer).getUint32(2), n);
      assert.equal(new DataView(opened.buffer).getUint32(6), p);
      assert.deepEqual(Buffer.from(opened.subarray(10)), expected);
      opened.fill(0);
      expected.fill(0);
      for (const wrong of [
        { ...c, challengeId: context().challengeId },
        { ...c, usernameRequired: !required },
        { ...c, binding: { ...c.binding, host: 'redirect.example' } },
      ])
        await assert.rejects(
          suite().open(
            {
              recipientKey: pair.privateKey,
              enc: Buffer.from(sealed.enc, 'base64'),
              info: tunnelAuthenticationInfo(wrong),
            },
            Buffer.from(sealed.ciphertext, 'base64'),
          ),
        );
    }
  // Shared backing memory must be snapshotted before either input is consumed.
  const c = context(),
    pair = await suite().kem.generateKeyPair();
  c.publicKey = Buffer.from(await suite().kem.serializePublicKey(pair.publicKey)).toString(
    'base64',
  );
  const aliases = Buffer.from('userpassword'),
    sealed = await sealTunnelAuthentication(c, aliases.subarray(0, 4), aliases.subarray(4));
  const raw = new Uint8Array(
    await suite().open(
      {
        recipientKey: pair.privateKey,
        enc: Buffer.from(sealed.enc, 'base64'),
        info: tunnelAuthenticationInfo(c),
      },
      Buffer.from(sealed.ciphertext, 'base64'),
    ),
  );
  assert.equal(new TextDecoder().decode(raw.subarray(10)), 'userpassword');
  raw.fill(0);
});

test('invalid factors, cancellation and crypto errors consume inputs without returning credentials', async (t) => {
  for (const mode of [
    'context',
    'empty',
    'username',
    'fixed',
    'blank',
    'oversized-name',
    'oversized-password',
    'control',
    'utf8',
    'crypto',
    'abort',
    'late',
  ]) {
    const c = context(),
      abort = new AbortController();
    let name = Buffer.from('u'),
      password = Buffer.from('p');
    if (mode === 'empty') password = Buffer.alloc(0);
    if (mode === 'username') name = Buffer.alloc(0);
    if (mode === 'fixed') c.usernameRequired = false;
    if (mode === 'blank') name = Buffer.from('\u2003');
    if (mode === 'oversized-name') name = Buffer.alloc(4097, 97);
    if (mode === 'oversized-password') password = Buffer.alloc(4097, 97);
    if (mode === 'control') password = Buffer.from('x\ny');
    if (mode === 'utf8') password = Buffer.from([255]);
    if (mode === 'crypto') c.publicKey = Buffer.alloc(32).toString('base64');
    if (mode === 'abort') abort.abort();
    const pending = sealTunnelAuthentication(
      mode === 'context' ? {} : c,
      name,
      password,
      abort.signal,
    );
    if (mode === 'late') abort.abort();
    await assert.rejects(pending, /could not be encrypted/);
    assert.ok(name.every((v) => v === 0) && password.every((v) => v === 0), mode);
  }
  await assert.rejects(sealTunnelAuthentication(context(), null as any, new Uint8Array([1])));
  await assert.rejects(sealTunnelAuthentication(context(), new Uint8Array([1]), null as any));
  await assert.rejects(
    sealTunnelAuthentication(
      context(),
      new Uint8Array(new SharedArrayBuffer(1)),
      new Uint8Array([1]),
    ),
  );
  const original = crypto.subtle.encrypt.bind(crypto.subtle),
    c = context(),
    pair = await suite().kem.generateKeyPair(),
    abort = new AbortController();
  c.publicKey = Buffer.from(await suite().kem.serializePublicKey(pair.publicKey)).toString(
    'base64',
  );
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
  const pending = sealTunnelAuthentication(c, Buffer.from('u'), Buffer.from('p'), abort.signal);
  void pending.catch(() => {});
  await begun;
  abort.abort();
  release();
  await assert.rejects(pending, /could not be encrypted/);
});
