import assert from 'node:assert/strict';
import test from 'node:test';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import { tunnelBrowserContext as context } from './fixtures/vault-tunnel-browser.ts';
import {
  parseVaultTunnelBrowserContext as parseContext,
  parseVaultTunnelBrowserChallenge as parseChallenge,
  parseVaultTunnelBrowserEnvelope as parseEnvelope,
  tunnelBrowserInfo,
  tunnelBrowserCallbackToken,
  sealTunnelBrowserToken,
} from '../electron/vault-tunnel-browser.ts';
const suite = () =>
  new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
test('SAML public context binds exact route, browser origin, callback and certificate policy', () => {
  const c = context(),
    b = c.binding;
  assert.deepEqual(parseContext(c), c);
  const copy = parseContext(c)!;
  copy.binding.host = 'changed';
  assert.notEqual(copy.binding.host, c.binding.host);
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
    c.startURL,
    c.callbackURL,
    'true',
  ];
  assert.deepEqual(
    Buffer.from(tunnelBrowserInfo(c)),
    Buffer.concat([
      Buffer.from('wormhole/v1/tunnel-browser-authentication'),
      ...fields.flatMap((s) => {
        const raw = Buffer.from(s),
          n = Buffer.alloc(4);
        n.writeUInt32BE(raw.length);
        return [n, raw];
      }),
    ]),
  );
  for (const bad of [
    null,
    {},
    { ...c, extra: true },
    { ...c, publicKey: 'bad' },
    { ...c, binding: { ...b, kind: 1 } },
    { ...c, startURL: null },
    { ...c, ignoreCertificateErrors: 0 },
    ...[
      'http://vpn.test/saml',
      'https://u:p@vpn.test/saml',
      'https://vpn.test/other',
      'https://vpn.test/saml#x',
      '%',
      'https://vpn.test/saml?x=' + 'a'.repeat(4096),
      'https://vpn.test/saml\n',
    ].map((startURL) => ({ ...c, startURL })),
    ...[
      'http://localhost:12345/',
      'http://127.0.0.1/',
      'http://127.0.0.1:12345/?',
      'http://u:p@127.0.0.1:12345/',
      'http://127.0.0.1:12345/#x',
      'http://127.0.0.1:12345/other',
      1,
    ].map((callbackURL) => ({ ...c, callbackURL })),
  ]) {
    assert.equal(parseContext(bad), undefined);
    assert.throws(() => tunnelBrowserInfo(bad));
  }
  const greeting = {
    type: 'browser-authentication-required',
    sessionId: b.sessionId,
    challengeId: c.challengeId,
    publicKey: c.publicKey,
    startURL: c.startURL,
    callbackURL: c.callbackURL,
    ignoreCertificateErrors: true,
  };
  assert.deepEqual(parseChallenge(greeting, b), c);
  for (const bad of [
    null,
    {},
    { ...greeting, extra: true },
    { ...greeting, type: 'ready' },
    { ...greeting, sessionId: c.challengeId },
  ])
    assert.equal(parseChallenge(bad, b), undefined);
});
test('SAML callbacks require the exact main-frame loopback target and exactly one hexadecimal token', () => {
  const c = context(),
    url = c.callbackURL + '?tokenid=' + 'ab'.repeat(16);
  assert.deepEqual(tunnelBrowserCallbackToken(url, c), new TextEncoder().encode('ab'.repeat(16)));
  for (const bad of [
    null,
    {},
    '%',
    'x'.repeat(4097),
    url + '&other=x',
    url + '&tokenid=' + 'cd'.repeat(16),
    url + '#x',
    url.replace('tokenid', 'other'),
    url.replace('12345', '12346'),
    url.replace('127.0.0.1', 'localhost'),
    url.replace('http:', 'https:'),
    url.replace('/?', '/other?'),
    url.replace('ab', 'zz'),
    url.replace('http://', 'http://u:p@'),
  ])
    assert.equal(tunnelBrowserCallbackToken(bad, c), undefined);
});
test('native SAML token sealing consumes bytes and is isolated from every substituted browser context', async () => {
  const c = context(),
    pair = await suite().kem.generateKeyPair();
  c.publicKey = Buffer.from(await suite().kem.serializePublicKey(pair.publicKey)).toString(
    'base64',
  );
  const token = new TextEncoder().encode('ab'.repeat(16)),
    pending = sealTunnelBrowserToken(c, token);
  assert.ok(token.every((v) => v === 0));
  const sealed = await pending;
  assert.deepEqual(parseEnvelope(sealed), sealed);
  const raw = new Uint8Array(
    await suite().open(
      {
        recipientKey: pair.privateKey,
        enc: Buffer.from(sealed.enc, 'base64'),
        info: tunnelBrowserInfo(c),
      },
      Buffer.from(sealed.ciphertext, 'base64'),
    ),
  );
  assert.deepEqual([...raw], [1, 1, ...new TextEncoder().encode('ab'.repeat(16))]);
  raw.fill(0);
  for (const bad of [
    { ...c, ignoreCertificateErrors: false },
    { ...c, callbackURL: c.callbackURL.replace('12345', '12346') },
    { ...c, startURL: c.startURL + 'x' },
    { ...c, challengeId: context().challengeId },
    { ...c, binding: { ...c.binding, host: 'foreign' } },
  ])
    await assert.rejects(
      suite().open(
        {
          recipientKey: pair.privateKey,
          enc: Buffer.from(sealed.enc, 'base64'),
          info: tunnelBrowserInfo(bad),
        },
        Buffer.from(sealed.ciphertext, 'base64'),
      ),
    );
  for (const bad of [
    null,
    {},
    { ...sealed, extra: true },
    { ...sealed, suiteId: 3 },
    { ...sealed, enc: 'bad' },
    { ...sealed, ciphertext: Buffer.alloc(49).toString('base64') },
    { ...sealed, ciphertext: Buffer.alloc(51).toString('base64') },
  ])
    assert.equal(parseEnvelope(bad), undefined);
  for (const mode of ['context', 'size', 'shared', 'cancel', 'late', 'crypto']) {
    const value = context(),
      abort = new AbortController(),
      input =
        mode === 'shared'
          ? new Uint8Array(new SharedArrayBuffer(32))
          : new Uint8Array(mode === 'size' ? 31 : 32).fill(97);
    if (mode === 'cancel') abort.abort();
    if (mode === 'crypto') value.publicKey = Buffer.alloc(32).toString('base64');
    const result = sealTunnelBrowserToken(mode === 'context' ? {} : value, input, abort.signal);
    if (mode === 'late') abort.abort();
    await assert.rejects(result, /could not complete/);
    assert.ok(input.every((v) => v === 0));
  }
  await assert.rejects(sealTunnelBrowserToken(c, null as any));
});

test('SAML encryption cancelled after crypto starts never returns its late envelope', async (t) => {
  const c = context(),
    pair = await suite().kem.generateKeyPair(),
    abort = new AbortController();
  c.publicKey = Buffer.from(await suite().kem.serializePublicKey(pair.publicKey)).toString(
    'base64',
  );
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
  const input = Buffer.from('aB'.repeat(16)),
    pending = sealTunnelBrowserToken(c, input, abort.signal);
  void pending.catch(() => {});
  await begun;
  assert.ok(input.every((v) => v === 0));
  abort.abort();
  release();
  await assert.rejects(pending, /could not complete/);
});
