import assert from 'node:assert/strict';
import test from 'node:test';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import { tunnelCookieContext as context } from './fixtures/vault-tunnel-cookie.ts';
import {
  parseVaultTunnelCookieContext as parseContext,
  parseVaultTunnelCookieChallenge as parseChallenge,
  parseVaultTunnelCookieEnvelope as parseEnvelope,
  validTunnelCookie,
  tunnelCookieInfo,
  tunnelCookieDigest,
  tunnelCookieResponseDigest,
  sealTunnelCookie,
} from '../electron/vault-tunnel-cookie.ts';
const suite = () =>
  new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
test('SSL cookie context is exact, route-bound and purpose-separated', async () => {
  const c = context(),
    b = c.binding;
  assert.deepEqual(parseContext(c), c);
  const copy = parseContext(c)!;
  copy.binding.host = 'changed';
  assert.notEqual(copy.binding.host, b.host);
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
    '2',
    b.rowVersion,
    b.configurationVersion,
    c.challengeId,
    c.startURL,
    'true',
    'SVPNCOOKIE',
  ];
  assert.deepEqual(
    Buffer.from(tunnelCookieInfo(c)),
    Buffer.concat([
      Buffer.from('wormhole/v1/tunnel-cookie-authentication'),
      ...fields.flatMap((s) => {
        const raw = Buffer.from(s),
          size = Buffer.alloc(4);
        size.writeUInt32BE(raw.length);
        return [size, raw];
      }),
    ]),
  );
  for (const bad of [
    null,
    {},
    { ...c, extra: true },
    { ...c, binding: null },
    { ...c, binding: { ...b, kind: 9 } },
    { ...c, challengeId: 'bad' },
    { ...c, publicKey: 'bad' },
    { ...c, ignoreCertificateErrors: 1 },
    { ...c, cookieName: 'OTHER' },
    ...[
      '%',
      null,
      'http://vpn.test/remote/saml/start',
      'https://u:p@vpn.test/remote/saml/start',
      'https://vpn.test/other',
      'https://vpn.test/remote/saml/start#x',
      c.startURL + '\n',
      c.startURL + 'a'.repeat(4096),
    ].map((startURL) => ({ ...c, startURL })),
  ]) {
    assert.equal(parseContext(bad), undefined);
    assert.throws(() => tunnelCookieInfo(bad));
  }
  const greeting = {
    type: 'cookie-authentication-required',
    sessionId: b.sessionId,
    challengeId: c.challengeId,
    publicKey: c.publicKey,
    startURL: c.startURL,
    ignoreCertificateErrors: true,
    cookieName: 'SVPNCOOKIE',
  };
  assert.deepEqual(parseChallenge(greeting, b), c);
  const { cookieName: _cookie, ...greetingFields } = greeting;
  const callback = {
    ...greetingFields,
    startURL: 'https://vpn.test/remote/saml/start?redirect=1',
    completion: 'fortinet-ssl',
  };
  const parsed = parseChallenge(callback, b);
  assert.equal(parsed && 'completion' in parsed && parsed.completion, 'fortinet-ssl');
  assert.equal(parseChallenge({ ...callback, cookieName: 'SVPNCOOKIE' }, b), undefined);
  assert.equal(parseChallenge({ ...callback, startURL: c.startURL }, b), undefined);
  assert.equal(parseChallenge({ ...greeting, startURL: callback.startURL }, b), undefined);
  assert.equal(parseChallenge({ ...callback, completion: 'unknown' }, b), undefined);
  for (const value of ['', 'a b', 'a'.repeat(4097), 'é'])
    await assert.rejects(sealTunnelCookie(parsed, new TextEncoder().encode(value)));
  for (const bad of [
    null,
    {},
    { ...greeting, extra: true },
    { ...greeting, sessionId: c.challengeId },
    { ...greeting, type: 'ready' },
  ])
    assert.equal(parseChallenge(bad, b), undefined);
});
test('fresh gateway headers must name an unchanged HttpOnly RFC cookie', () => {
  const cookie = 'Opaque+/=_~Ab',
    digest = tunnelCookieDigest(cookie);
  assert.ok(digest);
  assert.equal(
    tunnelCookieResponseDigest({
      'Set-Cookie': ['other=x', 'SVPNCOOKIE=' + cookie + '; Path=/; HttpOnly; Secure'],
    }),
    digest,
  );
  assert.equal(
    tunnelCookieResponseDigest({ 'set-cookie': ['SVPNCOOKIE=' + cookie + '; httponly'] }),
    digest,
  );
  assert.equal(tunnelCookieResponseDigest({ 'set-cookie': ['SVPNCOOKIE=; HttpOnly'] }), null);
  assert.equal(tunnelCookieResponseDigest({ 'set-cookie': ['SVPNCOOKIE=x'] }), null);
  assert.equal(tunnelCookieResponseDigest({ 'set-cookie': ['OTHER=x; HttpOnly'] }), undefined);
  assert.equal(tunnelCookieResponseDigest({ 'set-cookie': ['SVPNCOOKIE?; HttpOnly'] }), undefined);
  for (const headers of [
    null,
    {},
    Object.fromEntries(Array.from({ length: 257 }, (_, i) => ['x' + i, []])),
    { 'set-cookie': 'bad' },
    { 'set-cookie': Array(65).fill('x') },
    { 'set-cookie': [null] },
    { 'set-cookie': ['x'.repeat(32769)] },
  ])
    assert.equal(tunnelCookieResponseDigest(headers), undefined);
  for (const value of [
    '',
    'space value',
    'a;b',
    'a,b',
    'a"b',
    'a\\b',
    'a\nb',
    'é',
    'a'.repeat(16385),
  ]) {
    assert.equal(validTunnelCookie(Buffer.from(value)), false);
    assert.equal(tunnelCookieDigest(value), undefined);
  }
});
test('cookie encryption consumes input and interoperable frame bounds preserve opaque bytes', async () => {
  const c = context(),
    pair = await suite().kem.generateKeyPair();
  c.publicKey = Buffer.from(await suite().kem.serializePublicKey(pair.publicKey)).toString(
    'base64',
  );
  for (const input of ['Ab+/=_~', 'a'.repeat(16384)]) {
    const cookie = Buffer.from(input),
      pending = sealTunnelCookie(c, cookie);
    assert.ok(cookie.every((v) => v === 0));
    const sealed = await pending;
    assert.deepEqual(parseEnvelope(sealed), sealed);
    const raw = new Uint8Array(
      await suite().open(
        {
          recipientKey: pair.privateKey,
          enc: Buffer.from(sealed.enc, 'base64'),
          info: tunnelCookieInfo(c),
        },
        Buffer.from(sealed.ciphertext, 'base64'),
      ),
    );
    assert.deepEqual([...raw.slice(0, 2)], [1, 1]);
    assert.equal(new DataView(raw.buffer).getUint32(2), input.length);
    assert.equal(new TextDecoder().decode(raw.subarray(6)), input);
    raw.fill(0);
    for (const bad of [
      { ...c, startURL: c.startURL + 'x' },
      { ...c, ignoreCertificateErrors: false },
      { ...c, challengeId: context().challengeId },
      { ...c, binding: { ...c.binding, host: 'foreign' } },
    ])
      await assert.rejects(
        suite().open(
          {
            recipientKey: pair.privateKey,
            enc: Buffer.from(sealed.enc, 'base64'),
            info: tunnelCookieInfo(bad),
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
      { ...sealed, ciphertext: 123 },
      { ...sealed, ciphertext: 'bad' },
      { ...sealed, ciphertext: Buffer.alloc(22).toString('base64') },
      { ...sealed, ciphertext: Buffer.alloc(16407).toString('base64') },
    ])
      assert.equal(parseEnvelope(bad), undefined);
  }
});
test('cookie encryption failure and cancellation wipe factors before any async result', async () => {
  for (const mode of ['context', 'empty', 'large', 'bad', 'shared', 'crypto', 'abort', 'late']) {
    const c = context(),
      abort = new AbortController(),
      cookie =
        mode === 'shared'
          ? new Uint8Array(new SharedArrayBuffer(8))
          : Buffer.from(
              mode === 'empty'
                ? ''
                : mode === 'large'
                  ? 'a'.repeat(16385)
                  : mode === 'bad'
                    ? 'bad value'
                    : 'cookie',
            );
    if (mode === 'crypto') c.publicKey = Buffer.alloc(32).toString('base64');
    if (mode === 'abort') abort.abort();
    const result = sealTunnelCookie(mode === 'context' ? {} : c, cookie, abort.signal);
    if (mode === 'late') abort.abort();
    await assert.rejects(result, /could not complete/);
    assert.ok(cookie.every((v) => v === 0));
  }
  await assert.rejects(sealTunnelCookie(context(), null as any));
});
