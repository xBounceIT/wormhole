import assert from 'node:assert/strict';
import test from 'node:test';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import {
  parseTunnelImportChoice,
  parseTunnelImportContext,
  parseTunnelImportRequest,
  parseTunnelImportDisplay,
  parseTunnelImportDiscard,
  parseTunnelImportDiscarded,
  tunnelImportFormats,
} from '../electron/vault-tunnel-import.ts';
import { consumeVaultTunnelInput } from '../electron/vault-tunnel.ts';
import { createTunnelImportRecipient } from '../src/vault-tunnel-import-recipient.ts';
import { VaultBackendHost } from '../electron/vault-host.ts';
const id = '11111111-1111-4111-8111-111111111111',
  other = '22222222-2222-4222-8222-222222222222';
const context = { workspaceId: id, editorId: id, importId: other, kind: 1 };
const key = Buffer.alloc(32, 1).toString('base64');
const choice = { importId: other, kind: 1, format: 'openvpn', publicKey: key };
const request = {
  ...context,
  ...choice,
  tunnelId: '',
  rowVersion: '0',
  path: '/picked/profile.ovpn',
};
const discard = { workspaceId: id, editorId: id, importId: '' };
const response = {
  ...context,
  bundle: {
    formatVersion: 1,
    suiteId: 2,
    enc: key,
    ciphertext: Buffer.alloc(32).toString('base64'),
  },
};
const factor = () => ({
  vaultId: id,
  slotId: other,
  kind: 'password',
  factor: new Uint8Array([1]),
});
const tick = () => new Promise(setImmediate);
test('profile import contracts allow only provider formats, sealed previews and exact context', () => {
  for (let kind = -1; kind <= 10; kind++) {
    const formats = tunnelImportFormats(kind);
    assert.equal(
      formats.length,
      kind === 9 ? 3 : kind === 3 ? 2 : [1, 4, 5, 6].includes(kind) ? 1 : 0,
    );
    for (const format of formats) assert.ok(parseTunnelImportChoice({ ...choice, kind, format }));
  }
  assert.deepEqual(parseTunnelImportChoice(choice), choice);
  assert.deepEqual(parseTunnelImportContext(context), context);
  assert.deepEqual(parseTunnelImportRequest(request), request);
  assert.ok(parseTunnelImportRequest({ ...request, tunnelId: other, rowVersion: '1' }));
  assert.deepEqual(
    parseTunnelImportDisplay(response, request),
    response,
    'main-only path must not enter projection',
  );
  assert.deepEqual(parseTunnelImportDiscard(discard), discard);
  assert.ok(parseTunnelImportDiscard({ ...discard, importId: other }));
  assert.deepEqual(parseTunnelImportDiscarded({ discarded: true }), { discarded: true });
  const cases: [any, any, any[]][] = [
    [
      parseTunnelImportChoice,
      choice,
      [{ kind: 0 }, { kind: 1.5 }, { format: 'azure' }, { importId: 'bad' }, { publicKey: 'bad' }],
    ],
    [
      parseTunnelImportContext,
      context,
      [
        { workspaceId: 'bad' },
        { editorId: 'bad' },
        { importId: 'bad' },
        { kind: 8 },
        { kind: 1.5 },
      ],
    ],
    [
      parseTunnelImportRequest,
      request,
      [
        { workspaceId: 'bad' },
        { format: 'cisco' },
        { tunnelId: other },
        { rowVersion: '1' },
        { rowVersion: '00' },
        { tunnelId: other, rowVersion: '9223372036854775807' },
        { path: '' },
        { path: null },
        { path: 'a'.repeat(8193) },
        { path: 'a\0b' },
      ],
    ],
    [
      parseTunnelImportDiscard,
      discard,
      [{ workspaceId: 'bad' }, { editorId: 'bad' }, { importId: 'bad' }],
    ],
    [
      parseTunnelImportDiscarded,
      { discarded: true },
      [{ discarded: false }, { discarded: 'true' }],
    ],
  ];
  for (const [parse, value, changes] of cases)
    for (const bad of [
      null,
      [],
      {},
      { ...value, extra: 1 },
      ...changes.map((change) => ({ ...value, ...change })),
    ])
      assert.equal(parse(bad), undefined, JSON.stringify(bad));
  for (const bad of [
    null,
    {},
    { ...response, extra: 1 },
    ...Object.keys(context).map((key) => ({ ...response, [key]: 'bad' })),
    { ...response, bundle: null },
    { ...response, bundle: { ...response.bundle, ciphertext: 'bad' } },
  ])
    assert.equal(parseTunnelImportDisplay(bad, context), undefined);
});
test('native edit import identifiers are paired, copied and do not weaken patch ownership', () => {
  const input = () => ({
    metadata: { id: '', name: 'Imported', kind: 1 },
    rowVersion: '0',
    forgetHostKey: false,
    patch: new Uint8Array([123, 125]),
    editorId: id,
    importId: other,
  });
  const value = input();
  assert.equal(consumeVaultTunnelInput(value).importId, other);
  assert.deepEqual([...value.patch], [0, 0]);
  for (const change of [
    { editorId: undefined },
    { importId: undefined },
    { editorId: '' },
    { importId: 'bad' },
    { editorId: null },
  ]) {
    const value = { ...input(), ...change };
    assert.throws(() => consumeVaultTunnelInput(value), /Invalid/);
    assert.ok(value.patch.every((b) => b === 0));
  }
});
async function seal(publicKey: string, fields: string[], domain = 'wormhole/v1/tunnel-import') {
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
  const parts = [
    Buffer.from(domain),
    ...fields.flatMap((value) => {
      const length = Buffer.alloc(4);
      length.writeUInt32BE(Buffer.byteLength(value));
      return [length, Buffer.from(value)];
    }),
  ];
  const sender = await suite.createSenderContext({
    recipientPublicKey: await suite.kem.deserializePublicKey(Buffer.from(publicKey, 'base64')),
    info: Buffer.concat(parts),
  });
  return {
    ...context,
    bundle: {
      formatVersion: 1,
      suiteId: 2,
      enc: Buffer.from(sender.enc).toString('base64'),
      ciphertext: Buffer.from(
        await sender.seal(new TextEncoder().encode('public preview')),
      ).toString('base64'),
    },
  };
}
test('one-use import recipient authenticates every domain field and rejects editor envelopes', async () => {
  await assert.rejects(createTunnelImportRecipient({ ...context, kind: 8 }), /Invalid/);
  const fields = [id, id, other, '1'];
  const recipient = await createTunnelImportRecipient(context);
  const envelope = await seal(recipient.publicKey, fields);
  assert.equal(new TextDecoder().decode(await recipient.open(envelope)), 'public preview');
  await assert.rejects(recipient.open(envelope), /closed/);
  recipient.dispose();
  for (const index of [-2, -1, 0, 1, 2, 3]) {
    const recipient = await createTunnelImportRecipient(context);
    const swapped = [...fields];
    if (index >= 0) swapped[index] = 'different';
    const value =
      index === -2
        ? {}
        : await seal(
            recipient.publicKey,
            swapped,
            index === -1 ? 'wormhole/v1/tunnel-editor' : undefined,
          );
    await assert.rejects(recipient.open(value));
    recipient.dispose();
  }
  const closed = await createTunnelImportRecipient(context);
  closed.dispose();
  await assert.rejects(closed.open(envelope), /closed/);
});
test('host binds imports to an unlocked owner and retires late stages when authority disappears', async () => {
  let finish!: () => void,
    delayed = false,
    allowed = true,
    locks = 0;
  const client: any = {
    security: async () => ({ effective: 'default' }),
    unlock: async () => ({ unlocked: true, lockedMemory: true }),
    lock: async () => {
      locks++;
    },
    stageTunnelImport: async () => {
      if (delayed) await new Promise<void>((r) => (finish = r));
      return response;
    },
    discardTunnelImport: async () => {
      if (delayed) await new Promise<void>((r) => (finish = r));
      return { discarded: true };
    },
  };
  const host = new VaultBackendHost(
    () => client,
    () => true,
  );
  await assert.rejects(host.stageTunnelImport(null), /Invalid/);
  await assert.rejects(host.discardTunnelImport(null), /Invalid/);
  for (const method of ['stageTunnelImport', 'discardTunnelImport'] as const) {
    const value = method === 'stageTunnelImport' ? request : discard;
    await assert.rejects(host[method](value), /locked/);
  }
  await host.unlock(factor());
  await assert.rejects(host.stageTunnelImport({ ...request, workspaceId: other }), /locked/);
  await assert.rejects(host.discardTunnelImport({ ...discard, workspaceId: other }), /locked/);
  await assert.rejects(
    host.stageTunnelImport(request, () => false),
    /locked/,
  );
  assert.deepEqual(await host.stageTunnelImport(request), response);
  assert.deepEqual(await host.discardTunnelImport(discard), { discarded: true });
  delayed = true;
  const lost = host.stageTunnelImport(request, () => allowed);
  await tick();
  allowed = false;
  finish();
  await assert.rejects(lost, /locked/);
  assert.equal(locks, 1);
  assert.equal(host.unlockedWorkspaceId, undefined);
  for (const method of ['stageTunnelImport', 'discardTunnelImport'] as const) {
    await host.unlock(factor());
    const pending = host[method](method === 'stageTunnelImport' ? request : discard);
    await tick();
    await host.stop();
    finish();
    await assert.rejects(pending, /locked/);
  }
});
