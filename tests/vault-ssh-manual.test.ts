import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from '@hpke/core';
import { sshRequest, sshBundle } from './fixtures/vault-ssh.ts';
import {
  parseVaultSshManualPlanRequest,
  parseVaultSshManualPlan,
  parseVaultSshManualContext,
  parseVaultSshManualEnvelope,
  parseVaultSshManualRequest,
  parseVaultSshManualBundle,
  sshManualPlanPayload,
  sshManualPayload,
  sshManualInfo,
  maxSshManualCiphertext,
} from '../electron/vault-ssh-manual.ts';
import { sealSshTemporaryCredentials } from '../src/vault-ssh-credentials-sender.ts';
import { VaultBackendHost } from '../electron/vault-host.ts';
import { VaultBackendClient } from '../electron/vault-client.ts';
const suite = () =>
  new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });

test('private SSH manual client rejects malformed intents before spawning a vault process', async () => {
  let spawns = 0;
  const client = new VaultBackendClient(
    { executable: '/unused/backend', databasePath: '/unused/vault.db' },
    () => {
      spawns++;
      throw Error('unexpected spawn');
    },
  );
  for (const value of [null, {}, { password: 'private' }, { mode: 'account', sftpOnly: true }]) {
    await assert.rejects(client.sshManualPlan(value), /Invalid/);
    await assert.rejects(client.sshManualBundle(value), /Invalid/);
  }
  await client.stop();
  assert.equal(spawns, 0);
});
function fixture(routed = false, mode: 'account' | 'passphrase' = 'account', sftpOnly = false) {
  const q = sshRequest(),
    bundle: any = sshBundle(q);
  const route = routed
    ? {
        ...bundle.binding,
        fileId: randomUUID(),
        tunnelConfigId: randomUUID(),
        kind: 6,
        rowVersion: '9223372036854775807',
        configurationVersion: '9223372036854775806',
      }
    : null;
  const host = {
    binding: { ...bundle.binding, tunnelConfigId: route?.tunnelConfigId ?? '' },
    fileId: route?.fileId ?? randomUUID(),
    revision: 'a'.repeat(64),
    fingerprint: 'SHA256:' + Buffer.alloc(32).toString('base64').slice(0, -1),
  };
  const { publicKey: _, sftpOnly: _only, ...base } = q;
  const request = { ...base, route, mode, sftpOnly };
  const plan = { host, mode, sftpOnly, autoSudo: !sftpOnly };
  const context = { plan, route, endpoint: route ? '127.0.0.1:2345' : '', publicKey: q.publicKey };
  bundle.binding = route ?? host.binding;
  if (route) bundle.endpoint = context.endpoint;
  if (sftpOnly) bundle.sftpOnly = true;
  return {
    q,
    request,
    plan,
    context,
    bundle,
    manual: { ...bundle.bundle, ciphertext: Buffer.alloc(40).toString('base64') },
  };
}

test('SSH manual contract binds an exact snapshot, flags and route to one opaque document envelope', () => {
  for (const routed of [false, true])
    for (const mode of ['account', 'passphrase'] as const)
      for (const file of [false, true]) {
        const f = fixture(routed, mode, file);
        assert.deepEqual(parseVaultSshManualPlanRequest(f.request), f.request);
        assert.deepEqual(parseVaultSshManualPlan(f.plan, f.request), f.plan);
        assert.deepEqual(parseVaultSshManualContext(f.context), f.context);
        assert.equal(sshManualPlanPayload(f.request).epoch, '1');
        const request = { context: f.context, credentialOverride: '', manual: f.manual };
        assert.deepEqual(parseVaultSshManualRequest(request), request);
        assert.deepEqual(parseVaultSshManualBundle(f.bundle, request), f.bundle);
        const payload = sshManualPayload(request);
        assert.equal(payload.expected.mode, mode);
        assert.equal(payload.mode, mode);
        assert.equal(payload.sftpOnly, file);
        assert.equal('workspaceId' in payload, false);
        const copy = parseVaultSshManualRequest(request)!;
        copy.context.plan.host.binding.host = 'changed';
        copy.manual.enc = 'bad';
        assert.equal(f.context.plan.host.binding.host, 'host.example');
        assert.notEqual(f.manual.enc, 'bad');
        assert.equal(
          parseVaultSshManualBundle(
            { ...f.bundle, binding: { ...f.bundle.binding, host: 'changed' } },
            request,
          ),
          undefined,
        );
        assert.equal(parseVaultSshManualBundle({ ...f.bundle, bundle: null }, request), undefined);
        const selected = { ...request, credentialOverride: randomUUID() };
        assert.equal(!!parseVaultSshManualRequest(selected), mode === 'passphrase');
        const b = f.plan.host.binding,
          r = f.context.route;
        const fields = [
          b.workspaceId,
          b.nodeId,
          b.sessionId,
          b.requestId,
          b.protocol,
          b.host,
          String(b.port),
          b.tunnelConfigId,
          '1',
          r?.fileId ?? '',
          r ? '6' : '',
          r?.rowVersion ?? '',
          r?.configurationVersion ?? '',
          f.context.endpoint,
          mode,
          f.plan.host.fileId,
          f.plan.host.revision,
          f.plan.host.fingerprint,
          String(f.plan.autoSudo),
          String(file),
        ];
        const expected = Buffer.concat([
          Buffer.from('wormhole/v1/ssh-manual-credentials'),
          ...fields.flatMap((v) => {
            const data = Buffer.from(v),
              size = Buffer.alloc(4);
            size.writeUInt32BE(data.length);
            return [size, data];
          }),
        ]);
        assert.deepEqual(Buffer.from(sshManualInfo(f.context)), expected);
      }
});

test('SSH manual contracts reject private fields, weak modes, malformed snapshots and oversized ciphertext', () => {
  const f = fixture(),
    c = f.context,
    request = { context: c, credentialOverride: '', manual: f.manual };
  for (const bad of [
    null,
    {},
    { ...f.request, mode: 'bad' },
    { ...f.request, sftpOnly: undefined },
    { ...f.request, credentialOverride: randomUUID() },
    { ...f.request, password: 'secret' },
  ])
    assert.equal(parseVaultSshManualPlanRequest(bad), undefined);
  for (const bad of [
    null,
    {},
    { ...f.plan, mode: 'passphrase' },
    { ...f.plan, sftpOnly: true },
    { ...f.plan, autoSudo: 'yes' },
    { ...f.plan, host: { ...f.plan.host, fingerprint: '' } },
    { ...f.plan, extra: true },
  ])
    assert.equal(parseVaultSshManualPlan(bad, f.request), undefined);
  assert.equal(parseVaultSshManualPlan(f.plan, null), undefined);
  const files = fixture(false, 'account', true);
  assert.equal(
    parseVaultSshManualPlan({ ...files.plan, autoSudo: true }, files.request),
    undefined,
  );
  for (const bad of [
    null,
    {},
    { ...c, plan: null },
    { ...c, publicKey: 'bad' },
    { ...c, endpoint: undefined },
    { ...c, endpoint: 'remote:22' },
    { ...c, route: {} },
    { ...c, privateKey: 'secret' },
    {
      ...c,
      plan: {
        ...f.plan,
        host: { ...f.plan.host, binding: { ...f.plan.host.binding, nodeId: 'bad' } },
      },
    },
  ]) {
    assert.equal(parseVaultSshManualContext(bad), undefined);
    assert.throws(() => sshManualInfo(bad), /Invalid/);
  }
  for (const bad of [
    null,
    {},
    { ...request, context: null },
    { ...request, manual: null },
    { ...request, password: 'secret' },
    { ...request, credentialOverride: 'bad' },
  ])
    assert.equal(parseVaultSshManualRequest(bad), undefined);
  for (const bad of [
    null,
    {},
    { ...f.manual, formatVersion: 2 },
    { ...f.manual, suiteId: 1 },
    { ...f.manual, enc: 'bad' },
    { ...f.manual, ciphertext: 'bad=' },
    { ...f.manual, ciphertext: '!!!!' },
    { ...f.manual, ciphertext: 'A'.repeat(4 * Math.ceil(maxSshManualCiphertext / 3) + 4) },
  ])
    assert.equal(parseVaultSshManualEnvelope(bad), undefined);
  for (const size of [21, 22, maxSshManualCiphertext, maxSshManualCiphertext + 1])
    assert.equal(
      !!parseVaultSshManualEnvelope({
        ...f.manual,
        ciphertext: Buffer.alloc(size).toString('base64'),
      }),
      size >= 22 && size <= maxSshManualCiphertext,
    );
});

const input = (
  fields: Partial<
    Record<'username' | 'password' | 'privateKey' | 'passphrase' | 'certificate', string>
  > = {},
) =>
  Object.fromEntries(
    ['username', 'password', 'privateKey', 'passphrase', 'certificate'].map((k) => [
      k,
      new TextEncoder().encode(fields[k as keyof typeof fields] ?? ''),
    ]),
  ) as any;
test('SSH isolated sender consumes password, key, certificate and explicit empty passphrase buffers', async () => {
  for (const routed of [false, true])
    for (const kind of [
      'password',
      'key',
      'certificate',
      'passphrase',
      'empty-passphrase',
      'large-key',
    ]) {
      const f = fixture(routed, kind.includes('passphrase') ? 'passphrase' : 'account');
      const pair = (await crypto.subtle.generateKey({ name: 'X25519' }, false, [
        'deriveBits',
      ])) as CryptoKeyPair;
      f.context.publicKey = Buffer.from(
        await crypto.subtle.exportKey('raw', pair.publicKey),
      ).toString('base64');
      const values = kind.includes('passphrase')
        ? { passphrase: kind === 'passphrase' ? 'override' : '' }
        : {
            username: '例-user',
            ...(kind === 'password'
              ? { password: 'temporary-password' }
              : {
                  privateKey: kind === 'large-key' ? 'k'.repeat(1024 * 1024) : 'key',
                  passphrase: 'key-passphrase',
                  ...(kind === 'certificate' ? { certificate: 'certificate' } : {}),
                }),
          };
      const fields = input(values),
        pending = sealSshTemporaryCredentials(f.context, fields);
      for (const bytes of Object.values(fields) as Uint8Array[])
        assert.ok(
          bytes.every((v) => v === 0),
          'consumed before async',
        );
      const sealed = await pending;
      assert.ok(parseVaultSshManualEnvelope(sealed));
      const raw = new Uint8Array(
        await suite().open(
          {
            recipientKey: pair.privateKey,
            enc: Buffer.from(sealed.enc, 'base64'),
            info: sshManualInfo(f.context),
          },
          Buffer.from(sealed.ciphertext, 'base64'),
        ),
      );
      if (kind.includes('passphrase')) {
        assert.deepEqual([...raw.subarray(0, 2)], [1, 2]);
        assert.equal(new TextDecoder().decode(raw.subarray(6)), values.passphrase);
      } else {
        assert.equal(raw[0], 1);
        assert.equal(raw[1], 0);
        let offset = 2;
        const expected = [
          values.username,
          f.plan.host.fingerprint,
          (values as any).password ?? '',
          (values as any).privateKey ?? '',
          values.passphrase ?? '',
          (values as any).certificate ?? '',
        ];
        for (const value of expected) {
          const size = new DataView(raw.buffer).getUint32(offset);
          assert.equal(
            new TextDecoder().decode(raw.subarray(offset + 4, offset + 4 + size)),
            value,
          );
          offset += 4 + size;
        }
        assert.equal(offset, raw.length);
      }
      raw.fill(0);
    }
});

test('SSH sender wipes all caller buffers on validation, encryption and cancellation failures', async () => {
  const f = fixture();
  for (const fields of [
    input(),
    input({ username: 'u', password: 'p', privateKey: 'k' }),
    input({ username: 'bad\n', password: 'p' }),
    input({ username: 'u', password: 'p', certificate: 'cert' }),
    input({ username: 'u', password: 'p'.repeat(16385) }),
    input({ username: 'u', privateKey: 'k'.repeat(1024 * 1024 + 1) }),
    { ...input({ username: 'u', password: 'p' }), username: new Uint8Array([255]) },
  ]) {
    await assert.rejects(sealSshTemporaryCredentials(f.context, fields), /could not/);
    for (const bytes of Object.values(fields) as Uint8Array[])
      assert.ok(bytes.every((v) => v === 0));
  }
  await assert.rejects(sealSshTemporaryCredentials(f.context, undefined as any), /could not/);
  for (const value of [null, { ...f.context, publicKey: Buffer.alloc(32).toString('base64') }]) {
    const fields = input({ username: 'u', password: 'p' });
    await assert.rejects(sealSshTemporaryCredentials(value, fields));
    assert.ok(fields.password.every((v: number) => v === 0));
  }
  const pass = fixture(false, 'passphrase');
  await assert.rejects(
    sealSshTemporaryCredentials(pass.context, input({ username: 'saved', passphrase: 'p' })),
  );
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    sealSshTemporaryCredentials(
      f.context,
      input({ username: 'u', password: 'p' }),
      controller.signal,
    ),
    /cancelled/,
  );
  const late = new AbortController(),
    pending = sealSshTemporaryCredentials(
      f.context,
      input({ username: 'u', password: 'p' }),
      late.signal,
    );
  late.abort();
  await assert.rejects(pending, /cancelled/);
});

test('SSH manual host gates snapshots and sealed bundles across lock, owner, workspace and client changes', async () => {
  const tick = () => new Promise(setImmediate);
  for (const operation of ['plan', 'bundle']) {
    const f = fixture();
    let allowed = true,
      delayed = false,
      malformed = false,
      release!: () => void;
    const client: any = {
      describe: async () => ({
        vaultId: f.q.workspaceId,
        slots: [{ id: f.q.nodeId, kind: 'recovery' }],
      }),
      unlock: async () => ({ unlocked: true, lockedMemory: true }),
      security: async () => ({ effective: 'default' }),
      lock: async () => {},
      stop: async () => {},
      sshManualPlan: async () => {
        if (delayed)
          await new Promise<void>((r) => {
            release = r;
          });
        return malformed ? {} : f.plan;
      },
      sshManualBundle: async () => {
        if (delayed)
          await new Promise<void>((r) => {
            release = r;
          });
        return malformed ? {} : f.bundle;
      },
    };
    const host = new VaultBackendHost(
      () => client,
      () => true,
    );
    const input =
      operation === 'plan'
        ? f.request
        : { context: f.context, credentialOverride: '', manual: f.manual };
    const invoke = (value: unknown = input) =>
      operation === 'plan'
        ? host.sshManualPlan(value, () => allowed)
        : host.sshManualBundle(value, () => allowed);
    const unlock = async () => {
      await host.describe();
      await host.unlock({
        vaultId: f.q.workspaceId,
        slotId: f.q.nodeId,
        kind: 'recovery',
        factor: new Uint8Array(32),
      });
    };
    await assert.rejects(invoke(null), /Invalid/);
    await assert.rejects(invoke(), /locked/);
    await unlock();
    assert.deepEqual(await invoke(), operation === 'plan' ? f.plan : f.bundle);
    allowed = false;
    await assert.rejects(invoke(), /locked/);
    allowed = true;
    malformed = true;
    await assert.rejects(invoke(), /Invalid/);
    malformed = false;
    for (const invalidation of ['owner', 'client']) {
      delayed = true;
      const pending = invoke();
      await tick();
      if (invalidation === 'owner') allowed = false;
      else await host.stop();
      release();
      await assert.rejects(pending, /locked/);
      allowed = true;
      delayed = false;
      if (invalidation === 'client') await unlock();
    }
    await host.stop();
  }
});
