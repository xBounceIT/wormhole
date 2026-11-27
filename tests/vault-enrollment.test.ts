import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import { VaultBackendClient } from '../electron/vault-client.ts';
import { VaultBackendHost } from '../electron/vault-host.ts';
import {
  consumeVaultEnrollmentBegin,
  consumeVaultEnrollmentConfirm,
  parseVaultEnrollment,
  parseVaultEnrollmentCancel,
  enrollmentBytes,
} from '../electron/vault-enrollment-contract.ts';
import { createRecoveryRecipient } from '../src/vault-recovery-recipient.ts';

const id = '11111111-1111-4111-8111-111111111111';
const enrollment = () => ({
  enrollmentId: id,
  vaultId: '22222222-2222-4222-8222-222222222222',
  groups: [1, 11],
  bundle: {
    formatVersion: 1,
    suiteId: 2,
    enc: Buffer.alloc(32, 1).toString('base64'),
    ciphertext: Buffer.alloc(92, 2).toString('base64'),
  },
});
const begin = () => ({
  password: new TextEncoder().encode('fixture-password'),
  publicKey: new Uint8Array(32).fill(1),
});
const confirm = () => ({ enrollmentId: id, groups: new Uint8Array(10).fill(65) });

test('host enrollment reserves one owner, wipes rejected inputs and rejects late completion', async () => {
  let allowed = false,
    attempts = 0,
    stops = 0;
  let complete!: (value: any) => void;
  const client: any = {
    beginEnrollment: () => {
      attempts++;
      return new Promise((resolve) => {
        complete = resolve;
      });
    },
    lock: async () => {
      stops++;
    },
  };
  const host = new VaultBackendHost(
    () => client,
    () => allowed,
  );
  await assert.rejects(host.beginEnrollment(begin()), /unavailable/);
  allowed = true;
  const pending = host.beginEnrollment(begin());
  for (let i = 0; i < 2; i++) {
    const input = begin();
    await assert.rejects(host.beginEnrollment(input), /unavailable/);
    assert.ok(input.password.every((byte) => byte === 0));
  }
  assert.equal(attempts, 1);
  const unlocking = {
    vaultId: enrollment().vaultId,
    slotId: id,
    kind: 'password',
    factor: new Uint8Array([1]),
  };
  await assert.rejects(host.unlock(unlocking), /pending/);
  assert.equal(unlocking.factor[0], 0);
  await host.stop();
  complete(enrollment());
  await assert.rejects(pending, /unavailable/);
  assert.equal(stops, 1);
  assert.equal(host.unlockedWorkspaceId, undefined);
  const second = host.beginEnrollment(begin());
  complete(enrollment());
  await second;
  await assert.rejects(host.beginEnrollment(begin()), /unavailable/);
  const input = { ...confirm(), enrollmentId: enrollment().vaultId };
  await assert.rejects(host.confirmEnrollment(input), /unavailable/);
  assert.ok(input.groups.every((byte) => byte === 0));
  allowed = false;
  await assert.rejects(host.confirmEnrollment(confirm()), /unavailable/);
  await host.stop();
  allowed = true;
  client.beginEnrollment = async () => {
    throw Error('private error');
  };
  await assert.rejects(host.beginEnrollment(begin()), /unavailable/);
  assert.equal(stops, 3);
  assert.equal(host.hasOwner, false);
});

test('enrollment contracts bound and consume inputs without retaining caller buffers', () => {
  const input = begin(),
    owned = consumeVaultEnrollmentBegin(input);
  assert.ok(input.password.every((x) => x === 0));
  assert.ok(input.publicKey.every((x) => x === 0));
  assert.ok(owned.password.some((x) => x !== 0));
  const c = confirm(),
    copy = consumeVaultEnrollmentConfirm(c);
  assert.ok(c.groups.every((x) => x === 0));
  assert.ok(copy.groups.every((x) => x === 65));
  for (const bad of [
    null,
    [],
    {},
    { ...begin(), extra: 1 },
    { ...begin(), password: new Uint8Array(0) },
    { ...begin(), password: new Uint8Array(1025) },
    { ...begin(), publicKey: new Uint8Array(31) },
    { ...begin(), password: new Uint8Array(new SharedArrayBuffer(4)) },
  ]) {
    assert.throws(() => consumeVaultEnrollmentBegin(bad));
    if (bad?.password instanceof Uint8Array) assert.ok(bad.password.every((x) => x === 0));
  }
  for (const bad of [
    null,
    [],
    {},
    { ...confirm(), extra: 1 },
    { ...confirm(), enrollmentId: 'bad' },
    { ...confirm(), enrollmentId: '00000000-0000-0000-0000-000000000000' },
    { ...confirm(), groups: new Uint8Array(9) },
    { ...confirm(), groups: new Uint8Array(new SharedArrayBuffer(10)) },
  ])
    assert.throws(() => consumeVaultEnrollmentConfirm(bad));
  assert.deepEqual(parseVaultEnrollment(enrollment()), enrollment());
  for (const bad of [
    null,
    {},
    { ...enrollment(), extra: true },
    { ...enrollment(), vaultId: 'bad' },
    { ...enrollment(), groups: [1, 1] },
    { ...enrollment(), groups: [0, 12] },
    { ...enrollment(), groups: [1, 2.5] },
    { ...enrollment(), bundle: { ...enrollment().bundle, formatVersion: 2 } },
    { ...enrollment(), bundle: { ...enrollment().bundle, suiteId: 1 } },
    { ...enrollment(), bundle: { ...enrollment().bundle, enc: 'bad' } },
    { ...enrollment(), bundle: { ...enrollment().bundle, ciphertext: 'bad' } },
  ])
    assert.equal(parseVaultEnrollment(bad), undefined);
  for (const bad of [null, '', '%'.repeat(44), 'A'.repeat(44), 'A'.repeat(42) + 'B='])
    assert.equal(enrollmentBytes(bad, 32), undefined);
  assert.equal(parseVaultEnrollmentCancel({ cancelled: true }), true);
  assert.equal(parseVaultEnrollmentCancel({ cancelled: false }), undefined);
});

test('recovery recipient consumes its non-exportable key once and rejects other domains', async () => {
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
  for (const mode of [
    'valid',
    'format',
    'binding',
    'disposed',
    'double',
    'bad-shape',
    'dispose-during-open',
  ]) {
    const r = await createRecoveryRecipient(),
      response = enrollment();
    const infoParts = [new TextEncoder().encode('wormhole/v1/recovery-display')];
    for (const value of [
      response.vaultId,
      mode === 'binding' ? id.replace('1111', '2222') : response.enrollmentId,
    ]) {
      const b = new Uint8Array(40);
      new DataView(b.buffer).setUint32(0, 36);
      b.set(new TextEncoder().encode(value), 4);
      infoParts.push(b);
    }
    const info = Buffer.concat(infoParts);
    const publicKey = await crypto.subtle.importKey(
      'raw',
      r.publicKey,
      { name: 'X25519' },
      true,
      [],
    );
    const sender = await suite.createSenderContext({ recipientPublicKey: publicKey, info });
    const code = new TextEncoder().encode(
      mode === 'format' ? 'x'.repeat(76) : 'WHREC1-' + Array(11).fill('ABCDE').join('-') + '-ABC',
    );
    response.bundle.enc = Buffer.from(sender.enc).toString('base64');
    response.bundle.ciphertext = Buffer.from(await sender.seal(code)).toString('base64');
    if (mode === 'disposed') r.dispose();
    if (mode === 'bad-shape') response.bundle.suiteId = 0;
    const pending = r.open(response as any);
    if (mode === 'dispose-during-open') r.dispose();
    if (mode === 'valid' || mode === 'double') {
      assert.deepEqual(await pending, code);
      await assert.rejects(r.open(response as any), /closed/);
    } else await assert.rejects(pending);
    r.dispose();
    assert.ok(r.publicKey.every((x) => x === 0));
  }
});

test(
  'native enrollment interoperates with browser HPKE and activates only after confirmation',
  { timeout: 180_000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-enrollment-')),
      executable = join(directory, process.platform === 'win32' ? 'vault.exe' : 'vault');
    let current: VaultBackendClient | undefined;
    const host = new VaultBackendHost(
      () =>
        (current = new VaultBackendClient({
          executable,
          databasePath: join(directory, 'workspace.db'),
        })),
      () => true,
    );
    try {
      await promisify(execFile)('go', ['build', '-o', executable, '.'], {
        cwd: fileURLToPath(new URL('../tools/wormhole-backend/', import.meta.url)),
        windowsHide: true,
        timeout: 120_000,
      });
      assert.equal((await host.startup()).newWorkspace, true);
      const r = await createRecoveryRecipient();
      const response = await host.beginEnrollment({
        password: new TextEncoder().encode('browser-password-fixture'),
        publicKey: new Uint8Array(r.publicKey),
      });
      const code = await r.open(response);
      r.dispose();
      assert.equal(host.unlockedWorkspaceId, undefined);
      const wrong = { enrollmentId: response.enrollmentId, groups: new Uint8Array(10).fill(48) };
      await assert.rejects(host.confirmEnrollment(wrong));
      assert.ok(wrong.groups.every((x) => x === 0));
      const groups = new Uint8Array(10);
      response.groups.forEach((group, index) =>
        groups.set(code.slice(7 + (group - 1) * 6, 12 + (group - 1) * 6), index * 5),
      );
      await host.confirmEnrollment({ enrollmentId: response.enrollmentId, groups });
      assert.equal(host.unlockedWorkspaceId, response.vaultId);
      assert.ok(groups.every((x) => x === 0));
      assert.equal((await host.workspace()).tree.length, 0);
      assert.equal((await host.startup()).newWorkspace, false);
      await host.stop();
      const descriptor = await host.describe();
      assert.ok(descriptor);
      await host.unlock({
        vaultId: descriptor.vaultId,
        slotId: descriptor.slots.find((s) => s.kind === 'recovery')!.id,
        kind: 'recovery-code',
        factor: code,
      });
      assert.ok(code.every((x) => x === 0));
      await host.stop();
      const other = new VaultBackendClient({
        executable,
        databasePath: join(directory, 'other', 'workspace.db'),
      });
      current = other;
      const recipient = await createRecoveryRecipient();
      await other.beginEnrollment({
        password: new TextEncoder().encode('cancel-fixture'),
        publicKey: new Uint8Array(recipient.publicKey),
      });
      recipient.dispose();
      assert.equal(await other.cancelEnrollment(), true);
      assert.equal(await other.cancelEnrollment(), true);
      assert.equal((await other.startup()).newWorkspace, true);
      await other.lock();
    } finally {
      await host.stop();
      await current?.lock();
      await rm(directory, { recursive: true, force: true });
    }
  },
);
