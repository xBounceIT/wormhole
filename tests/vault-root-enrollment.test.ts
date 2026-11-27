import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import {
  consumeVaultRootEnrollmentBegin,
  parseVaultRootEnrollmentContext,
} from '../electron/vault-root-enrollment.ts';
import { VaultBackendClient } from '../electron/vault-client.ts';
import { VaultBackendHost } from '../electron/vault-host.ts';
import { createRecoveryRecipient } from '../src/vault-recovery-recipient.ts';
import { Session } from 'node:inspector/promises';
import { coverageThreshold } from '../scripts/test-coverage.ts';

const profiler = new Session();
const externalCoverage =
  process.execArgv.includes('--experimental-test-coverage') || !!process.env.NODE_V8_COVERAGE;
if (!externalCoverage) {
  profiler.connect();
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
}

const id = '11111111-1111-4111-8111-111111111111',
  slot = '22222222-2222-4222-8222-222222222222';
function request() {
  return {
    password: new Uint8Array([7, 8, 9]),
    publicKey: new Uint8Array(32).fill(1),
    authentication: {
      vaultId: id,
      slotId: slot,
      kind: 'password' as const,
      factor: new Uint8Array([3, 4, 5]),
    },
  };
}
function erase(input: ReturnType<typeof request>) {
  input.password.fill(0);
  input.publicKey.fill(0);
  input.authentication.factor.fill(0);
}

async function hostFixture(mode = '') {
  let stopped = 0,
    begun = 0,
    confirmed = 0,
    cancelled = 0,
    finish!: (value: any) => void;
  const enrollment = { enrollmentId: slot, vaultId: id, groups: [1, 2], bundle: {} };
  const context = {
    slots: {
      formatVersion: 1,
      vaultId: id,
      encrypted: false,
      slots: [{ id: slot, kind: 'password', preset: 'kdf-v1' }],
    },
  };
  const live = {
    formatVersion: 1,
    stage: 'foundation',
    protectionAvailable: false,
    sharedWorkspaceAvailable: false,
    unlocked: true,
    lockedMemory: true,
  };
  const client: any = {
    status: async () => {
      if (mode === 'status-error') throw Error('native failure');
      return mode === 'status-locked' ? { ...live, unlocked: false } : live;
    },
    unlock: async () => ({ unlocked: true, lockedMemory: true }),
    security: async () => ({
      sequence: '1',
      workspace: 'default',
      user: 'default',
      os: 'default',
      effective: 'default',
      source: 'workspace',
    }),
    lock: async () => {
      stopped++;
    },
    rootRotationSetupContext: async () =>
      mode === 'wrong-context' ? { slots: { ...context.slots, vaultId: slot } } : context,
    beginRootRotationSetup: async () => {
      begun++;
      if (['begin-error', 'status-error', 'status-locked'].includes(mode))
        throw Error('factor rejected');
      if (mode === 'begin-late') return new Promise((r) => (finish = r));
      return mode === 'wrong-begin' ? { ...enrollment, vaultId: slot } : enrollment;
    },
    confirmRootRotationSetup: async () => {
      confirmed++;
      if (mode === 'confirm-error') throw Error('groups rejected');
      if (mode === 'confirm-late') return new Promise((r) => (finish = r));
      return {
        prepared: true,
        restartRequired: true,
        vaultId: mode === 'wrong-confirm' ? slot : id,
      };
    },
    cancelRootRotationSetup: async () => {
      cancelled++;
      if (mode === 'cancel-error') throw Error('uncertain cleanup');
      if (mode === 'cancel-late') await new Promise((r) => (finish = r));
      return true;
    },
  };
  const host = new VaultBackendHost(
    () => client,
    () => true,
  );
  await host.unlock({ vaultId: id, slotId: slot, kind: 'password', factor: new Uint8Array([1]) });
  return {
    host,
    client,
    enrollment,
    context,
    resolve: (value: any) => finish(value),
    get counts() {
      return { stopped, begun, confirmed, cancelled };
    },
  };
}

test('root host rejects stale owners and retains only a positively confirmed source after rejection', async () => {
  for (const mode of [
    '',
    'wrong-context',
    'wrong-begin',
    'begin-error',
    'status-error',
    'status-locked',
  ]) {
    const f = await hostFixture(mode);
    try {
      if (mode === 'wrong-context') {
        await assert.rejects(f.host.rootRotationSetupContext());
        continue;
      }
      assert.deepEqual(await f.host.rootRotationSetupContext(), f.context);
      const input = request();
      if (!mode) {
        await f.host.beginRootRotationSetup(input);
        await assert.rejects(f.host.beginRootRotationSetup(request()));
        await assert.rejects(f.host.rootRotationSetupContext());
        assert.equal(await f.host.cancelRootRotationSetup(), true);
        assert.equal(await f.host.cancelRootRotationSetup(), true);
        assert.equal(f.host.unlockedWorkspaceId, id);
      } else {
        await assert.rejects(f.host.beginRootRotationSetup(input));
        assert.equal(f.host.unlockedWorkspaceId, mode === 'begin-error' ? id : undefined);
      }
      assert.ok(input.authentication.factor.every((x) => x === 0));
    } finally {
      await f.host.stop();
    }
  }
  const f = await hostFixture();
  await f.host.stop();
  await assert.rejects(f.host.rootRotationSetupContext());
  await assert.rejects(f.host.beginRootRotationSetup(request()));
  await assert.rejects(
    f.host.confirmRootRotationSetup({ enrollmentId: slot, groups: new Uint8Array(10).fill(65) }),
  );
});

test('root host serializes confirmation and cancellation and cannot publish a replaced owner', async () => {
  const proof = () => ({ enrollmentId: slot, groups: new Uint8Array(10).fill(65) });
  for (const mode of [
    '',
    'wrong-confirm',
    'confirm-error',
    'confirm-late',
    'begin-late',
    'cancel-error',
    'cancel-late',
  ]) {
    const f = await hostFixture(mode);
    try {
      if (mode === 'begin-late') {
        const pending = assert.rejects(f.host.beginRootRotationSetup(request()));
        await f.host.stop();
        f.resolve(f.enrollment);
        await pending;
        continue;
      }
      await f.host.beginRootRotationSetup(request());
      if (mode.startsWith('cancel')) {
        const request = f.host.cancelRootRotationSetup();
        if (mode === 'cancel-error') await assert.rejects(request);
        else {
          await assert.rejects(f.host.cancelRootRotationSetup());
          await assert.rejects(f.host.confirmRootRotationSetup(proof()));
          await f.host.stop();
          f.resolve(true);
          await assert.rejects(request);
        }
        assert.equal(f.host.unlockedWorkspaceId, undefined);
        continue;
      }
      const input = proof(),
        pending = f.host.confirmRootRotationSetup(input);
      if (mode === 'confirm-late') {
        await assert.rejects(f.host.confirmRootRotationSetup(proof()));
        await assert.rejects(f.host.cancelRootRotationSetup());
        assert.equal(f.counts.confirmed, 1);
        await f.host.stop();
        f.resolve({ prepared: true, restartRequired: true, vaultId: id });
        await assert.rejects(pending);
      } else if (mode) await assert.rejects(pending);
      else await pending;
      assert.ok(input.groups.every((x) => x === 0));
      assert.equal(f.host.unlockedWorkspaceId, mode === 'confirm-error' ? id : undefined);
    } finally {
      await f.host.stop();
    }
  }
});

test('root enrollment consumes bounded factors, including aliased buffers, before asynchronous use', () => {
  const shared = new Uint8Array(64).fill(6);
  const value = {
    password: shared.subarray(0, 8),
    publicKey: shared.subarray(8, 40),
    authentication: { vaultId: id, slotId: slot, kind: 'password', factor: shared.subarray(0, 8) },
  };
  const owned = consumeVaultRootEnrollmentBegin(value);
  assert.ok(shared.subarray(0, 40).every((x) => x === 0));
  assert.deepEqual(owned.password, new Uint8Array(8).fill(6));
  assert.deepEqual([...owned.authentication.factor], [...new Uint8Array(8).fill(6)]);
  erase(owned);
  for (const change of [
    (v: any) => ({ ...v, sourcePath: 'private' }),
    (v: any) => ({ ...v, authentication: null }),
    (v: any) => ({ ...v, authentication: { ...v.authentication, root: new Uint8Array(32) } }),
    (v: any) => ({ ...v, authentication: { ...v.authentication, factor: new Uint8Array(1025) } }),
    (v: any) => ({
      ...v,
      authentication: { ...v.authentication, factor: new Uint8Array(new SharedArrayBuffer(32)) },
    }),
    (v: any) => ({ ...v, password: new Uint8Array(0) }),
    (v: any) => ({ ...v, publicKey: new Uint8Array(31) }),
    (v: any) => ({ ...v, authentication: { ...v.authentication, kind: 'other' } }),
  ]) {
    const v = change(request());
    assert.throws(() => consumeVaultRootEnrollmentBegin(v));
    assert.ok(v.password.every((x: number) => x === 0));
    assert.ok(v.publicKey.every((x: number) => x === 0));
    if (v.authentication?.factor instanceof Uint8Array)
      assert.ok(v.authentication.factor.every((x: number) => x === 0));
  }
});

test('root enrollment context exposes only current local slot hints', () => {
  const context = {
    slots: {
      formatVersion: 1,
      vaultId: id,
      encrypted: false,
      slots: [{ id: slot, kind: 'password', preset: 'kdf-v1' }],
    },
  };
  assert.deepEqual(parseVaultRootEnrollmentContext(context), context);
  const encrypted = {
    slots: {
      ...context.slots,
      encrypted: true,
      slots: [...context.slots.slots, { id, kind: 'recovery' }],
    },
  };
  assert.deepEqual(parseVaultRootEnrollmentContext(encrypted), encrypted);
  const conversion = { ...context, encryptDatabase: true };
  assert.deepEqual(parseVaultRootEnrollmentContext(conversion), conversion);
  for (const bad of [
    null,
    {},
    { slots: null },
    { ...context, root: new Uint8Array(32) },
    { ...context, encryptDatabase: false },
    { ...encrypted, encryptDatabase: true },
  ])
    assert.equal(parseVaultRootEnrollmentContext(bad), undefined);
});

test(
  'real native root enrollment confirms a replacement recovery key and resumes after owner exit',
  { timeout: 180_000 },
  async () => {
    const root = dirname(dirname(fileURLToPath(import.meta.url))),
      directory = await mkdtemp(join(tmpdir(), 'wormhole-root-enrollment-'));
    const executable = join(directory, process.platform === 'win32' ? 'backend.exe' : 'backend'),
      source = join(directory, 'original'),
      databasePath = join(source, 'workspace.db');
    const make = (session = '') =>
      new VaultBackendHost(
        () =>
          new VaultBackendClient({
            executable,
            databasePath,
            userDataPath: source,
            migrationSessionData: session,
          }),
        () => true,
      );
    const original = make();
    let resumed: VaultBackendHost | undefined;
    const oldPassword = 'root enrollment current public fixture',
      newPassword = 'root enrollment replacement public fixture';
    const firstRecipient = await createRecoveryRecipient(),
      replacementRecipient = await createRecoveryRecipient();
    let firstCode: Uint8Array | undefined, replacementCode: Uint8Array | undefined;
    const groups = (response: { groups: [number, number] }, code: Uint8Array) => {
      const data = new Uint8Array(10);
      response.groups.forEach((number, index) =>
        data.set(code.subarray(7 + (number - 1) * 6, 12 + (number - 1) * 6), index * 5),
      );
      return data;
    };
    try {
      await mkdir(source);
      await promisify(execFile)('go', ['build', '-o', executable, '.'], {
        cwd: join(root, 'tools', 'wormhole-backend'),
        windowsHide: true,
        timeout: 120_000,
      });
      const created = await original.beginEnrollment({
        password: new TextEncoder().encode(oldPassword),
        publicKey: new Uint8Array(firstRecipient.publicKey),
      });
      firstCode = await firstRecipient.open(created);
      await original.confirmEnrollment({
        enrollmentId: created.enrollmentId,
        groups: groups(created, firstCode),
      });
      const before = await readFile(databasePath);
      const context = await original.rootRotationSetupContext();
      const current = context.slots.slots.find((s) => s.kind === 'password')!;
      await original.beginRootRotationSetup({
        password: new TextEncoder().encode('cancelled replacement fixture'),
        publicKey: new Uint8Array(replacementRecipient.publicKey),
        authentication: {
          vaultId: created.vaultId,
          slotId: current.id,
          kind: 'password',
          factor: new TextEncoder().encode(oldPassword),
        },
      });
      assert.equal(await original.cancelRootRotationSetup(), true);
      assert.equal(original.unlockedWorkspaceId, created.vaultId);
      assert.deepEqual(await readFile(databasePath), before);
      const enrollment = await original.beginRootRotationSetup({
        password: new TextEncoder().encode(newPassword),
        publicKey: new Uint8Array(replacementRecipient.publicKey),
        authentication: {
          vaultId: created.vaultId,
          slotId: current.id,
          kind: 'password',
          factor: new TextEncoder().encode(oldPassword),
        },
      });
      replacementCode = await replacementRecipient.open(enrollment);
      assert.deepEqual(await readFile(databasePath), before);
      await assert.rejects(
        original.confirmEnrollment({
          enrollmentId: enrollment.enrollmentId,
          groups: groups(enrollment, replacementCode),
        }),
      );
      await assert.rejects(
        original.confirmRootRotationSetup({
          enrollmentId: enrollment.enrollmentId,
          groups: new Uint8Array(10).fill(33),
        }),
      );
      assert.equal(original.unlockedWorkspaceId, created.vaultId);
      const prepared = await original.confirmRootRotationSetup({
        enrollmentId: enrollment.enrollmentId,
        groups: groups(enrollment, replacementCode),
      });
      assert.deepEqual(prepared, {
        prepared: true,
        restartRequired: true,
        vaultId: created.vaultId,
      });
      assert.equal(original.unlockedWorkspaceId, undefined);
      await original.stop();
      const session = await mkdtemp(join(directory, '.wormhole-vault-migration-'));
      resumed = make(session);
      const startup = await resumed.startup();
      assert.equal(startup.rotation?.pending, true);
      const passwordSlot = startup.slots!.slots.find((s) => s.kind === 'password')!;
      await resumed.resumeRootRotation({
        vaultId: created.vaultId,
        slotId: passwordSlot.id,
        kind: 'password',
        factor: new TextEncoder().encode(newPassword),
      });
      assert.equal(resumed.unlockedWorkspaceId, created.vaultId);
      const final = JSON.parse(await readFile(databasePath + '.slots', 'utf8'));
      assert.equal(final.rootKeyVersion, 2);
      assert.ok(!JSON.stringify(final).includes(newPassword));
    } finally {
      firstCode?.fill(0);
      replacementCode?.fill(0);
      firstRecipient.dispose();
      replacementRecipient.dispose();
      await original.stop();
      await resumed?.stop();
      assert.ok(directory.startsWith(join(tmpdir(), 'wormhole-root-enrollment-')));
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test('root transport consumes malformed authentication before starting a process', async () => {
  const client = new VaultBackendClient({ executable: 'never-start', databasePath: 'never-open' });
  await assert.rejects(client.beginRootRotationSetup(null));
  await assert.rejects(client.confirmRootRotationSetup(null));
  await client.lock();
});

test('root enrollment host and transport meet the project coverage threshold', async (t) => {
  if (externalCoverage) return;
  try {
    const coverage = await profiler.post('Profiler.takePreciseCoverage');
    for (const file of [
      'vault-root-enrollment.ts',
      'vault-root-enrollment-contract.ts',
      'vault-host.ts',
      'vault-client.ts',
    ]) {
      const scripts = coverage.result.filter((s) => s.url.endsWith('/electron/' + file));
      const functions = scripts
        .flatMap((s) => s.functions)
        .filter(
          (f) =>
            !['vault-host.ts', 'vault-client.ts'].includes(file) ||
            [
              'rootRotationSetupContext',
              'beginRootRotationSetup',
              'confirmRootRotationSetup',
              'cancelRootRotationSetup',
              'retainRotationSourceAfterRejection',
            ].includes(f.functionName),
        );
      const ranges = functions.flatMap((f) => f.ranges);
      assert.ok(ranges.length, file);
      const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
      t.diagnostic(file + ': ' + percent.toFixed(2) + '% V8 blocks');
      assert.ok(percent >= coverageThreshold, file);
    }
  } finally {
    profiler.disconnect();
  }
});
