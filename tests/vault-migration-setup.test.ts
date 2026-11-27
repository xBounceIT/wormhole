import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { Session } from 'node:inspector/promises';
import { coverageThreshold } from '../scripts/test-coverage.ts';
import { VaultBackendHost } from '../electron/vault-host.ts';
import { VaultBackendClient } from '../electron/vault-client.ts';
import {
  consumeVaultMigrationBegin,
  parseVaultMigrationPrepared,
  parseVaultMigrationContext,
} from '../electron/vault-migration-setup.ts';
import { createRecoveryRecipient } from '../src/vault-recovery-recipient.ts';

const id = '11111111-1111-4111-8111-111111111111';
const pending = () => ({
  enrollmentId: id,
  vaultId: '22222222-2222-4222-8222-222222222222',
  groups: [1, 2],
  bundle: {},
});
const begin = () => ({
  password: new TextEncoder().encode('new password'),
  publicKey: new Uint8Array(32).fill(7),
  legacyMethod: 'none',
  legacyFactor: new Uint8Array(),
});
const confirm = () => ({ enrollmentId: id, groups: new Uint8Array(10).fill(65) });
const prepared = () => ({ prepared: true, restartRequired: true, vaultId: pending().vaultId });

const profiler = new Session();
const externalCoverage =
  process.execArgv.includes('--experimental-test-coverage') || !!process.env.NODE_V8_COVERAGE;
if (!externalCoverage) {
  profiler.connect();
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
}

test('migration preparation consumes bounded factors and rejects renderer-selected authority', () => {
  const shared = new TextEncoder().encode('shared old and new password');
  const alias = consumeVaultMigrationBegin({
    ...begin(),
    password: shared,
    legacyMethod: 'password',
    legacyFactor: shared,
  });
  assert.deepEqual(alias.password, new TextEncoder().encode('shared old and new password'));
  assert.deepEqual(alias.legacyFactor, alias.password);
  assert.ok(shared.every((x) => x === 0));
  for (const method of ['none', 'pin', 'password']) {
    const input = {
      ...begin(),
      legacyMethod: method,
      legacyFactor: method === 'none' ? new Uint8Array() : new Uint8Array([49]),
    };
    const owned = consumeVaultMigrationBegin(input);
    assert.ok(input.password.every((x) => x === 0));
    assert.ok(input.publicKey.every((x) => x === 0));
    assert.ok(input.legacyFactor.every((x) => x === 0));
    assert.ok(owned.password.some((x) => x !== 0));
    assert.equal(owned.legacyMethod, method);
    assert.equal(owned.legacyFactor.length, method === 'none' ? 0 : 1);
  }
  for (const input of [
    null,
    [],
    {},
    { ...begin(), source: '/untrusted' },
    { ...begin(), legacyMethod: 'hello' },
    { ...begin(), legacyFactor: 'secret' },
    { ...begin(), legacyFactor: new Uint8Array(1025) },
    { ...begin(), legacyFactor: new Uint8Array([1]) },
    { ...begin(), legacyMethod: 'pin' },
    { ...begin(), publicKey: new Uint8Array(31) },
    { ...begin(), password: new Uint8Array() },
    { ...begin(), legacyMethod: 'pin', legacyFactor: new Uint8Array(new SharedArrayBuffer(1)) },
  ]) {
    assert.throws(() => consumeVaultMigrationBegin(input));
    if (input && !Array.isArray(input))
      for (const field of ['password', 'publicKey', 'legacyFactor']) {
        const bytes = (input as any)[field];
        if (bytes instanceof Uint8Array) assert.ok(bytes.every((x) => x === 0));
      }
  }
  const result = prepared();
  assert.deepEqual(parseVaultMigrationPrepared(result), result);
  assert.notEqual(parseVaultMigrationPrepared(result), result);
  for (const input of [
    null,
    {},
    { ...result, prepared: false },
    { ...result, restartRequired: false },
    { ...result, vaultId: 'bad' },
    { ...result, unlocked: true },
  ])
    assert.equal(parseVaultMigrationPrepared(input), undefined);
});

test('host preparation preserves confirmation retries and never activates an ordinary owner', async () => {
  let selected = 0,
    activated = 0,
    stops = 0,
    wrong = true;
  const client: any = {
    beginMigrationSetup: async () => pending(),
    confirmMigrationSetup: async () => {
      if (wrong) throw Error('rejected recovery group');
      return prepared();
    },
    lock: async () => {
      stops++;
    },
  };
  const host = new VaultBackendHost(
    () => client,
    () => true,
    () => {
      activated++;
    },
    () => {
      selected++;
    },
  );
  const input = begin();
  await host.beginMigrationSetup(input);
  assert.ok(input.password.every((x) => x === 0));
  await assert.rejects(
    host.beginEnrollment({ password: new Uint8Array([1]), publicKey: new Uint8Array(32) }),
    /unavailable/,
  );
  await assert.rejects(host.confirmEnrollment(confirm()), /unavailable/);
  await assert.rejects(
    host.confirmMigrationSetup({ ...confirm(), enrollmentId: pending().vaultId }),
    /unavailable/,
  );
  await assert.rejects(host.confirmMigrationSetup(confirm()), /unavailable/);
  assert.equal(stops, 0);
  wrong = false;
  const groups = confirm();
  assert.deepEqual(await host.confirmMigrationSetup(groups), prepared());
  assert.ok(groups.groups.every((x) => x === 0));
  assert.equal(host.isVaultWorkspace, true);
  assert.equal(host.unlockedWorkspaceId, undefined);
  assert.equal(activated, 0);
  assert.equal(selected, 1);
  await assert.rejects(host.confirmMigrationSetup(confirm()), /unavailable/);
  await host.stop();
  assert.equal(stops, 1);
});

test('host rejects confirmation for the other mode and retires mismatched or late committed responses', async () => {
  for (const mode of ['create', 'wrong workspace', 'late']) {
    let stops = 0;
    let finish!: (value: any) => void;
    const client: any = {
      beginEnrollment: async () => pending(),
      beginMigrationSetup: async () => pending(),
      confirmMigrationSetup: () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
      lock: async () => {
        stops++;
      },
    };
    const host = new VaultBackendHost(
      () => client,
      () => true,
    );
    if (mode === 'create') {
      await host.beginEnrollment({ password: new Uint8Array([1]), publicKey: new Uint8Array(32) });
      await assert.rejects(host.confirmMigrationSetup(confirm()), /unavailable/);
      assert.equal(stops, 0);
    } else {
      await host.beginMigrationSetup(begin());
      const confirming = host.confirmMigrationSetup(confirm());
      const rejected = assert.rejects(confirming, /unavailable/);
      if (mode === 'late') await host.stop();
      finish({ ...prepared(), ...(mode === 'wrong workspace' ? { vaultId: id } : {}) });
      await rejected;
      assert.equal(host.unlockedWorkspaceId, undefined);
      assert.equal(stops, 1);
    }
    await host.stop();
  }
});

test(
  'native client preparation keeps legacy files intact and stores browser-confirmed recovery authority',
  { timeout: 180_000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-migration-setup-'));
    const executable = join(directory, process.platform === 'win32' ? 'vault.exe' : 'vault');
    const databasePath = join(directory, 'workspace.db');
    const run = promisify(execFile);
    const client = new VaultBackendClient({ executable, databasePath, userDataPath: directory });
    const host = new VaultBackendHost(
      () => client,
      () => true,
    );
    try {
      await run('go', ['build', '-o', executable, '.'], {
        cwd: fileURLToPath(new URL('../tools/wormhole-backend/', import.meta.url)),
        windowsHide: true,
        timeout: 120_000,
      });
      await run(executable, ['--operation', 'workspace', '--database', databasePath], {
        windowsHide: true,
        timeout: 30_000,
      });
      const before = await readFile(databasePath);
      assert.equal((await host.startup()).newWorkspace, false);
      assert.deepEqual(await host.migrationSetupContext(), { methods: ['none'] });
      const recipient = await createRecoveryRecipient();
      const response = await host.beginMigrationSetup({
        ...begin(),
        publicKey: new Uint8Array(recipient.publicKey),
      });
      const code = await recipient.open(response);
      recipient.dispose();
      await assert.rejects(
        client.confirmMigrationSetup({ ...confirm(), enrollmentId: response.enrollmentId }),
      );
      const groups = new Uint8Array(10);
      response.groups.forEach((n, i) =>
        groups.set(code.subarray(7 + (n - 1) * 6, 12 + (n - 1) * 6), i * 5),
      );
      const result = await host.confirmMigrationSetup({
        enrollmentId: response.enrollmentId,
        groups,
      });
      assert.equal(result.vaultId, response.vaultId);
      assert.equal(host.unlockedWorkspaceId, undefined);
      assert.ok(groups.every((x) => x === 0));
      assert.deepEqual(await readFile(databasePath), before);
      const name = (await readdir(directory)).find((n) => n.endsWith('.setup'))!;
      const capsule = await readFile(join(directory, name));
      assert.equal(capsule.includes(code), false);
      assert.equal(capsule.includes(Buffer.from('new password')), false);
      const startup = await host.startup();
      assert.equal(startup.migration?.pending, true);
      assert.equal(startup.slots?.vaultId, response.vaultId);
      code.fill(0);
      await assert.rejects(client.beginMigrationSetup({ ...begin(), legacyMethod: 'hello' }));
      await assert.rejects(client.confirmMigrationSetup({}));
    } finally {
      await host.stop();
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test('pending preparation rejects overlapping starts and wipes factors after failure or shutdown', async () => {
  for (const mode of ['late', 'native failure', 'disallowed']) {
    let finish!: (value: any) => void,
      stops = 0,
      borrowed: any;
    const client: any = {
      beginMigrationSetup: (input: any) => {
        borrowed = input;
        if (mode === 'native failure') return Promise.reject(Error('private native error'));
        return new Promise((resolve) => {
          finish = resolve;
        });
      },
      lock: async () => {
        stops++;
      },
    };
    const host = new VaultBackendHost(
      () => client,
      () => mode !== 'disallowed',
    );
    const input = {
      ...begin(),
      legacyMethod: 'password',
      legacyFactor: new TextEncoder().encode('legacy factor'),
    };
    const starting = assert.rejects(host.beginMigrationSetup(input), /unavailable/);
    if (mode === 'late') {
      const overlap = begin();
      await assert.rejects(host.beginMigrationSetup(overlap), /unavailable/);
      assert.ok(overlap.password.every((x) => x === 0));
      assert.equal(stops, 0);
      await host.stop();
      finish(pending());
    }
    await starting;
    assert.ok(input.legacyFactor.every((x) => x === 0));
    if (borrowed)
      for (const bytes of [borrowed.password, borrowed.publicKey, borrowed.legacyFactor])
        assert.ok(bytes.every((x: number) => x === 0));
    assert.equal(host.unlockedWorkspaceId, undefined);
    assert.equal(stops, mode === 'disallowed' ? 0 : 1);
    await host.stop();
  }
});

test('migration context accepts only canonical native method hints', () => {
  for (const methods of [['none'], ['pin'], ['password'], ['password', 'pin']]) {
    const input = { methods };
    const result = parseVaultMigrationContext(input);
    assert.deepEqual(result, input);
    assert.notEqual(result!.methods, methods);
  }
  for (const input of [
    null,
    {},
    [],
    { methods: [] },
    { methods: ['password,pin'] },
    { methods: ['pin', 'password'] },
    { methods: ['none', 'pin'] },
    { methods: ['pin', 'pin'] },
    { methods: ['password', 'pin', 'none'] },
    { methods: [1] },
    { methods: ['hello'] },
    { methods: ['pin'], path: 'private' },
  ])
    assert.equal(parseVaultMigrationContext(input), undefined);
});
test('host context cannot select a workspace or survive replacement, pending setup or shutdown', async () => {
  for (const mode of ['normal', 'late', 'disallowed', 'pending', 'selected']) {
    let resolve!: (v: any) => void,
      selected = 0;
    const client: any = {
      migrationSetupContext: () => new Promise((r) => (resolve = r)),
      beginMigrationSetup: async () => pending(),
      confirmMigrationSetup: async () => prepared(),
      lock: async () => {},
    };
    const host = new VaultBackendHost(
      () => client,
      () => mode !== 'disallowed',
      undefined,
      () => selected++,
    );
    if (mode === 'pending' || mode === 'selected') {
      await host.beginMigrationSetup(begin());
      if (mode === 'selected') await host.confirmMigrationSetup(confirm());
      await assert.rejects(host.migrationSetupContext(), /unavailable/);
    } else if (mode === 'disallowed') await assert.rejects(host.migrationSetupContext());
    else {
      const request = host.migrationSetupContext();
      if (mode === 'late') await host.stop();
      resolve({ methods: ['none'] });
      if (mode === 'late') await assert.rejects(request, /unavailable/);
      else assert.deepEqual(await request, { methods: ['none'] });
      assert.equal(selected, 0);
      assert.equal(host.isVaultWorkspace, false);
    }
    await host.stop();
  }
});

test('changed client and host migration methods meet the project coverage threshold', async (t) => {
  if (externalCoverage) return;
  try {
    const coverage = await profiler.post('Profiler.takePreciseCoverage');
    for (const [filename, methods] of [
      [
        'vault-client.ts',
        ['migrationSetupContext', 'beginMigrationSetup', 'confirmMigrationSetup'],
      ],
      [
        'vault-host.ts',
        [
          'migrationSetupContext',
          'beginMigrationSetup',
          'beginEnrollmentRequest',
          'confirmMigrationSetup',
        ],
      ],
    ] as const) {
      for (const method of methods) {
        const ranges = coverage.result
          .filter((s) => s.url.endsWith('/electron/' + filename))
          .flatMap((s) => s.functions)
          .filter((f) => f.functionName === method)
          .flatMap((f) => f.ranges);
        assert.ok(ranges.length, method);
        const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
        t.diagnostic(`${filename} ${method}: ${percent.toFixed(2)}% V8 blocks`);
        assert.ok(percent >= coverageThreshold, method);
      }
    }
  } finally {
    profiler.disconnect();
  }
});
