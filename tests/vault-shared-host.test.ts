import assert from 'node:assert/strict';
import test from 'node:test';
import { resolve } from 'node:path';
import { Session } from 'node:inspector/promises';
import { VaultBackendHost } from '../electron/vault-host.ts';
import { coverageThreshold } from '../scripts/test-coverage.ts';
import { sshBundle, sshRequest } from './fixtures/vault-ssh.ts';

const vaultId = '11111111-1111-4111-8111-111111111111',
  slotId = '22222222-2222-4222-8222-222222222222';
const input = () => ({
  vaultId,
  slotId,
  password: new Uint8Array([1, 2, 3]),
  ask: new Uint8Array(32).fill(5),
});
const startup = () => ({
  slots: {
    formatVersion: 1 as const,
    vaultId,
    encrypted: true,
    slots: [{ id: slotId, kind: 'password' as const, preset: 'kdf-v1' as const }],
  },
  cosmetics: { theme: 'system' as const },
  newWorkspace: false,
  shared: { lastLoginName: 'alice', serverDisplayName: 'Team' },
});
const workspaceId = '33333333-3333-4333-8333-333333333333';
const runtime = () => ({
  vaultId,
  workspaceId,
  tls: 'off',
  security: {
    sequence: '1',
    workspace: 'default',
    user: 'default',
    os: 'default',
    effective: 'default',
    source: 'workspace',
  },
});
const tick = () => new Promise<void>((resolve) => setImmediate(resolve));

test('shared catalog saves retain the workspace and the protected prompt owner through confirmation', async () => {
  const change = {
    nodeId: slotId,
    revision: '4',
    workspaceId,
    epoch: '1',
    changeSeq: '2',
    changes: { host: 'updated.example' },
  };
  for (const mode of [
    'saved',
    'canceled',
    'wrong-workspace',
    'wrong-slot',
    'stale-parent',
    'stale-dialog',
    'foreign-readback',
  ]) {
    let current = true,
      writes = 0;
    const host = new VaultBackendHost(
      () =>
        ({
          startup: async () => startup(),
          sharedRuntime: async () => runtime(),
          lock: async () => {},
          sharedUnlock: async () => ({ admitted: true, lockedMemory: true, orgEscrow: true }),
          sharedNodeEdit: async (q, auth) => {
            if (!q.changes) return { status: 'ready', workspaceId: vaultId };
            if (!auth) return { status: 'authentication-required' };
            writes++;
            if (mode === 'stale-parent') current = false;
            return { status: 'saved', nodeId: slotId, revision: '5' };
          },
        }) as any,
      () => true,
    );
    await host.sharedUnlock(input(), '2.4.3', () => true);
    let factors: ReturnType<typeof input> | undefined;
    const confirm: Parameters<typeof host.sharedNodeEdit>[2] = async (
      _startup,
      accepted,
      submit,
    ) => {
      assert.ok(accepted());
      if (mode === 'canceled') return null;
      factors = input();
      if (mode === 'wrong-slot') factors.slotId = vaultId;
      return submit({ ...factors, appVersion: '2.4.3' }, () => mode !== 'stale-dialog');
    };
    try {
      const q =
        mode === 'foreign-readback'
          ? { nodeId: slotId, revision: '4' }
          : mode === 'wrong-workspace'
            ? { ...change, workspaceId: vaultId }
            : change;
      const operation = host.sharedNodeEdit(q, () => current, confirm);
      if (mode === 'saved')
        assert.deepEqual(await operation, { status: 'saved', nodeId: slotId, revision: '5' });
      else if (mode === 'canceled') assert.deepEqual(await operation, { status: 'unavailable' });
      else await assert.rejects(operation);
      assert.equal(writes, mode === 'saved' || mode === 'stale-parent' ? 1 : 0);
      if (factors)
        assert.ok(factors.password.every((n) => n === 0) && factors.ask.every((n) => n === 0));
    } finally {
      await host.stop();
    }
  }
});

test('shared SSH confirmations belong to the admitted device, exact slot and current route', async (t) => {
  const profiler = new Session();
  profiler.connect();
  t.after(() => profiler.disconnect());
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  const request = { ...sshRequest(), workspaceId };
  const { publicKey: _, ...context } = request;
  const action = {
    ...context,
    route: null,
    expected: {
      binding: sshBundle(request).binding,
      fileId: vaultId,
      revision: 'a'.repeat(64),
      fingerprint: '',
    },
    received: 'SHA256:' + Buffer.alloc(32, 1).toString('base64').slice(0, -1),
  };
  let effective = 'standard',
    device = vaultId,
    selectedSlot = slotId,
    accepted = true,
    calls = 0;
  const host = new VaultBackendHost(
    () =>
      ({
        startup: async () => {
          const result = startup();
          result.slots.slots[0].id = selectedSlot;
          return result;
        },
        sharedUnlock: async () => ({ admitted: true, lockedMemory: true, orgEscrow: true }),
        sharedRuntime: async () => ({
          ...runtime(),
          vaultId: device,
          tls: 'verified',
          security: { ...runtime().security, workspace: effective, effective },
        }),
        trustSharedSshHost: async (value, auth) => {
          assert.deepEqual(value, action);
          if (effective === 'standard') assert.deepEqual(Array.from(auth.password), [1, 2, 3]);
          else assert.equal(auth, undefined);
          calls++;
        },
        lock: async () => {},
      }) as any,
    () => true,
  );
  type Confirm = Parameters<typeof host.trustSharedSshHost>[1];
  const save = (confirm: Confirm) => host.trustSharedSshHost(action, confirm, () => accepted);
  const confirm: Confirm = async (_metadata, current, submit) => {
    assert.ok(current());
    const factors = { ...input(), appVersion: '2.4.3' };
    try {
      return await submit(factors, () => true);
    } finally {
      assert.ok(factors.password.every((n) => n === 0) && factors.ask.every((n) => n === 0));
    }
  };
  await assert.rejects(save(confirm));
  await host.sharedUnlock(input(), '2.4.3', () => true);
  try {
    await assert.rejects(save(async () => null));
    await assert.rejects(
      save(async (_m, _c, submit) => submit({ ...input(), appVersion: '2.4.3' }, () => false)),
    );
    await assert.rejects(
      save(async (_m, _c, submit) =>
        submit({ ...input(), vaultId: workspaceId, appVersion: '2.4.3' }, () => true),
      ),
    );
    selectedSlot = workspaceId;
    await assert.rejects(save(confirm));
    selectedSlot = slotId;
    device = workspaceId;
    await assert.rejects(save(confirm));
    device = vaultId;
    effective = 'hardened';
    await assert.rejects(save(confirm));
    assert.equal(calls, 0);
    effective = 'standard';
    await save(confirm);
    effective = 'default';
    await save(async () => assert.fail('Default requested login'));
    assert.equal(calls, 2);
    accepted = false;
    await assert.rejects(save(confirm));
    assert.equal(calls, 2);
  } finally {
    await host.stop();
  }
  const report = await profiler.post('Profiler.takePreciseCoverage');
  const ranges = report.result
    .filter((script) => script.url.endsWith('/electron/vault-host.ts'))
    .flatMap((script) => script.functions)
    .filter((fn) => fn.functionName === 'trustSharedSshHost')
    .flatMap((fn) => fn.ranges);
  assert.ok(ranges.length);
  const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
  t.diagnostic('shared SSH host confirmation: ' + percent.toFixed(2) + '% V8 blocks');
  assert.ok(percent >= coverageThreshold);
});

test('shared Standard requires a verified eligible device and locks only the committing owner', async () => {
  let tls = 'off',
    eligible = false,
    trusted = true,
    locks = 0,
    writes = 0;
  let onCommit = async () => {};
  const host = new VaultBackendHost(
    () =>
      ({
        startup: async () => startup(),
        sharedUnlock: async () => ({ admitted: true, lockedMemory: true, orgEscrow: true }),
        sharedRuntime: async () => ({
          ...runtime(),
          tls,
          security: { ...runtime().security, ...(eligible ? { canTightenToStandard: true } : {}) },
        }),
        tightenSharedProfile: async (sequence: string, auth: ReturnType<typeof input>) => {
          assert.equal(sequence, '1');
          assert.deepEqual([...auth.password], [1, 2, 3]);
          writes++;
          await onCommit();
          return true;
        },
        lock: async () => {},
      }) as any,
    () => true,
  );
  type Confirm = Parameters<typeof host.tightenSharedProfile>[0];
  const change = (confirm: Confirm) =>
    host.tightenSharedProfile(
      confirm,
      () => trusted,
      async () => {
        locks++;
      },
    );
  const confirm: Confirm = async (start, current, submit) => {
    assert.equal(start.slots?.vaultId, vaultId);
    assert.ok(current());
    const factors = { ...input(), appVersion: '2.0.0' };
    try {
      return await submit(factors, () => true);
    } finally {
      assert.ok(factors.password.every((n) => n === 0) && factors.ask.every((n) => n === 0));
    }
  };
  await assert.rejects(change(confirm), /unavailable/);
  await host.sharedUnlock(input(), '2.0.0', () => true);
  await assert.rejects(change(confirm), /unavailable/);
  eligible = true;
  await assert.rejects(change(confirm), /unavailable/);
  tls = 'verified';
  await change(async () => null);
  await assert.rejects(
    change(async (_, __, submit) => submit({ ...input(), appVersion: '2.0.0' }, () => false)),
    /unavailable/,
  );
  assert.deepEqual([locks, writes], [0, 0]);
  await change(confirm);
  onCommit = async () => {
    trusted = false;
  };
  await change(confirm);
  assert.deepEqual([locks, writes], [2, 2]);
  trusted = true;
  onCommit = async () => {
    await host.stop();
    await host.sharedUnlock(input(), '2.0.0', () => true);
  };
  await change(confirm);
  assert.deepEqual([locks, writes], [2, 3]);
  await host.stop();
});

test('live shared browser View lookups accept only the current owner and exact generation receipt', async () => {
  const query = [{ nodeId: slotId, generation: vaultId }];
  let reply: unknown = [false];
  let waiting: Promise<boolean[]> | undefined;
  const requests: unknown[] = [];
  const fake = {
    startup: async () => startup(),
    sharedUnlock: async () => ({ admitted: true, lockedMemory: true, orgEscrow: true }),
    sharedRuntime: async () => runtime(),
    checkWebSessionViews: async (views) => {
      requests.push(views);
      return waiting ?? reply;
    },
    lock: async () => {},
  };
  const host = new VaultBackendHost(
    () => fake as any,
    () => true,
  );
  await assert.rejects(host.checkWebSessionViews(workspaceId, query), /unavailable/);
  await host.sharedUnlock(input(), '1.0.0', () => true);
  try {
    await assert.rejects(host.checkWebSessionViews(vaultId, query), /unavailable/);
    await assert.rejects(host.checkWebSessionViews(workspaceId, []), /unavailable/);
    assert.deepEqual(requests, []);
    assert.deepEqual(await host.checkWebSessionViews(workspaceId, query), [false]);
    assert.deepEqual(requests[0], query);
    assert.notEqual(requests[0], query);
    reply = ['true'];
    await assert.rejects(host.checkWebSessionViews(workspaceId, query), /receipt/);
    const gate = Promise.withResolvers<boolean[]>();
    waiting = gate.promise;
    const pending = host.checkWebSessionViews(workspaceId, query);
    await tick();
    await host.stop();
    gate.resolve([true]);
    await assert.rejects(pending, /unavailable/);
  } finally {
    await host.stop();
  }
});

test('personal key recovery pins fresh authentication to the admitted custodian and protected window', async () => {
  const request = { accountId: '44444444-4444-4444-8444-444444444444', suspension: '5' };
  const review = 'ac'.repeat(32);
  for (const mode of [
    'confirmed',
    'member',
    'missing-slot',
    'device-changed',
    'closed-during-read',
  ]) {
    let accepted = true;
    let startups = 0;
    let publications = 0;
    const fake = {
      startup: async () => {
        const value = startup();
        if (++startups === 1) return value;
        if (mode === 'missing-slot') value.slots.slots = [];
        if (mode === 'device-changed') value.slots.vaultId = workspaceId;
        if (mode === 'closed-during-read') accepted = false;
        return value;
      },
      sharedUnlock: async () => ({ admitted: true, lockedMemory: true, orgEscrow: true }),
      sharedRuntime: async () => ({
        ...runtime(),
        tls: 'verified',
        ...(mode === 'member' ? {} : { administrator: true }),
      }),
      sharedPersonalRootRecovery: async (scope, auth) => {
        if (!scope.review) {
          assert.deepEqual(scope, request);
          assert.equal(auth, undefined);
          return { status: 'review', review, enrollment: workspaceId };
        }
        publications++;
        assert.deepEqual(scope, { ...request, review });
        assert.deepEqual(auth, input());
        return { status: 'changed' };
      },
      lock: async () => {},
    };
    const host = new VaultBackendHost(
      () => fake as any,
      () => true,
    );
    try {
      await host.sharedUnlock(input(), '1.0.0', () => true);
      await host.openSharedAdministration(
        () => true,
        async (current, ports) => {
          assert.ok(current());
          if (mode === 'member') {
            assert.equal(ports.personalRecovery, undefined);
            return;
          }
          assert.ok(ports.personalRecovery);
          assert.deepEqual(await ports.personalRecovery(request, undefined, () => accepted), {
            status: 'review',
            review,
            enrollment: workspaceId,
          });
          const { password, ask } = input();
          const submit = ports.personalRecovery(
            { ...request, review },
            { password, ask },
            () => accepted,
          );
          if (mode === 'confirmed') assert.deepEqual(await submit, { status: 'changed' });
          else await assert.rejects(submit, /unavailable/i);
        },
      );
      assert.equal(publications, mode === 'confirmed' ? 1 : 0);
    } finally {
      await host.stop();
    }
  }
});

test('re-enrollment publication requires a current custodian slot and a matching sealed receipt', async () => {
  for (const scenario of [
    'issued',
    'member',
    'no-custody',
    'stale-slot',
    'stale-window',
    'wrong-receipt',
  ]) {
    const path = resolve('replacement.whreset');
    const request = {
      targetLogin: 'suspended-user',
      targetUserId: '44444444-4444-4444-8444-444444444444',
      suspension: '17',
      requestId: slotId,
      recipient: new Uint8Array(32).fill(7),
      password: new Uint8Array([1, 2, 3]),
      ask: new Uint8Array(32).fill(8),
    };
    let startups = 0;
    let accepted = true;
    let publications = 0;
    const fake = {
      startup: async () => {
        const current = startup();
        if (++startups === 2) {
          if (scenario === 'stale-slot') current.slots.vaultId = workspaceId;
          if (scenario === 'stale-window') accepted = false;
        }
        return current;
      },
      sharedRuntime: async () => ({
        ...runtime(),
        tls: 'verified',
        ...(scenario === 'member' ? {} : { administrator: true }),
        ...(scenario === 'no-custody' ? {} : { recoveryBackup: true }),
      }),
      sharedUnlock: async () => ({ admitted: true, lockedMemory: true, orgEscrow: true }),
      issueSharedAccountReset: async (destination, scope, auth) => {
        publications++;
        assert.equal(destination, path);
        assert.deepEqual(scope, request);
        assert.deepEqual(auth, { vaultId, slotId });
        return {
          status: 'issued',
          handover: { workspaceId, requestId: scenario === 'wrong-receipt' ? vaultId : slotId },
        };
      },
      lock: async () => {},
    };
    const host = new VaultBackendHost(
      () => fake as any,
      () => true,
    );
    try {
      await host.sharedUnlock(input(), '2.4.3', () => true);
      await host.openSharedAdministration(
        () => true,
        async (_, ports) => {
          const operation = ports.reenrollment;
          if (scenario === 'member' || scenario === 'no-custody') {
            assert.equal(operation, undefined);
            return;
          }
          assert.equal(operation?.workspaceId, workspaceId);
          const result = operation!.submit(path, request, () => accepted);
          if (scenario === 'issued') assert.equal((await result).status, 'issued');
          else await assert.rejects(result);
        },
      );
      assert.equal(publications, ['issued', 'wrong-receipt'].includes(scenario) ? 1 : 0);
    } finally {
      await host.stop();
    }
  }
});

test('a backup binds its optional factors and receipt to the admitted device', async (t) => {
  const profiler = new Session();
  profiler.connect();
  t.after(() => profiler.disconnect());
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  const path = resolve('workspace-backup.json');
  for (const scenario of [
    'default',
    'standard',
    'missing-slot',
    'absent',
    'wrong-workspace',
    'wrong-device',
    'navigation',
    'locked',
    'wrong-receipt',
  ]) {
    const standard = scenario === 'standard' || scenario === 'missing-slot';
    let runtimeReads = 0;
    let nativeExports = 0;
    let accepted = true;
    const fake = {
      startup: async () => ({
        ...startup(),
        ...(runtimeReads > 1 && scenario === 'missing-slot' ? { slots: null } : {}),
      }),
      sharedUnlock: async () => ({ admitted: true, lockedMemory: true, orgEscrow: true }),
      sharedRuntime: async () => {
        const issued = runtimeReads++ === 0;
        const current = runtime();
        return {
          ...current,
          tls: 'verified',
          ...(issued || scenario !== 'absent' ? { recoveryBackup: true } : {}),
          ...(!issued && scenario === 'wrong-device' ? { vaultId: workspaceId } : {}),
          ...(!issued && scenario === 'wrong-workspace' ? { workspaceId: vaultId } : {}),
          ...(standard
            ? { security: { ...current.security, workspace: 'standard', effective: 'standard' } }
            : {}),
        };
      },
      exportSharedRecoveryBackup: async (destination, publicKey, auth) => {
        nativeExports++;
        assert.equal(destination, path);
        assert.equal(publicKey.length, 32);
        if (standard) {
          assert.equal(auth.vaultId, vaultId);
          assert.equal(auth.slotId, slotId);
          assert.deepEqual(auth.password, input().password);
          assert.deepEqual(auth.ask, input().ask);
        } else assert.equal(auth, undefined);
        return {
          status: 'exported',
          receipt: { vaultId: scenario === 'wrong-receipt' ? vaultId : workspaceId },
        };
      },
      lock: async () => {},
    };
    const host = new VaultBackendHost(
      () => fake as any,
      () => true,
    );
    try {
      assert.equal((await host.sharedUnlock(input(), '1.0.0', () => true)).recoveryBackup, true);
      const open = host.openSharedRecoveryBackup(
        () => accepted,
        async (current, operation) => {
          assert.ok(current());
          assert.equal(operation.authenticationRequired, standard);
          const { password, ask } = input();
          const factors = { recipient: new Uint8Array(32), ...(standard ? { password, ask } : {}) };
          assert.deepEqual(await operation.submit('relative.json', factors, () => true), {
            status: 'save-failed',
          });
          if (scenario === 'navigation') accepted = false;
          if (scenario === 'locked') await host.stop();
          const result = await operation.submit(path, factors, () => true);
          assert.equal(result.status, 'exported');
        },
      );
      if (scenario === 'default' || scenario === 'standard') await open;
      else await assert.rejects(open, /unavailable/i);
      assert.equal(
        nativeExports,
        ['default', 'standard', 'wrong-receipt'].includes(scenario) ? 1 : 0,
      );
    } finally {
      await host.stop();
    }
  }
  const coverage = await profiler.post('Profiler.takePreciseCoverage');
  const script = coverage.result.find((entry) => entry.url.endsWith('/electron/vault-host.ts'))!;
  const start = script.functions.find((entry) => entry.functionName === 'openSharedRecoveryBackup')!
    .ranges[0];
  const ranges = script.functions.flatMap(({ ranges }) =>
    ranges.filter(
      (range) => range.startOffset >= start.startOffset && range.endOffset <= start.endOffset,
    ),
  );
  const percent = (100 * ranges.filter(({ count }) => count > 0).length) / ranges.length;
  t.diagnostic(`Workspace backup host: ${percent.toFixed(2)}% V8 blocks`);
  assert.ok(percent >= coverageThreshold);
});

test('local administrator enrollment stages a restart without replacing the authenticated owner', async (t) => {
  const profiler = new Session();
  profiler.connect();
  t.after(() => profiler.disconnect());
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  const receipt = { switchOnRestart: true } as const;
  const request = () => ({
    action: 'admin-join' as const,
    workspaceId,
    accountPassword: new Uint8Array([1, 2, 3]),
    ask: new Uint8Array(32).fill(5),
    deviceName: 'Device',
  });
  let owner = true;
  let accepted = true;
  let activations = 0;
  let complete!: (value: typeof receipt) => void;
  const host = new VaultBackendHost(
    () =>
      ({
        startup: async () => ({ ...startup(), shared: undefined }),
        unlock: async () => ({ unlocked: true, lockedMemory: true }),
        security: async () => runtime().security,
        selectSharedWorkspace: () => new Promise<typeof receipt>((resolve) => (complete = resolve)),
        lock: async () => {},
      }) as any,
    () => owner,
    () => activations++,
  );
  try {
    await host.startup();
    await host.unlock({ vaultId, slotId, kind: 'password', factor: new Uint8Array([1]) });
    for (const mode of ['success', 'stale-parent', 'stale-owner', 'locked']) {
      const value = request();
      const pending = host.sharedJoinAdministrator(value, '1.0.0', () => accepted);
      const duplicate = request();
      await assert.rejects(
        host.sharedJoinAdministrator(duplicate, '1.0.0', () => true),
        /unavailable/,
      );
      assert.ok(duplicate.accountPassword.every((n) => n === 0));
      if (mode === 'stale-parent') accepted = false;
      if (mode === 'stale-owner') owner = false;
      if (mode === 'locked') await host.stop();
      complete(receipt);
      if (mode === 'success') assert.deepEqual(await pending, receipt);
      else await assert.rejects(pending, /interrupted/);
      assert.ok(value.accountPassword.every((n) => n === 0) && value.ask.every((n) => n === 0));
      owner = accepted = true;
      assert.equal(host.isSharedWorkspace, false);
      assert.equal(host.unlockedWorkspaceId, mode === 'locked' ? undefined : vaultId);
    }
    assert.equal(activations, 1);
  } finally {
    await host.stop();
  }
  const coverage = await profiler.post('Profiler.takePreciseCoverage');
  const ranges = coverage.result
    .filter((script) => script.url.endsWith('/electron/vault-host.ts'))
    .flatMap((script) =>
      script.functions.filter((fn) => fn.functionName === 'sharedJoinAdministrator'),
    )
    .flatMap((fn) => fn.ranges);
  assert.ok(ranges.length > 0);
  const percent = (100 * ranges.filter((range) => range.count > 0).length) / ranges.length;
  t.diagnostic(`Administrator restart selection: ${percent.toFixed(2)}% V8 blocks`);
  assert.ok(percent >= coverageThreshold);
});

test('public transport comes from the current native runtime and malformed receipts cannot activate', async () => {
  for (const mode of ['off', 'encrypted', 'verified', 'bad-admission', 'bad-recovery']) {
    let runtimes = 0,
      activations = 0,
      stops = 0;
    const receipt = Object.freeze({ admitted: true, lockedMemory: true, orgEscrow: true });
    const fake = {
      startup: async () => startup(),
      sharedUnlock: async () => (mode === 'bad-admission' ? { recovered: true } : receipt),
      sharedRecoverPassword: async () => receipt,
      sharedRuntime: async () => {
        runtimes++;
        return { ...runtime(), tls: mode };
      },
      lock: async () => {
        stops++;
      },
    };
    const host = new VaultBackendHost(
      () => fake as any,
      () => true,
      () => {
        activations++;
      },
    );
    try {
      const pending =
        mode === 'bad-recovery'
          ? host.sharedRecoverPassword(input(), '1.0.0', () => true)
          : host.sharedUnlock(input(), '1.0.0', () => true);
      if (mode.startsWith('bad-')) {
        await assert.rejects(pending, /Shared vault authentication unavailable/);
        assert.equal(runtimes, 0);
        assert.equal(activations, 0);
        assert.equal(stops, 1);
      } else {
        assert.deepEqual(await pending, { ...receipt, tls: mode });
        assert.equal(activations, 1);
        assert.equal(runtimes, 1);
      }
      assert.deepEqual(Object.keys(receipt).sort(), ['admitted', 'lockedMemory', 'orgEscrow']);
      assert.equal(host.unlockedWorkspaceId, mode.startsWith('bad-') ? undefined : workspaceId);
    } finally {
      await host.stop();
    }
  }
});

test('continuation rechecks capability, owner and device selection before native dispatch', async () => {
  for (const mode of ['success', 'legacy', 'active', 'wrong-slot', 'stale', 'error']) {
    let calls = 0,
      accepted = true,
      activations = 0;
    const fake = {
      startup: async () => {
        const m: any = startup();
        if (mode !== 'active') {
          m.sharedJoin = { ...m.shared, ...(mode !== 'legacy' ? { canContinue: true } : {}) };
          delete m.shared;
        }
        return m;
      },
      sharedContinueEnrollment: async (value: any, version: string) => {
        calls++;
        assert.equal(version, '1.2.3');
        assert.equal(value.acknowledgeTLSOff, true);
        assert.ok(value.code.every((n: number) => n === 6));
        assert.equal(host.unlockedWorkspaceId, undefined);
        value.code.fill(0);
        value.password.fill(0);
        value.ask?.fill(0);
        if (mode === 'stale') accepted = false;
        if (mode === 'error') throw Error('private');
        return { admitted: true, lockedMemory: true, orgEscrow: true };
      },
      sharedRuntime: async () => runtime(),
      lock: async () => {},
    };
    const host = new VaultBackendHost(
      () => fake as any,
      () => true,
      () => {
        activations++;
      },
    );
    const value = {
      ...input(),
      ...(mode === 'wrong-slot' ? { slotId: vaultId } : {}),
      code: new Uint8Array(16).fill(6),
      acknowledgeTLSOff: true,
    };
    try {
      const result = host.sharedContinueEnrollment(value, '1.2.3', () => accepted);
      if (mode === 'success') {
        assert.equal((await result).admitted, true);
        assert.equal(host.unlockedWorkspaceId, workspaceId);
      } else await assert.rejects(result, /Shared vault/);
      assert.equal(calls, ['success', 'stale', 'error'].includes(mode) ? 1 : 0);
      assert.equal(activations, mode === 'success' ? 1 : 0);
      assert.ok(value.code.every((n) => n === 0));
      assert.ok(value.password.every((n) => n === 0));
    } finally {
      await host.stop();
    }
  }
});

test('shared policy activation rejects stale owners, wrong slot identities and activation failures', async (t) => {
  const profiler = new Session();
  profiler.connect();
  t.after(() => profiler.disconnect());
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  for (const mode of [
    'success',
    'invalid',
    'tls-missing',
    'tls-invalid',
    'wrong-vault',
    'caller-lost',
    'owner-lost',
    'stopping',
    'native-error',
    'activate-error',
    'activate-stop',
    'activate-caller',
    'kind-flip',
    'locked-kind',
    'security-late',
  ]) {
    let accepted = true,
      canStart = true,
      calls = 0,
      stops = 0,
      activations = 0;
    const fake = {
      startup: async () => startup(),
      sharedUnlock: async () => ({ admitted: true, lockedMemory: true, orgEscrow: true }),
      sharedRuntime: async () => {
        calls++;
        assert.equal(host.unlockedWorkspaceId, undefined);
        if (mode === 'invalid') return { ...runtime(), capability: 'private' };
        if (mode === 'tls-missing') return { ...runtime(), tls: undefined };
        if (mode === 'tls-invalid') return { ...runtime(), tls: 'prefer' };
        if (mode === 'wrong-vault') return { ...runtime(), vaultId: slotId };
        if (mode === 'caller-lost') accepted = false;
        if (mode === 'owner-lost') await host.stop();
        if (mode === 'stopping') canStart = false;
        if (mode === 'native-error') throw Error('private diagnostic');
        return runtime();
      },
      security: async () => {
        if (mode === 'security-late') await host.stop();
        return runtime().security;
      },
      lock: async () => {
        stops++;
      },
    };
    const host = new VaultBackendHost(
      () => fake as any,
      () => canStart,
      (security) => {
        activations++;
        assert.deepEqual(security, runtime().security);
        assert.equal(host.unlockedWorkspaceId, undefined);
        if (mode === 'activate-error') throw Error('private activation error');
        if (mode === 'activate-stop') void host.stop();
        if (mode === 'activate-caller') accepted = false;
      },
    );
    try {
      const inputValue = input();
      const pending = host.sharedUnlock(inputValue, '1.0.0', () => accepted);
      if (['success', 'kind-flip', 'locked-kind', 'security-late'].includes(mode)) {
        await pending;
        assert.equal(host.unlockedWorkspaceId, workspaceId);
        assert.equal(host.isSharedWorkspace, true);
        assert.equal(activations, 1);
        if (mode === 'kind-flip') {
          fake.startup = async () => ({ ...startup(), shared: undefined }) as any;
          await assert.rejects(host.startup(), /identity changed/);
        }
        if (mode === 'locked-kind') {
          await host.stop();
          assert.equal(host.isSharedWorkspace, true);
          assert.equal(host.isVaultWorkspace, true);
          await assert.rejects(
            host.unlock({ vaultId, slotId, kind: 'password', factor: new Uint8Array([1]) }),
            /pending/,
          );
        }
        if (mode === 'security-late') await assert.rejects(host.security(), /stopping/);
      } else {
        await assert.rejects(pending, { message: 'Shared vault authentication unavailable.' });
        assert.equal(host.unlockedWorkspaceId, undefined);
        assert.equal(stops, 1);
      }
      assert.equal(calls, 1);
      assert.ok(inputValue.password.every((n) => n === 0));
      assert.ok(inputValue.ask.every((n) => n === 0));
    } finally {
      await host.stop();
    }
  }
  const report = await profiler.post('Profiler.takePreciseCoverage');
  const scripts = report.result.filter((s) => s.url.endsWith('/electron/vault-shared-runtime.ts'));
  const ranges = scripts.flatMap((s) => s.functions.flatMap((f) => f.ranges));
  assert.ok(ranges.length > 0);
  const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
  t.diagnostic(`shared runtime parser: ${percent.toFixed(2)}% V8 blocks`);
  assert.ok(percent >= coverageThreshold);
});

test('shared catalog requires admission and discards results after caller or owner loss', async (t) => {
  const profiler = new Session();
  profiler.connect();
  t.after(() => profiler.disconnect());
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  const request = { after: '', epoch: '0', changeSeq: '0', limit: 1 };
  const result = { epoch: '1', changeSeq: '0', nodes: [], next: null };
  for (const mode of ['success', 'not-admitted', 'invalid', 'caller-lost', 'owner-lost', 'error']) {
    let accepted = true,
      calls = 0,
      stops = 0;
    const fake = {
      startup: async () => startup(),
      sharedRuntime: async () => runtime(),
      sharedUnlock: async () => ({ admitted: true, lockedMemory: false, orgEscrow: true }),
      sharedChanges: async () => ({ epoch: '1', changeSeq: '0', reset: true, nodes: [] }),
      sharedCatalog: async (value: unknown) => {
        calls++;
        assert.deepEqual(value, request);
        if (mode === 'caller-lost') accepted = false;
        if (mode === 'owner-lost') await host.stop();
        if (mode === 'error') throw Error('private diagnostic');
        return result;
      },
      lock: async () => {
        stops++;
      },
    };
    const host = new VaultBackendHost(
      () => fake as any,
      () => true,
    );
    try {
      if (mode !== 'not-admitted') await host.sharedUnlock(input(), '1.0.0', () => true);
      await assert.rejects(
        host.sharedChanges({}, () => true),
        /Invalid shared changes/,
      );
      if (mode === 'success')
        assert.deepEqual(await host.sharedChanges({ epoch: '0', changeSeq: '0' }, () => true), {
          epoch: '1',
          changeSeq: '0',
          reset: true,
          nodes: [],
        });
      const pending = host.sharedCatalog(mode === 'invalid' ? {} : request, () => accepted);
      if (mode === 'success') assert.deepEqual(await pending, result);
      else await assert.rejects(pending, /shared catalog|Shared catalog/);
      assert.equal(calls, ['invalid', 'not-admitted'].includes(mode) ? 0 : 1);
      assert.equal(stops, ['caller-lost', 'owner-lost', 'error'].includes(mode) ? 1 : 0);
      assert.equal(
        host.unlockedWorkspaceId,
        ['success', 'invalid'].includes(mode) ? workspaceId : undefined,
      );
    } finally {
      await host.stop();
    }
  }
  const coverage = await profiler.post('Profiler.takePreciseCoverage');
  const ranges = coverage.result
    .filter((s) => s.url.endsWith('/electron/vault-host.ts'))
    .flatMap((s) => s.functions)
    .filter((f) => ['sharedCatalog', 'sharedChanges', 'sharedRead'].includes(f.functionName))
    .flatMap((f) => f.ranges);
  assert.ok(ranges.length > 0);
  const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
  t.diagnostic(`shared catalog host: ${percent.toFixed(2)}% V8 blocks`);
  assert.ok(percent >= coverageThreshold);
});

test('a committed CA change locks the original workspace even after renderer navigation', async () => {
  for (const mode of ['refused', 'retired', 'navigated', 'replaced']) {
    let trusted = true;
    let applicationLocks = 0;
    const host = new VaultBackendHost(
      () =>
        ({
          startup: async () => startup(),
          sharedRuntime: async () => runtime(),
          sharedUnlock: async () => ({ admitted: true, orgEscrow: true, lockedMemory: true }),
          sharedWorkspaceCA: async () => {
            if (mode === 'refused') return { status: 'installation-required' };
            if (mode === 'navigated') trusted = false;
            if (mode === 'replaced') {
              await host.stop();
              await host.sharedUnlock(input(), '1.0.0', () => true);
            }
            return { status: 'retired', reconnect: true };
          },
          lock: async () => {},
        }) as any,
      () => true,
    );
    try {
      await host.sharedUnlock(input(), '1.0.0', () => true);
      const response = host.sharedWorkspaceCA(
        { action: 'retire' },
        () => trusted,
        async () => {
          applicationLocks++;
          await host.stop();
        },
      );
      if (mode === 'replaced' || mode === 'navigated') await assert.rejects(response);
      else
        assert.equal(
          (await response).status,
          mode === 'retired' ? 'retired' : 'installation-required',
        );
      assert.equal(applicationLocks, mode === 'retired' || mode === 'navigated' ? 1 : 0);
      assert.equal(host.hasOwner, mode === 'refused' || mode === 'replaced');
    } finally {
      await host.stop();
    }
  }
});

test('trust export never writes after the chooser loses its workspace owner or caller', async () => {
  for (const mode of ['cancel', 'invalid', 'save', 'navigation', 'lock']) {
    let accepted = true;
    let writes = 0;
    let finish!: (path: string | null) => void;
    const expected = resolve('current.whtls');
    const host = new VaultBackendHost(
      () =>
        ({
          startup: async () => startup(),
          sharedRuntime: async () => runtime(),
          sharedUnlock: async () => ({ admitted: true, lockedMemory: true, orgEscrow: true }),
          exportSharedTLSBundle: async (path: string) => {
            assert.equal(path, expected);
            writes++;
            return true;
          },
          lock: async () => {},
        }) as any,
      () => true,
    );
    try {
      await host.sharedUnlock(input(), '1.0.0', () => true);
      const exporting = host.exportSharedTLSBundle(
        () => new Promise((resolvePath) => (finish = resolvePath)),
        () => accepted,
      );
      if (mode === 'navigation') accepted = false;
      if (mode === 'lock') await host.stop();
      finish(mode === 'cancel' ? null : mode === 'invalid' ? 'renderer.whtls' : expected);
      if (mode === 'navigation' || mode === 'lock') await assert.rejects(exporting);
      else assert.equal(await exporting, mode === 'cancel' ? null : mode === 'save');
      assert.equal(writes, mode === 'save' ? 1 : 0);
    } finally {
      await host.stop();
    }
  }
});

test('recovery kit refresh rechecks ownership after each native file picker', async () => {
  const source = resolve('old.whrecovery'),
    destination = resolve('new.whrecovery');
  for (const mode of [
    'cancel-open',
    'cancel-save',
    'same',
    'invalid',
    'navigation-open',
    'navigation-save',
    'success',
  ]) {
    let accepted = true;
    const prompts: string[] = [];
    const writes: string[][] = [];
    const host = new VaultBackendHost(
      () =>
        ({
          startup: async () => startup(),
          sharedRuntime: async () => runtime(),
          sharedUnlock: async () => ({ admitted: true, lockedMemory: true, orgEscrow: true }),
          refreshSharedRecoveryKit: async (from: string, to: string) => {
            writes.push([from, to]);
            return 'updated';
          },
          lock: async () => {},
        }) as any,
      () => true,
    );
    try {
      await host.sharedUnlock(input(), '1.0.0', () => true);
      const updating = host.refreshSharedRecoveryKit(
        async (intent) => {
          prompts.push(intent);
          if (mode === `navigation-${intent}`) accepted = false;
          if (mode === `cancel-${intent}`) return null;
          if (intent === 'open') return mode === 'invalid' ? 'relative.whrecovery' : source;
          return mode === 'same' ? source : destination;
        },
        () => accepted,
      );
      if (mode.startsWith('navigation')) await assert.rejects(updating);
      else
        assert.equal(
          await updating,
          mode === 'success'
            ? 'updated'
            : mode === 'invalid'
              ? 'invalid-kit'
              : mode === 'same'
                ? 'save-failed'
                : null,
        );
      assert.deepEqual(
        prompts,
        ['cancel-open', 'invalid', 'navigation-open'].includes(mode) ? ['open'] : ['open', 'save'],
      );
      assert.deepEqual(writes, mode === 'success' ? [[source, destination]] : []);
    } finally {
      await host.stop();
    }
  }
});

test('recovery kit confirmation is bound to the initiating document and wipes the factors', async () => {
  const source = resolve('old.whrecovery');
  const destination = resolve('new.whrecovery');
  for (const mode of ['stale-document', 'stale-dialog', 'retry']) {
    let current = true;
    let tries = 0;
    const host = new VaultBackendHost(
      () =>
        ({
          startup: async () => startup(),
          sharedRuntime: async () => runtime(),
          sharedUnlock: async () => ({ admitted: true, lockedMemory: true, orgEscrow: true }),
          lock: async () => {},
          refreshSharedRecoveryKit: async (from, to, auth) => {
            assert.equal(from, source);
            assert.equal(to, destination);
            if (!auth) return 'authentication-required';
            assert.ok(auth.password.some((n) => n !== 0));
            assert.ok(auth.ask.some((n) => n !== 0));
            return ++tries === 1 ? 'invalid-authentication' : 'updated';
          },
        }) as any,
      () => true,
    );
    try {
      await host.sharedUnlock(input(), '1.0.0', () => true);
      const updating = host.refreshSharedRecoveryKit(
        async (intent) => (intent === 'open' ? source : destination),
        () => current,
        async (metadata, accepted, submit) => {
          assert.ok(metadata.shared && accepted());
          const factors = { ...input(), appVersion: '1.0.0' };
          if (mode === 'stale-document') current = false;
          await assert.rejects(submit(factors, () => mode !== 'stale-dialog'));
          assert.ok(factors.password.every((n) => n === 0));
          assert.ok(factors.ask.every((n) => n === 0));
          if (mode !== 'retry') return null;
          return submit({ ...input(), appVersion: '1.0.0' }, () => true);
        },
      );
      if (mode === 'stale-document') await assert.rejects(updating);
      else assert.equal(await updating, mode === 'retry' ? 'updated' : null);
      assert.equal(tries, mode === 'retry' ? 2 : 0);
    } finally {
      await host.stop();
    }
  }
});

test('main-only shared host binds selection, disposes factors and activates verified shared policy before publishing the remote identity', async (t) => {
  const profiler = new Session();
  profiler.connect();
  t.after(() => profiler.disconnect());
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  for (const mode of [
    'admit',
    'recover',
    'missing-shared',
    'wrong-vault',
    'wrong-slot',
    'declined',
    'lost-startup',
    'lost-result',
    'busy',
    'native-error',
    'stopping',
  ] as const) {
    let accepted = true,
      canStart = true,
      calls = 0,
      stops = 0,
      activated = 0;
    let release: (() => void) | undefined;
    let borrowed: ReturnType<typeof input> | undefined;
    const fake = {
      startup: async () => {
        if (mode === 'lost-startup') accepted = false;
        const value = startup();
        if (mode === 'missing-shared') delete (value as { shared?: unknown }).shared;
        if (mode === 'wrong-vault') value.slots.vaultId = slotId;
        if (mode === 'wrong-slot') value.slots.slots[0].id = vaultId;
        return value;
      },
      sharedRuntime: async () => runtime(),
      security: async () => runtime().security,
      sharedUnlock: async (value: ReturnType<typeof input>, version: string) => {
        calls++;
        borrowed = value;
        assert.equal(version, '1.0.0');
        assert.deepEqual([...value.password], [1, 2, 3]);
        assert.ok(value.ask.every((n) => n === 5));
        assert.deepEqual(Object.keys(value).sort(), ['ask', 'password', 'slotId', 'vaultId']);
        if (mode === 'busy')
          await new Promise<void>((resolve) => {
            release = resolve;
          });
        if (mode === 'lost-result') accepted = false;
        if (mode === 'native-error') throw Error('private backend diagnostic');
        return { admitted: true as const, lockedMemory: false, orgEscrow: true };
      },
      sharedRecoverPassword: async (value: ReturnType<typeof input>, version: string) => {
        calls++;
        borrowed = value;
        assert.equal(version, '1.0.0');
        return { recovered: true as const };
      },
      lock: async () => {
        stops++;
      },
    };
    const host = new VaultBackendHost(
      () => fake as any,
      () => canStart,
      () => {
        activated++;
      },
    );
    try {
      if (mode === 'declined') accepted = false;
      if (mode === 'stopping') canStart = false;
      const value = input();
      const pending =
        mode === 'recover'
          ? host.sharedRecoverPassword(value, '1.0.0', () => accepted)
          : host.sharedUnlock(value, '1.0.0', () => accepted);
      assert.ok(value.password.every((n) => n === 0));
      assert.ok(value.ask.every((n) => n === 0));
      if (mode === 'busy') {
        await tick();
        assert.ok(release);
        const other = input();
        await assert.rejects(
          host.sharedUnlock(other, '1.0.0', () => true),
          /unavailable/,
        );
        assert.ok(other.password.every((n) => n === 0));
        assert.equal(calls, 1);
        assert.equal(stops, 0);
        const local = { vaultId, slotId, kind: 'password', factor: new Uint8Array([1]) };
        await assert.rejects(host.unlock(local), /pending/);
        assert.equal(local.factor[0], 0);
        release!();
      }
      if (['admit', 'recover', 'busy'].includes(mode)) {
        assert.deepEqual(
          await pending,
          mode === 'recover'
            ? { recovered: true }
            : { admitted: true, lockedMemory: false, orgEscrow: true, tls: 'off' },
        );
        if (mode === 'admit') {
          assert.deepEqual(await host.security(), runtime().security);
          const duplicate = input();
          await assert.rejects(
            host.sharedUnlock(duplicate, '1.0.0', () => true),
            /unavailable/,
          );
          assert.equal(calls, 1);
          assert.equal(stops, 0);
        }
      } else {
        await assert.rejects(pending, { message: 'Shared vault authentication unavailable.' });
        assert.equal(calls, ['lost-result', 'native-error'].includes(mode) ? 1 : 0);
        if (!['declined', 'stopping'].includes(mode)) assert.equal(stops, 1);
      }
      const admitted = ['admit', 'busy'].includes(mode);
      assert.equal(host.unlockedWorkspaceId, admitted ? workspaceId : undefined);
      assert.equal(activated, admitted ? 1 : 0);
      assert.equal(
        host.isSharedWorkspace,
        ![
          'missing-shared',
          'wrong-vault',
          'wrong-slot',
          'declined',
          'lost-startup',
          'stopping',
        ].includes(mode),
      );
      if (borrowed) {
        assert.ok(borrowed.password.every((n) => n === 0));
        assert.ok(borrowed.ask.every((n) => n === 0));
      }
    } finally {
      await host.stop();
    }
  }
  const coverage = await profiler.post('Profiler.takePreciseCoverage');
  const functions = coverage.result
    .filter((s) => s.url.endsWith('/electron/vault-host.ts'))
    .flatMap((s) => s.functions)
    .filter((f) =>
      ['sharedUnlock', 'sharedRecoverPassword', 'sharedAuthentication'].includes(f.functionName),
    );
  assert.equal(functions.length, 3);
  const ranges = functions.flatMap((f) => f.ranges);
  const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
  t.diagnostic(`shared host methods: ${percent.toFixed(2)}% V8 blocks`);
  assert.ok(percent >= coverageThreshold);
  const hostRanges = coverage.result
    .filter((s) => s.url.endsWith('/electron/vault-host.ts'))
    .flatMap((s) => s.functions)
    .filter((f) =>
      [
        'get isSharedWorkspace',
        'sharedAuthentication',
        'select',
        'rememberWorkspace',
        'security',
      ].includes(f.functionName),
    )
    .flatMap((f) => f.ranges);
  assert.ok(hostRanges.length > 0);
  const hostPercent = (100 * hostRanges.filter((r) => r.count > 0).length) / hostRanges.length;
  t.diagnostic(`shared activation and ownership: ${hostPercent.toFixed(2)}% V8 blocks`);
  assert.ok(hostPercent >= coverageThreshold);
});

test('shared connection context requires admission and discards caller/owner loss', async (t) => {
  const profiler = new Session();
  profiler.connect();
  t.after(() => profiler.disconnect());
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  for (const mode of ['ok', 'invalid', 'not-admitted', 'caller-lost', 'owner-lost', 'error']) {
    let accepted = true,
      calls = 0,
      stops = 0;
    const fake = {
      startup: async () => startup(),
      sharedRuntime: async () => runtime(),
      sharedUnlock: async () => ({ admitted: true, lockedMemory: true, orgEscrow: true }),
      sharedConnectionContext: async (value: any) => {
        calls++;
        assert.deepEqual(value, { nodeId: vaultId });
        if (mode === 'caller-lost') accepted = false;
        if (mode === 'owner-lost') await host.stop();
        if (mode === 'error') throw Error('private');
        return { nodeId: vaultId, protocol: 7 };
      },
      lock: async () => {
        stops++;
      },
    };
    const host = new VaultBackendHost(
      () => fake as any,
      () => true,
    );
    try {
      if (mode !== 'not-admitted') await host.sharedUnlock(input(), '1.0.0', () => true);
      const pending = host.sharedConnectionContext(
        mode === 'invalid' ? {} : { nodeId: vaultId },
        () => accepted,
      );
      if (mode === 'ok') assert.deepEqual(await pending, { nodeId: vaultId, protocol: 7 });
      else
        await assert.rejects(
          pending,
          (error) => error instanceof Error && !error.message.includes('private'),
        );
      assert.equal(calls, ['invalid', 'not-admitted'].includes(mode) ? 0 : 1);
      assert.equal(stops, ['caller-lost', 'owner-lost', 'error'].includes(mode) ? 1 : 0);
    } finally {
      await host.stop();
    }
  }
  const coverage = await profiler.post('Profiler.takePreciseCoverage');
  const ranges = coverage.result
    .filter((script) => script.url.endsWith('/electron/vault-host.ts'))
    .flatMap((script) => script.functions)
    .filter((fn) => fn.functionName === 'sharedConnectionContext')
    .flatMap((fn) => fn.ranges);
  assert.ok(ranges.length > 0);
  const percent = (100 * ranges.filter((range) => range.count > 0).length) / ranges.length;
  t.diagnostic('shared connection host: ' + percent.toFixed(2) + '% V8 blocks');
  assert.ok(percent >= coverageThreshold);
});
