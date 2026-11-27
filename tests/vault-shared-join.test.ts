import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { Session } from 'node:inspector/promises';
import { resolve } from 'node:path';
import { VaultBackendClient } from '../electron/vault-client.ts';
import { VaultBackendHost } from '../electron/vault-host.ts';
import { parseVaultStartup } from '../electron/vault-contract.ts';
import { prepareVaultMigrationBoot } from '../electron/vault-migration-boot.ts';
import { coverageThreshold } from '../scripts/test-coverage.ts';
import { consumeSharedInitialJoinInput } from '../electron/vault-shared-initial-join.ts';
import { consumeSharedAccountResetInput } from '../electron/vault-shared-account-reset.ts';
import {
  SharedConnectionLimit,
  SharedReenrollmentPending,
} from '../electron/vault-shared-unlock.ts';
import {
  isSharedInitialStartup,
  maxSharedInvitationBytes,
  parseSharedInvitation,
  validSharedInvitationText,
} from '../electron/vault-shared-invitation.ts';
const profiler = new Session(),
  external =
    process.execArgv.includes('--experimental-test-coverage') || !!process.env.NODE_V8_COVERAGE;
if (!external) {
  profiler.connect();
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
}
const vaultId = '11111111-1111-4111-8111-111111111111',
  slotId = '22222222-2222-4222-8222-222222222222',
  workspaceId = '33333333-3333-4333-8333-333333333333';
const metadata = () => ({
  slots: {
    formatVersion: 1 as const,
    vaultId,
    encrypted: true,
    slots: [{ id: slotId, kind: 'password' as const, preset: 'kdf-v1' as const }],
  },
  cosmetics: { theme: 'system' as const },
  newWorkspace: false,
  sharedJoin: { lastLoginName: 'alice', serverDisplayName: workspaceId },
});
const input = () => ({
  vaultId,
  slotId,
  password: new Uint8Array([1, 2, 3]),
  ask: new Uint8Array(32).fill(4),
});
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
const tick = () => new Promise(setImmediate);
const initialInput = () => ({
  invitation: 'WHINV2-public-token',
  code: new Uint8Array(16).fill(7),
  password: new Uint8Array([1, 2, 3]),
  ask: new Uint8Array(32).fill(4),
  deviceName: 'Native device',
  acknowledgeTLSOff: true,
});
const resetPath = resolve('selected-account.whreset');
const resetInput = () => ({
  kind: 'account-reset' as const,
  code: new Uint8Array(16).fill(7),
  password: new Uint8Array([1, 2, 3]),
  ask: new Uint8Array(32).fill(4),
  deviceName: 'Native device',
});

test('pending shared enrollment is exclusive public metadata and is recognized before readiness', () => {
  assert.deepEqual(parseVaultStartup(metadata()), metadata());
  const pendingReset = (hint: Record<string, unknown>) => ({
    ...metadata(),
    sharedJoin: { ...metadata().sharedJoin, ...hint },
  });
  const validReset = pendingReset({ accountReset: true, canContinue: true });
  assert.deepEqual(parseVaultStartup(validReset), validReset);
  for (const hint of [
    { accountReset: true },
    { accountReset: false, canContinue: true },
    { accountReset: true, canContinue: true, adminRecovery: true },
  ])
    assert.equal(parseVaultStartup(pendingReset(hint)), undefined);
  for (const extra of [
    { shared: {} },
    { legacy: {} },
    { migration: {} },
    { rotation: {} },
    { unprotected: {} },
    { upgrade: {} },
    { osMigration: {} },
    { newWorkspace: true },
    { slots: null },
    { sharedJoin: { lastLoginName: 'alice', serverDisplayName: workspaceId, authority: true } },
    { sharedJoin: { lastLoginName: 'bad\nlogin', serverDisplayName: workspaceId } },
  ])
    assert.equal(parseVaultStartup({ ...metadata(), ...extra }), undefined);
  const boot = prepareVaultMigrationBoot({
    app: {
      isReady: () => false,
      requestSingleInstanceLock: () => true,
      getPath: () => '',
      setPath: () => assert.fail('enrollment recovery is not legacy data retirement'),
    } as any,
    executable: () => 'native',
    databasePath: 'db',
    probe: () => ({ status: 0, stdout: JSON.stringify(metadata()) }),
  });
  assert.deepEqual(boot, { primary: true, unavailable: false });
});

test('shared enrollment transport wipes factors and requires the native admission response', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  for (const kind of ['recovery', 'initial', 'continuation', 'reset']) {
    const initial = kind === 'initial',
      continuing = kind === 'continuation',
      resetting = kind === 'reset';
    for (const invalid of [false, true, 'missing-notice', 'string-notice', 'awaiting-activation']) {
      const child: any = new EventEmitter();
      Object.assign(child, {
        pid: process.pid,
        exitCode: null,
        signalCode: null,
        stdout: new PassThrough(),
        stderr: new PassThrough(),
      });
      const frames: Buffer[] = [];
      let reply!: () => void;
      child.stdin = new Writable({
        write(chunk, _encoding, done) {
          frames.push(chunk);
          const request = JSON.parse(chunk.toString());
          if (request.operation !== 'lock') {
            assert.equal(
              request.operation,
              resetting
                ? 'shared-account-reset-redeem'
                : initial
                  ? 'shared-join-initial'
                  : continuing
                    ? 'shared-continue-enrollment'
                    : 'shared-recover-enrollment',
            );
            assert.deepEqual(
              Object.keys(request.payload).sort(),
              resetting
                ? ['appVersion', 'ask', 'code', 'deviceName', 'offerPath', 'password']
                : initial
                  ? [
                      'acknowledgeTLSOff',
                      'appVersion',
                      'ask',
                      'code',
                      'deviceName',
                      'invitation',
                      'password',
                    ]
                  : continuing
                    ? ['acknowledgeTLSOff', 'appVersion', 'code', 'factors']
                    : ['appVersion', 'factors'],
            );
            assert.equal(request.payload.appVersion, '1.0.0');
            if (resetting) {
              assert.equal(request.payload.offerPath, resetPath);
              assert.equal(request.payload.code, Buffer.alloc(16, 7).toString('base64'));
              assert.equal(request.payload.ask, Buffer.alloc(32, 4).toString('base64'));
            } else if (initial) {
              assert.equal(request.payload.code, Buffer.alloc(16, 7).toString('base64'));
              assert.equal(request.payload.invitation, initialInput().invitation);
              assert.equal(request.payload.acknowledgeTLSOff, true);
            } else {
              assert.deepEqual(Object.keys(request.payload.factors).sort(), [
                'ask',
                'password',
                'slotId',
                'vaultId',
              ]);
              if (continuing) {
                assert.equal(request.payload.code, Buffer.alloc(16, 7).toString('base64'));
                assert.equal(request.payload.acknowledgeTLSOff, true);
              }
            }
            reply = () =>
              child.stdout.write(
                JSON.stringify({
                  version: 1,
                  id: request.id,
                  result:
                    invalid === 'missing-notice'
                      ? { admitted: true, lockedMemory: true }
                      : invalid === 'string-notice'
                        ? { admitted: true, lockedMemory: true, orgEscrow: 'false' }
                        : invalid === 'awaiting-activation'
                          ? { awaitingActivation: true }
                          : invalid
                            ? { recovered: true }
                            : { admitted: true, lockedMemory: true, orgEscrow: true },
                }) + '\n',
              );
          }
          done();
        },
      });
      child.stdin.on('finish', () => {
        child.exitCode = 0;
        child.emit('exit', 0, null);
        child.stdout.end();
        child.stderr.end();
        child.emit('close', 0, null);
      });
      child.kill = () => {
        child.stdin.end();
        return true;
      };
      const client = new VaultBackendClient({ executable: 'native', databasePath: 'db' }, () => {
        queueMicrotask(() => child.emit('spawn'));
        return child;
      });
      try {
        const value = resetting
          ? resetInput()
          : initial
            ? initialInput()
            : continuing
              ? { ...input(), code: new Uint8Array(16).fill(7), acknowledgeTLSOff: true }
              : input();
        const pending = resetting
          ? client.sharedRedeemAccountReset(resetPath, value, '1.0.0')
          : initial
            ? client.sharedJoinInitial(value, '1.0.0')
            : continuing
              ? client.sharedContinueEnrollment(value, '1.0.0')
              : client.sharedRecoverEnrollment(value, '1.0.0');
        let settled = false;
        void pending.then(
          () => {
            settled = true;
          },
          () => {
            settled = true;
          },
        );
        await tick();
        if (!invalid) {
          t.mock.timers.tick(initial || continuing || resetting ? 310_000 : 125_000);
          await tick();
          assert.equal(
            settled,
            false,
            'two-stage native recovery timed out at the ordinary admission budget',
          );
        }
        reply();
        if (invalid === 'awaiting-activation')
          await assert.rejects(
            pending,
            (error) => error instanceof SharedReenrollmentPending !== initial,
          );
        else if (invalid) await assert.rejects(pending);
        else
          assert.deepEqual(await pending, { admitted: true, lockedMemory: true, orgEscrow: true });
        assert.ok(value.password.every((b) => b === 0) && value.ask.every((b) => b === 0));
        if ('code' in value) assert.ok(value.code.every((b) => b === 0));
        await tick();
        assert.ok(frames[0].every((b) => b === 0));
      } finally {
        await client.lock();
      }
    }
  }
});

test('account reset factors cannot provide a path or bypass required ASK', async () => {
  for (const [patch, version] of [
    [{ offerPath: resetPath }, '1.0.0'],
    [{ kind: 'invite' }, '1.0.0'],
    [{ ask: new Uint8Array(31).fill(4) }, '1.0.0'],
    [{ code: new Uint8Array(15).fill(4) }, '1.0.0'],
    [{ password: new Uint8Array(1025).fill(4) }, '1.0.0'],
    [{ deviceName: 'Device\nname' }, '1.0.0'],
    [{}, 'invalid'],
  ] as const) {
    const value = { ...resetInput(), ...patch };
    assert.throws(() => consumeSharedAccountResetInput(value, version));
    assert.ok(
      [value.code, value.password, value.ask].every((bytes) => bytes.every((b) => b === 0)),
    );
  }
  const overlap = new Uint8Array(32).fill(3);
  const result = consumeSharedAccountResetInput(
    {
      ...resetInput(),
      code: overlap.subarray(0, 16),
      ask: overlap,
      password: overlap.subarray(1, 4),
    },
    '1.0.0',
  );
  assert.ok(
    [result.code, result.ask, result.password].every((bytes) => bytes.every((b) => b === 3)),
  );
  assert.ok(overlap.every((b) => b === 0));
  const value = resetInput();
  const client = new VaultBackendClient({ executable: 'native', databasePath: 'db' }, () =>
    assert.fail('relative reset path started the backend'),
  );
  await assert.rejects(client.sharedRedeemAccountReset('relative.whreset', value, '1.0.0'));
  assert.ok([value.code, value.password, value.ask].every((bytes) => bytes.every((b) => b === 0)));
});

test('enrollment resume host binds the pending device, reserves authentication and activates only native verified policy', async () => {
  for (const mode of [
    'success',
    'continuation',
    'awaiting-activation',
    'awaiting-after-navigation',
    'capacity',
    'capacity-after-navigation',
    'capacity-during-stop',
    'ordinary',
    'slot',
    'native-error',
    'runtime-id',
    'late',
    'duplicate',
    'activation-error',
  ]) {
    let allowed = true,
      activations = 0,
      stops = 0,
      release!: () => void;
    const client: any = {
      startup: async () =>
        mode === 'ordinary'
          ? { ...metadata(), sharedJoin: undefined, shared: metadata().sharedJoin }
          : mode === 'continuation'
            ? { ...metadata(), sharedJoin: { ...metadata().sharedJoin, canContinue: true } }
            : metadata(),
      sharedContinueEnrollment: async (value: any) => {
        assert.ok(value.code.every((n: number) => n === 7));
        assert.equal(value.acknowledgeTLSOff, true);
        return { admitted: true, lockedMemory: true, orgEscrow: true };
      },
      sharedRecoverEnrollment: async () => {
        if (mode === 'capacity-after-navigation') allowed = false;
        if (mode.startsWith('capacity')) throw new SharedConnectionLimit();
        if (mode === 'awaiting-after-navigation') allowed = false;
        if (mode.startsWith('awaiting-')) throw new SharedReenrollmentPending();
        if (mode === 'native-error') throw Error('private');
        if (mode === 'late' || mode === 'duplicate')
          await new Promise<void>((yes) => {
            release = yes;
          });
        return { admitted: true, lockedMemory: true, orgEscrow: true };
      },
      sharedRuntime: async () =>
        mode === 'runtime-id' ? { ...runtime(), vaultId: slotId } : runtime(),
      lock: async () => {
        stops++;
        if (mode === 'capacity-during-stop') allowed = false;
      },
    };
    const host = new VaultBackendHost(
      () => client,
      () => true,
      (security) => {
        assert.deepEqual(security, runtime().security);
        activations++;
        if (mode === 'activation-error') throw Error('private');
      },
    );
    if (mode === 'success') {
      await host.startup();
      assert.equal(host.isSharedWorkspace, true);
      assert.equal(host.unlockedWorkspaceId, undefined);
    }
    const value = input();
    if (mode === 'slot') value.slotId = vaultId;
    const pending =
      mode === 'continuation'
        ? host.sharedContinueEnrollment(
            { ...value, code: new Uint8Array(16).fill(7), acknowledgeTLSOff: true },
            '1.0.0',
            () => allowed,
          )
        : host.sharedRecoverEnrollment(value, '1.0.0', () => allowed);
    void pending.catch(() => undefined);
    await tick();
    if (mode === 'late') {
      allowed = false;
      release();
    }
    if (mode === 'duplicate') {
      const duplicate = input();
      await assert.rejects(host.sharedRecoverEnrollment(duplicate, '1.0.0', () => true));
      assert.ok(duplicate.password.every((b) => b === 0));
      release();
    }
    if (mode === 'success' || mode === 'duplicate' || mode === 'continuation') {
      await pending;
      assert.equal(host.unlockedWorkspaceId, workspaceId);
      assert.equal(activations, 1);
    } else {
      await assert.rejects(
        pending,
        (error) =>
          error instanceof SharedReenrollmentPending === (mode === 'awaiting-activation') &&
          error instanceof SharedConnectionLimit === (mode === 'capacity'),
      );
      assert.equal(host.unlockedWorkspaceId, undefined);
      assert.equal(stops, mode === 'awaiting-activation' ? 0 : 1);
    }
    assert.ok(value.password.every((b) => b === 0) && value.ask.every((b) => b === 0));
    await host.stop();
  }
});

test('initial invitation factors are bounded, consumed on refusal and snapshot overlapping views', async () => {
  const shared = new Uint8Array(80).fill(9);
  const value = {
    ...initialInput(),
    code: shared.subarray(0, 16),
    password: shared.subarray(4, 25),
    ask: shared.subarray(0, 32),
  };
  const owned = consumeSharedInitialJoinInput(value, '1.0.0');
  assert.ok(
    owned.code.every((b) => b === 9) &&
      owned.password.every((b) => b === 9) &&
      owned.ask!.every((b) => b === 9),
  );
  assert.ok(shared.subarray(0, 32).every((b) => b === 0));
  for (const bytes of [owned.code, owned.password, owned.ask!]) bytes.fill(0);
  for (const [extra, version] of [
    [{ authority: true }, '1.0.0'],
    [{ invitation: '' }, '1.0.0'],
    [{ invitation: 'a'.repeat(maxSharedInvitationBytes + 1) }, '1.0.0'],
    [{ deviceName: '' }, '1.0.0'],
    [{ deviceName: 'bad\nname' }, '1.0.0'],
    [{ deviceName: 'a'.repeat(4097) }, '1.0.0'],
    [{ acknowledgeTLSOff: null }, '1.0.0'],
    [{ code: new Uint8Array(17) }, '1.0.0'],
    [{ password: new Uint8Array() }, '1.0.0'],
    [{ password: new Uint8Array(1025) }, '1.0.0'],
    [{ ask: new Uint8Array() }, '1.0.0'],
    [{ ask: new Uint8Array(31) }, '1.0.0'],
    [{}, 'bad-version'],
  ] as const) {
    const input: any = { ...initialInput(), ...extra };
    assert.throws(() => consumeSharedInitialJoinInput(input, version));
    for (const bytes of [input.code, input.password, input.ask])
      if (bytes instanceof Uint8Array) assert.ok(bytes.every((b) => b === 0));
  }
  const array: any = [];
  Object.assign(array, initialInput());
  assert.throws(() => consumeSharedInitialJoinInput(array, '1.0.0'));
  assert.ok(
    array.code.every((b: number) => b === 0) && array.password.every((b: number) => b === 0),
  );
  for (const input of [null, undefined, 3, 'invalid'])
    assert.throws(() => consumeSharedInitialJoinInput(input, '1.0.0'));
  const noASK: any = initialInput();
  delete noASK.ask;
  const accepted = consumeSharedInitialJoinInput(noASK, '1.0.0');
  assert.equal(accepted.ask, undefined);
  accepted.code.fill(0);
  accepted.password.fill(0);
  const client = new VaultBackendClient({ executable: 'native', databasePath: 'db' }, () =>
    assert.fail('invalid input started native'),
  );
  await assert.rejects(client.sharedJoinInitial(null, '1.0.0'));
  await client.lock();
});

test('initial invitation host reserves a fresh workspace and activates only completed native identity and policy', async () => {
  for (const mode of [
    'success',
    'reset-success',
    'reset-awaiting',
    'capacity',
    'existing',
    'native-error',
    'incomplete',
    'runtime-id',
    'late',
    'runtime-late',
    'duplicate',
    'activation-error',
    'activation-late',
    'denied',
    'replaced',
  ]) {
    let allowed = mode !== 'denied',
      activations = 0,
      stops = 0,
      starts = 0,
      reads = 0;
    let release!: () => void;
    const fresh = () => ({
      slots: null,
      cosmetics: { theme: 'system' },
      newWorkspace: true,
      unprotectedAllowed: true,
    });
    const completed = () => {
      const { sharedJoin, ...rest } = metadata();
      return { ...rest, shared: sharedJoin };
    };
    const client: any = {
      startup: async () => {
        reads++;
        if (reads === 1) return mode === 'existing' ? metadata() : fresh();
        return mode === 'incomplete' ? metadata() : completed();
      },
      sharedJoinInitial: async (value: any, version: string) => {
        starts++;
        assert.equal(version, '1.0.0');
        assert.equal(value.code[0], 7);
        if (mode === 'capacity') throw new SharedConnectionLimit();
        if (mode === 'native-error') throw Error('private');
        if (['late', 'duplicate', 'replaced'].includes(mode))
          await new Promise<void>((yes) => {
            release = yes;
          });
        return { admitted: true, lockedMemory: true, orgEscrow: true };
      },
      sharedRedeemAccountReset: async (path: string, value: any, version: string) => {
        assert.equal(path, resetPath);
        if (mode === 'reset-awaiting') {
          starts++;
          throw new SharedReenrollmentPending();
        }
        return client.sharedJoinInitial(value, version);
      },
      sharedRuntime: async () => {
        if (mode === 'runtime-late') allowed = false;
        return mode === 'runtime-id' ? { ...runtime(), vaultId: slotId } : runtime();
      },
      lock: async () => {
        stops++;
      },
    };
    const host = new VaultBackendHost(
      () => client,
      () => true,
      (security) => {
        assert.deepEqual(security, runtime().security);
        activations++;
        if (mode === 'activation-error') throw Error('private');
        if (mode === 'activation-late') allowed = false;
      },
    );
    const resetting = mode.startsWith('reset-');
    const value = resetting ? resetInput() : initialInput();
    const pending = resetting
      ? host.sharedRedeemAccountReset(resetPath, value, '1.0.0', () => allowed)
      : host.sharedJoinInitial(value, '1.0.0', () => allowed);
    void pending.catch(() => undefined);
    await tick();
    if (mode === 'late') {
      allowed = false;
      release();
    }
    if (mode === 'replaced') {
      await host.stop();
      release();
    }
    if (mode === 'duplicate') {
      const other = initialInput();
      await assert.rejects(host.sharedJoinInitial(other, '1.0.0', () => true));
      assert.ok(other.code.every((b) => b === 0) && other.password.every((b) => b === 0));
      await assert.rejects(host.sharedRecoverEnrollment(input(), '1.0.0', () => true));
      release();
    }
    if (mode === 'success' || mode === 'duplicate' || mode === 'reset-success') {
      assert.deepEqual(await pending, {
        admitted: true,
        lockedMemory: true,
        orgEscrow: true,
        tls: 'off',
      });
      assert.equal(host.unlockedWorkspaceId, workspaceId);
      assert.equal(host.isSharedWorkspace, true);
      assert.equal(activations, 1);
      assert.equal(starts, 1);
    } else {
      await assert.rejects(
        pending,
        (error) =>
          error instanceof SharedReenrollmentPending === (mode === 'reset-awaiting') &&
          error instanceof SharedConnectionLimit === (mode === 'capacity'),
      );
      assert.equal(host.unlockedWorkspaceId, undefined);
      assert.equal(stops, ['denied', 'reset-awaiting'].includes(mode) ? 0 : 1);
      assert.equal(starts, ['denied', 'existing'].includes(mode) ? 0 : 1);
    }
    assert.ok(
      value.code.every((b) => b === 0) &&
        value.password.every((b) => b === 0) &&
        value.ask.every((b) => b === 0),
    );
    await host.stop();
  }
});

const invitationInfo = () => ({
  invitation: 'WHINV2-public',
  workspaceId,
  loginName: 'alice',
  tls: 'verified' as const,
});

test('invitation hints remain a bounded public shape and cannot grant workspace authority', () => {
  assert.deepEqual(parseSharedInvitation(invitationInfo()), invitationInfo());
  const signed = { ...invitationInfo(), invitation: 'WHINV3-public' };
  assert.deepEqual(parseSharedInvitation(signed), signed);
  for (const extra of [
    { authority: true },
    { invitation: '' },
    { invitation: 'WHINV1-public' },
    { invitation: 'WHINV4-public' },
    { workspaceId: '' },
    { workspaceId: '00000000-0000-0000-0000-000000000000' },
    { loginName: '' },
    { loginName: 'a'.repeat(257) },
    { loginName: 'bad\nlogin' },
    { tls: 'prefer' },
  ])
    assert.equal(parseSharedInvitation({ ...invitationInfo(), ...extra }), undefined);
  for (const value of [
    null,
    [],
    2,
    {},
    { invitation: 'WHINV2-public', workspaceId, loginName: 'alice', role: 'administrator' },
  ])
    assert.equal(parseSharedInvitation(value), undefined);
  for (const value of [
    null,
    '',
    'x'.repeat(maxSharedInvitationBytes + 1),
    'é'.repeat(maxSharedInvitationBytes / 2 + 1),
  ])
    assert.equal(validSharedInvitationText(value), false);
  const fresh: any = { slots: null, cosmetics: { theme: 'system' }, newWorkspace: true };
  assert.equal(isSharedInitialStartup(fresh), true);
  for (const key of [
    'shared',
    'sharedJoin',
    'legacy',
    'osMigration',
    'migration',
    'rotation',
    'upgrade',
    'unprotected',
  ])
    assert.equal(isSharedInitialStartup({ ...fresh, [key]: {} }), false);
});

test('public invitation Client methods send only the fixed typed metadata operations', async () => {
  const child: any = new EventEmitter();
  Object.assign(child, {
    pid: process.pid,
    exitCode: null,
    signalCode: null,
    stdout: new PassThrough(),
    stderr: new PassThrough(),
  });
  const requests: any[] = [];
  let response = invitationInfo();
  child.stdin = new Writable({
    write(chunk, _encoding, done) {
      const request = JSON.parse(chunk.toString());
      if (request.operation !== 'lock') {
        requests.push(request);
        child.stdout.write(JSON.stringify({ version: 1, id: request.id, result: response }) + '\n');
      }
      done();
    },
  });
  child.stdin.on('finish', () => {
    child.exitCode = 0;
    child.emit('exit', 0, null);
    child.stdout.end();
    child.stderr.end();
    child.emit('close', 0, null);
  });
  child.kill = () => {
    child.stdin.end();
    return true;
  };
  const client = new VaultBackendClient({ executable: 'native', databasePath: 'db' }, () => {
    queueMicrotask(() => child.emit('spawn'));
    return child;
  });
  await assert.rejects(client.inspectSharedInvitation(''));
  await assert.rejects(client.readSharedInvitationFile(''));
  await assert.rejects(client.readSharedInvitationFile('bad\0path'));
  assert.deepEqual(await client.inspectSharedInvitation('WHINV2-public'), invitationInfo());
  assert.deepEqual(await client.readSharedInvitationFile('C:\\selected.whinv'), invitationInfo());
  assert.deepEqual(
    requests.map((r) => [r.operation, r.payload]),
    [
      ['shared-invitation-inspect', { invitation: 'WHINV2-public' }],
      ['shared-invitation-file', { path: 'C:\\selected.whinv' }],
    ],
  );
  // Verified TLS can carry a CA bundle up to 256 KiB; a valid public token
  // therefore exceeds the generic 64 KiB metadata response limit.
  response = { ...invitationInfo(), invitation: 'WHINV2-' + 'a'.repeat(96 * 1024) };
  assert.deepEqual(await client.inspectSharedInvitation(response.invitation), response);
  assert.deepEqual(await client.readSharedInvitationFile('C:\\selected.whinv'), response);
  response = { ...response, invitation: 'WHINV2-' + 'a'.repeat(maxSharedInvitationBytes) };
  await assert.rejects(client.readSharedInvitationFile('C:\\selected.whinv'));
  await client.lock();
});

test('invitation Host reads require a fresh current selection and reject a replaced document', async () => {
  for (const mode of ['inspect', 'file', 'existing', 'denied', 'late', 'error', 'bad-text']) {
    let allowed = mode !== 'denied',
      reads = 0;
    const client: any = {
      startup: async () =>
        mode === 'existing'
          ? metadata()
          : { slots: null, cosmetics: { theme: 'system' }, newWorkspace: true },
      inspectSharedInvitation: async () => {
        reads++;
        if (mode === 'error') throw Error('private');
        if (mode === 'late') allowed = false;
        return invitationInfo();
      },
      readSharedInvitationFile: async () => {
        reads++;
        return invitationInfo();
      },
      lock: async () => {},
    };
    const host = new VaultBackendHost(
      () => client,
      () => true,
    );
    const request =
      mode === 'file'
        ? host.readSharedInvitationFile('C:\\selected.whinv', () => allowed)
        : host.inspectSharedInvitation(mode === 'bad-text' ? '' : 'WHINV2-public', () => allowed);
    if (mode === 'inspect' || mode === 'file') assert.deepEqual(await request, invitationInfo());
    else await assert.rejects(request);
    assert.equal(host.unlockedWorkspaceId, undefined);
    assert.equal(reads, ['denied', 'existing', 'bad-text'].includes(mode) ? 0 : 1);
    await host.stop();
  }
});

test('enrollment resume and initial invitation methods meet measured coverage', async (t) => {
  if (external) return;
  try {
    const report = await profiler.post('Profiler.takePreciseCoverage');
    for (const file of ['vault-client.ts', 'vault-host.ts']) {
      for (const method of [
        'sharedRecoverEnrollment',
        'sharedContinueEnrollment',
        'sharedJoinInitial',
        'sharedRedeemAccountReset',
        'inspectSharedInvitation',
        'readSharedInvitationFile',
      ]) {
        const ranges = report.result
          .filter((s) => s.url.endsWith('/' + file))
          .flatMap((s) => s.functions)
          .filter((f) => f.functionName === method)
          .flatMap((f) => f.ranges);
        assert.ok(ranges.length, file);
        const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
        t.diagnostic(file + ' ' + method + ': ' + percent.toFixed(2) + '% V8 blocks');
        assert.ok(percent >= coverageThreshold, file);
      }
    }
    const ranges = report.result
      .filter((s) => s.url.endsWith('/vault-shared-initial-join.ts'))
      .flatMap((s) => s.functions)
      .filter((f) => f.functionName)
      .flatMap((f) => f.ranges);
    assert.ok(ranges.length);
    const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
    t.diagnostic('vault-shared-initial-join.ts: ' + percent.toFixed(2) + '% V8 blocks');
    assert.ok(percent >= coverageThreshold);
    const resetRanges = report.result
      .filter((s) => s.url.endsWith('/vault-shared-account-reset.ts'))
      .flatMap((s) => s.functions)
      .filter((f) => f.functionName)
      .flatMap((f) => f.ranges);
    const resetPercent = (100 * resetRanges.filter((r) => r.count > 0).length) / resetRanges.length;
    t.diagnostic('vault-shared-account-reset.ts: ' + resetPercent.toFixed(2) + '% V8 blocks');
    assert.ok(resetPercent >= coverageThreshold);
    const publicRanges = report.result
      .filter((s) => s.url.endsWith('/vault-shared-invitation.ts'))
      .flatMap((s) => s.functions)
      .filter((f) => f.functionName)
      .flatMap((f) => f.ranges);
    const publicPercent =
      (100 * publicRanges.filter((r) => r.count > 0).length) / publicRanges.length;
    t.diagnostic('vault-shared-invitation.ts: ' + publicPercent.toFixed(2) + '% V8 blocks');
    assert.ok(publicPercent >= coverageThreshold);
  } finally {
    profiler.disconnect();
  }
});
