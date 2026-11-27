import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import { ipcRegistration } from './fixtures/main-source.ts';
import { parseVaultSecurity } from '../electron/vault-security.ts';
import { parseSharedVaultRuntime } from '../electron/vault-shared-runtime.ts';

const base = {
  sequence: '1',
  workspace: 'default',
  user: 'default',
  os: 'default',
  effective: 'default',
  source: 'workspace',
};

test('profile status IPC only reads the monitor for a trusted unlocked vault', () => {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  let read!: (sender: unknown, ...args: unknown[]) => unknown;
  const owner = {};
  const status = { effective: 'standard', source: 'os', retainedUntilLock: false };
  let snapshot: typeof status | undefined = status;
  let reads = 0;
  const context = {
    ipcMain: {
      handle: (_channel: string, handler: typeof read) => {
        read = handler;
      },
    },
    isTrustedVaultSender: (value: unknown) => value === owner,
    isQuitting: false,
    authLockRequested: false,
    authSession: { isAccessAllowed: true },
    vaultBackend: { unlockedWorkspaceId: 'workspace' },
    vaultLockMonitor: {
      get profileStatus() {
        reads++;
        return snapshot;
      },
    },
  };
  runInNewContext(stripTypeScriptTypes(ipcRegistration(main, 'vault:profile-status')), context);
  assert.throws(() => read({}), /Invalid/);
  assert.throws(() => read(owner, status), /Invalid/);
  for (const key of ['isQuitting', 'authLockRequested'] as const) {
    context[key] = true;
    assert.throws(() => read(owner), /unavailable/);
    context[key] = false;
  }
  context.authSession.isAccessAllowed = false;
  assert.throws(() => read(owner), /unavailable/);
  context.authSession.isAccessAllowed = true;
  context.vaultBackend.unlockedWorkspaceId = '';
  assert.throws(() => read(owner), /unavailable/);
  assert.equal(reads, 0);
  context.vaultBackend.unlockedWorkspaceId = 'workspace';
  assert.deepEqual(read(owner), status);
  snapshot = undefined;
  assert.throws(() => read(owner), /unavailable/);
});

test('changing a local or shared profile accepts only the current trusted window and a protected prompt', async () => {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const parent = {},
    owner = { sender: {} },
    descriptor = { vaultId: 'fixture' };
  let handler!: (sender: unknown, ...args: unknown[]) => Promise<void>;
  let hasParent = true,
    calls = 0,
    locks = 0;
  const context = {
    ipcMain: {
      handle: (_channel: string, fn: typeof handler) => {
        handler = fn;
      },
    },
    BrowserWindow: {
      fromWebContents: (sender: unknown) => (hasParent && sender === owner.sender ? parent : null),
    },
    isTrustedVaultSender: (sender: unknown) => sender === owner,
    isQuitting: false,
    authLockRequested: false,
    authSession: { isAccessAllowed: true },
    vaultBackend: {
      unlockedWorkspaceId: 'fixture',
      tightenLocalProfile: async (confirm: Function, accepted: Function, lock: Function) => {
        calls++;
        assert.equal(accepted(), true);
        await confirm('tighten-local-profile', descriptor, submit);
        await lock();
      },
      tightenSharedProfile: async (confirm: Function, accepted: Function, lock: Function) => {
        calls++;
        await confirm(descriptor, accepted, submit);
        await lock();
      },
    },
    vaultSharedDialog: {
      open: async (
        window: unknown,
        current: Function,
        mode: string,
        startup: unknown,
        callback: unknown,
      ) => {
        assert.equal(window, parent);
        assert.equal(mode, 'tighten-profile');
        assert.equal(startup, descriptor);
        assert.equal(callback, submit);
        assert.equal(current(), true);
        context.authLockRequested = true;
        assert.equal(current(), false);
        context.authLockRequested = false;
      },
    },
    vaultReauthenticationDialog: {
      open: async (
        window: unknown,
        accepted: Function,
        op: string,
        value: unknown,
        callback: unknown,
      ) => {
        assert.equal(window, parent);
        assert.equal(op, 'tighten-local-profile');
        assert.equal(value, descriptor);
        assert.equal(callback, submit);
        assert.equal(accepted(), true);
        context.vaultBackend.unlockedWorkspaceId = 'replaced';
        assert.equal(accepted(), false);
      },
    },
    lockApplication: async () => {
      locks++;
    },
  };
  const submit = async () => {};
  for (const channel of ['vault:tighten-local-profile', 'vault:tighten-shared-profile']) {
    calls = locks = 0;
    runInNewContext(stripTypeScriptTypes(ipcRegistration(main, channel)), context);
    await assert.rejects(handler({ sender: {} }), /Invalid/);
    await assert.rejects(handler(owner, 'standard'), /Invalid/);
    for (const key of ['isQuitting', 'authLockRequested'] as const) {
      context[key] = true;
      await assert.rejects(handler(owner), /Invalid/);
      context[key] = false;
    }
    context.authSession.isAccessAllowed = false;
    await assert.rejects(handler(owner), /Invalid/);
    context.authSession.isAccessAllowed = true;
    hasParent = false;
    await assert.rejects(handler(owner), /unavailable/);
    assert.equal(calls, 0);
    hasParent = true;
    await handler(owner);
    assert.deepEqual([calls, locks], [1, 1]);
  }
});

test('shared runtime validates separate identities and an exact public security projection', () => {
  const value = {
    vaultId: '11111111-1111-4111-8111-111111111111',
    workspaceId: '33333333-3333-4333-8333-333333333333',
    security: base,
    tls: 'off',
  };
  assert.deepEqual(parseSharedVaultRuntime(value), value);
  assert.notEqual(parseSharedVaultRuntime(value)?.security, base);
  assert.deepEqual(parseSharedVaultRuntime({ ...value, tls: 'verified', recoveryBackup: true }), {
    ...value,
    tls: 'verified',
    recoveryBackup: true,
  });
  for (const recoveryBackup of [false, 1, null, undefined])
    assert.equal(parseSharedVaultRuntime({ ...value, tls: 'verified', recoveryBackup }), undefined);
  assert.equal(parseSharedVaultRuntime({ ...value, recoveryBackup: true, tls: 'off' }), undefined);
  for (const bad of [
    null,
    [],
    {},
    { ...value, rootKey: 'private' },
    ...[undefined, null, '', 'prefer', 'VERIFIED', true, {}].map((tls) => ({ ...value, tls })),
    { ...value, security: { ...base, password: 'private' } },
    { ...value, security: { ...base, canTightenToStandard: true } },
    { ...value, security: { ...base, effective: 'paranoid' } },
    ...[
      '',
      1,
      null,
      'ABCDEF11-1111-4111-8111-111111111111',
      '00000000-0000-0000-0000-000000000000',
    ].flatMap((id) => [
      { ...value, vaultId: id },
      { ...value, workspaceId: id },
    ]),
  ])
    assert.equal(parseSharedVaultRuntime(bad), undefined);
  for (const tls of ['off', 'encrypted', 'verified'])
    assert.equal(parseSharedVaultRuntime({ ...value, tls })?.tls, tls);
  for (const effective of ['standard', 'hardened', 'paranoid']) {
    const security = { ...base, workspace: effective, effective };
    assert.equal(
      parseSharedVaultRuntime({ ...value, security, tls: 'verified', recoveryBackup: true })
        ?.recoveryBackup,
      effective === 'standard' ? true : undefined,
    );
    assert.equal(parseSharedVaultRuntime({ ...value, security, tls: 'verified' })?.tls, 'verified');
    for (const tls of ['off', 'encrypted'])
      assert.equal(parseSharedVaultRuntime({ ...value, security, tls }), undefined);
  }
});

test('security projection requires the strictest profile and the correct authority', () => {
  const profiles = ['default', 'standard', 'hardened', 'paranoid'];
  for (const [w, workspace] of profiles.entries())
    for (const [u, user] of profiles.entries())
      for (const [o, os] of profiles.entries()) {
        const effective = profiles[Math.max(w, u, o)]!;
        const source = o > 0 && o >= w && o >= u ? 'os' : u > w ? 'user' : 'workspace';
        const value = { ...base, workspace, user, os, effective, source };
        assert.deepEqual(parseVaultSecurity(value), value);
        assert.notEqual(parseVaultSecurity(value), value);
      }
  assert.equal(
    parseVaultSecurity({ ...base, sequence: '9223372036854775807' })?.sequence,
    '9223372036854775807',
  );
});

test('security projection rejects private members, ambiguous sequences and weakened floors', () => {
  const retained = { ...base, effective: 'standard', source: 'user', retainedUntilLock: true };
  assert.deepEqual(parseVaultSecurity(retained), retained);
  const eligible = { ...base, canTightenToStandard: true };
  assert.deepEqual(parseVaultSecurity(eligible), eligible);
  for (const value of [
    null,
    [],
    {},
    { ...base, authentication: 'private' },
    ...[null, false, undefined, 'true'].map((canTightenToStandard) => ({
      ...base,
      canTightenToStandard,
    })),
    { ...retained, canTightenToStandard: true },
    { ...base, source: 'renderer' },
    { ...base, workspace: 'future' },
    { ...base, user: null },
    { ...base, os: 'Paranoid' },
    { ...base, os: 'standard' },
    { ...base, user: 'standard', effective: 'standard' },
    { ...retained, user: 'standard' },
    { ...retained, os: 'hardened' },
    { ...retained, effective: 'unknown' },
    { ...retained, source: 'unknown' },
    { ...retained, retainedUntilLock: false },
    ...[0, '', '0', '-1', '01', '1.0', '1e1', '9223372036854775808', '1'.repeat(20)].map(
      (sequence) => ({ ...base, sequence }),
    ),
  ])
    assert.equal(parseVaultSecurity(value), undefined);
});
