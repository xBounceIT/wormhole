import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, mkdirSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { prepareVaultMigrationBoot } from '../electron/vault-migration-boot.ts';

const pending = {
  slots: {
    formatVersion: 1,
    vaultId: '11111111-1111-4111-8111-111111111111',
    encrypted: false,
    slots: [{ id: '22222222-2222-4222-8222-222222222222', kind: 'recovery' }],
  },
  cosmetics: { theme: 'system' },
  newWorkspace: false,
  migration: { pending: true },
};
function fixture(stdout = JSON.stringify(pending)) {
  const calls: unknown[] = [];
  const app: any = {
    isReady: () => false,
    requestSingleInstanceLock: () => true,
    getPath: (name: string) => {
      calls.push(['get', name]);
      return 'original';
    },
    setPath: (...args: unknown[]) => calls.push(['set', ...args]),
  };
  const options = {
    app,
    executable: () => 'native-executable',
    databasePath: 'native-database',
    probe: (exe: string, args: string[]) => {
      calls.push(['probe', exe, args]);
      return { status: 0, stdout };
    },
    createSessionData: (original: string) => {
      calls.push(['create', original]);
      return 'isolated';
    },
  };
  return { app, options, calls };
}

test('native startup probe isolates pending Chromium storage before readiness and preserves userData', () => {
  const { options, calls } = fixture();
  assert.deepEqual(prepareVaultMigrationBoot(options), {
    primary: true,
    unavailable: false,
    migrationSessionData: 'isolated',
  });
  assert.deepEqual(calls, [
    [
      'probe',
      'native-executable',
      ['--operation', 'vault-startup', '--database', 'native-database'],
    ],
    ['get', 'userData'],
    ['create', 'original'],
    ['set', 'userData', 'isolated'],
    ['set', 'sessionData', 'isolated'],
  ]);
  const normal = fixture(
    JSON.stringify({ slots: null, cosmetics: { theme: 'dark' }, newWorkspace: true }),
  );
  assert.deepEqual(prepareVaultMigrationBoot(normal.options), {
    primary: true,
    unavailable: false,
  });
  assert.equal(normal.calls.length, 1);
});

test('secondary instances and late boot cannot open Chromium or assert migration authority', () => {
  const f = fixture();
  f.app.requestSingleInstanceLock = () => false;
  assert.deepEqual(prepareVaultMigrationBoot(f.options), { primary: false, unavailable: false });
  assert.equal(f.calls.length, 0);
  f.app.isReady = () => true;
  assert.throws(() => prepareVaultMigrationBoot(f.options), /readiness/);
  assert.equal(f.calls.length, 0);
});

test('only a Default-permitted legacy startup opts into early crash capture', () => {
  for (const unprotectedAllowed of [true, false]) {
    const f = fixture(
      JSON.stringify({
        slots: null,
        cosmetics: { theme: 'dark' },
        newWorkspace: false,
        legacy: { unprotectedAllowed },
      }),
    );
    assert.deepEqual(prepareVaultMigrationBoot(f.options), {
      primary: true,
      unavailable: false,
      legacyMigrationRequired: true,
      ...(unprotectedAllowed ? { legacyLocalCrashCapture: true } : {}),
    });
  }
});

test('ownerless OS upgrade isolates Chromium before readiness without granting an app owner', () => {
  const f = fixture(
    JSON.stringify({
      slots: null,
      cosmetics: { theme: 'system' },
      newWorkspace: false,
      upgrade: { vaultId: pending.slots.vaultId },
    }),
  );
  assert.equal(prepareVaultMigrationBoot(f.options).migrationSessionData, 'isolated');
  assert.ok(f.calls.some((c) => Array.isArray(c) && c[0] === 'set' && c[1] === 'sessionData'));
});

test('root rotation uses an isolated native restart without entering the original Chromium profile', () => {
  const { migration: _migration, ...base } = pending;
  const f = fixture(
    JSON.stringify({
      ...base,
      slots: { ...base.slots, formatVersion: 3 },
      rotation: { pending: true },
    }),
  );
  assert.deepEqual(prepareVaultMigrationBoot(f.options), {
    primary: true,
    unavailable: false,
    migrationSessionData: 'isolated',
  });
  assert.ok(
    f.calls.some(
      (call) => JSON.stringify(call) === JSON.stringify(['set', 'sessionData', 'isolated']),
    ),
  );
});

test('unreadable or malformed native metadata isolates storage but never grants quiescence', () => {
  for (const mode of ['status', 'error', 'throw', 'exe', 'json', 'shape', 'oversize']) {
    const f = fixture();
    if (mode === 'exe')
      f.options.executable = () => {
        throw Error('private native path');
      };
    f.options.probe = () => {
      if (mode === 'throw') throw Error('private diagnostic');
      return {
        status: mode === 'status' ? 1 : 0,
        error: mode === 'error' ? Error('private') : undefined,
        stdout:
          mode === 'json'
            ? 'not JSON'
            : mode === 'shape'
              ? '{}'
              : mode === 'oversize'
                ? ' '.repeat(65537)
                : JSON.stringify(pending),
      };
    };
    assert.deepEqual(prepareVaultMigrationBoot(f.options), { primary: true, unavailable: true });
    assert.deepEqual(f.calls.at(-1), ['set', 'sessionData', 'isolated']);
  }
  for (const mode of ['create', 'set']) {
    const f = fixture();
    if (mode === 'create')
      f.options.createSessionData = () => {
        throw Error('failed temp directory');
      };
    else
      f.app.setPath = () => {
        throw Error('already initialized');
      };
    assert.throws(() => prepareVaultMigrationBoot(f.options));
  }
});

test('only the stable native installation error identifies a location failure', () => {
  const blocked = {
    status: 1,
    stdout: '',
    stderr: 'vault_installation_location_untrusted\r\n',
  };
  const { options, calls } = fixture();
  assert.deepEqual(prepareVaultMigrationBoot({ ...options, probe: () => blocked }), {
    primary: true,
    unavailable: true,
    unsafeInstallation: true,
  });
  assert.deepEqual(calls.at(-1), ['set', 'sessionData', 'isolated']);
  assert.deepEqual(
    prepareVaultMigrationBoot({
      ...options,
      probe: () => ({ ...blocked, stderr: 'vault_installation_signature_untrusted\n' }),
    }),
    { primary: true, unavailable: true, unsafeInstallation: true },
  );
  for (const invalid of [
    { ...blocked, stderr: 'diagnostic: vault_installation_location_untrusted' },
    { ...blocked, status: 0 },
    { ...blocked, error: Error('process failed') },
  ]) {
    assert.deepEqual(prepareVaultMigrationBoot({ ...options, probe: () => invalid }), {
      primary: true,
      unavailable: true,
    });
  }
});

test('default isolation creates a native sibling without entering the original profile', () => {
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-boot-fixture-'));
  const original = join(directory, 'original');
  mkdirSync(original);
  try {
    const f = fixture();
    f.app.getPath = () => original;
    const result = prepareVaultMigrationBoot({ ...f.options, createSessionData: undefined });
    assert.equal(dirname(result.migrationSessionData!), realpathSync(directory));
    assert.equal(
      result.migrationSessionData!.startsWith(
        join(realpathSync(directory), '.wormhole-vault-migration-'),
      ),
      true,
    );
    assert.equal(result.unavailable, false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('a missing native component fails closed through the actual process probe', () => {
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-boot-missing-'));
  const original = join(directory, 'original');
  mkdirSync(original);
  try {
    const f = fixture();
    f.app.getPath = () => original;
    const result = prepareVaultMigrationBoot({
      ...f.options,
      probe: undefined,
      createSessionData: undefined,
      executable: () => join(directory, 'missing-native-component.exe'),
    });
    assert.deepEqual(result, { primary: true, unavailable: true });
    assert.equal((f.calls.at(-1) as string[])[1], 'sessionData');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
