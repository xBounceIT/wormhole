import assert from 'node:assert/strict';
import test from 'node:test';
import { Session } from 'node:inspector/promises';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { VaultBackendHost } from '../electron/vault-host.ts';
import { VaultBackendClient } from '../electron/vault-client.ts';
import { registerVaultOSMigrationIpc } from '../electron/vault-os-migration-ipc.ts';
import { parseVaultStartup } from '../electron/vault-contract.ts';
import { prepareVaultMigrationBoot } from '../electron/vault-migration-boot.ts';
import { coverageThreshold } from '../scripts/test-coverage.ts';
import { consumeOSMigrationPrepare } from '../electron/vault-os-migration-contract.ts';
const profiler = new Session(),
  external =
    process.execArgv.includes('--experimental-test-coverage') || !!process.env.NODE_V8_COVERAGE;
if (!external) {
  profiler.connect();
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
}
const id = '11111111-1111-4111-8111-111111111111',
  other = '22222222-2222-4222-8222-222222222222';
const startup = {
  slots: null,
  newWorkspace: false,
  cosmetics: { theme: 'system' },
  osMigration: { vaultId: id },
};
const proof = { unlocked: true, lockedMemory: true, vaultId: id };
const tick = () => new Promise(setImmediate);
function deferred() {
  let resolve!: (value: any) => void;
  const promise = new Promise<any>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}

test('OS migration hints are exclusive and require isolated Chromium before readiness', () => {
  assert.deepEqual(parseVaultStartup(startup), startup);
  for (const extra of [
    { slots: {} },
    { newWorkspace: true },
    { migration: { pending: true } },
    { rotation: { pending: true } },
    { unprotected: { vaultId: id } },
    { upgrade: { vaultId: id } },
    { shared: {} },
    { legacy: { unprotectedAllowed: true } },
    { osMigration: { vaultId: id, trusted: true } },
    { osMigration: { vaultId: 'invalid' } },
  ])
    assert.equal(parseVaultStartup({ ...startup, ...extra }), undefined);
  const calls: string[] = [];
  const app: any = {
    isReady: () => false,
    requestSingleInstanceLock: () => true,
    getPath: () => 'original',
    setPath: (name: string, path: string) => calls.push(name + ':' + path),
  };
  assert.equal(
    prepareVaultMigrationBoot({
      app,
      executable: () => 'native',
      databasePath: 'db',
      probe: () => ({ status: 0, stdout: JSON.stringify(startup) }),
      createSessionData: () => 'isolated',
    }).migrationSessionData,
    'isolated',
  );
  assert.deepEqual(calls, ['userData:isolated', 'sessionData:isolated']);
});

test('OS resume transport sends no authority fields and requires maintenance launch', async () => {
  const denied = new VaultBackendClient({ executable: 'never-start', databasePath: 'db' });
  await assert.rejects(denied.resumeOSMigration());
  await denied.lock();
  for (const invalid of [false, true]) {
    const child: any = new EventEmitter();
    child.pid = process.pid;
    child.exitCode = null;
    child.signalCode = null;
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.stdin = new Writable({
      write(chunk, _encoding, callback) {
        const request = JSON.parse(chunk.toString());
        assert.equal(request.payload, undefined);
        if (request.operation !== 'lock') {
          assert.equal(request.operation, 'migration-os-resume');
          child.stdout.write(
            JSON.stringify({
              version: 1,
              id: request.id,
              result: invalid ? { ...proof, mode: 'default' } : proof,
            }) + '\n',
          );
        }
        callback();
      },
    });
    child.stdin.on('finish', () => {
      child.exitCode = 0;
      child.emit('exit', 0, null);
      child.stdout.end();
      child.stderr.end();
      child.emit('close', 0, null);
    });
    const client = new VaultBackendClient(
      { executable: 'native', databasePath: 'db', migrationSessionData: 'isolated' },
      () => {
        queueMicrotask(() => child.emit('spawn'));
        return child;
      },
    );
    try {
      if (invalid) await assert.rejects(client.resumeOSMigration());
      else assert.deepEqual(await client.resumeOSMigration(), proof);
    } finally {
      await client.lock();
    }
  }
});

test('OS resume host binds native owner identity, reserves admission and retires stale attempts', async () => {
  const locked = new VaultBackendHost(
    () => ({}) as any,
    () => true,
  );
  await assert.rejects(locked.resumeOSMigration());
  for (const mode of [
    '',
    'wrong-hint',
    'wrong-proof',
    'native-error',
    'security-error',
    'late',
    'disabled',
  ]) {
    let stops = 0,
      active = 0,
      allowed = true,
      calls = 0;
    const wait = deferred(),
      client: any = {
        startup: async () => {
          calls++;
          return mode === 'wrong-hint' && calls > 1
            ? { ...startup, osMigration: { vaultId: other } }
            : startup;
        },
        resumeOSMigration: async () => {
          if (mode === 'native-error') throw Error('private');
          if (mode === 'late') await wait.promise;
          return mode === 'wrong-proof' ? { ...proof, vaultId: other } : proof;
        },
        security: async () => {
          if (mode === 'security-error') throw Error('private');
          return {
            sequence: '1',
            workspace: 'default',
            user: 'default',
            os: 'default',
            effective: 'default',
            source: 'workspace',
          };
        },
        lock: async () => {
          stops++;
        },
      };
    const host = new VaultBackendHost(
      () => client,
      () => allowed,
      () => active++,
    );
    await host.startup();
    assert.equal(host.unlockedWorkspaceId, undefined);
    if (mode === 'disabled') allowed = false;
    const pending = host.resumeOSMigration();
    if (mode === 'late') {
      await tick();
      await assert.rejects(host.resumeOSMigration());
      await host.stop();
      wait.resolve(true);
    }
    if (!mode) {
      assert.deepEqual(await pending, proof);
      assert.equal(host.unlockedWorkspaceId, id);
      assert.equal(active, 1);
      await assert.rejects(host.resumeOSMigration());
    } else {
      await assert.rejects(pending);
      assert.equal(host.unlockedWorkspaceId, undefined);
      assert.equal(active, 0);
    }
    await host.stop();
    assert.ok(stops > 0);
  }
});

function ipcFixture(mode = '') {
  let handler: any,
    owner: string | undefined,
    trusted = true;
  const calls: string[] = [],
    wait = deferred();
  registerVaultOSMigrationIpc({
    ipc: {
      handle: (name: string, fn: any) => {
        assert.equal(name, 'vault:os-migration-resume');
        handler = fn;
      },
    } as any,
    host: {
      get unlockedWorkspaceId() {
        return owner;
      },
      resumeOSMigration: async () => {
        calls.push('resume');
        if (mode === 'deferred') await wait.promise;
        if (mode === 'native-error' || mode === 'stop-error') throw Error('private');
        owner = id;
        if (mode === 'late-trust') trusted = false;
        return proof;
      },
      stop: async () => {
        calls.push('stop');
        if (mode === 'stop-error') throw Error('private');
        owner = undefined;
      },
    },
    trusted: () => {
      if (mode === 'trust-error') throw Error('private');
      return trusted && mode !== 'untrusted';
    },
    quiesced: () => mode !== 'ordinary',
    activate: () => {
      calls.push('activate');
      if (mode === 'activate-error') throw Error('private');
    },
    retire: async () => {
      calls.push('retire');
    },
    fatal: () => {
      calls.push('fatal');
    },
  });
  return { calls, wait, call: (...args: any[]) => handler({}, ...args) };
}
test('OS resume IPC does not activate from stale, ordinary or uncertain ownership', async () => {
  for (const mode of [
    '',
    'native-error',
    'stop-error',
    'late-trust',
    'untrusted',
    'ordinary',
    'trust-error',
    'activate-error',
  ]) {
    const f = ipcFixture(mode);
    if (!mode) {
      assert.equal(await f.call(), true);
      assert.deepEqual(f.calls, ['resume', 'activate']);
    } else {
      await assert.rejects(f.call(), /^Error: Migration unavailable\.$/);
      assert.equal(f.calls.includes('fatal'), mode === 'stop-error');
    }
    await assert.rejects(f.call({ quiesced: true }));
  }
  const f = ipcFixture('deferred'),
    pending = f.call();
  await tick();
  await assert.rejects(f.call());
  f.wait.resolve(true);
  await pending;
});

test('legacy preparation consumes only the selected old factor and rejects malformed or extra authority', () => {
  for (const method of ['none', 'pin', 'password']) {
    const input = {
        legacyMethod: method,
        legacyFactor: method === 'none' ? new Uint8Array() : new Uint8Array([1, 2]),
      },
      owned = consumeOSMigrationPrepare(input);
    assert.equal(owned.legacyMethod, method);
    assert.notEqual(owned.legacyFactor, input.legacyFactor);
    assert.ok(input.legacyFactor.every((b) => b === 0));
    owned.legacyFactor.fill(0);
  }
  for (const value of [
    null,
    {},
    { legacyMethod: 'other', legacyFactor: new Uint8Array([1]) },
    { legacyMethod: 'none', legacyFactor: new Uint8Array([1]) },
    { legacyMethod: 'pin', legacyFactor: new Uint8Array() },
    { legacyMethod: 'password', legacyFactor: new Uint8Array(1025) },
    { legacyMethod: 'pin', legacyFactor: new Uint8Array([1]), source: 'caller' },
  ]) {
    assert.throws(() => consumeOSMigrationPrepare(value));
    if (value && 'legacyFactor' in value) assert.ok(value.legacyFactor.every((b) => b === 0));
  }
});

test('typed legacy prepare transports old proof through a consumed stdin frame without new-password fields', async () => {
  const child: any = new EventEmitter(),
    frames: Buffer[] = [],
    requests: any[] = [];
  child.pid = process.pid;
  child.exitCode = null;
  child.signalCode = null;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.stdin = new Writable({
    write(chunk, _encoding, callback) {
      frames.push(chunk);
      const request = JSON.parse(chunk.toString());
      requests.push(request);
      const result =
        request.operation === 'migration-os-context'
          ? { methods: ['pin'] }
          : { prepared: true, restartRequired: true, vaultId: id };
      if (request.operation !== 'lock')
        child.stdout.write(JSON.stringify({ version: 1, id: request.id, result }) + '\n');
      callback();
    },
  });
  child.stdin.on('finish', () => {
    child.exitCode = 0;
    child.emit('exit', 0, null);
    child.stdout.end();
    child.stderr.end();
    child.emit('close', 0, null);
  });
  const client = new VaultBackendClient({ executable: 'native', databasePath: 'db' }, () => {
    queueMicrotask(() => child.emit('spawn'));
    return child;
  });
  try {
    assert.deepEqual(await client.osMigrationContext(), { methods: ['pin'] });
    const input = { legacyMethod: 'pin', legacyFactor: new Uint8Array([2, 4, 6, 8]) };
    assert.equal((await client.prepareOSMigration(input)).vaultId, id);
    assert.ok(input.legacyFactor.every((b) => b === 0));
    const request = requests.find((r) => r.operation === 'migration-os-prepare');
    assert.deepEqual(Object.keys(request.payload).sort(), ['legacyFactor', 'legacyMethod']);
    assert.equal(request.payload.legacyMethod, 'pin');
    await tick();
    assert.ok(frames[requests.indexOf(request)].every((b) => b === 0));
    await assert.rejects(client.prepareOSMigration(null));
  } finally {
    await client.lock();
  }
});

test('OS preparation host reserves a single native attempt, binds completion and never admits an owner', async () => {
  const input = () => ({ legacyMethod: 'pin', legacyFactor: new Uint8Array([1, 2, 3]) });
  for (const mode of [
    '',
    'context-error',
    'context-late',
    'native-error',
    'late',
    'disabled',
    'busy',
    'selected',
  ]) {
    let allowed = true,
      stops = 0,
      contextCalls = 0,
      prepareCalls = 0;
    const wait = deferred(),
      client: any = {
        startup: async () => startup,
        osMigrationContext: async () => {
          contextCalls++;
          if (mode === 'context-error') throw Error('private');
          if (mode === 'context-late') await wait.promise;
          return { methods: ['pin'] };
        },
        prepareOSMigration: async () => {
          prepareCalls++;
          if (mode === 'native-error') throw Error('private');
          if (mode === 'late' || mode === 'busy') await wait.promise;
          return { prepared: true, restartRequired: true, vaultId: id };
        },
        lock: async () => {
          stops++;
        },
      },
      host = new VaultBackendHost(
        () => client,
        () => allowed,
      );
    if (mode === 'context-late') {
      const pending = host.osMigrationContext();
      await host.stop();
      wait.resolve(undefined);
      await assert.rejects(pending);
    } else if (mode === 'context-error') await assert.rejects(host.osMigrationContext());
    else if (mode === 'selected') {
      await host.startup();
      const value = input();
      await assert.rejects(host.osMigrationContext());
      await assert.rejects(host.prepareOSMigration(value));
      assert.ok(value.legacyFactor.every((b) => b === 0));
      assert.equal(prepareCalls, 0);
    } else {
      assert.deepEqual(await host.osMigrationContext(), { methods: ['pin'] });
      if (mode === 'disabled') allowed = false;
      const value = input(),
        pending = host.prepareOSMigration(value);
      if (mode === 'late') {
        await host.stop();
        wait.resolve(undefined);
      } else if (mode === 'busy') {
        await assert.rejects(host.osMigrationContext());
        const duplicate = input();
        await assert.rejects(host.prepareOSMigration(duplicate));
        assert.ok(duplicate.legacyFactor.every((b) => b === 0));
        wait.resolve(undefined);
      }
      if (['disabled', 'native-error', 'late'].includes(mode)) await assert.rejects(pending);
      else {
        assert.equal((await pending).vaultId, id);
        assert.equal(host.isVaultWorkspace, true);
        await assert.rejects(host.prepareOSMigration(input()));
      }
      assert.ok(value.legacyFactor.every((b) => b === 0));
      assert.equal(contextCalls, 1);
    }
    assert.equal(host.unlockedWorkspaceId, undefined);
    allowed = true;
    await host.stop();
    assert.ok(stops <= 1);
  }
});

test('OS resume modules meet measured coverage', async (t) => {
  if (external) return;
  try {
    const result = await profiler.post('Profiler.takePreciseCoverage');
    for (const file of [
      'vault-os-migration-ipc.ts',
      'vault-os-migration-contract.ts',
      'vault-host.ts',
      'vault-client.ts',
    ]) {
      const functions = result.result
        .filter((s) => s.url.endsWith('/' + file))
        .flatMap((s) => s.functions)
        .filter(
          (f) =>
            file.startsWith('vault-os-migration-') ||
            ['resumeOSMigration', 'osMigrationContext', 'prepareOSMigration'].includes(
              f.functionName,
            ),
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
