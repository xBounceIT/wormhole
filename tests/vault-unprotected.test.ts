import assert from 'node:assert/strict';
import test from 'node:test';
import { Session } from 'node:inspector/promises';
import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { VaultBackendClient } from '../electron/vault-client.ts';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import { VaultBackendHost } from '../electron/vault-host.ts';
import { registerVaultUnprotectedIpc } from '../electron/vault-unprotected-ipc.ts';
import { parseVaultProtection, parseVaultStartup } from '../electron/vault-contract.ts';
import { mountUnprotectedStartup } from '../src/vault-unprotected-startup.ts';
import { prepareVaultMigrationBoot } from '../electron/vault-migration-boot.ts';
import { coverageThreshold } from '../scripts/test-coverage.ts';
const profiler = new Session();
const external =
  process.execArgv.includes('--experimental-test-coverage') || !!process.env.NODE_V8_COVERAGE;
if (!external) {
  profiler.connect();
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
}
const id = '11111111-1111-4111-8111-111111111111',
  other = '22222222-2222-4222-8222-222222222222';
const source = {
  slots: null,
  cosmetics: { theme: 'system' },
  newWorkspace: false,
  unprotected: { vaultId: id },
};
const empty = {
  slots: null,
  cosmetics: { theme: 'system' },
  newWorkspace: true,
  unprotectedAllowed: true,
};
const tick = () => new Promise(setImmediate);
function deferred() {
  let resolve!: (v: any) => void;
  const promise = new Promise<any>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}

test('OS-only hints and Default permission are strict metadata and cannot claim authenticated protection', () => {
  assert.deepEqual(parseVaultStartup(source), source);
  assert.deepEqual(parseVaultStartup(empty), empty);
  for (const input of [
    { ...source, upgrade: { vaultId: id } },
    { ...source, newWorkspace: true },
    { ...source, unprotected: { vaultId: id, protected: false } },
    { ...source, unprotectedAllowed: true },
    { ...empty, unprotectedAllowed: false },
  ])
    assert.equal(parseVaultStartup(input), undefined);
  assert.deepEqual(parseVaultProtection({ protected: false }), { protected: false });
  assert.deepEqual(parseVaultProtection({ protected: true }), { protected: true });
  for (const input of [null, { protected: 'false' }, { protected: false, root: [] }, []])
    assert.equal(parseVaultProtection(input), undefined);
  for (const prepare of [false, true]) {
    const calls: string[] = [];
    const app: any = {
      isReady: () => false,
      requestSingleInstanceLock: () => true,
      getPath: () => 'original',
      setPath: () => calls.push('isolated'),
    };
    const boot = prepareVaultMigrationBoot({
      app,
      executable: () => 'native',
      databasePath: 'db',
      prepareProtection: prepare,
      probe: () => ({ status: 0, stdout: JSON.stringify(source) }),
      createSessionData: () => 'isolated',
    });
    assert.equal(boot.migrationSessionData, prepare ? 'isolated' : undefined);
    assert.equal(calls.length, prepare ? 2 : 0);
  }
});

async function hostFixture(mode = '', create = false) {
  let opened = false,
    stops = 0,
    reads = 0,
    activated = 0;
  const wait = deferred();
  const client: any = {
    startup: async () => {
      reads++;
      if (mode === 'before-error' || (mode === 'after-error' && reads > 1)) throw Error('private');
      if (create && !opened) return empty;
      return mode === 'before-protected'
        ? { ...source, unprotected: undefined }
        : { ...source, unprotected: { vaultId: mode === 'after-wrong' && reads > 1 ? other : id } };
    },
    openUnprotected: async (value: boolean) => {
      assert.equal(value, create);
      if (mode === 'open-error') throw Error('private');
      if (mode === 'late') await wait.promise;
      opened = true;
      return { unlocked: true, lockedMemory: true, vaultId: mode === 'proof-wrong' ? other : id };
    },
    protection: async () => {
      if (mode === 'protection-error') throw Error('private');
      return { protected: mode === 'protected' };
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
    () => true,
    () => activated++,
  );
  return {
    host,
    client,
    wait,
    get stops() {
      return stops;
    },
    get activated() {
      return activated;
    },
  };
}
test('Default host admits only authenticated OS owners and rejects stale, protected and failed responses', async () => {
  for (const create of [false, true])
    for (const mode of [
      '',
      'before-error',
      'before-protected',
      'open-error',
      'after-error',
      'protection-error',
      'protected',
      'security-error',
      'proof-wrong',
      'late',
      'after-wrong',
    ]) {
      const f = await hostFixture(mode, create),
        pending = f.host.openUnprotected(create);
      if (mode === 'late') {
        await tick();
        await assert.rejects(f.host.openUnprotected(create));
        await f.host.stop();
        f.wait.resolve(true);
      }
      if (!mode) {
        assert.deepEqual(await pending, { unlocked: true, lockedMemory: true, vaultId: id });
        assert.equal(f.host.unlockedWorkspaceId, id);
        assert.deepEqual(await f.host.protection(), { protected: false });
        await assert.rejects(f.host.openUnprotected(create));
      } else {
        await assert.rejects(pending);
        assert.equal(f.host.unlockedWorkspaceId, undefined);
      }
      await f.host.stop();
      await assert.rejects(f.host.protection());
    }
  const f = await hostFixture();
  await f.host.openUnprotected(false);
  f.client.protection = async () => {
    throw Error('private');
  };
  await assert.rejects(f.host.protection());
  assert.ok(f.stops > 0);
});

function ipcFixture(mode = '') {
  const handlers = new Map<string, any>(),
    calls: string[] = [],
    wait = deferred();
  let trusted = true,
    canStart = true;
  const host: any = {
    unlockedWorkspaceId: mode === 'owner' ? id : undefined,
    startup: async () => {
      if (mode === 'startup-error') throw Error('private');
      return mode === 'no-source' ? empty : source;
    },
    openUnprotected: async (create: boolean) => {
      calls.push(create ? 'create' : 'open');
      if (mode === 'deferred') await wait.promise;
      if (mode === 'open-error') throw Error('private');
      host.unlockedWorkspaceId = id;
      if (mode === 'late-trust') trusted = false;
    },
    stop: async () => {
      calls.push('stop');
      if (mode.endsWith('stop-error')) throw Error('private');
      host.unlockedWorkspaceId = undefined;
    },
    protection: async () => {
      if (mode === 'protection-error') throw Error('private');
      return { protected: mode === 'protected' };
    },
  };
  registerVaultUnprotectedIpc({
    ipc: { handle: (name: string, fn: any) => handlers.set(name, fn) } as any,
    host,
    trusted: () => {
      if (mode === 'trust-error') throw Error('private');
      return trusted && mode !== 'untrusted';
    },
    parent: () => (mode === 'no-parent' ? undefined : ({} as any)),
    requireAccess: () => {
      calls.push('access');
      if (mode === 'access-error') throw Error('private');
    },
    canStart: () => canStart,
    hold: () => {
      calls.push('hold');
      return () => calls.push('release');
    },
    quiesce: async () => {
      calls.push('quiesce');
      if (mode === 'quiesce-error') throw Error('private');
      if (mode === 'cancel') return false;
      if (mode === 'deferred') await wait.promise;
      canStart = false;
      return true;
    },
    activate: () => {
      calls.push('activate');
      if (mode === 'activate-error' || mode === 'activate-stop-error') throw Error('private');
    },
    retire: async () => {
      calls.push('retire');
    },
    restartUpgrade: () => calls.push('restart'),
    fatal: () => calls.push('fatal'),
  });
  return {
    host,
    calls,
    wait,
    call: (name: string, ...args: any[]) => handlers.get('vault:' + name)({}, ...args),
  };
}
test('Default IPC uses fixed empty verbs, current authorization and positive cleanup', async () => {
  for (const mode of [
    '',
    'open-error',
    'late-trust',
    'untrusted',
    'trust-error',
    'activate-error',
    'activate-stop-error',
  ])
    for (const create of [true, false]) {
      const f = ipcFixture(mode),
        pending = f.call(create ? 'unprotected-create' : 'unprotected-open');
      if (!mode) {
        assert.equal(await pending, true);
        assert.deepEqual(f.calls, [create ? 'create' : 'open', 'activate']);
      } else {
        await assert.rejects(pending);
        assert.equal(f.calls.includes('activate'), mode.startsWith('activate'));
        assert.equal(f.calls.includes('fatal'), mode === 'activate-stop-error');
      }
    }
  const f = ipcFixture('deferred'),
    pending = f.call('unprotected-create');
  await tick();
  await assert.rejects(f.call('unprotected-open'));
  f.wait.resolve(true);
  await pending;
  await assert.rejects(f.call('unprotected-open', {}));
  for (const mode of ['', 'access-error', 'protection-error', 'untrusted']) {
    const f = ipcFixture(mode);
    if (!mode) assert.deepEqual(await f.call('protection'), { protected: false });
    else await assert.rejects(f.call('protection'));
    await assert.rejects(f.call('protection', {}));
  }
});
test('Protect now flushes and retires before requesting isolated relaunch, and holds uncertain cleanup', async () => {
  for (const mode of [
    '',
    'owner',
    'cancel',
    'no-source',
    'startup-error',
    'no-parent',
    'quiesce-error',
    'stop-error',
    'untrusted',
  ]) {
    const f = ipcFixture(mode),
      pending = f.call('prepare-unprotected');
    if (['', 'owner'].includes(mode)) {
      assert.equal(await pending, true);
      assert.ok(f.calls.indexOf('quiesce') < f.calls.indexOf('restart'));
      assert.equal(f.calls.includes('release'), false);
    } else if (mode === 'cancel') {
      assert.equal(await pending, false);
      assert.ok(f.calls.includes('release'));
    } else {
      await assert.rejects(pending);
      assert.equal(f.calls.includes('restart'), false);
      assert.equal(f.calls.includes('fatal'), ['quiesce-error', 'stop-error'].includes(mode));
    }
  }
  const f = ipcFixture('deferred'),
    pending = f.call('prepare-unprotected');
  await tick();
  await assert.rejects(f.call('unprotected-create'));
  f.wait.resolve(true);
  await pending;
  await assert.rejects(f.call('prepare-unprotected', {}));
});

class Element extends EventTarget {
  children: Element[] = [];
  textContent = '';
  disabled = false;
  tag: string;
  constructor(tag: string) {
    super();
    this.tag = tag;
  }
  setAttribute() {}
  replaceChildren(...children: Element[]) {
    this.children = children;
  }
}
test('OS startup keeps open retries bound to admitted owner and ignores disposed or duplicate actions', async (t) => {
  const original = globalThis.document;
  globalThis.document = { createElement: (tag: string) => new Element(tag) } as any;
  t.after(() => {
    globalThis.document = original;
  });
  for (const mode of ['open', 'retry', 'protect', 'cancel', 'error', 'disposed']) {
    const card = new Element('div'),
      wait = deferred();
    let opens = 0,
      admits = 0,
      prepares = 0;
    const dispose = mountUnprotectedStartup(
      card as any,
      {
        markStartupReady() {},
        openUnprotectedVault: async () => {
          admits++;
          await wait.promise;
          if (mode === 'error') throw Error('private');
          return true;
        },
        prepareUnprotectedVaultProtection: async () => {
          prepares++;
          await wait.promise;
          return mode !== 'cancel';
        },
      },
      async () => {
        opens++;
        if (mode === 'retry' && opens === 1) throw Error('private');
      },
    );
    const open = card.children[3],
      protect = card.children[4],
      button = ['protect', 'cancel'].includes(mode) ? protect : open;
    button.dispatchEvent(new Event('click'));
    button.dispatchEvent(new Event('click'));
    if (mode === 'disposed') dispose();
    wait.resolve(true);
    await tick();
    if (mode === 'retry') {
      open.dispatchEvent(new Event('click'));
      await tick();
      assert.equal(admits, 1);
      assert.equal(opens, 2);
    }
    if (mode === 'protect') {
      assert.equal(prepares, 1);
      assert.equal(opens, 0);
      assert.equal(open.disabled, true);
    }
    if (mode === 'disposed') assert.equal(opens, 0);
    assert.equal(card.children[2].textContent.includes('private'), false);
    dispose();
  }
});

test(
  'typed client creates and reopens an actual OS-owned Go vault and projects isolated setup only in maintenance',
  { timeout: 120_000, skip: process.platform !== 'win32' },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-default-os-')),
      root = fileURLToPath(new URL('../', import.meta.url)),
      data = join(directory, 'data'),
      database = join(data, 'workspace.db'),
      executable = join(directory, process.platform === 'win32' ? 'backend.exe' : 'backend');
    await mkdir(data);
    await promisify(execFile)('go', ['build', '-o', executable, '.'], {
      cwd: join(root, 'tools/wormhole-backend'),
      windowsHide: true,
      timeout: 120_000,
    });
    let host: VaultBackendHost | undefined, client: VaultBackendClient | undefined;
    try {
      const make = () =>
        new VaultBackendHost(
          () => new VaultBackendClient({ executable, databasePath: database, userDataPath: data }),
          () => true,
        );
      host = make();
      await host.openUnprotected(true);
      const id = host.unlockedWorkspaceId;
      assert.ok(id);
      assert.deepEqual(await host.protection(), { protected: false });
      await host.workspace();
      await host.stop();
      const doc = JSON.parse(await readFile(database + '.slots', 'utf8'));
      assert.equal(doc.slots[0].kind, 'unprotected');
      assert.equal(doc.initializing, false);
      host = make();
      assert.equal((await host.startup()).unprotected?.vaultId, id);
      await host.openUnprotected(false);
      assert.equal(host.unlockedWorkspaceId, id);
      await host.stop();
      const maintenance = await mkdtemp(join(directory, '.wormhole-vault-migration-'));
      client = new VaultBackendClient({
        executable,
        databasePath: database,
        userDataPath: data,
        migrationSessionData: maintenance,
      });
      assert.equal((await client.startup()).upgrade?.vaultId, id);
      await assert.rejects(client.openUnprotected(false));
    } finally {
      await host?.stop();
      await client?.lock();
      assert.ok(directory.startsWith(join(tmpdir(), 'wormhole-default-os-')));
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test('portable transport requires a native identity and projects isolated hints without changing OS slot parsing', async () => {
  for (const maintenance of [false, true])
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
          const result =
            request.operation === 'startup'
              ? source
              : request.operation === 'protection'
                ? { protected: false }
                : { unlocked: true, lockedMemory: true, ...(invalid ? {} : { vaultId: id }) };
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
      const client = new VaultBackendClient(
        {
          executable: 'native',
          databasePath: 'source',
          migrationSessionData: maintenance ? 'isolated' : '',
        },
        () => {
          queueMicrotask(() => child.emit('spawn'));
          return child;
        },
      );
      try {
        const startup = await client.startup();
        assert.equal(maintenance ? startup.upgrade?.vaultId : startup.unprotected?.vaultId, id);
        assert.deepEqual(await client.protection(), { protected: false });
        if (invalid) await assert.rejects(client.openUnprotected(false));
        else
          for (const create of [true, false])
            assert.deepEqual(await client.openUnprotected(create), {
              unlocked: true,
              lockedMemory: true,
              vaultId: id,
            });
      } finally {
        await client.lock();
      }
    }
});

test('actual main binds Default actions to shared quiescence and supplies the fixed isolated restart switch', async () => {
  const source = await readFile(new URL('../electron/main.ts', import.meta.url), 'utf8'),
    start = source.indexOf('  registerVaultUnprotectedIpc({'),
    end = source.indexOf('  const vaultResumeOptions = {', start);
  assert.ok(start > 0 && end > start);
  let options: any,
    active = 0,
    retired = 0,
    restarted = 0;
  const host = {},
    shared = {
      ipc: {},
      quiesce: () => false,
      restartUpgrade: () => {
        restarted++;
      },
    };
  runInNewContext(stripTypeScriptTypes(source.slice(start, end)), {
    registerVaultUnprotectedIpc: (value: any) => (options = value),
    vaultProtectionOptions: shared,
    vaultBackend: host,
    rememberAuthState: () => {},
    vaultAuthState: () => ({ mode: 'vault' }),
    authSession: { markUnlocked: () => active++ },
    lockApplication: async () => {
      retired++;
    },
  });
  assert.equal(options.host, host);
  assert.equal(options.quiesce, shared.quiesce);
  options.activate();
  await options.retire();
  assert.equal(options.restartUpgrade, shared.restartUpgrade);
  options.restartUpgrade();
  assert.equal(active, 1);
  assert.equal(retired, 1);
  assert.equal(restarted, 1);
});

test('Default IPC, startup and changed host methods meet project coverage', async (t) => {
  if (external) return;
  try {
    const result = await profiler.post('Profiler.takePreciseCoverage');
    for (const file of [
      'vault-unprotected-ipc.ts',
      'vault-unprotected-startup.ts',
      'vault-host.ts',
      'vault-client.ts',
    ]) {
      const functions = result.result
        .filter((s) => s.url.endsWith('/' + file))
        .flatMap((s) => s.functions)
        .filter(
          (f) =>
            !['vault-host.ts', 'vault-client.ts'].includes(file) ||
            ['openUnprotected', 'protection'].includes(f.functionName),
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
