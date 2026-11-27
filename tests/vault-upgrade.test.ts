import assert from 'node:assert/strict';
import test from 'node:test';
import { Session } from 'node:inspector/promises';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import { registerVaultUpgradeIpc } from '../electron/vault-upgrade-ipc.ts';
import { parseVaultUpgradeContext } from '../electron/vault-upgrade-contract.ts';
import { parseVaultStartup } from '../electron/vault-contract.ts';
import { VaultBackendHost } from '../electron/vault-host.ts';
import { VaultBackendClient } from '../electron/vault-client.ts';
import { mountVaultUpgradeStartup } from '../src/vault-upgrade-startup.ts';
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
const startup = {
  slots: null,
  cosmetics: { theme: 'system' },
  newWorkspace: false,
  upgrade: { vaultId: id },
};
const enrollment = { enrollmentId: other, vaultId: id, groups: [1, 2], bundle: {} };
const prepared = { prepared: true, restartRequired: true, vaultId: id };
const begin = () => ({ password: new Uint8Array([4, 5]), publicKey: new Uint8Array(32).fill(3) });
const confirm = () => ({ enrollmentId: other, groups: new Uint8Array(10).fill(65) });
const tick = () => new Promise(setImmediate);
function deferred() {
  let resolve!: (v: any) => void;
  const promise = new Promise<any>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}

test('upgrade hints are exclusive routing metadata with no factor or policy authority', () => {
  assert.deepEqual(parseVaultUpgradeContext({ vaultId: id }), { vaultId: id });
  for (const input of [
    null,
    [],
    { vaultId: 'x' },
    { vaultId: id, mode: 'upgrade' },
    { vaultId: id, root: [] },
  ])
    assert.equal(parseVaultUpgradeContext(input), undefined);
  assert.deepEqual(parseVaultStartup(startup), startup);
  for (const extra of [
    { newWorkspace: true },
    { upgrade: { vaultId: id, trusted: true } },
    { migration: { pending: true } },
    { rotation: { pending: true } },
    { slots: { formatVersion: 3, vaultId: id, encrypted: false, slots: [] } },
  ])
    assert.equal(parseVaultStartup({ ...startup, ...extra }), undefined);
});

function ipcFixture(mode = '') {
  const calls: string[] = [],
    wait = deferred();
  let handler: any,
    trusted = true;
  const host: any = {
    unlockedWorkspaceId: undefined,
    startup: async () => {
      calls.push('startup');
      if (mode === 'startup-error') throw Error('private');
      if (mode === 'late-trust') trusted = false;
      return mode === 'not-upgrade' ? { ...startup, upgrade: undefined } : startup;
    },
    stop: async () => {
      calls.push('stop');
      if (mode === 'stop-error') throw Error('private');
    },
  };
  registerVaultUpgradeIpc({
    ipc: {
      handle: (name: string, fn: any) => {
        assert.equal(name, 'vault:upgrade-protection');
        handler = fn;
      },
    } as any,
    host,
    dialog: {
      open: async (_parent: any, accepted: () => boolean) => {
        assert.equal(accepted(), true);
        calls.push('dialog');
        if (mode === 'dialog-error') throw Error('private');
        if (mode === 'dialog-late') {
          await wait.promise;
          trusted = false;
        }
        if (mode === 'deferred') await wait.promise;
        return mode !== 'cancel';
      },
    },
    trusted: () => {
      if (mode === 'trust-error') throw Error('private');
      return trusted && mode !== 'untrusted';
    },
    quiesced: () => mode !== 'not-quiesced',
    parent: () => (mode === 'no-parent' ? undefined : ({} as any)),
    hold: () => {
      calls.push('hold');
      return () => calls.push('release');
    },
    restart: () => calls.push('restart'),
    fatal: () => calls.push('fatal'),
  });
  return { calls, call: (...args: any[]) => handler({}, ...args), wait, host };
}
test('upgrade IPC keeps exclusion through cancel/restart and fails closed after uncertain cleanup', async () => {
  for (const mode of [
    '',
    'cancel',
    'untrusted',
    'not-quiesced',
    'trust-error',
    'startup-error',
    'late-trust',
    'not-upgrade',
    'no-parent',
    'dialog-error',
    'stop-error',
    'dialog-late',
  ]) {
    const f = ipcFixture(mode),
      pending = f.call();
    if (mode === 'dialog-late') {
      await tick();
      f.wait.resolve(true);
    }
    if (mode === '' || mode === 'cancel') {
      assert.equal(await pending, mode !== 'cancel');
      assert.deepEqual(f.calls, ['startup', 'hold', 'dialog', 'stop', 'restart']);
    } else {
      await assert.rejects(pending, /^Error: Vault upgrade unavailable\.$/);
      assert.equal(f.calls.includes('restart'), false);
      assert.equal(
        f.calls.includes('fatal'),
        ['dialog-error', 'stop-error', 'dialog-late'].includes(mode),
      );
    }
    assert.equal(f.calls.includes('release'), false);
  }
  const f = ipcFixture('deferred'),
    pending = f.call();
  await tick();
  await assert.rejects(f.call());
  f.wait.resolve(true);
  assert.equal(await pending, true);
  await assert.rejects(f.call({ password: 'rejected' }));
});

async function hostFixture(mode = '') {
  let stops = 0,
    active = 0,
    allowed = true;
  const wait = deferred();
  const client: any = {
    startup: async () => startup,
    lock: async () => {
      stops++;
    },
    upgradeSetupContext: async () => {
      if (mode === 'context-late') await wait.promise;
      return { vaultId: mode === 'context-wrong' ? other : id };
    },
    beginUpgradeSetup: async () => {
      if (mode === 'begin-error') throw Error('private');
      if (mode === 'begin-late') await wait.promise;
      return { ...enrollment, vaultId: mode === 'begin-wrong' ? other : id };
    },
    confirmRootRotationSetup: async () => {
      if (mode.startsWith('confirm-error')) throw Error('private');
      if (mode === 'confirm-late') await wait.promise;
      return { ...prepared, vaultId: mode === 'confirm-wrong' ? other : id };
    },
    status: async () => {
      if (mode === 'confirm-error-status') throw Error('private');
      return { unlocked: mode === 'confirm-error-owner' };
    },
    cancelRootRotationSetup: async () => {
      if (mode === 'cancel-error') throw Error('private');
      return true;
    },
  };
  const host = new VaultBackendHost(
    () => client,
    () => allowed,
    () => active++,
  );
  await host.startup();
  return {
    host,
    wait,
    client,
    deny: () => {
      allowed = false;
    },
    get stops() {
      return stops;
    },
    get active() {
      return active;
    },
  };
}
test('ownerless host binds enrollment and confirmation without activating app authorization', async () => {
  const empty = new VaultBackendHost(
    () => ({}) as any,
    () => true,
  );
  await assert.rejects(empty.upgradeSetupContext());
  const invalid = begin();
  await assert.rejects(empty.beginUpgradeSetup(invalid));
  assert.ok(invalid.password.every((b) => b === 0));
  await assert.rejects(empty.confirmUpgradeSetup(confirm()));
  for (const mode of [
    '',
    'context-wrong',
    'context-late',
    'begin-error',
    'begin-wrong',
    'begin-late',
    'confirm-error',
    'confirm-error-status',
    'confirm-error-owner',
    'confirm-wrong',
    'confirm-late',
    'cancel-error',
  ]) {
    const f = await hostFixture(mode);
    assert.equal(f.host.isVaultWorkspace, true);
    assert.equal(f.host.unlockedWorkspaceId, undefined);
    if (mode.startsWith('context')) {
      const p = f.host.upgradeSetupContext();
      if (mode === 'context-late') {
        await tick();
        await f.host.stop();
        f.wait.resolve(true);
      }
      await assert.rejects(p);
    } else {
      await f.host.upgradeSetupContext();
      const input = begin(),
        p = f.host.beginUpgradeSetup(input);
      if (mode === 'begin-late') {
        await tick();
        await assert.rejects(f.host.beginUpgradeSetup(begin()));
        await f.host.stop();
        f.wait.resolve(true);
      }
      if (mode.startsWith('begin')) await assert.rejects(p);
      else {
        await p;
        assert.ok(input.password.every((b) => b === 0));
        await assert.rejects(f.host.beginUpgradeSetup(begin()));
        await assert.rejects(f.host.confirmEnrollment(confirm()));
        await assert.rejects(f.host.confirmRootRotationSetup(confirm()));
        if (mode === 'cancel-error') await assert.rejects(f.host.cancelRootRotationSetup());
        else {
          const c = confirm(),
            q = f.host.confirmUpgradeSetup(c);
          if (mode === 'confirm-late') {
            await tick();
            await f.host.stop();
            f.wait.resolve(true);
          }
          if (mode.startsWith('confirm')) await assert.rejects(q);
          else assert.deepEqual(await q, prepared);
          assert.ok(c.groups.every((b) => b === 0));
          if (mode === 'confirm-error') {
            assert.equal(f.stops, 0);
            await f.host.cancelRootRotationSetup();
          }
        }
      }
    }
    assert.equal(f.host.unlockedWorkspaceId, undefined);
    assert.equal(f.active, 0);
    await f.host.stop();
  }
});

test('typed transport denies maintenance-only upgrade before spawning and consumes secrets', async () => {
  const client = new VaultBackendClient({ executable: 'never-start', databasePath: 'never-open' });
  await assert.rejects(client.upgradeSetupContext());
  const input = begin();
  await assert.rejects(client.beginUpgradeSetup(input));
  assert.ok(input.password.every((b) => b === 0));
  assert.ok(input.publicKey.every((b) => b === 0));
  await client.lock();
});

test('typed upgrade transport sends only new enrollment bytes through consumable stdin frames', async () => {
  for (const invalid of [false, true]) {
    const child: any = new EventEmitter(),
      frames: Buffer[] = [],
      requests: any[] = [];
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.pid = process.pid;
    child.exitCode = null;
    child.signalCode = null;
    child.stdin = new Writable({
      write(chunk, _encoding, callback) {
        frames.push(chunk);
        const request = JSON.parse(chunk.toString());
        requests.push(request);
        const result =
          request.operation === 'rotation-upgrade-context'
            ? { vaultId: id, ...(invalid ? { mode: 'upgrade' } : {}) }
            : {
                ...enrollment,
                bundle: {
                  formatVersion: 1,
                  suiteId: 2,
                  enc: Buffer.alloc(32).toString('base64'),
                  ciphertext: Buffer.alloc(92).toString('base64'),
                },
              };
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
        migrationSessionData: 'isolated',
        userDataPath: 'original',
      },
      (_executable, args) => {
        assert.ok(args.includes('vault-migration'));
        assert.equal(
          args.some((s) => s.includes('password')),
          false,
        );
        queueMicrotask(() => child.emit('spawn'));
        return child;
      },
    );
    try {
      const context = client.upgradeSetupContext();
      if (invalid) await assert.rejects(context);
      else {
        assert.deepEqual(await context, { vaultId: id });
        const input = begin();
        const response = await client.beginUpgradeSetup(input);
        assert.equal(response.vaultId, id);
        const request = requests.find((r) => r.operation === 'rotation-upgrade-begin');
        assert.deepEqual(Object.keys(request.payload).sort(), ['password', 'publicKey']);
        assert.ok(input.password.every((b) => b === 0));
        await tick();
        // Public metadata frames carry no factors; the mutable enrollment frame
        // must be erased after its write callback acknowledges consumption.
        assert.ok(frames[requests.indexOf(request)].every((b) => b === 0));
        await assert.rejects(client.beginUpgradeSetup(null));
      }
    } finally {
      await client.lock();
    }
  }
});

test('dedicated preload exposes only upgrade enrollment and consumes borrowed arrays even on IPC failure', async () => {
  const source = stripTypeScriptTypes(
    readFileSync(new URL('../electron/vault-upgrade-preload.cts', import.meta.url), 'utf8'),
  ).replace(/^import .*?;\s*/gms, '');
  for (const platform of ['win32', 'linux'])
    for (const fail of [false, true]) {
      let api: any;
      const channels: string[] = [];
      runInNewContext(source, {
        Uint8Array,
        process: { platform },
        contextBridge: {
          exposeInMainWorld: (name: string, value: any) => {
            assert.equal(name, 'vaultCreate');
            api = value;
          },
        },
        ipcRenderer: {
          invoke: (channel: string) => {
            channels.push(channel);
            if (fail) throw Error('fixture');
            return Promise.resolve(true);
          },
        },
      });
      assert.deepEqual(
        Object.keys(api).sort(),
        ['begin', 'cancel', 'confirm', 'contentProtectionAvailable', 'upgradeContext'].sort(),
      );
      assert.equal(api.contentProtectionAvailable, platform !== 'linux');
      const input = begin(),
        proof = confirm();
      for (const call of [
        () => api.upgradeContext(),
        () => api.begin(input),
        () => api.confirm(proof),
        () => api.cancel(),
      ]) {
        if (fail) assert.throws(call);
        else await call();
      }
      assert.ok(input.password.every((b) => b === 0));
      assert.ok(input.publicKey.every((b) => b === 0));
      assert.ok(proof.groups.every((b) => b === 0));
      assert.deepEqual(
        channels,
        ['context', 'begin', 'confirm', 'cancel'].map((name) => 'vault-upgrade-setup:' + name),
      );
    }
});

class Element extends EventTarget {
  children: Element[] = [];
  textContent = '';
  disabled = false;
  readonly tag: string;
  constructor(tag: string) {
    super();
    this.tag = tag;
  }
  setAttribute() {}
  replaceChildren(...children: Element[]) {
    this.children = children;
  }
}
test('upgrade startup never mounts workspace and blocks duplicate/late actions through restart', async (t) => {
  const original = globalThis.document;
  globalThis.document = { createElement: (tag: string) => new Element(tag) } as any;
  t.after(() => {
    globalThis.document = original;
  });
  for (const mode of ['ok', 'cancel', 'error', 'disposed-ok', 'disposed-error']) {
    const wait = deferred(),
      card = new Element('div');
    let calls = 0,
      ready = 0;
    const dispose = mountVaultUpgradeStartup(card as any, {
      upgradeVaultProtection: async () => {
        calls++;
        await wait.promise;
        if (mode.endsWith('error')) throw Error('private');
        return mode !== 'cancel';
      },
      markStartupReady: () => ready++,
    });
    const button = card.children[3],
      status = card.children[2];
    button.dispatchEvent(new Event('click'));
    button.dispatchEvent(new Event('click'));
    assert.equal(calls, 1);
    assert.equal(ready, 1);
    assert.equal(button.disabled, true);
    if (mode.startsWith('disposed')) dispose();
    wait.resolve(true);
    await tick();
    assert.equal(status.textContent.includes('private'), false);
    if (mode === 'error') {
      assert.equal(button.disabled, false);
      assert.match(status.textContent, /Try again/);
    } else assert.equal(button.disabled, true);
    button.dispatchEvent(new Event('click'));
    await tick();
    assert.equal(calls, mode === 'error' ? 2 : 1);
    dispose();
  }
});

test('upgrade modules and changed host methods satisfy measured project coverage', async (t) => {
  if (external) return;
  try {
    const result = await profiler.post('Profiler.takePreciseCoverage');
    for (const file of [
      'vault-upgrade-ipc.ts',
      'vault-upgrade-contract.ts',
      'vault-upgrade-startup.ts',
      'vault-host.ts',
      'vault-client.ts',
    ]) {
      const functions = result.result
        .filter((s) => s.url.endsWith('/' + file))
        .flatMap((s) => s.functions)
        .filter((f) =>
          file === 'vault-client.ts'
            ? ['upgradeSetupContext', 'beginUpgradeSetup'].includes(f.functionName)
            : file !== 'vault-host.ts' ||
              [
                'upgradeSetupContext',
                'beginUpgradeSetup',
                'confirmUpgradeSetup',
                'confirmRootSetup',
                'retainRotationSourceAfterRejection',
              ].includes(f.functionName),
        );
      const ranges = functions.flatMap((f) => f.ranges);
      assert.ok(ranges.length, file);
      const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
      t.diagnostic(`${file}: ${percent.toFixed(2)}% V8 blocks`);
      assert.ok(percent >= coverageThreshold, file);
    }
  } finally {
    profiler.disconnect();
  }
});
