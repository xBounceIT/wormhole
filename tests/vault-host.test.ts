import { Session } from 'node:inspector/promises';
import { coverageThreshold } from '../scripts/test-coverage.ts';
import { vncRequest, vncBundle, routedVncRequest, routedVncBundle } from './fixtures/vault-vnc.ts';
import { rdpRequest, rdpBundle, routedRdpRequest, routedRdpBundle } from './fixtures/vault-rdp.ts';
import { preferences } from './fixtures/vault-preferences.ts';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import {
  VaultBackendHost,
  isTrustedVaultDocument,
  registerVaultIpc,
} from '../electron/vault-host.ts';
import type { VaultStatus } from '../electron/vault-contract.ts';
import { registerVaultLocalBackupIpc } from '../electron/vault-local-backup-ipc.ts';
import { sshRequest, sshBundle } from './fixtures/vault-ssh.ts';

const status: VaultStatus = {
  formatVersion: 1,
  stage: 'foundation',
  protectionAvailable: false,
  sharedWorkspaceAvailable: false,
  unlocked: false,
  lockedMemory: false,
};
const security = {
  sequence: '1',
  workspace: 'default' as const,
  user: 'default' as const,
  os: 'default' as const,
  effective: 'default' as const,
  source: 'workspace' as const,
};
const startup = { slots: null, cosmetics: { theme: 'system' as const }, newWorkspace: false };
const catalog = { nodes: [], credentials: [], tunnels: [] };
const workspace = {
  tree: [],
  credentials: [],
  credentialOptions: { ssh: [], rdp: [], vnc: [] },
  tunnels: [],
};

function unlockInput() {
  return {
    vaultId: '11111111-1111-4111-8111-111111111111',
    slotId: '22222222-2222-4222-8222-222222222222',
    kind: 'password',
    factor: new Uint8Array([1, 2, 3]),
  };
}

test('choosing Standard binds the protected prompt and subsequent lock to the same owner', async () => {
  let eligible = false,
    trusted = true,
    commits = 0,
    locks = 0;
  const auth = unlockInput();
  const descriptor = {
    formatVersion: 3 as const,
    vaultId: auth.vaultId,
    slots: [{ id: auth.slotId, kind: 'password' as const, preset: 'kdf-v1' as const }],
  };
  let afterCommit = async () => {};
  const host = new VaultBackendHost(
    () => ({
      security: async () => ({
        ...security,
        sequence: '7',
        ...(eligible ? { canTightenToStandard: true as const } : {}),
      }),
      describe: async () => descriptor,
      unlock: async () => ({ unlocked: true, lockedMemory: true }),
      lock: async () => {},
      tightenLocalProfile: async (sequence, input) => {
        assert.equal(sequence, '7');
        assert.deepEqual([...input.factor], [1, 2, 3]);
        commits++;
        await afterCommit();
        return true as const;
      },
    }),
    () => true,
  );
  let prompts = 0;
  const submit: Parameters<typeof host.tightenLocalProfile>[0] = async (
    operation,
    current,
    confirm,
  ) => {
    prompts++;
    assert.equal(operation, 'tighten-local-profile');
    assert.equal(current, descriptor);
    const factor = unlockInput();
    try {
      return await confirm(factor as Parameters<typeof confirm>[0]);
    } finally {
      assert.deepEqual([...factor.factor], [0, 0, 0]);
    }
  };
  const change = (prompt = submit) =>
    host.tightenLocalProfile(
      prompt,
      () => trusted,
      async () => {
        locks++;
      },
    );
  await assert.rejects(change(), /unavailable/);
  await host.unlock(unlockInput());
  await assert.rejects(change(), /unavailable/);
  eligible = true;
  trusted = false;
  await assert.rejects(change(), /unavailable/);
  assert.equal(prompts, 0);
  trusted = true;
  await assert.rejects(
    change(async () => {
      throw Error('canceled');
    }),
    /canceled/,
  );
  assert.deepEqual([commits, locks], [0, 0]);
  await change();
  assert.deepEqual([commits, locks], [1, 1]);
  afterCommit = async () => {
    trusted = false;
  };
  await assert.rejects(change(), /locked/);
  assert.deepEqual([commits, locks], [2, 2]);
  trusted = true;
  afterCommit = async () => {
    await host.stop();
    await host.unlock(unlockInput());
  };
  await assert.rejects(change(), /locked/);
  assert.deepEqual([commits, locks], [3, 2]);
  await host.stop();
});

test('local backup is bound to the encrypted owner across selection and authentication', async () => {
  let encrypted = false;
  let confirmCount = 0;
  const calls: { path: string; factor?: number[] }[] = [];
  const auth = unlockInput();
  const descriptor = {
    formatVersion: 3 as const,
    vaultId: auth.vaultId,
    get encrypted() {
      return encrypted;
    },
    slots: [{ id: auth.slotId, kind: 'password' as const, preset: 'kdf-v1' as const }],
  };
  const host = new VaultBackendHost(
    () => ({
      status: async () => status,
      describe: async () => descriptor,
      preferences: async () => preferences(),
      security: async () => ({ ...security, workspace: 'standard', effective: 'standard' }),
      unlock: async () => ({ unlocked: true, lockedMemory: true }),
      lock: async () => {},
      exportLocalBackup: async (path, input) => {
        calls.push({ path, factor: input && Array.from(input.factor) });
        return true as const;
      },
    }),
    () => true,
  );
  const pick = async () => '/native/fixture.whvault';
  const confirm: Parameters<VaultBackendHost['exportLocalBackup']>[1] = async (
    operation,
    current,
    submit,
  ) => {
    confirmCount++;
    assert.equal(operation, 'local-backup-export');
    assert.equal(current.vaultId, auth.vaultId);
    const result = await submit(auth as Parameters<typeof submit>[0]);
    assert.deepEqual(Array.from(auth.factor), [0, 0, 0]);
    return result;
  };
  assert.equal(await host.localBackupAvailable(), false);
  await host.unlock(unlockInput());
  assert.equal(await host.localBackupAvailable(), false);
  await assert.rejects(
    host.exportLocalBackup(pick, confirm, () => true),
    /unavailable/,
  );
  encrypted = true;
  assert.equal(await host.localBackupAvailable(), true);
  assert.equal(
    await host.exportLocalBackup(
      async () => null,
      confirm,
      () => true,
    ),
    false,
  );
  assert.equal(await host.exportLocalBackup(pick, confirm, () => true), true);
  assert.equal(confirmCount, 1);
  assert.deepEqual(calls, [{ path: '/native/fixture.whvault', factor: [1, 2, 3] }]);
  await assert.rejects(
    host.exportLocalBackup(
      async () => {
        await host.stop();
        return pick();
      },
      confirm,
      () => true,
    ),
    /unavailable/,
  );
  assert.equal(calls.length, 1);
});

test('local restore uses the reviewed archive and retires forwarded factors', async () => {
  const auth = unlockInput();
  const slots = {
    formatVersion: 3 as const,
    vaultId: auth.vaultId,
    encrypted: true,
    slots: [{ id: auth.slotId, kind: 'recovery' as const }],
  };
  const fingerprint = 'a'.repeat(64);
  const file = '/native/recovery.whvault';
  const calls: string[][] = [];
  let fresh = false;
  const host = new VaultBackendHost(
    () => ({
      status: async () => status,
      startup: async () => ({ ...startup, newWorkspace: fresh }),
      lock: async () => {},
      inspectLocalBackup: async (path) => {
        assert.equal(path, file);
        return { slots, fingerprint };
      },
      installLocalBackup: async (path, reviewed, code) => {
        assert.equal(code.length, 76);
        assert.ok(code.every((byte) => byte === 65));
        calls.push([path, reviewed]);
        return true as const;
      },
    }),
    () => true,
  );
  const pick = async () => file;
  const accept: Parameters<VaultBackendHost['restoreLocalBackup']>[1] = async (
    operation,
    descriptor,
    submit,
  ) => {
    assert.equal(operation, 'local-backup-install');
    assert.deepEqual(descriptor, slots);
    const factor = new Uint8Array(76).fill(65);
    try {
      return await submit({ ...auth, kind: 'recovery-code', factor });
    } finally {
      assert.ok(factor.every((byte) => byte === 0));
    }
  };
  await assert.rejects(
    host.restoreLocalBackup(pick, accept, () => true),
    /unavailable/,
  );
  fresh = true;
  assert.equal(
    await host.restoreLocalBackup(
      async () => null,
      accept,
      () => true,
    ),
    false,
  );
  let trusted = true;
  await assert.rejects(
    host.restoreLocalBackup(
      pick,
      (operation, descriptor, submit) => {
        trusted = false;
        return accept(operation, descriptor, submit);
      },
      () => trusted,
    ),
    /unavailable/,
  );
  assert.deepEqual(calls, []);
  assert.equal(await host.restoreLocalBackup(pick, accept, () => true), true);
  assert.deepEqual(calls, [[file, fingerprint]]);
  await host.stop();
});

test('local backup IPC uses the native picker and rejects stale, concurrent and parameterized requests', async () => {
  const handlers = new Map<string, (...args: any[]) => Promise<unknown>>();
  const sender = new EventEmitter();
  const event = { sender };
  let trust = true;
  let destroyed = false;
  let pending: ((path: string | null) => void) | undefined;
  const parent = { isDestroyed: () => destroyed };
  const confirmed: string[] = [];
  registerVaultLocalBackupIpc({
    ipc: { handle: (name, handler) => handlers.set(name, handler as any) },
    parent: () => parent as any,
    host: {
      localBackupAvailable: async () => true,
      restoreLocalBackup: async (pick, _confirm, accepted) => !!(await pick()) && accepted(),
      async exportLocalBackup(pick, _confirm, accepted) {
        const path = await pick();
        if (!accepted()) throw Error('invalidated');
        if (path === 'cancel-fresh') throw Error('Authentication cancelled.');
        if (!path) return false;
        confirmed.push(path);
        return true;
      },
    },
    trusted: () => {
      if (!trust) throw Error('no frame');
      return true;
    },
    pickExport: () => new Promise((resolve) => (pending = resolve)),
    pickRestore: async () => '/native/final.whvault',
    authenticate: () => async () => {
      throw Error('unreachable test authentication');
    },
    restart: async () => {
      confirmed.push('restarted');
    },
  });
  const available = handlers.get('vault:local-backup-available')!;
  const exportBackup = handlers.get('vault:local-backup-export')!;
  assert.equal(await available(event), true);
  await assert.rejects(available(event, 'extra'), /unavailable/);
  await assert.rejects(exportBackup(event, '/renderer/forged.whvault'), /unavailable/);
  trust = false;
  await assert.rejects(exportBackup(event), /unavailable/);
  await assert.rejects(handlers.get('vault:local-backup-restore')!(event), /unavailable/);
  trust = true;
  destroyed = true;
  await assert.rejects(exportBackup(event), /unavailable/);
  destroyed = false;
  const stale = exportBackup(event);
  await assert.rejects(exportBackup(event), /unavailable/);
  sender.emit('did-start-navigation', {}, 'https://test.invalid', false, true);
  pending!('/native/stale.whvault');
  await assert.rejects(stale, /invalidated/);
  assert.equal(sender.listenerCount('did-start-navigation'), 0);
  const cancelled = exportBackup(event);
  pending!('cancel-fresh');
  assert.equal(await cancelled, false);
  const success = exportBackup(event);
  sender.emit('did-start-navigation', {}, '/same-document', true, true);
  pending!('/native/fixture.whvault');
  assert.equal(await success, true);
  assert.deepEqual(confirmed, ['/native/fixture.whvault']);
  assert.equal(await handlers.get('vault:local-backup-restore')!(event), true);
  assert.deepEqual(confirmed, ['/native/fixture.whvault', 'restarted']);
});

test('sealed requests require current unlocked owner and cannot survive owner replacement', async () => {
  let finish!: (value: any) => void,
    allowed = true,
    calls = 0;
  const host = new VaultBackendHost(
    () => ({
      status: async () => status,
      describe: async () => null,
      catalog: async () => catalog,
      workspace: async () => workspace,
      startup: async () => startup,
      preferences: async () => preferences(),
      security: async () => security,
      unlock: async () => ({ unlocked: true, lockedMemory: true }),
      lock: async () => {},
      sshBundle: async () => {
        calls++;
        return new Promise((resolve) => {
          finish = resolve;
        });
      },
    }),
    () => allowed,
  );
  const q = sshRequest();
  q.workspaceId = unlockInput().vaultId;
  await assert.rejects(host.sshBundle(q), /locked/);
  assert.equal(calls, 0);
  await host.unlock(unlockInput());
  assert.equal(host.unlockedWorkspaceId, q.workspaceId);
  await assert.rejects(host.sshBundle({ ...q, workspaceId: sshRequest().workspaceId }), /locked/);
  const success = host.sshBundle(q);
  finish(sshBundle(q));
  assert.deepEqual(await success, sshBundle(q));
  const stale = host.sshBundle(q);
  await host.stop();
  await host.unlock(unlockInput());
  finish(sshBundle(q));
  await assert.rejects(stale, /locked/);
  allowed = false;
  assert.equal(host.unlockedWorkspaceId, undefined);
  await assert.rejects(host.sshBundle(q), /locked/);
  await host.stop();
});

test('synchronous monitor retirement during activation cannot publish an unlocked owner', async () => {
  const host = new VaultBackendHost(
    () => ({
      status: async () => status,
      describe: async () => null,
      catalog: async () => catalog,
      workspace: async () => workspace,
      startup: async () => startup,
      preferences: async () => preferences(),
      security: async () => security,
      unlock: async () => ({ unlocked: true, lockedMemory: true }),
      lock: async () => {},
      sshBundle: async (q) => sshBundle(q),
    }),
    () => true,
    () => {
      void host.stop();
    },
  );
  await assert.rejects(host.unlock(unlockInput()), /policy/);
  assert.equal(host.unlockedWorkspaceId, undefined);
});

test('unlock acknowledgement requires current native security and successful monitor activation', async () => {
  for (const [mode, effective, lockedMemory, shouldUnlock] of [
    ['success', 'default', true, true],
    ['optional-memory', 'default', false, true],
    ['standard-memory', 'standard', false, true],
    ['hardened-memory', 'hardened', false, false],
    ['paranoid-memory', 'paranoid', false, false],
    ['policy-error', 'default', true, false],
    ['activation-error', 'default', true, false],
    ['shutdown', 'default', true, false],
  ] as const) {
    const reportedSecurity = { ...security, workspace: effective, effective };
    let stops = 0,
      activations = 0,
      allowed = true;
    let borrowed!: Uint8Array;
    const host = new VaultBackendHost(
      () => ({
        status: async () => status,
        describe: async () => null,
        catalog: async () => catalog,
        workspace: async () => workspace,
        startup: async () => startup,
        preferences: async () => preferences(),
        sshBundle: async () => {
          throw Error('not configured by this metadata fixture');
        },
        security: async () => {
          if (mode === 'policy-error') throw Error('private policy diagnostic');
          if (mode === 'shutdown') allowed = false;
          return reportedSecurity;
        },
        unlock: async (value) => {
          borrowed = (value as { factor: Uint8Array }).factor;
          return { unlocked: true, lockedMemory };
        },
        lock: async () => {
          stops++;
        },
      }),
      () => allowed,
      (value) => {
        activations++;
        assert.deepEqual(value, reportedSecurity);
        if (mode === 'activation-error') throw Error('private timer diagnostic');
      },
    );
    assert.equal(host.hasOwner, false);
    const input = unlockInput();
    const pending = host.unlock(input);
    assert.ok(input.factor.every((byte) => byte === 0));
    if (shouldUnlock) assert.deepEqual(await pending, { unlocked: true, lockedMemory });
    else await assert.rejects(pending, { message: 'Vault policy could not be activated.' });
    assert.ok(borrowed.every((byte) => byte === 0));
    assert.equal(activations, shouldUnlock || mode === 'activation-error' ? 1 : 0);
    assert.equal(stops, shouldUnlock ? 0 : 1);
    assert.equal(host.hasOwner, shouldUnlock);
    await host.stop();
  }
});

test('late unlock policy responses neither activate nor retire a replacement owner', async () => {
  for (const replaced of [false, true]) {
    let finish!: (value: typeof security) => void;
    let policyStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      policyStarted = resolve;
    });
    let spawned = 0,
      stops = 0,
      activations = 0;
    const host = new VaultBackendHost(
      () => {
        spawned++;
        return {
          status: async () => status,
          describe: async () => null,
          catalog: async () => catalog,
          workspace: async () => workspace,
          startup: async () => startup,
          preferences: async () => preferences(),
          security: () => {
            policyStarted();
            return new Promise<typeof security>((resolve) => {
              finish = resolve;
            });
          },
          unlock: async () => ({ unlocked: true, lockedMemory: true }),
          lock: async () => {
            stops++;
          },
        };
      },
      () => true,
      () => {
        activations++;
      },
    );
    const pending = host.unlock(unlockInput());
    await started;
    await host.stop();
    if (replaced) await host.status();
    finish(security);
    await assert.rejects(pending, /policy could not be activated/);
    assert.equal(activations, 0);
    assert.equal(stops, 1);
    assert.equal(spawned, replaced ? 2 : 1);
    assert.equal(host.hasOwner, replaced);
    await host.stop();
  }
});

test('vault host shares its owner and does not replace it until exit is confirmed', async () => {
  let spawned = 0;
  let finish!: () => void;
  let allowed = true;
  const host = new VaultBackendHost(
    () => {
      spawned++;
      return {
        status: async () => status,
        describe: async () => null,
        catalog: async () => catalog,
        workspace: async () => workspace,
        startup: async () => startup,
        preferences: async () => preferences(),
        sshBundle: async () => {
          throw Error('not configured by this metadata fixture');
        },
        security: async () => security,
        unlock: async () => ({ unlocked: true, lockedMemory: true }),
        lock: () =>
          new Promise<void>((resolve) => {
            finish = resolve;
          }),
      };
    },
    () => allowed,
  );
  await host.stop();
  assert.equal(spawned, 0);
  assert.deepEqual(await host.status(), status);
  assert.equal(await host.describe(), null);
  assert.deepEqual(await host.catalog(), catalog);
  assert.deepEqual(await host.workspace(), workspace);
  assert.deepEqual(await host.startup(), startup);
  assert.deepEqual(await host.security(), security);
  assert.equal(spawned, 1);
  const stopping = host.stop();
  assert.equal(host.stop(), stopping);
  await assert.rejects(host.describe(), /stopping/);
  finish();
  await stopping;
  await host.status();
  assert.equal(spawned, 2);
  const second = host.stop();
  finish();
  await second;
  allowed = false;
  await assert.rejects(host.status(), /stopping/);
  assert.equal(spawned, 2);
});

test('unconfirmed vault exit retains the existing owner until a later confirmation', async () => {
  let confirmed = false;
  let spawned = 0;
  const host = new VaultBackendHost(
    () => {
      spawned++;
      return {
        status: async () => status,
        describe: async () => null,
        catalog: async () => catalog,
        workspace: async () => workspace,
        startup: async () => startup,
        preferences: async () => preferences(),
        sshBundle: async () => {
          throw Error('not configured by this metadata fixture');
        },
        security: async () => security,
        unlock: async () => ({ unlocked: true, lockedMemory: true }),
        lock: async () => {
          if (!confirmed) throw Error('unconfirmed');
        },
      };
    },
    () => true,
  );
  await host.status();
  await assert.rejects(host.stop(), /unconfirmed/);
  await host.describe();
  assert.equal(spawned, 1);
  confirmed = true;
  await host.stop();
  await host.status();
  assert.equal(spawned, 2);
  await host.stop();
});

test('vault document trust does not grant packaged apps a development origin bypass', () => {
  const production = 'file:///C:/Wormhole/dist/index.html';
  assert.equal(isTrustedVaultDocument(production + '#settings', production, undefined, true), true);
  assert.equal(
    isTrustedVaultDocument(
      'http://localhost:5173/settings',
      production,
      'http://localhost:5173',
      false,
    ),
    true,
  );
  assert.equal(
    isTrustedVaultDocument('http://127.0.0.1:5173', production, 'http://127.0.0.1:5173', false),
    true,
  );
  assert.equal(
    isTrustedVaultDocument('http://[::1]:5173', production, 'http://[::1]:5173', false),
    true,
  );
  for (const [document, development, packaged] of [
    ['http://localhost:5173', 'http://localhost:5173', true],
    ['https://evil.invalid', 'https://evil.invalid', false],
    ['http://localhost:5174', 'http://localhost:5173', false],
    ['file:///C:/Wormhole/other.html', undefined, true],
    ['file://server/C:/Wormhole/dist/index.html', undefined, true],
    ['invalid', undefined, true],
    ['http://localhost:5173', 'invalid', false],
    ['file:///C:/Wormhole/dist/index.html', 'file:///C:/Wormhole/dist/index.html', false],
  ] as const)
    assert.equal(isTrustedVaultDocument(document, production, development, packaged), false);
});

test('vault IPC verifies sender and refuses extra payloads before and after work', async () => {
  const handlers = new Map<string, (event: any, ...args: unknown[]) => Promise<unknown>>();
  let trusted = true;
  let disposed = false;
  let calls = 0;
  let complete: (() => void) | undefined;
  let delay = false;
  const host = new VaultBackendHost(
    () => ({
      status: async () => {
        calls++;
        if (delay)
          await new Promise<void>((resolve) => {
            complete = resolve;
          });
        return status;
      },
      describe: async () => null,
      catalog: async () => catalog,
      workspace: async () => workspace,
      startup: async () => startup,
      preferences: async () => preferences(),
      sshBundle: async () => {
        throw Error('not configured by this metadata fixture');
      },
      security: async () => security,
      unlock: async () => ({ unlocked: true, lockedMemory: true }),
      lock: async () => undefined,
    }),
    () => true,
  );
  registerVaultIpc(
    {
      handle: (channel: string, handler: any) => {
        handlers.set(channel, handler);
      },
    },
    host,
    () => {
      if (disposed) throw Error('private native frame diagnostic');
      return trusted;
    },
  );
  assert.deepEqual(
    [...handlers.keys()],
    [
      'vault:status',
      'vault:describe',
      'vault:catalog',
      'vault:workspace',
      'vault:startup',
      'vault:sftp-recovery-scopes',
      'vault:sftp-recovery-records',
      'vault:edit-credential',
      'vault:delete-tunnel',
      'vault:delete-credential',
      'vault:migration-report',
      'vault:migration-decide',
      'vault:save-connection',
      'vault:save-folder',
      'vault:delete-nodes',
      'vault:move-nodes',
      'vault:duplicate-connection',
      'vault:unlock',
    ],
  );
  const read = handlers.get('vault:status')!;
  assert.deepEqual(await read({}), status);
  assert.equal(await handlers.get('vault:describe')!({}), null);
  assert.deepEqual(await handlers.get('vault:catalog')!({}), catalog);
  await assert.rejects(handlers.get('vault:catalog')!({}, {}), /Invalid/);
  assert.deepEqual(await handlers.get('vault:workspace')!({}), workspace);
  await assert.rejects(handlers.get('vault:workspace')!({}, {}), /Invalid/);
  assert.deepEqual(await handlers.get('vault:startup')!({}), startup);
  await assert.rejects(handlers.get('vault:startup')!({}, {}), /Invalid/);
  await assert.rejects(read({}, { password: 'never-forward' }), /Invalid/);
  trusted = false;
  await assert.rejects(read({}), /Invalid/);
  assert.equal(calls, 1);
  disposed = true;
  await assert.rejects(read({}), { message: 'Invalid vault request.' });
  disposed = false;
  trusted = true;
  delay = true;
  const pending = read({});
  await new Promise<void>((resolve) => setImmediate(resolve));
  disposed = true;
  complete!();
  await assert.rejects(pending, /no longer available/);
  await host.stop();
});

test('unlock IPC consumes factors and retires the owner when the submitting document disappears', async () => {
  for (const mode of [
    'success',
    'failure',
    'untrusted',
    'extra',
    'navigate-success',
    'navigate-failure',
    'stopping',
  ] as const) {
    const handlers = new Map<string, (event: any, ...args: unknown[]) => Promise<unknown>>();
    let trusted = mode !== 'untrusted';
    let calls = 0;
    let stops = 0;
    let borrowed: Uint8Array | undefined;
    const host = new VaultBackendHost(
      () => ({
        status: async () => status,
        describe: async () => null,
        catalog: async () => catalog,
        workspace: async () => workspace,
        startup: async () => startup,
        preferences: async () => preferences(),
        sshBundle: async () => {
          throw Error('not configured by this metadata fixture');
        },
        security: async () => security,
        unlock: async (value) => {
          calls++;
          borrowed = (value as { factor: Uint8Array }).factor;
          assert.deepEqual([...borrowed], [1, 2, 3]);
          if (mode.startsWith('navigate')) trusted = false;
          if (mode.endsWith('failure')) throw Error('Vault operation failed.');
          return { unlocked: true, lockedMemory: true };
        },
        lock: async () => {
          stops++;
        },
      }),
      () => mode !== 'stopping',
    );
    registerVaultIpc(
      {
        handle: (channel: string, handler: any) => {
          handlers.set(channel, handler);
        },
      },
      host,
      () => trusted,
    );
    const factor = new Uint8Array([1, 2, 3]);
    const input = {
      vaultId: '11111111-1111-4111-8111-111111111111',
      slotId: '22222222-2222-4222-8222-222222222222',
      kind: 'password',
      factor,
    };
    const pending = handlers.get('vault:unlock')!({}, input, ...(mode === 'extra' ? [{}] : []));
    assert.ok(factor.every((byte) => byte === 0));
    if (mode === 'success') assert.deepEqual(await pending, { unlocked: true, lockedMemory: true });
    else
      await assert.rejects(
        pending,
        mode.startsWith('navigate') ? /no longer available/ : /Invalid|failed|stopping/,
      );
    assert.ok(!borrowed || borrowed.every((byte) => byte === 0));
    assert.equal(calls, ['untrusted', 'extra', 'stopping'].includes(mode) ? 0 : 1);
    assert.equal(stops, mode.startsWith('navigate') ? 1 : 0);
    await host.stop();
  }
});

test('workspace selection survives locking and rejects missing or replaced public identity', async () => {
  let descriptor: any = null;
  let finish: ((value: any) => void) | undefined;
  let delay = false;
  const client = {
    status: async () => status,
    describe: async () => descriptor,
    catalog: async () => catalog,
    workspace: async () => workspace,
    security: async () => security,
    startup: async () =>
      delay
        ? new Promise<any>((resolve) => {
            finish = resolve;
          })
        : { ...startup, slots: descriptor },
    preferences: async () => preferences(),
    sshBundle: async (q: any) => sshBundle(q),
    unlock: async () => ({ unlocked: true as const, lockedMemory: true as const }),
    lock: async () => {},
  };
  let allowed = true;
  const host = new VaultBackendHost(
    () => ({ ...client }),
    () => allowed,
  );
  await assert.rejects(host.preferences(), /locked/);
  assert.equal(host.hasOwner, false);
  await host.startup();
  assert.equal(host.hasOwner, true);
  assert.equal(host.isVaultWorkspace, false);
  descriptor = { formatVersion: 1, vaultId: unlockInput().vaultId, encrypted: true, slots: [] };
  await host.describe();
  assert.equal(host.isVaultWorkspace, true);
  await assert.rejects(
    host.unlock({ ...unlockInput(), vaultId: sshRequest().workspaceId }),
    /identity/,
  );
  await host.unlock(unlockInput());
  assert.deepEqual(await host.preferences(), preferences());
  await host.stop();
  assert.equal(host.isVaultWorkspace, true);
  assert.equal(host.unlockedWorkspaceId, undefined);
  await host.startup();
  descriptor = null;
  await assert.rejects(host.startup(), /identity/);
  descriptor = { formatVersion: 1, vaultId: sshRequest().workspaceId, encrypted: true, slots: [] };
  await assert.rejects(host.describe(), /identity/);
  for (const phase of ['stop', 'replace', 'disallow']) {
    delay = true;
    const pending = host.startup();
    if (phase === 'disallow') allowed = false;
    else {
      await host.stop();
      if (phase === 'replace') await host.status();
    }
    finish!({ ...startup, slots: descriptor });
    await assert.rejects(pending, /stopping/);
    allowed = true;
  }
  await host.stop();
});

test('preferences cannot outlive the authenticated owner', async () => {
  let finish!: (value: any) => void;
  const host = new VaultBackendHost(
    () => ({
      status: async () => status,
      describe: async () => null,
      catalog: async () => catalog,
      workspace: async () => workspace,
      startup: async () => startup,
      security: async () => security,
      sshBundle: async (q) => sshBundle(q),
      preferences: () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
      unlock: async () => ({ unlocked: true, lockedMemory: true }),
      lock: async () => {},
    }),
    () => true,
  );
  await host.unlock(unlockInput());
  const pending = host.preferences();
  await host.stop();
  await host.unlock(unlockInput());
  finish(preferences());
  await assert.rejects(pending, /locked/);
  await host.stop();
});

test('IPC publishes app authorization only for a live trusted unlock and retires failed activation', async () => {
  for (const mode of ['ok', 'hook-fails', 'late-lock']) {
    const handlers = new Map<string, any>();
    let activated = 0;
    let retired = 0;
    const host = {
      unlock: async () => ({ unlocked: true, lockedMemory: true }),
      get unlockedWorkspaceId() {
        return mode === 'late-lock' ? undefined : unlockInput().vaultId;
      },
      stop: async () => {
        retired++;
      },
    } as unknown as VaultBackendHost;
    registerVaultIpc(
      {
        handle: (channel, handler) => {
          handlers.set(channel, handler);
        },
      },
      host,
      () => true,
      () => {
        activated++;
        if (mode === 'hook-fails') throw Error('private diagnostic');
      },
    );
    const pending = handlers.get('vault:unlock')({}, unlockInput());
    if (mode === 'ok') assert.deepEqual(await pending, { unlocked: true, lockedMemory: true });
    else await assert.rejects(pending, /session could not be activated/);
    assert.equal(activated, mode === 'late-lock' ? 0 : 1);
    assert.equal(retired, mode === 'ok' ? 0 : 1);
  }
});

test('tunnel deletion IPC binds authorization before and after native mutation', async () => {
  for (const mode of ['valid', 'untrusted', 'extra', 'retired', 'failed']) {
    const handlers = new Map<string, any>();
    let trusted = mode !== 'untrusted',
      calls = 0;
    const input = { id: '11111111-1111-4111-8111-111111111111', rowVersion: '4' };
    const result = { ...input, rowVersion: '5', deleted: true };
    const confirm = async () => null;
    registerVaultIpc(
      { handle: (name, handler) => handlers.set(name, handler) },
      {
        deleteTunnel: async (value: any, confirmation: any, accepted: () => boolean) => {
          calls++;
          assert.deepEqual(value, input);
          assert.equal(confirmation, confirm);
          assert.equal(accepted(), true);
          if (mode === 'failed') throw Error('Tunnel deletion failed.');
          if (mode === 'retired') trusted = false;
          return result;
        },
      } as unknown as VaultBackendHost,
      () => trusted,
      undefined,
      () => confirm,
    );
    const pending = handlers.get('vault:delete-tunnel')(
      {},
      input,
      ...(mode === 'extra' ? [true] : []),
    );
    if (mode === 'valid') assert.deepEqual(await pending, result);
    else await assert.rejects(pending);
    assert.equal(calls, mode === 'untrusted' || mode === 'extra' ? 0 : 1);
  }
});

test('offline recovery IPC checks exact arity and document ownership around asynchronous work', async () => {
  const handlers = new Map<string, any>();
  let trusted = true,
    calls = 0,
    finish!: (v: any) => void,
    delay = false;
  const scopes = { nodeIds: [], after: '' };
  const records = { edits: [], after: '', busy: false };
  const read = async (result: typeof scopes | typeof records) => {
    calls++;
    return delay
      ? new Promise((resolve) => {
          finish = resolve;
        })
      : result;
  };
  registerVaultIpc(
    { handle: (name: string, fn: any) => handlers.set(name, fn) } as any,
    { sftpRecoveryScopes: () => read(scopes), sftpRecoveryRecords: () => read(records) } as any,
    () => trusted,
  );
  for (const [name, arg, result] of [
    ['vault:sftp-recovery-scopes', '', scopes],
    ['vault:sftp-recovery-records', { nodeId: 'node', operation: 'list' }, records],
  ] as const) {
    const fn = handlers.get(name);
    assert.deepEqual(await fn({}, arg), result);
    await assert.rejects(fn({}), /Invalid/);
    await assert.rejects(fn({}, arg, {}), /Invalid/);
    trusted = false;
    const before = calls;
    await assert.rejects(fn({}, arg), /Invalid/);
    assert.equal(calls, before);
    trusted = true;
    delay = true;
    const pending = fn({}, arg);
    trusted = false;
    finish(result);
    await assert.rejects(pending, /no longer/);
    trusted = true;
    delay = false;
  }
  await assert.rejects(handlers.get('vault:sftp-recovery-scopes')({}, {}), /Invalid/);
});

test('offline reveal opens the native-authorized folder in main and returns public fields', async () => {
  const handlers = new Map<string, any>();
  const response = { edits: [], after: '', busy: false };
  const opened: string[] = [];
  let trusted = true;
  let replacement = false;
  let loseOwnerDuringRead = false;
  let loseOwnerDuringOpen = false;
  let lockDuringOpen = false;
  let failOpen = false;
  const host = {
    unlockedWorkspaceId: 'admitted',
    sftpRecoveryRecords: async () => {
      if (replacement) host.unlockedWorkspaceId = 'replacement';
      if (loseOwnerDuringRead) trusted = false;
      return { ...response, revealPath: 'private recovery directory', nativeOnly: true };
    },
  };
  registerVaultIpc(
    { handle: (name: string, fn: any) => handlers.set(name, fn) } as any,
    host as any,
    () => trusted,
    undefined,
    undefined,
    undefined,
    async (folder) => {
      opened.push(folder);
      if (loseOwnerDuringOpen) trusted = false;
      if (lockDuringOpen) host.unlockedWorkspaceId = '';
      return failOpen ? folder : '';
    },
  );
  const reveal = handlers.get('vault:sftp-recovery-records');
  assert.deepEqual(await reveal({}, {}), response);
  assert.deepEqual(opened, ['private recovery directory']);
  replacement = true;
  await assert.rejects(reveal({}, {}), /unavailable/);
  replacement = false;
  loseOwnerDuringRead = true;
  await assert.rejects(reveal({}, {}), /no longer/);
  assert.equal(opened.length, 1);
  loseOwnerDuringRead = false;
  trusted = true;
  failOpen = true;
  await assert.rejects(reveal({}, {}), { message: 'Recovery folder could not be opened.' });
  failOpen = false;
  lockDuringOpen = true;
  await assert.rejects(reveal({}, {}), /no longer/);
  host.unlockedWorkspaceId = 'admitted';
  lockDuringOpen = false;
  loseOwnerDuringOpen = true;
  await assert.rejects(reveal({}, {}), /no longer/);
});

test('VNC handoffs reject locked, stale, rejected-owner and cross-workspace requests', async () => {
  for (const routed of [false, true]) {
    let finish!: (value: any) => void,
      calls = 0,
      accepted = true;
    const client: any = {
      status: async () => status,
      describe: async () => null,
      startup: async () => startup,
      security: async () => security,
      unlock: async () => ({ unlocked: true, lockedMemory: true }),
      lock: async () => {},
      vncBundle: () => {
        calls++;
        return new Promise((resolve) => {
          finish = resolve;
        });
      },
      routedVncBundle: () => {
        calls++;
        return new Promise((resolve) => {
          finish = resolve;
        });
      },
    };
    const host = new VaultBackendHost(
      () => ({ ...client }),
      () => true,
    );
    const q = routed ? routedVncRequest() : vncRequest();
    q.workspaceId = unlockInput().vaultId;
    if (routed) (q as any).route.workspaceId = q.workspaceId;
    const method = routed ? 'routedVncBundle' : 'vncBundle';
    await assert.rejects(host[method]({ ...q, epoch: 0 }), /Invalid/);
    await assert.rejects(host[method](q), /locked/);
    assert.equal(calls, 0);
    await host.unlock(unlockInput());
    await assert.rejects(
      host[method]({ ...q, workspaceId: vncRequest().workspaceId }),
      /locked|Invalid/,
    );
    await assert.rejects(
      host[method](q, () => false),
      /locked/,
    );
    const reply = routed ? routedVncBundle(q as any) : vncBundle(q);
    const success = host[method](q);
    finish(reply);
    assert.deepEqual(await success, reply);
    const owner = host[method](q, () => accepted);
    accepted = false;
    finish(reply);
    await assert.rejects(owner, /locked/);
    const stale = host[method](q);
    await host.stop();
    await host.unlock(unlockInput());
    finish(reply);
    await assert.rejects(stale, /locked/);
    await host.stop();
  }
});

test('RDP handoffs reject locked, stale, rejected-owner and cross-workspace requests', async () => {
  for (const routed of [false, true]) {
    let finish!: (value: any) => void,
      calls = 0,
      accepted = true;
    const client: any = {
      status: async () => status,
      describe: async () => null,
      startup: async () => startup,
      security: async () => security,
      unlock: async () => ({ unlocked: true, lockedMemory: true }),
      lock: async () => {},
      rdpBundle: () => {
        calls++;
        return new Promise((resolve) => {
          finish = resolve;
        });
      },
      routedRdpBundle: () => {
        calls++;
        return new Promise((resolve) => {
          finish = resolve;
        });
      },
    };
    const host = new VaultBackendHost(
      () => ({ ...client }),
      () => true,
    );
    const q = routed ? routedRdpRequest() : rdpRequest();
    q.workspaceId = unlockInput().vaultId;
    if (routed) (q as any).route.workspaceId = q.workspaceId;
    const method = routed ? 'routedRdpBundle' : 'rdpBundle';
    await assert.rejects(host[method]({ ...q, epoch: 0 }), /Invalid/);
    await assert.rejects(host[method](q), /locked/);
    assert.equal(calls, 0);
    await host.unlock(unlockInput());
    await assert.rejects(
      host[method]({ ...q, workspaceId: rdpRequest().workspaceId }),
      /locked|Invalid/,
    );
    await assert.rejects(
      host[method](q, () => false),
      /locked/,
    );
    const reply = routed ? routedRdpBundle(q as any) : rdpBundle(q);
    const success = host[method](q);
    finish(reply);
    assert.deepEqual(await success, reply);
    const owner = host[method](q, () => accepted);
    accepted = false;
    finish(reply);
    await assert.rejects(owner, /locked/);
    const stale = host[method](q);
    await host.stop();
    await host.unlock(unlockInput());
    finish(reply);
    await assert.rejects(stale, /locked/);
    await host.stop();
  }
});

test('native migration admission binds fresh startup identity and cannot survive a replaced owner', async (t) => {
  const profiler =
    process.execArgv.includes('--experimental-test-coverage') || process.env.NODE_V8_COVERAGE
      ? undefined
      : new Session();
  if (profiler) {
    profiler.connect();
    t.after(() => profiler.disconnect());
    await profiler.post('Profiler.enable');
    await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  }
  for (const kind of ['migration', 'rotation'] as const)
    for (const mode of [
      'ok',
      'not pending',
      'wrong workspace',
      'late metadata',
      'late result',
      'native error',
    ]) {
      const method = kind === 'migration' ? 'resumeMigration' : 'resumeRootRotation';
      let finish!: (value: any) => void,
        calls = 0,
        activated = 0;
      const input = unlockInput();
      const hints = {
        slots: {
          formatVersion: kind === 'migration' ? 1 : 3,
          vaultId: input.vaultId,
          encrypted: false,
          slots: [],
        },
        [kind]: { pending: true },
        cosmetics: { theme: 'system' },
        newWorkspace: false,
      };
      const client: any = {
        startup: () =>
          mode === 'late metadata'
            ? new Promise((resolve) => {
                finish = resolve;
              })
            : Promise.resolve(
                mode === 'not pending'
                  ? { ...hints, [kind]: undefined }
                  : mode === 'wrong workspace'
                    ? { ...hints, slots: { ...hints.slots, vaultId: 'other' } }
                    : hints,
              ),
        [method]: async () => {
          calls++;
          if (mode === 'native error') throw Error('factor rejected');
          if (mode === 'late result')
            return new Promise((resolve) => {
              finish = resolve;
            });
          return { unlocked: true, lockedMemory: true };
        },
        security: async () => security,
        lock: async () => {},
      };
      const host = new VaultBackendHost(
        () => client,
        () => true,
        () => {
          activated++;
        },
      );
      const request = host[method](input);
      const checked = mode === 'ok' ? request : assert.rejects(request);
      if (mode.startsWith('late')) {
        for (let i = 0; i < 4 && !finish; i++) await Promise.resolve();
        await host.stop();
        finish(mode === 'late metadata' ? hints : { unlocked: true, lockedMemory: true });
      }
      await checked;
      assert.ok(input.factor.every((x) => x === 0));
      assert.equal(activated, mode === 'ok' ? 1 : 0);
      if (mode === 'ok') {
        await assert.rejects(host[method](unlockInput()), /unavailable/);
        assert.equal(calls, 1);
      } else assert.equal(host.unlockedWorkspaceId, undefined);
      await host.stop();
    }
  if (!profiler) return;
  const coverage = await profiler.post('Profiler.takePreciseCoverage');
  const ranges = coverage.result
    .filter((s) => s.url.endsWith('/electron/vault-host.ts'))
    .flatMap((s) => s.functions)
    .filter((f) =>
      ['resumeMigration', 'resumeRootRotation', 'resumeMaintenance'].includes(f.functionName),
    )
    .flatMap((f) => f.ranges);
  assert.ok(ranges.length);
  const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
  t.diagnostic('migration host ' + percent.toFixed(2) + '% V8 blocks');
  assert.ok(percent >= coverageThreshold);
});
