import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import { transformWithOxc } from 'vite';
import { readBitwardenStartupState } from '../electron/bitwarden-startup.ts';
import { bitwardenCliAuthMode } from '../src/bitwarden-cli-view.ts';
import { prepareWorkspaceStartup } from '../src/bitwarden-startup-gate.ts';

const enabled = { enabled: true, installed: {}, serverRegion: 'Europe' as const };
const loggedOut = { status: 'Unauthenticated' as const, serverUrl: null, hasSessionKey: false };

function backend(): Parameters<typeof readBitwardenStartupState>[0] & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    readState: async () => {
      calls.push('read');
      return enabled;
    },
    ensureInstalled: async () => {
      calls.push('install');
      return enabled;
    },
    readStatus: async () => {
      calls.push('status');
      return loggedOut;
    },
    requireAuthorization: () => {
      calls.push('authorize');
    },
  };
}

test('startup ignores a disabled credential integration without reading its status or installing', async () => {
  const api = backend();
  api.readState = async () => ({ ...enabled, enabled: false });
  assert.equal(await readBitwardenStartupState(api), null);
  assert.deepEqual(api.calls, ['authorize']);
});

test('startup returns the configured region and fresh credential session status', async () => {
  const api = backend();
  assert.deepEqual(await readBitwardenStartupState(api), {
    serverRegion: 'Europe',
    status: loggedOut,
  });
  assert.deepEqual(api.calls, ['read', 'authorize', 'status', 'authorize']);
});

test('startup waits for a missing CLI before deciding which authentication to show', async () => {
  const api = backend();
  api.readState = async () => ({ ...enabled, installed: null });
  assert.deepEqual(await readBitwardenStartupState(api), {
    serverRegion: 'Europe',
    status: loggedOut,
  });
  assert.deepEqual(api.calls, ['authorize', 'install', 'authorize', 'status', 'authorize']);

  for (const state of [
    { ...enabled, installed: null },
    { ...enabled, enabled: false },
  ]) {
    api.calls.length = 0;
    api.ensureInstalled = async () => state;
    assert.equal(await readBitwardenStartupState(api), null);
    assert.deepEqual(api.calls, ['authorize', 'authorize']);
  }
});

test('startup stops after authorization is lost at every asynchronous boundary', async () => {
  for (const step of [1, 2, 3]) {
    const api = backend();
    api.readState = async () => ({ ...enabled, installed: null });
    let authorizationChecks = 0;
    api.requireAuthorization = () => {
      if (++authorizationChecks === step) throw new Error('Workspace locked');
    };
    await assert.rejects(readBitwardenStartupState(api), /Workspace locked/);
    assert.deepEqual(api.calls, step === 1 ? [] : step === 2 ? ['install'] : ['install', 'status']);
  }
});

test('startup propagates read, installation and status failures without requesting credentials', async () => {
  for (const operation of ['readState', 'ensureInstalled', 'readStatus'] as const) {
    const api = backend();
    api.readState = async () => ({ ...enabled, installed: null });
    api[operation] = async () => {
      throw new Error('Vault unavailable');
    };
    await assert.rejects(readBitwardenStartupState(api), /Vault unavailable/);
    assert.equal(api.calls.includes('status'), false);
  }
});

test('startup selects login or unlock from the native vault session, not the HTTPS extension', () => {
  for (const hasSessionKey of [false, true, undefined]) {
    assert.equal(bitwardenCliAuthMode({ status: 'Unauthenticated', hasSessionKey }), 'login');
    for (const status of ['Locked', 'Unlocked'] as const) {
      assert.equal(
        bitwardenCliAuthMode({ status, hasSessionKey }),
        hasSessionKey ? null : 'unlock',
      );
    }
    assert.equal(bitwardenCliAuthMode({ status: 'Unknown', hasSessionKey }), null);
  }
});

test('workspace startup waits for the Bitwarden decision before exposing the workspace', async () => {
  let releaseBitwarden!: (state: typeof loggedOut) => void;
  const bitwarden = new Promise<typeof loggedOut>((resolve) => {
    releaseBitwarden = resolve;
  });
  const workspace = { tree: ['ready'] };
  let settled = false;
  const prepared = prepareWorkspaceStartup(
    { readBitwardenStartupState: () => bitwarden.then((status) => ({ ...enabled, status })) },
    workspace,
  ).finally(() => {
    settled = true;
  });

  await Promise.resolve();
  assert.equal(settled, false, 'the workspace became interactive before Bitwarden was ready');

  releaseBitwarden(loggedOut);
  assert.deepEqual(await prepared, {
    workspace,
    bitwarden: { ...enabled, status: loggedOut },
  });
});

test('workspace startup remains available when the optional Bitwarden check fails', async () => {
  const workspace = { tree: ['ready'] };
  assert.deepEqual(
    await prepareWorkspaceStartup(
      {
        readBitwardenStartupState: async () => {
          throw new Error('Vault unavailable');
        },
      },
      workspace,
    ),
    { workspace, bitwarden: null },
  );
});

test('workspace startup never swallows authorization loss as an optional Bitwarden failure', async () => {
  await assert.rejects(
    prepareWorkspaceStartup(
      {
        readBitwardenStartupState: async () => {
          throw new Error(
            "Error invoking remote method 'bitwarden:startup-state': Authentication is required before accessing the Wormhole workspace.",
          );
        },
      },
      { tree: ['private'] },
    ),
    /Authentication is required/,
  );
});

test('all initial unlock paths preload Bitwarden before mounting the workspace', () => {
  const startupSource = readFileSync(new URL('../src/main.tsx', import.meta.url), 'utf8');
  const appSource = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  assert.equal(
    startupSource.match(/prepareWorkspaceStartup\(/g)?.length,
    3,
    'Windows Hello, secret unlock, and disabled Wormhole auth must all use the startup gate',
  );
  assert.equal(
    startupSource.match(
      /await mountWorkspace\(startup, prepared\.workspace, prepared\.bitwarden\);/g,
    )?.length,
    3,
  );
  assert.match(
    appSource,
    /useState<BitwardenStartupPromptState \| null>\(\(\) =>\s*bitwardenStartupPromptState\(initialState\)/,
    'the preloaded prompt must be open on the first workspace render',
  );
});

test('the startup IPC handler authorizes access and calls only the credential backend', async () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const start = source.indexOf("  ipcMain.handle('bitwarden:startup-state'");
  const end = source.indexOf("  ipcMain.handle('bitwarden:set-enabled'", start);
  assert.ok(start >= 0 && end > start);
  const { code } = await transformWithOxc(source.slice(start, end), 'startup-handler.ts');
  let handler: () => Promise<unknown>;
  let authorized = false;
  const calls: string[] = [];
  runInNewContext(code, {
    ipcMain: {
      handle: (channel: string, callback: typeof handler) => {
        assert.equal(channel, 'bitwarden:startup-state');
        handler = callback;
      },
    },
    readBitwardenStartupState,
    runAuthorizedOperation: async (operation: (epoch: number) => Promise<unknown>) => {
      if (!authorized) throw new Error('Workspace locked');
      return operation(42);
    },
    requireAuthorizationEpoch: (epoch: number) => assert.equal(epoch, 42),
    runBitwardenBackend: async (action: string) => {
      calls.push(action);
      if (action === 'bitwarden.read') return { ...enabled, installed: null };
      if (action === 'bitwarden.ensure-installed') return enabled;
      if (action === 'bitwarden.status') return loggedOut;
      assert.fail(`Unexpected backend action: ${action}`);
    },
  });
  await assert.rejects(handler!(), /Workspace locked/);
  assert.deepEqual(calls, []);
  authorized = true;
  assert.deepEqual(await handler!(), { serverRegion: 'Europe', status: loggedOut });
  assert.deepEqual(calls, ['bitwarden.read', 'bitwarden.ensure-installed', 'bitwarden.status']);
});

test('background maintenance syncs enabled vaults without repeating a failed startup installation', async () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const slice = (start: string, end: string) => {
    const first = source.indexOf(start);
    const last = source.indexOf(end, first);
    assert.ok(first >= 0 && last > first);
    return source.slice(first, last);
  };
  const { code } = await transformWithOxc(
    'let bitwardenStartupMaintenancePromise;\n' +
      slice(
        'async function runBitwardenCredentialMaintenance',
        'async function runBitwardenExtensionStartupMaintenance',
      ) +
      slice(
        'function runBitwardenStartupMaintenance',
        'function startBitwardenBackgroundMaintenance',
      ),
    'startup-maintenance.ts',
  );
  let installs = 0;
  let syncs = 0;
  const api = backend();
  api.readState = async () => ({ ...enabled, installed: null });
  api.ensureInstalled = async () => {
    installs++;
    throw new Error('Download unavailable');
  };
  const maintenance = runInNewContext(code + '\nrunBitwardenStartupMaintenance;', {
    isQuitting: false,
    authSession: { isAccessAllowed: true, authorizationEpoch: 1 },
    isAuthorizationEpochCurrent: () => true,
    runBitwardenExtensionStartupMaintenance: async () => {},
    runBitwardenBackend: async (action: string) => {
      if (action === 'bitwarden.read') return api.readState();
      if (action === 'bitwarden.ensure-installed') return api.ensureInstalled();
      if (action === 'bitwarden.sync-if-stale') return syncs++;
      assert.fail(`Unexpected maintenance action: ${action}`);
    },
    console: { warn: () => {} },
  }) as () => Promise<void>;
  await assert.rejects(readBitwardenStartupState(api), /Download unavailable/);
  await maintenance();
  assert.equal(installs, 1, 'startup and background work must not install the same CLI twice');
  assert.equal(syncs, 0);
  api.readState = async () => enabled;
  await maintenance();
  assert.equal(syncs, 1, 'installed and enabled vaults must keep their background sync');
  api.readState = async () => ({ ...enabled, enabled: false });
  await maintenance();
  assert.equal(syncs, 1, 'disabled vaults must not sync');
});
