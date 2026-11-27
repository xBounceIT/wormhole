import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import { VaultCrashCapturePolicy } from '../electron/crash-diagnostics.ts';
import { declarations } from './fixtures/main-source.ts';

// Entrypoint wiring only: protocol, process and IPC semantics have executable tests.
test('vault bridge is restricted to the registered main document and shutdown lifecycle', () => {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const sender = main.slice(
    main.indexOf('function isTrustedVaultSender('),
    main.indexOf('async function runBackend<'),
  );
  for (const guard of [
    'event.sender.isDestroyed()',
    'owner.isDestroyed()',
    'windowCloseCoordinators.has(owner)',
    'frame !== event.sender.mainFrame',
    'isTrustedVaultDocument(',
    'app.isPackaged',
  ])
    assert.ok(sender.includes(guard), guard);
  const host = main.slice(
    main.indexOf('const vaultBackend ='),
    main.indexOf('function isTrustedVaultSender('),
  );
  assert.ok(host.includes('!isQuitting && !authLockRequested && !nativeResourceShutdownPromise'));
  assert.ok(host.includes('vaultLockMonitor.deactivate()'));
  assert.ok(host.includes('if (!authLockRequested && !isQuitting) requestAutomaticVaultLock()'));
  assert.ok(host.includes('(security) => vaultLockMonitor.activate(security)'));
  assert.match(main, /vaultWindowPolicy\.apply\(profile\)/);
  assert.equal(main.match(/new BrowserWindow\(/g)?.length, 1);
  assert.match(main, /vaultWindowPolicy\.createWindow\(options\)/);
  assert.ok(main.includes('bindVaultPowerEvents(powerMonitor, requestAutomaticVaultLock)'));
  assert.match(
    main,
    /if \(process\.platform === 'linux' \|\| process\.platform === 'win32'\) \{\s*app\.once\(\s*'will-quit',\s*bindNativeVaultSession\(process\.platform, backendPath, requestAutomaticVaultLock, \{\s*beginSleep: beginLinuxVaultSleep,/,
  );
  assert.ok(main.includes("window.on('minimize', () => vaultLockMonitor.minimized())"));
  assert.match(main, /registerVaultIpc\(\s*ipcMain,\s*vaultBackend,\s*isTrustedVaultSender,/);
  const shutdown = main.slice(
    main.indexOf('function shutdownNativeResources()'),
    main.indexOf('function scheduleUnlockedBackgroundWork()'),
  );
  assert.ok(shutdown.includes('vaultBackend.stop()'));
  assert.match(
    shutdown,
    /results\[2\]\.status === 'rejected'\) throw new Error\('Vault shutdown could not be confirmed\.'/,
  );
  const lock = main.slice(
    main.indexOf('async function lockApplication('),
    main.indexOf('function registerIpcHandlers('),
  );
  assert.ok(lock.includes('const vaultStopped = vaultBackend.stop().then('));
  assert.ok(lock.includes('await vaultStopped'));
  assert.ok(lock.includes('stopVaultBitwardenCLIUnlock().then('));
  assert.ok(lock.includes('await bitwardenCLIStopped'));
  assert.ok(shutdown.includes('stopVaultBitwardenCLIUnlock()'));
  const preload = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
  assert.match(preload, /getVaultStatus: \(\) => ipcRenderer.invoke\('vault:status'\)/);
  assert.match(preload, /getVaultDescriptor: \(\) => ipcRenderer.invoke\('vault:describe'\)/);
  assert.match(preload, /loadVaultCatalog: \(\) => ipcRenderer.invoke\('vault:catalog'\)/);
  assert.match(preload, /loadVaultWorkspace: \(\) => ipcRenderer.invoke\('vault:workspace'\)/);
  assert.match(preload, /loadVaultStartup: \(\) => ipcRenderer.invoke\('vault:startup'\)/);
  assert.match(preload, /ipcRenderer.invoke\('vault:unlock', request\)/);
  assert.match(
    preload,
    /unlockVaultBitwardenCLI: \(\) => ipcRenderer.invoke\('vault:bitwarden-cli-unlock'\)/,
  );
  assert.match(preload, /request.factor.fill\(0\)/);
  assert.doesNotMatch(preload, /ipcRenderer.invoke\('vault:(?:initialize|request)'/);
});

test('pre-suspend uses the main authorization barrier around confirmed vault retirement', async () => {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  let holds = 0;
  let retirements = 0;
  let finish!: () => void;
  const workspace = { isVaultWorkspace: true, hasOwner: true };
  const binding = runInNewContext(
    stripTypeScriptTypes(
      declarations(main, [
        'hasAutomaticVaultLockTarget',
        'beginLinuxVaultSleep',
        'holdApplicationLock',
      ]) + '\n({ begin: beginLinuxVaultSleep, held: () => authLockRequested });',
    ),
    {
      authLocksInProgress: 0,
      authLockRequested: false,
      authSession: {
        holdLock: () => {
          holds++;
          return () => holds--;
        },
      },
      vaultBackend: workspace,
      vaultCreateDialog: { active: false },
      vaultOSMigrationDialog: { active: false },
      vaultMigrationSetupDialog: { active: false },
      vaultSharedSetupDialog: { active: false },
      lockApplication: (_sender: undefined, options: { refreshLegacy: boolean }) => {
        assert.equal(holds, 1);
        assert.equal(options.refreshLegacy, false);
        retirements++;
        return new Promise<void>((resolve) => (finish = resolve));
      },
    },
  );
  const active = binding.begin();
  assert.equal(binding.held(), true);
  assert.equal(retirements, 1);
  finish();
  await active.retired;
  assert.equal(binding.held(), true);
  active.release();
  assert.equal(binding.held(), false);
  workspace.isVaultWorkspace = false;
  workspace.hasOwner = false;
  const inactive = binding.begin();
  await inactive.retired;
  assert.equal(retirements, 1);
  assert.equal(binding.held(), true);
  inactive.release();
  assert.equal(holds, 0);
});

function profileApplication(
  platform: string,
  vaultCrashCapture: Pick<VaultCrashCapturePolicy, 'apply'>,
) {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  let required = false;
  let retiredUpdates = 0;
  const apply = runInNewContext(
    stripTypeScriptTypes(
      declarations(main, ['vaultLockMonitor']) + '\nvaultLockMonitor.applyProfile;',
    ),
    {
      process: { platform },
      vaultCrashCapture,
      retireVaultUpdates: () => retiredUpdates++,
      VaultLockMonitor: class {
        constructor(options: { applyProfile: unknown }) {
          return options;
        }
      },
      vaultWindowPolicy: {
        get requiresContentProtection() {
          return required;
        },
        apply(profile: string) {
          required = profile === 'hardened' || profile === 'paranoid';
        },
      },
    },
  );
  return { apply, needsProtection: () => required, retiredUpdates: () => retiredUpdates };
}

test('Windows retires existing native overlays when the authenticated policy first requires capture exclusion', () => {
  for (const platform of ['win32', 'darwin']) {
    const { apply, needsProtection, retiredUpdates } = profileApplication(platform, { apply() {} });
    apply('standard', 'unlock');
    assert.equal(retiredUpdates(), 0);
    if (platform === 'win32') assert.throws(() => apply('hardened', 'refresh'), /new vault unlock/);
    else apply('hardened', 'refresh');
    assert.equal(needsProtection(), true);
    apply('hardened', 'unlock');
    apply('paranoid', 'refresh');
    assert.equal(needsProtection(), true);
    assert.equal(retiredUpdates(), 2);
  }
});

test('main refuses strict admission and policy refresh after it has started Crashpad', () => {
  let starts = 0;
  const start = () => starts++;
  const current = profileApplication('win32', new VaultCrashCapturePolicy(start));
  current.apply('standard', 'unlock');
  assert.throws(() => current.apply('hardened', 'refresh'), /requires a fresh app process/);
  assert.throws(() => current.apply('paranoid', 'unlock'), /requires a fresh app process/);
  assert.equal(current.needsProtection(), false);

  const fresh = profileApplication('win32', new VaultCrashCapturePolicy(start));
  fresh.apply('paranoid', 'unlock');
  assert.equal(fresh.needsProtection(), true);
  assert.equal(starts, 1);
});
