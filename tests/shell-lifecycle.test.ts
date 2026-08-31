import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import { selectDialogVisuals } from '../src/dialog-lifecycle.ts';
import {
  readDarwinHardwareModel,
  shouldDisableHardwareAcceleration,
} from '../electron/gpu-compatibility.ts';
import { stopChildProcess } from '../electron/rdp.ts';
import { TunnelLeaseRegistry } from '../electron/tunnel-lease-registry.ts';
import {
  isSafeUpdateInstallerPath,
  updateInstallAction,
  updateInstallerExtension,
} from '../electron/update-installer.ts';
import {
  runWindowTeardown,
  WindowCloseCoordinator,
  WindowCloseReasonTracker,
} from '../electron/window-lifecycle.ts';
import { createLogLevelSaveState, drainLogLevelChanges } from '../src/log-level-settings.ts';
import { buildMcpConfig } from '../src/mcp-config.ts';
import {
  canDisconnectRemoteDesktopSession,
  canOpenRdpSystemClient,
  disconnectedRemoteDesktopState,
  isSessionActive,
  nextSelectedSessionId,
  reconnectingVncState,
  sessionRuntimeRetryKeys,
  SessionCloseGate,
  SessionResourceReleaseGate,
  shouldConfirmConnectedTabClose,
} from '../src/session-lifecycle.ts';
import {
  createDebouncedSidebarWriter,
  defaultSidebarWidth,
  maxSidebarWidth,
  minSidebarWidth,
  normalizeSidebarWidth,
} from '../src/sidebar-settings.ts';
import { failedSshReconnectState, reconnectingSshState } from '../src/ssh-reconnect-state.ts';
import {
  hasNewerReleaseWithoutInstaller,
  isUpdateInstallable,
  shouldOfferUpdate,
} from '../src/update-state.ts';

test('unsupported macOS on legacy Intel MacBook Air selects software rendering before ready', () => {
  for (const [hardwareModel, systemVersion] of [
    ['MacBookAir7,1', '13.0'],
    [' MacBookAir7,2\n', '17.0.1'],
    ['MacBookAir7,2', '26'],
    ['MacBookAir7,2', 'unknown'],
  ]) {
    assert.equal(
      shouldDisableHardwareAcceleration({
        platform: 'darwin',
        architecture: 'x64',
        hardwareModel,
        systemVersion,
      }),
      true,
    );
  }

  for (const context of [
    {
      platform: 'darwin',
      architecture: 'x64',
      hardwareModel: 'MacBookAir7,2',
      systemVersion: '12.7.6',
    },
    {
      platform: 'darwin',
      architecture: 'x64',
      hardwareModel: 'MacBookAir8,1',
      systemVersion: '17.0',
    },
    {
      platform: 'darwin',
      architecture: 'arm64',
      hardwareModel: 'MacBookAir7,2',
      systemVersion: '17.0',
    },
    {
      platform: 'win32',
      architecture: 'x64',
      hardwareModel: 'MacBookAir7,2',
      systemVersion: '17.0',
    },
  ] as const) {
    assert.equal(shouldDisableHardwareAcceleration(context), false);
  }

  assert.equal(
    readDarwinHardwareModel('win32', () => 'MacBookAir7,2'),
    undefined,
  );
  assert.equal(
    readDarwinHardwareModel('darwin', () => ' MacBookAir7,2\n'),
    'MacBookAir7,2',
  );
  assert.equal(
    readDarwinHardwareModel('darwin', () => {
      throw new Error('sysctl unavailable');
    }),
    undefined,
  );

  const mainSource = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const crashDiagnostics = mainSource.indexOf('initializeLocalCrashDiagnostics({');
  const overrideDecision = mainSource.indexOf('const useSoftwareRendering =');
  const modelDetection = mainSource.indexOf('hardwareModel: readDarwinHardwareModel()');
  const disableHardwareAcceleration = mainSource.indexOf('app.disableHardwareAcceleration()');
  const readiness = mainSource.indexOf('app.whenReady().then');
  for (const position of [
    crashDiagnostics,
    overrideDecision,
    modelDetection,
    disableHardwareAcceleration,
    readiness,
  ]) {
    assert.notEqual(position, -1);
  }
  assert.match(
    mainSource.slice(overrideDecision, modelDetection),
    /forceSoftwareRendering\s*\|\|\s*shouldDisableHardwareAcceleration/,
  );
  assert.ok(crashDiagnostics < overrideDecision);
  assert.ok(overrideDecision < modelDetection);
  assert.ok(modelDetection < disableHardwareAcceleration);
  assert.ok(disableHardwareAcceleration < readiness);
});

test('startup keeps optional native and renderer work off the first-frame path', () => {
  const mainSource = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const appSource = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const imports = mainSource.slice(0, mainSource.indexOf('const __dirname'));
  const appReady = mainSource.slice(
    mainSource.indexOf('app.whenReady().then'),
    mainSource.indexOf('let quitCleanupStarted'),
  );
  const extensionLoader = mainSource.slice(
    mainSource.indexOf('private async ensureChromeExtensionApis'),
    mainSource.indexOf('private resolveBitwardenSurface'),
  );
  const mcpStatus = mainSource.slice(
    mainSource.indexOf('async mcpStatus()'),
    mainSource.indexOf('async startMcp'),
  );
  const startupReadyHandler = mainSource.slice(
    mainSource.indexOf("ipcMain.on('startup:ready'"),
    mainSource.indexOf("ipcMain.handle('startup:load'"),
  );
  const mcpUnlockSync = mainSource.slice(
    mainSource.indexOf('async syncMcpAfterUnlock'),
    mainSource.indexOf('async dispose()', mainSource.indexOf('async syncMcpAfterUnlock')),
  );
  const backgroundScheduler = mainSource.slice(
    mainSource.indexOf('function scheduleUnlockedBackgroundWork'),
    mainSource.indexOf('authSession.onUnlocked'),
  );

  assert.match(imports, /import type \{ ElectronChromeExtensions \}/);
  assert.doesNotMatch(imports, /import \{ ElectronChromeExtensions \}/);
  assert.match(extensionLoader, /await import\('electron-chrome-extensions'\)/);
  assert.match(appReady, /registerIpcHandlers\(sshBackend\);\s*createWindow\(\);/);
  assert.doesNotMatch(appReady, /\bawait\b|ensureWebSharedSessionReady|runFirstLaunchMigrations/);
  assert.match(startupReadyHandler, /scheduleUnlockedBackgroundWork\(\)/);
  assert.match(mcpStatus, /return runBackend<McpStatusResponse>\('mcp-status'\)/);
  assert.match(mcpUnlockSync, /syncMcpAfterUnlock\(authorizationEpoch: number\)/);
  const statusIndex = mcpUnlockSync.indexOf('const status = await this.mcpStatus()');
  const firstGuardIndex = mcpUnlockSync.indexOf(
    'if (!isAuthorizationEpochCurrent(authorizationEpoch))',
    statusIndex,
  );
  const startMcpIndex = mcpUnlockSync.indexOf('this.startMcp', firstGuardIndex);
  const secondGuardIndex = mcpUnlockSync.indexOf(
    'if (!isAuthorizationEpochCurrent(authorizationEpoch))',
    firstGuardIndex + 1,
  );
  const unlockMcpIndex = mcpUnlockSync.indexOf('await this.setMcpLocked(false)', secondGuardIndex);
  assert.ok(statusIndex >= 0 && statusIndex < firstGuardIndex);
  assert.ok(firstGuardIndex < startMcpIndex && startMcpIndex < secondGuardIndex);
  assert.ok(secondGuardIndex < unlockMcpIndex);
  for (const staleBranch of [
    mcpUnlockSync.slice(firstGuardIndex, startMcpIndex),
    mcpUnlockSync.slice(secondGuardIndex, unlockMcpIndex),
  ]) {
    assert.match(staleBranch, /await this\.setMcpLocked\(true\)[\s\S]*return;/);
  }
  assert.match(
    backgroundScheduler,
    /const authorizationEpoch = authSession\.authorizationEpoch;[\s\S]*syncMcpAfterUnlock\(authorizationEpoch\)/,
  );
  assert.match(appSource, /lazy\(\(\) =>[\s\S]*import\('\.\/components\/VncSurface'\)/);
  assert.match(appSource, /mremoteImportOpen \? \([\s\S]*<Suspense fallback=\{null\}>/);
});

test('cross-platform backend features are not gated by Windows-only IPC handlers', () => {
  const mainSource = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const preloadSource = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
  const handlers = mainSource.slice(
    mainSource.indexOf("ipcMain.handle('mcp:status'"),
    mainSource.indexOf("ipcMain.handle('tree-tooltip:show'"),
  );

  assert.doesNotMatch(handlers, /process\.platform|available on Windows builds/);
  for (const call of [
    'sshBackend.mcpStatus()',
    'sshBackend.startMcp(parsedPort)',
    'sshBackend.stopMcp()',
    'sshBackend.setMcpPort(parsedPort)',
    'sshBackend.getMcpToken()',
    'sshBackend.regenerateMcpToken()',
    "runBackend<{ updated: boolean }>('workspace-update-node-web-settings', request)",
  ]) {
    assert.ok(handlers.includes(call), `missing cross-platform handler call: ${call}`);
  }
  assert.match(preloadSource, /platform: process\.platform/);
});

test('MCP client configuration uses the host platform command contract', () => {
  const windows = JSON.parse(
    buildMcpConfig('claude-desktop', 'http://127.0.0.1:8765/mcp', 'token', 'win32'),
  );
  const linux = JSON.parse(
    buildMcpConfig('claude-desktop', 'http://127.0.0.1:8765/mcp', 'token', 'linux'),
  );

  assert.equal(windows.mcpServers.wormhole.command, 'cmd');
  assert.deepEqual(windows.mcpServers.wormhole.args.slice(0, 3), [
    '/c',
    'npx',
    'mcp-remote@latest',
  ]);
  assert.equal(linux.mcpServers.wormhole.command, 'npx');
  assert.equal(linux.mcpServers.wormhole.args[0], 'mcp-remote@latest');
  assert.equal(linux.mcpServers.wormhole.env.WORMHOLE_MCP_TOKEN, 'Bearer token');
});

test('update installers use verified platform-specific cache and launch contracts', () => {
  const cacheRoot = path.join(process.cwd(), 'cache', 'updates');
  for (const [platform, fileName, action] of [
    ['win32', 'Wormhole-2.0.1-win-x64-setup.exe', 'execute'],
    ['darwin', 'Wormhole-2.0.1-mac-universal-setup.dmg', 'open'],
    ['linux', 'Wormhole-2.0.1-linux-x86_64.AppImage', 'reveal'],
  ] as const) {
    assert.equal(
      isSafeUpdateInstallerPath(path.join(cacheRoot, fileName), cacheRoot, platform),
      true,
    );
    assert.equal(updateInstallAction(platform), action);
  }
  assert.equal(updateInstallerExtension('freebsd'), undefined);
  assert.equal(updateInstallAction('freebsd'), undefined);
  assert.equal(
    isSafeUpdateInstallerPath(
      path.join(cacheRoot, 'nested', 'Wormhole-2.0.1-win-x64-setup.exe'),
      cacheRoot,
      'win32',
    ),
    false,
  );
  assert.equal(
    isSafeUpdateInstallerPath(
      path.join(cacheRoot, 'Wormhole-2.0.1-win-x64-setup.dmg'),
      cacheRoot,
      'win32',
    ),
    false,
  );

  const mainSource = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const downloadHandler = mainSource.slice(
    mainSource.indexOf("ipcMain.handle('update:download'"),
    mainSource.indexOf("ipcMain.handle('update:install'"),
  );
  assert.match(downloadHandler, /expected\?\.isUpdateAvailable/);
  assert.match(downloadHandler, /installerSha256\.toLowerCase\(\)/);
  assert.match(downloadHandler, /installerUrl !== expected\.installerUrl/);

  const installerHandler = mainSource.slice(
    mainSource.indexOf('async function handleDownloadedUpdate'),
    mainSource.indexOf('function scheduleStartupUpdateCheck'),
  );
  assert.match(installerHandler, /await new Promise<void>/);
  assert.match(installerHandler, /child\.once\('error', reject\)/);
  assert.match(installerHandler, /child\.once\('spawn'/);
  assert.ok(
    installerHandler.indexOf("child.once('spawn'") < installerHandler.indexOf('app.quit()'),
  );
});

test('update availability uses the backend version decision from the same result', () => {
  assert.equal(
    hasNewerReleaseWithoutInstaller({
      latestVersion: '2.1.0',
      isNewerRelease: true,
      isUpdateAvailable: false,
    }),
    true,
  );
  assert.equal(
    hasNewerReleaseWithoutInstaller({
      latestVersion: '2.0.0',
      isNewerRelease: false,
      isUpdateAvailable: false,
    }),
    false,
  );
  assert.equal(
    hasNewerReleaseWithoutInstaller({
      latestVersion: '2.1.0',
      isNewerRelease: true,
      isUpdateAvailable: true,
    }),
    false,
  );
  assert.equal(
    hasNewerReleaseWithoutInstaller({
      latestVersion: '2.0.0',
      isNewerRelease: false,
      isUpdateAvailable: false,
    }),
    false,
  );
  const installable = {
    latestVersion: '2.1.0',
    isUpdateAvailable: true,
  };
  assert.equal(isUpdateInstallable(installable), true);
  assert.equal(shouldOfferUpdate(installable, null), true);
  assert.equal(shouldOfferUpdate(installable, '2.1.0'), false);
});

test('SSH automatic reconnect keeps the tab alive and reports terminal exhaustion', () => {
  assert.deepEqual(reconnectingSshState({ attempt: 1, maxAttempts: 3, delaySeconds: 10 }), {
    status: 'connecting',
    sftp: undefined,
    tunnelProgress: null,
    error: 'Connection lost. Reconnecting in 10 seconds (attempt 1 of 3).',
  });
  assert.deepEqual(
    failedSshReconnectState({ attempt: 3, maxAttempts: 3, error: 'network unavailable' }),
    {
      status: 'failed',
      sftp: undefined,
      tunnelProgress: null,
      error: 'Automatic reconnect failed after 3 attempts. network unavailable',
    },
  );
});

test('SSH reconnect lifecycle is validated before renderer delivery and retains its VPN lease', () => {
  const mainSource = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const appSource = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const parser = mainSource.slice(
    mainSource.indexOf('function parseSshBackendEvent'),
    mainSource.indexOf('function parseMcpBackendMessage'),
  );
  assert.match(parser, /value\.type === 'reconnecting' \|\| value\.type === 'reconnect-failed'/);
  assert.match(parser, /value\.max_attempts > 10/);
  const handler = mainSource.slice(
    mainSource.indexOf('private handleLine'),
    mainSource.indexOf('private broadcast', mainSource.indexOf('private handleLine')),
  );
  assert.match(handler, /event\.type === 'closed' \|\| event\.type === 'reconnect-failed'/);
  assert.doesNotMatch(handler, /event\.type === 'reconnecting'/);
  assert.match(mainSource, /prepareForLock\(\): void[\s\S]*type: 'app-lock-all'/);
  assert.match(
    mainSource.slice(mainSource.indexOf("ipcMain.handle('auth:lock'")),
    /sshBackend\.prepareForLock\(\)/,
  );
  assert.match(appSource, /event\.type === 'reconnecting'[\s\S]*reconnectingSshState\(event\)/);
  assert.match(
    appSource,
    /event\.type === 'reconnect-failed'[\s\S]*failedSshReconnectState\(event\)/,
  );
});

test('dialog close animations retain the last open visuals instead of rendering cleared state', () => {
  const retained = { icon: 'success', message: 'Extension updated.' };

  assert.deepEqual(
    selectDialogVisuals(true, { icon: 'success', message: 'Extension updated.' }, retained),
    { icon: 'success', message: 'Extension updated.' },
  );
  assert.deepEqual(
    selectDialogVisuals(false, { icon: 'error', message: 'Missing state.' }, retained),
    { icon: 'success', message: 'Extension updated.' },
  );
  assert.deepEqual(
    selectDialogVisuals(true, { icon: 'working', message: 'Trying again…' }, retained),
    { icon: 'working', message: 'Trying again…' },
  );
});

test('shared dialog content applies lifecycle retention and blocks closing interactions', () => {
  const dialogSource = readFileSync(
    new URL('../src/components/ui/dialog.tsx', import.meta.url),
    'utf8',
  );
  assert.match(dialogSource, /DialogOpenContext/);
  assert.match(dialogSource, /selectDialogVisuals\(open,/);
  assert.match(dialogSource, /data-closed:pointer-events-none/);
});

test('active-session app close uses the renderer shadcn confirmation contract', () => {
  const mainSource = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const preloadSource = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
  const appSource = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');

  assert.match(mainSource, /requestRendererCloseConfirmation\(window, activeCount, 'window'\)/);
  assert.match(mainSource, /requestRendererCloseConfirmation\(owner, activeCount, 'quit'\)/);
  assert.match(preloadSource, /onWindowCloseConfirmationRequested/);
  assert.match(appSource, /role="alertdialog"/);
  assert.match(appSource, /Close and terminate sessions/);
});

test('log level changes stay isolated without disrupting Radix select close focus', () => {
  const appSource = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const settingSource = appSource.slice(
    appSource.indexOf('function LogLevelSetting'),
    appSource.indexOf('function BitwardenCliDialog'),
  );
  const settingsPageSource = appSource.slice(
    appSource.indexOf('function SettingsPage'),
    appSource.indexOf('function UtilityPage'),
  );

  assert.match(settingSource, /const \[logLevel, setLogLevel\] = useState/);
  assert.match(settingSource, /busyRef\.current/);
  assert.match(settingSource, /drainLogLevelChanges/);
  assert.match(settingSource, /const \[error, setError\] = useState\(''\)/);
  assert.match(settingSource, /disabled=\{!loaded\}/);
  assert.match(settingSource, /aria-busy=\{busy\}/);
  assert.doesNotMatch(settingSource, /disabled=\{busy\}/);
  assert.match(settingsPageSource, /<SettingsTabPanel forceMount value="logs">/);
  assert.match(settingsPageSource, /loaded=\{logsInfo !== null\}/);
  assert.match(settingsPageSource, /logsActionError/);
  assert.match(settingsPageSource, /retentionError/);
  assert.doesNotMatch(settingsPageSource, /\blogsError\b|\bsetLogsError\b/);
  assert.doesNotMatch(settingsPageSource, /setLogLevelState|function commitLogLevel/);
});

test('log level persistence drains the latest selection without dropping rapid changes', async () => {
  const state = createLogLevelSaveState('info');
  state.desired = 'debug';
  let releaseFirst!: (level: string) => void;
  const firstWrite = new Promise<string>((resolve) => {
    releaseFirst = resolve;
  });
  const writes: string[] = [];
  const persisted: string[] = [];
  const draining = drainLogLevelChanges(
    state,
    async (level) => {
      writes.push(level);
      return writes.length === 1 ? firstWrite : level;
    },
    (level) => persisted.push(level),
  );

  state.desired = 'info';
  releaseFirst('debug');
  await draining;

  assert.deepEqual(writes, ['debug', 'info']);
  assert.deepEqual(persisted, ['debug', 'info']);
  assert.deepEqual(state, { desired: 'info', persisted: 'info' });
});

test('log level persistence rejects a mismatched backend response atomically', async () => {
  const state = createLogLevelSaveState('info');
  state.desired = 'debug';

  await assert.rejects(
    drainLogLevelChanges(
      state,
      async () => 'info',
      () => assert.fail('must not commit'),
    ),
    /log level response is invalid/i,
  );
  assert.deepEqual(state, { desired: 'debug', persisted: 'info' });
});

test('session activity excludes failed, closed, disconnected, and idle tabs', () => {
  assert.equal(isSessionActive({ protocol: 'ssh', status: 'connected' }), true);
  assert.equal(isSessionActive({ protocol: 'serial', status: 'connecting' }), true);
  assert.equal(isSessionActive({ protocol: 'ssh', status: 'closed' }), false);
  assert.equal(
    isSessionActive({ protocol: 'rdp', status: 'placeholder', rdpStatus: 'connected' }),
    true,
  );
  assert.equal(
    isSessionActive({ protocol: 'rdp', status: 'placeholder', rdpStatus: 'disconnected' }),
    false,
  );
  assert.equal(
    shouldConfirmConnectedTabClose(false, [{ protocol: 'ssh', status: 'connected' }]),
    false,
  );
});

test('remote desktop actions expose only valid disconnect and system-client states', () => {
  assert.equal(canDisconnectRemoteDesktopSession({ protocol: 'vnc', status: 'connecting' }), true);
  assert.equal(canDisconnectRemoteDesktopSession({ protocol: 'vnc', status: 'closed' }), false);
  assert.equal(
    canDisconnectRemoteDesktopSession({
      protocol: 'rdp',
      status: 'placeholder',
      rdpStatus: 'connected',
    }),
    true,
  );
  assert.equal(
    canDisconnectRemoteDesktopSession({
      protocol: 'rdp',
      status: 'placeholder',
      rdpStatus: 'disconnected',
    }),
    false,
  );
  assert.equal(
    canDisconnectRemoteDesktopSession({
      protocol: 'rdp',
      status: 'placeholder',
      rdpStatus: 'failed',
    }),
    true,
  );
  assert.equal(
    canOpenRdpSystemClient({
      protocol: 'rdp',
      status: 'placeholder',
      rdpStatus: 'failed',
      rdpSystemClientSupported: true,
    }),
    true,
  );
  assert.equal(
    canOpenRdpSystemClient({
      protocol: 'rdp',
      status: 'placeholder',
      rdpStatus: 'starting',
      rdpSystemClientSupported: true,
    }),
    false,
  );
  assert.equal(
    canOpenRdpSystemClient({
      protocol: 'rdp',
      status: 'placeholder',
      rdpStatus: 'connected',
      rdpExternal: true,
      rdpSystemClientSupported: true,
    }),
    false,
  );
});

test('disconnect preserves remote desktop tabs and VNC reconnect advances its attempt', () => {
  assert.deepEqual(
    disconnectedRemoteDesktopState({
      protocol: 'rdp',
      status: 'placeholder',
      rdpStatus: 'connected',
      rdpExternal: true,
    }),
    {
      status: 'closed',
      rdpStatus: 'disconnected',
      rdpExternal: false,
    },
  );
  const disconnectedVnc = {
    protocol: 'vnc',
    status: 'closed',
    vncConnectionGeneration: 4,
  };
  assert.deepEqual(reconnectingVncState(disconnectedVnc), {
    status: 'connecting',
    vncConnectionGeneration: 5,
  });
});

test('window close cancellation is fail-closed and duplicate requests do not prompt twice', async () => {
  const coordinator = new WindowCloseCoordinator();
  coordinator.updateActiveCount(2);
  let prompts = 0;
  let teardowns = 0;
  let closes = 0;
  const request = {
    reason: 'window' as const,
    confirm: async () => {
      prompts++;
      return false;
    },
    teardown: async () => {
      teardowns++;
    },
    close: () => {
      closes++;
    },
  };
  await Promise.all([coordinator.request(request), coordinator.request(request)]);
  assert.deepEqual({ prompts, teardowns, closes }, { prompts: 1, teardowns: 0, closes: 0 });
});

test('confirmed and non-interactive closes teardown once before closing', async () => {
  for (const reason of [
    'window',
    'quit',
    'update',
    'system-shutdown',
    'renderer-failure',
  ] as const) {
    const coordinator = new WindowCloseCoordinator();
    coordinator.updateActiveCount(1);
    const order: string[] = [];
    await coordinator.request({
      reason,
      confirm: async () => {
        order.push('confirm');
        return true;
      },
      teardown: async () => {
        order.push('teardown');
      },
      close: () => order.push('close'),
    });
    assert.deepEqual(
      order,
      reason === 'window' ? ['confirm', 'teardown', 'close'] : ['teardown', 'close'],
    );
  }
});

test('window teardown flushes browser state before sessions and still releases sessions on failure', async () => {
  const order: string[] = [];
  await runWindowTeardown(
    async () => {
      order.push('bitwarden-flush');
    },
    async () => {
      order.push('session-release');
    },
  );
  assert.deepEqual(order, ['bitwarden-flush', 'session-release']);

  order.length = 0;
  await assert.rejects(
    runWindowTeardown(
      async () => {
        order.push('bitwarden-flush');
        throw new Error('backend unavailable');
      },
      async () => {
        order.push('session-release');
      },
    ),
  );
  assert.deepEqual(order, ['bitwarden-flush', 'session-release']);
});

test('sidebar values clamp and resize writes debounce', async () => {
  assert.equal(normalizeSidebarWidth(undefined), defaultSidebarWidth);
  assert.equal(normalizeSidebarWidth(-1), minSidebarWidth);
  assert.equal(normalizeSidebarWidth(9999), maxSidebarWidth);
  const callbacks: Array<() => void> = [];
  const writes: number[] = [];
  const writer = createDebouncedSidebarWriter((width) => writes.push(width), {
    delayMs: 250,
    scheduler: {
      set(callback) {
        callbacks.push(callback);
        return callbacks.length - 1;
      },
      clear(handle) {
        callbacks[handle as number] = () => undefined;
      },
    },
  });
  writer.schedule(300);
  writer.schedule(340.4);
  for (const callback of callbacks) callback();
  await writer.flush();
  assert.deepEqual(writes, [340]);
  writer.schedule(340);
  callbacks.at(-1)?.();
  await writer.flush();
  assert.deepEqual(writes, [340]);
  writer.schedule(360);
  await writer.flush();
  assert.deepEqual(writes, [340, 360]);
});

test('failed sidebar persistence is retried and flush waits for the write', async () => {
  let attempts = 0;
  const writer = createDebouncedSidebarWriter(async () => {
    attempts++;
    if (attempts === 1) throw new Error('backend unavailable');
  });
  writer.schedule(400);
  await assert.rejects(writer.flush());
  writer.schedule(400);
  await writer.flush();
  assert.equal(attempts, 2);
});

test('connected tab close gate rejects duplicates until the first close settles', async () => {
  const gate = new SessionCloseGate();
  let release!: () => void;
  const pending = new Promise<void>((resolve) => {
    release = resolve;
  });
  const first = gate.run('session-1', () => pending);
  assert.equal(await gate.run('session-1', async () => undefined), false);
  release();
  assert.equal(await first, true);
  assert.equal(await gate.run('session-1', async () => undefined), true);
});

test('session resources release exactly once across overlapping close paths', async () => {
  const gate = new SessionResourceReleaseGate();
  let releases = 0;
  let finish!: () => void;
  const pending = new Promise<void>((resolve) => {
    finish = resolve;
  });
  const first = gate.release('session-1', async () => {
    releases++;
    await pending;
  });
  const overlapping = gate.release('session-1', async () => {
    releases++;
  });
  finish();
  await Promise.all([first, overlapping]);
  await gate.release('session-1', async () => {
    releases++;
  });
  assert.equal(releases, 1);

  gate.reset('session-1');
  await gate.release('session-1', async () => {
    releases++;
  });
  assert.equal(releases, 2);
});

test('concurrent tab removal never selects or restores another closing tab', () => {
  const sessions = [{ id: 'a' }, { id: 'b' }, { id: 'c' }];
  const closing = new Set(['a', 'b']);
  assert.equal(
    nextSelectedSessionId(sessions, 'a', (id) => closing.has(id)),
    'c',
  );
  assert.equal(
    nextSelectedSessionId(sessions, 'c', (id) => closing.has(id)),
    'c',
  );
  assert.equal(
    nextSelectedSessionId(sessions, 'c', (id) => id === 'a' || id === 'c'),
    'b',
  );
});

test('bulk session cleanup removes every protocol retry identity', () => {
  assert.deepEqual(
    sessionRuntimeRetryKeys({ id: 'visible-session', backendSessionId: 'native-ssh-session' }),
    ['rdp:visible-session', 'vnc:visible-session', 'ssh:native-ssh-session'],
  );
  assert.deepEqual(sessionRuntimeRetryKeys({ id: 'visible-session' }), [
    'rdp:visible-session',
    'vnc:visible-session',
  ]);
});

test('cancelled OS shutdown restores ordinary close confirmation policy', () => {
  let reset = () => undefined;
  const tracker = new WindowCloseReasonTracker({
    set(callback) {
      reset = callback;
      return 1;
    },
    clear() {
      reset = () => undefined;
    },
  });
  tracker.beginSystemShutdown();
  assert.equal(tracker.reason, 'system-shutdown');
  reset();
  assert.equal(tracker.reason, 'window');
});

test('window close always follows renderer teardown with native cleanup', () => {
  const mainSource = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const start = mainSource.indexOf("if (closeReason.reason !== 'renderer-failure')");
  const failureBranch = mainSource.slice(start, start + 1_000);
  assert.match(failureBranch, /await requestRendererTeardown\(window\)/);
  assert.doesNotMatch(
    failureBranch.slice(
      failureBranch.indexOf('await requestRendererTeardown(window)'),
      failureBranch.indexOf('await shutdownNativeResources()'),
    ),
    /\breturn\b/,
  );
  assert.match(failureBranch, /await shutdownNativeResources\(\)/);
});

test('RDP start cancellation and VPN ownership are scoped before asynchronous profile resolution', () => {
  const mainSource = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const start = mainSource.indexOf("ipcMain.handle('rdp:start'");
  const end = mainSource.indexOf("ipcMain.handle('rdp:system-client-capability'", start);
  const startHandler = mainSource.slice(start, end);
  assert.match(startHandler, /rdpStartAttempts\.begin\(request\.sessionId\)/);
  assert.match(startHandler, /resolveNativeRdpProfile\(/);
  assert.ok(
    startHandler.indexOf('rdpStartAttempts.begin(request.sessionId)') <
      startHandler.indexOf('resolveNativeRdpProfile('),
  );
  assert.match(startHandler, /assertRdpStartCurrent\(request\.sessionId, requestAttempt\)/);
  assert.match(startHandler, /rdpSessionAttempts\.begin\(request\.sessionId\)/);
  assert.match(
    startHandler,
    /assertRdpStartCurrent\(request\.sessionId, requestAttempt, generation\)/,
  );
  assert.match(startHandler, /rdpTunnelLeases\.claim\(lifecycleId, leaseId\)/);
  assert.match(startHandler, /rdpTunnelLeaseSessions\.set\(lifecycleId, request\.sessionId\)/);
  assert.match(startHandler, /releaseRdpTunnelsForSession\(request\.sessionId\)/);
  assert.doesNotMatch(startHandler, /rdpTunnelLeases\.claim\(request\.sessionId, leaseId\)/);
  assert.match(
    mainSource,
    /function cancelPreparingRdpStarts\(\)[\s\S]*rdpStartAttempts\.cancelAll\(\)[\s\S]*rdpSessionAttempts\.cancelAll\(\)[\s\S]*releaseRdpTunnel\(lifecycleId\)/,
  );
});

test('web renderer loss releases its VPN-backed surface immediately', () => {
  const mainSource = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const crashHandler = mainSource.slice(
    mainSource.indexOf("contents.on('render-process-gone'"),
    mainSource.indexOf("contents.once('destroyed'"),
  );
  assert.match(crashHandler, /this\.close\(sessionId\)/);
});

test('application shutdown permanently stops the broker before dropping its reference', () => {
  const mainSource = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const shutdown = mainSource.slice(
    mainSource.indexOf('function shutdownNativeResources()'),
    mainSource.indexOf('authSession.onUnlocked'),
  );
  assert.ok(
    shutdown.indexOf('nativeBackend = undefined') < shutdown.indexOf('await backend?.stop(true)'),
  );
  assert.match(mainSource, /gracefulTimeoutMs: nativeBackendShutdownTimeoutMs/);
  for (const channel of ['tunnel:test', 'web:open', 'ssh:open', 'rdp:start']) {
    const handler = mainSource.slice(mainSource.indexOf(`ipcMain.handle('${channel}'`));
    assert.match(handler.slice(0, 300), /requireNativeResourcesRunning\(\)/);
  }
});

test('child process shutdown waits for graceful exit and force-kills only after timeout', async () => {
  const gracefulEvents = new EventEmitter();
  const graceful: any = {
    exitCode: null,
    signalCode: null,
    stdin: {
      end() {
        graceful.exitCode = 0;
        queueMicrotask(() => gracefulEvents.emit('close'));
      },
    },
    once: gracefulEvents.once.bind(gracefulEvents),
    removeListener: gracefulEvents.removeListener.bind(gracefulEvents),
    killCalls: 0,
    kill() {
      graceful.killCalls++;
      return true;
    },
  };
  assert.equal(
    await stopChildProcess(graceful, { gracefulTimeoutMs: 10, forceKillTimeoutMs: 10 }),
    true,
  );
  assert.equal(graceful.killCalls, 0);

  const forcedEvents = new EventEmitter();
  const forced: any = {
    exitCode: null,
    signalCode: null,
    stdin: { end() {} },
    once: forcedEvents.once.bind(forcedEvents),
    removeListener: forcedEvents.removeListener.bind(forcedEvents),
    killCalls: 0,
    kill() {
      forced.killCalls++;
      forced.signalCode = 'SIGTERM';
      queueMicrotask(() => forcedEvents.emit('close'));
      return true;
    },
  };
  assert.equal(
    await stopChildProcess(forced, { gracefulTimeoutMs: 1, forceKillTimeoutMs: 10 }),
    true,
  );
  assert.equal(forced.killCalls, 1);
});

test('tunnel lease release is idempotent, cancels ownership immediately, and retries failures', async () => {
  const leases = new TunnelLeaseRegistry();
  leases.claim('rdp-session', 'lease-one');
  let finish!: () => void;
  let releases = 0;
  const pending = () =>
    new Promise<void>((resolve) => {
      releases++;
      finish = resolve;
    });
  const first = leases.release('rdp-session', pending);
  const duplicate = leases.release('rdp-session', pending);
  assert.equal(leases.isActive('rdp-session', 'lease-one'), false);
  assert.equal(releases, 1);
  finish();
  await Promise.all([first, duplicate]);
  assert.equal(leases.has('rdp-session'), false);

  leases.claim('web-session', 'lease-two');
  await assert.rejects(
    leases.release('web-session', async () => Promise.reject(new Error('pipe'))),
  );
  assert.equal(leases.has('web-session'), true);
  await leases.release('web-session', async () => undefined);
  assert.equal(leases.has('web-session'), false);

  leases.claim('rdp-old-lifecycle', 'lease-old');
  leases.claim('rdp-new-lifecycle', 'lease-new');
  await leases.release('rdp-old-lifecycle', async () => undefined);
  assert.equal(leases.has('rdp-old-lifecycle'), false);
  assert.equal(leases.isActive('rdp-new-lifecycle', 'lease-new'), true);
});

test('VNC disconnect remains available as cleanup across an authentication lock', () => {
  const mainSource = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const handler = mainSource.slice(
    mainSource.indexOf("ipcMain.handle('vnc:command'"),
    mainSource.indexOf("ipcMain.handle('rdp:start'"),
  );
  const disconnect = handler.indexOf("command.action === 'vnc.disconnect'");
  const authGate = handler.indexOf('return serializeAuthOperation');
  assert.ok(disconnect >= 0 && disconnect < authGate);
  assert.match(
    handler.slice(disconnect, authGate),
    /getNativeBackend\(\)\.send\(command, cliOperationTimeoutMs\)/,
  );
  assert.match(handler, /vncSessionAttempts\.cancel\(command\.sessionId!\)/);
  assert.match(handler, /vncSessionAttempts\.begin\(command\.sessionId!\)/);
  assert.match(handler, /vncSessionAttempts\.isCurrent\(command\.sessionId!, attempt\)/);
});
