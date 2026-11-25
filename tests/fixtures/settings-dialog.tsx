import * as React from 'react';
import { createRoot } from 'react-dom/client';
import App from '../../src/App';
import {
  ContextMenuOverlayProvider,
  useContextMenuOverlayOpen,
} from '../../src/components/ui/context-menu';
import '../../src/index.css';

declare global {
  interface Window {
    settingsAssert: typeof import('node:assert/strict');
    settingsInput: (event: Record<string, unknown>) => Promise<void>;
    settingsReducedMotion: (reduce: boolean) => Promise<void>;
    runSettingsDialogTests: (mode: 'desktop' | 'compact') => Promise<void>;
  }
}

function OverlayProbe() {
  const overlayOpen = useContextMenuOverlayOpen();
  return (
    <output className="sr-only" id="overlay-state">
      {String(overlayOpen)}
    </output>
  );
}

function createWormholeMock(options: {
  initialTheme?: 'dark' | 'light';
  updateResult?: WormholeUpdateCheckResult | null;
  idleSeconds?: number;
}) {
  let updateListener: ((result: WormholeUpdateCheckResult) => void) | undefined;
  let currentUpdateResult: WormholeUpdateCheckResult | null = options.updateResult ?? null;
  const theme = options.initialTheme ?? 'dark';

  const appSettings: WormholeAppSettings = {
    sshTerminalTheme: 'tango',
    theme,
    promptBeforeTunnelConnect: true,
    autoCopyOnSelect: false,
    confirmOnTabClose: true,
    confirmOnWindowClose: true,
    sidebarWidth: 280,
    sidebarPinned: true,
    connectionTreeExpansion: null,
    autoCheckForUpdates: false,
    lastUpdateCheck: null,
    skippedUpdateVersion: null,
  };

  const api = {
    platform: 'win32',
    getPathForFile: (file: File) => file.name,
    loadStartup: async () => {
      throw new Error('Not used in rendered workspace fixture');
    },
    unlockStartup: async () => ({ succeeded: true, message: '' }),
    markStartupReady: () => {},
    markWorkspaceFailed: () => {},
    setTitlebarTheme: () => {},
    loadWorkspace: async () => ({
      tree: [],
      credentials: [],
      credentialOptions: { ssh: [], rdp: [], vnc: [] },
      tunnels: [],
    }),
    loadWorkspaceNodeNotes: async () => ({ notes: '' }),
    selectMRemoteImport: async () => null,
    analyzeMRemoteImport: async () => {
      throw new Error('Not used');
    },
    cancelMRemoteImportAnalysis: () => {},
    commitMRemoteImport: async () => {
      throw new Error('Not used');
    },
    cancelMRemoteImportCommit: async () => true,
    clearMRemoteImport: () => {},
    moveWorkspaceNodes: async () => ({ moved: true }),
    duplicateWorkspaceNode: async () => ({ nodeId: 'dup', name: 'Duplicate' }),
    deleteWorkspaceNode: async () => ({ deleted: true }),
    deleteWorkspaceNodes: async () => ({ deleted: true }),
    showWorkspaceCredentials: async () => ({ found: false, connectionName: '' }),
    exportBackup: async () => null,
    cancelBackupExport: async () => true,
    selectBackupForImport: async () => null,
    clearBackupImportSelection: () => {},
    importBackup: async () => {
      throw new Error('Not used');
    },
    cancelBackupImport: async () => true,
    onOperationProgress: () => () => {},
    createWorkspaceNode: async () => ({ nodeId: 'node-1' }),
    updateWorkspaceNode: async () => ({ updated: true }),
    rdpExternalClientRequirement: async () => ({ required: false }),
    createCredential: async () => {
      throw new Error('Not used');
    },
    updateCredential: async () => {
      throw new Error('Not used');
    },
    selectSshPrivateKey: async () => null,
    selectSshCertificate: async () => null,
    discardSshCertificateSelection: async () => ({ discarded: true }),
    discardSshPrivateKeySelection: async () => ({ discarded: true }),
    deleteCredential: async () => ({ deleted: true }),
    updateWorkspaceNodeSshSettings: async () => ({ updated: true }),
    listCredentialsForProtocol: async () => [],
    updateWorkspaceNodeCredential: async () => ({ updated: true }),
    updateWorkspaceNodeInlineCredential: async () => ({ updated: true }),
    updateWorkspaceNodeWebSettings: async () => ({ updated: true }),
    openWebSession: async () => {
      throw new Error('Not used');
    },
    setWebSessionBounds: async () => undefined,
    commandWebSession: async () => {},
    showTreeTooltip: async () => {},
    hideTreeTooltip: async () => {},
    closeWebSession: async () => {},
    onWebEvent: () => () => {},
    updateWorkspaceNodeTunnelSettings: async () => ({ updated: true }),
    enterFortinetIPsecCredential: async () => false,
    discardFortinetIPsecCredentials: async () => {},
    createTunnel: async () => {
      throw new Error('Not used');
    },
    listTunnels: async () => [],
    readTunnel: async () => {
      throw new Error('Not used');
    },
    updateTunnel: async () => {
      throw new Error('Not used');
    },
    deleteTunnel: async () => ({ deleted: true }),
    testTunnel: async () => ({ connected: false }),
    cancelTunnelTest: async () => ({ cancelled: true }),
    onTunnelTestProgress: () => () => {},
    importWatchguardProfile: async () => null,
    importAzureVpnProfile: async () => null,
    importOvpnProfile: async () => null,
    importCiscoProfile: async () => null,
    respondTunnelPrompt: async () => {},
    respondTunnelRoute: async () => {},
    readAppSettings: async () => appSettings,
    setTheme: async (nextTheme: 'system' | 'light' | 'dark') => {
      appSettings.theme = nextTheme;
      return { updated: true };
    },
    setSshTerminalTheme: async () => ({ updated: true }),
    setPromptBeforeTunnelConnect: async (enabled: boolean) => {
      appSettings.promptBeforeTunnelConnect = enabled;
      return { updated: true };
    },
    setConfirmOnTabClose: async (enabled: boolean) => {
      appSettings.confirmOnTabClose = enabled;
      return { updated: true };
    },
    setConfirmOnWindowClose: async (enabled: boolean) => {
      appSettings.confirmOnWindowClose = enabled;
      return { updated: true };
    },
    setSidebarWidth: async (width: number) => ({ updated: true, sidebarWidth: width }),
    setSidebarPinned: async (pinned: boolean) => {
      appSettings.sidebarPinned = pinned;
      return { updated: true };
    },
    setConnectionTreeExpansion: async () => ({ updated: true }),
    reportActiveSessionCount: () => {},
    onWindowCloseConfirmationRequested: () => () => {},
    onWindowCloseRequested: () => () => {},
    setAutoCopyOnSelect: async (enabled: boolean) => {
      appSettings.autoCopyOnSelect = enabled;
      return { updated: true };
    },
    setUpdatePreferences: async () => ({ updated: true }),
    updateStatus: async () => ({
      currentVersion: '2.4.4',
      result: currentUpdateResult,
    }),
    checkForUpdates: async () =>
      currentUpdateResult ?? {
        currentVersion: '2.4.4',
        latestVersion: '2.4.4',
        isNewerRelease: false,
        isUpdateAvailable: false,
        checkFailed: false,
      },
    downloadUpdate: async () => 'installer.exe',
    installUpdate: async () => ({ appWillQuit: false }),
    openExternal: async () => {},
    openTerminalLink: async () => {},
    onUpdateResult: (listener: (result: WormholeUpdateCheckResult) => void) => {
      updateListener = listener;
      return () => {
        if (updateListener === listener) updateListener = undefined;
      };
    },
    onUpdateProgress: () => () => {},
    readLogsInfo: async (): Promise<WormholeLogsInfo> => ({
      currentLogFilePath: 'C:\\Users\\test\\AppData\\Roaming\\Wormhole\\logs\\2026-11-20.log',
      logsDirectoryPath: 'C:\\Users\\test\\AppData\\Roaming\\Wormhole\\logs',
      logRetentionDays: 14,
      logLevel: 'info',
    }),
    setLogRetentionDays: async (days: number) => ({ updated: true, logRetentionDays: days }),
    setLogLevel: async (level: string) => ({ updated: true, logLevel: level }),
    openCurrentLogFile: async () => ({ opened: true }),
    openLogsFolder: async () => ({ opened: true }),
    readBitwardenExtension: async (): Promise<WormholeBitwardenExtensionState> => ({
      enabled: false,
      source: 'OfficialGitHub',
      releasesUrl: 'https://github.com/bitwarden/clients/releases',
      version: null,
      path: null,
      sha256: null,
      assetName: null,
      downloadUrl: null,
      lastUpdateCheckUtc: null,
      lastUpdateStatus: null,
      lastUpdateError: null,
      availableVersion: null,
      installed: null,
    }),
    setBitwardenExtensionEnabled: async () => {
      throw new Error('Not used');
    },
    installBitwardenExtension: async () => {
      throw new Error('Not used');
    },
    ensureBitwardenExtension: async () => {
      throw new Error('Not used');
    },
    importBitwardenExtensionZip: async () => null,
    importBitwardenExtensionFolder: async () => null,
    readBitwardenCli: async (): Promise<WormholeBitwardenCliState> => ({
      enabled: false,
      path: 'bw',
      serverRegion: 'UnitedStates',
      releasesUrl: 'https://github.com/bitwarden/clients/releases',
      version: null,
      sha256: null,
      assetName: null,
      downloadUrl: null,
      installStatus: null,
      installError: null,
      lastSyncUtc: null,
      lastSyncStatus: null,
      lastSyncError: null,
      availableCount: null,
      installed: null,
    }),
    readBitwardenStartupState: async () => null,
    setBitwardenCliEnabled: async () => {
      throw new Error('Not used');
    },
    setBitwardenCliConfig: async () => {
      throw new Error('Not used');
    },
    installBitwardenCli: async () => {
      throw new Error('Not used');
    },
    refreshBitwardenCliStatus: async (): Promise<WormholeBitwardenCliStatus> => ({
      status: 'Unauthenticated',
      userEmail: null,
      serverUrl: null,
    }),
    loginBitwardenCli: async () => ({ loggedIn: true }),
    unlockBitwardenCli: async () => ({ unlocked: true }),
    logoutBitwardenCli: async () => ({ loggedOut: true }),
    syncBitwardenCli: async () => ({
      lastSyncUtc: '2026-11-20T10:00:00Z',
      lastSyncStatus: 'Synced',
      availableCount: 0,
      usedCache: false,
    }),
    searchBitwardenItems: async () => ({ items: [] }),
    nodeUsesBitwarden: async () => ({ bitwarden: false }),
    openBitwardenPopup: async () => ({ open: true }),
    closeBitwardenPopup: async () => ({ open: false }),
    onBitwardenPopupState: () => () => {},
    openSshSession: async () => {
      throw new Error('Not used');
    },
    trustSshHostKey: async () => {
      throw new Error('Not used');
    },
    sendSshInput: async () => {},
    pasteClipboardToSsh: async () => ({ pasted: false }),
    resizeSshSession: async () => {},
    readSftpEditorSettings: async (): Promise<WormholeSftpEditorSettings> => ({
      editors: [],
      defaultEditor: 'auto',
      maxFileSize: 10 * 1048576,
      swapPanels: false,
    }),
    writeSftpEditorSettings: async () => ({ updated: true }),
    sftpEdit: async (): Promise<WormholeSftpEditEvent> => ({
      type: 'sftp.edit',
      sessionId: 'sftp-recovery',
      edits: [],
    }),
    prepareSftpEditClose: async () => true,
    shareSftpSession: async () => ({}),
    listSftpTree: async () => {},
    openSftpBrowser: async () => {},
    listSftpDirectory: async () => {},
    listLocalSftpDirectory: async () => {},
    operateSftp: async () => {},
    startSftpTransfer: async () => {},
    decideSftpConflict: async () => {},
    cancelSftpTransfer: async () => {},
    closeSftpBrowser: async () => {},
    closeSshSession: async () => {},
    acknowledgeSshTerminal: () => {},
    onSshEvent: () => () => {},
    openSerialSession: async () => {
      throw new Error('Not used');
    },
    sendSerialInput: async () => {},
    resizeSerialSession: async () => {},
    closeSerialSession: async () => {},
    onSerialEvent: () => () => {},
    getAuthState: async (): Promise<WormholeAuthState> => ({
      mode: 'pin',
      fallback: 'pin',
      idleTimeoutMinutes: null,
      hasPin: true,
      hasPassword: false,
      isCorrupted: false,
      configured: true,
      windowsHello: { available: false, message: '' },
    }),
    verifyAuth: async () => ({ succeeded: true, message: '' }),
    setAuthSecret: async () => {
      throw new Error('Not used');
    },
    updateAuthSettings: async () => {
      throw new Error('Not used');
    },
    lockAuthentication: async () => {},
    checkWindowsHello: async () => ({ available: false, message: '' }),
    verifyWindowsHello: async () => ({ succeeded: false, message: '' }),
    getSystemIdleSeconds: async () => ({ seconds: options.idleSeconds ?? 0 }),
    mcpStatus: async (): Promise<WormholeMcpStatus> => ({
      enabled: false,
      running: false,
      port: 8765,
      endpoint: 'http://127.0.0.1:8765/mcp',
      approvalMode: 'first-access',
    }),
    startMcp: async (port: number) => ({
      enabled: true,
      running: true,
      port,
      endpoint: `http://127.0.0.1:${port}/mcp`,
      approvalMode: 'first-access',
    }),
    stopMcp: async () => ({
      enabled: false,
      running: false,
      port: 8765,
      endpoint: 'http://127.0.0.1:8765/mcp',
      approvalMode: 'first-access',
    }),
    setMcpPort: async (port: number) => ({
      enabled: false,
      running: false,
      port,
      endpoint: `http://127.0.0.1:${port}/mcp`,
      approvalMode: 'first-access',
    }),
    setMcpApprovalMode: async (approvalMode: WormholeMcpApprovalMode) => ({
      enabled: false,
      running: false,
      port: 8765,
      endpoint: 'http://127.0.0.1:8765/mcp',
      approvalMode,
    }),
    getMcpToken: async () => 'test-token',
    regenerateMcpToken: async () => 'new-token',
    respondMcpApproval: async () => {},
    revokeMcpSessionAccess: async () => {},
    onMcpApproval: () => () => {},
    sendVncCommand: async () => ({ id: '1', ok: true }),
    onBackendEvent: () => () => {},
    sendRdpInput: async () => {},
    startRdpSession: async () => ({ type: 'started' }),
    getRdpSystemClientCapability: async () => ({ supported: false }),
    openRdpInSystemClient: async () => ({
      ok: false,
      lifecycleCommitted: false,
      error: 'Unsupported',
    }),
    resizeRdpSession: async () => ({ type: 'ready' }),
    commandRdpSession: async () => ({ type: 'ready' }),
    onRdpEvent: () => () => {},
  };

  return {
    api: api as unknown as Window['wormhole'],
    emitUpdate: (result: WormholeUpdateCheckResult) => {
      currentUpdateResult = result;
      updateListener?.(result);
    },
  };
}

window.runSettingsDialogTests = async (mode: 'desktop' | 'compact') => {
  const assert = window.settingsAssert;
  const root = createRoot(document.getElementById('root')!);
  const tick = () => React.act(async () => new Promise((resolve) => setTimeout(resolve, 30)));
  const waitFor = async (condition: () => boolean, message: string) => {
    const deadline = performance.now() + 5000;
    while (!condition()) {
      assert.ok(performance.now() < deadline, message);
      await tick();
    }
  };
  const query = <T extends HTMLElement = HTMLElement>(selector: string) =>
    document.querySelector<T>(selector);
  const dialog = () => query('[data-settings-dialog][data-state="open"]');
  const closeButton = () => query<HTMLButtonElement>('[aria-label="Close settings"]');
  const overlayState = () => query('#overlay-state')?.textContent;
  const insetText = () => query('[data-slot="sidebar-inset"]')?.textContent ?? '';

  const clickElement = async (element: HTMLElement) => {
    const rect = element.getBoundingClientRect();
    const x = Math.round(rect.left + rect.width / 2);
    const y = Math.round(rect.top + rect.height / 2);
    await React.act(async () => window.settingsInput({ type: 'mouseMove', x, y }));
    await tick();
    await waitFor(
      () => element.contains(document.elementFromPoint(x, y)),
      `Target ${element.getAttribute('aria-label') || element.textContent} covered by ${
        document.elementFromPoint(x, y)?.outerHTML.slice(0, 180) ?? 'null'
      }`,
    );
    await React.act(async () => {
      await window.settingsInput({ type: 'mouseDown', button: 'left', x, y, clickCount: 1 });
      await window.settingsInput({ type: 'mouseUp', button: 'left', x, y, clickCount: 1 });
    });
    await tick();
  };

  const clickPoint = async (x: number, y: number) => {
    await React.act(async () => {
      await window.settingsInput({ type: 'mouseMove', x, y });
      await window.settingsInput({ type: 'mouseDown', button: 'left', x, y, clickCount: 1 });
      await window.settingsInput({ type: 'mouseUp', button: 'left', x, y, clickCount: 1 });
    });
    await tick();
  };

  const keypress = async (keyCode: string) => {
    await React.act(async () => {
      await window.settingsInput({ type: 'keyDown', keyCode });
      await window.settingsInput({ type: 'keyUp', keyCode });
    });
    await tick();
  };

  const setInputValue = async (input: HTMLInputElement, value: string) => {
    const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    descriptor?.set?.call(input, value);
    await React.act(async () => {
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await tick();
  };

  const assertDialogGeometry = (expectSideBySide = true) => {
    const popup = dialog();
    assert.ok(popup, 'Expected open settings dialog');
    const bounds = popup.getBoundingClientRect();
    assert.ok(bounds.left > 0, `Popup left must leave backdrop margin: ${bounds.left}`);
    assert.ok(bounds.top > 0, `Popup top must leave backdrop margin: ${bounds.top}`);
    assert.ok(
      bounds.right < window.innerWidth,
      `Popup right must leave backdrop margin: ${bounds.right} vs ${window.innerWidth}`,
    );
    assert.ok(
      bounds.bottom < window.innerHeight,
      `Popup bottom must leave backdrop margin: ${bounds.bottom} vs ${window.innerHeight}`,
    );
    assert.ok(
      popup.scrollWidth <= popup.clientWidth + 1,
      `Settings dialog overflowed horizontally: ${popup.scrollWidth} > ${popup.clientWidth}`,
    );

    const aside = popup.querySelector<HTMLElement>('aside[aria-label="Settings navigation"]')!;
    const contentPane = aside.nextElementSibling as HTMLElement;
    const asideRect = aside.getBoundingClientRect();
    const contentRect = contentPane.getBoundingClientRect();
    if (expectSideBySide) {
      assert.ok(
        asideRect.right <= contentRect.left + 1,
        `Sidebar (${asideRect.right}) must sit strictly left of content (${contentRect.left})`,
      );
      assert.ok(
        Math.abs(asideRect.top - contentRect.top) <= 1,
        'Sidebar and content pane must align at the top',
      );
    }
    assert.ok(
      contentPane.scrollWidth <= contentPane.clientWidth + 1,
      `Content pane overflowed horizontally: ${contentPane.scrollWidth} > ${contentPane.clientWidth}`,
    );

    const closeBtn = closeButton()!;
    const closeRect = closeBtn.getBoundingClientRect();
    assert.ok(
      closeRect.right <= bounds.right && closeRect.top >= bounds.top,
      'Close button must fit in the top-right corner',
    );
    assert.ok(
      closeRect.left >= bounds.right - 64 && closeRect.top <= bounds.top + 48,
      'Close button must be anchored in the top-right corner',
    );
    assert.ok(
      closeBtn.contains(
        document.elementFromPoint(
          closeRect.left + closeRect.width / 2,
          closeRect.top + closeRect.height / 2,
        ),
      ),
      'Close button must be directly clickable',
    );
  };

  let mountKey = 0;
  const mountApp = async (options: {
    theme?: 'dark' | 'light';
    authConfigured?: boolean;
    idleTimeoutMinutes?: number | null;
    pinned?: boolean;
    updateResult?: WormholeUpdateCheckResult | null;
  }) => {
    const mock = createWormholeMock({
      initialTheme: options.theme,
      updateResult: options.updateResult,
      idleSeconds: options.idleTimeoutMinutes ? 120 : 0,
    });
    window.wormhole = mock.api;
    const authConfigured = options.authConfigured ?? false;
    await React.act(async () =>
      root.render(
        <React.StrictMode key={++mountKey}>
          <ContextMenuOverlayProvider>
            <OverlayProbe />
            <App
              initialAuthState={{
                mode: authConfigured ? 'pin' : 'disabled',
                fallback: 'pin',
                idleTimeoutMinutes: options.idleTimeoutMinutes ?? null,
                hasPin: authConfigured,
                hasPassword: false,
                isCorrupted: false,
                configured: authConfigured,
                windowsHello: { available: false, message: '' },
              }}
              initialWorkspace={{
                tree: [],
                credentials: [],
                credentialOptions: { ssh: [], rdp: [], vnc: [] },
                tunnels: [],
              }}
              initialSettings={{
                theme: options.theme ?? 'dark',
                sshTerminalTheme: 'tango',
                promptBeforeTunnelConnect: true,
                autoCopyOnSelect: false,
                confirmOnTabClose: true,
                confirmOnWindowClose: true,
                sidebarWidth: 280,
                sidebarPinned: options.pinned ?? true,
                connectionTreeExpansion: null,
                autoCheckForUpdates: false,
                lastUpdateCheck: null,
                skippedUpdateVersion: null,
              }}
            />
          </ContextMenuOverlayProvider>
        </React.StrictMode>,
      ),
    );
    await tick();
    return mock;
  };

  const originalBridge = window.wormhole;
  await React.act(async () => window.settingsReducedMotion(true));
  try {
    if (mode === 'compact') {
      await mountApp({ theme: 'dark', pinned: false });
      const pin = query('[data-sidebar-pin]')!;
      const pinRect = pin.getBoundingClientRect();
      await React.act(async () =>
        window.settingsInput({
          type: 'mouseMove',
          x: Math.round(pinRect.left + pinRect.width / 2),
          y: Math.round(pinRect.top + pinRect.height / 2),
        }),
      );
      await waitFor(
        () => query('[data-sidebar-layout]')?.dataset.revealed === 'true',
        'Unpinned sidebar did not reveal at 640x480',
      );
      await clickElement(query('nav[aria-label="Main navigation"] button[aria-label="Settings"]')!);
      await waitFor(() => dialog() !== null, 'Settings did not open at 640x480');
      assertDialogGeometry(true);
      return;
    }

    // 1. Dark mode full flow: sidebar open, page preservation, occlusion, geometry, categories, search, close ways.
    const updateRelease: WormholeUpdateCheckResult = {
      currentVersion: '2.4.4',
      latestVersion: '2.5.0',
      isNewerRelease: true,
      isUpdateAvailable: true,
      checkFailed: false,
      releaseNotes: '## Wormhole 2.5.0\n\n- Overlay settings modal',
      installerUrl: 'https://example.test/Wormhole-2.5.0.exe',
      installerFileName: 'Wormhole-2.5.0.exe',
      installerSha256: 'a'.repeat(64),
      installerSize: 1024,
    };
    const mock = await mountApp({
      theme: 'dark',
      authConfigured: true,
      pinned: true,
      updateResult: updateRelease,
    });

    assert.equal(dialog(), null);
    assert.equal(
      overlayState(),
      'true',
      'UpdateNotification occludes native surfaces while visible',
    );

    // Dismiss update notification first so we can verify overlay state toggles cleanly on Settings open/close.
    await clickElement(query('[aria-label="Close update notification"]')!);
    await waitFor(
      () => query('[aria-label="Close update notification"]') === null,
      'Update banner did not dismiss',
    );
    assert.equal(
      overlayState(),
      'false',
      'Native surfaces become visible after dismissing update banner',
    );

    // Navigate to Tunnels and verify Settings opens over Tunnels without replacing it.
    await clickElement(query('nav[aria-label="Main navigation"] button[aria-label="Tunnels"]')!);
    assert.match(insetText(), /Tunnels/i);

    const settingsNavBtn = query(
      'nav[aria-label="Main navigation"] button[aria-label="Settings"]',
    )!;
    assert.equal(settingsNavBtn.getAttribute('aria-haspopup'), 'dialog');
    assert.equal(settingsNavBtn.getAttribute('aria-current'), null);
    await clickElement(settingsNavBtn);

    await waitFor(() => dialog() !== null, 'Settings overlay did not open');
    assert.equal(overlayState(), 'true', 'Open Settings overlay must occlude native surfaces');
    assert.match(insetText(), /Tunnels/i, 'Underlying page must stay rendered behind the modal');
    assertDialogGeometry(true);

    // Verify all 8 categories switch properly and display their heading & subtitle.
    const expectedPanels = [
      ['File transfer', 'Remote file editors, size limits, and working copy recovery.'],
      ['Security', 'App lock, Windows Hello, and idle auto-lock.'],
      ['Extensions', 'Use Bitwarden for credential passwords and Browser connections.'],
      [
        'AI Agent (MCP)',
        'Let a local AI agent open saved connections and control live SSH sessions.',
      ],
      ['Backup & Restore', 'Export and merge connections, credentials, SSH keys, and VPN tunnels.'],
      ['Logs', 'Diagnostic log files, verbosity, and daily rotation.'],
      ['Updates', 'Application version, automatic checks, and release notes.'],
      ['General', 'Appearance, tabs, terminal, and tunnel defaults.'],
    ] as const;

    for (const [label, description] of expectedPanels) {
      const tab = [...dialog()!.querySelectorAll<HTMLButtonElement>('[role="tab"]')].find((item) =>
        item.textContent?.includes(label),
      );
      assert.ok(tab, `Missing category tab: ${label}`);
      await clickElement(tab);
      const activePanel = dialog()!.querySelector<HTMLElement>(
        '[role="tabpanel"][data-state="active"]',
      );
      assert.ok(activePanel, `Expected active panel for ${label}`);
      assert.equal(activePanel.querySelector('h2')?.textContent, label);
      assert.ok(activePanel.textContent?.includes(description));
    }

    // Verify search filtering, automatic tab switch, empty state + clear search.
    const searchInput = dialog()!.querySelector<HTMLInputElement>(
      '[aria-label="Search settings"]',
    )!;
    await setInputValue(searchInput, 'bitwarden');
    assert.deepEqual(
      [...dialog()!.querySelectorAll<HTMLButtonElement>('[role="tab"]')].map((tab) =>
        tab.textContent?.trim(),
      ),
      ['Extensions'],
    );
    assert.equal(
      dialog()!.querySelector('[role="tabpanel"][data-state="active"] h2')?.textContent,
      'Extensions',
    );

    await setInputValue(searchInput, 'does-not-match-anything');
    assert.equal(dialog()!.querySelectorAll('[role="tab"]').length, 0);
    assert.ok(dialog()!.textContent?.includes('No matching settings'));
    await clickElement(
      [...dialog()!.querySelectorAll<HTMLButtonElement>('button')].find(
        (button) => button.textContent?.trim() === 'Clear search',
      )!,
    );
    assert.equal(searchInput.value, '');
    assert.equal(dialog()!.querySelectorAll('[role="tab"]').length, 8);
    assert.equal(
      dialog()!.querySelector('[role="tabpanel"][data-state="active"] h2')?.textContent,
      'General',
    );

    // Close via Close button.
    await clickElement(closeButton()!);
    await waitFor(() => dialog() === null, 'Close button did not dismiss Settings');
    assert.equal(overlayState(), 'false');
    assert.match(insetText(), /Tunnels/i);

    // Reopen, close via Escape.
    await clickElement(settingsNavBtn);
    await waitFor(() => dialog() !== null, 'Settings did not reopen');
    await keypress('Escape');
    await waitFor(() => dialog() === null, 'Escape did not dismiss Settings');
    assert.equal(overlayState(), 'false');

    // Reopen, close via backdrop click.
    await clickElement(settingsNavBtn);
    await waitFor(() => dialog() !== null, 'Settings did not reopen before backdrop click');
    await clickPoint(8, 8);
    await waitFor(() => dialog() === null, 'Backdrop click did not dismiss Settings');
    assert.equal(overlayState(), 'false');

    // Navigate to Credentials and emit a newer update -> "View changes" opens Updates directly over Credentials.
    await clickElement(
      query('nav[aria-label="Main navigation"] button[aria-label="Credentials"]')!,
    );
    assert.match(insetText(), /Credentials/i);
    await React.act(async () => mock.emitUpdate({ ...updateRelease, latestVersion: '2.6.0' }));
    await waitFor(
      () => query('[aria-label="Close update notification"]') !== null,
      'Newer update banner did not appear',
    );
    await clickElement(
      [...document.querySelectorAll<HTMLButtonElement>('button')].find(
        (button) => button.textContent?.trim() === 'View changes',
      )!,
    );
    await waitFor(() => dialog() !== null, 'View changes did not open Settings overlay');
    assert.match(insetText(), /Credentials/i);
    assert.equal(
      dialog()!.querySelector('[role="tabpanel"][data-state="active"] h2')?.textContent,
      'Updates',
    );

    // While Settings is open on another tab with an active search, emitting a newer update leaves
    // UpdateNotification behind the modal backdrop until Settings closes; closing and clicking
    // "View changes" clears the prior search/tab state and opens straight to Updates.
    await setInputValue(
      dialog()!.querySelector<HTMLInputElement>('[aria-label="Search settings"]')!,
      'mcp',
    );
    assert.equal(
      dialog()!.querySelector('[role="tabpanel"][data-state="active"] h2')?.textContent,
      'AI Agent (MCP)',
    );
    await React.act(async () => mock.emitUpdate({ ...updateRelease, latestVersion: '2.7.0' }));
    await waitFor(
      () => query('[aria-label="Close update notification"]') !== null,
      'Second update banner did not appear',
    );
    const viewChangesBtn = [...document.querySelectorAll<HTMLButtonElement>('button')].find(
      (button) => button.textContent?.trim() === 'View changes',
    )!;
    const viewChangesRect = viewChangesBtn.getBoundingClientRect();
    const hitWhileModalOpen = document.elementFromPoint(
      Math.round(viewChangesRect.left + viewChangesRect.width / 2),
      Math.round(viewChangesRect.top + viewChangesRect.height / 2),
    );
    assert.equal(
      viewChangesBtn.contains(hitWhileModalOpen),
      false,
      'Background UpdateNotification must stay behind the open modal backdrop',
    );
    assert.equal(
      dialog()!.querySelector('[role="tabpanel"][data-state="active"] h2')?.textContent,
      'AI Agent (MCP)',
    );

    await clickElement(closeButton()!);
    await waitFor(() => dialog() === null, 'Settings did not close before clicking View changes');
    await clickElement(
      [...document.querySelectorAll<HTMLButtonElement>('button')].find(
        (button) => button.textContent?.trim() === 'View changes',
      )!,
    );
    await waitFor(() => dialog() !== null, 'View changes did not reopen Settings overlay');
    assert.match(insetText(), /Credentials/i);
    assert.equal(
      dialog()!.querySelector<HTMLInputElement>('[aria-label="Search settings"]')!.value,
      '',
    );
    assert.equal(
      dialog()!.querySelector('[role="tabpanel"][data-state="active"] h2')?.textContent,
      'Updates',
    );
    assert.ok(dialog()!.textContent?.includes('Update available: 2.7.0'));

    // Test AuthPrompt stacking over open Settings ("Test app lock" in Security).
    const securityTab = [...dialog()!.querySelectorAll<HTMLButtonElement>('[role="tab"]')].find(
      (item) => item.textContent?.includes('Security'),
    )!;
    await clickElement(securityTab);
    await clickElement(
      [...dialog()!.querySelectorAll<HTMLButtonElement>('button')].find(
        (button) => button.textContent?.trim() === 'Test app lock',
      )!,
    );
    await waitFor(
      () => query<HTMLDialogElement>('dialog[open]') !== null,
      'AuthPrompt did not open',
    );
    const authInput = query<HTMLInputElement>('dialog[open] #auth-secret')!;
    const authRect = authInput.getBoundingClientRect();
    assert.ok(
      authInput.contains(
        document.elementFromPoint(
          authRect.left + authRect.width / 2,
          authRect.top + authRect.height / 2,
        ),
      ),
      'AuthPrompt input must stay hit-testable above the Settings overlay',
    );
    await keypress('Escape');
    await waitFor(
      () => query<HTMLDialogElement>('dialog[open]') === null,
      'Escape did not cancel AuthPrompt',
    );
    assert.ok(dialog() !== null, 'Canceling AuthPrompt must keep Settings overlay open');

    // Verify full lock (authGate === 'locked') hides/inerts Settings without unmounting, then restores it on unlock.
    const realSetInterval = window.setInterval;
    const realClearInterval = window.clearInterval;
    const realDateNow = Date.now;
    let timeOffset = 0;
    const activeIdleIntervals = new Map<number, () => void>();
    window.setInterval = ((handler: TimerHandler, timeout?: number, ...args: unknown[]) => {
      const id = (realSetInterval as (...fnArgs: unknown[]) => number)(handler, timeout, ...args);
      if (timeout === 15_000 && typeof handler === 'function') {
        activeIdleIntervals.set(id, () => (handler as (...cbArgs: unknown[]) => void)(...args));
      }
      return id;
    }) as typeof window.setInterval;
    window.clearInterval = ((id?: number) => {
      if (id !== undefined) activeIdleIntervals.delete(id);
      return realClearInterval(id);
    }) as typeof window.clearInterval;
    Date.now = () => realDateNow() + timeOffset;
    try {
      await mountApp({ theme: 'dark', authConfigured: true, idleTimeoutMinutes: 1, pinned: true });
      await clickElement(query('nav[aria-label="Main navigation"] button[aria-label="Settings"]')!);
      await waitFor(() => dialog() !== null, 'Settings did not open before idle lock');
      const lockSecurityTab = [
        ...dialog()!.querySelectorAll<HTMLButtonElement>('[role="tab"]'),
      ].find((item) => item.textContent?.includes('Security'))!;
      await clickElement(lockSecurityTab);
      assert.equal(activeIdleIntervals.size, 1, 'Expected one active idle check interval');
      timeOffset = 120_000;
      await React.act(async () => {
        for (const callback of activeIdleIntervals.values()) callback();
      });
      await waitFor(
        () =>
          query<HTMLDialogElement>('dialog[open]')?.textContent?.includes('Wormhole is locked') ??
          false,
        'Idle lock AuthPrompt did not open',
      );
      const lockedDialog = dialog();
      assert.ok(lockedDialog !== null, 'Settings dialog must remain mounted while locked');
      assert.equal(lockedDialog.dataset.locked, 'true');
      assert.equal(lockedDialog.inert, true);
      assert.equal(getComputedStyle(lockedDialog).visibility, 'hidden');

      const lockInput = query<HTMLInputElement>('dialog[open] #auth-secret')!;
      await setInputValue(lockInput, '1234');
      await clickElement(
        [...query('dialog[open]')!.querySelectorAll<HTMLButtonElement>('button')].find(
          (button) => button.textContent?.trim() === 'Unlock',
        )!,
      );
      await waitFor(
        () => query<HTMLDialogElement>('dialog[open]') === null,
        'Unlocking did not dismiss lock AuthPrompt',
      );
      await waitFor(
        () => dialog()?.dataset.locked === 'false',
        'Settings dialog did not become active again after unlock',
      );
      assert.equal(dialog()!.inert, false);
      assert.equal(getComputedStyle(dialog()!).visibility, 'visible');
      assert.equal(
        dialog()!.querySelector('[role="tabpanel"][data-state="active"] h2')?.textContent,
        'Security',
      );
    } finally {
      window.setInterval = realSetInterval;
      window.clearInterval = realClearInterval;
      Date.now = realDateNow;
    }

    // 2. Light theme geometry & rendering check.
    await mountApp({ theme: 'light', pinned: true });
    await clickElement(query('nav[aria-label="Main navigation"] button[aria-label="Settings"]')!);
    await waitFor(() => dialog() !== null, 'Settings did not open in light theme');
    assertDialogGeometry(true);
  } finally {
    await React.act(async () => root.unmount());
    window.wormhole = originalBridge;
    await React.act(async () => window.settingsReducedMotion(false));
  }
};
