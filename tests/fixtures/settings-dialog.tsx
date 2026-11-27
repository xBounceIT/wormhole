import * as React from 'react';
import { createRoot } from 'react-dom/client';
import App from '../../src/App';
import { latestRelease } from '../../src/changelog/latest-release';
import { VisualChangelogCarousel } from '../../src/components/VisualChangelog';
import {
  ContextMenuOverlayProvider,
  useContextMenuOverlayOpen,
} from '../../src/components/ui/context-menu';
import { applyTheme } from '../../src/theme';
import '../../src/startup.css';
import '../../src/index.css';

declare global {
  interface Window {
    settingsAssert: typeof import('node:assert/strict');
    settingsInput: (event: Record<string, unknown>) => Promise<void>;
    settingsHover: (selector: string, enabled: boolean) => Promise<void>;
    settingsReducedMotion: (reduce: boolean) => Promise<void>;
    settingsSearchPixels: (point: { x: number; y: number }) => Promise<number[]>;
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
  initialTheme?: WormholeAppSettings['theme'];
  updateResult?: WormholeUpdateCheckResult | null;
  idleSeconds?: number;
  currentVersion?: string;
  claimVisualChangelog?: (hasChangelog: boolean) => Promise<{ claimed: boolean }>;
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
    setTheme: async (nextTheme: WormholeAppSettings['theme']) => {
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
      currentVersion: options.currentVersion ?? '2.4.4',
      result: currentUpdateResult,
    }),
    claimVisualChangelog: options.claimVisualChangelog ?? (async () => ({ claimed: false })),
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

  function searchAppearance(input: HTMLElement) {
    const field = input.closest('[data-slot="search-field"]');
    assert.ok(field);
    assert.ok(!input.matches(':focus-visible'));
    const style = getComputedStyle(input);
    const icon = getComputedStyle(field.querySelector('svg')!);
    return {
      height: style.height,
      radius: style.borderTopLeftRadius,
      border: style.borderTopColor,
      background: style.backgroundColor,
      fontSize: style.fontSize,
      lineHeight: style.lineHeight,
      padding: style.paddingInlineStart,
      placeholder: getComputedStyle(input, '::placeholder').color,
      iconSize: icon.width,
      iconOffset: icon.left,
      iconColor: icon.color,
    };
  }

  async function searchBorderPixel(input: HTMLElement, theme: 'light' | 'dark') {
    const { left, width, top } = input.getBoundingClientRect();
    const pixels = await window.settingsSearchPixels({
      x: Math.floor(left + width / 2),
      y: Math.round(top),
    });
    const [outside, before, edge, after, inside] = pixels;
    assert.ok(
      [edge, before, after].some(
        (pixel) =>
          Math.abs(outside - pixel) >= 7 && (theme === 'light' ? pixel < inside : pixel > inside),
      ),
      `${input.getAttribute('aria-label')} must draw a visible ${theme} border. Pixels ${pixels.join(', ')}`,
    );
  }

  const moveTo = async (element: HTMLElement) => {
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
    return { x, y };
  };

  const clickElement = async (element: HTMLElement) => {
    const { x, y } = await moveTo(element);
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
    assert.equal(getComputedStyle(popup).borderRadius, '16px');
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

  const assertSwitchAlignment = (label: string) => {
    const toggle = dialog()!.querySelector<HTMLButtonElement>(
      `[role="switch"][aria-label="${label}"]`,
    )!;
    const track = toggle.getBoundingClientRect();
    const thumb = toggle.querySelector('[data-slot="switch-thumb"]')!.getBoundingClientRect();
    const text = toggle.previousElementSibling!.getBoundingClientRect();
    assert.equal(thumb.top - track.top, 1, `${label} needs a 1px inset above the thumb`);
    assert.equal(track.bottom - thumb.bottom, 1, `${label} needs a 1px inset below the thumb`);
    assert.ok(
      Math.abs((track.top + track.bottom) / 2 - (text.top + text.bottom) / 2) < 0.02,
      `${label} must be centered on its title and description`,
    );
    return toggle;
  };

  let mountKey = 0;
  const mountApp = async (options: {
    theme?: WormholeAppSettings['theme'];
    authConfigured?: boolean;
    idleTimeoutMinutes?: number | null;
    pinned?: boolean;
    updateResult?: WormholeUpdateCheckResult | null;
    currentVersion?: string;
    claimVisualChangelog?: (hasChangelog: boolean) => Promise<{ claimed: boolean }>;
  }) => {
    const mock = createWormholeMock({
      ...options,
      initialTheme: options.theme,
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

  async function assertVisualChangelog() {
    const carousel = () => query('[data-visual-changelog][data-state="open"]');
    const title = () => carousel()?.querySelector('h3')?.textContent;
    const button = (text: string) =>
      [...carousel()!.querySelectorAll<HTMLButtonElement>('button')].find(
        (button) => button.textContent?.trim() === text,
      )!;
    let claims = 0;
    const checkVisualChangelog = async (hasChangelog: boolean) => ({
      claimed: hasChangelog && ++claims === 1,
    });
    const { slides, version } = latestRelease;

    for (const currentVersion of [version.replace(/0$/, '1'), `${version}-preview.1`, '0.0.0']) {
      let checked = false;
      await mountApp({
        currentVersion,
        claimVisualChangelog: async (hasChangelog) => {
          checked = true;
          assert.equal(hasChangelog, false);
          return { claimed: false };
        },
      });
      assert.equal(checked, true, 'Unmatched versions are recorded without claiming slides');
      assert.equal(carousel(), null);
    }

    await mountApp({ currentVersion: version, claimVisualChangelog: checkVisualChangelog });
    await waitFor(() => carousel() !== null, 'Changelog did not open for its release');
    assert.equal(claims, 1, 'StrictMode must send one claim');
    assert.equal(overlayState(), 'true', 'Native session surfaces must stay below the dialog');
    assert.equal(title(), slides[0].title);
    assert.equal(button('Back').getAttribute('aria-disabled'), 'true');
    const bounds = carousel()!.getBoundingClientRect();
    assert.ok(bounds.top >= 0 && bounds.bottom <= innerHeight && bounds.left >= 0);

    if (slides.length > 1) {
      await clickElement(button('Next'));
      assert.equal(title(), slides[1]!.title, 'Next must advance the carousel');
      await clickElement(button('Back'));
      assert.equal(title(), slides[0].title, 'Back must show the previous slide');
      await keypress('Right');
      assert.equal(title(), slides[1]!.title, 'Arrow navigation must retain focus after Back');
    }
    await clickElement(carousel()!.querySelector('[data-slot="dialog-close"]')!);
    await waitFor(() => carousel() === null, 'The close button did not dismiss the changelog');
    assert.equal(overlayState(), 'false');
    assert.equal(claims, 1);

    await mountApp({ currentVersion: version, claimVisualChangelog: checkVisualChangelog });
    assert.equal(claims, 2);
    assert.equal(carousel(), null, 'A recorded release must stay dismissed after relaunch');

    let resolveClaim!: (value: { claimed: boolean }) => void;
    const pendingClaim = new Promise<{ claimed: boolean }>((resolve) => {
      resolveClaim = resolve;
    });
    await mountApp({ currentVersion: version, claimVisualChangelog: () => pendingClaim });
    await React.act(async () =>
      query<HTMLButtonElement>('button[aria-label="Quick Connect"]')!.click(),
    );
    await waitFor(
      () =>
        [...document.querySelectorAll('[role="dialog"] [data-slot="dialog-title"]')].some(
          (title) => title.textContent === 'Quick Connect',
        ),
      'Quick Connect did not open',
    );
    await React.act(async () => resolveClaim({ claimed: true }));
    assert.equal(carousel(), null, 'Changelog must wait for the existing dialog');
    await keypress('Escape');
    await waitFor(() => carousel() !== null, 'Changelog must open after Quick Connect closes');
    for (const [index, slide] of slides.entries()) {
      assert.equal(title(), slide.title);
      assert.ok(carousel()!.textContent?.includes(slide.subtitle));
      const { media } = slide;
      if (media.kind !== 'video') {
        const image = carousel()!.querySelector('img')!;
        await image.decode();
        assert.ok(image.alt.trim() && image.alt === media.alt);
        assert.ok(image.naturalWidth > 0 && image.naturalHeight > 0);
        const frame = image.closest('picture')!.parentElement!.getBoundingClientRect();
        const bounds = image.getBoundingClientRect();
        assert.ok(
          bounds.left >= frame.left - 1 &&
            bounds.right <= frame.right + 1 &&
            bounds.top >= frame.top - 1 &&
            bounds.bottom <= frame.bottom + 1,
          `${slide.title} preview (${bounds.width}×${bounds.height}) must fit its frame (${frame.width}×${frame.height})`,
        );
        if (media.kind === 'gif') {
          assert.equal(image.currentSrc, media.poster);
          await window.settingsReducedMotion(false);
          await waitFor(
            () => image.currentSrc === media.src,
            'The visible slide must select its GIF',
          );
          await image.decode();
          await window.settingsReducedMotion(true);
          await waitFor(() => image.currentSrc === media.poster, 'The still preview must return');
          await image.decode();
        }
      }
      await clickElement(button(index === slides.length - 1 ? 'Done' : 'Next'));
    }
    await waitFor(() => carousel() === null, 'Done must dismiss the last release slide');

    let attempts = 0;
    await mountApp({
      currentVersion: version,
      claimVisualChangelog: async () => {
        if (++attempts === 1) throw new Error('Settings unavailable');
        return { claimed: true };
      },
    });
    assert.equal(carousel(), null, 'A failed claim must leave the workspace usable');
    await React.act(async () => query<HTMLButtonElement>('button[aria-label="Settings"]')!.click());
    await waitFor(() => dialog() !== null, 'Settings did not open after a failed claim');
    await keypress('Escape');
    await waitFor(() => carousel() !== null, 'The next eligible check must retry a failed claim');
    assert.equal(attempts, 2);
    await clickElement(carousel()!.querySelector('[data-slot="dialog-close"]')!);

    const gif = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';
    const poster = `data:image/svg+xml,${encodeURIComponent(
      '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>',
    )}`;
    const video = URL.createObjectURL(new MediaSource());
    const captions = `data:text/vtt,${encodeURIComponent('WEBVTT\n\n00:00:00.000 --> 00:00:01.000\nRelease preview\n')}`;
    let finished = false;
    try {
      await React.act(async () =>
        root.render(
          <ContextMenuOverlayProvider>
            <VisualChangelogCarousel
              onClose={() => {
                finished = true;
              }}
              open
              release={{
                version,
                slides: [
                  {
                    title: 'Animated preview',
                    subtitle: 'GIF slide',
                    media: { kind: 'gif', src: gif, poster, alt: 'Preview' },
                  },
                  {
                    title: 'Video preview',
                    subtitle: 'Video slide',
                    media: { kind: 'video', src: video, label: 'Demo', captions },
                  },
                ],
              }}
            />
          </ContextMenuOverlayProvider>,
        ),
      );
      const image = carousel()!.querySelector('img')!;
      await image.decode();
      assert.equal(image.currentSrc, poster, 'Reduced motion must select the static GIF preview');
      await clickElement(button('Next'));
      const player = carousel()!.querySelector('video')!;
      assert.equal(player.controls, true);
      assert.equal(player.autoplay, false);
      const captionTrack = player.querySelector('track')!;
      captionTrack.track.mode = 'hidden';
      await waitFor(() => captionTrack.readyState === 2, 'The video captions did not load');
      assert.equal(captionTrack.track.cues?.length, 1);
      await React.act(async () => player.dispatchEvent(new Event('error')));
      assert.match(carousel()!.textContent ?? '', /Preview unavailable/);
      await clickElement(button('Done'));
      assert.equal(finished, true);
    } finally {
      URL.revokeObjectURL(video);
    }
  }

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
      assertSwitchAlignment('Confirm before closing Wormhole');
      await assertVisualChangelog();
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
    assert.equal(searchInput.getBoundingClientRect().height, 32);
    assert.ok(parseFloat(getComputedStyle(searchInput).borderTopLeftRadius) >= 16);
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

    await clickElement(
      dialog()!.querySelector<HTMLButtonElement>('[aria-label="Clear settings search"]')!,
    );
    assert.equal(searchInput.value, '');
    assert.ok(document.activeElement === searchInput);

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
    const regenerate = [...dialog()!.querySelectorAll<HTMLButtonElement>('button')].find(
      (button) => button.textContent?.trim() === 'Regenerate',
    )!;
    const confirmRegeneration = () => query('[role="alertdialog"][data-state="open"]');
    await clickElement(regenerate);
    await waitFor(() => Boolean(confirmRegeneration()), 'MCP confirmation did not open');
    assert.equal(getComputedStyle(confirmRegeneration()!).borderRadius, '16px');
    await keypress('Escape');
    await waitFor(() => !confirmRegeneration(), 'Escape did not close the MCP confirmation');
    assert.ok(dialog(), 'Cancelling a nested confirmation must keep Settings open');
    assert.equal(query<HTMLInputElement>('#settings-mcp-token')!.value, '');
    await clickElement(regenerate);
    await clickElement(
      [...confirmRegeneration()!.querySelectorAll<HTMLButtonElement>('button')].find(
        (button) => button.textContent?.trim() === 'Regenerate token',
      )!,
    );
    assert.equal(query<HTMLInputElement>('#settings-mcp-token')!.value, 'new-token');
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
      const selectSettingsTab = (name: string) =>
        clickElement(
          [...dialog()!.querySelectorAll<HTMLButtonElement>('[role="tab"]')].find((tab) =>
            tab.textContent?.includes(name),
          )!,
        );
      let resolveToken!: (value: string) => void;
      let resolvePicker!: (value: WormholeBackupImportSelection) => void;
      window.wormhole!.getMcpToken = () =>
        new Promise((resolve) => {
          resolveToken = resolve;
        });
      window.wormhole!.selectBackupForImport = () =>
        new Promise((resolve) => {
          resolvePicker = resolve;
        });
      await selectSettingsTab('MCP');
      await clickElement(query('#settings-mcp-token')!.parentElement!.querySelector('button')!);
      await selectSettingsTab('Backup & Restore');
      await clickElement(
        [...dialog()!.querySelectorAll<HTMLButtonElement>('button')].find(
          (button) => button.textContent?.trim() === 'Import backup…',
        )!,
      );
      let discards = 0;
      window.wormhole!.sftpEdit = async (sessionId, request) => {
        if (request.operation === 'discard') discards++;
        return {
          type: 'sftp.edit',
          sessionId,
          edits: [
            {
              id: 'recovered',
              sessionId,
              nodeId: 'node',
              name: 'draft.txt',
              remotePath: '/draft.txt',
              editor: 'System',
              state: 'Recovered',
              pending: true,
              recovered: true,
            },
          ],
        };
      };
      const fileTransferTab = [
        ...dialog()!.querySelectorAll<HTMLButtonElement>('[role="tab"]'),
      ].find((item) => item.textContent?.includes('File transfer'))!;
      await clickElement(fileTransferTab);
      const discard = () =>
        [...dialog()!.querySelectorAll<HTMLButtonElement>('button')].find(
          (item) => item.textContent?.trim() === 'Discard',
        );
      await waitFor(() => Boolean(discard()), 'Missing recovered SFTP file');
      await clickElement(discard()!);
      await waitFor(
        () => Boolean(query('[role="alertdialog"][data-state="open"]')),
        'Discard confirmation did not open',
      );
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
      assert.ok(
        !query('[role="alertdialog"][data-state="open"]'),
        'Lock must cancel the pending discard',
      );
      assert.equal(getComputedStyle(lockedDialog).visibility, 'hidden');
      assert.equal(
        getComputedStyle(query('dialog[open] [data-dialog-surface]')!).borderRadius,
        '16px',
      );

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
        'File transfer',
      );
      await React.act(async () => {
        resolvePicker({
          fileName: 'retired-selection.json',
          encrypted: false,
          schemaVersion: 1,
          exportedAt: '',
        });
        resolveToken('retired-test-token');
      });
      assert.ok(!document.body.textContent?.includes('retired-selection.json'));
      await selectSettingsTab('MCP');
      assert.equal(query<HTMLInputElement>('#settings-mcp-token')!.value, '');
      assert.equal(discards, 0);
      assert.ok(!query('[role="alertdialog"][data-state="open"]'));
    } finally {
      window.setInterval = realSetInterval;
      window.clearInterval = realClearInterval;
      Date.now = realDateNow;
    }

    // 2. Light theme geometry & rendering check.
    await mountApp({ theme: 'light', pinned: true });
    const connectionsSearch = query('[aria-label="Search connections"]')!;
    const tabsSearchButton = query('[aria-label="Search open tabs"]')!;
    await clickElement(tabsSearchButton);
    const tabsSearch = query('[aria-label="Search open tabs by title"]')!;
    await waitFor(
      () => document.activeElement === tabsSearch,
      'Tab search did not focus its input',
    );
    await React.act(async () => tabsSearch.blur());
    const tabSearchPopoverStyle = getComputedStyle(query('[data-session-tab-search]')!);
    assert.equal(tabSearchPopoverStyle.backgroundColor, 'oklch(1 0 0)');
    const lightTabsSearchStyle = searchAppearance(tabsSearch);
    await searchBorderPixel(tabsSearch, 'light');
    await searchBorderPixel(connectionsSearch, 'light');
    applyTheme('dark');
    assert.equal(tabSearchPopoverStyle.backgroundColor, 'rgb(27, 27, 27)');
    const darkTabsSearchStyle = searchAppearance(tabsSearch);
    await searchBorderPixel(tabsSearch, 'dark');
    await searchBorderPixel(connectionsSearch, 'dark');
    applyTheme('oled');
    assert.equal(tabSearchPopoverStyle.backgroundColor, 'oklch(0.145 0 0)');
    applyTheme('light');
    await clickElement(tabsSearchButton);
    const sessionsButton = query('nav[aria-label="Main navigation"] [aria-label="Sessions"]')!;
    const credentialsSelector = 'nav[aria-label="Main navigation"] [aria-label="Credentials"]';
    const credentialsButton = query(credentialsSelector)!;
    const selectedBackground = getComputedStyle(sessionsButton).backgroundColor;
    const idleBackground = getComputedStyle(credentialsButton).backgroundColor;
    const pointer = await moveTo(credentialsButton);
    await window.settingsHover(credentialsSelector, true);
    const navigationHover = getComputedStyle(credentialsButton).backgroundColor;
    assert.notEqual(navigationHover, idleBackground);
    assert.notEqual(navigationHover, selectedBackground);
    await React.act(async () =>
      window.settingsInput({ type: 'mouseDown', button: 'left', ...pointer, clickCount: 1 }),
    );
    await waitFor(
      () => getComputedStyle(credentialsButton).backgroundColor !== navigationHover,
      'Credentials should give immediate feedback while pressed',
    );
    assert.equal(sessionsButton.getAttribute('aria-current'), 'page');
    await React.act(async () =>
      window.settingsInput({ type: 'mouseUp', button: 'left', ...pointer, clickCount: 1 }),
    );
    await waitFor(
      () => credentialsButton.getAttribute('aria-current') === 'page',
      'Credentials should activate on a completed click',
    );
    assert.equal(getComputedStyle(credentialsButton).backgroundColor, selectedBackground);
    await window.settingsHover(credentialsSelector, false);
    await clickElement(sessionsButton);
    await clickElement(query('nav[aria-label="Main navigation"] button[aria-label="Settings"]')!);
    await waitFor(() => dialog() !== null, 'Settings did not open in light theme');
    assertDialogGeometry(true);
    const confirmTabClose = assertSwitchAlignment('Confirm before closing a connected tab');
    assertSwitchAlignment('Confirm before closing Wormhole');
    assert.equal(confirmTabClose.getAttribute('aria-checked'), 'true');
    await clickElement(confirmTabClose);
    assert.equal(confirmTabClose.getAttribute('aria-checked'), 'false');
    assertSwitchAlignment('Confirm before closing a connected tab');
    const settingsSearch = dialog()!.querySelector<HTMLElement>('[aria-label="Search settings"]')!;
    const settingsSidebar = dialog()!.querySelector('[aria-label="Settings navigation"]')!;
    function assertSharedPalette() {
      const sidebar = getComputedStyle(settingsSidebar).backgroundColor;
      const canvas = getComputedStyle(settingsSidebar.nextElementSibling!).backgroundColor;
      for (const selector of ['[data-workspace-shell]', '[data-sidebar-surface]', 'header']) {
        assert.equal(getComputedStyle(query(selector)!).backgroundColor, sidebar);
      }
      assert.equal(getComputedStyle(query('[data-session-canvas]')!).backgroundColor, canvas);
      return { sidebar, canvas };
    }
    assertSharedPalette();
    const lightSearchStyle = searchAppearance(settingsSearch);
    await searchBorderPixel(settingsSearch, 'light');
    assert.equal(lightSearchStyle.fontSize, '14px');
    assert.deepEqual(searchAppearance(connectionsSearch), lightSearchStyle, 'Connections in light');
    assert.deepEqual(lightTabsSearchStyle, lightSearchStyle, 'Tabs in light');
    const category = dialog()!.querySelector<HTMLElement>('[role="tab"][aria-selected="true"]')!;
    const navigation = query('nav[aria-label="Main navigation"] [aria-current="page"]')!;
    const settingsLauncher = query('nav[aria-label="Main navigation"] [aria-expanded="true"]')!;
    const inactive = dialog()!.querySelector<HTMLElement>('[role="tab"][aria-selected="false"]')!;
    const settingsPointer = await moveTo(inactive);
    const inactiveSelector = `#${CSS.escape(inactive.id)}`;
    await window.settingsHover(inactiveSelector, true);
    assert.equal(getComputedStyle(inactive).backgroundColor, navigationHover);
    await React.act(async () =>
      window.settingsInput({
        type: 'mouseDown',
        button: 'left',
        ...settingsPointer,
        clickCount: 1,
      }),
    );
    await waitFor(
      () => inactive.getAttribute('aria-selected') === 'true',
      'The Settings category should activate before the mouse button is released',
    );
    assert.equal(getComputedStyle(inactive).backgroundColor, selectedBackground);
    await React.act(async () =>
      window.settingsInput({ type: 'mouseUp', button: 'left', ...settingsPointer, clickCount: 1 }),
    );
    await window.settingsHover(inactiveSelector, false);
    await clickElement(category);
    const nextNavigation = navigation.parentElement!.nextElementSibling!.querySelector('button')!;
    assert.equal(
      nextNavigation.getBoundingClientRect().top - navigation.getBoundingClientRect().top,
      inactive.getBoundingClientRect().top - category.getBoundingClientRect().top,
    );
    const categoryStyle = getComputedStyle(category);
    const navStyle = getComputedStyle(navigation);
    const settingsLauncherStyle = getComputedStyle(settingsLauncher);
    for (const property of [
      'height',
      'columnGap',
      'paddingInlineStart',
      'paddingInlineEnd',
      'borderTopLeftRadius',
      'fontSize',
      'fontWeight',
    ] as const) {
      assert.equal(navStyle[property], categoryStyle[property], property);
    }
    const iconStyle = getComputedStyle(navigation.querySelector('svg')!);
    const categoryIconStyle = getComputedStyle(category.querySelector('svg')!);
    assert.equal(iconStyle.width, categoryIconStyle.width);
    assert.equal(iconStyle.opacity, categoryIconStyle.opacity);
    assert.equal(navStyle.backgroundColor, categoryStyle.backgroundColor);
    assert.equal(
      navStyle.getPropertyValue('--tw-shadow'),
      categoryStyle.getPropertyValue('--tw-shadow'),
    );
    assert.notEqual(categoryStyle.backgroundColor, getComputedStyle(inactive).backgroundColor);
    assert.notEqual(
      categoryStyle.getPropertyValue('--tw-shadow'),
      getComputedStyle(inactive).getPropertyValue('--tw-shadow'),
    );
    assert.equal(navStyle.transitionProperty, 'none');
    assert.equal(categoryStyle.transitionProperty, 'none');
    assert.equal(settingsLauncherStyle.backgroundColor, categoryStyle.backgroundColor);
    await React.act(async () => window.settingsReducedMotion(false));
    assert.equal(navStyle.transitionProperty, 'background-color, color, box-shadow');
    assert.equal(navStyle.transitionProperty, categoryStyle.transitionProperty);
    assert.equal(navStyle.transitionDuration, categoryStyle.transitionDuration);
    const lightBackground = navStyle.backgroundColor;
    applyTheme('dark');
    const darkPalette = assertSharedPalette();
    const darkSearchStyle = searchAppearance(settingsSearch);
    await searchBorderPixel(settingsSearch, 'dark');
    assert.deepEqual(searchAppearance(connectionsSearch), darkSearchStyle, 'Connections in dark');
    assert.deepEqual(darkTabsSearchStyle, darkSearchStyle, 'Tabs in dark');
    assert.notEqual(navStyle.backgroundColor, lightBackground);
    assert.equal(navStyle.backgroundColor, categoryStyle.backgroundColor);
    assert.equal(settingsLauncherStyle.backgroundColor, categoryStyle.backgroundColor);
    applyTheme('light');
    assert.equal(navStyle.backgroundColor, lightBackground);
    assert.equal(categoryStyle.backgroundColor, lightBackground);

    async function chooseTheme(label: 'Dark' | 'OLED') {
      const trigger = query('#settings-theme')!;
      await clickElement(trigger);
      const option = Array.from(document.querySelectorAll<HTMLElement>('[role="option"]')).find(
        (item) => item.textContent?.trim() === label,
      );
      assert.ok(option, `Missing ${label} theme`);
      await clickElement(option);
      assert.equal(trigger.textContent?.trim(), label);
      assert.equal((await window.wormhole!.readAppSettings()).theme, label.toLowerCase());
      // Chromium reports interpolated colors in Oklab while a label is transitioning.
      await waitFor(
        () =>
          !document
            .getAnimations()
            .some(
              (animation) =>
                animation instanceof CSSTransition && animation.transitionProperty === 'color',
            ),
        `Label colors did not settle after selecting ${label}`,
      );
    }

    function assertBrightLabels() {
      const color = getComputedStyle(query('[data-sidebar-surface] h1')!).color;
      for (const element of [
        nextNavigation,
        nextNavigation.querySelector('svg')!,
        query('[aria-label="Quick Connect"] svg')!,
        inactive,
        inactive.querySelector('svg')!,
        dialog()!.querySelector('label[for="settings-theme"]')!.nextElementSibling!,
      ]) {
        const style = getComputedStyle(element);
        assert.equal(style.color, color);
        assert.equal(style.opacity, '1');
      }
      assert.equal(getComputedStyle(settingsSearch, '::placeholder').color, color);
      assert.equal(getComputedStyle(connectionsSearch, '::placeholder').color, color);
    }

    await chooseTheme('OLED');
    assert.ok(document.documentElement.classList.contains('oled'));
    assert.deepEqual(assertSharedPalette(), {
      sidebar: 'rgb(5, 5, 5)',
      canvas: 'rgb(16, 16, 16)',
    });
    assertBrightLabels();
    await chooseTheme('Dark');
    assert.ok(!document.documentElement.classList.contains('oled'));
    assert.deepEqual(assertSharedPalette(), darkPalette);
    assertBrightLabels();
  } finally {
    await React.act(async () => root.unmount());
    window.wormhole = originalBridge;
    await React.act(async () => window.settingsReducedMotion(false));
  }
};
