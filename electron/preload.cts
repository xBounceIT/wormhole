import { contextBridge, ipcRenderer } from 'electron';
import type { RdpBackendEvent, RdpCommandRequest, RdpStartRequest } from './rdp-contract.js';

type WormholeUpdateCheckResult = {
  currentVersion: string;
  latestVersion: string;
  isUpdateAvailable: boolean;
  checkFailed: boolean;
  releaseTag?: string;
  releaseName?: string;
  releaseUrl?: string;
  releaseNotes?: string;
  installerUrl?: string;
  installerFileName?: string;
  installerSize?: number | null;
  installerSha256?: string;
};

const wormholeBridge = {
  loadStartup: () => ipcRenderer.invoke('startup:load'),
  unlockStartup: (request: { method: 'pin' | 'password'; secret: string }) =>
    ipcRenderer.invoke('startup:unlock', request),
  markStartupReady: () => ipcRenderer.send('startup:ready'),
  loadWorkspace: () => ipcRenderer.invoke('workspace:load'),
  selectMRemoteImport: () => ipcRenderer.invoke('mremote-import:select'),
  analyzeMRemoteImport: (options: { password: string; structureOnly: boolean }) =>
    ipcRenderer.invoke('mremote-import:analyze', options),
  cancelMRemoteImportAnalysis: () => ipcRenderer.send('mremote-import:cancel-analysis'),
  commitMRemoteImport: (options: { password: string; structureOnly: boolean }) =>
    ipcRenderer.invoke('mremote-import:commit', options),
  clearMRemoteImport: () => ipcRenderer.send('mremote-import:clear'),
  duplicateWorkspaceNode: (request: { nodeId: string }) =>
    ipcRenderer.invoke('workspace:duplicate-node', request),
  deleteWorkspaceNode: (request: { nodeId: string }) =>
    ipcRenderer.invoke('workspace:delete-node', request),
  showWorkspaceCredentials: (request: { nodeId: string }) =>
    ipcRenderer.invoke('workspace:show-credentials', request),
  exportBackup: (password: string) => ipcRenderer.invoke('backup:export', { password }),
  selectBackupForImport: () => ipcRenderer.invoke('backup:select-import'),
  clearBackupImportSelection: () => ipcRenderer.send('backup:clear-import'),
  importBackup: (password: string) => ipcRenderer.invoke('backup:import', { password }),
  createWorkspaceNode: (request: {
    parentId: string;
    name: string;
    kind: 'folder' | 'connection';
    protocol: '' | 'ssh' | 'rdp' | 'http' | 'https' | 'vnc' | 'serial';
    host: string;
    sshAutoSudo: boolean | null;
    httpIgnoreCertErrors: boolean | null;
    tunnelEnabled: boolean | null;
    tunnelConfigId: string;
    credentialMode: 0 | 1 | 2;
    credentialId: string;
    serialBaudRate: number;
    serialDataBits: number;
    serialStopBits: number;
    serialParity: number;
    serialFlowControl: number;
  }) => ipcRenderer.invoke('workspace:create-node', request),
  updateWorkspaceNode: (request: {
    id: string;
    parentId: string;
    name: string;
    kind: 'folder' | 'connection';
    protocol: '' | 'ssh' | 'rdp' | 'http' | 'https' | 'vnc' | 'serial';
    host: string;
    sshAutoSudo: boolean | null;
    httpIgnoreCertErrors: boolean | null;
    tunnelEnabled: boolean | null;
    tunnelConfigId: string;
    credentialMode: 0 | 1 | 2;
    credentialId: string;
    serialBaudRate: number;
    serialDataBits: number;
    serialStopBits: number;
    serialParity: number;
    serialFlowControl: number;
  }) => ipcRenderer.invoke('workspace:update-node', request),
  createCredential: (request: {
    name: string;
    protocol: 'ssh' | 'rdp' | 'vnc';
    username: string;
    domain: string;
    password: string;
    provider: 'Local' | 'Bitwarden';
    bitwardenItemId?: string;
    bitwardenItemName?: string;
    bitwardenFieldPath?: string;
  }) => ipcRenderer.invoke('workspace:create-credential', request),
  updateCredential: (request: {
    id: string;
    name: string;
    protocol: 'ssh' | 'rdp' | 'vnc';
    username: string;
    domain: string;
    password: string;
    provider: 'Local' | 'Bitwarden';
    bitwardenItemId?: string;
    bitwardenItemName?: string;
    bitwardenFieldPath?: string;
  }) => ipcRenderer.invoke('workspace:update-credential', request),
  deleteCredential: (request: { id: string }) =>
    ipcRenderer.invoke('workspace:delete-credential', request),
  updateWorkspaceNodeSshSettings: (request: { nodeId: string; sshAutoSudo: boolean | null }) =>
    ipcRenderer.invoke('workspace:update-node-ssh-settings', request),
  listCredentialsForProtocol: (protocol: 'ssh' | 'rdp' | 'vnc') =>
    ipcRenderer.invoke('workspace:credentials-for-protocol', protocol),
  updateWorkspaceNodeCredential: (request: {
    nodeId: string;
    mode: 0 | 1 | 2;
    credentialId: string;
  }) => ipcRenderer.invoke('workspace:update-node-credential', request),
  updateWorkspaceNodeWebSettings: (request: {
    nodeId: string;
    httpIgnoreCertErrors: boolean | null;
  }) => ipcRenderer.invoke('workspace:update-node-web-settings', request),
  openWebSession: (request: {
    sessionId: string;
    attempt: number;
    nodeId?: string;
    address?: string;
    protocol?: 'http' | 'https';
    ignoreCertErrors?: boolean;
    tunnelConfigId?: string;
  }) => ipcRenderer.invoke('web:open', request),
  setWebSessionBounds: (request: {
    sessionId: string;
    x: number;
    y: number;
    width: number;
    height: number;
    visible: boolean;
  }) => ipcRenderer.invoke('web:set-bounds', request),
  commandWebSession: (request: {
    sessionId: string;
    operation: 'back' | 'forward' | 'reload' | 'stop';
  }) => ipcRenderer.invoke('web:command', request),
  showSessionTabContextMenu: (request: { canTransfer: boolean }) =>
    ipcRenderer.invoke('session-tab:context-menu', request),
  showTreeTooltip: (request: {
    text: string;
    anchor: { x: number; y: number; width: number; height: number };
    width: number;
  }) => ipcRenderer.invoke('tree-tooltip:show', request),
  hideTreeTooltip: () => ipcRenderer.invoke('tree-tooltip:hide'),
  closeWebSession: (sessionId: string) => ipcRenderer.invoke('web:close', sessionId),
  onWebEvent: (
    listener: (event: {
      type: 'connected' | 'failed' | 'navigation';
      sessionId: string;
      attempt: number;
      url: string;
      canGoBack: boolean;
      canGoForward: boolean;
      isLoading: boolean;
      error?: string;
    }) => void,
  ) => {
    const handler = (_event: Electron.IpcRendererEvent, value: unknown) => {
      listener(value as Parameters<typeof listener>[0]);
    };
    ipcRenderer.on('web:event', handler);
    return () => ipcRenderer.removeListener('web:event', handler);
  },
  updateWorkspaceNodeTunnelSettings: (
    request:
      | {
          nodeId: string;
          tunnelEnabled: null;
          tunnelConfigId: '';
        }
      | {
          nodeId: string;
          tunnelEnabled: false;
          tunnelConfigId: '';
        }
      | {
          nodeId: string;
          tunnelEnabled: true;
          tunnelConfigId: string;
        },
  ) => ipcRenderer.invoke('workspace:update-node-tunnel', request),
  createTunnel: (request: { name: string; kind: number; settings: Record<string, unknown> }) =>
    ipcRenderer.invoke('tunnel:create', request),
  readTunnel: (id: string) => ipcRenderer.invoke('tunnel:read', { id }),
  updateTunnel: (request: {
    id: string;
    name: string;
    kind: number;
    settings: Record<string, unknown>;
  }) => ipcRenderer.invoke('tunnel:update', request),
  deleteTunnel: (id: string) => ipcRenderer.invoke('tunnel:delete', { id }),
  testTunnel: (id: string) => ipcRenderer.invoke('tunnel:test', { id }),
  importWatchguardProfile: () => ipcRenderer.invoke('tunnel:import-watchguard'),
  importAzureVpnProfile: () => ipcRenderer.invoke('tunnel:import-azure-vpn'),
  importOvpnProfile: () => ipcRenderer.invoke('tunnel:import-ovpn'),
  importCiscoProfile: () => ipcRenderer.invoke('tunnel:import-cisco'),
  respondTunnelPrompt: (request: {
    leaseId: string;
    promptId: string;
    value: string;
    cancelled: boolean;
  }) => ipcRenderer.invoke('tunnel:prompt-response', request),
  respondTunnelRoute: (request: {
    leaseId: string;
    promptId: string;
    choice: 'tunnel' | 'direct' | 'cancel';
  }) => ipcRenderer.invoke('tunnel:route-response', request),
  readAppSettings: () =>
    ipcRenderer.invoke('settings:read') as Promise<{
      promptBeforeTunnelConnect: boolean;
      autoCopyOnSelect: boolean;
      confirmOnTabClose: boolean;
      sidebarWidth: number;
      autoCheckForUpdates: boolean;
      lastUpdateCheck: string | null;
      skippedUpdateVersion: string | null;
    }>,
  setPromptBeforeTunnelConnect: (enabled: boolean) =>
    ipcRenderer.invoke('settings:set-prompt-before-tunnel', enabled),
  setAutoCopyOnSelect: (enabled: boolean) =>
    ipcRenderer.invoke('settings:set-auto-copy-on-select', enabled),
  setConfirmOnTabClose: (enabled: boolean) =>
    ipcRenderer.invoke('settings:set-confirm-on-tab-close', enabled),
  setSidebarWidth: (width: number) => ipcRenderer.invoke('settings:set-sidebar-width', width),
  reportActiveSessionCount: (count: number) =>
    ipcRenderer.send('lifecycle:active-session-count', count),
  onWindowCloseRequested: (listener: () => Promise<void>) => {
    const handler = (_event: Electron.IpcRendererEvent, requestId: unknown) => {
      if (typeof requestId !== 'string') return;
      void Promise.resolve(listener()).finally(() => {
        ipcRenderer.send('lifecycle:teardown-complete', requestId);
      });
    };
    ipcRenderer.on('lifecycle:prepare-close', handler);
    return () => ipcRenderer.removeListener('lifecycle:prepare-close', handler);
  },
  setUpdatePreferences: (preferences: {
    autoCheckForUpdates?: boolean;
    skippedUpdateVersion?: string | null;
  }) => ipcRenderer.invoke('settings:set-update-preferences', preferences),
  updateStatus: () =>
    ipcRenderer.invoke('update:status') as Promise<{
      currentVersion: string;
      result: WormholeUpdateCheckResult | null;
    }>,
  checkForUpdates: () => ipcRenderer.invoke('update:check') as Promise<WormholeUpdateCheckResult>,
  downloadUpdate: (request: {
    installerUrl: string;
    installerFileName: string;
    installerSha256?: string;
    installerSize?: number | null;
  }) => ipcRenderer.invoke('update:download', request) as Promise<string>,
  installUpdate: (installerPath: string) =>
    ipcRenderer.invoke('update:install', { path: installerPath }) as Promise<{
      launched: boolean;
    }>,
  openExternal: (url: string) => ipcRenderer.invoke('update:open-release', url) as Promise<void>,
  onUpdateResult: (listener: (result: WormholeUpdateCheckResult) => void) => {
    const handler = (_event: Electron.IpcRendererEvent, value: unknown) => {
      listener(value as WormholeUpdateCheckResult);
    };
    ipcRenderer.on('update:result', handler);
    return () => ipcRenderer.removeListener('update:result', handler);
  },
  onUpdateProgress: (listener: (progress: { downloaded: number; total: number }) => void) => {
    const handler = (_event: Electron.IpcRendererEvent, value: unknown) => {
      listener(value as { downloaded: number; total: number });
    };
    ipcRenderer.on('update:progress', handler);
    return () => ipcRenderer.removeListener('update:progress', handler);
  },
  readLogsInfo: () => ipcRenderer.invoke('settings:logs-info'),
  setLogRetentionDays: (days: number) => ipcRenderer.invoke('settings:set-log-retention', days),
  setLogLevel: (level: string) => ipcRenderer.invoke('settings:set-log-level', level),
  openCurrentLogFile: () => ipcRenderer.invoke('logs:open-current-file'),
  openLogsFolder: () => ipcRenderer.invoke('logs:open-folder'),
  readBitwardenExtension: () => ipcRenderer.invoke('extensions:read'),
  setBitwardenExtensionEnabled: (enabled: boolean) =>
    ipcRenderer.invoke('extensions:set-enabled', enabled),
  installBitwardenExtension: () => ipcRenderer.invoke('extensions:install'),
  ensureBitwardenExtension: () => ipcRenderer.invoke('extensions:ensure-installed'),
  importBitwardenExtensionZip: () => ipcRenderer.invoke('extensions:import-zip'),
  importBitwardenExtensionFolder: () => ipcRenderer.invoke('extensions:import-folder'),
  readBitwardenCli: () => ipcRenderer.invoke('bitwarden:read'),
  setBitwardenCliEnabled: (enabled: boolean) =>
    ipcRenderer.invoke('bitwarden:set-enabled', enabled),
  setBitwardenCliConfig: (config: { path: string; serverRegion: number }) =>
    ipcRenderer.invoke('bitwarden:set-config', config),
  installBitwardenCli: () => ipcRenderer.invoke('bitwarden:install'),
  refreshBitwardenCliStatus: () => ipcRenderer.invoke('bitwarden:status'),
  loginBitwardenCli: (request: {
    email: string;
    masterPassword: string;
    authenticatorCode?: string;
    serverRegion: number;
  }) => ipcRenderer.invoke('bitwarden:login', request),
  unlockBitwardenCli: (masterPassword: string) =>
    ipcRenderer.invoke('bitwarden:unlock', { masterPassword }),
  logoutBitwardenCli: () => ipcRenderer.invoke('bitwarden:logout'),
  syncBitwardenCli: () => ipcRenderer.invoke('bitwarden:sync'),
  searchBitwardenItems: (query: string) => ipcRenderer.invoke('bitwarden:search-items', query),
  nodeUsesBitwarden: (request: { nodeId: string; protocol: 'ssh' | 'rdp' | 'vnc' }) =>
    ipcRenderer.invoke('bitwarden:node-uses-vault', request),
  openBitwardenPopup: (request: {
    sessionId: string;
    anchor: { x: number; y: number; width: number; height: number };
  }) => ipcRenderer.invoke('web:bitwarden-popup-open', request),
  closeBitwardenPopup: (sessionId: string) =>
    ipcRenderer.invoke('web:bitwarden-popup-close', sessionId),
  onBitwardenPopupState: (listener: (state: { sessionId: string; open: boolean }) => void) => {
    const handler = (
      _event: Electron.IpcRendererEvent,
      value: { sessionId: string; open: boolean },
    ) => listener(value);
    ipcRenderer.on('web:bitwarden-popup-state', handler);
    return () => ipcRenderer.removeListener('web:bitwarden-popup-state', handler);
  },
  openSshSession: (request: {
    sessionId: string;
    nodeId?: string;
    host?: string;
    port?: number;
    tunnelConfigId?: string;
    columns: number;
    rows: number;
    manualCredentials?: boolean;
    username?: string;
    password?: string;
  }) => ipcRenderer.invoke('ssh:open', request),
  trustSshHostKey: (request: { nodeId: string; expected: string; received: string }) =>
    ipcRenderer.invoke('ssh:trust-host-key', request),
  sendSshInput: (sessionId: string, data: string) =>
    ipcRenderer.invoke('ssh:input', sessionId, data),
  pasteClipboardToSsh: (sessionId: string) => ipcRenderer.invoke('ssh:paste-clipboard', sessionId),
  resizeSshSession: (sessionId: string, columns: number, rows: number) =>
    ipcRenderer.invoke('ssh:resize', sessionId, columns, rows),
  openSftpBrowser: (sessionId: string, requestId?: string) =>
    ipcRenderer.invoke('ssh:sftp-open', sessionId, requestId),
  listSftpDirectory: (sessionId: string, path: string, requestId?: string) =>
    ipcRenderer.invoke('ssh:sftp-list', sessionId, path, requestId),
  listLocalSftpDirectory: (sessionId: string, path: string, requestId: string) =>
    ipcRenderer.invoke('ssh:sftp-local-list', sessionId, path, requestId),
  operateSftp: (
    sessionId: string,
    request: {
      requestId: string;
      pane: 'local' | 'remote';
      operation: 'mkdir' | 'file' | 'delete' | 'rename' | 'open';
      path: string;
      destinationPath?: string;
    },
  ) => ipcRenderer.invoke('ssh:sftp-operation', sessionId, request),
  startSftpTransfer: (
    sessionId: string,
    request: {
      transferId: string;
      direction: 'local-to-remote' | 'remote-to-local' | 'local-to-local';
      destinationPath: string;
      items: Array<{
        sourcePath: string;
        name: string;
        isDirectory: boolean;
        size: number;
      }>;
    },
  ) => ipcRenderer.invoke('ssh:sftp-transfer', sessionId, request),
  decideSftpConflict: (
    sessionId: string,
    transferId: string,
    itemId: string,
    decision: 'overwrite' | 'skip',
    applyToAll: boolean,
  ) =>
    ipcRenderer.invoke(
      'ssh:sftp-transfer-decision',
      sessionId,
      transferId,
      itemId,
      decision,
      applyToAll,
    ),
  cancelSftpTransfer: (sessionId: string, transferId: string, itemId?: string) =>
    ipcRenderer.invoke('ssh:sftp-transfer-cancel', sessionId, transferId, itemId),
  closeSftpBrowser: (sessionId: string) => ipcRenderer.invoke('ssh:sftp-close', sessionId),
  closeSshSession: (sessionId: string) => ipcRenderer.invoke('ssh:close', sessionId),
  openSerialSession: (request: {
    sessionId: string;
    nodeId?: string;
    portName?: string;
    settings?: {
      baudRate: number;
      dataBits: number;
      stopBits: number;
      parity: number;
      flowControl: number;
    };
    columns: number;
    rows: number;
  }) => ipcRenderer.invoke('serial:open', request),
  sendSerialInput: (sessionId: string, data: string) =>
    ipcRenderer.invoke('serial:input', sessionId, data),
  resizeSerialSession: (sessionId: string, columns: number, rows: number) =>
    ipcRenderer.invoke('serial:resize', sessionId, columns, rows),
  closeSerialSession: (sessionId: string) => ipcRenderer.invoke('serial:close', sessionId),
  onSerialEvent: (
    listener: (event: {
      type: 'connected' | 'screen' | 'closed' | 'error';
      sessionId: string;
      portName?: string;
      baudRate?: number;
      dataBits?: number;
      stopBits?: number;
      parity?: number;
      flowControl?: number;
      frame?: {
        columns: number;
        rows: number;
        full: boolean;
        cells?: Array<{
          character: string;
          foreground: number;
          background: number;
        }>;
        changes?: Array<{
          index: number;
          character: string;
          foreground: number;
          background: number;
        }>;
        scrollbackReset?: boolean;
        viewportReset?: boolean;
        scrollback?: Array<{
          runs: Array<{
            text: string;
            cells: number;
            foreground: number;
            background: number;
          }>;
        }>;
        cursorX: number;
        cursorY: number;
        cursorVisible: boolean;
        applicationCursor: boolean;
        title?: string;
        sequence: number;
      };
      error?: string;
    }) => void,
  ) => {
    const handler = (_event: Electron.IpcRendererEvent, value: unknown) => {
      listener(value as Parameters<typeof listener>[0]);
    };
    ipcRenderer.on('serial:event', handler);
    return () => ipcRenderer.removeListener('serial:event', handler);
  },
  onSshEvent: (
    listener: (event: {
      type:
        | 'connected'
        | 'screen'
        | 'closed'
        | 'error'
        | 'sftp.opening'
        | 'sftp.ready'
        | 'sftp.error'
        | 'sftp.local.ready'
        | 'sftp.local.error'
        | 'sftp.operation'
        | 'sftp.conflict'
        | 'sftp.transfer'
        | 'sftp.closed';
      sessionId: string;
      host?: string;
      port?: number;
      username?: string;
      fingerprint?: string;
      hostKeyExpected?: string;
      hostKeyReceived?: string;
      frame?: {
        columns: number;
        rows: number;
        full: boolean;
        cells?: Array<{
          character: string;
          foreground: number;
          background: number;
        }>;
        changes?: Array<{
          index: number;
          character: string;
          foreground: number;
          background: number;
        }>;
        scrollbackReset?: boolean;
        viewportReset?: boolean;
        scrollback?: Array<{
          runs: Array<{
            text: string;
            cells: number;
            foreground: number;
            background: number;
          }>;
        }>;
        cursorX: number;
        cursorY: number;
        cursorVisible: boolean;
        applicationCursor: boolean;
        title?: string;
        sequence: number;
      };
      path?: string;
      entries?: Array<{
        name: string;
        fullPath: string;
        isDirectory: boolean;
        isSymbolicLink: boolean;
        size: number;
        lastModifiedUtc?: string;
      }>;
      quickPaths?: Array<{
        displayName: string;
        path: string;
        isSeparator: boolean;
      }>;
      truncated?: boolean;
      error?: string;
      requestId?: string;
      pane?: 'local' | 'remote';
      operation?: 'mkdir' | 'file' | 'delete' | 'rename' | 'open';
      transferId?: string;
      itemId?: string;
      transferState?:
        | 'running'
        | 'progress'
        | 'completed'
        | 'failed'
        | 'cancelled'
        | 'batch-failed'
        | 'batch-completed'
        | 'batch-cancelled';
      direction?: 'local-to-remote' | 'remote-to-local' | 'local-to-local';
      displayName?: string;
      expectedBytes?: number;
      bytesTransferred?: number;
      incomingSize?: number;
      existingSize?: number;
      existingIsDirectory?: boolean;
    }) => void,
  ) => {
    const handler = (_event: Electron.IpcRendererEvent, value: unknown) => {
      listener(value as Parameters<typeof listener>[0]);
    };
    ipcRenderer.on('ssh:event', handler);
    return () => ipcRenderer.removeListener('ssh:event', handler);
  },
  getAuthState: () => ipcRenderer.invoke('auth:status'),
  verifyAuth: (request: unknown) => ipcRenderer.invoke('auth:verify', request),
  setAuthSecret: (request: unknown) => ipcRenderer.invoke('auth:set-secret', request),
  updateAuthSettings: (request: unknown) => ipcRenderer.invoke('auth:update-settings', request),
  lockAuthentication: () => ipcRenderer.invoke('auth:lock'),
  checkWindowsHello: () => ipcRenderer.invoke('auth:hello-status'),
  verifyWindowsHello: () => ipcRenderer.invoke('auth:hello-verify'),
  getSystemIdleSeconds: () => ipcRenderer.invoke('auth:system-idle'),
  mcpStatus: () => ipcRenderer.invoke('mcp:status'),
  startMcp: (port: number) => ipcRenderer.invoke('mcp:start', port),
  stopMcp: () => ipcRenderer.invoke('mcp:stop'),
  setMcpPort: (port: number) => ipcRenderer.invoke('mcp:set-port', port),
  getMcpToken: () => ipcRenderer.invoke('mcp:get-token'),
  regenerateMcpToken: () => ipcRenderer.invoke('mcp:regenerate-token'),
  respondMcpApproval: (requestId: string, approved: boolean) =>
    ipcRenderer.invoke('mcp:approval', { requestId, approved }),
  onMcpApproval: (
    listener: (event: {
      type: 'mcp.approval';
      requestId: string;
      sessionId: string;
      host: string;
      port: number;
      username: string;
      title: string;
      tool: string;
    }) => void,
  ) => {
    const handler = (_event: Electron.IpcRendererEvent, value: unknown) => {
      listener(value as Parameters<typeof listener>[0]);
    };
    ipcRenderer.on('mcp:approval', handler);
    return () => ipcRenderer.removeListener('mcp:approval', handler);
  },
  sendVncCommand: (command: unknown) => ipcRenderer.invoke('vnc:command', command),
  onBackendEvent: (listener: (event: unknown) => void) => {
    const handler = (_event: Electron.IpcRendererEvent, payload: unknown) => listener(payload);
    ipcRenderer.on('backend:event', handler);
    return () => ipcRenderer.removeListener('backend:event', handler);
  },
  startRdpSession: (request: RdpStartRequest) => ipcRenderer.invoke('rdp:start', request),
  resizeRdpSession: (request: RdpCommandRequest) => ipcRenderer.invoke('rdp:resize', request),
  commandRdpSession: (
    request: RdpCommandRequest & { operation: 'show' | 'hide' | 'focus' | 'disconnect' },
  ) => ipcRenderer.invoke('rdp:command', request),
  onRdpEvent: (listener: (event: RdpBackendEvent) => void) => {
    const handler = (_event: Electron.IpcRendererEvent, value: RdpBackendEvent) => listener(value);
    ipcRenderer.on('rdp:event', handler);
    return () => ipcRenderer.removeListener('rdp:event', handler);
  },
};

// Child frames can display remote appliance content in future protocol surfaces, but they must
// never inherit the privileged workspace/secret bridge from the top-level Wormhole renderer.
if (process.isMainFrame) contextBridge.exposeInMainWorld('wormhole', wormholeBridge);
