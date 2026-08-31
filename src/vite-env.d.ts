/// <reference types="vite/client" />

type WormholeProtocol = 'ssh' | 'rdp' | 'http' | 'https' | 'vnc' | 'serial';

interface WormholeRdpSurfaceRect {
  x: number;
  y: number;
  width: number;
  height: number;
}

interface WormholeRdpProfile {
  nodeId?: string;
  credentialId?: string;
  credentialIdOverride?: string;
  gatewayCredentialId?: string;
  tunnelConfigId?: string;
  name?: string;
  host: string;
  port?: number;
  username?: string;
  domain?: string;
  password?: string;
  gatewayHostname?: string;
  gatewayUsername?: string;
  gatewayPassword?: string;
  screenSize?: string;
  fullScreen?: boolean;
  colorDepth?: number;
  useAllMonitors?: boolean;
  audioMode?: number;
  audioCaptureMode?: number;
  keyboardHookMode?: number;
  redirectClipboard?: boolean;
  redirectPrinters?: boolean;
  redirectSmartCards?: boolean;
  redirectPorts?: boolean;
  redirectDevices?: boolean;
  redirectDrives?: string;
  connectionSpeed?: number;
  desktopBackground?: boolean;
  fontSmoothing?: boolean;
  desktopComposition?: boolean;
  windowDrag?: boolean;
  menuAnimation?: boolean;
  visualStyles?: boolean;
  bitmapCaching?: boolean;
  autoReconnect?: boolean;
  serverAuthentication?: number;
  gatewayUsageMethod?: number;
  gatewayBypassLocal?: boolean;
  gatewayUseSameCreds?: boolean;
  useExternalClient?: boolean;
  socksEndpoint?: string;
  tunnelEnabled?: boolean;
}

interface WormholeWorkspaceRdpSettings {
  domain: string;
  screenSize: string;
  fullScreen: boolean;
  colorDepth: number;
  useAllMonitors: boolean;
  audioMode: number;
  audioCaptureMode: number;
  keyboardHookMode: number;
  redirectClipboard: boolean;
  redirectPrinters: boolean;
  redirectSmartCards: boolean;
  redirectPorts: boolean;
  redirectDevices: boolean;
  redirectDrives: string;
  connectionSpeed: number;
  desktopBackground: boolean;
  fontSmoothing: boolean;
  desktopComposition: boolean;
  windowDrag: boolean;
  menuAnimation: boolean;
  visualStyles: boolean;
  bitmapCaching: boolean;
  autoReconnect: boolean;
  serverAuthentication: number;
  gatewayUsageMethod: number;
  gatewayHostname: string;
  gatewayCredentialId: string;
  gatewayBypassLocal: boolean;
  gatewayUseSameCreds: boolean;
  useExternalClient: boolean;
}

interface WormholeRdpBackendEvent {
  type:
    | 'started'
    | 'ready'
    | 'connected'
    | 'loginComplete'
    | 'disconnected'
    | 'fatalError'
    | 'logonError'
    | 'autoReconnecting'
    | 'autoReconnected'
    | 'exited'
    | 'ack'
    | 'error';
  requestId?: string;
  sessionId?: string;
  backend?: 'activex' | 'freerdp';
  external?: boolean;
  lifecycleGeneration?: number;
  code?: number;
  attempt?: number;
  max?: number;
  message?: string;
  credentialFailure?: boolean;
}

interface WormholeWorkspaceNode {
  id: string;
  name: string;
  kind: 'folder' | 'connection';
  protocol?: WormholeProtocol;
  host?: string;
  port?: number;
  username?: string;
  hasInlineCredential?: boolean;
  rdp?: WormholeWorkspaceRdpSettings;
  httpIgnoreCertErrors?: boolean;
  serialBaudRate?: number;
  serialDataBits?: number;
  serialStopBits?: number;
  serialParity?: number;
  serialFlowControl?: number;
  sshAutoSudo?: boolean;
  tunnelEnabled?: boolean;
  tunnelConfigId?: string;
  credentialMode?: number;
  credentialId?: string;
  persisted?: boolean;
  children?: WormholeWorkspaceNode[];
}

interface WormholeWorkspaceCredential {
  id: string;
  name: string;
  protocol: WormholeProtocol;
  kind: 'password' | 'sshKey' | 'unsupported';
  username: string;
  domain?: string;
  provider: 'Local' | 'Bitwarden';
  canEdit: boolean;
  canDelete: boolean;
  bitwardenItemId?: string;
  bitwardenItemName?: string;
  privateKeyFileName?: string;
  isVirtualBitwarden?: boolean;
}

interface WormholeWorkspaceTunnel {
  id: string;
  name: string;
  kind: string;
  endpoint?: string;
}

interface WormholeTunnelDetails {
  id: string;
  name: string;
  kind: number;
  endpoint?: string;
  settings: Record<string, unknown>;
}

interface WormholeWorkspaceSnapshot {
  tree: WormholeWorkspaceNode[];
  credentials: WormholeWorkspaceCredential[];
  credentialOptions: Record<'ssh' | 'rdp' | 'vnc', WormholeWorkspaceCredential[]>;
  tunnels: WormholeWorkspaceTunnel[];
}

interface WormholeWorkspaceCredentialReveal {
  found: boolean;
  connectionName: string;
  credentialName?: string;
  username?: string;
  domain?: string;
  secretLabel?: string;
  secret?: string;
}

interface WormholeWebTarget {
  url: string;
  protocol: 'http' | 'https';
  host: string;
  port: number;
  ignoreCertErrors: boolean;
  bitwarden?: {
    partition: string;
    popupUrl: string;
  };
}

interface WormholeBitwardenExtensionState {
  enabled: boolean;
  source: 'OfficialGitHub' | 'ManualZip' | 'ManualFolder';
  releasesUrl: string;
  version: string | null;
  path: string | null;
  sha256: string | null;
  assetName: string | null;
  downloadUrl: string | null;
  lastUpdateCheckUtc: string | null;
  lastUpdateStatus: string | null;
  lastUpdateError: string | null;
  availableVersion: string | null;
  installed: {
    name: string;
    version: string;
    path: string;
    defaultPopup?: string;
  } | null;
}

interface WormholeBitwardenCliState {
  enabled: boolean;
  path: string;
  serverRegion: 'UnitedStates' | 'Europe' | 'Current';
  releasesUrl: string;
  version: string | null;
  sha256: string | null;
  assetName: string | null;
  downloadUrl: string | null;
  installStatus: string | null;
  installError: string | null;
  lastSyncUtc: string | null;
  lastSyncStatus: string | null;
  lastSyncError: string | null;
  availableCount: number | null;
  installed: {
    version: string;
    path: string;
    sha256?: string;
    assetName?: string;
    downloadUrl?: string;
  } | null;
}

interface WormholeBitwardenCliStatus {
  status: 'Unauthenticated' | 'Locked' | 'Unlocked' | 'Unknown';
  userEmail: string | null;
  serverUrl: string | null;
  lastSync?: string;
  hasSessionKey?: boolean;
}

interface WormholeBitwardenLoginItem {
  id: string;
  name: string;
  username?: string;
  revisionDate?: string;
}

interface WormholeWebEvent {
  type: 'connected' | 'failed' | 'navigation';
  sessionId: string;
  attempt: number;
  url: string;
  canGoBack: boolean;
  canGoForward: boolean;
  isLoading: boolean;
  error?: string;
}

interface WormholeSshConnected {
  sessionId: string;
  host: string;
  port: number;
  username: string;
  fingerprint: string;
}

interface WormholeSshTerminalCell {
  character: string;
  foreground: number;
  background: number;
}

interface WormholeSshTerminalCellChange extends WormholeSshTerminalCell {
  index: number;
}

interface WormholeSshTerminalScrollbackRun {
  text: string;
  cells: number;
  foreground: number;
  background: number;
}

interface WormholeSshTerminalScrollbackLine {
  runs: WormholeSshTerminalScrollbackRun[];
}

interface WormholeSshTerminalFrame {
  columns: number;
  rows: number;
  full: boolean;
  cells?: WormholeSshTerminalCell[];
  changes: WormholeSshTerminalCellChange[];
  scrollbackReset: boolean;
  viewportReset: boolean;
  scrollback?: WormholeSshTerminalScrollbackLine[];
  cursorX: number;
  cursorY: number;
  cursorVisible: boolean;
  applicationCursor: boolean;
  title?: string;
  sequence: number;
}

interface WormholeSftpEntry {
  name: string;
  fullPath: string;
  isDirectory: boolean;
  isSymbolicLink: boolean;
  size: number;
  lastModifiedUtc?: string;
}

interface WormholeSftpQuickPath {
  displayName: string;
  path: string;
  isSeparator: boolean;
}

type WormholeSshEvent =
  | ({ type: 'connected' } & WormholeSshConnected)
  | { type: 'screen'; sessionId: string; frame: WormholeSshTerminalFrame }
  | { type: 'closed'; sessionId: string }
  | {
      type: 'reconnecting';
      sessionId: string;
      error: string;
      attempt: number;
      maxAttempts: number;
      delaySeconds: number;
    }
  | {
      type: 'reconnect-failed';
      sessionId: string;
      error: string;
      attempt: number;
      maxAttempts: number;
    }
  | {
      type: 'error';
      sessionId: string;
      error: string;
      hostKeyExpected?: string;
      hostKeyReceived?: string;
    }
  | {
      type: 'tunnel.progress';
      sessionId: string;
      phase: string;
      detail?: string;
    }
  | {
      type: 'sftp.opening' | 'sftp.closed';
      sessionId: string;
      requestId?: string;
    }
  | {
      type: 'sftp.ready';
      sessionId: string;
      path: string;
      entries: WormholeSftpEntry[];
      truncated: boolean;
      requestId?: string;
    }
  | {
      type: 'sftp.error';
      sessionId: string;
      error: string;
      path?: string;
      requestId?: string;
    }
  | {
      type: 'sftp.local.ready';
      sessionId: string;
      requestId: string;
      pane: 'local';
      path: string;
      entries: WormholeSftpEntry[];
      truncated: boolean;
      quickPaths?: WormholeSftpQuickPath[];
    }
  | {
      type: 'sftp.local.error';
      sessionId: string;
      requestId: string;
      pane: 'local';
      path?: string;
      error: string;
    }
  | {
      type: 'sftp.operation';
      sessionId: string;
      requestId: string;
      pane: 'local' | 'remote';
      operation: 'mkdir' | 'file' | 'delete' | 'rename' | 'open';
      path: string;
      error?: string;
    }
  | {
      type: 'sftp.conflict';
      sessionId: string;
      transferId: string;
      itemId: string;
      direction: 'local-to-remote' | 'remote-to-local' | 'local-to-local';
      displayName: string;
      path: string;
      incomingSize: number;
      existingSize: number;
      existingIsDirectory: boolean;
    }
  | {
      type: 'sftp.transfer';
      sessionId: string;
      transferId: string;
      itemId?: string;
      transferState:
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
      error?: string;
    };

type WormholeSerialEvent =
  | {
      type: 'connected';
      sessionId: string;
      portName: string;
      baudRate: number;
      dataBits: number;
      stopBits: number;
      parity: number;
      flowControl: number;
    }
  | { type: 'screen'; sessionId: string; frame: WormholeSshTerminalFrame }
  | { type: 'closed'; sessionId: string }
  | { type: 'error'; sessionId: string; error: string };
type WormholeAuthMode = 'disabled' | 'pin' | 'password' | 'windowsHello';
type WormholeAuthFallback = 'pin' | 'password';

interface WormholeHelloStatus {
  available: boolean;
  message: string;
}

interface WormholeAuthState {
  mode: WormholeAuthMode;
  fallback: WormholeAuthFallback;
  idleTimeoutMinutes: number | null;
  hasPin: boolean;
  hasPassword: boolean;
  isCorrupted: boolean;
  configured: boolean;
  windowsHello: WormholeHelloStatus;
}

interface WormholeAuthVerification {
  succeeded: boolean;
  message: string;
}

interface WormholeAuthVerificationRequest {
  method: WormholeAuthFallback;
  secret: string;
}

interface WormholeAuthSecretRequest {
  method: WormholeAuthFallback;
  secret: string;
}

interface WormholeAuthSettingsRequest {
  mode: WormholeAuthMode;
  fallback: WormholeAuthFallback;
  idleTimeoutMinutes: number | null;
}

type WormholeVncCommand =
  | {
      action: 'vnc.connect';
      sessionId: string;
      nodeId?: string;
      credentialId?: string;
      host?: string;
      port?: number;
      password?: string;
      tunnelConfigId?: string;
      passwordProvided?: boolean;
    }
  | { action: 'vnc.disconnect'; sessionId: string }
  | {
      action: 'vnc.pointer';
      sessionId: string;
      x: number;
      y: number;
      buttons: number;
    }
  | { action: 'vnc.key'; sessionId: string; down: boolean; keysym: number };

interface WormholeBackendResponse {
  id: string;
  ok: boolean;
  error?: string;
}

interface WormholeBackendEvent {
  type:
    | 'vnc.status'
    | 'vnc.frame'
    | 'tunnel.prompt'
    | 'tunnel.prompt-closed'
    | 'tunnel.progress'
    | 'tunnel.route'
    | 'tunnel.route-closed';
  sessionId: string;
  leaseId?: string;
  phase?: string;
  detail?: string;
  connectionName?: string;
  tunnelName?: string;
  status?: 'connecting' | 'connected' | 'failed' | 'disconnected';
  message?: string;
  passwordRequired?: boolean;
  width?: number;
  height?: number;
  image?: string;
  promptId?: string;
  title?: string;
  secret?: boolean;
  confirmation?: boolean;
  acceptLabel?: string;
}

interface WormholeTunnelPrompt {
  type: 'tunnel.prompt';
  sessionId: string;
  promptId: string;
  title: string;
  message: string;
  secret: boolean;
  confirmation: boolean;
  acceptLabel?: string;
}

interface WormholeMcpStatus {
  enabled: boolean;
  running: boolean;
  port: number;
  endpoint: string;
}

interface WormholeMcpApproval {
  type: 'mcp.approval';
  requestId: string;
  sessionId: string;
  host: string;
  port: number;
  username: string;
  title: string;
  tool: string;
}

interface WormholeUpdateCheckResult {
  currentVersion: string;
  latestVersion: string;
  isNewerRelease: boolean;
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
}

interface WormholeAppSettings {
  theme: 'system' | 'light' | 'dark';
  promptBeforeTunnelConnect: boolean;
  autoCopyOnSelect: boolean;
  confirmOnTabClose: boolean;
  sidebarWidth: number;
  connectionTreeExpansion: { defaultExpanded: boolean; folderIds: string[] } | null;
  autoCheckForUpdates: boolean;
  lastUpdateCheck: string | null;
  skippedUpdateVersion: string | null;
}

interface WormholeBackupExportResult {
  fileName: string;
  nodeCount: number;
  credentialCount: number;
  tunnelCount: number;
  passwordCount: number;
  privateKeyCount: number;
  tunnelPayloadCount: number;
  encrypted: boolean;
}

interface WormholeBackupImportSelection {
  fileName: string;
  encrypted: boolean;
  schemaVersion: number;
  exportedAt: string;
}

interface WormholeBackupImportResult {
  nodesImported: number;
  nodesSkipped: number;
  credentialsImported: number;
  credentialsSkipped: number;
  tunnelsImported: number;
  tunnelsSkipped: number;
  passwordsImported: number;
  privateKeysImported: number;
  tunnelPayloadsImported: number;
  warnings: string[];
}

interface WormholeMRemoteImportInspection {
  fileName: string;
  fileSize: number;
  confVersion: string;
  passwordRequired: boolean;
  fullFileEncrypted: boolean;
}

interface WormholeMRemoteImportPlan {
  planToken: string;
  folders: number;
  connections: number;
  credentials: number;
  skippedUnsupported: number;
  skippedUnsupportedSamples: string[];
  warnings: string[];
  droppedWarnings: number;
  preview: Array<{
    name: string;
    kind: 'folder' | 'connection';
    protocol?: 'ssh' | 'rdp' | 'vnc';
    depth: number;
  }>;
  previewTruncated: boolean;
}

interface WormholeMRemoteImportResult {
  foldersCreated: number;
  connectionsCreated: number;
  credentialsCreated: number;
  skippedUnsupported: number;
  warnings: string[];
  droppedWarnings: number;
}

interface WormholeStartupSnapshot {
  auth: WormholeAuthState;
  workspace?: WormholeWorkspaceSnapshot;
  settings: WormholeAppSettings;
  themeMigration: {
    handled: boolean;
    migrated: boolean;
  };
  migration: {
    status: 'completed' | 'already-completed' | 'skipped-non-windows';
    migrated: number;
    missing: number;
  };
  migrationFailed: boolean;
}

interface WormholeStartupUnlock {
  succeeded: boolean;
  message: string;
  workspace?: WormholeWorkspaceSnapshot;
}

interface WormholeLogsInfo {
  currentLogFilePath: string;
  logsDirectoryPath: string;
  logRetentionDays: number;
  logLevel: string;
}

interface WormholeOperationProgress {
  kind: 'backup-export' | 'backup-import' | 'mremote-import';
  phase: string;
  detail: string;
  percent: number;
}

interface WormholeTunnelTestProgress {
  attempt: number;
  phase: string;
  detail: string;
}

interface Window {
  wormhole?: {
    platform: string;
    loadStartup(legacyTheme?: 'system' | 'light' | 'dark'): Promise<WormholeStartupSnapshot>;
    unlockStartup(request: WormholeAuthVerificationRequest): Promise<WormholeStartupUnlock>;
    markStartupReady(): void;
    loadWorkspace(): Promise<WormholeWorkspaceSnapshot>;
    selectMRemoteImport(): Promise<WormholeMRemoteImportInspection | null>;
    analyzeMRemoteImport(options: {
      password: string;
      structureOnly: boolean;
    }): Promise<WormholeMRemoteImportPlan>;
    cancelMRemoteImportAnalysis(): void;
    commitMRemoteImport(options: {
      password: string;
      structureOnly: boolean;
    }): Promise<WormholeMRemoteImportResult>;
    cancelMRemoteImportCommit(): Promise<boolean>;
    clearMRemoteImport(): void;
    duplicateWorkspaceNode(request: { nodeId: string }): Promise<{ nodeId: string; name: string }>;
    deleteWorkspaceNode(request: { nodeId: string }): Promise<{ deleted: boolean }>;
    deleteWorkspaceNodes(request: { nodeIds: string[] }): Promise<{ deleted: boolean }>;
    showWorkspaceCredentials(request: {
      nodeId: string;
    }): Promise<WormholeWorkspaceCredentialReveal>;
    exportBackup(password: string): Promise<WormholeBackupExportResult | null>;
    cancelBackupExport(): Promise<boolean>;
    selectBackupForImport(): Promise<WormholeBackupImportSelection | null>;
    clearBackupImportSelection(): void;
    importBackup(password: string): Promise<WormholeBackupImportResult>;
    cancelBackupImport(): Promise<boolean>;
    onOperationProgress(listener: (event: WormholeOperationProgress) => void): () => void;
    createWorkspaceNode(request: {
      parentId: string;
      name: string;
      kind: 'folder' | 'connection';
      protocol: '' | WormholeProtocol;
      host: string;
      port: number;
      username: string;
      inlinePasswordAction: 'preserve' | 'set' | 'clear';
      inlinePassword: string;
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
      rdp?: WormholeWorkspaceRdpSettings;
    }): Promise<{ nodeId: string }>;
    updateWorkspaceNode(request: {
      id: string;
      parentId: string;
      name: string;
      kind: 'folder' | 'connection';
      protocol: '' | WormholeProtocol;
      host: string;
      port: number;
      username: string;
      inlinePasswordAction: 'preserve' | 'set' | 'clear';
      inlinePassword: string;
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
      rdp?: WormholeWorkspaceRdpSettings;
    }): Promise<{ updated: boolean }>;
    rdpExternalClientRequirement(request: {
      username: string;
      domain: string;
      credentialId?: string;
      inheritedFromNodeId?: string;
    }): Promise<{ required: boolean }>;
    createCredential(request: {
      name: string;
      protocol: 'ssh' | 'rdp' | 'vnc';
      kind: 'password' | 'sshKey';
      username: string;
      domain: string;
      password: string;
      passphrase: string;
      clearPassphrase: boolean;
      privateKeySelectionId?: string;
      provider: 'Local';
    }): Promise<WormholeWorkspaceCredential>;
    updateCredential(request: {
      id: string;
      name: string;
      protocol: 'ssh' | 'rdp' | 'vnc';
      kind: 'password' | 'sshKey';
      username: string;
      domain: string;
      password: string;
      passphrase: string;
      clearPassphrase: boolean;
      privateKeySelectionId?: string;
      provider: 'Local' | 'Bitwarden';
      bitwardenItemId?: string;
      bitwardenItemName?: string;
      bitwardenFieldPath?: string;
    }): Promise<WormholeWorkspaceCredential>;
    selectSshPrivateKey(): Promise<{
      selectionId: string;
      fileName: string;
    } | null>;
    discardSshPrivateKeySelection(request: {
      selectionId: string;
    }): Promise<{ discarded: boolean }>;
    deleteCredential(request: { id: string }): Promise<{ deleted: boolean; error?: string }>;
    updateWorkspaceNodeSshSettings(request: {
      nodeId: string;
      sshAutoSudo: boolean | null;
    }): Promise<{ updated: boolean }>;
    listCredentialsForProtocol(
      protocol: 'ssh' | 'rdp' | 'vnc',
    ): Promise<WormholeWorkspaceCredential[]>;
    updateWorkspaceNodeCredential(request: {
      nodeId: string;
      mode: 0 | 1 | 2;
      credentialId: string;
    }): Promise<{ updated: boolean }>;
    updateWorkspaceNodeInlineCredential(request: {
      nodeId: string;
      protocol: 'ssh' | 'rdp';
      username: string;
      domain: string;
      password: string;
    }): Promise<{ updated: boolean }>;
    updateWorkspaceNodeWebSettings(request: {
      nodeId: string;
      httpIgnoreCertErrors: boolean | null;
    }): Promise<{ updated: boolean }>;
    openWebSession(request: {
      sessionId: string;
      attempt: number;
      nodeId?: string;
      address?: string;
      port?: number;
      protocol?: 'http' | 'https';
      ignoreCertErrors?: boolean;
      tunnelConfigId?: string;
    }): Promise<WormholeWebTarget>;
    setWebSessionBounds(request: {
      sessionId: string;
      x: number;
      y: number;
      width: number;
      height: number;
      visible: boolean;
    }): Promise<void>;
    commandWebSession(request: {
      sessionId: string;
      operation: 'back' | 'forward' | 'reload' | 'stop';
    }): Promise<void>;
    showTreeTooltip(request: {
      text: string;
      anchor: { x: number; y: number; width: number; height: number };
      width: number;
    }): Promise<void>;
    hideTreeTooltip(): Promise<void>;
    closeWebSession(sessionId: string): Promise<void>;
    onWebEvent(listener: (event: WormholeWebEvent) => void): () => void;
    updateWorkspaceNodeTunnelSettings(
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
    ): Promise<{ updated: boolean }>;
    createTunnel(request: {
      name: string;
      kind: number;
      settings: Record<string, unknown>;
    }): Promise<WormholeTunnelDetails>;
    listTunnels(): Promise<WormholeWorkspaceTunnel[]>;
    readTunnel(id: string): Promise<WormholeTunnelDetails>;
    updateTunnel(request: {
      id: string;
      name: string;
      kind: number;
      settings: Record<string, unknown>;
    }): Promise<WormholeTunnelDetails>;
    deleteTunnel(id: string): Promise<{ deleted: boolean; error?: string }>;
    testTunnel(request: {
      id: string;
      attempt: number;
      targetHost?: string;
      targetPort?: number;
    }): Promise<{ connected: boolean; error?: string }>;
    cancelTunnelTest(): Promise<{ cancelled: boolean }>;
    onTunnelTestProgress(listener: (event: WormholeTunnelTestProgress) => void): () => void;
    importWatchguardProfile(): Promise<{
      server: string;
      port: number;
      profileOvpn: string;
    } | null>;
    importAzureVpnProfile(): Promise<{
      name?: string;
      settings: Record<string, unknown>;
    } | null>;
    importOvpnProfile(): Promise<{ contents: string } | null>;
    importCiscoProfile(): Promise<{
      host: string;
      port: number;
      group?: string;
      profileName?: string;
    } | null>;
    respondTunnelPrompt(request: {
      leaseId: string;
      promptId: string;
      value: string;
      cancelled: boolean;
    }): Promise<void>;
    respondTunnelRoute(request: {
      leaseId: string;
      promptId: string;
      choice: 'tunnel' | 'direct' | 'cancel';
    }): Promise<void>;
    readAppSettings(): Promise<WormholeAppSettings>;
    setTheme(theme: 'system' | 'light' | 'dark'): Promise<{ updated: boolean }>;
    setPromptBeforeTunnelConnect(enabled: boolean): Promise<{ updated: boolean }>;
    setConfirmOnTabClose(enabled: boolean): Promise<{ updated: boolean }>;
    setSidebarWidth(width: number): Promise<{ updated: boolean; sidebarWidth: number }>;
    setConnectionTreeExpansion(state: {
      defaultExpanded: boolean;
      folderIds: string[];
    }): Promise<{ updated: boolean }>;
    reportActiveSessionCount(count: number): void;
    onWindowCloseConfirmationRequested(
      listener: (request: {
        activeSessionCount: number;
        action: 'window' | 'quit';
      }) => boolean | Promise<boolean>,
    ): () => void;
    onWindowCloseRequested(listener: () => Promise<void>): () => void;
    setAutoCopyOnSelect(enabled: boolean): Promise<{ updated: boolean }>;
    setUpdatePreferences(preferences: {
      autoCheckForUpdates?: boolean;
      skippedUpdateVersion?: string | null;
    }): Promise<{ updated: boolean }>;
    updateStatus(): Promise<{
      currentVersion: string;
      result: WormholeUpdateCheckResult | null;
    }>;
    checkForUpdates(): Promise<WormholeUpdateCheckResult>;
    downloadUpdate(request: {
      installerUrl: string;
      installerFileName: string;
      installerSha256?: string;
      installerSize?: number | null;
    }): Promise<string>;
    installUpdate(installerPath: string): Promise<{ appWillQuit: boolean }>;
    openExternal(url: string): Promise<void>;
    onUpdateResult(listener: (result: WormholeUpdateCheckResult) => void): () => void;
    onUpdateProgress(
      listener: (progress: { downloaded: number; total: number }) => void,
    ): () => void;
    readLogsInfo(): Promise<WormholeLogsInfo>;
    setLogRetentionDays(days: number): Promise<{ updated: boolean; logRetentionDays: number }>;
    setLogLevel(level: string): Promise<{ updated: boolean; logLevel: string }>;
    openCurrentLogFile(): Promise<{ opened: boolean }>;
    openLogsFolder(): Promise<{ opened: boolean }>;
    readBitwardenExtension(): Promise<WormholeBitwardenExtensionState>;
    setBitwardenExtensionEnabled(enabled: boolean): Promise<WormholeBitwardenExtensionState>;
    installBitwardenExtension(): Promise<WormholeBitwardenExtensionState>;
    ensureBitwardenExtension(): Promise<WormholeBitwardenExtensionState>;
    importBitwardenExtensionZip(): Promise<WormholeBitwardenExtensionState | null>;
    importBitwardenExtensionFolder(): Promise<WormholeBitwardenExtensionState | null>;
    readBitwardenCli(): Promise<WormholeBitwardenCliState>;
    setBitwardenCliEnabled(enabled: boolean): Promise<WormholeBitwardenCliState>;
    setBitwardenCliConfig(config: {
      path: string;
      serverRegion: number;
    }): Promise<WormholeBitwardenCliState>;
    installBitwardenCli(): Promise<WormholeBitwardenCliState>;
    refreshBitwardenCliStatus(): Promise<WormholeBitwardenCliStatus>;
    loginBitwardenCli(request: {
      email: string;
      masterPassword: string;
      authenticatorCode?: string;
      serverRegion: number;
    }): Promise<{ loggedIn: boolean }>;
    unlockBitwardenCli(masterPassword: string): Promise<{ unlocked: boolean }>;
    logoutBitwardenCli(): Promise<{ loggedOut: boolean }>;
    syncBitwardenCli(): Promise<{
      lastSyncUtc: string;
      lastSyncStatus: string;
      availableCount: number;
      usedCache: boolean;
      lastSyncError?: string;
    }>;
    searchBitwardenItems(query: string): Promise<{ items: WormholeBitwardenLoginItem[] }>;
    nodeUsesBitwarden(request: {
      nodeId: string;
      protocol: 'ssh' | 'rdp' | 'vnc';
    }): Promise<{ bitwarden: boolean }>;
    openBitwardenPopup(request: {
      sessionId: string;
      anchor: { x: number; y: number; width: number; height: number };
    }): Promise<{ open: boolean }>;
    closeBitwardenPopup(sessionId: string): Promise<{ open: false }>;
    onBitwardenPopupState(
      listener: (state: { sessionId: string; open: boolean }) => void,
    ): () => void;
    openSshSession(request: {
      sessionId: string;
      nodeId?: string;
      host?: string;
      port?: number;
      username?: string;
      password?: string;
      credentialId?: string;
      autoSudo?: boolean;
      tunnelConfigId?: string;
      columns: number;
      rows: number;
      manualCredentials?: boolean;
      keyPassphrase?: string;
      manualKeyPassphrase?: boolean;
    }): Promise<WormholeSshConnected>;
    trustSshHostKey(request: {
      sessionId: string;
      nodeId: string;
      expected: string;
      received: string;
    }): Promise<WormholeSshConnected>;
    sendSshInput(sessionId: string, data: string): Promise<void>;
    pasteClipboardToSsh(sessionId: string): Promise<{ pasted: boolean }>;
    resizeSshSession(sessionId: string, columns: number, rows: number): Promise<void>;
    openSftpBrowser(sessionId: string, requestId?: string): Promise<void>;
    listSftpDirectory(sessionId: string, path: string, requestId?: string): Promise<void>;
    listLocalSftpDirectory(sessionId: string, path: string, requestId: string): Promise<void>;
    operateSftp(
      sessionId: string,
      request: {
        requestId: string;
        pane: 'local' | 'remote';
        operation: 'mkdir' | 'file' | 'delete' | 'rename' | 'open';
        path: string;
        destinationPath?: string;
      },
    ): Promise<void>;
    startSftpTransfer(
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
    ): Promise<void>;
    decideSftpConflict(
      sessionId: string,
      transferId: string,
      itemId: string,
      decision: 'overwrite' | 'skip',
      applyToAll: boolean,
    ): Promise<void>;
    cancelSftpTransfer(sessionId: string, transferId: string, itemId?: string): Promise<void>;
    closeSftpBrowser(sessionId: string): Promise<void>;
    closeSshSession(sessionId: string): Promise<void>;
    onSshEvent(listener: (event: WormholeSshEvent) => void): () => void;
    openSerialSession(request: {
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
    }): Promise<{
      sessionId: string;
      portName: string;
      baudRate: number;
      dataBits: number;
      stopBits: number;
      parity: number;
      flowControl: number;
    }>;
    sendSerialInput(sessionId: string, data: string): Promise<void>;
    resizeSerialSession(sessionId: string, columns: number, rows: number): Promise<void>;
    closeSerialSession(sessionId: string): Promise<void>;
    onSerialEvent(listener: (event: WormholeSerialEvent) => void): () => void;
    getAuthState(): Promise<WormholeAuthState>;
    verifyAuth(request: WormholeAuthVerificationRequest): Promise<WormholeAuthVerification>;
    setAuthSecret(request: WormholeAuthSecretRequest): Promise<WormholeAuthState>;
    updateAuthSettings(request: WormholeAuthSettingsRequest): Promise<WormholeAuthState>;
    lockAuthentication(): Promise<void>;
    checkWindowsHello(): Promise<WormholeHelloStatus>;
    verifyWindowsHello(): Promise<WormholeAuthVerification>;
    getSystemIdleSeconds(): Promise<{ seconds: number }>;
    mcpStatus(): Promise<WormholeMcpStatus>;
    startMcp(port: number): Promise<WormholeMcpStatus>;
    stopMcp(): Promise<WormholeMcpStatus>;
    setMcpPort(port: number): Promise<WormholeMcpStatus>;
    getMcpToken(): Promise<string>;
    regenerateMcpToken(): Promise<string>;
    respondMcpApproval(requestId: string, approved: boolean): Promise<void>;
    onMcpApproval(listener: (event: WormholeMcpApproval) => void): () => void;
    sendVncCommand(command: WormholeVncCommand): Promise<WormholeBackendResponse>;
    onBackendEvent(listener: (event: WormholeBackendEvent) => void): () => void;
    startRdpSession(request: {
      sessionId: string;
      profile: WormholeRdpProfile;
      bounds?: WormholeRdpSurfaceRect;
      manualCredentials?: boolean;
    }): Promise<WormholeRdpBackendEvent>;
    getRdpSystemClientCapability(request: { nodeId: string }): Promise<{ supported: boolean }>;
    openRdpInSystemClient(request: {
      sessionId: string;
      nodeId: string;
    }): Promise<
      | { ok: true; event: WormholeRdpBackendEvent }
      | { ok: false; lifecycleCommitted: boolean; error: string }
    >;
    resizeRdpSession(request: {
      sessionId: string;
      bounds?: WormholeRdpSurfaceRect;
    }): Promise<WormholeRdpBackendEvent>;
    commandRdpSession(request: {
      sessionId: string;
      operation: 'show' | 'hide' | 'focus' | 'disconnect';
      bounds?: WormholeRdpSurfaceRect;
    }): Promise<WormholeRdpBackendEvent>;
    onRdpEvent(listener: (event: WormholeRdpBackendEvent) => void): () => void;
  };
}
