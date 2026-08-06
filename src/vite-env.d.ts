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
  code?: number;
  attempt?: number;
  max?: number;
  message?: string;
}

interface WormholeWorkspaceNode {
  id: string;
  name: string;
  kind: 'folder' | 'connection';
  protocol?: WormholeProtocol;
  host?: string;
  port?: number;
  httpIgnoreCertErrors?: boolean;
  serialBaudRate?: number;
  serialDataBits?: number;
  serialStopBits?: number;
  serialParity?: number;
  serialFlowControl?: number;
  sshAutoSudo?: boolean;
  tunnelEnabled?: boolean;
  tunnelConfigId?: string;
  persisted?: boolean;
  children?: WormholeWorkspaceNode[];
}

interface WormholeWorkspaceCredential {
  id: string;
  name: string;
  protocol: WormholeProtocol;
  username: string;
  domain?: string;
  provider: 'Local' | 'Bitwarden';
  canEdit: boolean;
  canDelete: boolean;
}

interface WormholeWorkspaceTunnel {
  id: string;
  name: string;
  kind: string;
}

interface WormholeTunnelDetails {
  id: string;
  name: string;
  kind: number;
  settings: Record<string, unknown>;
}

interface WormholeWorkspaceSnapshot {
  tree: WormholeWorkspaceNode[];
  credentials: WormholeWorkspaceCredential[];
  tunnels: WormholeWorkspaceTunnel[];
}

interface WormholeWebTarget {
  url: string;
  protocol: 'http' | 'https';
  host: string;
  port: number;
  ignoreCertErrors: boolean;
}

interface WormholeWebEvent {
  type: 'connected' | 'failed' | 'navigation';
  sessionId: string;
  attempt: number;
  url: string;
  canGoBack: boolean;
  canGoForward: boolean;
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
      type: 'error';
      sessionId: string;
      error: string;
      hostKeyExpected?: string;
      hostKeyReceived?: string;
    }
  | { type: 'tunnel.progress'; sessionId: string; phase: string; detail?: string }
  | { type: 'sftp.opening' | 'sftp.closed'; sessionId: string; requestId?: string }
  | {
      type: 'sftp.ready';
      sessionId: string;
      path: string;
      entries: WormholeSftpEntry[];
      truncated: boolean;
      requestId?: string;
    }
  | { type: 'sftp.error'; sessionId: string; error: string; path?: string; requestId?: string }
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
    }
  | { action: 'vnc.disconnect'; sessionId: string }
  | { action: 'vnc.pointer'; sessionId: string; x: number; y: number; buttons: number }
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
}

interface WormholeTunnelPrompt {
  type: 'tunnel.prompt';
  sessionId: string;
  promptId: string;
  title: string;
  message: string;
  secret: boolean;
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
  promptBeforeTunnelConnect: boolean;
  autoCheckForUpdates: boolean;
  lastUpdateCheck: string | null;
  skippedUpdateVersion: string | null;
}

interface Window {
  wormhole?: {
    loadWorkspace(): Promise<WormholeWorkspaceSnapshot>;
    createCredential(request: {
      name: string;
      protocol: 'ssh' | 'rdp' | 'vnc';
      username: string;
      domain: string;
      password: string;
    }): Promise<WormholeWorkspaceCredential>;
    updateCredential(request: {
      id: string;
      name: string;
      protocol: 'ssh' | 'rdp' | 'vnc';
      username: string;
      domain: string;
      password: string;
    }): Promise<WormholeWorkspaceCredential>;
    deleteCredential(request: { id: string }): Promise<{ deleted: boolean; error?: string }>;
    updateWorkspaceNodeSshSettings(request: {
      nodeId: string;
      sshAutoSudo: boolean | null;
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
      protocol?: 'http' | 'https';
      ignoreCertErrors?: boolean;
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
      operation: 'back' | 'forward' | 'reload';
    }): Promise<void>;
    closeWebSession(sessionId: string): Promise<void>;
    onWebEvent(listener: (event: WormholeWebEvent) => void): () => void;
    updateWorkspaceNodeTunnelSettings(request: {
      nodeId: string;
      tunnelEnabled: boolean | null;
      tunnelConfigId: string;
    }): Promise<{ updated: boolean }>;
    createTunnel(request: {
      name: string;
      kind: number;
      settings: Record<string, unknown>;
    }): Promise<WormholeTunnelDetails>;
    readTunnel(id: string): Promise<WormholeTunnelDetails>;
    updateTunnel(request: {
      id: string;
      name: string;
      kind: number;
      settings: Record<string, unknown>;
    }): Promise<WormholeTunnelDetails>;
    deleteTunnel(id: string): Promise<{ deleted: boolean; error?: string }>;
    testTunnel(id: string): Promise<{ connected: boolean; error?: string }>;
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
    setPromptBeforeTunnelConnect(enabled: boolean): Promise<{ updated: boolean }>;
    setUpdatePreferences(preferences: {
      autoCheckForUpdates?: boolean;
      skippedUpdateVersion?: string | null;
    }): Promise<{ updated: boolean }>;
    updateStatus(): Promise<{ currentVersion: string; result: WormholeUpdateCheckResult | null }>;
    checkForUpdates(): Promise<WormholeUpdateCheckResult>;
    downloadUpdate(request: {
      installerUrl: string;
      installerFileName: string;
      installerSha256?: string;
      installerSize?: number | null;
    }): Promise<string>;
    installUpdate(installerPath: string): Promise<{ launched: boolean }>;
    openExternal(url: string): Promise<void>;
    onUpdateResult(listener: (result: WormholeUpdateCheckResult) => void): () => void;
    onUpdateProgress(
      listener: (progress: { downloaded: number; total: number }) => void,
    ): () => void;
    openSshSession(request: {
      sessionId: string;
      nodeId: string;
      columns: number;
      rows: number;
    }): Promise<WormholeSshConnected>;
    trustSshHostKey(request: {
      nodeId: string;
      expected: string;
      received: string;
    }): Promise<{ updated: boolean }>;
    sendSshInput(sessionId: string, data: string): Promise<void>;
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
    }): Promise<WormholeRdpBackendEvent>;
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
