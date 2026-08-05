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
  children?: WormholeWorkspaceNode[];
}

interface WormholeWorkspaceCredential {
  id: string;
  name: string;
  protocol: WormholeProtocol;
  username: string;
  domain?: string;
  provider: 'Local' | 'Bitwarden';
  readOnly?: boolean;
}

interface WormholeWorkspaceTunnel {
  id: string;
  name: string;
  kind: string;
}

interface WormholeWorkspaceSnapshot {
  tree: WormholeWorkspaceNode[];
  credentials: WormholeWorkspaceCredential[];
  tunnels: WormholeWorkspaceTunnel[];
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
    };
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
  type: 'vnc.status' | 'vnc.frame';
  sessionId: string;
  status?: 'connecting' | 'connected' | 'failed' | 'disconnected';
  message?: string;
  passwordRequired?: boolean;
  width?: number;
  height?: number;
  image?: string;
}

interface Window {
  wormhole?: {
    loadWorkspace(): Promise<WormholeWorkspaceSnapshot>;
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
    closeSshSession(sessionId: string): Promise<void>;
    onSshEvent(listener: (event: WormholeSshEvent) => void): () => void;
    getAuthState(): Promise<WormholeAuthState>;
    verifyAuth(request: WormholeAuthVerificationRequest): Promise<WormholeAuthVerification>;
    setAuthSecret(request: WormholeAuthSecretRequest): Promise<WormholeAuthState>;
    updateAuthSettings(request: WormholeAuthSettingsRequest): Promise<WormholeAuthState>;
    lockAuthentication(): Promise<void>;
    checkWindowsHello(): Promise<WormholeHelloStatus>;
    verifyWindowsHello(): Promise<WormholeAuthVerification>;
    getSystemIdleSeconds(): Promise<{ seconds: number }>;
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
