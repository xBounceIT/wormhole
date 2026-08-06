import {
  app,
  BrowserWindow,
  dialog,
  ipcMain,
  screen,
  session as electronSession,
  shell,
  WebContentsView,
} from 'electron';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { createInterface, type Interface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { AuthSession } from './auth-session.js';
import { RdpBackendClient } from './rdp.js';
import { isMatchingOAuthRedirect } from './tunnel-auth.js';
import {
  SerialBackendClient,
  isSerialInput,
  isSerialOpenRequest,
  isSerialSessionId,
  type SerialBackendEvent,
  type SerialConnectedResponse,
  type SerialOpenRequest,
} from './serial.js';
import { WebSessionAttemptTracker } from './web-session-attempt.js';
import type {
  RdpBackendEvent,
  RdpCommandRequest,
  RdpProfile,
  RdpStartRequest,
  RdpSurfaceRect,
} from './rdp-contract.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rendererUrl = process.env.VITE_DEV_SERVER_URL;
const nativeTitlebarColor = '#0a0a0a00';
const nativeTitlebarSymbolColor = '#ffffff';
const nativeTitlebarHeight = 48;
const wormholeDataDirectoryName = 'Wormhole';
const backendTimeoutMs = 30_000;
const tunnelTestTimeoutMs = 315_000;
const nativeConnectionTimeoutMs = 315_000;
const backendMaxBuffer = 16 * 1024 * 1024;
const backendMaxRequestBytes = 64 * 1024;
const backendMaxTunnelRequestBytes = 4 * 1024 * 1024;
const nativeBackendLineLimit = 32 * 1024 * 1024;
const nativeBackendCommandTimeoutMs = 15_000;
let rdpClient: RdpBackendClient | undefined;
const rdpTunnelLeases = new Map<string, string>();
let serialBackend: SerialBackendClient | undefined;
let latestUpdateCheck: UpdateCheckResult | undefined;
let updateCheckInFlight: Promise<UpdateCheckResult> | undefined;
let updateDownloadChild: ChildProcessWithoutNullStreams | undefined;

type BackendOperation =
  | 'workspace'
  | 'web-target'
  | 'watchguard-import'
  | 'azure-vpn-import'
  | 'cisco-profile-import'
  | 'ovpn-file-import'
  | 'credential-create'
  | 'credential-update'
  | 'credential-delete'
  | 'workspace-update-node'
  | 'workspace-update-node-web-settings'
  | 'workspace-update-node-tunnel'
  | 'tunnel-create'
  | 'tunnel-read'
  | 'tunnel-update'
  | 'tunnel-delete'
  | 'migrate'
  | 'auth-status'
  | 'auth-verify'
  | 'auth-set-secret'
  | 'auth-update-settings'
  | 'auth-hello-status'
  | 'auth-hello-verify'
  | 'auth-system-idle'
  | 'ssh-trust-host-key'
  | 'settings-read'
  | 'settings-set-prompt-before-tunnel'
  | 'settings-set-update-preferences'
  | 'update-check'
  | 'update-download';
type VncAction =
  | 'vnc.connect'
  | 'vnc.disconnect'
  | 'vnc.pointer'
  | 'vnc.key'
  | 'tunnel.acquire'
  | 'tunnel.release'
  | 'tunnel.prompt-response'
  | 'tunnel.route-response';
type VncCommand = {
  action: VncAction;
  sessionId: string;
  nodeId?: string;
  credentialId?: string;
  host?: string;
  port?: number;
  password?: string;
  x?: number;
  y?: number;
  buttons?: number;
  down?: boolean;
  keysym?: number;
  tunnelConfigId?: string;
  promptId?: string;
  value?: string;
  cancelled?: boolean;
  progressSessionId?: string;
};
type BackendResponse = {
  id: string;
  ok: boolean;
  error?: string;
  socksEndpoint?: string;
  leaseId?: string;
};
type BackendEvent = {
  type: string;
  sessionId: string;
  status?: string;
  message?: string;
  passwordRequired?: boolean;
  width?: number;
  height?: number;
  image?: string;
  promptId?: string;
  title?: string;
  secret?: boolean;
  urls?: string[];
  ignoreCertificateErrors?: boolean;
  leaseId?: string;
  phase?: string;
  detail?: string;
  connectionName?: string;
  tunnelName?: string;
};
type MigrationResponse = {
  status: 'completed' | 'already-completed' | 'skipped-non-windows';
  migrated: number;
  missing: number;
};
type AppSettings = {
  promptBeforeTunnelConnect: boolean;
  autoCheckForUpdates: boolean;
  lastUpdateCheck: string | null;
  skippedUpdateVersion: string | null;
};
type UpdateCheckResult = {
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
type UpdateDownloadRequest = {
  installerUrl: string;
  installerFileName: string;
  installerSha256?: string;
  installerSize?: number | null;
};
type WorkspaceResponse = {
  tree: unknown[];
  credentials: WorkspaceCredential[];
  tunnels: unknown[];
};
type WorkspaceCredential = {
  id: string;
  name: string;
  protocol: CredentialProtocol;
  username: string;
  domain?: string;
  provider: 'Local' | 'Bitwarden';
  canEdit: boolean;
  canDelete: boolean;
};
type CredentialProtocol = 'ssh' | 'rdp' | 'vnc';
type CredentialCreateRequest = {
  name: string;
  protocol: CredentialProtocol;
  username: string;
  domain: string;
  password: string;
};
type CredentialUpdateRequest = CredentialCreateRequest & { id: string };
type CredentialDeleteRequest = { id: string };
type WorkspaceNodeSshSettingsRequest = {
  nodeId: string;
  sshAutoSudo: boolean | null;
};
type WorkspaceNodeWebSettingsRequest = {
  nodeId: string;
  httpIgnoreCertErrors: boolean | null;
};
type WebTargetResponse = {
  url: string;
  protocol: 'http' | 'https';
  host: string;
  port: number;
  ignoreCertErrors: boolean;
  tunnelConfigId?: string;
  proxyUrl?: string;
};
type WebOpenRequest = {
  sessionId: string;
  attempt: number;
  nodeId?: string;
  address?: string;
  protocol?: 'http' | 'https';
  ignoreCertErrors?: boolean;
};
type WebBoundsRequest = {
  sessionId: string;
  x: number;
  y: number;
  width: number;
  height: number;
  visible: boolean;
};
type WebCommandRequest = {
  sessionId: string;
  operation: 'back' | 'forward' | 'reload';
};
type WorkspaceNodeTunnelSettingsRequest = {
  nodeId: string;
  tunnelEnabled: boolean | null;
  tunnelConfigId: string;
};
type TunnelWriteRequest = {
  id?: string;
  name: string;
  kind: number;
  settings: Record<string, unknown>;
};
type TunnelReadRequest = { id: string };
type TunnelDeleteRequest = { id: string };
type TunnelDetailsResponse = {
  id: string;
  name: string;
  kind: number;
  settings: Record<string, unknown>;
};
type AuthStateResponse = {
  mode: string;
  configured: boolean;
};

const authSession = new AuthSession();
let authOperationQueue: Promise<void> = Promise.resolve();

type SshConnectedResponse = {
  sessionId: string;
  host: string;
  port: number;
  username: string;
  fingerprint: string;
};

type SshTerminalCell = {
  character: string;
  foreground: number;
  background: number;
};

type SshTerminalCellChange = SshTerminalCell & {
  index: number;
};

type SshTerminalScrollbackRun = {
  text: string;
  cells: number;
  foreground: number;
  background: number;
};

type SshTerminalScrollbackLine = {
  runs: SshTerminalScrollbackRun[];
};

type SshTerminalFrame = {
  columns: number;
  rows: number;
  full: boolean;
  cells?: SshTerminalCell[];
  changes: SshTerminalCellChange[];
  scrollbackReset: boolean;
  viewportReset: boolean;
  scrollback?: SshTerminalScrollbackLine[];
  cursorX: number;
  cursorY: number;
  cursorVisible: boolean;
  applicationCursor: boolean;
  title?: string;
  sequence: number;
};

type SshSftpEntry = {
  name: string;
  fullPath: string;
  isDirectory: boolean;
  isSymbolicLink: boolean;
  size: number;
  lastModifiedUtc?: string;
};

type SshSftpWireEntry = {
  name: string;
  full_path: string;
  is_directory: boolean;
  is_symbolic_link: boolean;
  size: number;
  last_modified_utc?: string;
};
type SshSftpQuickPath = {
  displayName: string;
  path: string;
  isSeparator: boolean;
};

type SshSftpPane = 'local' | 'remote';
type SshSftpOperation = 'mkdir' | 'file' | 'delete' | 'rename' | 'open';
type SshSftpTransferDirection = 'local-to-remote' | 'remote-to-local' | 'local-to-local';
type SshSftpTransferDecision = 'overwrite' | 'skip';
type SshSftpTransferState =
  | 'running'
  | 'progress'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'batch-failed'
  | 'batch-completed'
  | 'batch-cancelled';
type SshSftpTransferItem = {
  sourcePath: string;
  name: string;
  isDirectory: boolean;
  size: number;
};

type SshBackendEvent =
  | {
      type: 'connected';
      sessionId: string;
      host: string;
      port: number;
      username: string;
      fingerprint: string;
    }
  | { type: 'screen'; sessionId: string; frame: SshTerminalFrame }
  | { type: 'closed'; sessionId: string }
  | {
      type: 'error';
      sessionId: string;
      error: string;
      hostKeyExpected?: string;
      hostKeyReceived?: string;
    }
  | { type: 'sftp.opening' | 'sftp.closed'; sessionId: string; requestId?: string }
  | {
      type: 'sftp.ready';
      sessionId: string;
      path: string;
      entries: SshSftpEntry[];
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
      entries: SshSftpEntry[];
      truncated: boolean;
      quickPaths?: SshSftpQuickPath[];
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
      pane: SshSftpPane;
      operation: SshSftpOperation;
      path: string;
      error?: string;
    }
  | {
      type: 'sftp.conflict';
      sessionId: string;
      transferId: string;
      itemId: string;
      direction: SshSftpTransferDirection;
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
      transferState: SshSftpTransferState;
      direction?: SshSftpTransferDirection;
      displayName?: string;
      expectedBytes?: number;
      bytesTransferred?: number;
      error?: string;
    };

type SshOpenRequest = {
  sessionId: string;
  nodeId: string;
  columns: number;
  rows: number;
};

type SshHostKeyTrustRequest = {
  nodeId: string;
  expected: string;
  received: string;
};

type SftpOperationRequest = {
  requestId: string;
  pane: SshSftpPane;
  operation: SshSftpOperation;
  path: string;
  destinationPath?: string;
};

type SftpTransferRequest = {
  transferId: string;
  direction: SshSftpTransferDirection;
  destinationPath: string;
  items: SshSftpTransferItem[];
};

type McpStatusResponse = {
  enabled: boolean;
  running: boolean;
  port: number;
  endpoint: string;
};

type McpControlResponse = {
  type: 'mcp.response';
  requestId: string;
  status?: McpStatusResponse;
  token?: string;
  error?: string;
};

type McpApprovalEvent = {
  type: 'mcp.approval';
  requestId: string;
  sessionId: string;
  host: string;
  port: number;
  username: string;
  title: string;
  tool: string;
};

const sshMaxSessionIdLength = 128;
const sshMaxInputLength = 1_500_000;
const sshMaxTerminalCells = 500 * 500;
const sshMaxTerminalScrollbackLines = 5000;
const sshMaxTerminalScrollbackLineLength = 2048;
const sshMaxSftpPathLength = 16 * 1024;
const sshMaxSftpEntries = 4096;
const sshMaxSftpEntryNameLength = 4096;
const sshMaxSftpErrorLength = 4096;
const sshMaxSftpQuickPaths = 64;
const sshMaxSftpQuickPathLabelLength = 256;
const credentialMaxNameLength = 256;
const credentialMaxUsernameLength = 512;
const credentialMaxDomainLength = 512;
const credentialMaxPasswordLength = 4096;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isSshSessionId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= sshMaxSessionIdLength &&
    value.trim() === value
  );
}

// Omit the `persist:` prefix so appliance cookies and cache remain available to tabs during this
// Electron run but are never written to disk after the app closes.
const webSharedPartition = 'wormhole-web';
const webMaxUrlLength = 4096;
const webMaxAddressLength = 4096;
const webMaxSurfaceCoordinate = 100_000;

function isWebOpenRequest(value: unknown): value is WebOpenRequest {
  if (
    !isRecord(value) ||
    !isSshSessionId(value.sessionId) ||
    typeof value.attempt !== 'number' ||
    !Number.isSafeInteger(value.attempt) ||
    value.attempt < 1
  ) {
    return false;
  }
  const hasNodeId = value.nodeId !== undefined;
  const hasDirectTarget = value.address !== undefined || value.protocol !== undefined;
  if (hasNodeId === hasDirectTarget) return false;
  if (hasNodeId) {
    return (
      isSshSessionId(value.nodeId) &&
      value.address === undefined &&
      value.protocol === undefined &&
      value.ignoreCertErrors === undefined
    );
  }
  if (
    typeof value.address !== 'string' ||
    value.address.length === 0 ||
    value.address.length > webMaxAddressLength ||
    (value.protocol !== 'http' && value.protocol !== 'https')
  ) {
    return false;
  }
  return value.ignoreCertErrors === undefined || typeof value.ignoreCertErrors === 'boolean';
}

function isWebBoundsRequest(value: unknown): value is WebBoundsRequest {
  if (!isRecord(value) || !isSshSessionId(value.sessionId) || typeof value.visible !== 'boolean') {
    return false;
  }
  for (const field of ['x', 'y', 'width', 'height'] as const) {
    const coordinate = value[field];
    if (
      typeof coordinate !== 'number' ||
      !Number.isFinite(coordinate) ||
      coordinate < 0 ||
      coordinate > webMaxSurfaceCoordinate
    ) {
      return false;
    }
  }
  const width = value.width;
  const height = value.height;
  return typeof width === 'number' && typeof height === 'number' && width >= 1 && height >= 1;
}

function isWebCommandRequest(value: unknown): value is WebCommandRequest {
  return (
    isRecord(value) &&
    isSshSessionId(value.sessionId) &&
    (value.operation === 'back' || value.operation === 'forward' || value.operation === 'reload')
  );
}

function isSshOpenRequest(value: unknown): value is SshOpenRequest {
  return (
    isRecord(value) &&
    isSshSessionId(value.sessionId) &&
    isSshSessionId(value.nodeId) &&
    typeof value.columns === 'number' &&
    Number.isInteger(value.columns) &&
    value.columns >= 0 &&
    value.columns <= 500 &&
    typeof value.rows === 'number' &&
    Number.isInteger(value.rows) &&
    value.rows >= 0 &&
    value.rows <= 500
  );
}

function isWorkspaceNodeSshSettingsRequest(
  value: unknown,
): value is WorkspaceNodeSshSettingsRequest {
  return (
    isRecord(value) &&
    isSshSessionId(value.nodeId) &&
    (value.sshAutoSudo === null || typeof value.sshAutoSudo === 'boolean')
  );
}

function parseCredentialCreateRequest(value: unknown): CredentialCreateRequest {
  if (!isRecord(value)) throw new Error('Credential details are invalid.');
  const name = value.name;
  const protocol = value.protocol;
  const username = value.username;
  const domain = value.domain;
  const password = value.password;
  if (
    typeof name !== 'string' ||
    name.length > credentialMaxNameLength ||
    typeof username !== 'string' ||
    username.length > credentialMaxUsernameLength ||
    typeof domain !== 'string' ||
    domain.length > credentialMaxDomainLength ||
    typeof password !== 'string' ||
    password.length === 0 ||
    password.length > credentialMaxPasswordLength ||
    (protocol !== 'ssh' && protocol !== 'rdp' && protocol !== 'vnc')
  ) {
    throw new Error('Credential details are invalid.');
  }
  return { name, protocol, username, domain, password };
}

function parseCredentialUpdateRequest(value: unknown): CredentialUpdateRequest {
  const request = parseCredentialCreateRequest(value);
  const id = isRecord(value) ? value.id : undefined;
  if (typeof id !== 'string' || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(id)) {
    throw new Error('Credential id is invalid.');
  }
  return { ...request, id };
}

function parseCredentialDeleteRequest(value: unknown): CredentialDeleteRequest {
  const id = isRecord(value) ? value.id : undefined;
  if (typeof id !== 'string' || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(id)) {
    throw new Error('Credential id is invalid.');
  }
  return { id };
}

function isSshInput(value: unknown): value is string {
  return typeof value === 'string' && value.length <= sshMaxInputLength;
}

function isSftpPath(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    Buffer.byteLength(value, 'utf8') <= sshMaxSftpPathLength &&
    (value.length === 0 || value.startsWith('/')) &&
    !value.includes('\\') &&
    !value.includes('\u0000')
  );
}

function isLocalSftpPath(value: unknown, allowEmpty = false): value is string {
  return (
    typeof value === 'string' &&
    Buffer.byteLength(value, 'utf8') <= sshMaxSftpPathLength &&
    (allowEmpty && value.length === 0 ? true : /^(?:[A-Za-z]:[\\/]|\\\\)/.test(value)) &&
    !value.includes('\u0000')
  );
}

function isSftpPane(value: unknown): value is SshSftpPane {
  return value === 'local' || value === 'remote';
}

function isSftpOperation(value: unknown): value is SshSftpOperation {
  return (
    value === 'mkdir' ||
    value === 'file' ||
    value === 'delete' ||
    value === 'rename' ||
    value === 'open'
  );
}

function isSftpTransferDirection(value: unknown): value is SshSftpTransferDirection {
  return value === 'local-to-remote' || value === 'remote-to-local' || value === 'local-to-local';
}

function isSftpTransferDecision(value: unknown): value is SshSftpTransferDecision {
  return value === 'overwrite' || value === 'skip';
}

function isSftpRequestId(value: unknown): value is string {
  return (
    typeof value === 'string' && value.length > 0 && value.length <= 128 && value.trim() === value
  );
}

function isSftpTransferId(value: unknown): value is string {
  return isSftpRequestId(value);
}

function isSftpTransferItem(value: unknown): value is SshSftpTransferItem {
  return (
    isRecord(value) &&
    typeof value.sourcePath === 'string' &&
    value.sourcePath.length > 0 &&
    Buffer.byteLength(value.sourcePath, 'utf8') <= sshMaxSftpPathLength &&
    typeof value.name === 'string' &&
    value.name.length > 0 &&
    Buffer.byteLength(value.name, 'utf8') <= sshMaxSftpEntryNameLength &&
    !value.name.includes('/') &&
    !value.name.includes('\\') &&
    !value.name.includes(':') &&
    !value.name.includes('\u0000') &&
    value.name !== '.' &&
    value.name !== '..' &&
    typeof value.isDirectory === 'boolean' &&
    typeof value.size === 'number' &&
    Number.isSafeInteger(value.size) &&
    value.size >= 0
  );
}

function isSftpOperationRequest(value: unknown): value is SftpOperationRequest {
  if (
    !isRecord(value) ||
    !isSftpRequestId(value.requestId) ||
    !isSftpPane(value.pane) ||
    !isSftpOperation(value.operation) ||
    typeof value.path !== 'string' ||
    value.path.length === 0
  ) {
    return false;
  }
  const pathIsValid = value.pane === 'local' ? isLocalSftpPath(value.path) : isSftpPath(value.path);
  if (!pathIsValid) return false;
  if (value.destinationPath !== undefined) {
    if (typeof value.destinationPath !== 'string' || value.destinationPath.length === 0)
      return false;
    if (
      value.pane === 'local'
        ? !isLocalSftpPath(value.destinationPath)
        : !isSftpPath(value.destinationPath)
    ) {
      return false;
    }
  }
  return value.operation === 'rename' ? value.destinationPath !== undefined : true;
}

function isSftpTransferRequest(value: unknown): value is SftpTransferRequest {
  if (
    !isRecord(value) ||
    !isSftpTransferId(value.transferId) ||
    !isSftpTransferDirection(value.direction) ||
    !Array.isArray(value.items) ||
    value.items.length === 0 ||
    value.items.length > 256 ||
    !value.items.every(isSftpTransferItem) ||
    (value.direction === 'local-to-remote'
      ? !isSftpPath(value.destinationPath)
      : !isLocalSftpPath(value.destinationPath))
  ) {
    return false;
  }
  const sourceIsLocal = value.direction !== 'remote-to-local';
  return value.items.every((item) =>
    sourceIsLocal ? isLocalSftpPath(item.sourcePath) : isSftpPath(item.sourcePath),
  );
}

function isSftpEntry(value: unknown, pane: SshSftpPane = 'remote'): value is SshSftpWireEntry {
  if (!isRecord(value)) return false;
  return (
    typeof value.name === 'string' &&
    value.name.length > 0 &&
    Buffer.byteLength(value.name, 'utf8') <= sshMaxSftpEntryNameLength &&
    !value.name.includes('/') &&
    !value.name.includes('\\') &&
    !value.name.includes(':') &&
    !value.name.includes('\u0000') &&
    typeof value.full_path === 'string' &&
    value.full_path.length > 0 &&
    (pane === 'local' ? isLocalSftpPath(value.full_path) : isSftpPath(value.full_path)) &&
    typeof value.is_directory === 'boolean' &&
    typeof value.is_symbolic_link === 'boolean' &&
    typeof value.size === 'number' &&
    Number.isSafeInteger(value.size) &&
    value.size >= 0 &&
    (value.last_modified_utc === undefined ||
      (typeof value.last_modified_utc === 'string' && value.last_modified_utc.length <= 128))
  );
}

function isSftpQuickPath(value: unknown): value is {
  display_name: string;
  path?: string;
  is_separator?: boolean;
} {
  if (
    !isRecord(value) ||
    typeof value.display_name !== 'string' ||
    value.display_name.length > sshMaxSftpQuickPathLabelLength ||
    (value.is_separator !== undefined && typeof value.is_separator !== 'boolean')
  ) {
    return false;
  }
  if (value.is_separator === true) {
    return value.path === undefined || value.path === '';
  }
  return isLocalSftpPath(value.path);
}

function isSshFingerprint(value: unknown): value is string {
  return typeof value === 'string' && /^SHA256:[A-Za-z0-9+/]{43}$/.test(value);
}

function isSshHostKeyTrustRequest(value: unknown): value is SshHostKeyTrustRequest {
  return (
    isRecord(value) &&
    isSshSessionId(value.nodeId) &&
    isSshFingerprint(value.expected) &&
    isSshFingerprint(value.received) &&
    value.expected !== value.received
  );
}

function isSshTerminalCell(value: unknown): value is SshTerminalCell {
  return (
    isRecord(value) &&
    typeof value.character === 'string' &&
    value.character.length <= 8 &&
    typeof value.foreground === 'number' &&
    Number.isInteger(value.foreground) &&
    value.foreground >= 0 &&
    value.foreground <= 0xffff &&
    typeof value.background === 'number' &&
    Number.isInteger(value.background) &&
    value.background >= 0 &&
    value.background <= 0xffff
  );
}

function isSshTerminalScrollbackLine(
  value: unknown,
  maxCells: number,
): value is SshTerminalScrollbackLine {
  if (!isRecord(value) || !Array.isArray(value.runs) || value.runs.length > maxCells) {
    return false;
  }
  let textLength = 0;
  let cellCount = 0;
  for (const run of value.runs) {
    if (
      !isRecord(run) ||
      typeof run.text !== 'string' ||
      run.text.length === 0 ||
      run.text.length > sshMaxTerminalScrollbackLineLength ||
      typeof run.cells !== 'number' ||
      !Number.isInteger(run.cells) ||
      run.cells < 1 ||
      run.cells > maxCells ||
      typeof run.foreground !== 'number' ||
      !Number.isInteger(run.foreground) ||
      run.foreground < 0 ||
      run.foreground > 0xffff ||
      typeof run.background !== 'number' ||
      !Number.isInteger(run.background) ||
      run.background < 0 ||
      run.background > 0xffff
    ) {
      return false;
    }
    textLength += run.text.length;
    cellCount += run.cells;
    if (textLength > sshMaxTerminalScrollbackLineLength || cellCount > maxCells) {
      return false;
    }
  }
  return true;
}

function parseSshTerminalFrame(value: unknown): SshTerminalFrame | undefined {
  if (
    !isRecord(value) ||
    typeof value.columns !== 'number' ||
    !Number.isInteger(value.columns) ||
    value.columns < 1 ||
    value.columns > 500 ||
    typeof value.rows !== 'number' ||
    !Number.isInteger(value.rows) ||
    value.rows < 1 ||
    value.rows > 500 ||
    (value.full !== undefined && typeof value.full !== 'boolean') ||
    (value.scrollback_reset !== undefined && typeof value.scrollback_reset !== 'boolean') ||
    (value.viewport_reset !== undefined && typeof value.viewport_reset !== 'boolean') ||
    typeof value.cursor_x !== 'number' ||
    !Number.isInteger(value.cursor_x) ||
    value.cursor_x < 0 ||
    value.cursor_x >= value.columns ||
    typeof value.cursor_y !== 'number' ||
    !Number.isInteger(value.cursor_y) ||
    value.cursor_y < 0 ||
    value.cursor_y >= value.rows ||
    typeof value.cursor_visible !== 'boolean' ||
    typeof value.application_cursor !== 'boolean' ||
    typeof value.sequence !== 'number' ||
    !Number.isSafeInteger(value.sequence) ||
    value.sequence < 1
  ) {
    return undefined;
  }

  const cellCount = value.columns * value.rows;
  let cells: SshTerminalCell[] | undefined;
  if (value.cells !== undefined) {
    if (
      !Array.isArray(value.cells) ||
      value.cells.length > sshMaxTerminalCells ||
      !value.cells.every(isSshTerminalCell)
    ) {
      return undefined;
    }
    cells = value.cells;
  }
  const full = value.full === true;
  if (full && (!cells || cells.length !== cellCount)) return undefined;

  const changes: SshTerminalCellChange[] = [];
  if (value.changes !== undefined) {
    if (!Array.isArray(value.changes) || value.changes.length > cellCount) return undefined;
    for (const change of value.changes) {
      const index = isRecord(change) ? change.index : undefined;
      if (
        !isRecord(change) ||
        typeof index !== 'number' ||
        !Number.isInteger(index) ||
        index < 0 ||
        index >= cellCount ||
        !isSshTerminalCell(change)
      ) {
        return undefined;
      }
      changes.push({ ...change, index });
    }
  }

  let scrollback: SshTerminalScrollbackLine[] | undefined;
  if (value.scrollback !== undefined) {
    if (
      !Array.isArray(value.scrollback) ||
      value.scrollback.length > sshMaxTerminalScrollbackLines ||
      !value.scrollback.every((line) => isSshTerminalScrollbackLine(line, value.columns as number))
    ) {
      return undefined;
    }
    scrollback = value.scrollback.slice();
  }

  return {
    columns: value.columns,
    rows: value.rows,
    full,
    cells,
    changes,
    scrollbackReset: value.scrollback_reset === true,
    viewportReset: value.viewport_reset === true,
    scrollback,
    cursorX: value.cursor_x,
    cursorY: value.cursor_y,
    cursorVisible: value.cursor_visible,
    applicationCursor: value.application_cursor,
    title: typeof value.title === 'string' ? value.title.slice(0, 2048) : undefined,
    sequence: value.sequence,
  };
}

function parseSshBackendEvent(line: string): SshBackendEvent | undefined {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return undefined;
  }
  if (!isRecord(value) || typeof value.type !== 'string' || !isSshSessionId(value.session_id)) {
    return undefined;
  }

  if (
    value.type === 'connected' &&
    typeof value.host === 'string' &&
    typeof value.port === 'number' &&
    Number.isInteger(value.port) &&
    value.port > 0 &&
    value.port <= 65535 &&
    typeof value.username === 'string' &&
    typeof value.fingerprint === 'string'
  ) {
    return {
      type: 'connected',
      sessionId: value.session_id,
      host: value.host,
      port: value.port,
      username: value.username,
      fingerprint: value.fingerprint,
    };
  }
  if (value.type === 'screen') {
    const frame = parseSshTerminalFrame(value.frame);
    return frame ? { type: 'screen', sessionId: value.session_id, frame } : undefined;
  }
  if (value.type === 'closed') {
    return { type: 'closed', sessionId: value.session_id };
  }
  if (value.type === 'sftp.opening' || value.type === 'sftp.closed') {
    if (value.request_id !== undefined && !isSftpRequestId(value.request_id)) {
      return undefined;
    }
    return {
      type: value.type,
      sessionId: value.session_id,
      requestId: isSftpRequestId(value.request_id) ? value.request_id : undefined,
    };
  }
  if (value.type === 'sftp.ready') {
    if (
      typeof value.path !== 'string' ||
      value.path.length === 0 ||
      !isSftpPath(value.path) ||
      (value.request_id !== undefined && !isSftpRequestId(value.request_id)) ||
      !Array.isArray(value.entries) ||
      value.entries.length > sshMaxSftpEntries ||
      !value.entries.every((entry) => isSftpEntry(entry)) ||
      typeof value.truncated !== 'boolean'
    ) {
      return undefined;
    }
    return {
      type: 'sftp.ready',
      sessionId: value.session_id,
      path: value.path,
      entries: value.entries.map((entry) => ({
        name: entry.name,
        fullPath: entry.full_path,
        isDirectory: entry.is_directory,
        isSymbolicLink: entry.is_symbolic_link,
        size: entry.size,
        lastModifiedUtc: entry.last_modified_utc,
      })),
      truncated: value.truncated,
      requestId: isSftpRequestId(value.request_id) ? value.request_id : undefined,
    };
  }
  if (value.type === 'sftp.local.ready') {
    if (
      !isSftpRequestId(value.request_id) ||
      value.pane !== 'local' ||
      !isLocalSftpPath(value.path) ||
      (value.quick_paths !== undefined &&
        (!Array.isArray(value.quick_paths) ||
          value.quick_paths.length > sshMaxSftpQuickPaths ||
          !value.quick_paths.every(isSftpQuickPath))) ||
      !Array.isArray(value.entries) ||
      value.entries.length > sshMaxSftpEntries ||
      !value.entries.every((entry) => isSftpEntry(entry, 'local')) ||
      typeof value.truncated !== 'boolean'
    ) {
      return undefined;
    }
    return {
      type: 'sftp.local.ready',
      sessionId: value.session_id,
      requestId: value.request_id,
      pane: 'local',
      path: value.path,
      entries: value.entries.map((entry) => ({
        name: entry.name,
        fullPath: entry.full_path,
        isDirectory: entry.is_directory,
        isSymbolicLink: entry.is_symbolic_link,
        size: entry.size,
        lastModifiedUtc: entry.last_modified_utc,
      })),
      truncated: value.truncated,
      quickPaths: Array.isArray(value.quick_paths)
        ? value.quick_paths.map((quickPath) => ({
            displayName: quickPath.display_name,
            path: quickPath.path ?? '',
            isSeparator: quickPath.is_separator === true,
          }))
        : [],
    };
  }
  if (value.type === 'sftp.local.error') {
    if (
      !isSftpRequestId(value.request_id) ||
      value.pane !== 'local' ||
      typeof value.error !== 'string' ||
      (value.path !== undefined && !isLocalSftpPath(value.path, true))
    ) {
      return undefined;
    }
    return {
      type: 'sftp.local.error',
      sessionId: value.session_id,
      requestId: value.request_id,
      pane: 'local',
      path: value.path,
      error: value.error.slice(0, sshMaxSftpErrorLength),
    };
  }
  if (value.type === 'sftp.operation') {
    if (
      !isSftpRequestId(value.request_id) ||
      !isSftpPane(value.pane) ||
      !isSftpOperation(value.operation) ||
      typeof value.path !== 'string' ||
      (value.pane === 'local' ? !isLocalSftpPath(value.path) : !isSftpPath(value.path)) ||
      (value.error !== undefined && typeof value.error !== 'string')
    ) {
      return undefined;
    }
    return {
      type: 'sftp.operation',
      sessionId: value.session_id,
      requestId: value.request_id,
      pane: value.pane,
      operation: value.operation,
      path: value.path,
      error:
        typeof value.error === 'string' ? value.error.slice(0, sshMaxSftpErrorLength) : undefined,
    };
  }
  if (value.type === 'sftp.conflict') {
    if (
      !isSftpTransferId(value.transfer_id) ||
      !isSftpRequestId(value.item_id) ||
      !isSftpTransferDirection(value.direction) ||
      typeof value.display_name !== 'string' ||
      value.display_name.length === 0 ||
      value.display_name.length > sshMaxSftpEntryNameLength * 2 ||
      typeof value.path !== 'string' ||
      (value.direction === 'local-to-remote'
        ? !isSftpPath(value.path)
        : !isLocalSftpPath(value.path)) ||
      typeof value.incoming_size !== 'number' ||
      !Number.isSafeInteger(value.incoming_size) ||
      value.incoming_size < 0 ||
      typeof value.existing_size !== 'number' ||
      !Number.isSafeInteger(value.existing_size) ||
      value.existing_size < 0 ||
      typeof value.existing_is_directory !== 'boolean'
    ) {
      return undefined;
    }
    return {
      type: 'sftp.conflict',
      sessionId: value.session_id,
      transferId: value.transfer_id,
      itemId: value.item_id,
      direction: value.direction,
      displayName: value.display_name,
      path: value.path,
      incomingSize: value.incoming_size,
      existingSize: value.existing_size,
      existingIsDirectory: value.existing_is_directory,
    };
  }
  if (value.type === 'sftp.transfer') {
    const states = [
      'running',
      'progress',
      'completed',
      'failed',
      'cancelled',
      'batch-failed',
      'batch-completed',
      'batch-cancelled',
    ];
    if (
      !isSftpTransferId(value.transfer_id) ||
      typeof value.transfer_state !== 'string' ||
      !states.includes(value.transfer_state) ||
      (value.item_id !== undefined && !isSftpRequestId(value.item_id)) ||
      (value.direction !== undefined && !isSftpTransferDirection(value.direction)) ||
      (value.display_name !== undefined &&
        (typeof value.display_name !== 'string' ||
          value.display_name.length > sshMaxSftpEntryNameLength * 2)) ||
      (value.expected_bytes !== undefined &&
        (typeof value.expected_bytes !== 'number' ||
          !Number.isSafeInteger(value.expected_bytes) ||
          value.expected_bytes < 0)) ||
      (value.bytes_transferred !== undefined &&
        (typeof value.bytes_transferred !== 'number' ||
          !Number.isSafeInteger(value.bytes_transferred) ||
          value.bytes_transferred < 0)) ||
      (value.error !== undefined && typeof value.error !== 'string')
    ) {
      return undefined;
    }
    return {
      type: 'sftp.transfer',
      sessionId: value.session_id,
      transferId: value.transfer_id,
      itemId: value.item_id,
      transferState: value.transfer_state as SshSftpTransferState,
      direction: value.direction as SshSftpTransferDirection | undefined,
      displayName: value.display_name,
      expectedBytes: value.expected_bytes,
      bytesTransferred: value.bytes_transferred,
      error:
        typeof value.error === 'string' ? value.error.slice(0, sshMaxSftpErrorLength) : undefined,
    };
  }
  if (value.type === 'sftp.error' && typeof value.error === 'string') {
    if (value.request_id !== undefined && !isSftpRequestId(value.request_id)) {
      return undefined;
    }
    return {
      type: 'sftp.error',
      sessionId: value.session_id,
      error: value.error.slice(0, sshMaxSftpErrorLength),
      path: isSftpPath(value.path) ? value.path : undefined,
      requestId: isSftpRequestId(value.request_id) ? value.request_id : undefined,
    };
  }
  if (value.type === 'error' && typeof value.error === 'string') {
    const hostKeyExpected = isSshFingerprint(value.host_key_expected)
      ? value.host_key_expected
      : undefined;
    const hostKeyReceived = isSshFingerprint(value.host_key_received)
      ? value.host_key_received
      : undefined;
    return {
      type: 'error',
      sessionId: value.session_id,
      error: value.error,
      hostKeyExpected,
      hostKeyReceived,
    };
  }
  return undefined;
}

function parseMcpBackendMessage(line: string): McpControlResponse | McpApprovalEvent | undefined {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return undefined;
  }
  if (!isRecord(value) || typeof value.type !== 'string') return undefined;

  if (value.type === 'mcp.response' && typeof value.request_id === 'string') {
    const response: McpControlResponse = {
      type: 'mcp.response',
      requestId: value.request_id,
      error: typeof value.error === 'string' ? value.error : undefined,
      token: typeof value.token === 'string' ? value.token : undefined,
    };
    const rawStatus = value.mcp_status;
    if (isRecord(rawStatus)) {
      if (
        typeof rawStatus.enabled !== 'boolean' ||
        typeof rawStatus.running !== 'boolean' ||
        typeof rawStatus.port !== 'number' ||
        !Number.isInteger(rawStatus.port) ||
        rawStatus.port < 1 ||
        rawStatus.port > 65535 ||
        typeof rawStatus.endpoint !== 'string' ||
        rawStatus.endpoint.length > 512
      ) {
        return undefined;
      }
      response.status = {
        enabled: rawStatus.enabled,
        running: rawStatus.running,
        port: rawStatus.port,
        endpoint: rawStatus.endpoint,
      };
    }
    return response;
  }

  if (
    value.type === 'mcp.approval' &&
    typeof value.request_id === 'string' &&
    isSshSessionId(value.session_id) &&
    typeof value.host === 'string' &&
    value.host.length <= 1024 &&
    typeof value.port === 'number' &&
    Number.isInteger(value.port) &&
    value.port > 0 &&
    value.port <= 65535 &&
    typeof value.username === 'string' &&
    value.username.length <= 1024 &&
    typeof value.title === 'string' &&
    value.title.length <= 2048 &&
    typeof value.tool === 'string' &&
    value.tool.length <= 128
  ) {
    return {
      type: 'mcp.approval',
      requestId: value.request_id,
      sessionId: value.session_id,
      host: value.host,
      port: value.port,
      username: value.username,
      title: value.title,
      tool: value.tool,
    };
  }
  return undefined;
}

type TunnelBrowserEvent = {
  sessionId: string;
  promptId: string;
  title: string;
  urls: string[];
  ignoreCertificateErrors: boolean;
  completion: 'query-token' | 'oauth-code' | 'cookie';
  redirectPrefix?: string;
  expectedState?: string;
  cookieName?: string;
  requireHttpOnly?: boolean;
};

function parseTunnelBrowserEvent(value: object): TunnelBrowserEvent | undefined {
  if (
    !('sessionId' in value) ||
    !('promptId' in value) ||
    !('title' in value) ||
    !('urls' in value)
  ) {
    return undefined;
  }
  const sessionId = value.sessionId;
  const promptId = value.promptId;
  const title = value.title;
  const urls = value.urls;
  const ignoreCertificateErrors =
    'ignoreCertificateErrors' in value && value.ignoreCertificateErrors === true;
  const completion = 'completion' in value ? value.completion : undefined;
  const redirectPrefix = 'redirectPrefix' in value ? value.redirectPrefix : undefined;
  const expectedState = 'expectedState' in value ? value.expectedState : undefined;
  const cookieName = 'cookieName' in value ? value.cookieName : undefined;
  const requireHttpOnly = 'requireHttpOnly' in value && value.requireHttpOnly === true;
  if (
    typeof sessionId !== 'string' ||
    sessionId.length === 0 ||
    sessionId.length > 128 ||
    typeof promptId !== 'string' ||
    promptId.length === 0 ||
    promptId.length > 128 ||
    typeof title !== 'string' ||
    title.length === 0 ||
    title.length > 256 ||
    !Array.isArray(urls) ||
    urls.length === 0 ||
    urls.length > 5 ||
    !urls.every((url) => typeof url === 'string' && url.length <= 4096) ||
    (completion !== 'query-token' && completion !== 'oauth-code' && completion !== 'cookie') ||
    (completion === 'oauth-code' &&
      (typeof redirectPrefix !== 'string' ||
        redirectPrefix !== 'http://localhost:2023' ||
        typeof expectedState !== 'string' ||
        expectedState.length < 16 ||
        expectedState.length > 256)) ||
    (completion === 'cookie' &&
      (typeof cookieName !== 'string' || cookieName.length === 0 || cookieName.length > 256))
  ) {
    return undefined;
  }
  try {
    const parsed = urls.map((url) => new URL(url));
    if (parsed.some((url) => url.protocol !== 'https:' || url.username || url.password)) {
      return undefined;
    }
    if (parsed.some((url) => url.origin !== parsed[0].origin)) return undefined;
  } catch {
    return undefined;
  }
  return {
    sessionId,
    promptId,
    title,
    urls,
    ignoreCertificateErrors,
    completion,
    redirectPrefix: typeof redirectPrefix === 'string' ? redirectPrefix : undefined,
    expectedState: typeof expectedState === 'string' ? expectedState : undefined,
    cookieName: typeof cookieName === 'string' ? cookieName : undefined,
    requireHttpOnly,
  };
}

let tunnelBrowserAuthQueue: Promise<void> = Promise.resolve();

function enqueueTunnelBrowserAuth(backend: NativeBackendProcess, event: TunnelBrowserEvent): void {
  tunnelBrowserAuthQueue = tunnelBrowserAuthQueue
    .catch(() => undefined)
    .then(() => runTunnelBrowserAuth(backend, event));
}

async function runTunnelBrowserAuth(
  backend: NativeBackendProcess,
  event: TunnelBrowserEvent,
): Promise<void> {
  if (!authSession.isAccessAllowed || isQuitting) {
    await backend
      .respondTunnelPrompt({
        leaseId: event.sessionId,
        promptId: event.promptId,
        value: '',
        cancelled: true,
      })
      .catch(() => undefined);
    return;
  }
  const initialURLs = event.urls.map((value) => new URL(value));
  const fireboxOrigin = initialURLs[0].origin;
  const cookieScopeURL = initialURLs[0].toString();
  const fireboxHost = initialURLs[0].hostname;
  const partition = `wormhole-tunnel-auth-${randomUUID()}`;
  const browserSession = electronSession.fromPartition(partition, { cache: false });
  browserSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  browserSession.setPermissionCheckHandler(() => false);
  if (event.ignoreCertificateErrors) {
    browserSession.setCertificateVerifyProc((request, callback) => {
      callback(request.hostname === fireboxHost ? 0 : -3);
    });
  }
  const parent = BrowserWindow.getFocusedWindow() ?? BrowserWindow.getAllWindows()[0];
  const authWindow = new BrowserWindow({
    width: 900,
    height: 700,
    minWidth: 640,
    minHeight: 480,
    title: event.title,
    parent: parent && !parent.isDestroyed() ? parent : undefined,
    modal: Boolean(parent && !parent.isDestroyed()),
    show: false,
    autoHideMenuBar: true,
    webPreferences: {
      partition,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      devTools: false,
    },
  });
  let candidate = 0;
  let settled = false;
  let authTimeout: NodeJS.Timeout | undefined;
  let finish!: () => void;
  const finished = new Promise<void>((resolve) => {
    finish = resolve;
  });
  const complete = async (cancelled: boolean, value = '') => {
    if (settled) return;
    settled = true;
    if (authTimeout) clearTimeout(authTimeout);
    if (!authWindow.isDestroyed()) authWindow.destroy();
    try {
      await backend
        .respondTunnelPrompt({
          leaseId: event.sessionId,
          promptId: event.promptId,
          value,
          cancelled,
        })
        .catch(() => undefined);
    } finally {
      finish();
    }
  };
  authTimeout = setTimeout(() => void complete(true), nativeConnectionTimeoutMs - 5_000);
  const matchesOAuthRedirect = (current: URL) =>
    event.completion === 'oauth-code' && isMatchingOAuthRedirect(current, event.redirectPrefix!);
  const inspectNavigation = async (rawURL: string) => {
    if (settled) return;
    let current: URL;
    try {
      current = new URL(rawURL);
    } catch {
      return;
    }
    if (event.completion === 'oauth-code') {
      if (!matchesOAuthRedirect(current)) return;
      const state = current.searchParams.get('state') ?? '';
      const code = current.searchParams.get('code') ?? '';
      const oauthError = current.searchParams.get('error') ?? '';
      const description = current.searchParams.get('error_description') ?? '';
      const value = JSON.stringify({ code, state, error: oauthError, description });
      await complete(false, value);
      return;
    }
    if (current.origin !== fireboxOrigin) return;
    const username = current.searchParams.get('user')?.trim() ?? '';
    const token = current.searchParams.get('token') ?? '';
    if (!username || !token || username.length > 1024 || token.length > 16 * 1024) return;
    const cookies = await browserSession.cookies.get({ url: cookieScopeURL });
    const value = JSON.stringify({
      username,
      token,
      cookies: cookies.slice(0, 256).map((cookie) => ({
        name: cookie.name,
        value: cookie.value,
        path: cookie.path || '/',
        domain: cookie.domain,
        secure: cookie.secure,
        httpOnly: cookie.httpOnly,
      })),
    });
    if (Buffer.byteLength(value, 'utf8') > 16 * 1024) {
      await complete(true);
      return;
    }
    await complete(false, value);
  };
  const inspectCookie = async () => {
    if (settled || event.completion !== 'cookie') return;
    const cookies = await browserSession.cookies.get({ url: cookieScopeURL });
    const cookie = cookies.find(
      (candidate) =>
        candidate.name === event.cookieName &&
        candidate.value &&
        (!event.requireHttpOnly || candidate.httpOnly),
    );
    if (cookie) await complete(false, cookie.value);
  };
  authWindow.webContents.setWindowOpenHandler(({ url }) => {
    try {
      const target = new URL(url);
      if (matchesOAuthRedirect(target)) {
        void inspectNavigation(url);
        return { action: 'deny' };
      }
      if (target.protocol === 'https:' && !target.username && !target.password) {
        void authWindow.loadURL(target.toString()).catch(() => undefined);
      }
    } catch {
      // Keep malformed and non-web popup targets outside the privileged auth session.
    }
    return { action: 'deny' };
  });
  authWindow.webContents.on('did-navigate', (_event, url) => void inspectNavigation(url));
  authWindow.webContents.on('did-navigate-in-page', (_event, url) => void inspectNavigation(url));
  authWindow.webContents.on('will-navigate', (navigationEvent, url) => {
    if (event.completion === 'oauth-code') {
      try {
        if (matchesOAuthRedirect(new URL(url))) {
          navigationEvent.preventDefault();
          void inspectNavigation(url);
        }
      } catch {
        // Chromium handles malformed navigation attempts as ordinary load failures.
      }
    }
  });
  authWindow.webContents.on('did-fail-load', (_event, _code, _description, _url, isMainFrame) => {
    if (!isMainFrame || settled) return;
    candidate++;
    if (candidate < event.urls.length) {
      void authWindow.loadURL(event.urls[candidate]).catch(() => undefined);
    } else {
      void complete(true);
    }
  });
  authWindow.once('closed', () => void complete(true));
  authWindow.once('ready-to-show', () => authWindow.show());
  const cookieTimer =
    event.completion === 'cookie' ? setInterval(() => void inspectCookie(), 250) : undefined;
  authWindow.once('closed', () => {
    if (cookieTimer) clearInterval(cookieTimer);
  });
  await browserSession.cookies
    .get({ url: cookieScopeURL })
    .then((cookies) =>
      Promise.all(
        cookies
          .filter((cookie) => event.completion === 'cookie' && cookie.name === event.cookieName)
          .map((cookie) => browserSession.cookies.remove(cookieScopeURL, cookie.name)),
      ),
    )
    .catch(() => undefined);
  await authWindow.loadURL(event.urls[0]).catch(() => complete(true));
  await finished;
}

class NativeBackendProcess {
  private child: ReturnType<typeof spawn> | undefined;
  private startPromise: Promise<void> | undefined;
  private outputBuffer = '';
  private requestSequence = 0;
  private readonly pending = new Map<
    string,
    { resolve: (response: BackendResponse) => void; reject: (error: Error) => void }
  >();

  async send(
    command: VncCommand,
    timeoutMs = nativeBackendCommandTimeoutMs,
  ): Promise<BackendResponse> {
    await this.start();
    const child = this.child;
    if (!child?.stdin || child.stdin.destroyed) {
      throw new Error('Native backend is not available.');
    }

    const id = `electron-${++this.requestSequence}`;
    const payload = JSON.stringify({ id, ...command }) + '\n';
    const response = new Promise<BackendResponse>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
    });
    try {
      child.stdin.write(payload);
    } catch (error) {
      this.pending.delete(id);
      throw error instanceof Error ? error : new Error(String(error));
    }

    const timeout = setTimeout(() => {
      const pending = this.pending.get(id);
      if (!pending) return;
      this.pending.delete(id);
      pending.reject(new Error('Native backend command timed out.'));
    }, timeoutMs);

    return response.finally(() => clearTimeout(timeout));
  }

  async acquireTunnel(request: {
    leaseId: string;
    nodeId?: string;
    tunnelConfigId?: string;
    progressSessionId?: string;
  }): Promise<string> {
    const response = await this.send(
      {
        action: 'tunnel.acquire',
        sessionId: request.leaseId,
        nodeId: request.nodeId,
        tunnelConfigId: request.tunnelConfigId,
        progressSessionId: request.progressSessionId,
      },
      tunnelTestTimeoutMs,
    );
    if (!response.ok) throw new Error(response.error || 'Could not establish the VPN tunnel.');
    return response.socksEndpoint ?? '';
  }

  async releaseTunnel(leaseId: string): Promise<void> {
    const response = await this.send({ action: 'tunnel.release', sessionId: leaseId });
    if (!response.ok) throw new Error(response.error || 'Could not release the VPN tunnel.');
  }

  async respondTunnelPrompt(request: {
    leaseId: string;
    promptId: string;
    value: string;
    cancelled: boolean;
  }): Promise<void> {
    const response = await this.send({
      action: 'tunnel.prompt-response',
      sessionId: request.leaseId,
      promptId: request.promptId,
      value: request.value,
      cancelled: request.cancelled,
    });
    if (!response.ok) throw new Error(response.error || 'Could not answer the VPN prompt.');
  }

  async respondTunnelRoute(request: {
    leaseId: string;
    promptId: string;
    value: 'tunnel' | 'direct' | 'cancel';
  }): Promise<void> {
    const response = await this.send({
      action: 'tunnel.route-response',
      sessionId: request.leaseId,
      promptId: request.promptId,
      value: request.value,
    });
    if (!response.ok) throw new Error(response.error || 'Could not answer the VPN prompt.');
  }

  stop(): void {
    const child = this.child;
    this.child = undefined;
    this.outputBuffer = '';
    if (!child) return;

    const error = new Error('Native backend stopped.');
    for (const pending of this.pending.values()) pending.reject(error);
    this.pending.clear();
    child.stdin?.end();
    const forceKill = setTimeout(() => {
      if (!child.killed) child.kill();
    }, 7_000);
    child.once('close', () => clearTimeout(forceKill));
  }

  private async start(): Promise<void> {
    if (this.child) return;
    if (this.startPromise) return this.startPromise;

    this.startPromise = new Promise<void>((resolve, reject) => {
      let settled = false;
      const child = spawn(
        backendPath(),
        [
          '--operation',
          'serve',
          '--database',
          wormholeDatabasePath(),
          '--electron-user-data',
          electronUserDataPath(),
        ],
        { windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'] },
      );
      this.child = child;
      child.stdout?.setEncoding('utf8');
      child.stdout?.on('data', (chunk: string | Buffer) => this.readOutput(String(chunk)));
      child.stdout?.once('error', (error) => {
        this.rejectAll(error instanceof Error ? error : new Error(String(error)));
        this.stop();
      });
      child.stdin?.once('error', (error) => {
        this.rejectAll(error instanceof Error ? error : new Error(String(error)));
      });
      child.once('spawn', () => {
        settled = true;
        resolve();
      });
      child.once('error', (error) => {
        this.child = undefined;
        this.rejectAll(error instanceof Error ? error : new Error(String(error)));
        if (!settled) reject(error instanceof Error ? error : new Error(String(error)));
      });
      child.once('close', (code) => {
        this.child = undefined;
        this.outputBuffer = '';
        const error = new Error(
          code === null ? 'Native backend stopped.' : `Native backend exited (${code}).`,
        );
        this.rejectAll(error);
        if (!settled) reject(error);
      });
    }).finally(() => {
      this.startPromise = undefined;
    });

    return this.startPromise;
  }

  private readOutput(chunk: string): void {
    this.outputBuffer += chunk;
    if (this.outputBuffer.length > nativeBackendLineLimit) {
      this.stop();
      return;
    }

    while (true) {
      const newline = this.outputBuffer.indexOf('\n');
      if (newline < 0) return;
      const line = this.outputBuffer.slice(0, newline).trim();
      this.outputBuffer = this.outputBuffer.slice(newline + 1);
      if (!line) continue;

      let message: unknown;
      try {
        message = JSON.parse(line);
      } catch {
        continue;
      }
      if (!message || typeof message !== 'object') continue;
      if ('id' in message && typeof message.id === 'string') {
        const pending = this.pending.get(message.id);
        if (pending) {
          this.pending.delete(message.id);
          pending.resolve(message as BackendResponse);
        }
        continue;
      }
      if ('type' in message && typeof message.type === 'string') {
        if (message.type === 'tunnel.browser') {
          const event = parseTunnelBrowserEvent(message);
          if (event) enqueueTunnelBrowserAuth(this, event);
          continue;
        }
        if (!authSession.isAccessAllowed) continue;
        for (const window of BrowserWindow.getAllWindows()) {
          if (window.isDestroyed()) continue;
          try {
            window.webContents.send('backend:event', message as BackendEvent);
          } catch {
            // The window may be destroyed between isDestroyed() and send().
          }
        }
      }
    }
  }

  private rejectAll(error: Error): void {
    for (const pending of this.pending.values()) pending.reject(error);
    this.pending.clear();
  }
}

let nativeBackend: NativeBackendProcess | undefined;
let isQuitting = false;

function getNativeBackend(): NativeBackendProcess {
  nativeBackend ??= new NativeBackendProcess();
  return nativeBackend;
}

function parseVncCommand(value: unknown): VncCommand {
  if (!value || typeof value !== 'object') throw new Error('Invalid VNC command.');
  const input = value as Record<string, unknown>;
  const action = input.action;
  const sessionId = input.sessionId;
  if (
    (action !== 'vnc.connect' &&
      action !== 'vnc.disconnect' &&
      action !== 'vnc.pointer' &&
      action !== 'vnc.key') ||
    typeof sessionId !== 'string' ||
    sessionId.length === 0 ||
    sessionId.length > 128
  ) {
    throw new Error('Invalid VNC command.');
  }

  const command: VncCommand = { action, sessionId };
  const stringField = (name: string, maxLength: number): string | undefined => {
    const field = input[name];
    if (field === undefined) return undefined;
    if (typeof field !== 'string' || field.length > maxLength)
      throw new Error(`Invalid VNC ${name}.`);
    return field;
  };
  const numberField = (name: string, max: number): number | undefined => {
    const field = input[name];
    if (field === undefined) return undefined;
    if (typeof field !== 'number' || !Number.isInteger(field) || field < 0 || field > max) {
      throw new Error(`Invalid VNC ${name}.`);
    }
    return field;
  };

  if (action === 'vnc.connect') {
    command.nodeId = stringField('nodeId', 128);
    command.credentialId = stringField('credentialId', 128);
    command.host = stringField('host', 1024);
    command.password = stringField('password', 16 * 1024);
    command.port = numberField('port', 65535);
    return command;
  }
  if (action === 'vnc.pointer') {
    command.x = numberField('x', 65535);
    command.y = numberField('y', 65535);
    command.buttons = numberField('buttons', 255);
    if (command.x === undefined || command.y === undefined || command.buttons === undefined) {
      throw new Error('Invalid VNC pointer command.');
    }
    return command;
  }
  if (action === 'vnc.key') {
    command.keysym = numberField('keysym', 0xffffffff);
    if (typeof input.down !== 'boolean' || command.keysym === undefined || command.keysym === 0) {
      throw new Error('Invalid VNC key command.');
    }
    command.down = input.down;
  }
  return command;
}

function isWorkspaceNodeTunnelSettingsRequest(
  value: unknown,
): value is WorkspaceNodeTunnelSettingsRequest {
  return (
    isRecord(value) &&
    isSshSessionId(value.nodeId) &&
    (value.tunnelEnabled === null || typeof value.tunnelEnabled === 'boolean') &&
    typeof value.tunnelConfigId === 'string' &&
    (value.tunnelConfigId === '' || isTunnelID(value.tunnelConfigId))
  );
}

function isTunnelID(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)
  );
}

function isTunnelSettings(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function parseTunnelWriteRequest(value: unknown, requiresID: boolean): TunnelWriteRequest {
  if (!value || typeof value !== 'object') throw new Error('VPN tunnel settings are invalid.');
  const input = value as Record<string, unknown>;
  if (
    typeof input.name !== 'string' ||
    input.name.trim().length === 0 ||
    input.name.length > 128 ||
    typeof input.kind !== 'number' ||
    !Number.isInteger(input.kind) ||
    input.kind < 0 ||
    input.kind > 6 ||
    !isTunnelSettings(input.settings)
  ) {
    throw new Error('VPN tunnel settings are invalid.');
  }
  if (requiresID && !isTunnelID(input.id)) throw new Error('VPN tunnel id is invalid.');
  return {
    ...(isTunnelID(input.id) ? { id: input.id } : {}),
    name: input.name,
    kind: input.kind,
    settings: input.settings,
  };
}

function parseTunnelIDRequest(value: unknown): TunnelReadRequest {
  if (!value || typeof value !== 'object' || !isTunnelID((value as Record<string, unknown>).id)) {
    throw new Error('VPN tunnel id is invalid.');
  }
  return { id: (value as Record<string, string>).id };
}

function wormholeDatabasePath(): string {
  const configured = process.env.WORMHOLE_DATABASE?.trim();
  if (configured) return configured;

  const localAppData = process.env.LOCALAPPDATA;
  if (localAppData) return path.join(localAppData, wormholeDataDirectoryName, 'wormhole.db');

  // Linux/macOS do not have the Windows compatibility root. The Electron user-data directory
  // is deliberately kept separate from the renderer profile, while still giving the Go backend
  // one stable location for future cross-platform persistence.
  return path.join(app.getPath('userData'), wormholeDataDirectoryName, 'wormhole.db');
}

function electronUserDataPath(): string {
  return app.getPath('userData');
}

function findBundledExecutable(name: string): string | undefined {
  const candidates = [
    path.join(process.resourcesPath, name),
    path.join(__dirname, name),
    path.join(__dirname, '..', name),
  ];
  return candidates.find((candidate) => existsSync(candidate));
}

function backendPath(): string {
  const architecture = process.arch === 'arm64' ? 'arm64' : 'x64';
  const executableName = `wormhole-backend-${architecture}${process.platform === 'win32' ? '.exe' : ''}`;
  const executablePath = findBundledExecutable(executableName);
  if (!executablePath) {
    throw new Error(`Electron Go backend is missing (${executableName}).`);
  }
  return executablePath;
}

function nativeRdpHostPath(): string | undefined {
  if (process.platform !== 'win32') return undefined;
  const architecture = process.arch === 'arm64' ? 'arm64' : 'x64';
  return findBundledExecutable(`wormhole-rdp-host-${architecture}.exe`);
}

function credentialReaderPath(): string | undefined {
  const architecture = process.arch === 'arm64' ? 'arm64' : 'x64';
  return findBundledExecutable(`wormhole-credential-reader-${architecture}.exe`);
}

async function runBackend<T>(operation: BackendOperation, request?: unknown): Promise<T> {
  const args = [
    '--operation',
    operation,
    '--database',
    wormholeDatabasePath(),
    '--electron-user-data',
    electronUserDataPath(),
  ];
  if (operation === 'migrate') {
    const reader = credentialReaderPath();
    if (reader) args.push('--credential-reader', reader);
  }
  let requestPayload: string | undefined;
  if (request !== undefined) {
    requestPayload = JSON.stringify(request);
    const requestLimit = operation.startsWith('tunnel-')
      ? backendMaxTunnelRequestBytes
      : backendMaxRequestBytes;
    if (requestPayload === undefined || Buffer.byteLength(requestPayload, 'utf8') > requestLimit) {
      throw new Error('Electron Go backend request is too large.');
    }
  }

  const child = spawn(backendPath(), args, {
    stdio: 'pipe',
    windowsHide: true,
  });

  const output = await new Promise<string>((resolve, reject) => {
    let stdout = '';
    let stdoutBytes = 0;
    let stderr = '';
    let settled = false;
    const timeout = setTimeout(() => {
      child.kill();
      finishReject(new Error('Electron Go backend timed out.'));
    }, backendTimeoutMs);

    function finishReject(error: Error) {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      reject(error);
    }

    child.stdout?.setEncoding('utf8');
    child.stderr?.setEncoding('utf8');
    child.stdout?.on('data', (chunk: string) => {
      stdout += chunk;
      stdoutBytes += Buffer.byteLength(chunk, 'utf8');
      if (stdoutBytes > backendMaxBuffer) {
        child.kill();
        finishReject(new Error('Electron Go backend returned too much data.'));
      }
    });
    child.stderr?.on('data', (chunk: string) => {
      stderr += chunk;
      if (stderr.length > backendMaxBuffer) stderr = stderr.slice(-backendMaxBuffer);
    });
    child.on('error', (error) => finishReject(error));
    child.stdin?.on('error', (error) => finishReject(error));
    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (code !== 0) {
        reject(new Error(stderr.trim() || 'Electron Go backend failed.'));
        return;
      }
      resolve(stdout);
    });

    if (requestPayload === undefined) {
      child.stdin?.end();
    } else {
      child.stdin?.end(requestPayload);
    }
  });

  try {
    return JSON.parse(output) as T;
  } catch {
    throw new Error('Electron Go backend returned invalid data.');
  }
}

// ---- update checks / downloads ----

// performUpdateCheck keeps a single in-flight check: a startup check and a user-triggered
// "Check now" coalesce into one GitHub round-trip instead of two concurrent backend processes.
function performUpdateCheck(): Promise<UpdateCheckResult> {
  if (!updateCheckInFlight) {
    updateCheckInFlight = runBackend<UpdateCheckResult>('update-check', {
      currentVersion: app.getVersion(),
    })
      .then((result) => {
        latestUpdateCheck = result;
        broadcastUpdateResult(result);
        return result;
      })
      .finally(() => {
        updateCheckInFlight = undefined;
      });
  }
  return updateCheckInFlight;
}

function broadcastUpdateResult(result: UpdateCheckResult): void {
  for (const window of BrowserWindow.getAllWindows()) {
    if (!window.isDestroyed()) window.webContents.send('update:result', result);
  }
}

function broadcastUpdateProgress(
  target: Electron.WebContents,
  downloaded: number,
  total: number,
): void {
  if (target.isDestroyed()) return;
  target.send('update:progress', { downloaded, total });
}

function updateCacheRoot(): string {
  return path.join(path.dirname(wormholeDatabasePath()), 'cache', 'updates');
}

function isSafeInstallerPath(value: string): boolean {
  const installerPath = path.resolve(value);
  const cacheRoot = path.resolve(updateCacheRoot());
  return (
    path.extname(installerPath).toLowerCase() === '.exe' &&
    (installerPath === cacheRoot || installerPath.startsWith(cacheRoot + path.sep))
  );
}

// downloadUpdateInstaller runs a dedicated backend process that streams the installer to the
// update cache. The backend reports {"type":"progress",...} JSON lines and finishes with
// {"type":"complete","path":...}; the final path resolves this promise. The 30s runBackend
// timeout would kill a large installer on a slow connection, so this spawn deliberately bypasses
// it (matching the WinUI download client's long timeout).
function downloadUpdateInstaller(
  request: UpdateDownloadRequest,
  onProgress: (downloaded: number, total: number) => void,
): Promise<string> {
  if (updateDownloadChild) {
    return Promise.reject(new Error('An update download is already in progress.'));
  }
  const child = spawn(
    backendPath(),
    [
      '--operation',
      'update-download',
      '--database',
      wormholeDatabasePath(),
      '--electron-user-data',
      electronUserDataPath(),
    ],
    { stdio: 'pipe', windowsHide: true },
  );
  updateDownloadChild = child;
  const cleanup = () => {
    if (updateDownloadChild === child) updateDownloadChild = undefined;
  };

  return new Promise<string>((resolve, reject) => {
    let stdoutBytes = 0;
    let stderr = '';
    let settled = false;
    const lineReader = createInterface({ input: child.stdout!, crlfDelay: Infinity });

    function finishResolve(path: string) {
      if (settled) return;
      settled = true;
      cleanup();
      lineReader.close();
      resolve(path);
    }

    function finishReject(error: Error) {
      if (settled) return;
      settled = true;
      cleanup();
      lineReader.close();
      reject(error);
    }

    child.stderr?.setEncoding('utf8');
    child.stderr?.on('data', (chunk: string) => {
      stderr += chunk;
      if (stderr.length > backendMaxBuffer) stderr = stderr.slice(-backendMaxBuffer);
    });
    child.on('error', (error) => finishReject(error));
    child.on('close', (code) => {
      if (settled) return;
      if (code !== 0) {
        finishReject(new Error(stderr.trim() || 'The installer download failed.'));
        return;
      }
      finishReject(new Error('The installer download ended before completing.'));
    });

    lineReader.on('line', (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      stdoutBytes += Buffer.byteLength(trimmed, 'utf8');
      if (stdoutBytes > backendMaxBuffer) {
        child.kill();
        finishReject(new Error('The installer download returned too much data.'));
        return;
      }
      let message: unknown;
      try {
        message = JSON.parse(trimmed);
      } catch {
        return;
      }
      if (!isRecord(message)) return;
      if (
        message.type === 'progress' &&
        typeof message.downloaded === 'number' &&
        typeof message.total === 'number'
      ) {
        onProgress(message.downloaded, message.total);
        return;
      }
      if (message.type === 'complete' && typeof message.path === 'string') {
        finishResolve(message.path);
      }
    });

    child.stdin?.end(JSON.stringify(request));
  });
}

function launchInstallerAndExit(installerPath: string): void {
  // Detached + unref so the Inno Setup process survives this app's immediate exit, exactly like
  // the WinUI app's Process.Start + Environment.Exit(0). /RESTARTAPP is handled by the installer
  // script, which relaunches the newly installed app when present.
  const child = spawn(installerPath, ['/SILENT', '/RESTARTAPP'], {
    detached: true,
    stdio: 'ignore',
    windowsHide: true,
  });
  child.unref();
  app.quit();
}

async function runStartupUpdateCheck(): Promise<void> {
  try {
    const settings = await runBackend<AppSettings>('settings-read');
    if (!settings.autoCheckForUpdates) return;
    await performUpdateCheck();
  } catch (error) {
    // A failed startup check must never block the app: the settings page still exposes
    // "Check now", and a later result arrives through the update:result event.
    const message = error instanceof Error ? error.message : String(error);
    console.warn('[Wormhole] Startup update check failed.', message);
  }
}

async function runUserDeletion<T extends { deleted: boolean }>(
  operation: BackendOperation,
  request: { id: string },
  what: string,
): Promise<T | { deleted: false; error: string }> {
  try {
    const result = await runBackend<T>(operation, request);
    console.info(`[Wormhole] Deleted ${what}.`, request.id);
    return result;
  } catch (error) {
    // A refused or already-missing item is a normal user outcome, not an app error.
    const message = error instanceof Error ? error.message : String(error);
    console.info(`[Wormhole] ${what} deletion was not performed (${request.id}): ${message}`);
    return { deleted: false, error: message };
  }
}

function isWorkspaceNodeWebSettingsRequest(
  value: unknown,
): value is WorkspaceNodeWebSettingsRequest {
  return (
    isRecord(value) &&
    isSshSessionId(value.nodeId) &&
    (value.httpIgnoreCertErrors === null || typeof value.httpIgnoreCertErrors === 'boolean')
  );
}

type WebSurfaceRecord = {
  owner: BrowserWindow;
  view: WebContentsView;
  attempt: number;
  initialNavigationPending: boolean;
  disposed: boolean;
  tunnelLeaseId?: string;
};

function validateWebTarget(value: WebTargetResponse): WebTargetResponse {
  if (
    !value ||
    typeof value.url !== 'string' ||
    (value.protocol !== 'http' && value.protocol !== 'https') ||
    typeof value.host !== 'string' ||
    !Number.isInteger(value.port) ||
    value.port < 1 ||
    value.port > 65535 ||
    typeof value.ignoreCertErrors !== 'boolean' ||
    (value.tunnelConfigId !== undefined && !isTunnelID(value.tunnelConfigId)) ||
    value.proxyUrl !== undefined
  ) {
    throw new Error('Electron Go backend returned an invalid web target.');
  }
  const targetUrl = new URL(value.url);
  if (
    targetUrl.protocol !== `${value.protocol}:` ||
    targetUrl.hostname !== value.host ||
    targetUrl.username ||
    targetUrl.password
  ) {
    throw new Error('Electron Go backend returned an invalid web target.');
  }
  return value;
}

class WebSurfaceManager {
  private readonly surfaces = new Map<string, WebSurfaceRecord>();
  private readonly pendingOpenOwners = new Map<string, BrowserWindow>();
  private readonly attempts = new WebSessionAttemptTracker();
  private isolatedPartitionSequence = 0;

  async open(owner: BrowserWindow, request: WebOpenRequest): Promise<WebTargetResponse> {
    const generation = this.attempts.begin(request.sessionId);
    this.pendingOpenOwners.set(request.sessionId, owner);
    this.dispose(request.sessionId);
    let openingLeaseId: string | undefined;
    try {
      const target = validateWebTarget(
        await runBackend<WebTargetResponse>('web-target', {
          nodeId: request.nodeId,
          address: request.address,
          protocol: request.protocol,
          ignoreCertErrors: request.ignoreCertErrors,
        }),
      );
      if (target.tunnelConfigId) {
        const leaseId = randomUUID();
        openingLeaseId = leaseId;
        const socksEndpoint = await getNativeBackend().acquireTunnel({
          leaseId,
          nodeId: request.nodeId,
          tunnelConfigId: target.tunnelConfigId,
          progressSessionId: request.sessionId,
        });
        if (socksEndpoint) target.proxyUrl = `socks5://${socksEndpoint}`;
      }
      if (
        !this.attempts.isCurrent(request.sessionId, generation) ||
        this.pendingOpenOwners.get(request.sessionId) !== owner ||
        owner.isDestroyed()
      ) {
        throw new Error('Web session was superseded before its browser could open.');
      }

      const partition = target.proxyUrl
        ? `wormhole-web-tunnel-${++this.isolatedPartitionSequence}`
        : target.ignoreCertErrors
          ? `wormhole-web-isolated-${++this.isolatedPartitionSequence}`
          : webSharedPartition;
      const browserSession = electronSession.fromPartition(partition, { cache: true });
      if (target.proxyUrl) {
        await browserSession.setProxy({
          proxyRules: target.proxyUrl,
          proxyBypassRules: '<-loopback>',
        });
      }
      browserSession.setPermissionRequestHandler((_webContents, _permission, callback) =>
        callback(false),
      );
      browserSession.setPermissionCheckHandler(() => false);

      const view = new WebContentsView({
        webPreferences: {
          partition,
          contextIsolation: true,
          nodeIntegration: false,
          sandbox: true,
          webSecurity: true,
          allowRunningInsecureContent: false,
          devTools: false,
        },
      });
      const record: WebSurfaceRecord = {
        owner,
        view,
        attempt: request.attempt,
        initialNavigationPending: true,
        disposed: false,
        tunnelLeaseId: openingLeaseId,
      };
      this.surfaces.set(request.sessionId, record);
      this.pendingOpenOwners.delete(request.sessionId);
      owner.contentView.addChildView(view);
      view.setVisible(false);
      this.configureWebContents(request.sessionId, record, target);
      void view.webContents.loadURL(target.url).catch((error: unknown) => {
        if (!record.disposed && record.initialNavigationPending) {
          record.initialNavigationPending = false;
          this.sendEvent(request.sessionId, record, 'failed', {
            error: describeWebNavigationError(error),
          });
        }
      });
      openingLeaseId = undefined;
      return target;
    } catch (error) {
      if (this.surfaces.has(request.sessionId)) {
        this.dispose(request.sessionId);
        openingLeaseId = undefined;
      }
      if (openingLeaseId) void nativeBackend?.releaseTunnel(openingLeaseId).catch(() => undefined);
      if (
        this.attempts.isCurrent(request.sessionId, generation) &&
        this.pendingOpenOwners.get(request.sessionId) === owner
      ) {
        this.pendingOpenOwners.delete(request.sessionId);
      }
      throw error;
    }
  }

  setBounds(owner: BrowserWindow, request: WebBoundsRequest): void {
    const record = this.surfaces.get(request.sessionId);
    if (!record || record.owner !== owner || record.disposed) return;
    record.view.setBounds({
      x: Math.round(request.x),
      y: Math.round(request.y),
      width: Math.round(request.width),
      height: Math.round(request.height),
    });
    record.view.setVisible(request.visible);
  }

  command(owner: BrowserWindow, request: WebCommandRequest): void {
    const record = this.surfaces.get(request.sessionId);
    if (!record || record.owner !== owner || record.disposed) return;
    const contents = record.view.webContents;
    if (request.operation === 'back') {
      if (contents.navigationHistory.canGoBack()) contents.navigationHistory.goBack();
    } else if (request.operation === 'forward') {
      if (contents.navigationHistory.canGoForward()) contents.navigationHistory.goForward();
    } else {
      contents.reload();
    }
    this.sendEvent(request.sessionId, record, 'navigation');
  }

  close(sessionId: string): void {
    this.attempts.cancel(sessionId);
    this.pendingOpenOwners.delete(sessionId);
    this.dispose(sessionId);
  }

  private dispose(sessionId: string): void {
    const record = this.surfaces.get(sessionId);
    if (!record) return;
    this.surfaces.delete(sessionId);
    record.disposed = true;
    if (record.tunnelLeaseId)
      void nativeBackend?.releaseTunnel(record.tunnelLeaseId).catch(() => undefined);
    try {
      record.owner.contentView.removeChildView(record.view);
    } catch {
      // A window can already be closing while the renderer removes its session.
    }
    try {
      record.view.webContents.close();
    } catch {
      // Closing an already-destroyed WebContents is harmless.
    }
  }

  closeForOwner(owner: BrowserWindow, sessionId: string): void {
    const record = this.surfaces.get(sessionId);
    if (record?.owner === owner || this.pendingOpenOwners.get(sessionId) === owner) {
      this.close(sessionId);
    }
  }

  hideAll(): void {
    for (const record of this.surfaces.values()) {
      if (!record.disposed) record.view.setVisible(false);
    }
  }

  closeForWindow(owner: BrowserWindow): void {
    const sessionIds = new Set<string>();
    for (const [sessionId, record] of this.surfaces) {
      if (record.owner === owner) sessionIds.add(sessionId);
    }
    for (const [sessionId, pendingOwner] of this.pendingOpenOwners) {
      if (pendingOwner === owner) sessionIds.add(sessionId);
    }
    for (const sessionId of sessionIds) this.close(sessionId);
  }

  closeAll(): void {
    const sessionIds = new Set([...this.surfaces.keys(), ...this.pendingOpenOwners.keys()]);
    for (const sessionId of sessionIds) this.close(sessionId);
  }

  private configureWebContents(
    sessionId: string,
    record: WebSurfaceRecord,
    target: WebTargetResponse,
  ): void {
    const contents = record.view.webContents;
    contents.setWindowOpenHandler(({ url }) => {
      if (!isAllowedWebNavigation(url)) return { action: 'deny' };
      void contents.loadURL(url).catch(() => undefined);
      return { action: 'deny' };
    });
    contents.on('will-navigate', (event, url) => {
      if (!isAllowedWebNavigation(url)) event.preventDefault();
    });
    if (target.ignoreCertErrors) {
      contents.on('certificate-error', (event, _url, _error, _certificate, callback) => {
        // The opt-in belongs to this isolated WebContents only. A regular tab cannot inherit this
        // exception through Chromium's shared profile or certificate-decision cache.
        event.preventDefault();
        callback(true);
      });
    }
    contents.on('did-navigate', () => this.sendEvent(sessionId, record, 'navigation'));
    contents.on('did-navigate-in-page', () => this.sendEvent(sessionId, record, 'navigation'));
    contents.on('did-finish-load', () => {
      this.sendEvent(
        sessionId,
        record,
        record.initialNavigationPending ? 'connected' : 'navigation',
      );
      record.initialNavigationPending = false;
    });
    contents.on(
      'did-fail-load',
      (
        _event,
        errorCode: number,
        errorDescription: string,
        _validatedURL: string,
        isMainFrame: boolean,
      ) => {
        // ERR_ABORTED is the normal companion to client-side redirects and must not turn a viable
        // connection into a failed tab.
        if (!isMainFrame || errorCode === -3 || record.disposed) return;
        if (record.initialNavigationPending) {
          record.initialNavigationPending = false;
          this.sendEvent(sessionId, record, 'failed', {
            error: describeWebLoadFailure(errorCode, errorDescription),
          });
          return;
        }
        this.sendEvent(sessionId, record, 'navigation');
      },
    );
    contents.on('render-process-gone', () => {
      if (!record.initialNavigationPending || record.disposed) return;
      record.initialNavigationPending = false;
      this.sendEvent(sessionId, record, 'failed', {
        error: 'The browser process stopped unexpectedly.',
      });
    });
  }

  private sendEvent(
    sessionId: string,
    record: WebSurfaceRecord,
    type: 'connected' | 'failed' | 'navigation',
    values: { error?: string } = {},
  ): void {
    if (record.disposed || record.owner.isDestroyed()) return;
    const contents = record.view.webContents;
    try {
      record.owner.webContents.send('web:event', {
        type,
        sessionId,
        attempt: record.attempt,
        url: contents.getURL().slice(0, webMaxUrlLength),
        canGoBack: contents.navigationHistory.canGoBack(),
        canGoForward: contents.navigationHistory.canGoForward(),
        error: values.error?.slice(0, 2048),
      });
    } catch {
      // The renderer may be reloading while an in-flight navigation completes.
    }
  }
}

function isAllowedWebNavigation(value: string): boolean {
  try {
    const target = new URL(value);
    return target.protocol === 'http:' || target.protocol === 'https:';
  } catch {
    return false;
  }
}

function describeWebNavigationError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message
    ? `The browser could not start the page: ${message}`
    : 'The browser could not start the page.';
}

function describeWebLoadFailure(errorCode: number, description: string): string {
  switch (errorCode) {
    case -105:
      return 'The host name could not be resolved.';
    case -102:
      return 'The server is unreachable.';
    case -118:
      return 'The connection timed out.';
    case -101:
    case -100:
      return 'The connection was reset.';
    case -200:
    case -201:
    case -202:
    case -203:
    case -204:
      return 'The server certificate could not be validated. If this appliance uses a self-signed certificate, enable “Ignore certificate errors” for this connection.';
    default:
      return description ? `Navigation failed (${description}).` : 'Navigation failed.';
  }
}

const webSurfaces = new WebSurfaceManager();

class NativeSshBackend {
  private child: ChildProcessWithoutNullStreams | undefined;
  private lineReader: Interface | undefined;
  private controlSequence = 0;
  private readonly activeSessions = new Set<string>();
  private readonly tunnelLeases = new Map<string, string>();
  private readonly openWaiters = new Map<
    string,
    {
      resolve: (response: SshConnectedResponse) => void;
      reject: (error: Error) => void;
      timeout: NodeJS.Timeout;
    }
  >();
  private readonly controlWaiters = new Map<
    string,
    {
      resolve: (response: McpControlResponse) => void;
      reject: (error: Error) => void;
      timeout: NodeJS.Timeout;
    }
  >();

  async open(request: SshOpenRequest): Promise<SshConnectedResponse> {
    if (this.openWaiters.has(request.sessionId) || this.activeSessions.has(request.sessionId)) {
      throw new Error('SSH session id is already in use.');
    }
    const leaseId = randomUUID();
    this.tunnelLeases.set(request.sessionId, leaseId);
    let socksEndpoint = '';
    try {
      socksEndpoint = await getNativeBackend().acquireTunnel({
        leaseId,
        nodeId: request.nodeId,
        progressSessionId: request.sessionId,
      });
    } catch (error) {
      if (this.tunnelLeases.get(request.sessionId) === leaseId) {
        this.tunnelLeases.delete(request.sessionId);
      }
      throw error;
    }
    if (this.tunnelLeases.get(request.sessionId) !== leaseId) {
      throw new Error('SSH connection closed while opening its VPN tunnel.');
    }
    if (!socksEndpoint) {
      this.tunnelLeases.delete(request.sessionId);
      void nativeBackend?.releaseTunnel(leaseId).catch(() => undefined);
    }
    try {
      this.ensureStarted();
    } catch (error) {
      this.releaseTunnel(request.sessionId);
      throw error;
    }

    return new Promise<SshConnectedResponse>((resolve, reject) => {
      const timeout = setTimeout(() => {
        const waiter = this.openWaiters.get(request.sessionId);
        if (!waiter || waiter.timeout !== timeout) return;
        this.openWaiters.delete(request.sessionId);
        this.releaseTunnel(request.sessionId);
        reject(new Error('SSH connection timed out.'));
        try {
          this.write({ type: 'close', session_id: request.sessionId });
        } catch {
          // The backend may already have stopped; the timeout has released the renderer.
        }
      }, nativeConnectionTimeoutMs);
      this.openWaiters.set(request.sessionId, { resolve, reject, timeout });
      try {
        this.write({
          type: 'open',
          session_id: request.sessionId,
          node_id: request.nodeId,
          socks_endpoint: socksEndpoint,
          tunnel_enabled: socksEndpoint ? undefined : false,
          columns: request.columns,
          rows: request.rows,
        });
      } catch (error) {
        this.openWaiters.delete(request.sessionId);
        clearTimeout(timeout);
        this.releaseTunnel(request.sessionId);
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }

  sendInput(sessionId: string, data: string): void {
    this.write({ type: 'input', session_id: sessionId, data });
  }

  resize(sessionId: string, columns: number, rows: number): void {
    this.write({ type: 'resize', session_id: sessionId, columns, rows });
  }

  openSftp(sessionId: string, requestId = ''): void {
    this.write({ type: 'sftp-open', session_id: sessionId, request_id: requestId });
  }

  listSftp(sessionId: string, path: string, requestId = ''): void {
    this.write({ type: 'sftp-list', session_id: sessionId, path, request_id: requestId });
  }

  listLocalSftp(sessionId: string, path: string, requestId: string): void {
    this.write({
      type: 'sftp-local-list',
      session_id: sessionId,
      path,
      request_id: requestId,
    });
  }

  operateSftp(sessionId: string, request: SftpOperationRequest): void {
    this.write({
      type: 'sftp-operation',
      session_id: sessionId,
      request_id: request.requestId,
      pane: request.pane,
      operation: request.operation,
      path: request.path,
      destination_path: request.destinationPath,
    });
  }

  startSftpTransfer(sessionId: string, request: SftpTransferRequest): void {
    this.write({
      type: 'sftp-transfer',
      session_id: sessionId,
      transfer_id: request.transferId,
      direction: request.direction,
      destination_path: request.destinationPath,
      items: request.items.map((item) => ({
        source_path: item.sourcePath,
        name: item.name,
        is_directory: item.isDirectory,
        size: item.size,
      })),
    });
  }

  decideSftpConflict(
    sessionId: string,
    transferId: string,
    itemId: string,
    decision: SshSftpTransferDecision,
    applyToAll: boolean,
  ): void {
    this.write({
      type: 'sftp-transfer-decision',
      session_id: sessionId,
      transfer_id: transferId,
      item_id: itemId,
      decision,
      apply_to_all: applyToAll,
    });
  }

  cancelSftpTransfer(sessionId: string, transferId: string, itemId?: string): void {
    this.write({
      type: 'sftp-transfer-cancel',
      session_id: sessionId,
      transfer_id: transferId,
      item_id: itemId,
    });
  }

  closeSftp(sessionId: string): void {
    this.write({ type: 'sftp-close', session_id: sessionId });
  }

  closeAllSftp(): void {
    for (const sessionId of this.activeSessions) {
      try {
        this.closeSftp(sessionId);
      } catch {
        // A broken pipe for one session must not prevent cleanup commands for the others.
        continue;
      }
    }
  }

  cancelAutoSudo(): void {
    for (const sessionId of this.activeSessions) {
      try {
        this.write({ type: 'auto-sudo-cancel', session_id: sessionId });
      } catch {
        // A broken pipe during lock/reload is already a terminal cleanup state.
        continue;
      }
    }

    // A connection can load its saved password and construct the Go-side Auto Sudo driver before
    // its connected event reaches this process. Lock/reload must cancel those handshakes too.
    for (const sessionId of [...this.openWaiters.keys()]) {
      this.close(sessionId);
    }
  }

  close(sessionId: string): void {
    const waiter = this.openWaiters.get(sessionId);
    if (waiter) {
      this.openWaiters.delete(sessionId);
      clearTimeout(waiter.timeout);
      waiter.reject(new Error('SSH connection closed while connecting.'));
    }
    if (this.child && !this.child.killed) {
      try {
        this.write({ type: 'close', session_id: sessionId });
      } catch {
        // The backend may exit between the state check and the write. The renderer is already
        // removing this tab, so there is no useful recovery action here.
      }
    }
    this.releaseTunnel(sessionId);
  }

  private releaseTunnel(sessionId: string): void {
    const leaseId = this.tunnelLeases.get(sessionId);
    if (!leaseId) return;
    this.tunnelLeases.delete(sessionId);
    void nativeBackend?.releaseTunnel(leaseId).catch(() => undefined);
  }

  requestSnapshots(): void {
    if (!authSession.isAccessAllowed || !this.child || this.child.killed) return;
    for (const sessionId of this.activeSessions) {
      try {
        this.write({ type: 'snapshot', session_id: sessionId });
      } catch {
        return;
      }
    }
  }

  async mcpStatus(): Promise<McpStatusResponse> {
    const response = await this.sendMcpControl({ type: 'mcp.status' });
    if (!response.status) throw new Error('Native MCP backend returned no status.');
    return response.status;
  }

  async startMcp(port: number): Promise<McpStatusResponse> {
    const response = await this.sendMcpControl({ type: 'mcp.start', port });
    if (!response.status) throw new Error('Native MCP backend returned no status.');
    return response.status;
  }

  async stopMcp(): Promise<McpStatusResponse> {
    const response = await this.sendMcpControl({ type: 'mcp.stop' });
    if (!response.status) throw new Error('Native MCP backend returned no status.');
    return response.status;
  }

  async setMcpPort(port: number): Promise<McpStatusResponse> {
    const response = await this.sendMcpControl({ type: 'mcp.set-port', port });
    if (!response.status) throw new Error('Native MCP backend returned no status.');
    return response.status;
  }

  async getMcpToken(): Promise<string> {
    const response = await this.sendMcpControl({ type: 'mcp.get-token' });
    if (!response.token) throw new Error('Native MCP backend returned no token.');
    return response.token;
  }

  async regenerateMcpToken(): Promise<string> {
    const response = await this.sendMcpControl({ type: 'mcp.regenerate-token' });
    if (!response.token) throw new Error('Native MCP backend returned no token.');
    return response.token;
  }

  async respondMcpApproval(approvalId: string, approved: boolean): Promise<void> {
    await this.sendMcpControl({ type: 'mcp.approve', approval_id: approvalId, approved });
  }

  async setMcpLocked(locked: boolean): Promise<void> {
    if (!this.child || this.child.killed) return;
    await this.sendMcpControl({ type: locked ? 'mcp.lock' : 'mcp.unlock' });
  }

  async syncMcpAfterUnlock(): Promise<void> {
    let startError: unknown;
    try {
      const status = await this.mcpStatus();
      if (status.enabled && !status.running) await this.startMcp(status.port);
    } catch (error) {
      startError = error;
    }
    await this.setMcpLocked(false);
    if (startError instanceof Error) throw startError;
    if (startError !== undefined) throw new Error(String(startError));
  }

  dispose(): void {
    for (const waiter of this.openWaiters.values()) {
      clearTimeout(waiter.timeout);
      waiter.reject(new Error('SSH backend stopped.'));
    }
    this.openWaiters.clear();
    this.failControlWaiters(new Error('Native SSH backend stopped.'));
    this.activeSessions.clear();
    for (const sessionId of [...this.tunnelLeases.keys()]) this.releaseTunnel(sessionId);
    this.lineReader?.close();
    this.lineReader = undefined;
    const child = this.child;
    this.child = undefined;
    if (!child || child.killed) return;
    child.stdin.end();
    child.kill();
  }

  private ensureStarted(): void {
    if (this.child && !this.child.killed) return;

    const child = spawn(
      backendPath(),
      [
        '--operation',
        'ssh',
        '--database',
        wormholeDatabasePath(),
        '--electron-user-data',
        electronUserDataPath(),
      ],
      { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] },
    );
    this.child = child;
    const lineReader = createInterface({ input: child.stdout, crlfDelay: Infinity });
    this.lineReader = lineReader;
    lineReader.on('line', (line) => {
      if (this.child === child) this.handleLine(line);
    });
    child.stdin.on('error', (error) => {
      if (this.child !== child) return;
      const failure = new Error(`Native SSH backend input failed: ${error.message}`);
      this.failOpenWaiters(failure);
      this.failControlWaiters(failure);
    });
    child.stderr.on('data', () => {
      // The backend deliberately keeps protocol events on stdout. Drain stderr so a native
      // failure cannot block the session pipe; do not mirror raw backend text into the UI.
    });
    child.on('error', (error) => {
      if (this.child !== child) return;
      const failure = new Error(`Native SSH backend failed: ${error.message}`);
      this.failOpenWaiters(failure);
      this.failControlWaiters(failure);
    });
    child.on('exit', () => {
      lineReader.close();
      if (this.child !== child) return;
      this.child = undefined;
      if (this.lineReader === lineReader) this.lineReader = undefined;
      const closedSessions = [...this.activeSessions];
      this.activeSessions.clear();
      for (const sessionId of closedSessions) {
        this.broadcast({ type: 'closed', sessionId });
      }
      const failure = new Error('Native SSH backend stopped.');
      this.failOpenWaiters(failure);
      this.failControlWaiters(failure);
      for (const sessionId of [...this.tunnelLeases.keys()]) this.releaseTunnel(sessionId);
    });
  }

  private write(command: Record<string, unknown>): void {
    const child = this.child;
    if (!child || child.killed || child.stdin.destroyed) {
      throw new Error('Native SSH backend is not running.');
    }
    child.stdin.write(`${JSON.stringify(command)}\n`, 'utf8');
  }

  private async sendMcpControl(command: Record<string, unknown>): Promise<McpControlResponse> {
    this.ensureStarted();
    const requestId = `electron-mcp-${++this.controlSequence}`;
    const response = new Promise<McpControlResponse>((resolve, reject) => {
      const timeout = setTimeout(() => {
        const waiter = this.controlWaiters.get(requestId);
        if (!waiter || waiter.timeout !== timeout) return;
        this.controlWaiters.delete(requestId);
        reject(new Error('Native MCP backend command timed out.'));
      }, backendTimeoutMs);
      this.controlWaiters.set(requestId, { resolve, reject, timeout });
    });
    try {
      this.write({ ...command, request_id: requestId });
    } catch (error) {
      const waiter = this.controlWaiters.get(requestId);
      if (waiter) {
        this.controlWaiters.delete(requestId);
        clearTimeout(waiter.timeout);
        waiter.reject(error instanceof Error ? error : new Error(String(error)));
      }
    }
    const result = await response;
    if (result.error) throw new Error(result.error);
    return result;
  }

  private handleLine(line: string): void {
    const mcpMessage = parseMcpBackendMessage(line);
    if (mcpMessage?.type === 'mcp.response') {
      const waiter = this.controlWaiters.get(mcpMessage.requestId);
      if (!waiter) return;
      this.controlWaiters.delete(mcpMessage.requestId);
      clearTimeout(waiter.timeout);
      waiter.resolve(mcpMessage);
      return;
    }
    if (mcpMessage?.type === 'mcp.approval') {
      if (!authSession.isAccessAllowed) return;
      for (const window of BrowserWindow.getAllWindows()) {
        if (!window.isDestroyed()) window.webContents.send('mcp:approval', mcpMessage);
      }
      return;
    }
    const event = parseSshBackendEvent(line);
    if (!event) return;

    if (event.type === 'connected') {
      this.activeSessions.add(event.sessionId);
      const waiter = this.openWaiters.get(event.sessionId);
      if (waiter) {
        this.openWaiters.delete(event.sessionId);
        clearTimeout(waiter.timeout);
        waiter.resolve(event);
      }
    } else if (event.type === 'error') {
      const waiter = this.openWaiters.get(event.sessionId);
      if (waiter) {
        this.openWaiters.delete(event.sessionId);
        clearTimeout(waiter.timeout);
        waiter.reject(new Error(event.error || 'SSH connection failed.'));
      }
      this.releaseTunnel(event.sessionId);
    } else if (event.type === 'closed') {
      this.activeSessions.delete(event.sessionId);
      this.releaseTunnel(event.sessionId);
    }

    this.broadcast(event);
  }

  private broadcast(event: SshBackendEvent): void {
    // Lifecycle notifications let the locked renderer settle pending tabs, but terminal frames
    // must never cross the native authentication boundary until the session is unlocked again.
    if (
      (event.type === 'screen' || event.type.startsWith('sftp.')) &&
      !authSession.isAccessAllowed
    ) {
      return;
    }
    for (const window of BrowserWindow.getAllWindows()) {
      if (!window.isDestroyed()) window.webContents.send('ssh:event', event);
    }
  }

  private failOpenWaiters(error: Error): void {
    for (const waiter of this.openWaiters.values()) {
      clearTimeout(waiter.timeout);
      waiter.reject(error);
    }
    this.openWaiters.clear();
  }

  private failControlWaiters(error: Error): void {
    for (const waiter of this.controlWaiters.values()) {
      clearTimeout(waiter.timeout);
      waiter.reject(error);
    }
    this.controlWaiters.clear();
  }
}

function serializeAuthOperation<T>(operation: () => Promise<T>): Promise<T> {
  const result = authOperationQueue.then(operation, operation);
  authOperationQueue = result.then(
    () => undefined,
    () => undefined,
  );
  return result;
}

function rememberAuthState(state: AuthStateResponse, assumeUnlocked: boolean): AuthStateResponse {
  authSession.remember(state, assumeUnlocked);
  return state;
}

async function refreshAuthSession(): Promise<AuthStateResponse> {
  const state = await runBackend<AuthStateResponse>('auth-status');
  return rememberAuthState(state, false);
}

async function ensureAuthSession(): Promise<void> {
  if (!authSession.isInitialized) await refreshAuthSession();
}

async function requireWorkspaceAuth(): Promise<void> {
  await ensureAuthSession();
  authSession.requireUnlocked();
}

const defaultMcpStatus: McpStatusResponse = {
  enabled: false,
  running: false,
  port: 8765,
  endpoint: 'http://127.0.0.1:8765/mcp',
};

function parseMcpPort(value: unknown): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > 65535) {
    throw new Error('MCP port must be an integer between 1 and 65535.');
  }
  return value;
}

function parseMcpApproval(value: unknown): { requestId: string; approved: boolean } {
  if (!isRecord(value)) throw new Error('MCP approval request is invalid.');
  const requestId = typeof value.requestId === 'string' ? value.requestId.trim() : '';
  if (!requestId || requestId.length > 128) throw new Error('MCP approval request is invalid.');
  if (typeof value.approved !== 'boolean') throw new Error('MCP approval decision is invalid.');
  return { requestId, approved: value.approved };
}

async function runFirstLaunchMigrations(): Promise<void> {
  // The legacy Credential Manager is a Windows-only source. Keeping this guard in the Electron
  // main process also prevents the Windows backend/helper from being loaded on other platforms.
  if (process.platform !== 'win32') return;

  const result = await runBackend<MigrationResponse>('migrate');
  if (result.status === 'completed') {
    console.info(
      `[Wormhole] Credential Manager migration completed: ${result.migrated} migrated, ${result.missing} missing.`,
    );
  } else if (result.status === 'already-completed') {
    console.info('[Wormhole] Credential Manager migration already completed.');
  }
}

function registerIpcHandlers(sshBackend: NativeSshBackend): void {
  ipcMain.handle('workspace:load', async () => {
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      const workspace = await runBackend<WorkspaceResponse>('workspace');
      console.info(
        `[Wormhole] Workspace loaded: ${workspace.tree.length} roots, ${workspace.credentials.length} credentials, ${workspace.tunnels.length} tunnels.`,
      );
      return workspace;
    });
  });

  ipcMain.handle('workspace:update-node-ssh-settings', async (_event, request: unknown) => {
    if (!isWorkspaceNodeSshSettingsRequest(request)) {
      throw new Error('Workspace node settings are invalid.');
    }
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<{ updated: boolean }>('workspace-update-node', request);
    });
  });

  ipcMain.handle('workspace:create-credential', async (_event, value: unknown) => {
    const request = parseCredentialCreateRequest(value);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<WorkspaceCredential>('credential-create', request);
    });
  });

  ipcMain.handle('workspace:update-credential', async (_event, value: unknown) => {
    const request = parseCredentialUpdateRequest(value);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<WorkspaceCredential>('credential-update', request);
    });
  });

  ipcMain.handle('workspace:delete-credential', async (_event, value: unknown) => {
    const request = parseCredentialDeleteRequest(value);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runUserDeletion<{ deleted: boolean }>('credential-delete', request, 'credential');
    });
  });

  ipcMain.handle('workspace:update-node-tunnel', async (_event, request: unknown) => {
    if (!isWorkspaceNodeTunnelSettingsRequest(request)) {
      throw new Error('Workspace VPN tunnel settings are invalid.');
    }
    return serializeAuthOperation(async () => {
      await ensureAuthSession();
      authSession.requireUnlocked();
      return runBackend<{ updated: boolean }>('workspace-update-node-tunnel', request);
    });
  });

  ipcMain.handle('settings:read', async () => {
    return serializeAuthOperation(async () => {
      return runBackend<AppSettings>('settings-read');
    });
  });

  ipcMain.handle('settings:set-prompt-before-tunnel', async (_event, value: unknown) => {
    if (typeof value !== 'boolean') throw new Error('VPN tunnel prompt setting is invalid.');
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<{ updated: boolean }>('settings-set-prompt-before-tunnel', {
        enabled: value,
      });
    });
  });

  ipcMain.handle('settings:set-update-preferences', async (_event, value: unknown) => {
    if (!isRecord(value)) throw new Error('Update preferences are invalid.');
    const request: Record<string, unknown> = {};
    if (value.autoCheckForUpdates !== undefined) {
      if (typeof value.autoCheckForUpdates !== 'boolean') {
        throw new Error('Update preferences are invalid.');
      }
      request.autoCheckForUpdates = value.autoCheckForUpdates;
    }
    if (value.skippedUpdateVersion !== undefined) {
      if (value.skippedUpdateVersion !== null && typeof value.skippedUpdateVersion !== 'string') {
        throw new Error('Update preferences are invalid.');
      }
      request.skippedUpdateVersion = value.skippedUpdateVersion;
    }
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<{ updated: boolean }>('settings-set-update-preferences', request);
    });
  });

  ipcMain.handle('update:status', async () => {
    return serializeAuthOperation(async () => {
      return { currentVersion: app.getVersion(), result: latestUpdateCheck ?? null };
    });
  });

  ipcMain.handle('update:check', async () => {
    return serializeAuthOperation(async () => performUpdateCheck());
  });

  ipcMain.handle('update:download', async (event, value: unknown) => {
    if (!isRecord(value)) throw new Error('The update download request is invalid.');
    const installerUrl = typeof value.installerUrl === 'string' ? value.installerUrl.trim() : '';
    const installerFileName =
      typeof value.installerFileName === 'string' ? value.installerFileName.trim() : '';
    const installerSha256 =
      typeof value.installerSha256 === 'string' ? value.installerSha256.trim() : '';
    const installerSize =
      typeof value.installerSize === 'number' && Number.isInteger(value.installerSize)
        ? value.installerSize
        : null;
    if (
      !installerUrl ||
      !installerFileName ||
      path.basename(installerFileName) !== installerFileName ||
      !/^https:\/\//i.test(installerUrl)
    ) {
      throw new Error('The update download request is invalid.');
    }
    const target = event.sender;
    return downloadUpdateInstaller(
      {
        installerUrl,
        installerFileName,
        ...(installerSha256 ? { installerSha256 } : {}),
        ...(installerSize !== null ? { installerSize } : {}),
      },
      (downloaded, total) => broadcastUpdateProgress(target, downloaded, total),
    );
  });

  ipcMain.handle('update:install', async (_event, value: unknown) => {
    if (!isRecord(value) || typeof value.path !== 'string' || !isSafeInstallerPath(value.path)) {
      throw new Error('The installer path is invalid.');
    }
    const installerPath = path.resolve(value.path);
    if (!existsSync(installerPath)) throw new Error('The installer was not found.');
    launchInstallerAndExit(installerPath);
    return { launched: true };
  });

  ipcMain.handle('update:open-release', async (_event, value: unknown) => {
    if (typeof value !== 'string' || !/^https:\/\/github\.com\//i.test(value)) {
      throw new Error('The release URL is invalid.');
    }
    await shell.openExternal(value);
  });

  ipcMain.handle('tunnel:create', async (_event, value: unknown) => {
    const request = parseTunnelWriteRequest(value, false);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<TunnelDetailsResponse>('tunnel-create', request);
    });
  });

  ipcMain.handle('tunnel:read', async (_event, value: unknown) => {
    const request = parseTunnelIDRequest(value);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<TunnelDetailsResponse>('tunnel-read', request);
    });
  });

  ipcMain.handle('tunnel:update', async (_event, value: unknown) => {
    const request = parseTunnelWriteRequest(value, true);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<TunnelDetailsResponse>('tunnel-update', request);
    });
  });

  ipcMain.handle('tunnel:delete', async (_event, value: unknown) => {
    const request = parseTunnelIDRequest(value) as TunnelDeleteRequest;
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runUserDeletion<{ deleted: boolean }>('tunnel-delete', request, 'VPN tunnel');
    });
  });

  ipcMain.handle('tunnel:test', async (_event, value: unknown) => {
    const request = parseTunnelIDRequest(value);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      const leaseId = randomUUID();
      try {
        const socksEndpoint = await getNativeBackend().acquireTunnel({
          leaseId,
          tunnelConfigId: request.id,
        });
        if (!socksEndpoint) throw new Error('The VPN tunnel returned no SOCKS endpoint.');
        return { connected: true };
      } catch (error) {
        // A cancelled authentication is a normal user outcome; other test failures are expected
        // user-facing results too. Return them as data instead of rejecting the IPC call, so
        // Electron doesn't log "Error occurred in handler" for them.
        const message = error instanceof Error ? error.message : String(error);
        if (/cancell/i.test(message)) {
          console.info(`[Wormhole] VPN tunnel test cancelled (${request.id}): ${message}`);
        } else {
          console.warn(`[Wormhole] VPN tunnel test failed (${request.id}): ${message}`);
        }
        return { connected: false, error: message };
      } finally {
        await nativeBackend?.releaseTunnel(leaseId).catch(() => undefined);
      }
    });
  });

  ipcMain.handle('tunnel:import-watchguard', async (event) => {
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      const owner = BrowserWindow.fromWebContents(event.sender);
      const options: Electron.OpenDialogOptions = {
        title: 'Import WatchGuard Mobile VPN profile',
        properties: ['openFile'],
        filters: [
          { name: 'WatchGuard SSL VPN profile', extensions: ['wgssl', 'tgz', 'tar', 'gz'] },
          { name: 'All files', extensions: ['*'] },
        ],
      };
      const selection = owner
        ? await dialog.showOpenDialog(owner, options)
        : await dialog.showOpenDialog(options);
      if (selection.canceled || selection.filePaths.length !== 1) return null;
      const imported = await runBackend<{
        server: string;
        port: number;
        profileOvpn: string;
      }>('watchguard-import', { path: selection.filePaths[0] });
      if (
        typeof imported.server !== 'string' ||
        imported.server.length === 0 ||
        imported.server.length > 1024 ||
        !Number.isInteger(imported.port) ||
        imported.port < 1 ||
        imported.port > 65535 ||
        typeof imported.profileOvpn !== 'string' ||
        imported.profileOvpn.length === 0 ||
        Buffer.byteLength(imported.profileOvpn, 'utf8') > backendMaxTunnelRequestBytes
      ) {
        throw new Error('The WatchGuard profile importer returned an invalid result.');
      }
      return imported;
    });
  });

  ipcMain.handle('tunnel:import-azure-vpn', async (event) => {
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      const owner = BrowserWindow.fromWebContents(event.sender);
      const options: Electron.OpenDialogOptions = {
        title: 'Import Azure VPN profile',
        properties: ['openFile'],
        filters: [
          { name: 'Azure VPN configuration', extensions: ['xml'] },
          { name: 'All files', extensions: ['*'] },
        ],
      };
      const selection = owner
        ? await dialog.showOpenDialog(owner, options)
        : await dialog.showOpenDialog(options);
      if (selection.canceled || selection.filePaths.length !== 1) return null;
      const imported = await runBackend<{ name?: string; settings: Record<string, unknown> }>(
        'azure-vpn-import',
        { path: selection.filePaths[0] },
      );
      if (
        !isRecord(imported.settings) ||
        (imported.name !== undefined && typeof imported.name !== 'string')
      ) {
        throw new Error('The Azure VPN profile importer returned an invalid result.');
      }
      return imported;
    });
  });

  ipcMain.handle('tunnel:import-ovpn', async (event) => {
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      const owner = BrowserWindow.fromWebContents(event.sender);
      const options: Electron.OpenDialogOptions = {
        title: 'Import OpenVPN profile',
        properties: ['openFile'],
        filters: [
          { name: 'OpenVPN profile', extensions: ['ovpn', 'conf'] },
          { name: 'All files', extensions: ['*'] },
        ],
      };
      const selection = owner
        ? await dialog.showOpenDialog(owner, options)
        : await dialog.showOpenDialog(options);
      if (selection.canceled || selection.filePaths.length !== 1) return null;
      const imported = await runBackend<{ contents: string }>('ovpn-file-import', {
        path: selection.filePaths[0],
      });
      if (
        typeof imported.contents !== 'string' ||
        Buffer.byteLength(imported.contents, 'utf8') > backendMaxTunnelRequestBytes
      ) {
        throw new Error('The OpenVPN profile importer returned an invalid result.');
      }
      return imported;
    });
  });

  ipcMain.handle('tunnel:import-cisco', async (event) => {
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      const owner = BrowserWindow.fromWebContents(event.sender);
      const options: Electron.OpenDialogOptions = {
        title: 'Import AnyConnect profile',
        properties: ['openFile'],
        filters: [{ name: 'AnyConnect XML profile', extensions: ['xml'] }],
      };
      const selection = owner
        ? await dialog.showOpenDialog(owner, options)
        : await dialog.showOpenDialog(options);
      if (selection.canceled || selection.filePaths.length !== 1) return null;
      const imported = await runBackend<{
        host: string;
        port: number;
        group?: string;
        profileName?: string;
      }>('cisco-profile-import', { path: selection.filePaths[0] });
      if (
        typeof imported.host !== 'string' ||
        imported.host.length === 0 ||
        imported.host.length > 1024 ||
        !Number.isInteger(imported.port) ||
        imported.port < 1 ||
        imported.port > 65535 ||
        (imported.group !== undefined &&
          (typeof imported.group !== 'string' || imported.group.length > 256)) ||
        (imported.profileName !== undefined &&
          (typeof imported.profileName !== 'string' || imported.profileName.length > 256))
      ) {
        throw new Error('The AnyConnect profile importer returned an invalid result.');
      }
      return imported;
    });
  });

  ipcMain.handle('tunnel:prompt-response', async (_event, value: unknown) => {
    if (!isRecord(value)) throw new Error('VPN authentication response is invalid.');
    const leaseId = value.leaseId;
    const promptId = value.promptId;
    const promptValue = value.value;
    const cancelled = value.cancelled;
    if (
      typeof leaseId !== 'string' ||
      leaseId.length === 0 ||
      leaseId.length > 128 ||
      typeof promptId !== 'string' ||
      promptId.length === 0 ||
      promptId.length > 128 ||
      typeof promptValue !== 'string' ||
      promptValue.length > 16 * 1024 ||
      typeof cancelled !== 'boolean'
    ) {
      throw new Error('VPN authentication response is invalid.');
    }
    await requireWorkspaceAuth();
    await getNativeBackend().respondTunnelPrompt({
      leaseId,
      promptId,
      value: promptValue,
      cancelled,
    });
  });

  ipcMain.handle('tunnel:route-response', async (_event, value: unknown) => {
    if (!isRecord(value)) throw new Error('VPN tunnel choice is invalid.');
    const leaseId = value.leaseId;
    const promptId = value.promptId;
    const choice = value.choice;
    if (
      typeof leaseId !== 'string' ||
      leaseId.length === 0 ||
      leaseId.length > 128 ||
      typeof promptId !== 'string' ||
      promptId.length === 0 ||
      promptId.length > 128 ||
      (choice !== 'tunnel' && choice !== 'direct' && choice !== 'cancel')
    ) {
      throw new Error('VPN tunnel choice is invalid.');
    }
    await requireWorkspaceAuth();
    await getNativeBackend().respondTunnelRoute({ leaseId, promptId, value: choice });
  });

  ipcMain.handle('auth:status', async () => {
    return serializeAuthOperation(refreshAuthSession);
  });

  ipcMain.handle('auth:verify', async (_event, request: unknown) => {
    return serializeAuthOperation(async () => {
      await ensureAuthSession();
      const result = await runBackend<{ succeeded: boolean }>('auth-verify', request);
      if (result.succeeded) authSession.markUnlocked();
      return result;
    });
  });

  ipcMain.handle('auth:set-secret', async (_event, request: unknown) => {
    return serializeAuthOperation(async () => {
      await ensureAuthSession();
      authSession.requireUnlocked();
      const state = await runBackend<AuthStateResponse>('auth-set-secret', request);
      return rememberAuthState(state, true);
    });
  });

  ipcMain.handle('auth:update-settings', async (_event, request: unknown) => {
    return serializeAuthOperation(async () => {
      await ensureAuthSession();
      authSession.requireUnlocked();
      const state = await runBackend<AuthStateResponse>('auth-update-settings', request);
      return rememberAuthState(state, true);
    });
  });

  ipcMain.handle('auth:lock', async (event) => {
    return serializeAuthOperation(async () => {
      await ensureAuthSession();
      authSession.lock();
      sshBackend.cancelAutoSudo();
      sshBackend.closeAllSftp();
      try {
        await sshBackend.setMcpLocked(true);
      } catch {
        // The native process may already have exited; the Electron auth session is still locked.
      }
      webSurfaces.hideAll();
      const ownerWindow = BrowserWindow.fromWebContents(event.sender);
      if (!ownerWindow || ownerWindow.isDestroyed()) return;
      try {
        await rdpClient?.hideAll(nativeWindowHandle(ownerWindow));
      } catch {
        // Authentication remains locked even if a native RDP surface has already exited.
      }
    });
  });

  ipcMain.handle('auth:hello-status', async () => {
    if (process.platform !== 'win32') {
      return { available: false, message: 'Windows Hello only works on Windows.' };
    }
    return runBackend('auth-hello-status');
  });

  ipcMain.handle('auth:hello-verify', async (event) => {
    if (process.platform !== 'win32') {
      return { succeeded: false, message: 'Windows Hello only works on Windows.' };
    }
    return serializeAuthOperation(async () => {
      await ensureAuthSession();
      const state = await refreshAuthSession();
      if (state.mode !== 'windowsHello' || !state.configured) {
        return {
          succeeded: false,
          message: 'Choose Windows Hello in Settings first.',
        };
      }
      const ownerWindow = BrowserWindow.fromWebContents(event.sender);
      if (!ownerWindow || ownerWindow.isDestroyed()) {
        return { succeeded: false, message: 'Bring Wormhole to the front and try again.' };
      }
      if (!ownerWindow.isVisible()) ownerWindow.show();
      ownerWindow.focus();
      const result = await runBackend<{ succeeded: boolean }>('auth-hello-verify', {
        ownerWindow: nativeWindowHandle(ownerWindow),
      });
      if (result.succeeded) authSession.markUnlocked();
      return result;
    });
  });

  ipcMain.handle('auth:system-idle', async () => {
    return runBackend('auth-system-idle');
  });
  ipcMain.handle('mcp:status', async () => {
    if (process.platform !== 'win32') return defaultMcpStatus;
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return sshBackend.mcpStatus();
    });
  });
  ipcMain.handle('mcp:start', async (_event, port: unknown) => {
    if (process.platform !== 'win32') throw new Error('MCP is available on Windows builds.');
    const parsedPort = parseMcpPort(port);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return sshBackend.startMcp(parsedPort);
    });
  });
  ipcMain.handle('mcp:stop', async () => {
    if (process.platform !== 'win32') throw new Error('MCP is available on Windows builds.');
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return sshBackend.stopMcp();
    });
  });
  ipcMain.handle('mcp:set-port', async (_event, port: unknown) => {
    if (process.platform !== 'win32') throw new Error('MCP is available on Windows builds.');
    const parsedPort = parseMcpPort(port);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return sshBackend.setMcpPort(parsedPort);
    });
  });
  ipcMain.handle('mcp:get-token', async () => {
    if (process.platform !== 'win32') throw new Error('MCP is available on Windows builds.');
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return sshBackend.getMcpToken();
    });
  });
  ipcMain.handle('mcp:regenerate-token', async () => {
    if (process.platform !== 'win32') throw new Error('MCP is available on Windows builds.');
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return sshBackend.regenerateMcpToken();
    });
  });
  ipcMain.handle('mcp:approval', async (_event, value: unknown) => {
    if (process.platform !== 'win32') throw new Error('MCP is available on Windows builds.');
    const approval = parseMcpApproval(value);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      await sshBackend.respondMcpApproval(approval.requestId, approval.approved);
    });
  });

  ipcMain.handle('workspace:update-node-web-settings', async (_event, request: unknown) => {
    if (!isWorkspaceNodeWebSettingsRequest(request)) {
      throw new Error('Workspace web node settings are invalid.');
    }
    if (process.platform !== 'win32') return { updated: false };
    return serializeAuthOperation(async () => {
      await ensureAuthSession();
      authSession.requireUnlocked();
      return runBackend<{ updated: boolean }>('workspace-update-node-web-settings', request);
    });
  });
  ipcMain.handle('web:open', async (event, request: unknown) => {
    if (!isWebOpenRequest(request)) throw new Error('Web connection request is invalid.');
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow || ownerWindow.isDestroyed())
      throw new Error('Web session owner window is unavailable.');
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return webSurfaces.open(ownerWindow, request);
    });
  });
  ipcMain.handle('web:set-bounds', async (event, request: unknown) => {
    if (!isWebBoundsRequest(request)) throw new Error('Web surface bounds are invalid.');
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow || ownerWindow.isDestroyed()) return;
    // Bounds updates are intentionally lightweight, but never make private page contents visible
    // after the native workspace was locked.
    if (process.platform === 'win32' && !authSession.isAccessAllowed) {
      webSurfaces.hideAll();
      return;
    }
    webSurfaces.setBounds(ownerWindow, request);
  });
  ipcMain.handle('web:command', async (event, request: unknown) => {
    if (!isWebCommandRequest(request)) throw new Error('Web browser command is invalid.');
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow || ownerWindow.isDestroyed()) return;
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      webSurfaces.command(ownerWindow, request);
    });
  });
  ipcMain.handle('web:close', async (event, sessionId: unknown) => {
    if (!isSshSessionId(sessionId)) throw new Error('Web session id is invalid.');
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow || ownerWindow.isDestroyed()) return;
    webSurfaces.closeForOwner(ownerWindow, sessionId);
  });
  ipcMain.handle('ssh:open', async (_event, request: unknown) => {
    if (!isSshOpenRequest(request)) throw new Error('SSH open request is invalid.');
    let connection: Promise<SshConnectedResponse> | undefined;
    await serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      // Start the long-lived connection inside the authorization queue, but do not make the
      // queue wait for the remote handshake. This keeps a lock request responsive while a host
      // is unreachable or still negotiating.
      connection = sshBackend.open(request);
    });
    return connection!;
  });
  ipcMain.handle('ssh:trust-host-key', async (_event, request: unknown) => {
    if (!isSshHostKeyTrustRequest(request)) {
      throw new Error('SSH host-key trust request is invalid.');
    }
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend('ssh-trust-host-key', request);
    });
  });
  ipcMain.handle('ssh:input', async (_event, sessionId: unknown, data: unknown) => {
    if (!isSshSessionId(sessionId) || !isSshInput(data)) {
      throw new Error('SSH input request is invalid.');
    }
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      sshBackend.sendInput(sessionId, data);
    });
  });
  ipcMain.handle(
    'ssh:resize',
    async (_event, sessionId: unknown, columns: unknown, rows: unknown) => {
      if (
        !isSshSessionId(sessionId) ||
        typeof columns !== 'number' ||
        !Number.isInteger(columns) ||
        columns < 0 ||
        columns > 500 ||
        typeof rows !== 'number' ||
        !Number.isInteger(rows) ||
        rows < 0 ||
        rows > 500
      ) {
        throw new Error('SSH resize request is invalid.');
      }
      return serializeAuthOperation(async () => {
        await requireWorkspaceAuth();
        sshBackend.resize(sessionId, columns, rows);
      });
    },
  );
  ipcMain.handle('ssh:sftp-open', async (_event, sessionId: unknown, requestId: unknown) => {
    if (!isSshSessionId(sessionId) || (requestId !== undefined && !isSftpRequestId(requestId))) {
      throw new Error('SFTP open request is invalid.');
    }
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      sshBackend.openSftp(sessionId, typeof requestId === 'string' ? requestId : '');
    });
  });
  ipcMain.handle(
    'ssh:sftp-list',
    async (_event, sessionId: unknown, path: unknown, requestId: unknown) => {
      if (
        !isSshSessionId(sessionId) ||
        !isSftpPath(path) ||
        (requestId !== undefined && !isSftpRequestId(requestId))
      ) {
        throw new Error('SFTP list request is invalid.');
      }
      return serializeAuthOperation(async () => {
        await requireWorkspaceAuth();
        sshBackend.listSftp(sessionId, path, typeof requestId === 'string' ? requestId : '');
      });
    },
  );
  ipcMain.handle(
    'ssh:sftp-local-list',
    async (_event, sessionId: unknown, path: unknown, requestId: unknown) => {
      if (
        !isSshSessionId(sessionId) ||
        !isLocalSftpPath(path, true) ||
        !isSftpRequestId(requestId)
      ) {
        throw new Error('Local SFTP list request is invalid.');
      }
      return serializeAuthOperation(async () => {
        await requireWorkspaceAuth();
        sshBackend.listLocalSftp(sessionId, path, requestId);
      });
    },
  );
  ipcMain.handle('ssh:sftp-operation', async (_event, sessionId: unknown, request: unknown) => {
    if (!isSshSessionId(sessionId) || !isSftpOperationRequest(request)) {
      throw new Error('SFTP operation request is invalid.');
    }
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      sshBackend.operateSftp(sessionId, request);
    });
  });
  ipcMain.handle('ssh:sftp-transfer', async (_event, sessionId: unknown, request: unknown) => {
    if (!isSshSessionId(sessionId) || !isSftpTransferRequest(request)) {
      throw new Error('SFTP transfer request is invalid.');
    }
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      sshBackend.startSftpTransfer(sessionId, request);
    });
  });
  ipcMain.handle(
    'ssh:sftp-transfer-decision',
    async (
      _event,
      sessionId: unknown,
      transferId: unknown,
      itemId: unknown,
      decision: unknown,
      applyToAll: unknown,
    ) => {
      if (
        !isSshSessionId(sessionId) ||
        !isSftpTransferId(transferId) ||
        !isSftpRequestId(itemId) ||
        !isSftpTransferDecision(decision) ||
        typeof applyToAll !== 'boolean'
      ) {
        throw new Error('SFTP transfer decision is invalid.');
      }
      return serializeAuthOperation(async () => {
        await requireWorkspaceAuth();
        sshBackend.decideSftpConflict(sessionId, transferId, itemId, decision, applyToAll);
      });
    },
  );
  ipcMain.handle(
    'ssh:sftp-transfer-cancel',
    async (_event, sessionId: unknown, transferId: unknown, itemId: unknown) => {
      if (
        !isSshSessionId(sessionId) ||
        !isSftpTransferId(transferId) ||
        (itemId !== undefined && !isSftpRequestId(itemId))
      ) {
        throw new Error('SFTP transfer cancellation is invalid.');
      }
      return serializeAuthOperation(async () => {
        await requireWorkspaceAuth();
        sshBackend.cancelSftpTransfer(
          sessionId,
          transferId,
          typeof itemId === 'string' ? itemId : undefined,
        );
      });
    },
  );
  ipcMain.handle('ssh:sftp-close', async (_event, sessionId: unknown) => {
    if (!isSshSessionId(sessionId)) throw new Error('SFTP close request is invalid.');
    return serializeAuthOperation(async () => {
      sshBackend.closeSftp(sessionId);
    });
  });
  ipcMain.handle('ssh:close', async (_event, sessionId: unknown) => {
    if (!isSshSessionId(sessionId)) throw new Error('SSH close request is invalid.');
    sshBackend.close(sessionId);
  });
  ipcMain.handle('serial:open', async (_event, request: unknown) => {
    if (!isSerialOpenRequest(request)) throw new Error('Serial open request is invalid.');
    let connection: Promise<SerialConnectedResponse> | undefined;
    await serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      connection = getSerialBackend().open(request as SerialOpenRequest);
    });
    return connection!;
  });
  ipcMain.handle('serial:input', async (_event, sessionId: unknown, data: unknown) => {
    if (!isSerialSessionId(sessionId) || !isSerialInput(data)) {
      throw new Error('Serial input request is invalid.');
    }
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      getSerialBackend().sendInput(sessionId, data);
    });
  });
  ipcMain.handle(
    'serial:resize',
    async (_event, sessionId: unknown, columns: unknown, rows: unknown) => {
      if (
        !isSerialSessionId(sessionId) ||
        typeof columns !== 'number' ||
        !Number.isInteger(columns) ||
        columns < 0 ||
        columns > 500 ||
        typeof rows !== 'number' ||
        !Number.isInteger(rows) ||
        rows < 0 ||
        rows > 500
      ) {
        throw new Error('Serial resize request is invalid.');
      }
      return serializeAuthOperation(async () => {
        await requireWorkspaceAuth();
        getSerialBackend().resize(sessionId, columns, rows);
      });
    },
  );
  ipcMain.handle('serial:close', async (_event, sessionId: unknown) => {
    if (!isSerialSessionId(sessionId)) throw new Error('Serial close request is invalid.');
    getSerialBackend().close(sessionId);
  });
  ipcMain.handle('vnc:command', async (_event, input: unknown) => {
    if (isQuitting) {
      return { id: '', ok: false, error: 'Native backend is stopping.' };
    }
    let command: VncCommand;
    try {
      command = parseVncCommand(input);
    } catch (error) {
      return {
        id: '',
        ok: false,
        error: error instanceof Error ? error.message : 'Invalid VNC command.',
      };
    }
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return getNativeBackend().send(command);
    });
  });

  ipcMain.handle('rdp:start', async (event, value: unknown) => {
    const request = parseRdpStartRequest(value);
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow) throw new Error('RDP owner window is unavailable.');

    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      const client = getRdpClient();
      const bounds = toScreenBounds(ownerWindow, request.bounds);
      releaseRdpTunnel(request.sessionId);
      let socksEndpoint = '';
      if (request.profile.nodeId) {
        const leaseId = randomUUID();
        rdpTunnelLeases.set(request.sessionId, leaseId);
        try {
          socksEndpoint = await getNativeBackend().acquireTunnel({
            leaseId,
            nodeId: request.profile.nodeId,
            progressSessionId: request.sessionId,
          });
        } catch (error) {
          if (rdpTunnelLeases.get(request.sessionId) === leaseId) {
            rdpTunnelLeases.delete(request.sessionId);
          }
          throw error;
        }
        if (rdpTunnelLeases.get(request.sessionId) !== leaseId) {
          throw new Error('RDP connection closed while opening its VPN tunnel.');
        }
        if (!socksEndpoint) releaseRdpTunnel(request.sessionId);
      }
      try {
        return await client.start(
          {
            ...request,
            profile: {
              ...request.profile,
              socksEndpoint: socksEndpoint || undefined,
              tunnelEnabled:
                request.profile.nodeId && !socksEndpoint ? false : request.profile.tunnelEnabled,
            },
          },
          nativeWindowHandle(ownerWindow),
          bounds,
        );
      } catch (error) {
        releaseRdpTunnel(request.sessionId);
        throw error;
      }
    });
  });

  ipcMain.handle('rdp:resize', async (event, value: unknown) => {
    const request = parseRdpCommandRequest(value);
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow) throw new Error('RDP owner window is unavailable.');

    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      const client = getRdpClient();
      const bounds = request.bounds ? toScreenBounds(ownerWindow, request.bounds) : undefined;
      return client.resize({ ...request, bounds }, nativeWindowHandle(ownerWindow));
    });
  });

  ipcMain.handle('rdp:command', async (event, value: unknown) => {
    const request = parseRdpCommandRequest(value);
    const operation = valueAsString(value, 'operation');
    if (
      operation !== 'show' &&
      operation !== 'hide' &&
      operation !== 'focus' &&
      operation !== 'disconnect'
    ) {
      throw new Error('Unsupported RDP command.');
    }
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow) throw new Error('RDP owner window is unavailable.');
    const bounds = request.bounds ? toScreenBounds(ownerWindow, request.bounds) : undefined;
    const command = () =>
      getRdpClient().command(operation, request.sessionId, nativeWindowHandle(ownerWindow), bounds);
    if (operation === 'hide' || operation === 'disconnect') {
      const result = command();
      if (operation === 'disconnect') releaseRdpTunnel(request.sessionId);
      return result;
    }
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return command();
    });
  });
}

function getRdpClient(): RdpBackendClient {
  if (rdpClient) return rdpClient;

  const args = ['--operation', 'rdp', '--database', wormholeDatabasePath()];
  const hostPath = nativeRdpHostPath();
  if (hostPath) args.push('--rdp-host', hostPath);
  const configuredFreeRdp = process.env.WORMHOLE_FREERDP_PATH?.trim();
  if (configuredFreeRdp) args.push('--freerdp', configuredFreeRdp);

  rdpClient = new RdpBackendClient({ executable: backendPath(), args });
  rdpClient.onEvent((event: RdpBackendEvent) => {
    if (
      event.sessionId &&
      (event.type === 'disconnected' ||
        event.type === 'fatalError' ||
        event.type === 'logonError' ||
        event.type === 'exited' ||
        event.type === 'error')
    ) {
      releaseRdpTunnel(event.sessionId);
    }
    for (const window of BrowserWindow.getAllWindows()) {
      if (!window.isDestroyed()) window.webContents.send('rdp:event', event);
    }
  });
  return rdpClient;
}

function releaseRdpTunnel(sessionId: string): void {
  const leaseId = rdpTunnelLeases.get(sessionId);
  if (!leaseId) return;
  rdpTunnelLeases.delete(sessionId);
  void nativeBackend?.releaseTunnel(leaseId).catch(() => undefined);
}

function getSerialBackend(): SerialBackendClient {
  if (serialBackend) return serialBackend;

  const client = new SerialBackendClient({
    executable: backendPath(),
    args: [
      '--operation',
      'serial',
      '--database',
      wormholeDatabasePath(),
      '--electron-user-data',
      electronUserDataPath(),
    ],
  });
  client.onEvent((event: SerialBackendEvent) => {
    if (event.type === 'screen' && !authSession.isAccessAllowed) return;
    for (const window of BrowserWindow.getAllWindows()) {
      if (!window.isDestroyed()) window.webContents.send('serial:event', event);
    }
  });
  serialBackend = client;
  return client;
}

function nativeWindowHandle(window: BrowserWindow): string {
  const handle = window.getNativeWindowHandle();
  if (handle.length >= 8) return handle.readBigUInt64LE(0).toString();
  if (handle.length >= 4) return handle.readUInt32LE(0).toString();
  throw new Error('RDP native owner window handle is unavailable.');
}

function toScreenBounds(window: BrowserWindow, rect?: RdpSurfaceRect): RdpSurfaceRect | undefined {
  if (!rect) return undefined;
  const content = window.getContentBounds();
  const dipRect = {
    x: content.x + rect.x,
    y: content.y + rect.y,
    width: rect.width,
    height: rect.height,
  };
  if (process.platform === 'win32') {
    // The renderer and Electron window bounds are DIP coordinates, while SetWindowPos in the
    // ActiveX helper needs physical pixels. Electron's conversion handles negative monitor
    // origins and per-monitor DPI correctly, including a window moved between displays.
    const physical = screen.dipToScreenRect(window, dipRect);
    return {
      x: physical.x,
      y: physical.y,
      width: Math.max(1, physical.width),
      height: Math.max(1, physical.height),
    };
  }

  const display = screen.getDisplayNearestPoint({ x: dipRect.x, y: dipRect.y });
  const scale = display.scaleFactor > 0 ? display.scaleFactor : 1;
  return {
    x: Math.round(dipRect.x),
    y: Math.round(dipRect.y),
    width: Math.max(1, Math.round(rect.width * scale)),
    height: Math.max(1, Math.round(rect.height * scale)),
  };
}

function parseRdpStartRequest(value: unknown): RdpStartRequest {
  if (!value || typeof value !== 'object') throw new Error('Invalid RDP start request.');
  const sessionId = valueAsString(value, 'sessionId');
  const profile = valueAsObject(value, 'profile') as RdpProfile;
  const host = typeof profile.host === 'string' ? profile.host.trim() : '';
  if (!sessionId || sessionId.length > 128 || !host || host.length > 253) {
    throw new Error('RDP session or host is invalid.');
  }
  if (
    profile.port !== undefined &&
    (typeof profile.port !== 'number' ||
      !Number.isInteger(profile.port) ||
      profile.port < 0 ||
      profile.port > 65535)
  ) {
    throw new Error('RDP port is invalid.');
  }
  if (typeof profile.password === 'string' && profile.password.length > 4096) {
    throw new Error('RDP password is too long.');
  }
  if (typeof profile.gatewayPassword === 'string' && profile.gatewayPassword.length > 4096) {
    throw new Error('RDP gateway password is too long.');
  }
  return {
    sessionId,
    profile: { ...profile, host },
    bounds: parseOptionalBounds(valueAsUnknown(value, 'bounds')),
  };
}

function parseRdpCommandRequest(value: unknown): RdpCommandRequest {
  if (!value || typeof value !== 'object') throw new Error('Invalid RDP command request.');
  const sessionId = valueAsString(value, 'sessionId');
  if (!sessionId || sessionId.length > 128) throw new Error('RDP session ID is invalid.');
  return {
    sessionId,
    bounds: parseOptionalBounds(valueAsUnknown(value, 'bounds')),
  };
}

function parseOptionalBounds(value: unknown): RdpSurfaceRect | undefined {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object') throw new Error('RDP surface bounds are invalid.');
  const bounds = value as Record<string, unknown>;
  const numbers = ['x', 'y', 'width', 'height'].map((key) => bounds[key]);
  if (!numbers.every((number) => typeof number === 'number' && Number.isFinite(number))) {
    throw new Error('RDP surface bounds are invalid.');
  }
  return {
    x: numbers[0] as number,
    y: numbers[1] as number,
    width: numbers[2] as number,
    height: numbers[3] as number,
  };
}

function valueAsUnknown(value: unknown, key: string): unknown {
  return valueAsRecord(value)[key];
}

function valueAsString(value: unknown, key: string): string {
  const result = valueAsRecord(value)[key];
  return typeof result === 'string' ? result.trim() : '';
}

function valueAsObject(value: unknown, key: string): Record<string, unknown> {
  const result = valueAsRecord(value)[key];
  if (!result || typeof result !== 'object' || Array.isArray(result)) {
    throw new Error(`RDP ${key} is invalid.`);
  }
  return result as Record<string, unknown>;
}

function valueAsRecord(value: unknown): Record<string, any> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Invalid RDP request.');
  }
  return value as Record<string, any>;
}

function createWindow() {
  const productionRendererPath = path.resolve(__dirname, '..', 'dist', 'index.html');
  const window = new BrowserWindow({
    // Keep the window hidden until the renderer has painted its first frame
    // (ready-to-show). Showing it earlier flashes unpainted frames — black
    // (backgroundColor) then the light default page — before the UI appears.
    show: false,
    width: 1440,
    height: 900,
    minWidth: 980,
    minHeight: 640,
    // Matches the renderer's dark theme background (--background in index.css,
    // oklch(0.145 0 0) ~ #0a0a0a) so a not-yet-painted frame during a resize
    // never flashes white.
    backgroundColor: '#0a0a0a',
    icon: path.join(__dirname, '..', 'Assets', 'Wormhole.ico'),
    title: 'Wormhole',
    titleBarStyle: 'hidden',
    ...(process.platform !== 'darwin'
      ? {
          titleBarOverlay: {
            color: nativeTitlebarColor,
            symbolColor: nativeTitlebarSymbolColor,
            height: nativeTitlebarHeight,
          },
        }
      : {}),
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      preload: path.join(__dirname, 'preload.cjs'),
    },
  });

  // Safety net: if the first paint never arrives (failed page load, hung dev
  // server), show the window anyway so the app is never left invisible.
  let showFallbackTimer: NodeJS.Timeout | undefined;
  const showWindow = () => {
    if (showFallbackTimer) clearTimeout(showFallbackTimer);
    if (!window.isDestroyed()) window.show();
  };
  window.once('ready-to-show', showWindow);
  showFallbackTimer = setTimeout(showWindow, 10_000);

  window.webContents.on('did-start-loading', () => {
    webSurfaces.closeForWindow(window);
    void serializeAuthOperation(async () => {
      // A renderer reload creates a fresh UI process context. Do not let a previous renderer's
      // native unlock survive into the new context before it proves possession of the secret.
      authSession.lock();
      sshBackend.cancelAutoSudo();
      sshBackend.closeAllSftp();
      try {
        await sshBackend.setMcpLocked(true);
      } catch {
        // The MCP process is allowed to exit while the renderer is being re-authenticated.
      }
      await rdpClient?.dispose();
    }).catch((error) => {
      console.error('[Wormhole] Could not reset native authentication for the renderer.', error);
    });
  });

  window.webContents.on('preload-error', (_event, preloadPath, error) => {
    console.error(`[Wormhole] Preload failed (${path.basename(preloadPath)}).`, error.message);
  });

  window.once('closed', () => webSurfaces.closeForWindow(window));
  window.webContents.on('will-navigate', (event, targetUrl) => {
    if (!isTrustedRendererNavigation(targetUrl, productionRendererPath)) event.preventDefault();
  });
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));

  if (rendererUrl) {
    void window.loadURL(rendererUrl);
  } else {
    void window.loadFile(productionRendererPath);
  }
}

function isTrustedRendererNavigation(targetUrl: string, productionRendererPath: string): boolean {
  try {
    const target = new URL(targetUrl);
    if (rendererUrl) return target.origin === new URL(rendererUrl).origin;
    return (
      target.protocol === 'file:' && path.resolve(fileURLToPath(target)) === productionRendererPath
    );
  } catch {
    return false;
  }
}

const sshBackend = new NativeSshBackend();
authSession.onUnlocked(() => {
  sshBackend.requestSnapshots();
  serialBackend?.requestSnapshots();
  serialBackend?.requestSnapshots();
  void sshBackend.syncMcpAfterUnlock().catch((error) => {
    console.error('[Wormhole] Could not synchronize the native MCP server after unlock.', error);
  });
});

app.whenReady().then(async () => {
  registerIpcHandlers(sshBackend);
  try {
    // Defense in depth for the in-memory profile: a run starts with no appliance cookies or cache.
    const browserSession = electronSession.fromPartition(webSharedPartition, { cache: true });
    await Promise.all([browserSession.clearStorageData(), browserSession.clearCache()]);
  } catch (error) {
    console.warn('[Wormhole] Could not clear the browser session at startup.', error);
  }
  try {
    await runFirstLaunchMigrations();
  } catch (error) {
    // A failed first attempt remains retryable because no completion marker is written. The app
    // still opens so a missing native dependency or a temporarily locked DB cannot prevent the
    // user from launching Electron and fixing the environment.
    const message = error instanceof Error ? error.message : String(error);
    console.error('[Wormhole] Credential Manager migration failed.', message);
  }

  createWindow();
  void runStartupUpdateCheck();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('before-quit', () => {
  isQuitting = true;
  updateDownloadChild?.kill();
  updateDownloadChild = undefined;
  webSurfaces.closeAll();
  nativeBackend?.stop();
  nativeBackend = undefined;
  serialBackend?.dispose();
  serialBackend = undefined;
  sshBackend.dispose();
  void rdpClient?.dispose();
});

app.on('window-all-closed', () => {
  void rdpClient?.dispose();
  if (process.platform !== 'darwin') app.quit();
});
