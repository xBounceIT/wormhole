import {
  app,
  BrowserWindow,
  clipboard,
  crashReporter,
  dialog,
  ipcMain,
  Menu,
  screen,
  session as electronSession,
  shell,
  webContents as electronWebContents,
  WebContentsView,
} from 'electron';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { createInterface, type Interface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import type { ElectronChromeExtensions } from 'electron-chrome-extensions';
import { AuthSession } from './auth-session.js';
import { hasValidCredentialSecretLength } from './credential-secret-length.js';
import {
  bringMcpApprovalWindowToFront,
  McpApprovalWindowCoordinator,
  selectMcpApprovalWindow,
} from './mcp-approval-window.js';
import {
  connectionTreeExpansionMaxRequestBytes,
  parseConnectionTreeExpansionSetting,
  type ConnectionTreeExpansionSetting,
} from './connection-tree-settings.js';
import { initializeLocalCrashDiagnostics } from './crash-diagnostics.js';
import { isAppTheme, parseThemeStartupRequest, type AppTheme } from './theme-settings.js';
import {
  runWindowTeardown,
  WindowCloseCoordinator,
  WindowCloseReasonTracker,
} from './window-lifecycle.js';
import {
  createBitwardenActiveTabContext,
  selectBitwardenTabRegistrationPartition,
} from './bitwarden-active-tab-bridge.js';
import {
  buildBitwardenBrowserContext,
  buildBitwardenPersistentRouteKey,
  getBitwardenBrowserPartition,
} from './bitwarden-browser-profile.js';
import {
  isPointInsideBitwardenAnchor,
  positionBitwardenPopup,
  type BitwardenPopupAnchor,
} from './bitwarden-popup-layout.js';
import {
  afterBitwardenPopupInputEvent,
  closeBitwardenPopupContents,
} from './bitwarden-popup-lifecycle.js';
import {
  captureBitwardenExtensionStorage,
  restoreBitwardenExtensionStorage,
} from './bitwarden-storage.js';
import {
  buildBitwardenCookieSetDetails,
  buildBitwardenCookieRefreshPlan,
  selectBitwardenCookiesForTarget,
} from './bitwarden-cookie-seed.js';
import { ExtensionMutationGuard } from './extension-mutation-guard.js';
import { readDarwinHardwareModel, shouldDisableHardwareAcceleration } from './gpu-compatibility.js';
import { KeyedSingleFlight } from './keyed-single-flight.js';
import {
  parseWorkspaceNodesRequest,
  workspaceDeleteNodesMaxRequestBytes,
} from './workspace-delete-contract.js';
import { KeyedTaskTracker } from './keyed-task-tracker.js';
import { shouldDeferExtensionReload } from './extension-reload-policy.js';
import { encodeTerminalClipboardText, isEncodedSshInput } from './terminal-clipboard.js';
import {
  isLocalSftpPath,
  isSftpName,
  sshMaxSftpEntryNameLength,
  sshMaxSftpPathLength,
  type SftpNameDestination,
} from './sftp-contract.js';
import { RdpBackendClient, stopChildProcess } from './rdp.js';
import { drainSshBackendSessionIds } from './ssh-backend-lifecycle.js';
import { settleTunnelCleanup, TunnelLeaseRegistry } from './tunnel-lease-registry.js';
import {
  isTunnelIdentifier,
  parseTunnelDetailsResponse,
  parseTunnelSummaryList,
  parseTunnelTestRequest,
} from './tunnel-test-contract.js';
import {
  isSameCertificateHostname,
  isMatchingOAuthRedirect,
  tunnelAuthPartition,
  type TunnelBrowserCompletion,
} from './tunnel-auth.js';
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
import { getInSessionNavigationUrl } from './web-new-window-navigation.js';
import { isSafeUpdateInstallerPath, updateInstallAction } from './update-installer.js';
import { parseWorkspaceRdpSettings, type WorkspaceRdpSettings } from './workspace-rdp-contract.js';
import type {
  RdpBackendEvent,
  RdpCommandRequest,
  RdpExternalClientRequirementRequest,
  RdpProfile,
  RdpStartRequest,
  RdpSurfaceRect,
  RdpSystemClientCapability,
  RdpSystemClientCapabilityRequest,
  RdpSystemClientOpenRequest,
  RdpSystemClientOpenResult,
} from './rdp-contract.js';
import {
  canProceedWithRdpTunnelRoute,
  isRdpLifecycleEvent,
  isRdpSurfaceRectWithinNativeBounds,
  parseRdpExternalClientRequirementRequest,
  rdpGatewayCredentialIdForResolution,
  rdpGatewayUsername,
  rdpTunnelEnabledForNative,
} from './rdp-contract.js';
import {
  parseMRemoteImportInspection,
  parseMRemoteImportOptions,
  parseMRemoteImportPlan,
  parseMRemoteImportResult,
  type MRemoteImportPlan,
} from './mremote-import-contract.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rendererUrl = process.env.VITE_DEV_SERVER_URL;
const nativeTitlebarColor = '#0a0a0a00';
const nativeTitlebarSymbolColor = '#ffffff';
const nativeTitlebarHeight = 48;
const applicationIconPath = path.join(
  __dirname,
  '..',
  'Assets',
  process.platform === 'win32' ? 'Wormhole.ico' : 'Wormhole.png',
);
const startupWindowOpacity = 0.96;
const wormholeDataDirectoryName = 'Wormhole';
const backendTimeoutMs = 30_000;
const backupTimeoutMs = 5 * 60_000;
const nativeLongOperationTimeoutMs = 30 * 60_000;
const tunnelTestTimeoutMs = 315_000;
// The Go installers allow five minutes for the browser ZIP and ten minutes for the CLI ZIP.
// IPC must outlive those inner deadlines or the UI reports a timeout while Go completes later.
const extensionOperationTimeoutMs = 6 * 60_000;
const cliOperationTimeoutMs = 11 * 60_000;
const nativeConnectionTimeoutMs = 315_000;
const backendMaxBuffer = 16 * 1024 * 1024;
const backendMaxRequestBytes = 64 * 1024;

const backendMaxTunnelRequestBytes = 4 * 1024 * 1024;
const nativeBackendLineLimit = 64 * 1024 * 1024;
const nativeBackendCommandTimeoutMs = 15_000;
// Go may spend up to seven seconds cancelling an in-flight establishment and another six
// stopping the resulting sidecar. Keep the broker alive long enough to finish that cleanup.
const nativeBackendShutdownTimeoutMs = 20_000;
const startupUpdateDelayMs = 10_000;
const startupBackgroundDelayMs = 1_500;
const bitwardenBrowserNavigationTimeoutMs = 15_000;
const bitwardenExtensionReadyTimeoutMs = 15_000;
const bitwardenExtensionHostMaxListeners = 64;

// Crashpad must start before any renderer or utility process is created. This adapter keeps every
// report local, records only bounded non-secret context, and degrades without blocking startup.
initializeLocalCrashDiagnostics({
  app,
  reporter: crashReporter,
  platform: process.platform,
  arch: process.arch,
  electronVersion: process.versions.electron ?? 'unknown',
  processId: process.pid,
  localAppData: process.env.LOCALAPPDATA,
});

const forceSoftwareRendering = process.env.WORMHOLE_DISABLE_HARDWARE_ACCELERATION === '1';
const useSoftwareRendering =
  forceSoftwareRendering ||
  shouldDisableHardwareAcceleration({
    platform: process.platform,
    architecture: process.arch,
    hardwareModel: readDarwinHardwareModel(),
    systemVersion: process.getSystemVersion(),
  });
if (useSoftwareRendering) {
  // This must run synchronously before Electron readiness; Chromium cannot change GPU mode later.
  app.disableHardwareAcceleration();
  console.warn(
    forceSoftwareRendering
      ? '[Wormhole] Hardware acceleration disabled by startup override.'
      : '[Wormhole] Hardware acceleration disabled for legacy Intel macOS GPU compatibility.',
  );
}

let rdpClient: RdpBackendClient | undefined;
const rdpTunnelLeases = new TunnelLeaseRegistry();
const rdpTunnelLeaseSessions = new Map<string, string>();
const rdpStartOperations = new KeyedSingleFlight<string>();
const rdpStartAttempts = new WebSessionAttemptTracker();
const rdpSessionAttempts = new WebSessionAttemptTracker();
const rdpConnectingLifecycles = new Map<string, string>();
const vncSessionAttempts = new WebSessionAttemptTracker();
const rdpSurfacePlacements = new Map<
  string,
  { owner: BrowserWindow; rendererBounds: RdpSurfaceRect }
>();
const rdpOwnerSyncTasks = new Map<number, NodeJS.Immediate>();
let serialBackend: SerialBackendClient | undefined;
let latestUpdateCheck: UpdateCheckResult | undefined;
let updateCheckInFlight: Promise<UpdateCheckResult> | undefined;
let updateDownloadChild: ChildProcessWithoutNullStreams | undefined;
let startupUpdateTimer: NodeJS.Timeout | undefined;
let startupUpdateScheduled = false;
let startupBackgroundTimer: NodeJS.Timeout | undefined;
let webSharedSessionReady: Promise<void> | undefined;
const startupReadyWindows = new WeakSet<BrowserWindow>();

type BackendOperation =
  | 'startup'
  | 'startup-unlock'
  | 'workspace'
  | 'mremote-import-inspect'
  | 'mremote-import-analyze'
  | 'mremote-import-commit'
  | 'backup-inspect'
  | 'backup-export'
  | 'backup-import'
  | 'web-target'
  | 'watchguard-import'
  | 'azure-vpn-import'
  | 'rdp-external-client-requirement'
  | 'cisco-profile-import'
  | 'ovpn-file-import'
  | 'credential-create'
  | 'credential-update'
  | 'credential-delete'
  | 'workspace-duplicate-node'
  | 'workspace-delete-node'
  | 'workspace-delete-nodes'
  | 'workspace-show-credentials'
  | 'credentials-for-protocol'
  | 'workspace-update-node'
  | 'workspace-update-node-web-settings'
  | 'workspace-update-node-tunnel'
  | 'workspace-update-node-credential'
  | 'workspace-update-node-inline-credential'
  | 'workspace-node-create'
  | 'workspace-node-update'
  | 'tunnel-create'
  | 'tunnel-list'
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
  | 'settings-set-theme'
  | 'settings-set-prompt-before-tunnel'
  | 'settings-set-update-preferences'
  | 'update-check'
  | 'update-download'
  | 'logs-info'
  | 'settings-set-log-retention'
  | 'settings-set-log-level'
  | 'open-log-file'
  | 'open-logs-folder'
  | 'settings-set-auto-copy-on-select'
  | 'settings-set-confirm-on-tab-close'
  | 'settings-set-sidebar-width'
  | 'settings-set-connection-tree-expansion'
  | 'bitwarden-onboarding-read'
  | 'bitwarden-onboarding-dismiss'
  | 'mcp-status'
  | 'extension-read'
  | 'extension-set-enabled'
  | 'extension-install'
  | 'extension-ensure-installed'
  | 'extension-import-zip'
  | 'extension-import-folder'
  | 'extension-update-if-stale';
type NativeBackendAction =
  | 'vnc.connect'
  | 'vnc.disconnect'
  | 'vnc.pointer'
  | 'vnc.key'
  | 'tunnel.acquire'
  | 'tunnel.forward'
  | 'tunnel.probe'
  | 'tunnel.release'
  | 'tunnel.prompt-response'
  | 'tunnel.route-response'
  | 'backup.export'
  | 'backup.import'
  | 'mremote.import.commit'
  | 'operation.cancel'
  | 'bitwarden.read'
  | 'bitwarden.set-enabled'
  | 'bitwarden.set-config'
  | 'bitwarden.install'
  | 'bitwarden.ensure-installed'
  | 'bitwarden.status'
  | 'bitwarden.login'
  | 'bitwarden.unlock'
  | 'bitwarden.logout'
  | 'bitwarden.sync'
  | 'bitwarden.sync-if-stale'
  | 'bitwarden.list'
  | 'bitwarden.search'
  | 'bitwarden.get'
  | 'bitwarden.resolve-credential'
  | 'bitwarden.resolve-node'
  | 'rdp.resolve-credential'
  | 'rdp.resolve-profile'
  | 'rdp.system-client-capability'
  | 'rdp.resolve-system-profile'
  | 'bitwarden.node-reference'
  | 'bitwarden.browser-storage-read'
  | 'bitwarden.browser-storage-capture'
  | 'bitwarden.browser-profile-seed'
  | 'bitwarden.browser-profile-register'
  | 'bitwarden.clear-session';
type NativeBackendCommand = {
  action: NativeBackendAction;
  sessionId?: string;
  nodeId?: string;
  credentialId?: string;
  host?: string;
  port?: number;
  username?: string;
  domain?: string;
  password?: string;
  passwordProvided?: boolean;
  manualCredentials?: boolean;
  x?: number;
  y?: number;
  buttons?: number;
  down?: boolean;
  keysym?: number;
  tunnelConfigId?: string;
  dedicated?: boolean;
  promptId?: string;
  value?: string;
  cancelled?: boolean;
  progressSessionId?: string;
  enabled?: boolean;
  path?: string;
  serverRegion?: number;
  email?: string;
  masterPassword?: string;
  authenticatorCode?: string;
  query?: string;
  itemId?: string;
  protocol?: CredentialProtocol;
  localJson?: string;
  sessionJson?: string;
  sourceRevision?: number;
  profilePath?: string;
  structureOnly?: boolean;
  planNonce?: string;
  planToken?: string;
};
type BackendResponse = {
  id: string;
  ok: boolean;
  error?: string;
  socksEndpoint?: string;
  forwardHost?: string;
  forwardPort?: number;
  tunnelActive?: boolean;
  leaseId?: string;
  result?: unknown;
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
  confirmation?: boolean;
  acceptLabel?: string;
  urls?: string[];
  ignoreCertificateErrors?: boolean;
  leaseId?: string;
  phase?: string;
  detail?: string;
  percent?: number;
  connectionName?: string;
  tunnelName?: string;
};
type MigrationResponse = {
  status: 'completed' | 'already-completed' | 'skipped-non-windows';
  migrated: number;
  missing: number;
};
type AppSettings = {
  theme: AppTheme;
  promptBeforeTunnelConnect: boolean;
  autoCopyOnSelect: boolean;
  confirmOnTabClose: boolean;
  sidebarWidth: number;
  connectionTreeExpansion: ConnectionTreeExpansionSetting | null;
  autoCheckForUpdates: boolean;
  lastUpdateCheck: string | null;
  skippedUpdateVersion: string | null;
};

const windowCloseCoordinators = new WeakMap<BrowserWindow, WindowCloseCoordinator>();
const closeConfirmationReadyWindows = new WeakSet<BrowserWindow>();
const closeConfirmationWaiters = new Map<
  string,
  { webContentsId: number; resolve: (confirmed: boolean) => void }
>();
const rendererTeardownWaiters = new Map<
  string,
  { webContentsId: number; resolve: () => void; timer: NodeJS.Timeout }
>();

function requestRendererTeardown(window: BrowserWindow, timeoutMs = 5_000): Promise<void> {
  if (window.isDestroyed() || window.webContents.isDestroyed()) return Promise.resolve();
  const requestId = randomUUID();
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      rendererTeardownWaiters.delete(requestId);
      resolve();
    }, timeoutMs);
    rendererTeardownWaiters.set(requestId, {
      webContentsId: window.webContents.id,
      resolve: () => {
        clearTimeout(timer);
        rendererTeardownWaiters.delete(requestId);
        resolve();
      },
      timer,
    });
    try {
      window.webContents.send('lifecycle:prepare-close', requestId);
    } catch {
      rendererTeardownWaiters.get(requestId)?.resolve();
    }
  });
}

function requestRendererCloseConfirmation(
  window: BrowserWindow | undefined,
  activeSessionCount: number,
  action: 'window' | 'quit',
): Promise<boolean> {
  if (
    !window ||
    window.isDestroyed() ||
    window.webContents.isDestroyed() ||
    !closeConfirmationReadyWindows.has(window)
  ) {
    return Promise.resolve(false);
  }
  const requestId = randomUUID();
  return new Promise((resolve) => {
    const finish = (confirmed: boolean) => {
      closeConfirmationWaiters.delete(requestId);
      window.webContents.removeListener('destroyed', rendererDestroyed);
      resolve(confirmed);
    };
    const rendererDestroyed = () => finish(false);
    closeConfirmationWaiters.set(requestId, {
      webContentsId: window.webContents.id,
      resolve: finish,
    });
    window.webContents.once('destroyed', rendererDestroyed);
    try {
      window.webContents.send('lifecycle:confirm-close', requestId, {
        activeSessionCount,
        action,
      });
    } catch {
      finish(false);
    }
  });
}
type StartupResponse = {
  auth: AuthStateResponse;
  workspace?: WorkspaceResponse;
  settings: AppSettings;
  themeMigration: {
    handled: boolean;
    migrated: boolean;
  };
  migration: MigrationResponse;
  migrationFailed: boolean;
};

type StartupUnlockResponse = {
  succeeded: boolean;
  message: string;
  workspace?: WorkspaceResponse;
};
type UpdateCheckResult = {
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
  credentialOptions: Record<CredentialProtocol, WorkspaceCredential[]>;
  tunnels: unknown[];
};
type BackupInspectBackendResponse = {
  encrypted: boolean;
  schemaVersion: number;
  exportedAt: string;
};
type BackupExportBackendResponse = {
  path: string;
  nodeCount: number;
  credentialCount: number;
  tunnelCount: number;
  passwordCount: number;
  privateKeyCount: number;
  tunnelPayloadCount: number;
  encrypted: boolean;
};
type BackupExportResponse = Omit<BackupExportBackendResponse, 'path'> & {
  fileName: string;
};
type BackupImportResponse = {
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
};
type BackupImportSelection = BackupInspectBackendResponse & {
  fileName: string;
};
type WorkspaceCredential = {
  id: string;
  name: string;
  protocol: CredentialProtocol;
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
};
type CredentialProtocol = 'ssh' | 'rdp' | 'vnc';
type CredentialWriteRequest = {
  name: string;
  protocol: CredentialProtocol;
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
};
type CredentialCreateRequest = Omit<
  CredentialWriteRequest,
  'provider' | 'bitwardenItemId' | 'bitwardenItemName' | 'bitwardenFieldPath'
> & { provider: 'Local' };
type CredentialUpdateRequest = CredentialWriteRequest & { id: string };
type CredentialDeleteRequest = { id: string };
type WorkspaceNodeRequest = { nodeId: string };
type WorkspaceDuplicateNodeResponse = { nodeId: string; name: string };
type WorkspaceDeleteNodeResponse = { deleted: boolean };
type WorkspaceCredentialRevealResponse = {
  found: boolean;
  connectionName: string;
  credentialName?: string;
  username?: string;
  domain?: string;
  secretLabel?: string;
  secret?: string;
};
type WorkspaceNodeSshSettingsRequest = {
  nodeId: string;
  sshAutoSudo: boolean | null;
};
type WorkspaceNodeWebSettingsRequest = {
  nodeId: string;
  httpIgnoreCertErrors: boolean | null;
};
type WorkspaceNodeWriteRequest = {
  id?: string;
  parentId: string;
  name: string;
  kind: 'folder' | 'connection';
  protocol: '' | 'ssh' | 'rdp' | 'http' | 'https' | 'vnc' | 'serial';
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
  rdp?: WorkspaceRdpSettings;
};
type WebTargetResponse = {
  url: string;
  protocol: 'http' | 'https';
  host: string;
  port: number;
  ignoreCertErrors: boolean;
  tunnelConfigId?: string;
  proxyUrl?: string;
  bitwarden?: {
    partition: string;
    popupUrl: string;
  };
};
type BitwardenExtensionState = {
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
};
type WorkspaceNodeCredentialSettingsRequest = {
  nodeId: string;
  mode: 0 | 1 | 2;
  credentialId: string;
};
type WorkspaceNodeInlineCredentialRequest = {
  nodeId: string;
  protocol: 'ssh' | 'rdp';
  username: string;
  domain: string;
  password: string;
};
type BitwardenCliState = {
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
};
type BitwardenCliStatusResponse = {
  status: 'Unauthenticated' | 'Locked' | 'Unlocked' | 'Unknown';
  userEmail: string | null;
  serverUrl: string | null;
  lastSync?: string;
  hasSessionKey?: boolean;
};
type BitwardenCliLoginItem = {
  id: string;
  name: string;
  username?: string;
  revisionDate?: string;
};
type WebOpenRequest = {
  sessionId: string;
  attempt: number;
  nodeId?: string;
  address?: string;
  port?: number;
  protocol?: 'http' | 'https';
  ignoreCertErrors?: boolean;
  tunnelConfigId?: string;
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
  operation: 'back' | 'forward' | 'reload' | 'stop';
};
type TreeTooltipRequest = {
  text: string;
  anchor: { x: number; y: number; width: number; height: number };
  width: number;
};
type BitwardenPopupOpenRequest = {
  sessionId: string;
  anchor: BitwardenPopupAnchor;
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
type ActiveTunnelTest = {
  leaseId: string;
  attempt: number;
  cancelled: boolean;
  backend?: NativeBackendProcess;
  leases: TunnelLeaseRegistry;
  sender: Electron.WebContents;
  lastProgress?: string;
};
type NativeOperationKind = 'backup-export' | 'backup-import' | 'mremote-import';
type ActiveNativeOperation = {
  id: string;
  kind: NativeOperationKind;
  backend: NativeBackendProcess;
  sender: Electron.WebContents;
};
type AuthStateResponse = {
  mode: string;
  configured: boolean;
};

type WormholeLogsInfo = {
  currentLogFilePath: string;
  logsDirectoryPath: string;
  logRetentionDays: number;
  logLevel: string;
};

const authSession = new AuthSession();
let authOperationQueue: Promise<void> = Promise.resolve();
let currentAuthState: AuthStateResponse | undefined;
let authRefreshInFlight: Promise<AuthStateResponse> | undefined;
const backupImportSelections = new WeakMap<Electron.WebContents, string>();
type SshPrivateKeySelection = { id: string; path: string; fileName: string };
const sshPrivateKeySelections = new WeakMap<Electron.WebContents, SshPrivateKeySelection>();
type MRemoteImportSelection = {
  path: string;
  planNonce?: string;
  planToken?: string;
  structureOnly?: boolean;
};
const mremoteImportSelections = new WeakMap<Electron.WebContents, MRemoteImportSelection>();
const mremoteImportAnalysis = new WeakMap<Electron.WebContents, AbortController>();
let authStateMutationQueue: Promise<void> = Promise.resolve();
let authLockRequested = false;
let bitwardenExtensionOperationQueue: Promise<void> = Promise.resolve();

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
  alternateScreen: boolean;
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
      retainTunnelLease: boolean;
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
      entries: SshSftpEntry[];
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
};

type SshHostKeyTrustRequest = {
  sessionId: string;
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
const sshMaxTerminalCells = 500 * 500;
const sshMaxTerminalScrollbackLines = 5000;
const sshMaxTerminalScrollbackLineLength = 2048;
const sshMaxSftpEntries = 4096;
const sshMaxBackendErrorLength = 4096;
const sshMaxSftpQuickPaths = 64;
const sshMaxSftpQuickPathLabelLength = 256;
const credentialMaxNameLength = 256;
const credentialMaxUsernameLength = 512;
const credentialMaxDomainLength = 512;
const credentialMaxPasswordLength = 4096;
const backupMaxPasswordBytes = 16 * 1024;
const backupMaxWarnings = 1000;
const backupMaxWarningLength = 1024;
const credentialMaxBitwardenItemIdLength = 512;
const credentialMaxBitwardenItemNameLength = 1024;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function parseBackupPasswordRequest(value: unknown): { password: string } {
  if (!isRecord(value) || typeof value.password !== 'string') {
    throw new Error('Backup password is invalid.');
  }
  if (Buffer.byteLength(value.password, 'utf8') > backupMaxPasswordBytes) {
    throw new Error('Backup password is too long.');
  }
  return { password: value.password };
}

function isBackupCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function parseBackupInspectResponse(value: unknown): BackupInspectBackendResponse {
  if (
    !isRecord(value) ||
    typeof value.encrypted !== 'boolean' ||
    !Number.isSafeInteger(value.schemaVersion) ||
    typeof value.exportedAt !== 'string' ||
    value.exportedAt.length > 128 ||
    (value.exportedAt.length > 0 && Number.isNaN(Date.parse(value.exportedAt)))
  ) {
    throw new Error('The backup inspector returned an invalid result.');
  }
  return {
    encrypted: value.encrypted,
    schemaVersion: value.schemaVersion as number,
    exportedAt: value.exportedAt,
  };
}

function parseBackupExportResponse(value: unknown, selectedPath: string): BackupExportResponse {
  if (!isRecord(value) || value.path !== selectedPath || typeof value.encrypted !== 'boolean') {
    throw new Error('The backup exporter returned an invalid result.');
  }
  const countFields = [
    'nodeCount',
    'credentialCount',
    'tunnelCount',
    'passwordCount',
    'privateKeyCount',
    'tunnelPayloadCount',
  ] as const;
  if (countFields.some((field) => !isBackupCount(value[field]))) {
    throw new Error('The backup exporter returned an invalid result.');
  }
  return {
    fileName: path.basename(selectedPath),
    nodeCount: value.nodeCount as number,
    credentialCount: value.credentialCount as number,
    tunnelCount: value.tunnelCount as number,
    passwordCount: value.passwordCount as number,
    privateKeyCount: value.privateKeyCount as number,
    tunnelPayloadCount: value.tunnelPayloadCount as number,
    encrypted: value.encrypted,
  };
}

function parseBackupImportResponse(value: unknown): BackupImportResponse {
  if (!isRecord(value)) throw new Error('The backup importer returned an invalid result.');
  const countFields = [
    'nodesImported',
    'nodesSkipped',
    'credentialsImported',
    'credentialsSkipped',
    'tunnelsImported',
    'tunnelsSkipped',
    'passwordsImported',
    'privateKeysImported',
    'tunnelPayloadsImported',
  ] as const;
  if (
    countFields.some((field) => !isBackupCount(value[field])) ||
    !Array.isArray(value.warnings) ||
    value.warnings.length > backupMaxWarnings ||
    value.warnings.some(
      (warning) => typeof warning !== 'string' || warning.length > backupMaxWarningLength,
    )
  ) {
    throw new Error('The backup importer returned an invalid result.');
  }
  return {
    nodesImported: value.nodesImported as number,
    nodesSkipped: value.nodesSkipped as number,
    credentialsImported: value.credentialsImported as number,
    credentialsSkipped: value.credentialsSkipped as number,
    tunnelsImported: value.tunnelsImported as number,
    tunnelsSkipped: value.tunnelsSkipped as number,
    passwordsImported: value.passwordsImported as number,
    privateKeysImported: value.privateKeysImported as number,
    tunnelPayloadsImported: value.tunnelPayloadsImported as number,
    warnings: value.warnings as string[],
  };
}

function parseCliLoginRequest(value: unknown): {
  email: string;
  masterPassword: string;
  authenticatorCode?: string;
  serverRegion: number;
} {
  if (!isRecord(value)) throw new Error('Bitwarden CLI login request is invalid.');
  const email = typeof value.email === 'string' ? value.email : '';
  const masterPassword = typeof value.masterPassword === 'string' ? value.masterPassword : '';
  const authenticatorCode =
    typeof value.authenticatorCode === 'string' ? value.authenticatorCode : undefined;
  const serverRegion = typeof value.serverRegion === 'number' ? value.serverRegion : -1;
  if (email.length === 0 || email.length > 512) throw new Error('Bitwarden email is invalid.');
  if (masterPassword.length === 0 || masterPassword.length > 4096)
    throw new Error('Bitwarden master password is invalid.');
  if (authenticatorCode && authenticatorCode.length > 64)
    throw new Error('Bitwarden authenticator code is invalid.');
  if (!Number.isInteger(serverRegion) || serverRegion < 0 || serverRegion > 2)
    throw new Error('Bitwarden server region is invalid.');
  return { email, masterPassword, authenticatorCode, serverRegion };
}

function isSshSessionId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= sshMaxSessionIdLength &&
    value.trim() === value
  );
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(value);
}

// Omit the `persist:` prefix so appliance cookies and cache remain available to tabs during this
// Electron run but are never written to disk after the app closes.
const webSharedPartition = 'wormhole-web';
const webMaxUrlLength = 4096;
const webMaxAddressLength = 4096;
const webMaxSurfaceCoordinate = 100_000;

function ensureWebSharedSessionReady(): Promise<void> {
  if (!webSharedSessionReady) {
    const browserSession = electronSession.fromPartition(webSharedPartition, {
      cache: true,
    });
    webSharedSessionReady = Promise.all([
      browserSession.clearStorageData(),
      browserSession.clearCache(),
    ])
      .then(() => undefined)
      .catch((error) => {
        // Clearing an in-memory partition is defense in depth. A failure should not prevent the
        // user from opening an appliance, and this lazy path keeps the work off app startup.
        console.warn('[Wormhole] Could not clear the browser session.', error);
      });
  }
  return webSharedSessionReady;
}

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
      value.port === undefined &&
      value.protocol === undefined &&
      value.ignoreCertErrors === undefined &&
      value.tunnelConfigId === undefined
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
  return (
    (value.port === undefined ||
      (typeof value.port === 'number' &&
        Number.isInteger(value.port) &&
        value.port >= 1 &&
        value.port <= 65535)) &&
    (value.ignoreCertErrors === undefined || typeof value.ignoreCertErrors === 'boolean') &&
    (value.tunnelConfigId === undefined || isTunnelID(value.tunnelConfigId))
  );
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
    (value.operation === 'back' ||
      value.operation === 'forward' ||
      value.operation === 'reload' ||
      value.operation === 'stop')
  );
}

function isTreeTooltipRequest(value: unknown): value is TreeTooltipRequest {
  if (!isRecord(value) || typeof value.text !== 'string' || value.text.length > 512) return false;
  if (!isRecord(value.anchor)) return false;
  const anchor = value.anchor;
  return (
    value.text.length > 0 &&
    typeof value.width === 'number' &&
    Number.isFinite(value.width) &&
    value.width >= 48 &&
    value.width <= 328 &&
    ['x', 'y', 'width', 'height'].every(
      (key) => typeof anchor[key] === 'number' && Number.isFinite(anchor[key]),
    )
  );
}

function isBitwardenPopupOpenRequest(value: unknown): value is BitwardenPopupOpenRequest {
  if (!isRecord(value) || !isSshSessionId(value.sessionId) || !isRecord(value.anchor)) {
    return false;
  }
  const anchor = value.anchor;
  for (const field of ['x', 'y', 'width', 'height'] as const) {
    const coordinate = anchor[field];
    if (
      typeof coordinate !== 'number' ||
      !Number.isFinite(coordinate) ||
      coordinate < 0 ||
      coordinate > webMaxSurfaceCoordinate
    ) {
      return false;
    }
  }
  return (
    typeof anchor.width === 'number' &&
    anchor.width > 0 &&
    typeof anchor.height === 'number' &&
    anchor.height > 0
  );
}

function hasValidSshKeyPassphraseOverride(value: Record<string, unknown>): boolean {
  return (
    (value.manualKeyPassphrase === undefined || typeof value.manualKeyPassphrase === 'boolean') &&
    (value.keyPassphrase === undefined ||
      (typeof value.keyPassphrase === 'string' &&
        value.keyPassphrase.length > 0 &&
        hasValidCredentialSecretLength(value.keyPassphrase))) &&
    (value.manualKeyPassphrase === true) === (value.keyPassphrase !== undefined)
  );
}

function isSshOpenRequest(value: unknown): value is SshOpenRequest {
  if (
    !isRecord(value) ||
    !isSshSessionId(value.sessionId) ||
    typeof value.columns !== 'number' ||
    !Number.isInteger(value.columns) ||
    value.columns < 0 ||
    value.columns > 500 ||
    typeof value.rows !== 'number' ||
    !Number.isInteger(value.rows) ||
    value.rows < 0 ||
    value.rows > 500
  ) {
    return false;
  }

  if (value.nodeId !== undefined) {
    return (
      isSshSessionId(value.nodeId) &&
      value.host === undefined &&
      value.port === undefined &&
      value.tunnelConfigId === undefined &&
      value.autoSudo === undefined &&
      (value.credentialId === undefined || isTunnelID(value.credentialId)) &&
      (value.manualCredentials === undefined || typeof value.manualCredentials === 'boolean') &&
      (value.manualCredentials !== true || value.credentialId === undefined) &&
      hasValidSshKeyPassphraseOverride(value) &&
      !(value.manualCredentials === true && value.manualKeyPassphrase === true) &&
      (value.username === undefined ||
        (typeof value.username === 'string' &&
          value.username.length <= credentialMaxUsernameLength)) &&
      (value.password === undefined ||
        (typeof value.password === 'string' &&
          Buffer.byteLength(value.password, 'utf8') <= credentialMaxPasswordLength)) &&
      (value.manualCredentials !== true ||
        (typeof value.username === 'string' && value.username.trim().length > 0))
    );
  }

  const host = value.host;
  const username = value.username;
  const password = value.password;
  const credentialId = value.credentialId;
  return (
    typeof host === 'string' &&
    host.trim().length > 0 &&
    host.length <= 4096 &&
    !/[\r\n\0]/.test(host) &&
    ((isTunnelID(credentialId) && username === undefined && password === undefined) ||
      (credentialId === undefined &&
        typeof username === 'string' &&
        username.trim().length > 0 &&
        username.length <= credentialMaxUsernameLength &&
        !/[\r\n\0]/.test(username) &&
        typeof password === 'string' &&
        Buffer.byteLength(password, 'utf8') <= credentialMaxPasswordLength)) &&
    (value.port === undefined ||
      (typeof value.port === 'number' &&
        Number.isInteger(value.port) &&
        value.port >= 1 &&
        value.port <= 65535)) &&
    (value.tunnelConfigId === undefined || isTunnelID(value.tunnelConfigId)) &&
    (value.autoSudo === undefined || typeof value.autoSudo === 'boolean') &&
    hasValidSshKeyPassphraseOverride(value) &&
    (value.manualKeyPassphrase !== true || credentialId !== undefined) &&
    value.manualCredentials !== true
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

function parseWorkspaceNodeRequest(value: unknown): WorkspaceNodeRequest {
  if (!isRecord(value) || !isSshSessionId(value.nodeId)) {
    throw new Error('Workspace connection is invalid.');
  }
  return { nodeId: value.nodeId };
}

function sshPrivateKeyDisplayName(filePath: string): string {
  const fileName = path.basename(filePath);
  const characters = Array.from(fileName);
  if (
    fileName.length === 0 ||
    characters.length > credentialMaxNameLength ||
    characters.some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f);
    })
  ) {
    return 'SSH private key';
  }
  return fileName;
}

function parseCredentialWriteRequest(value: unknown, updating = false): CredentialWriteRequest {
  if (!isRecord(value)) throw new Error('Credential details are invalid.');
  const name = value.name;
  const protocol = value.protocol;
  const kind =
    value.kind === 'sshKey' ? 'sshKey' : value.kind === 'password' ? 'password' : undefined;
  const username = value.username;
  const domain = value.domain;
  const password = value.password;
  const passphrase = value.passphrase;
  const clearPassphrase = value.clearPassphrase;
  const privateKeySelectionId =
    typeof value.privateKeySelectionId === 'string' && value.privateKeySelectionId.length > 0
      ? value.privateKeySelectionId
      : undefined;
  const provider =
    value.provider === 'Bitwarden' ? 'Bitwarden' : value.provider === 'Local' ? 'Local' : undefined;
  const bitwardenItemId = typeof value.bitwardenItemId === 'string' ? value.bitwardenItemId : '';
  const bitwardenItemName =
    typeof value.bitwardenItemName === 'string' ? value.bitwardenItemName : '';
  if (
    typeof name !== 'string' ||
    name.length > credentialMaxNameLength ||
    kind === undefined ||
    typeof username !== 'string' ||
    username.length > credentialMaxUsernameLength ||
    typeof domain !== 'string' ||
    domain.length > credentialMaxDomainLength ||
    typeof password !== 'string' ||
    password.length > credentialMaxPasswordLength ||
    typeof passphrase !== 'string' ||
    !hasValidCredentialSecretLength(passphrase) ||
    typeof clearPassphrase !== 'boolean' ||
    provider === undefined ||
    (privateKeySelectionId !== undefined && !isUuid(privateKeySelectionId)) ||
    (kind === 'password' && provider === 'Local' && password.length === 0 && !updating) ||
    (kind === 'password' &&
      provider === 'Bitwarden' &&
      (bitwardenItemId.trim().length === 0 ||
        bitwardenItemId.length > credentialMaxBitwardenItemIdLength ||
        bitwardenItemName.length > credentialMaxBitwardenItemNameLength)) ||
    (kind === 'password' &&
      (passphrase.length !== 0 || clearPassphrase || privateKeySelectionId !== undefined)) ||
    (kind === 'sshKey' &&
      (protocol !== 'ssh' ||
        provider !== 'Local' ||
        password.length !== 0 ||
        domain.trim().length !== 0 ||
        bitwardenItemId.length !== 0 ||
        bitwardenItemName.length !== 0 ||
        (clearPassphrase && (!updating || passphrase.length !== 0)) ||
        (!updating && privateKeySelectionId === undefined))) ||
    (protocol !== 'ssh' && protocol !== 'rdp' && protocol !== 'vnc')
  ) {
    throw new Error('Credential details are invalid.');
  }
  return {
    name,
    protocol,
    kind,
    username,
    domain,
    password,
    passphrase,
    clearPassphrase,
    privateKeySelectionId,
    provider,
    bitwardenItemId,
    bitwardenItemName,
    bitwardenFieldPath: 'login.password',
  };
}

function parseCredentialCreateRequest(value: unknown): CredentialCreateRequest {
  const request = parseCredentialWriteRequest(value);
  if (request.provider !== 'Local') {
    throw new Error('Bitwarden credential profiles cannot be created manually.');
  }
  return {
    name: request.name,
    protocol: request.protocol,
    kind: request.kind,
    username: request.username,
    domain: request.domain,
    password: request.password,
    passphrase: request.passphrase,
    clearPassphrase: request.clearPassphrase,
    privateKeySelectionId: request.privateKeySelectionId,
    provider: 'Local',
  };
}

function parseWorkspaceNodeWriteRequest(
  value: unknown,
  updating: boolean,
): WorkspaceNodeWriteRequest {
  if (!isRecord(value)) throw new Error('Workspace node is invalid.');
  const id = typeof value.id === 'string' ? value.id.trim() : '';
  const parentId = typeof value.parentId === 'string' ? value.parentId.trim() : '';
  const name = typeof value.name === 'string' ? value.name.trim() : '';
  const kind = value.kind;
  const protocol = value.protocol;
  const host = typeof value.host === 'string' ? value.host.trim() : '';
  const port = value.port;
  const username = typeof value.username === 'string' ? value.username.trim() : '';
  const inlinePasswordAction = value.inlinePasswordAction;
  const inlinePassword = value.inlinePassword;
  const credentialMode = value.credentialMode;
  const credentialId = typeof value.credentialId === 'string' ? value.credentialId.trim() : '';
  const tunnelConfigId =
    typeof value.tunnelConfigId === 'string' ? value.tunnelConfigId.trim() : '';
  const nullableBoolean = (candidate: unknown) =>
    candidate === null || typeof candidate === 'boolean';
  const validProtocol =
    protocol === '' ||
    protocol === 'ssh' ||
    protocol === 'rdp' ||
    protocol === 'http' ||
    protocol === 'https' ||
    protocol === 'vnc' ||
    protocol === 'serial';
  if (
    (updating ? !isSshSessionId(id) : id !== '') ||
    (parentId !== '' && !isSshSessionId(parentId)) ||
    name.length === 0 ||
    name.length > 256 ||
    (kind !== 'folder' && kind !== 'connection') ||
    !validProtocol ||
    (kind === 'connection' && (protocol === '' || host.length === 0)) ||
    (kind === 'folder' && (protocol !== '' || host !== '')) ||
    host.length > webMaxAddressLength ||
    username.length > credentialMaxUsernameLength ||
    typeof port !== 'number' ||
    !Number.isSafeInteger(port) ||
    port < 0 ||
    port > 65535 ||
    ((kind === 'folder' || protocol === 'serial') && port !== 0) ||
    !nullableBoolean(value.sshAutoSudo) ||
    !nullableBoolean(value.httpIgnoreCertErrors) ||
    !nullableBoolean(value.tunnelEnabled) ||
    tunnelConfigId.length > sshMaxSessionIdLength ||
    (credentialMode !== 0 && credentialMode !== 1 && credentialMode !== 2) ||
    (credentialMode === 2 ? !isSshSessionId(credentialId) : credentialId !== '') ||
    (inlinePasswordAction !== 'preserve' &&
      inlinePasswordAction !== 'set' &&
      inlinePasswordAction !== 'clear') ||
    typeof inlinePassword !== 'string' ||
    inlinePassword.length > credentialMaxPasswordLength ||
    (inlinePasswordAction === 'set' ? inlinePassword.length === 0 : inlinePassword.length !== 0) ||
    (protocol !== 'ssh' && protocol !== 'rdp' && inlinePasswordAction !== 'clear')
  ) {
    throw new Error('Workspace node is invalid.');
  }
  const serialValues = [
    value.serialBaudRate,
    value.serialDataBits,
    value.serialStopBits,
    value.serialParity,
    value.serialFlowControl,
  ];
  if (
    !serialValues.every(
      (candidate) =>
        typeof candidate === 'number' && Number.isSafeInteger(candidate) && candidate >= 0,
    )
  ) {
    throw new Error('Workspace serial settings are invalid.');
  }
  const rdp = protocol === 'rdp' ? parseWorkspaceRdpSettings(value.rdp) : undefined;
  if (protocol !== 'rdp' && value.rdp !== undefined) {
    throw new Error('RDP settings are invalid for this protocol.');
  }
  return {
    ...(updating ? { id } : {}),
    parentId,
    name,
    kind,
    protocol,
    host,
    port,
    username,
    inlinePasswordAction,
    inlinePassword,
    sshAutoSudo: value.sshAutoSudo as boolean | null,
    httpIgnoreCertErrors: value.httpIgnoreCertErrors as boolean | null,
    tunnelEnabled: value.tunnelEnabled as boolean | null,
    tunnelConfigId,
    credentialMode,
    credentialId,
    serialBaudRate: value.serialBaudRate as number,
    serialDataBits: value.serialDataBits as number,
    serialStopBits: value.serialStopBits as number,
    serialParity: value.serialParity as number,
    serialFlowControl: value.serialFlowControl as number,
    rdp,
  };
}

function isWorkspaceNodeCredentialSettingsRequest(
  value: unknown,
): value is WorkspaceNodeCredentialSettingsRequest {
  return (
    isRecord(value) &&
    isSshSessionId(value.nodeId) &&
    (value.mode === 0 || value.mode === 1 || value.mode === 2) &&
    typeof value.credentialId === 'string' &&
    (value.mode !== 2 || isUuid(value.credentialId))
  );
}

function isWorkspaceNodeInlineCredentialRequest(
  value: unknown,
): value is WorkspaceNodeInlineCredentialRequest {
  return (
    isRecord(value) &&
    isSshSessionId(value.nodeId) &&
    (value.protocol === 'ssh' || value.protocol === 'rdp') &&
    typeof value.username === 'string' &&
    value.username.trim().length > 0 &&
    value.username.length <= credentialMaxUsernameLength &&
    !/[\r\n\0]/.test(value.username) &&
    typeof value.domain === 'string' &&
    value.domain.length <= credentialMaxUsernameLength &&
    !/[\r\n\0]/.test(value.domain) &&
    typeof value.password === 'string' &&
    value.password.length > 0 &&
    Buffer.byteLength(value.password, 'utf8') <= credentialMaxPasswordLength
  );
}

function parseCredentialUpdateRequest(value: unknown): CredentialUpdateRequest {
  const request = parseCredentialWriteRequest(value, true);
  const id = isRecord(value) ? value.id : undefined;
  if (!isUuid(id)) {
    throw new Error('Credential id is invalid.');
  }
  return { ...request, id };
}

function parseCredentialDeleteRequest(value: unknown): CredentialDeleteRequest {
  const id = isRecord(value) ? value.id : undefined;
  if (!isUuid(id)) {
    throw new Error('Credential id is invalid.');
  }
  return { id };
}

function isSshInput(value: unknown): value is string {
  return isEncodedSshInput(value);
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

function isSftpTransferItem(
  value: unknown,
  destination: SftpNameDestination,
): value is SshSftpTransferItem {
  return (
    isRecord(value) &&
    typeof value.sourcePath === 'string' &&
    value.sourcePath.length > 0 &&
    Buffer.byteLength(value.sourcePath, 'utf8') <= sshMaxSftpPathLength &&
    isSftpName(value.name, destination) &&
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
    (value.direction === 'local-to-remote'
      ? !isSftpPath(value.destinationPath)
      : !isLocalSftpPath(value.destinationPath))
  ) {
    return false;
  }
  const destination = value.direction === 'local-to-remote' ? 'remote' : 'local';
  if (!value.items.every((item) => isSftpTransferItem(item, destination))) return false;
  const sourceIsLocal = value.direction !== 'remote-to-local';
  return value.items.every((item) =>
    sourceIsLocal ? isLocalSftpPath(item.sourcePath) : isSftpPath(item.sourcePath),
  );
}

function isSftpEntry(value: unknown, pane: SshSftpPane = 'remote'): value is SshSftpWireEntry {
  if (!isRecord(value)) return false;
  return (
    isSftpName(value.name, pane) &&
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

function isSshHostKeyMismatch(expected: string | undefined, received: string | undefined): boolean {
  return Boolean(expected && received && expected !== received);
}

function isSshHostKeyTrustRequest(value: unknown): value is SshHostKeyTrustRequest {
  return (
    isRecord(value) &&
    isSshSessionId(value.sessionId) &&
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
    typeof value.alternate_screen !== 'boolean' ||
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
    alternateScreen: value.alternate_screen,
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
  if (value.type === 'reconnecting' || value.type === 'reconnect-failed') {
    if (
      typeof value.error !== 'string' ||
      value.error.length > sshMaxBackendErrorLength ||
      typeof value.attempt !== 'number' ||
      !Number.isInteger(value.attempt) ||
      value.attempt < 1 ||
      value.attempt > 10 ||
      typeof value.max_attempts !== 'number' ||
      !Number.isInteger(value.max_attempts) ||
      value.max_attempts < value.attempt ||
      value.max_attempts > 10 ||
      (value.type === 'reconnecting' &&
        (typeof value.delay_seconds !== 'number' ||
          !Number.isInteger(value.delay_seconds) ||
          value.delay_seconds < 0 ||
          value.delay_seconds > 3600))
    ) {
      return undefined;
    }
    return value.type === 'reconnecting'
      ? {
          type: 'reconnecting',
          sessionId: value.session_id,
          error: value.error,
          attempt: value.attempt,
          maxAttempts: value.max_attempts,
          delaySeconds: value.delay_seconds as number,
        }
      : {
          type: 'reconnect-failed',
          sessionId: value.session_id,
          error: value.error,
          attempt: value.attempt,
          maxAttempts: value.max_attempts,
        };
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
      error: value.error.slice(0, sshMaxBackendErrorLength),
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
        typeof value.error === 'string'
          ? value.error.slice(0, sshMaxBackendErrorLength)
          : undefined,
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
        typeof value.error === 'string'
          ? value.error.slice(0, sshMaxBackendErrorLength)
          : undefined,
    };
  }
  if (value.type === 'sftp.error' && typeof value.error === 'string') {
    if (value.request_id !== undefined && !isSftpRequestId(value.request_id)) {
      return undefined;
    }
    return {
      type: 'sftp.error',
      sessionId: value.session_id,
      error: value.error.slice(0, sshMaxBackendErrorLength),
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
    const hasHostKeyMismatch = isSshHostKeyMismatch(hostKeyExpected, hostKeyReceived);
    const retainTunnelLease = value.retain_tunnel_lease === true && hasHostKeyMismatch;
    return {
      type: 'error',
      sessionId: value.session_id,
      error: value.error,
      hostKeyExpected: hasHostKeyMismatch ? hostKeyExpected : undefined,
      hostKeyReceived: hasHostKeyMismatch ? hostKeyReceived : undefined,
      retainTunnelLease,
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
  completion: TunnelBrowserCompletion;
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
const mcpApprovalWindowCoordinator = new McpApprovalWindowCoordinator<BrowserWindow>();

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
  const partition =
    event.completion === 'query-token'
      ? tunnelAuthPartition({
          completion: event.completion,
          origin: fireboxOrigin,
          ignoreCertificateErrors: event.ignoreCertificateErrors,
        })
      : tunnelAuthPartition({ completion: event.completion });
  const browserSession = electronSession.fromPartition(partition, {
    cache: false,
  });
  browserSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  browserSession.setPermissionCheckHandler(() => false);
  // The partition isolates WatchGuard origin and trust policy. Still replace the verifier so a
  // reused same-policy partition cannot retain a stale callback from an earlier authentication.
  browserSession.setCertificateVerifyProc((request, callback) => {
    callback(
      event.ignoreCertificateErrors && isSameCertificateHostname(request.hostname, fireboxHost)
        ? 0
        : -3,
    );
  });
  const parent = BrowserWindow.getFocusedWindow() ?? BrowserWindow.getAllWindows()[0];
  const authWindow = new BrowserWindow({
    width: 900,
    height: 700,
    minWidth: 640,
    minHeight: 480,
    title: event.title,
    parent: parent && !parent.isDestroyed() ? parent : undefined,
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
      const value = JSON.stringify({
        code,
        state,
        error: oauthError,
        description,
      });
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
  const clearCompletionCookie = async () => {
    if (event.completion !== 'cookie') return;
    const cookies = await browserSession.cookies.get({ url: cookieScopeURL });
    await Promise.all(
      cookies
        .filter((cookie) => cookie.name === event.cookieName)
        .map((cookie) => browserSession.cookies.remove(cookieScopeURL, cookie.name)),
    );
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
  authWindow.once('closed', () => {
    mcpApprovalWindowCoordinator.forgetTunnelAuthWindow(authWindow);
    void complete(true);
  });
  // Keep this child non-modal so an MCP approval can safely preempt it on every supported desktop.
  authWindow.once('ready-to-show', () =>
    mcpApprovalWindowCoordinator.presentTunnelAuthWindow(authWindow),
  );
  const cookieTimer =
    event.completion === 'cookie' ? setInterval(() => void inspectCookie(), 250) : undefined;
  authWindow.once('closed', () => {
    if (cookieTimer) clearInterval(cookieTimer);
  });
  await clearCompletionCookie().catch(() => undefined);
  await authWindow.loadURL(event.urls[0]).catch(() => complete(true));
  await finished;
  // Keep the IdP profile persistent, but never retain Fortinet's ephemeral VPN credential in
  // Chromium's cookie store after it has crossed the one-shot Go sidecar boundary.
  await clearCompletionCookie().catch(() => undefined);
}

class NativeBackendProcess {
  private child: ReturnType<typeof spawn> | undefined;
  private startPromise: Promise<void> | undefined;
  private stopPromise: Promise<void> | undefined;
  private stopping = false;
  private permanentlyStopped = false;
  private outputBuffer = '';
  private requestSequence = 0;
  private readonly pending = new Map<
    string,
    {
      resolve: (response: BackendResponse) => void;
      reject: (error: Error) => void;
    }
  >();

  async send(
    command: NativeBackendCommand,
    timeoutMs = nativeBackendCommandTimeoutMs,
  ): Promise<BackendResponse> {
    await this.start();
    const child = this.child;
    if (!child?.stdin || child.stdin.destroyed) {
      throw new Error('Wormhole service is not available.');
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
      pending.reject(new Error('Wormhole service did not respond in time.'));
    }, timeoutMs);

    return response.finally(() => clearTimeout(timeout));
  }

  async acquireTunnel(request: {
    leaseId: string;
    nodeId?: string;
    tunnelConfigId?: string;
    progressSessionId?: string;
    dedicated?: boolean;
  }): Promise<string> {
    return (await this.acquireTunnelRoute(request)).socksEndpoint;
  }

  async acquireTunnelRoute(request: {
    leaseId: string;
    nodeId?: string;
    tunnelConfigId?: string;
    progressSessionId?: string;
    dedicated?: boolean;
  }): Promise<{ active: boolean; socksEndpoint: string }> {
    const response = await this.send(
      {
        action: 'tunnel.acquire',
        sessionId: request.leaseId,
        nodeId: request.nodeId,
        tunnelConfigId: request.tunnelConfigId,
        progressSessionId: request.progressSessionId,
        dedicated: request.dedicated,
      },
      tunnelTestTimeoutMs,
    );
    if (!response.ok) throw new Error(response.error || 'Could not establish the VPN tunnel.');
    return {
      active: response.tunnelActive === true,
      socksEndpoint: response.socksEndpoint ?? '',
    };
  }

  async bindTunnelForwarder(
    leaseId: string,
    host: string,
    port: number,
  ): Promise<{ host: string; port: number }> {
    const response = await this.send({
      action: 'tunnel.forward',
      sessionId: leaseId,
      host,
      port,
    });
    const forwardPort = response.forwardPort;
    if (
      !response.ok ||
      response.forwardHost !== '127.0.0.1' ||
      typeof forwardPort !== 'number' ||
      !Number.isInteger(forwardPort) ||
      forwardPort < 1 ||
      forwardPort > 65535
    ) {
      throw new Error(response.error || 'Could not bind the VPN tunnel forwarder.');
    }
    return { host: response.forwardHost, port: forwardPort };
  }

  async probeTunnelTarget(leaseId: string, host: string, port: number): Promise<void> {
    const response = await this.send(
      {
        action: 'tunnel.probe',
        sessionId: leaseId,
        host,
        port,
      },
      10_000,
    );
    if (!response.ok)
      throw new Error(response.error || 'The VPN tunnel could not reach the target.');
  }

  async releaseTunnel(leaseId: string): Promise<void> {
    const response = await this.send({
      action: 'tunnel.release',
      sessionId: leaseId,
    });
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

  async runOperation(
    operationId: string,
    action: 'backup.export' | 'backup.import' | 'mremote.import.commit',
    request: Pick<
      NativeBackendCommand,
      'path' | 'password' | 'structureOnly' | 'planNonce' | 'planToken'
    >,
  ): Promise<unknown> {
    const response = await this.send(
      { action, sessionId: operationId, ...request },
      nativeLongOperationTimeoutMs,
    );
    if (!response.ok) throw new Error(response.error || 'The operation failed.');
    return response.result;
  }

  async cancelOperation(operationId: string): Promise<void> {
    // A crashed/stopped backend has already ended every operation. Do not restart a fresh process
    // merely to send an idempotent cancellation for work that no longer exists.
    if (!this.child) return;
    const response = await this.send(
      { action: 'operation.cancel', sessionId: operationId },
      backupTimeoutMs,
    );
    if (!response.ok) throw new Error(response.error || 'Could not cancel the operation.');
  }

  async stop(permanent = false): Promise<void> {
    if (permanent) this.permanentlyStopped = true;
    if (this.stopPromise) return this.stopPromise;
    this.stopping = true;
    const child = this.child;
    this.outputBuffer = '';
    this.rejectAll(new Error('Wormhole service stopped.'));

    this.stopPromise = (async () => {
      if (!child) return;
      const exited = await stopChildProcess(child, {
        gracefulTimeoutMs: nativeBackendShutdownTimeoutMs,
      });
      if (!exited) {
        console.warn('[Wormhole] App service did not stop within the allowed time.');
      }
      if (this.child === child) this.child = undefined;
    })().finally(() => {
      this.stopping = false;
      this.stopPromise = undefined;
    });
    return this.stopPromise;
  }

  private async start(): Promise<void> {
    if (this.permanentlyStopped) throw new Error('Wormhole service has stopped.');
    if (this.stopping) throw new Error('Wormhole service is stopping.');
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
        void this.stop();
      });
      child.stdin?.once('error', (error) => {
        this.rejectAll(error instanceof Error ? error : new Error(String(error)));
      });
      child.once('spawn', () => {
        settled = true;
        resolve();
      });
      child.once('error', (error) => {
        if (this.child === child) this.child = undefined;
        this.rejectAll(error instanceof Error ? error : new Error(String(error)));
        if (!settled) reject(error instanceof Error ? error : new Error(String(error)));
      });
      child.once('close', (code) => {
        if (this.child === child) this.child = undefined;
        this.outputBuffer = '';
        const error = new Error(
          code === null ? 'Wormhole service stopped.' : `Wormhole service stopped (${code}).`,
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
      void this.stop();
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
        if (message.type === 'operation.progress') {
          routeNativeOperationProgress(this, message);
          continue;
        }
        if (message.type === 'tunnel.progress' && routeTunnelTestProgress(this, message)) {
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
const activeTunnelTests = new Map<number, ActiveTunnelTest>();
const activeNativeOperations = new Map<number, ActiveNativeOperation>();

function boundedProgressText(value: unknown, maximum = 512): string {
  if (typeof value !== 'string') return '';
  return value
    .replace(/[\p{Cc}]+/gu, ' ')
    .trim()
    .slice(0, maximum);
}

function sendTunnelTestProgress(test: ActiveTunnelTest, phase: string, detail: string): void {
  const safePhase = boundedProgressText(phase, 64);
  const safeDetail = boundedProgressText(detail);
  if (!authSession.isAccessAllowed || !safePhase || !safeDetail || test.sender.isDestroyed())
    return;
  test.lastProgress = safeDetail;
  test.sender.send('tunnel:test-progress', {
    attempt: test.attempt,
    phase: safePhase,
    detail: safeDetail,
  });
}

function routeTunnelTestProgress(backend: NativeBackendProcess, value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;
  const event = value as Record<string, unknown>;
  if (typeof event.sessionId !== 'string') return false;
  const test = [...activeTunnelTests.values()].find(
    (candidate) => candidate.backend === backend && candidate.leaseId === event.sessionId,
  );
  if (!test) return false;
  if (
    authSession.isAccessAllowed &&
    typeof event.phase === 'string' &&
    typeof event.detail === 'string'
  ) {
    sendTunnelTestProgress(test, event.phase, event.detail);
  }
  return true;
}

function routeNativeOperationProgress(backend: NativeBackendProcess, value: unknown): void {
  if (!authSession.isAccessAllowed || !value || typeof value !== 'object') return;
  const event = value as Record<string, unknown>;
  if (typeof event.sessionId !== 'string') return;
  const operation = [...activeNativeOperations.values()].find(
    (candidate) => candidate.backend === backend && candidate.id === event.sessionId,
  );
  if (!operation || operation.sender.isDestroyed()) return;
  const phase = boundedProgressText(event.phase, 64);
  const detail = boundedProgressText(event.detail);
  const percent = event.percent;
  if (
    !phase ||
    !detail ||
    !Number.isInteger(percent) ||
    (percent as number) < 0 ||
    (percent as number) > 100
  )
    return;
  operation.sender.send('operation:progress', {
    kind: operation.kind,
    phase,
    detail,
    percent,
  });
}
let isQuitting = false;
let skipQuitConfirmation = false;
let bitwardenBackgroundTimer: NodeJS.Timeout | undefined;
let bitwardenOnboardingPromise: Promise<void> | undefined;
let bitwardenStartupMaintenancePromise: Promise<void> | undefined;

function requireNativeResourcesRunning(): void {
  if (isQuitting) throw new Error('Wormhole service is stopping.');
}

function getNativeBackend(): NativeBackendProcess {
  nativeBackend ??= new NativeBackendProcess();
  return nativeBackend;
}

async function releaseNativeTunnelLease(leaseId: string): Promise<void> {
  const backend = nativeBackend;
  if (!backend) return;
  await backend.releaseTunnel(leaseId);
}

async function runBitwardenCredentialMaintenance(ensureInstalled: boolean): Promise<void> {
  // WinUI starts both Bitwarden services only after startup authentication. Keep the same native
  // trust boundary here: a locked or not-yet-initialized renderer cannot trigger vault/installer
  // work merely because the background timer fired.
  if (isQuitting || !authSession.isAccessAllowed) return;
  const authorizationEpoch = authSession.authorizationEpoch;
  try {
    let state = await runBitwardenBackend<BitwardenCliState>('bitwarden.read');
    if (!isAuthorizationEpochCurrent(authorizationEpoch)) return;
    if (state.enabled) {
      if (!state.installed && ensureInstalled) {
        state = await runBitwardenBackend<BitwardenCliState>('bitwarden.ensure-installed');
        if (!isAuthorizationEpochCurrent(authorizationEpoch)) return;
      }
      if (state.installed && isAuthorizationEpochCurrent(authorizationEpoch)) {
        await runBitwardenBackend('bitwarden.sync-if-stale');
      }
    }
  } catch (error) {
    console.warn('[Wormhole] Bitwarden credential background maintenance failed.', error);
  }
}

async function runBitwardenExtensionStartupMaintenance(): Promise<void> {
  if (isQuitting || !authSession.isAccessAllowed) return;
  const authorizationEpoch = authSession.authorizationEpoch;
  try {
    await serializeBitwardenExtensionOperation(async () => {
      if (!isAuthorizationEpochCurrent(authorizationEpoch)) return;
      const state = await runBackend<BitwardenExtensionState>('extension-read');
      if (state.enabled) {
        if (!state.installed && state.source === 'OfficialGitHub') {
          await webSurfaces.runBitwardenExtensionMutation(() => {
            if (!isAuthorizationEpochCurrent(authorizationEpoch)) return Promise.resolve(state);
            return runBackend<BitwardenExtensionState>(
              'extension-ensure-installed',
              undefined,
              extensionOperationTimeoutMs,
            );
          });
        } else if (state.installed && state.source === 'OfficialGitHub') {
          await webSurfaces.runBitwardenExtensionMutation(() => {
            if (!isAuthorizationEpochCurrent(authorizationEpoch)) return Promise.resolve(state);
            return runBackend<BitwardenExtensionState>(
              'extension-update-if-stale',
              undefined,
              extensionOperationTimeoutMs,
            );
          });
        }
      }
    });
  } catch (error) {
    console.warn('[Wormhole] Bitwarden browser extension background maintenance failed.', error);
  }
}

function runBitwardenStartupMaintenance(): Promise<void> {
  bitwardenStartupMaintenancePromise ??= Promise.all([
    runBitwardenCredentialMaintenance(true),
    runBitwardenExtensionStartupMaintenance(),
  ])
    .then(() => undefined)
    .finally(() => {
      bitwardenStartupMaintenancePromise = undefined;
    });
  return bitwardenStartupMaintenancePromise;
}

function startBitwardenBackgroundMaintenance(): void {
  void runBitwardenStartupMaintenance();
  // The five-minute timer refreshes only the credential catalog. Extension install/update is a
  // startup concern, so a failed download is not retried forever in the background.
  bitwardenBackgroundTimer ??= setInterval(
    () => void runBitwardenCredentialMaintenance(false),
    5 * 60_000,
  );
}

function showBitwardenOnboardingNoticeIfNeeded(): Promise<void> {
  bitwardenOnboardingPromise ??= (async () => {
    if (isQuitting || !authSession.isAccessAllowed) return;
    const authorizationEpoch = authSession.authorizationEpoch;
    const notice = await runBackend<{
      show: boolean;
      title?: string;
      message?: string;
    }>('bitwarden-onboarding-read', { appVersion: app.getVersion() });
    if (
      !notice.show ||
      !notice.title ||
      !notice.message ||
      !isAuthorizationEpochCurrent(authorizationEpoch)
    )
      return;

    const owner = BrowserWindow.getFocusedWindow() ?? BrowserWindow.getAllWindows()[0];
    if (!owner || owner.isDestroyed()) return;
    await dialog.showMessageBox(owner, {
      type: 'info',
      title: notice.title,
      message: notice.title,
      detail: notice.message,
      buttons: ['OK'],
      defaultId: 0,
      cancelId: 0,
      noLink: true,
      icon: path.join(__dirname, '..', 'Assets', 'Bitwarden', 'bitwarden-icon.png'),
    });
    if (!isAuthorizationEpochCurrent(authorizationEpoch)) return;
    await runBackend<{ updated: boolean }>('bitwarden-onboarding-dismiss');
  })()
    .catch((error) => {
      console.warn('[Wormhole] Could not show the Bitwarden onboarding notice.', error);
    })
    .finally(() => {
      bitwardenOnboardingPromise = undefined;
    });
  return bitwardenOnboardingPromise;
}

async function runBitwardenBackend<T>(
  action: Extract<NativeBackendAction, `bitwarden.${string}`>,
  values: Omit<NativeBackendCommand, 'action'> = {},
  timeoutMs = cliOperationTimeoutMs,
): Promise<T> {
  const response = await getNativeBackend().send({ action, ...values }, timeoutMs);
  if (!response.ok) throw new Error(response.error || 'Bitwarden operation failed.');
  return response.result as T;
}

async function resolveNativeRdpProfile(
  nodeId: string,
  manualCredentials: boolean,
  supplied: RdpProfile,
): Promise<RdpProfile> {
  const response = await getNativeBackend().send(
    {
      action: 'rdp.resolve-profile',
      nodeId,
      manualCredentials,
      username: manualCredentials ? supplied.username : undefined,
      domain: manualCredentials ? supplied.domain : undefined,
      password: manualCredentials ? supplied.password : undefined,
      credentialId: manualCredentials ? undefined : supplied.credentialIdOverride,
    },
    cliOperationTimeoutMs,
  );
  if (!response.ok) throw new Error(response.error || 'RDP profile resolution failed.');
  return response.result as RdpProfile;
}

async function resolveRdpExternalClientRequirement(
  request: RdpExternalClientRequirementRequest,
): Promise<boolean> {
  const response = await runBackend<{ required: boolean }>(
    'rdp-external-client-requirement',
    request,
  );
  if (!response || typeof response.required !== 'boolean') {
    throw new Error('RDP external-client requirement returned an invalid result.');
  }
  return response.required;
}

async function resolveNativeRdpSystemClientCapability(
  nodeId: string,
): Promise<RdpSystemClientCapability> {
  const response = await getNativeBackend().send(
    { action: 'rdp.system-client-capability', nodeId },
    cliOperationTimeoutMs,
  );
  if (!response.ok) throw new Error(response.error || 'RDP system client capability failed.');
  const result = response.result as Partial<RdpSystemClientCapability> | undefined;
  if (!result || typeof result.supported !== 'boolean') {
    throw new Error('RDP system client capability returned an invalid result.');
  }
  return { supported: result.supported };
}

async function resolveNativeRdpSystemProfile(nodeId: string): Promise<RdpProfile> {
  const response = await getNativeBackend().send(
    { action: 'rdp.resolve-system-profile', nodeId },
    cliOperationTimeoutMs,
  );
  if (!response.ok) throw new Error(response.error || 'RDP system profile resolution failed.');
  const profile = response.result as RdpProfile | undefined;
  if (
    !profile ||
    typeof profile.host !== 'string' ||
    !profile.host ||
    profile.useExternalClient !== true ||
    profile.username ||
    profile.domain ||
    profile.password ||
    profile.gatewayUsername ||
    profile.gatewayPassword
  ) {
    throw new Error('RDP system profile returned an invalid result.');
  }
  return profile;
}

async function resolveNativeRdpCredential(
  credentialId: string,
): Promise<BitwardenResolvedCredential> {
  const response = await getNativeBackend().send(
    { action: 'rdp.resolve-credential', credentialId },
    cliOperationTimeoutMs,
  );
  if (!response.ok) throw new Error(response.error || 'RDP credential resolution failed.');
  return response.result as BitwardenResolvedCredential;
}

type BitwardenResolvedCredential = {
  bitwarden: boolean;
  itemId?: string;
  itemName?: string;
  username?: string;
  domain?: string;
  password?: string;
};

type BitwardenBrowserStorageSnapshot = {
  revision: number;
  profileRevision: number;
  restore: boolean;
  localJson: string;
  sessionJson: string;
  durable: boolean;
};

function parseVncCommand(value: unknown): NativeBackendCommand {
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

  const command: NativeBackendCommand = { action, sessionId };
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
    command.tunnelConfigId = stringField('tunnelConfigId', 128);
    if (command.tunnelConfigId !== undefined && !isTunnelID(command.tunnelConfigId)) {
      throw new Error('Invalid VNC tunnel configuration.');
    }
    if (input.passwordProvided !== undefined && typeof input.passwordProvided !== 'boolean') {
      throw new Error('Invalid VNC password presence flag.');
    }
    command.passwordProvided = input.passwordProvided === true;
    if (command.passwordProvided && command.password === undefined) {
      throw new Error('Invalid VNC password override.');
    }
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
  if (!isRecord(value) || !isSshSessionId(value.nodeId)) return false;
  const hasCanonicalRoute =
    (value.tunnelEnabled === null && value.tunnelConfigId === '') ||
    (value.tunnelEnabled === false && value.tunnelConfigId === '') ||
    (value.tunnelEnabled === true && isTunnelID(value.tunnelConfigId));
  return hasCanonicalRoute;
}

function isTunnelID(value: unknown): value is string {
  return isTunnelIdentifier(value);
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

function releaseTunnelTest(test: ActiveTunnelTest): Promise<void> {
  const backend = test.backend;
  if (!backend) return Promise.resolve();
  return test.leases.release('tunnel-test', (leaseId) => backend.releaseTunnel(leaseId));
}

async function cancelTunnelTest(test: ActiveTunnelTest): Promise<void> {
  test.cancelled = true;
  await releaseTunnelTest(test);
}

async function runOwnedNativeOperation(
  sender: Electron.WebContents,
  kind: NativeOperationKind,
  action: 'backup.export' | 'backup.import' | 'mremote.import.commit',
  request: Pick<
    NativeBackendCommand,
    'path' | 'password' | 'structureOnly' | 'planNonce' | 'planToken'
  >,
): Promise<unknown> {
  requireNativeResourcesRunning();
  if (activeNativeOperations.has(sender.id)) {
    throw new Error('Another backup or import operation is already running.');
  }
  const backend = getNativeBackend();
  const operation: ActiveNativeOperation = {
    id: randomUUID(),
    kind,
    backend,
    sender,
  };
  activeNativeOperations.set(sender.id, operation);
  const cancel = () => backend.cancelOperation(operation.id);
  const cancelWhenRendererCloses = () => void cancel().catch(() => undefined);
  sender.once('destroyed', cancelWhenRendererCloses);
  try {
    try {
      return await runAuthorizedOperation(
        () => backend.runOperation(operation.id, action, request),
        cancel,
      );
    } catch (error) {
      // A timed-out or failed request must not leave its Go mutation running headlessly after
      // the renderer loses the only cancellation handle. Cancelling an already-finished
      // operation is intentionally idempotent.
      await cancel().catch(() => undefined);
      throw error;
    }
  } finally {
    if (!sender.isDestroyed()) sender.removeListener('destroyed', cancelWhenRendererCloses);
    if (activeNativeOperations.get(sender.id) === operation) {
      activeNativeOperations.delete(sender.id);
    }
  }
}

async function cancelOwnedNativeOperation(
  sender: Electron.WebContents,
  expected: NativeOperationKind,
): Promise<boolean> {
  const operation = activeNativeOperations.get(sender.id);
  if (!operation || operation.kind !== expected) return false;
  await operation.backend.cancelOperation(operation.id);
  return true;
}

function cancelAllUserOperations(): void {
  for (const test of activeTunnelTests.values()) {
    void cancelTunnelTest(test).catch(() => undefined);
  }
  for (const operation of activeNativeOperations.values()) {
    void operation.backend.cancelOperation(operation.id).catch(() => undefined);
  }
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
  const executablePath =
    findBundledExecutable(executableName) ??
    (process.platform === 'darwin'
      ? findBundledExecutable('wormhole-backend-universal')
      : undefined);
  if (!executablePath) {
    throw new Error('A required Wormhole component is missing.');
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

async function runBackend<T>(
  operation: BackendOperation,
  request?: unknown,
  timeoutMs: number = backendTimeoutMs,
  signal?: AbortSignal,
): Promise<T> {
  if (signal?.aborted) throw new Error('Operation cancelled.');
  const args = [
    '--operation',
    operation,
    '--database',
    wormholeDatabasePath(),
    '--electron-user-data',
    electronUserDataPath(),
  ];
  if (operation === 'migrate' || operation === 'startup') {
    const reader = credentialReaderPath();
    if (reader) args.push('--credential-reader', reader);
  }
  let requestPayload: string | undefined;
  if (request !== undefined) {
    requestPayload = JSON.stringify(request);
    const requestLimit =
      operation === 'workspace-delete-nodes'
        ? workspaceDeleteNodesMaxRequestBytes
        : operation === 'settings-set-connection-tree-expansion'
          ? connectionTreeExpansionMaxRequestBytes
          : operation.startsWith('tunnel-')
            ? backendMaxTunnelRequestBytes
            : backendMaxRequestBytes;
    if (requestPayload === undefined || Buffer.byteLength(requestPayload, 'utf8') > requestLimit) {
      throw new Error('The Wormhole request is too large.');
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
    const effectiveTimeoutMs =
      timeoutMs === backendTimeoutMs && operation.startsWith('backup-')
        ? backupTimeoutMs
        : timeoutMs;
    const timeout = setTimeout(() => {
      child.kill();
      finishReject(new Error('Wormhole did not respond in time.'));
    }, effectiveTimeoutMs);
    const abort = () => {
      child.kill();
      finishReject(new Error('Operation cancelled.'));
    };
    signal?.addEventListener('abort', abort, { once: true });

    function finishReject(error: Error) {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      signal?.removeEventListener('abort', abort);
      reject(error);
    }

    child.stdout?.setEncoding('utf8');
    child.stderr?.setEncoding('utf8');
    child.stdout?.on('data', (chunk: string) => {
      stdout += chunk;
      stdoutBytes += Buffer.byteLength(chunk, 'utf8');
      if (stdoutBytes > backendMaxBuffer) {
        child.kill();
        finishReject(new Error('Wormhole returned too much data.'));
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
      signal?.removeEventListener('abort', abort);
      if (code !== 0) {
        reject(new Error(stderr.trim() || 'Wormhole could not complete the request.'));
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
    throw new Error('Wormhole returned invalid data.');
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
  return isSafeUpdateInstallerPath(value, updateCacheRoot(), process.platform);
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
    const lineReader = createInterface({
      input: child.stdout!,
      crlfDelay: Infinity,
    });

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

async function handleDownloadedUpdate(installerPath: string): Promise<{ appWillQuit: boolean }> {
  const action = updateInstallAction(process.platform);
  if (action === 'execute') {
    // Detached + unref lets Inno Setup survive the immediate exit. /RESTARTAPP relaunches the
    // newly installed Windows build when present.
    await new Promise<void>((resolve, reject) => {
      const child = spawn(installerPath, ['/SILENT', '/RESTARTAPP'], {
        detached: true,
        stdio: 'ignore',
        windowsHide: true,
      });
      child.once('error', reject);
      child.once('spawn', () => {
        child.removeListener('error', reject);
        child.unref();
        resolve();
      });
    });
    skipQuitConfirmation = true;
    app.quit();
    return { appWillQuit: true };
  }
  if (action === 'open') {
    const error = await shell.openPath(installerPath);
    if (error) throw new Error(error);
    return { appWillQuit: false };
  }
  if (action === 'reveal') {
    shell.showItemInFolder(installerPath);
    return { appWillQuit: false };
  }
  throw new Error('Updates are not supported on this platform.');
}

function scheduleStartupUpdateCheck(settings: AppSettings): void {
  if (!settings.autoCheckForUpdates || startupUpdateScheduled) return;
  startupUpdateScheduled = true;
  startupUpdateTimer = setTimeout(() => {
    startupUpdateTimer = undefined;
    void performUpdateCheck().catch((error) => {
      // A failed startup check must never block the app: the settings page still exposes
      // "Check now", and a later result arrives through the update:result event.
      const message = error instanceof Error ? error.message : String(error);
      console.warn('[Wormhole] Startup update check failed.', message);
    });
  }, startupUpdateDelayMs);
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
  navigation: {
    navigateUrl: string;
    originalUrl?: string;
  };
  tunnelLeaseId?: string;
  tunnelBackend?: NativeBackendProcess;
  tunnelProbeTarget?: { host: string; port: number };
  bitwardenUseRelease?: () => void;
  bitwardenTabRegistered?: boolean;
  bitwarden?: {
    partition: string;
    popupUrl: string;
  };
};

type LoadedBitwardenExtension = {
  id: string;
  defaultPopup?: string;
};

type BitwardenBrowserProfileSeedResult = {
  initialized: boolean;
  seeded: boolean;
  cookieSourceProfiles: string[];
};

type BitwardenCookieSeed = {
  routeKey: string;
  targetUrl: string;
};

type ExtensionTabCreateDetails = {
  url?: string;
  windowId?: number;
};

type ExtensionWindowCreateDetails = {
  url?: string | string[];
  focused?: boolean;
  width?: number;
  height?: number;
  left?: number;
  top?: number;
};

type BitwardenAuxiliaryWindow = {
  window: BrowserWindow;
  partition: string;
  sessionId: string;
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
    throw new Error('Wormhole returned an invalid web address.');
  }
  const targetUrl = new URL(value.url);
  if (
    targetUrl.protocol !== `${value.protocol}:` ||
    targetUrl.hostname !== value.host ||
    targetUrl.username ||
    targetUrl.password
  ) {
    throw new Error('Wormhole returned an invalid web address.');
  }
  return value;
}

function validateBitwardenBrowserStorageSnapshot(
  value: BitwardenBrowserStorageSnapshot,
): BitwardenBrowserStorageSnapshot {
  if (
    !value ||
    !Number.isSafeInteger(value.revision) ||
    value.revision < 0 ||
    !Number.isSafeInteger(value.profileRevision) ||
    value.profileRevision < 0 ||
    typeof value.restore !== 'boolean' ||
    typeof value.localJson !== 'string' ||
    typeof value.sessionJson !== 'string' ||
    typeof value.durable !== 'boolean'
  ) {
    throw new Error('Go returned invalid Bitwarden browser storage.');
  }
  for (const json of [value.localJson, value.sessionJson]) {
    const parsed: unknown = JSON.parse(json);
    if (!isRecord(parsed)) throw new Error('Go returned invalid Bitwarden browser storage.');
  }
  return value;
}

function withBitwardenBrowserTimeout<T>(
  operation: Promise<T>,
  timeoutMs: number,
  message: string,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(message)), timeoutMs);
    void operation.then(
      (result) => {
        clearTimeout(timeout);
        resolve(result);
      },
      (error: unknown) => {
        clearTimeout(timeout);
        reject(error instanceof Error ? error : new Error(String(error)));
      },
    );
  });
}

async function loadBitwardenExtensionWhenReady(
  browserSession: Electron.Session,
  extensionPath: string,
): Promise<Electron.Extension> {
  const readyIds = new Set<string>();
  let loadedId = '';
  let resolveReady!: () => void;
  const ready = new Promise<void>((resolve) => {
    resolveReady = resolve;
  });
  const onReady = (_event: Electron.Event, extension: Electron.Extension) => {
    readyIds.add(extension.id);
    if (loadedId === extension.id) resolveReady();
  };
  const configureExtensionHost = (contents: Electron.WebContents) => {
    if (contents.session === browserSession && contents.getType() === 'backgroundPage') {
      // electron-chrome-extensions installs one cleanup listener per chrome.* event subscribed by
      // Bitwarden. They all belong to this host and are removed when it is destroyed.
      contents.setMaxListeners(bitwardenExtensionHostMaxListeners);
    }
  };
  const onWebContentsCreated = (_event: Electron.Event, contents: Electron.WebContents) => {
    configureExtensionHost(contents);
  };
  browserSession.extensions.on('extension-ready', onReady);
  app.on('web-contents-created', onWebContentsCreated);
  let extension: Electron.Extension | undefined;
  try {
    extension = await browserSession.extensions.loadExtension(extensionPath);
    loadedId = extension.id;
    if (readyIds.has(extension.id)) resolveReady();
    await withBitwardenBrowserTimeout(
      ready,
      bitwardenExtensionReadyTimeoutMs,
      'Bitwarden extension background page did not become ready.',
    );
    for (const contents of electronWebContents.getAllWebContents()) {
      configureExtensionHost(contents);
    }
    return extension;
  } catch (error) {
    if (extension) browserSession.extensions.removeExtension(extension.id);
    throw error;
  } finally {
    browserSession.extensions.off('extension-ready', onReady);
    app.off('web-contents-created', onWebContentsCreated);
  }
}

type TreeTooltipRecord = {
  view: WebContentsView;
  ready: Promise<void>;
  revision: number;
};

class TreeTooltipManager {
  private readonly records = new Map<number, TreeTooltipRecord>();

  show(owner: BrowserWindow, request: TreeTooltipRequest): void {
    const record = this.getOrCreate(owner);
    const revision = ++record.revision;
    void record.ready
      .then(async () => {
        if (record.revision !== revision || owner.isDestroyed()) return;
        await record.view.webContents.executeJavaScript(
          `document.getElementById('tooltip-text').textContent = ${JSON.stringify(request.text)}`,
        );
        if (record.revision !== revision || owner.isDestroyed()) return;

        const [contentWidth, contentHeight] = owner.getContentSize();
        const width = Math.round(request.width);
        const height = 30;
        const x = Math.min(
          Math.max(0, Math.round(request.anchor.x + request.anchor.width)),
          Math.max(0, contentWidth - width),
        );
        const y = Math.min(
          Math.max(0, Math.round(request.anchor.y + (request.anchor.height - height) / 2)),
          Math.max(0, contentHeight - height),
        );

        // Reinsert the tooltip last so it stays above every connection WebContentsView.
        owner.contentView.removeChildView(record.view);
        owner.contentView.addChildView(record.view);
        record.view.setBounds({ x, y, width, height });
      })
      .catch(() => undefined);
  }

  hide(owner: BrowserWindow): void {
    const record = this.records.get(owner.id);
    if (!record) return;
    record.revision += 1;
    record.view.setBounds({ x: 0, y: 0, width: 0, height: 0 });
  }

  closeForWindow(owner: BrowserWindow): void {
    const record = this.records.get(owner.id);
    if (!record) return;
    this.records.delete(owner.id);
    if (!owner.isDestroyed()) owner.contentView.removeChildView(record.view);
    if (!record.view.webContents.isDestroyed()) record.view.webContents.close();
  }

  private getOrCreate(owner: BrowserWindow): TreeTooltipRecord {
    const existing = this.records.get(owner.id);
    if (existing) return existing;

    const view = new WebContentsView({
      webPreferences: {
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
        devTools: false,
      },
    });
    view.setBackgroundColor('#00000000');
    view.setBounds({ x: 0, y: 0, width: 0, height: 0 });
    owner.contentView.addChildView(view);
    const html = `<!doctype html>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<style>
  * { box-sizing: border-box; }
  html, body { width: 100%; height: 100%; margin: 0; overflow: hidden; background: transparent; }
  body { position: relative; display: flex; align-items: center; padding-left: 5px; font: 12px/16px system-ui, sans-serif; }
  body::before { position: absolute; z-index: 1; top: 50%; left: 1px; width: 10px; height: 10px; content: ''; transform: translateY(-50%) rotate(45deg); border-radius: 2px; background: #fafafa; }
  .tooltip { position: relative; width: calc(100% - 5px); overflow: hidden; padding: 6px 12px; border-radius: 6px; background: #fafafa; color: #0a0a0a; white-space: nowrap; text-overflow: ellipsis; }
  #tooltip-text { position: relative; z-index: 2; }
</style>
<div class="tooltip"><span id="tooltip-text"></span></div>`;
    const ready = view.webContents
      .loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`)
      .then(() => undefined);
    const record = { view, ready, revision: 0 };
    this.records.set(owner.id, record);
    return record;
  }
}

const treeTooltips = new TreeTooltipManager();

class WebSurfaceManager {
  private readonly surfaces = new Map<string, WebSurfaceRecord>();
  private readonly pendingOpenOwners = new Map<string, BrowserWindow>();
  private readonly tunnelLeases = new TunnelLeaseRegistry();
  private readonly tunnelLeaseOwners = new Map<string, BrowserWindow>();
  private readonly attempts = new WebSessionAttemptTracker();
  private readonly extensionLoads = new Map<string, Promise<void>>();
  private readonly extensionLoadKeys = new Map<string, string>();
  private readonly extensionIds = new Map<string, string>();
  private readonly extensionPopupPaths = new Map<string, string>();
  private readonly chromeExtensionApis = new Map<string, ElectronChromeExtensions>();
  private readonly activeBitwardenSessions = new Map<string, string>();
  private readonly bitwardenAuxiliaryWindows = new Map<number, BitwardenAuxiliaryWindow>();
  private readonly bitwardenPopups = new Map<string, WebContentsView>();
  private readonly bitwardenPopupDismissHandlers = new Map<
    string,
    {
      owner: BrowserWindow;
      pageContents: Electron.WebContents;
      ownerBlur: () => void;
      ownerMouse: (event: Electron.Event, mouse: Electron.MouseInputEvent) => void;
      pageMouse: (event: Electron.Event, mouse: Electron.MouseInputEvent) => void;
    }
  >();
  private readonly bitwardenPopupOpens = new KeyedSingleFlight<string, { open: boolean }>();
  private readonly bitwardenStorageTasks = new KeyedTaskTracker<string>();
  private readonly bitwardenExtensionMutation = new ExtensionMutationGuard();
  private bitwardenStorageQueue: Promise<void> = Promise.resolve();
  private isolatedPartitionSequence = 0;

  async open(owner: BrowserWindow, request: WebOpenRequest): Promise<WebTargetResponse> {
    const authorizationEpoch = authSession.authorizationEpoch;
    const generation = this.attempts.begin(request.sessionId);
    this.pendingOpenOwners.set(request.sessionId, owner);
    this.dispose(request.sessionId);
    let openingLeaseId: string | undefined;
    let openingTunnelBackend: NativeBackendProcess | undefined;
    let bitwardenUseRelease: (() => void) | undefined;
    try {
      await this.releaseTunnel(request.sessionId);
      this.assertOpenCurrent(
        request.sessionId,
        generation,
        owner,
        'Web session was superseded before its VPN tunnel could open.',
      );
      const targetResult = await runBackend<WebTargetResponse>('web-target', {
        nodeId: request.nodeId,
        address: request.address,
        port: request.port,
        protocol: request.protocol,
        ignoreCertErrors: request.ignoreCertErrors,
        tunnelConfigId: request.tunnelConfigId,
      });
      const target = validateWebTarget(targetResult);
      this.assertOpenCurrent(
        request.sessionId,
        generation,
        owner,
        'Web session was superseded before its VPN tunnel could open.',
      );
      const logicalTargetUrl = target.url;
      let resolvedTunnelRoute: 'direct' | 'socks5' | 'forwarder' = 'direct';
      if (target.tunnelConfigId) {
        const leaseId = randomUUID();
        openingLeaseId = leaseId;
        this.tunnelLeases.claim(request.sessionId, leaseId);
        this.tunnelLeaseOwners.set(request.sessionId, owner);
        openingTunnelBackend = getNativeBackend();
        const tunnelRoute = await openingTunnelBackend.acquireTunnelRoute({
          leaseId,
          nodeId: request.nodeId,
          tunnelConfigId: target.tunnelConfigId,
          progressSessionId: request.sessionId,
        });
        if (tunnelRoute.socksEndpoint) {
          resolvedTunnelRoute = 'socks5';
          target.proxyUrl = `socks5://${tunnelRoute.socksEndpoint}`;
        } else if (tunnelRoute.active) {
          resolvedTunnelRoute = 'forwarder';
          const forwarder = await openingTunnelBackend.bindTunnelForwarder(
            leaseId,
            target.host,
            target.port,
          );
          const forwardedUrl = new URL(target.url);
          forwardedUrl.hostname = forwarder.host;
          forwardedUrl.port = String(forwarder.port);
          target.url = forwardedUrl.toString();
        } else {
          await this.releaseTunnel(request.sessionId);
          openingLeaseId = undefined;
        }
      }
      if (!isAuthorizationEpochCurrent(authorizationEpoch)) {
        throw new Error('Web session was superseded before its browser could open.');
      }
      this.assertOpenCurrent(
        request.sessionId,
        generation,
        owner,
        'Web session was superseded before its browser could open.',
      );

      let extensionPath: string | undefined;
      let bitwardenPartition: string | undefined;
      let bitwardenDefaultPopup: string | undefined;
      let bitwardenInstallKey: string | undefined;
      let bitwardenCookieSeed: BitwardenCookieSeed | undefined;
      if (target.url.startsWith('https://')) {
        let freshState: BitwardenExtensionState | undefined;
        let reservedUseRelease: (() => void) | undefined;
        try {
          const extensionState = await runBackend<BitwardenExtensionState>('extension-read');
          if (extensionState.enabled && extensionState.installed) {
            // Updating the extension is background maintenance. Opening an HTTPS tab must never
            // wait for a GitHub request or a storage flush before its browser surface is created.
            reservedUseRelease = this.bitwardenExtensionMutation.reserveUse();
            if (!isAuthorizationEpochCurrent(authorizationEpoch)) {
              throw new Error('Web session was cancelled while Wormhole locked.');
            }
            freshState = extensionState;
            bitwardenUseRelease = reservedUseRelease;
            reservedUseRelease = undefined;
          }
        } catch (error) {
          reservedUseRelease?.();
          // An optional extension failure must not prevent the appliance session itself from
          // opening. The plain HTTPS tab remains available and Settings exposes the install error.
          console.warn(
            '[Wormhole] Bitwarden browser extension setup failed for this HTTPS tab.',
            error,
          );
        }
        const freshInstall = freshState?.installed;
        if (freshState?.enabled && freshInstall) {
          // Match the WinUI 3 browser context: direct HTTPS tabs share one profile. SOCKS tabs use
          // a runtime endpoint-specific Chromium session (proxy is session-wide) plus a stable route
          // identity that lets the next endpoint inherit extension state and appliance cookies.
          let routeKey = '';
          if (target.tunnelConfigId && resolvedTunnelRoute !== 'direct') {
            routeKey = buildBitwardenPersistentRouteKey(
              target.tunnelConfigId,
              resolvedTunnelRoute,
              logicalTargetUrl,
            );
          }
          const browserContext = buildBitwardenBrowserContext(target.proxyUrl, routeKey);
          bitwardenPartition = getBitwardenBrowserPartition(
            browserContext,
            target.ignoreCertErrors,
          );
          if (routeKey) {
            bitwardenCookieSeed = {
              routeKey,
              targetUrl: logicalTargetUrl,
            };
          }
          extensionPath = freshInstall.path;
          bitwardenDefaultPopup = freshInstall.defaultPopup;
          bitwardenInstallKey = `${freshInstall.path}\0${freshState.sha256 ?? freshInstall.version}`;
        }
      }
      if (!isAuthorizationEpochCurrent(authorizationEpoch)) {
        throw new Error('Web session was superseded before its browser could open.');
      }
      this.assertOpenCurrent(
        request.sessionId,
        generation,
        owner,
        'Web session was superseded before its browser could open.',
      );

      const partition =
        bitwardenPartition ??
        (resolvedTunnelRoute !== 'direct'
          ? `wormhole-web-tunnel-${++this.isolatedPartitionSequence}`
          : target.ignoreCertErrors
            ? `wormhole-web-isolated-${++this.isolatedPartitionSequence}`
            : webSharedPartition);
      if (partition === webSharedPartition) await ensureWebSharedSessionReady();
      const browserSession = electronSession.fromPartition(partition, {
        cache: true,
      });
      if (target.proxyUrl) {
        await browserSession.setProxy({
          proxyRules: target.proxyUrl,
          proxyBypassRules: '<-loopback>',
        });
      }
      if (extensionPath && bitwardenPartition) {
        // Chromium derives the unpacked extension id from its folder path; the popup URL can only
        // be built after Electron reports the id back. A failed load degrades to a plain HTTPS tab
        // (matching WinUI 3, where the toolbar button hides but the session still opens).
        const loadedExtension = await this.loadBitwardenExtension(
          bitwardenPartition,
          extensionPath,
          bitwardenInstallKey ?? extensionPath,
          bitwardenDefaultPopup,
          bitwardenCookieSeed,
        );
        if (loadedExtension?.defaultPopup) {
          target.bitwarden = {
            partition: bitwardenPartition,
            popupUrl: `chrome-extension://${loadedExtension.id}/${loadedExtension.defaultPopup}`,
          };
        }
      }
      if (!target.bitwarden) {
        bitwardenUseRelease?.();
        bitwardenUseRelease = undefined;
      }
      const bitwardenExtensionId = target.bitwarden
        ? new URL(target.bitwarden.popupUrl).hostname
        : undefined;
      const isAllowedBitwardenPermission = (permission: string, url: string): boolean => {
        let page: URL;
        try {
          page = new URL(url);
        } catch {
          return false;
        }
        return (
          page.protocol === 'chrome-extension:' &&
          page.hostname === bitwardenExtensionId &&
          (permission === 'clipboard-read' ||
            permission === 'clipboard-sanitized-write' ||
            permission === 'notifications')
        );
      };
      browserSession.setPermissionRequestHandler((webContents, permission, callback) => {
        callback(isAllowedBitwardenPermission(permission, webContents.getURL()));
      });
      browserSession.setPermissionCheckHandler((_webContents, permission, requestingOrigin) => {
        return isAllowedBitwardenPermission(permission, requestingOrigin);
      });
      if (!isAuthorizationEpochCurrent(authorizationEpoch)) {
        throw new Error('Web session was superseded while preparing its browser surface.');
      }
      this.assertOpenCurrent(
        request.sessionId,
        generation,
        owner,
        'Web session was superseded while preparing its browser surface.',
      );

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
      if (target.bitwarden) {
        view.webContents.setMaxListeners(bitwardenExtensionHostMaxListeners);
      }
      const record: WebSurfaceRecord = {
        owner,
        view,
        attempt: request.attempt,
        initialNavigationPending: true,
        disposed: false,
        navigation: {
          navigateUrl: target.url,
          originalUrl: resolvedTunnelRoute === 'forwarder' ? logicalTargetUrl : undefined,
        },
        tunnelLeaseId: openingLeaseId,
        tunnelBackend: openingLeaseId ? openingTunnelBackend : undefined,
        tunnelProbeTarget:
          resolvedTunnelRoute === 'socks5' ? { host: target.host, port: target.port } : undefined,
        bitwardenUseRelease,
        bitwarden: target.bitwarden,
      };
      this.surfaces.set(request.sessionId, record);
      bitwardenUseRelease = undefined;
      this.pendingOpenOwners.delete(request.sessionId);
      owner.contentView.addChildView(view);
      view.setVisible(false);
      this.configureWebContents(request.sessionId, record, target);
      const bitwardenTabPartition = selectBitwardenTabRegistrationPartition(
        bitwardenPartition,
        record.bitwarden?.partition,
      );
      if (bitwardenTabPartition) {
        // Register the HTTPS tab with the chrome.* API provider so the Bitwarden service worker
        // and popup can read chrome.tabs / chrome.windows for the active appliance page. The popup
        // itself must not be registered as a tab, or active-tab queries would return the extension.
        const api = this.chromeExtensionApis.get(bitwardenTabPartition);
        if (api) {
          api.addTab(view.webContents, owner);
          record.bitwardenTabRegistered = true;
        }
      }
      void view.webContents.loadURL(target.url).catch((error: unknown) => {
        if (!record.disposed && record.initialNavigationPending) {
          this.beginInitialNavigationFailure(
            request.sessionId,
            record,
            describeWebNavigationError(error),
          );
        }
      });
      openingLeaseId = undefined;
      return target;
    } catch (error) {
      bitwardenUseRelease?.();
      if (this.surfaces.has(request.sessionId)) {
        this.dispose(request.sessionId);
      }
      if (openingLeaseId || this.tunnelLeases.has(request.sessionId)) {
        await this.releaseTunnel(request.sessionId).catch(() => undefined);
      }
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
    if (request.visible && record.bitwardenTabRegistered && record.bitwarden) {
      this.activeBitwardenSessions.set(record.bitwarden.partition, request.sessionId);
      this.chromeExtensionApis.get(record.bitwarden.partition)?.selectTab(record.view.webContents);
    }
  }

  async command(owner: BrowserWindow, request: WebCommandRequest): Promise<void> {
    let record = this.surfaces.get(request.sessionId);
    if (!record || record.owner !== owner || record.disposed) return;
    if (this.bitwardenPopups.has(request.sessionId)) {
      await afterBitwardenPopupInputEvent(async () => {
        await this.closeBitwardenPopup(request.sessionId);
      });
      record = this.surfaces.get(request.sessionId);
      if (!record || record.owner !== owner || record.disposed) return;
    }
    const contents = record.view.webContents;
    if (request.operation === 'back') {
      if (contents.navigationHistory.canGoBack()) contents.navigationHistory.goBack();
    } else if (request.operation === 'forward') {
      if (contents.navigationHistory.canGoForward()) contents.navigationHistory.goForward();
    } else if (request.operation === 'stop') {
      contents.stop();
    } else {
      contents.reload();
    }
    this.sendEvent(request.sessionId, record, 'navigation');
  }

  async openBitwardenPopup(request: BitwardenPopupOpenRequest): Promise<{ open: boolean }> {
    return this.bitwardenPopupOpens.run(request.sessionId, () =>
      this.openBitwardenPopupCore(request),
    );
  }

  private async openBitwardenPopupCore(
    request: BitwardenPopupOpenRequest,
  ): Promise<{ open: boolean }> {
    const { sessionId } = request;
    const authorizationEpoch = authSession.authorizationEpoch;
    const record = this.surfaces.get(sessionId);
    if (!record || record.disposed || !record.bitwarden?.popupUrl) {
      return { open: false };
    }
    if (this.bitwardenPopups.has(sessionId)) {
      return { open: true };
    }
    // Only one Bitwarden popup at a time: a popup on another tab would otherwise float over the
    // window independently of the tab that owns it.
    for (const otherSessionId of [...this.bitwardenPopups.keys()]) {
      if (otherSessionId !== sessionId) await this.closeBitwardenPopup(otherSessionId);
    }

    const popup = new WebContentsView({
      webPreferences: {
        partition: record.bitwarden.partition,
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
        webSecurity: true,
        allowRunningInsecureContent: false,
        devTools: false,
      },
    });
    popup.webContents.setMaxListeners(bitwardenExtensionHostMaxListeners);
    const popupUrl = record.bitwarden.popupUrl;
    this.activeBitwardenSessions.set(record.bitwarden.partition, sessionId);
    const [contentWidth, contentHeight] = record.owner.getContentSize();
    popup.setBounds(positionBitwardenPopup(request.anchor, [contentWidth, contentHeight]));
    popup.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    popup.webContents.on('will-navigate', (event, url) => {
      let sameExtensionPage = false;
      try {
        const target = new URL(url);
        const popupTarget = new URL(popupUrl);
        sameExtensionPage =
          target.protocol === 'chrome-extension:' && target.hostname === popupTarget.hostname;
      } catch {
        // A malformed URL cannot be an extension page.
      }
      if (!sameExtensionPage) event.preventDefault();
    });
    let dismissScheduled = false;
    const dismiss = () => {
      if (dismissScheduled) return;
      dismissScheduled = true;
      void afterBitwardenPopupInputEvent(async () => {
        if (this.bitwardenPopups.get(sessionId) !== popup) return;
        await this.closeBitwardenPopup(sessionId);
      }).catch((error) => {
        console.warn('[Wormhole] Could not dismiss the Bitwarden browser popup.', error);
      });
    };
    const onOwnerMouse = (_event: Electron.Event, mouse: Electron.MouseInputEvent) => {
      if (
        mouse.type === 'mouseDown' &&
        !isPointInsideBitwardenAnchor({ x: mouse.x, y: mouse.y }, request.anchor)
      ) {
        dismiss();
      }
    };
    const onPageMouse = (_event: Electron.Event, mouse: Electron.MouseInputEvent) => {
      if (mouse.type === 'mouseDown') dismiss();
    };
    record.owner.on('blur', dismiss);
    record.owner.webContents.on('before-mouse-event', onOwnerMouse);
    record.view.webContents.on('before-mouse-event', onPageMouse);
    record.owner.contentView.addChildView(popup);
    popup.setVisible(false);
    this.bitwardenPopups.set(sessionId, popup);
    this.bitwardenPopupDismissHandlers.set(sessionId, {
      owner: record.owner,
      pageContents: record.view.webContents,
      ownerBlur: dismiss,
      ownerMouse: onOwnerMouse,
      pageMouse: onPageMouse,
    });
    // Restore shared vault state through the MV2 background page while the popup loads. This must
    // never delay showing the UI; direct profiles already have their local state and routed
    // profiles receive chrome.storage change events when the asynchronous restore completes.
    void this.synchronizeBitwardenStorageInBridge(
      record.owner,
      record.bitwarden.partition,
      popupUrl,
    ).catch((error) => {
      console.warn('[Wormhole] Could not prepare Bitwarden browser storage for its popup.', error);
    });
    try {
      await withBitwardenBrowserTimeout(
        popup.webContents.loadURL(popupUrl),
        bitwardenBrowserNavigationTimeoutMs,
        'Bitwarden browser popup navigation timed out.',
      );
      if (this.bitwardenPopups.get(sessionId) !== popup || record.disposed) {
        return { open: false };
      }
      if (!isAuthorizationEpochCurrent(authorizationEpoch)) {
        await this.closeBitwardenPopup(sessionId);
        return { open: false };
      }
      popup.setVisible(true);
      if (!record.owner.webContents.isDestroyed()) {
        record.owner.webContents.send('web:bitwarden-popup-state', {
          sessionId,
          open: true,
        });
      }
    } catch (error) {
      console.warn('[Wormhole] Could not open the Bitwarden browser popup.', error);
      await this.closeBitwardenPopup(sessionId);
      return { open: false };
    }
    return { open: true };
  }

  async closeBitwardenPopup(
    sessionId: string,
    waitForStorageFlush = false,
  ): Promise<{ open: false }> {
    const popup = this.bitwardenPopups.get(sessionId);
    const record = this.surfaces.get(sessionId);
    const owner = record?.owner;
    const dismissHandlers = this.bitwardenPopupDismissHandlers.get(sessionId);
    this.bitwardenPopupDismissHandlers.delete(sessionId);
    if (dismissHandlers) {
      try {
        dismissHandlers.owner.removeListener('blur', dismissHandlers.ownerBlur);
        if (
          !dismissHandlers.owner.isDestroyed() &&
          !dismissHandlers.owner.webContents.isDestroyed()
        ) {
          dismissHandlers.owner.webContents.removeListener(
            'before-mouse-event',
            dismissHandlers.ownerMouse,
          );
        }
      } catch {
        // The BrowserWindow can disappear while Bitwarden completes an autofill operation.
      }
      try {
        if (!dismissHandlers.pageContents.isDestroyed()) {
          dismissHandlers.pageContents.removeListener(
            'before-mouse-event',
            dismissHandlers.pageMouse,
          );
        }
      } catch {
        // The embedded page can close in the same input event that dismisses the popup.
      }
    }
    if (popup) {
      this.bitwardenPopups.delete(sessionId);
      try {
        popup.setVisible(false);
      } catch {
        // Bitwarden can close its own extension window immediately after filling a credential.
      }
      try {
        owner?.contentView.removeChildView(popup);
      } catch {
        // The owner can already be closing.
      }
      closeBitwardenPopupContents(popup);
    }
    try {
      if (owner && !owner.isDestroyed() && !owner.webContents.isDestroyed()) {
        owner.webContents.send('web:bitwarden-popup-state', {
          sessionId,
          open: false,
        });
      }
    } catch {
      // Sending state to a renderer that is closing is unnecessary.
    }
    const storageFlush =
      popup && record?.bitwarden && !record.owner.isDestroyed()
        ? this.synchronizeBitwardenStorageInBridge(
            record.owner,
            record.bitwarden.partition,
            record.bitwarden.popupUrl,
          ).catch((error) => {
            console.warn(
              '[Wormhole] Could not flush Bitwarden browser storage when its popup closed.',
              error,
            );
          })
        : undefined;
    if (waitForStorageFlush) await storageFlush;
    return { open: false };
  }

  private serializeBitwardenStorage<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.bitwardenStorageQueue.then(operation, operation);
    this.bitwardenStorageQueue = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  private async synchronizeBitwardenStorageCore(
    partition: string,
    contents: Electron.WebContents,
  ): Promise<void> {
    await this.serializeBitwardenStorage(async () => {
      if (contents.isDestroyed()) return;
      const profilePath = electronSession.fromPartition(partition).storagePath;
      if (!profilePath)
        throw new Error('Bitwarden browser profile has no persistent storage path.');
      const shared = validateBitwardenBrowserStorageSnapshot(
        await runBitwardenBackend<BitwardenBrowserStorageSnapshot>(
          'bitwarden.browser-storage-read',
          { profilePath },
        ),
      );
      let sourceRevision = shared.profileRevision;
      if (shared.restore) {
        await restoreBitwardenExtensionStorage(contents, shared);
        sourceRevision = shared.revision;
      }
      const captured = await captureBitwardenExtensionStorage(contents);
      validateBitwardenBrowserStorageSnapshot(
        await runBitwardenBackend<BitwardenBrowserStorageSnapshot>(
          'bitwarden.browser-storage-capture',
          {
            profilePath,
            localJson: captured.localJson,
            sessionJson: captured.sessionJson,
            sourceRevision,
          },
        ),
      );
    });
  }

  private async synchronizeBitwardenStorageInBridge(
    owner: BrowserWindow,
    partition: string,
    popupUrl: string,
  ): Promise<void> {
    await this.bitwardenStorageTasks.run(partition, async () => {
      const extensionId = new URL(popupUrl).hostname;
      const browserSession = electronSession.fromPartition(partition, {
        cache: true,
      });
      const backgroundContents = electronWebContents.getAllWebContents().find((contents) => {
        if (
          contents.isDestroyed() ||
          contents.session !== browserSession ||
          contents.getType() !== 'backgroundPage'
        ) {
          return false;
        }
        try {
          const url = new URL(contents.getURL());
          return url.protocol === 'chrome-extension:' && url.hostname === extensionId;
        } catch {
          return false;
        }
      });
      if (backgroundContents) {
        await this.synchronizeBitwardenStorageCore(partition, backgroundContents);
        return;
      }

      const bridge = new WebContentsView({
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
      bridge.webContents.setMaxListeners(bitwardenExtensionHostMaxListeners);
      owner.contentView.addChildView(bridge);
      bridge.setBounds({ x: 0, y: 0, width: 1, height: 1 });
      bridge.setVisible(false);
      try {
        await withBitwardenBrowserTimeout(
          bridge.webContents.loadURL(popupUrl),
          bitwardenBrowserNavigationTimeoutMs,
          'Bitwarden browser storage page navigation timed out.',
        );
        await this.synchronizeBitwardenStorageCore(partition, bridge.webContents);
      } finally {
        try {
          owner.contentView.removeChildView(bridge);
        } catch {
          // The owner can already be closing.
        }
        if (!bridge.webContents.isDestroyed()) bridge.webContents.close();
      }
    });
  }

  private async ensureChromeExtensionApis(partition: string): Promise<ElectronChromeExtensions> {
    const existing = this.chromeExtensionApis.get(partition);
    if (existing) return existing;
    const { ElectronChromeExtensions } = await import('electron-chrome-extensions');
    const session = electronSession.fromPartition(partition, { cache: true });
    let instance!: ElectronChromeExtensions;
    instance = new ElectronChromeExtensions({
      session,
      license: 'GPL-3.0',
      createTab: async (details) => this.openExtensionTabInSession(partition, details),
      createWindow: async (details) =>
        this.openExtensionWindow(partition, instance, details as ExtensionWindowCreateDetails),
      assignTabDetails: (details, contents) => {
        const record = [...this.surfaces.values()].find(
          (candidate) =>
            !candidate.disposed &&
            candidate.bitwarden?.partition === partition &&
            candidate.view.webContents === contents,
        );
        if (!record) return;
        const context = createBitwardenActiveTabContext(
          record.navigation.navigateUrl,
          record.navigation.originalUrl,
          contents.getURL(),
        );
        if (context) details.url = context.logicalUrl;
      },
      // The library observes BrowserWindow.closed and removes its own bookkeeping. Destroying an
      // already closed window from its default removeWindow fallback is unnecessary.
      removeWindow: () => undefined,
    });
    this.chromeExtensionApis.set(partition, instance);
    return instance;
  }

  private resolveBitwardenSurface(
    partition: string,
    windowId?: number,
  ): [string, WebSurfaceRecord] | undefined {
    const auxiliary =
      windowId === undefined ? undefined : this.bitwardenAuxiliaryWindows.get(windowId);
    const preferredSessionId =
      auxiliary?.partition === partition
        ? auxiliary.sessionId
        : this.activeBitwardenSessions.get(partition);
    const preferred = preferredSessionId ? this.surfaces.get(preferredSessionId) : undefined;
    if (
      preferred &&
      !preferred.disposed &&
      preferred.bitwarden?.partition === partition &&
      (windowId === undefined ||
        preferred.owner.id === windowId ||
        auxiliary?.sessionId === preferredSessionId)
    ) {
      return [preferredSessionId!, preferred];
    }
    return [...this.surfaces.entries()].find(
      ([, candidate]) =>
        !candidate.disposed &&
        candidate.bitwarden?.partition === partition &&
        (windowId === undefined || candidate.owner.id === windowId),
    );
  }

  private async openExtensionTabInSession(
    partition: string,
    details: ExtensionTabCreateDetails,
  ): Promise<[Electron.WebContents, BrowserWindow]> {
    if (!authSession.isAccessAllowed || isQuitting) {
      throw new Error('Authentication is required before Bitwarden can open a browser tab.');
    }
    const resolved = this.resolveBitwardenSurface(partition, details.windowId);
    if (!resolved) {
      throw new Error('Bitwarden has no active HTTPS session for this navigation.');
    }
    const [selectedSessionId, record] = resolved;
    if (!record.bitwarden) {
      throw new Error('Bitwarden has no active HTTPS session for this navigation.');
    }

    const navigationUrl = getInSessionNavigationUrl(
      details.url,
      record.navigation.originalUrl ? record.navigation.navigateUrl : undefined,
      record.navigation.originalUrl,
    );
    if (!navigationUrl || !isAllowedWebNavigation(navigationUrl)) {
      throw new Error(
        'Bitwarden requested a URL that cannot be opened within this routed session.',
      );
    }

    // Chrome resolves tabs.create when the tab exists, before its navigation completes. Bitwarden's
    // web-auth flow installs a tabs.onUpdated listener after that resolution, so awaiting loadURL
    // here would lose the completion event and leave the login hanging.
    void record.view.webContents.loadURL(navigationUrl).catch(() => undefined);
    this.activeBitwardenSessions.set(partition, selectedSessionId);
    return [record.view.webContents, record.owner];
  }

  private async openExtensionWindow(
    partition: string,
    api: ElectronChromeExtensions,
    details: ExtensionWindowCreateDetails,
  ): Promise<BrowserWindow> {
    if (mcpApprovalWindowCoordinator.hasPendingApprovals) {
      throw new Error('Bitwarden cannot open a browser window while an MCP approval is pending.');
    }
    if (!authSession.isAccessAllowed || isQuitting) {
      throw new Error('Authentication is required before Bitwarden can open a browser window.');
    }
    const resolved = this.resolveBitwardenSurface(partition);
    if (!resolved) throw new Error('Bitwarden has no active HTTPS session for this window.');
    const [sessionId, record] = resolved;
    const requestedUrl = Array.isArray(details.url) ? details.url[0] : details.url;
    if (!requestedUrl) throw new Error('Bitwarden requested a window without a URL.');

    let requested: URL;
    try {
      requested = new URL(requestedUrl);
    } catch {
      throw new Error('Bitwarden requested an invalid window URL.');
    }
    const extensionId = this.extensionIds.get(partition);
    if (requested.protocol !== 'chrome-extension:' || requested.hostname !== extensionId) {
      const [, owner] = await this.openExtensionTabInSession(partition, {
        url: requestedUrl,
        windowId: record.owner.id,
      });
      return owner;
    }

    const extensionWindow = new BrowserWindow({
      parent: record.owner,
      show: false,
      autoHideMenuBar: true,
      width: clampWindowDimension(details.width, 420, 320, 1_200),
      height: clampWindowDimension(details.height, 640, 320, 1_200),
      ...(Number.isFinite(details.left) && Number.isFinite(details.top)
        ? { x: Math.round(details.left!), y: Math.round(details.top!) }
        : {}),
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
    extensionWindow.webContents.setMaxListeners(bitwardenExtensionHostMaxListeners);
    this.bitwardenAuxiliaryWindows.set(extensionWindow.id, {
      window: extensionWindow,
      partition,
      sessionId,
    });
    api.addTab(extensionWindow.webContents, extensionWindow);
    api.selectTab(extensionWindow.webContents);
    extensionWindow.webContents.setWindowOpenHandler(({ url }) => {
      void this.openExtensionTabInSession(partition, {
        url,
        windowId: extensionWindow.id,
      }).catch(() => undefined);
      return { action: 'deny' };
    });
    extensionWindow.webContents.on('will-navigate', (event, url) => {
      let sameExtension = false;
      try {
        const target = new URL(url);
        sameExtension = target.protocol === 'chrome-extension:' && target.hostname === extensionId;
      } catch {
        // Invalid navigation is blocked below.
      }
      if (sameExtension) return;
      event.preventDefault();
      void this.openExtensionTabInSession(partition, {
        url,
        windowId: extensionWindow.id,
      }).catch(() => undefined);
    });
    extensionWindow.once('closed', () => {
      this.bitwardenAuxiliaryWindows.delete(extensionWindow.id);
      const source = this.surfaces.get(sessionId);
      if (source?.bitwarden && !source.disposed && !source.owner.isDestroyed()) {
        void this.synchronizeBitwardenStorageInBridge(
          source.owner,
          source.bitwarden.partition,
          source.bitwarden.popupUrl,
        ).catch((error) => {
          console.warn(
            '[Wormhole] Could not flush Bitwarden browser storage after its auxiliary window closed.',
            error,
          );
        });
      }
    });
    try {
      await withBitwardenBrowserTimeout(
        extensionWindow.loadURL(requested.toString()),
        bitwardenBrowserNavigationTimeoutMs,
        'Bitwarden auxiliary window navigation timed out.',
      );
      if (
        mcpApprovalWindowCoordinator.hasPendingApprovals ||
        extensionWindow.isDestroyed() ||
        !authSession.isAccessAllowed ||
        record.disposed ||
        record.owner.isDestroyed()
      ) {
        throw new Error('Bitwarden auxiliary window was cancelled before it could be shown.');
      }
      if (details.focused === false) extensionWindow.showInactive();
      else extensionWindow.show();
      return extensionWindow;
    } catch (error) {
      if (!extensionWindow.isDestroyed()) extensionWindow.destroy();
      throw error;
    }
  }

  private async loadBitwardenExtension(
    partition: string,
    extensionPath: string,
    installKey: string,
    defaultPopup?: string,
    cookieSeed?: BitwardenCookieSeed,
  ): Promise<LoadedBitwardenExtension | undefined> {
    const existing = this.extensionLoads.get(partition);
    if (existing) {
      await existing;
      if (this.extensionLoadKeys.get(partition) === installKey) {
        return this.loadedBitwardenExtension(partition);
      }
      return this.loadBitwardenExtension(
        partition,
        extensionPath,
        installKey,
        defaultPopup,
        cookieSeed,
      );
    }
    let loading!: Promise<void>;
    loading = (async () => {
      try {
        // A background update or manual import can replace the configured bundle while Wormhole is
        // running. Electron otherwise keeps the first unpacked bundle loaded for the lifetime of the
        // partition, so compare the install digest/version and reload it before opening a new tab.
        const previousId = this.extensionIds.get(partition);
        const activeSurfaceCount = [...this.surfaces.values()].filter(
          (record) => !record.disposed && record.bitwarden?.partition === partition,
        ).length;
        if (
          previousId &&
          shouldDeferExtensionReload(
            this.extensionLoadKeys.get(partition),
            installKey,
            activeSurfaceCount,
          )
        ) {
          // Removing an extension immediately detaches it from every WebContents in the shared
          // partition. Keep the loaded version until its final tab closes; the next open then
          // applies the update without turning live Bitwarden buttons into stale popup URLs.
          return;
        }
        for (const [sessionId, popup] of this.bitwardenPopups) {
          const record = this.surfaces.get(sessionId);
          if (record?.bitwarden?.partition === partition && !popup.webContents.isDestroyed()) {
            await this.closeBitwardenPopup(sessionId);
          }
        }
        // Closing a tab starts its final storage bridge asynchronously. Do not remove the loaded
        // extension until every bridge and popup flush for this profile has finished, or the last
        // vault mutations can be lost while Chromium tears down the old service worker.
        await this.bitwardenStorageTasks.waitForIdle(partition);
        const browserSession = electronSession.fromPartition(partition, {
          cache: true,
        });
        const profilePath = browserSession.storagePath;
        if (previousId) {
          browserSession.extensions.removeExtension(previousId);
          this.extensionIds.delete(partition);
          this.extensionPopupPaths.delete(partition);
        }
        if (profilePath) {
          try {
            const seedResult = await runBitwardenBackend<BitwardenBrowserProfileSeedResult>(
              'bitwarden.browser-profile-seed',
              {
                profilePath,
                path: extensionPath,
                query: cookieSeed?.routeKey ?? '',
              },
            );
            if (cookieSeed && seedResult.cookieSourceProfiles.length > 0) {
              await this.seedBitwardenApplianceCookies(
                browserSession,
                seedResult.cookieSourceProfiles,
                cookieSeed.targetUrl,
                seedResult.initialized,
              );
            }
          } catch (error) {
            // Profile seeding is an offline convenience. A locked or concurrently active source
            // IndexedDB must not prevent the HTTPS session or the extension from opening.
            console.warn('[Wormhole] Bitwarden browser profile state could not be seeded.', error);
          }
        }
        // Initialize the chrome.* API bridge before Electron starts Bitwarden's persistent MV2
        // background page. Loading without this bridge produces a popup that looks healthy but
        // cannot communicate with the vault background context.
        await this.ensureChromeExtensionApis(partition);
        const extension = await loadBitwardenExtensionWhenReady(browserSession, extensionPath);
        this.extensionIds.set(partition, extension.id);
        this.extensionLoadKeys.set(partition, installKey);
        if (profilePath) {
          try {
            await runBitwardenBackend('bitwarden.browser-profile-register', {
              profilePath,
              path: extensionPath,
              value: extension.id,
              query: cookieSeed?.routeKey ?? '',
            });
          } catch (error) {
            // Registration only discovers a source for future profiles. Keep the current session
            // usable even when its marker cannot be persisted.
            console.warn('[Wormhole] Bitwarden browser profile could not be registered.', error);
          }
        }
        if (defaultPopup) this.extensionPopupPaths.set(partition, defaultPopup);
        else this.extensionPopupPaths.delete(partition);
        if (defaultPopup) {
          for (const record of this.surfaces.values()) {
            if (record.bitwarden?.partition === partition) {
              record.bitwarden.popupUrl = `chrome-extension://${extension.id}/${defaultPopup}`;
            }
          }
        }
      } catch (error) {
        console.warn(
          '[Wormhole] Bitwarden browser extension could not be loaded for this HTTPS tab.',
          error,
        );
        this.extensionIds.delete(partition);
        this.extensionLoadKeys.delete(partition);
        this.extensionPopupPaths.delete(partition);
      } finally {
        if (this.extensionLoads.get(partition) === loading) {
          this.extensionLoads.delete(partition);
        }
      }
    })();
    this.extensionLoads.set(partition, loading);
    await loading;
    return this.loadedBitwardenExtension(partition);
  }

  private async seedBitwardenApplianceCookies(
    destinationSession: Electron.Session,
    sourceProfilePaths: readonly string[],
    targetUrl: string,
    refreshExisting: boolean,
  ): Promise<void> {
    const destinationCookies = selectBitwardenCookiesForTarget(
      await destinationSession.cookies.get({}),
      targetUrl,
    );
    if (!refreshExisting && destinationCookies.length > 0) return;

    const destinationPath = destinationSession.storagePath;
    for (const sourceProfilePath of new Set(sourceProfilePaths)) {
      if (
        destinationPath &&
        (process.platform === 'win32'
          ? sourceProfilePath.toLowerCase() === destinationPath.toLowerCase()
          : sourceProfilePath === destinationPath)
      ) {
        continue;
      }
      const sourceCookies = selectBitwardenCookiesForTarget(
        await electronSession.fromPath(sourceProfilePath, { cache: true }).cookies.get({}),
        targetUrl,
      );

      if (refreshExisting) {
        const refresh = buildBitwardenCookieRefreshPlan(destinationCookies, sourceCookies);
        for (const cookie of refresh.set) {
          try {
            await destinationSession.cookies.set(buildBitwardenCookieSetDetails(cookie, targetUrl));
          } catch {
            // Continue with the other cookies without exposing their values in a diagnostic.
          }
        }
        for (const cookie of refresh.remove) {
          try {
            const details = buildBitwardenCookieSetDetails(cookie, targetUrl);
            await destinationSession.cookies.remove(details.url, cookie.name);
          } catch {
            // Cookie refresh is best-effort and cookie values must never appear in logs.
          }
        }
        return;
      }

      let copied = 0;
      for (const cookie of sourceCookies) {
        try {
          await destinationSession.cookies.set(buildBitwardenCookieSetDetails(cookie, targetUrl));
          copied++;
        } catch {
          // A malformed or expired individual cookie should not block the remaining appliance
          // session state, and cookie values must never appear in logs.
        }
      }
      if (copied > 0) return;
    }
  }

  private loadedBitwardenExtension(partition: string): LoadedBitwardenExtension | undefined {
    const id = this.extensionIds.get(partition);
    if (!id) return undefined;
    return { id, defaultPopup: this.extensionPopupPaths.get(partition) };
  }

  async runBitwardenExtensionMutation<TResult>(
    operation: () => Promise<TResult>,
  ): Promise<TResult> {
    return this.bitwardenExtensionMutation.runMutation(
      () => this.bitwardenStorageTasks.waitForAllIdle(),
      operation,
    );
  }

  close(sessionId: string): void {
    this.attempts.cancel(sessionId);
    this.pendingOpenOwners.delete(sessionId);
    this.dispose(sessionId);
    void this.releaseTunnel(sessionId).catch((error) => {
      console.warn('[Wormhole] Could not release the web VPN tunnel.', error);
    });
  }

  private dispose(sessionId: string, bitwardenAlreadyFlushed = false): void {
    const record = this.surfaces.get(sessionId);
    if (!record) return;
    record.disposed = true;
    for (const auxiliary of [...this.bitwardenAuxiliaryWindows.values()]) {
      if (auxiliary.sessionId === sessionId && !auxiliary.window.isDestroyed()) {
        auxiliary.window.destroy();
      }
    }
    const hadBitwardenPopup = this.bitwardenPopups.has(sessionId);
    if (!bitwardenAlreadyFlushed) void this.closeBitwardenPopup(sessionId);
    this.surfaces.delete(sessionId);
    if (
      !bitwardenAlreadyFlushed &&
      !hadBitwardenPopup &&
      record.bitwarden &&
      !record.owner.isDestroyed()
    ) {
      void this.synchronizeBitwardenStorageInBridge(
        record.owner,
        record.bitwarden.partition,
        record.bitwarden.popupUrl,
      ).catch((error) => {
        console.warn(
          '[Wormhole] Could not flush Bitwarden browser storage when its HTTPS tab closed.',
          error,
        );
      });
    }
    if (record.bitwarden && record.bitwardenTabRegistered) {
      const api = this.chromeExtensionApis.get(record.bitwarden.partition);
      if (api) {
        try {
          api.removeTab(record.view.webContents);
        } catch {
          // Removing an already-destroyed tab is harmless.
        }
      }
    }
    record.bitwardenUseRelease?.();
    record.bitwardenUseRelease = undefined;
    if (
      record.bitwarden &&
      this.activeBitwardenSessions.get(record.bitwarden.partition) === sessionId
    ) {
      this.activeBitwardenSessions.delete(record.bitwarden.partition);
    }
    if (record.tunnelLeaseId) {
      record.tunnelLeaseId = undefined;
      void this.releaseTunnel(sessionId).catch((error) => {
        console.warn('[Wormhole] Could not release the web VPN tunnel.', error);
      });
    }
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

  private async releaseTunnel(sessionId: string): Promise<void> {
    await this.tunnelLeases.release(sessionId, releaseNativeTunnelLease);
    if (!this.tunnelLeases.has(sessionId)) this.tunnelLeaseOwners.delete(sessionId);
  }

  private assertOpenCurrent(
    sessionId: string,
    generation: number,
    owner: BrowserWindow,
    message: string,
  ): void {
    if (
      !this.attempts.isCurrent(sessionId, generation) ||
      this.pendingOpenOwners.get(sessionId) !== owner ||
      owner.isDestroyed()
    ) {
      throw new Error(message);
    }
  }

  hideAll(): void {
    for (const sessionId of [...this.pendingOpenOwners.keys()]) {
      this.attempts.cancel(sessionId);
      this.pendingOpenOwners.delete(sessionId);
      void this.releaseTunnel(sessionId).catch(() => undefined);
    }
    for (const record of this.surfaces.values()) {
      if (!record.disposed) record.view.setVisible(false);
    }
    this.closeBitwardenFloatingWindows();
  }

  closeBitwardenFloatingWindows(): void {
    for (const sessionId of [...this.bitwardenPopups.keys()]) {
      void this.closeBitwardenPopup(sessionId);
    }
    for (const auxiliary of [...this.bitwardenAuxiliaryWindows.values()]) {
      if (!auxiliary.window.isDestroyed()) auxiliary.window.destroy();
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
    for (const sessionId of this.tunnelLeases.keys()) {
      if (this.tunnelLeaseOwners.get(sessionId) === owner) sessionIds.add(sessionId);
    }
    for (const sessionId of sessionIds) this.close(sessionId);
  }

  async flushAndCloseForWindow(owner: BrowserWindow): Promise<void> {
    const sessionIds = new Set<string>();
    for (const [sessionId, record] of this.surfaces) {
      if (record.owner === owner) sessionIds.add(sessionId);
    }
    for (const [sessionId, pendingOwner] of this.pendingOpenOwners) {
      if (pendingOwner === owner) sessionIds.add(sessionId);
    }
    for (const sessionId of this.tunnelLeases.keys()) {
      if (this.tunnelLeaseOwners.get(sessionId) === owner) sessionIds.add(sessionId);
    }
    const popupSessions = new Set(
      [...this.bitwardenPopups.keys()].filter(
        (sessionId) => this.surfaces.get(sessionId)?.owner === owner,
      ),
    );
    for (const sessionId of popupSessions) {
      await this.closeBitwardenPopup(sessionId, true);
    }
    for (const [sessionId, record] of this.surfaces) {
      if (
        record.owner !== owner ||
        popupSessions.has(sessionId) ||
        !record.bitwarden ||
        owner.isDestroyed()
      ) {
        continue;
      }
      try {
        await this.synchronizeBitwardenStorageInBridge(
          owner,
          record.bitwarden.partition,
          record.bitwarden.popupUrl,
        );
      } catch (error) {
        console.warn(
          '[Wormhole] Could not flush Bitwarden browser storage while closing its window.',
          error,
        );
      }
    }
    for (const sessionId of sessionIds) {
      this.attempts.cancel(sessionId);
      this.pendingOpenOwners.delete(sessionId);
      const record = this.surfaces.get(sessionId);
      await this.releaseTunnel(sessionId).catch(() => undefined);
      if (record) record.tunnelLeaseId = undefined;
      this.dispose(sessionId, true);
    }
  }

  async flushAndCloseAll(): Promise<void> {
    const sessionIds = new Set([
      ...this.surfaces.keys(),
      ...this.pendingOpenOwners.keys(),
      ...this.tunnelLeases.keys(),
    ]);
    const popupSessions = new Set(this.bitwardenPopups.keys());
    for (const sessionId of popupSessions) {
      await this.closeBitwardenPopup(sessionId, true);
    }
    for (const [sessionId, record] of this.surfaces) {
      if (popupSessions.has(sessionId) || !record.bitwarden || record.owner.isDestroyed()) continue;
      try {
        await this.synchronizeBitwardenStorageInBridge(
          record.owner,
          record.bitwarden.partition,
          record.bitwarden.popupUrl,
        );
      } catch (error) {
        console.warn(
          '[Wormhole] Could not flush Bitwarden browser storage during application shutdown.',
          error,
        );
      }
    }
    for (const sessionId of sessionIds) {
      this.attempts.cancel(sessionId);
      this.pendingOpenOwners.delete(sessionId);
      const record = this.surfaces.get(sessionId);
      await this.releaseTunnel(sessionId).catch(() => undefined);
      if (record) record.tunnelLeaseId = undefined;
      this.dispose(sessionId, true);
    }
  }

  backendStopped(): void {
    this.tunnelLeases.clear();
    this.tunnelLeaseOwners.clear();
    for (const record of this.surfaces.values()) record.tunnelLeaseId = undefined;
  }

  private configureWebContents(
    sessionId: string,
    record: WebSurfaceRecord,
    target: WebTargetResponse,
  ): void {
    const contents = record.view.webContents;
    const routeNavigation = (url: string) =>
      getInSessionNavigationUrl(
        url,
        record.navigation.originalUrl ? record.navigation.navigateUrl : undefined,
        record.navigation.originalUrl,
      );
    contents.setWindowOpenHandler(({ url }) => {
      const navigationUrl = routeNavigation(url);
      if (!navigationUrl || !isAllowedWebNavigation(navigationUrl)) return { action: 'deny' };
      void contents.loadURL(navigationUrl).catch(() => undefined);
      return { action: 'deny' };
    });
    const enforceRoutedNavigation = (event: Electron.Event, url: string) => {
      const navigationUrl = routeNavigation(url);
      if (!navigationUrl || !isAllowedWebNavigation(navigationUrl)) {
        event.preventDefault();
        return;
      }
      if (navigationUrl !== url) {
        event.preventDefault();
        void contents.loadURL(navigationUrl).catch(() => undefined);
      }
    };
    contents.on('will-navigate', enforceRoutedNavigation);
    contents.on('will-redirect', enforceRoutedNavigation);
    contents.on('context-menu', (_event, params) => {
      if (!authSession.isAccessAllowed || !record.bitwarden) return;
      const api = this.chromeExtensionApis.get(record.bitwarden.partition);
      if (!api) return;
      const items = api.getContextMenuItems(contents, params);
      if (items.length === 0) return;
      const menu = new Menu();
      for (const item of items) menu.append(item);
      menu.popup({ window: record.owner });
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
    contents.on('did-start-loading', () =>
      this.sendEvent(sessionId, record, 'navigation', { isLoading: true }),
    );
    contents.on('did-stop-loading', () =>
      this.sendEvent(sessionId, record, 'navigation', { isLoading: false }),
    );
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
          this.beginInitialNavigationFailure(
            sessionId,
            record,
            describeWebLoadFailure(errorCode, errorDescription),
          );
          return;
        }
        this.sendEvent(sessionId, record, 'navigation');
      },
    );
    contents.on('render-process-gone', () => {
      if (record.disposed || this.surfaces.get(sessionId) !== record) return;
      record.initialNavigationPending = false;
      this.sendEvent(sessionId, record, 'failed', {
        error: 'The browser process stopped unexpectedly.',
      });
      // A crashed renderer no longer has a connection that can consume this route. Dispose the
      // unusable surface and release its VPN lease instead of leaving the proxy alive until the
      // user closes or retries the failed tab.
      this.close(sessionId);
    });
    contents.once('destroyed', () => {
      if (record.disposed || this.surfaces.get(sessionId) !== record) return;
      // Covers destruction paths that do not emit render-process-gone (for example a native
      // WebContents teardown during an owner-window failure).
      this.close(sessionId);
    });
  }

  private beginInitialNavigationFailure(
    sessionId: string,
    record: WebSurfaceRecord,
    error: string,
  ): void {
    if (
      record.disposed ||
      !record.initialNavigationPending ||
      this.surfaces.get(sessionId) !== record
    ) {
      return;
    }
    record.initialNavigationPending = false;
    void this.finishInitialNavigationFailure(sessionId, record, error);
  }

  private async finishInitialNavigationFailure(
    sessionId: string,
    record: WebSurfaceRecord,
    error: string,
  ): Promise<void> {
    const leaseId = record.tunnelLeaseId;
    const backend = record.tunnelBackend;
    const probeTarget = record.tunnelProbeTarget;
    let finalError = error;
    if (leaseId && backend && probeTarget) {
      try {
        await backend.probeTunnelTarget(leaseId, probeTarget.host, probeTarget.port);
      } catch {
        finalError = `The VPN tunnel is up, but target ${probeTarget.host}:${probeTarget.port} did not respond through it. Check that the target allows access from the VPN network.`;
      }
    }
    if (record.disposed || this.surfaces.get(sessionId) !== record) return;

    this.sendEvent(sessionId, record, 'failed', { error: finalError });
    if (leaseId && this.tunnelLeases.isActive(sessionId, leaseId)) {
      record.tunnelLeaseId = undefined;
      void this.releaseTunnel(sessionId).catch((releaseError) => {
        console.warn(
          '[Wormhole] Could not release the failed web session VPN tunnel.',
          releaseError,
        );
      });
    }
  }

  private sendEvent(
    sessionId: string,
    record: WebSurfaceRecord,
    type: 'connected' | 'failed' | 'navigation',
    values: { error?: string; isLoading?: boolean } = {},
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
        isLoading: values.isLoading ?? contents.isLoading(),
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

function clampWindowDimension(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  return Number.isFinite(value)
    ? Math.min(maximum, Math.max(minimum, Math.round(value!)))
    : fallback;
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
  // Go remains the lifecycle source of truth. Electron retains only the IDs Go explicitly marks
  // so an unexpected child exit can deliver the terminal closed event to the renderer.
  private readonly retainedMismatchSessions = new Set<string>();
  private readonly tunnelLeases = new TunnelLeaseRegistry();
  private readonly connectionAttempts = new WebSessionAttemptTracker();
  private readonly pendingConnections = new Map<string, number>();
  private readonly openWaiters = new Map<
    string,
    {
      resolve: (response: SshConnectedResponse) => void;
      reject: (error: Error) => void;
      timeout: NodeJS.Timeout;
      usedBitwarden: boolean;
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

  async open(request: SshOpenRequest, authorizationEpoch: number): Promise<SshConnectedResponse> {
    if (
      this.pendingConnections.has(request.sessionId) ||
      this.openWaiters.has(request.sessionId) ||
      this.activeSessions.has(request.sessionId)
    ) {
      throw new Error('SSH session id is already in use.');
    }
    const generation = this.connectionAttempts.begin(request.sessionId);
    this.pendingConnections.set(request.sessionId, generation);
    try {
      return await this.openCurrent(request, authorizationEpoch, generation);
    } finally {
      if (this.pendingConnections.get(request.sessionId) === generation) {
        this.pendingConnections.delete(request.sessionId);
      }
    }
  }

  private async openCurrent(
    request: SshOpenRequest,
    authorizationEpoch: number,
    generation: number,
  ): Promise<SshConnectedResponse> {
    let bitwardenCredential: BitwardenResolvedCredential = { bitwarden: false };
    if ((request.nodeId || request.credentialId) && !request.manualCredentials) {
      try {
        bitwardenCredential = await runBitwardenBackend<BitwardenResolvedCredential>(
          request.credentialId ? 'bitwarden.resolve-credential' : 'bitwarden.resolve-node',
          request.credentialId
            ? { credentialId: request.credentialId, protocol: 'ssh' }
            : { nodeId: request.nodeId, protocol: 'ssh' },
        );
      } catch (error) {
        const message = error instanceof Error ? error.message : 'The vault could not be read.';
        throw new Error(`Bitwarden credential is unavailable: ${message}`);
      }
      if (bitwardenCredential.bitwarden && !bitwardenCredential.username?.trim()) {
        throw new Error('Bitwarden credential is unavailable: the SSH username is missing.');
      }
    }
    if (!this.connectionAttempts.isCurrent(request.sessionId, generation)) {
      throw new Error('SSH connection closed before opening its VPN tunnel.');
    }
    requireAuthorizationEpoch(authorizationEpoch);
    await this.releaseTunnel(request.sessionId);
    if (!this.connectionAttempts.isCurrent(request.sessionId, generation)) {
      throw new Error('SSH connection closed before opening its VPN tunnel.');
    }
    let socksEndpoint = '';
    const tunnelRequested = Boolean(request.nodeId || request.tunnelConfigId);
    let leaseId: string | undefined;
    if (tunnelRequested) {
      leaseId = randomUUID();
      this.tunnelLeases.claim(request.sessionId, leaseId);
      try {
        socksEndpoint = await getNativeBackend().acquireTunnel({
          leaseId,
          nodeId: request.nodeId,
          tunnelConfigId: request.tunnelConfigId,
          progressSessionId: request.sessionId,
        });
      } catch (error) {
        await this.releaseTunnel(request.sessionId).catch(() => undefined);
        throw error;
      }
      if (
        !this.connectionAttempts.isCurrent(request.sessionId, generation) ||
        !this.tunnelLeases.isActive(request.sessionId, leaseId)
      ) {
        throw new Error('SSH connection closed while opening its VPN tunnel.');
      }
      if (!socksEndpoint) {
        await this.releaseTunnel(request.sessionId);
        if (request.tunnelConfigId) {
          throw new Error('The VPN tunnel returned no SOCKS endpoint.');
        }
      }
    }
    try {
      if (!this.connectionAttempts.isCurrent(request.sessionId, generation)) {
        throw new Error('SSH connection closed before it could start.');
      }
      requireAuthorizationEpoch(authorizationEpoch);
      this.ensureStarted();
    } catch (error) {
      await this.releaseTunnel(request.sessionId);
      throw error;
    }

    return await this.waitForConnection(request.sessionId, bitwardenCredential.bitwarden, () => {
      this.write({
        type: 'open',
        session_id: request.sessionId,
        node_id: request.nodeId,
        credential_id:
          request.credentialId && !bitwardenCredential.bitwarden ? request.credentialId : undefined,
        auto_sudo: request.autoSudo,
        host: request.host,
        port: request.port,
        username: request.nodeId ? undefined : request.username,
        password: request.nodeId ? undefined : request.password,
        tunnel_config_id: request.tunnelConfigId,
        socks_endpoint: socksEndpoint,
        tunnel_enabled: request.nodeId && !socksEndpoint ? false : undefined,
        username_override: request.manualCredentials
          ? request.username?.trim()
          : bitwardenCredential.bitwarden
            ? bitwardenCredential.username
            : undefined,
        username_override_authoritative:
          request.manualCredentials === true || request.credentialId !== undefined,
        password_override: request.manualCredentials
          ? request.password
          : bitwardenCredential.bitwarden
            ? bitwardenCredential.password
            : undefined,
        credential_override: request.manualCredentials === true || bitwardenCredential.bitwarden,
        key_passphrase_override: request.manualKeyPassphrase ? request.keyPassphrase : undefined,
        columns: request.columns,
        rows: request.rows,
      });
    });
  }

  async trustHostKey(request: SshHostKeyTrustRequest): Promise<SshConnectedResponse> {
    if (
      this.pendingConnections.has(request.sessionId) ||
      this.openWaiters.has(request.sessionId) ||
      this.activeSessions.has(request.sessionId)
    ) {
      throw new Error('SSH session is not waiting for host-key trust.');
    }
    this.ensureStarted();
    return this.waitForConnection(request.sessionId, false, () => {
      this.write({
        type: 'host-key-trust',
        session_id: request.sessionId,
        node_id: request.nodeId,
        host_key_expected: request.expected,
        host_key_received: request.received,
      });
    });
  }

  private waitForConnection(
    sessionId: string,
    usedBitwarden: boolean,
    start: () => void,
  ): Promise<SshConnectedResponse> {
    return new Promise<SshConnectedResponse>((resolve, reject) => {
      const timeout = setTimeout(() => {
        const waiter = this.openWaiters.get(sessionId);
        if (!waiter || waiter.timeout !== timeout) return;
        this.openWaiters.delete(sessionId);
        void this.releaseTunnel(sessionId).catch(() => undefined);
        reject(new Error('SSH connection timed out.'));
        try {
          this.write({ type: 'close', session_id: sessionId });
        } catch {
          // The backend may already have stopped; the timeout has released the renderer.
        }
      }, nativeConnectionTimeoutMs);
      this.openWaiters.set(sessionId, {
        resolve,
        reject,
        timeout,
        usedBitwarden,
      });
      try {
        start();
      } catch (error) {
        this.openWaiters.delete(sessionId);
        clearTimeout(timeout);
        void this.releaseTunnel(sessionId).catch(() => undefined);
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
    this.write({
      type: 'sftp-open',
      session_id: sessionId,
      request_id: requestId,
    });
  }

  listSftp(sessionId: string, path: string, requestId = ''): void {
    this.write({
      type: 'sftp-list',
      session_id: sessionId,
      path,
      request_id: requestId,
    });
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

  prepareForLock(): void {
    mcpApprovalWindowCoordinator.reset();
    try {
      this.write({ type: 'app-lock-all' });
    } catch {
      // A broken pipe during lock/reload is already a terminal cleanup state.
    }
  }

  async close(sessionId: string): Promise<void> {
    this.connectionAttempts.cancel(sessionId);
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
    await this.releaseTunnel(sessionId);
  }

  cancelPendingConnections(): void {
    for (const sessionId of this.pendingConnections.keys()) {
      void this.close(sessionId).catch((error) => {
        console.warn('[Wormhole] Could not release a pending SSH VPN tunnel.', error);
      });
    }
  }

  private async releaseTunnel(sessionId: string): Promise<void> {
    await this.tunnelLeases.release(sessionId, releaseNativeTunnelLease);
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
    if (!this.child || this.child.killed) {
      return runBackend<McpStatusResponse>('mcp-status');
    }
    const response = await this.sendMcpControl({ type: 'mcp.status' });
    if (!response.status) throw new Error('MCP service returned no status.');
    return response.status;
  }

  async startMcp(port: number): Promise<McpStatusResponse> {
    const response = await this.sendMcpControl({ type: 'mcp.start', port });
    if (!response.status) throw new Error('MCP service returned no status.');
    return response.status;
  }

  async stopMcp(): Promise<McpStatusResponse> {
    const response = await this.sendMcpControl({ type: 'mcp.stop' });
    if (!response.status) throw new Error('MCP service returned no status.');
    return response.status;
  }

  async setMcpPort(port: number): Promise<McpStatusResponse> {
    const response = await this.sendMcpControl({ type: 'mcp.set-port', port });
    if (!response.status) throw new Error('MCP service returned no status.');
    return response.status;
  }

  async getMcpToken(): Promise<string> {
    const response = await this.sendMcpControl({ type: 'mcp.get-token' });
    if (!response.token) throw new Error('MCP service returned no token.');
    return response.token;
  }

  async regenerateMcpToken(): Promise<string> {
    const response = await this.sendMcpControl({
      type: 'mcp.regenerate-token',
    });
    if (!response.token) throw new Error('MCP service returned no token.');
    return response.token;
  }

  async respondMcpApproval(approvalId: string, approved: boolean): Promise<void> {
    await this.sendMcpControl({
      type: 'mcp.approve',
      approval_id: approvalId,
      approved,
    });
  }

  async setMcpLocked(locked: boolean): Promise<void> {
    if (!this.child || this.child.killed) return;
    await this.sendMcpControl({ type: locked ? 'mcp.lock' : 'mcp.unlock' });
  }

  async syncMcpAfterUnlock(authorizationEpoch: number): Promise<void> {
    let startError: unknown;
    try {
      const status = await this.mcpStatus();
      if (!isAuthorizationEpochCurrent(authorizationEpoch)) {
        await this.setMcpLocked(true).catch(() => undefined);
        return;
      }
      if (status.enabled && !status.running) await this.startMcp(status.port);
    } catch (error) {
      startError = error;
    }
    if (!isAuthorizationEpochCurrent(authorizationEpoch)) {
      await this.setMcpLocked(true).catch(() => undefined);
      return;
    }
    await this.setMcpLocked(false);
    if (startError instanceof Error) throw startError;
    if (startError !== undefined) throw new Error(String(startError));
  }

  async dispose(): Promise<void> {
    mcpApprovalWindowCoordinator.reset();
    for (const sessionId of this.pendingConnections.keys()) {
      this.connectionAttempts.cancel(sessionId);
    }
    for (const waiter of this.openWaiters.values()) {
      clearTimeout(waiter.timeout);
      waiter.reject(new Error('SSH service stopped.'));
    }
    this.openWaiters.clear();
    this.failControlWaiters(new Error('SSH service stopped.'));
    this.activeSessions.clear();
    this.retainedMismatchSessions.clear();
    const tunnelReleases = this.tunnelLeases.releaseAll(releaseNativeTunnelLease);
    this.lineReader?.close();
    this.lineReader = undefined;
    const child = this.child;
    this.child = undefined;
    if (child && !child.killed) {
      const exited = await stopChildProcess(child);
      if (!exited) {
        console.warn('[Wormhole] SSH service did not stop within the allowed time.');
      }
    }
    await tunnelReleases;
  }

  backendStopped(): void {
    this.tunnelLeases.clear();
    this.retainedMismatchSessions.clear();
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
    const lineReader = createInterface({
      input: child.stdout,
      crlfDelay: Infinity,
    });
    this.lineReader = lineReader;
    lineReader.on('line', (line) => {
      if (this.child === child) this.handleLine(line);
    });
    child.stdin.on('error', (error) => {
      if (this.child !== child) return;
      const failure = new Error(`SSH service connection failed: ${error.message}`);
      this.failOpenWaiters(failure);
      this.failControlWaiters(failure);
    });
    child.stderr.on('data', () => {
      // The backend deliberately keeps protocol events on stdout. Drain stderr so a native
      // failure cannot block the session pipe; do not mirror raw backend text into the UI.
    });
    child.on('error', (error) => {
      if (this.child !== child) return;
      const failure = new Error(`SSH service failed: ${error.message}`);
      this.failOpenWaiters(failure);
      this.failControlWaiters(failure);
    });
    child.on('exit', () => {
      lineReader.close();
      if (this.child !== child) return;
      this.child = undefined;
      if (this.lineReader === lineReader) this.lineReader = undefined;
      const closedSessions = drainSshBackendSessionIds(
        this.activeSessions,
        this.retainedMismatchSessions,
      );
      for (const sessionId of closedSessions) {
        this.broadcast({ type: 'closed', sessionId });
      }
      const failure = new Error('SSH service stopped.');
      this.failOpenWaiters(failure);
      this.failControlWaiters(failure);
      void this.tunnelLeases.releaseAll(releaseNativeTunnelLease);
    });
  }

  private write(command: Record<string, unknown>): void {
    const child = this.child;
    if (!child || child.killed || child.stdin.destroyed) {
      throw new Error('SSH service is not running.');
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
        reject(new Error('MCP service did not respond in time.'));
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
      const windows = BrowserWindow.getAllWindows();
      mcpApprovalWindowCoordinator.beginApproval(mcpMessage.requestId);
      webSurfaces.closeBitwardenFloatingWindows();
      const approvalWindow = selectMcpApprovalWindow(
        windows,
        BrowserWindow.getFocusedWindow(),
        (window) => windowCloseCoordinators.has(window),
      );
      if (approvalWindow) bringMcpApprovalWindowToFront(approvalWindow);
      for (const window of windows) {
        if (!window.isDestroyed() && windowCloseCoordinators.has(window)) {
          window.webContents.send('mcp:approval', mcpMessage);
        }
      }
      return;
    }
    const event = parseSshBackendEvent(line);
    if (!event) return;

    if (event.type === 'connected') {
      this.activeSessions.add(event.sessionId);
      this.retainedMismatchSessions.delete(event.sessionId);
      const waiter = this.openWaiters.get(event.sessionId);
      if (waiter) {
        this.pendingConnections.delete(event.sessionId);
        this.openWaiters.delete(event.sessionId);
        clearTimeout(waiter.timeout);
        waiter.resolve(event);
      }
    } else if (event.type === 'error') {
      const waiter = this.openWaiters.get(event.sessionId);
      if (waiter) {
        this.pendingConnections.delete(event.sessionId);
        this.openWaiters.delete(event.sessionId);
        clearTimeout(waiter.timeout);
        const message = event.error || 'SSH connection failed.';
        const credentialFailure =
          /authenticat|password|permission denied|no usable ssh credential/i.test(message);
        waiter.reject(
          new Error(
            waiter.usedBitwarden && credentialFailure
              ? `Bitwarden credential was rejected by the SSH server: ${message}`
              : message,
          ),
        );
      }
      if (event.retainTunnelLease) {
        this.retainedMismatchSessions.add(event.sessionId);
      } else {
        this.retainedMismatchSessions.delete(event.sessionId);
        void this.releaseTunnel(event.sessionId).catch(() => undefined);
      }
    } else if (event.type === 'closed' || event.type === 'reconnect-failed') {
      const waiter = this.openWaiters.get(event.sessionId);
      if (waiter) {
        this.openWaiters.delete(event.sessionId);
        clearTimeout(waiter.timeout);
        waiter.reject(new Error('SSH connection closed while connecting.'));
      }
      this.activeSessions.delete(event.sessionId);
      this.retainedMismatchSessions.delete(event.sessionId);
      void this.releaseTunnel(event.sessionId).catch(() => undefined);
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

function serializeAuthStateMutation<T>(operation: () => Promise<T>): Promise<T> {
  const result = authStateMutationQueue.then(
    () =>
      serializeAuthOperation(async () => {
        if (authLockRequested) {
          throw new Error('Authentication is required before changing Wormhole security.');
        }
        return operation();
      }),
    () =>
      serializeAuthOperation(async () => {
        if (authLockRequested) {
          throw new Error('Authentication is required before changing Wormhole security.');
        }
        return operation();
      }),
  );
  authStateMutationQueue = result.then(
    () => undefined,
    () => undefined,
  );
  return result;
}

async function runAuthorizedOperation<T, TResult = T>(
  operation: (authorizationEpoch: number) => Promise<T>,
  onAuthorizationLost?: () => Promise<void> | void,
  commit?: (result: T) => TResult,
): Promise<TResult> {
  let epoch = -1;
  let pending!: Promise<T>;
  await serializeAuthOperation(async () => {
    await requireWorkspaceAuth();
    epoch = authSession.authorizationEpoch;
    // Begin the potentially long operation while authorization is serialized, then release the
    // queue immediately so a lock request cannot sit behind network, CLI, or native handshakes.
    pending = operation(epoch);
  });

  let result: T;
  let failure: unknown;
  let failed = false;
  try {
    result = await pending;
  } catch (error) {
    failed = true;
    failure = error;
  }
  let committed!: TResult;
  const stillAuthorized = await serializeAuthOperation(async () => {
    const current = authSession.isAccessAllowed && authSession.authorizationEpoch === epoch;
    if (current && !failed) committed = commit ? commit(result!) : (result! as unknown as TResult);
    return current;
  });
  if (!stillAuthorized) {
    await onAuthorizationLost?.();
    throw new Error('Authentication is required before accessing the Wormhole workspace.');
  }
  if (failed) throw failure;
  return committed;
}

function isAuthorizationEpochCurrent(expectedEpoch: number): boolean {
  return authSession.isAccessAllowed && authSession.authorizationEpoch === expectedEpoch;
}

function requireAuthorizationEpoch(expectedEpoch: number): void {
  if (!isAuthorizationEpochCurrent(expectedEpoch)) {
    throw new Error('Authentication is required before accessing the Wormhole workspace.');
  }
}

async function clearBitwardenSessionAfterAuthorizationLoss(): Promise<void> {
  await nativeBackend?.send({ action: 'bitwarden.clear-session' }).catch(() => undefined);
}

function serializeBitwardenExtensionOperation<T>(operation: () => Promise<T>): Promise<T> {
  const result = bitwardenExtensionOperationQueue.then(operation, operation);
  bitwardenExtensionOperationQueue = result.then(
    () => undefined,
    () => undefined,
  );
  return result;
}

function runAuthorizedBitwardenExtensionOperation<T>(
  operation: (authorizationEpoch: number) => Promise<T>,
): Promise<T> {
  return runAuthorizedOperation((authorizationEpoch) =>
    serializeBitwardenExtensionOperation(async () => {
      requireAuthorizationEpoch(authorizationEpoch);
      return operation(authorizationEpoch);
    }),
  );
}

function rememberAuthState(state: AuthStateResponse, assumeUnlocked: boolean): AuthStateResponse {
  authSession.remember(state, assumeUnlocked);
  currentAuthState = state;
  return state;
}

function refreshAuthSession(): Promise<AuthStateResponse> {
  if (!authRefreshInFlight) {
    authRefreshInFlight = runBackend<AuthStateResponse>('auth-status')
      .then((state) => rememberAuthState(state, false))
      .finally(() => {
        authRefreshInFlight = undefined;
      });
  }
  return authRefreshInFlight;
}

async function ensureAuthSession(): Promise<void> {
  if (!authSession.isInitialized) await refreshAuthSession();
}

async function requireWorkspaceAuth(): Promise<void> {
  await ensureAuthSession();
  authSession.requireUnlocked();
}

function parseMcpPort(value: unknown): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > 65535) {
    throw new Error('MCP port must be an integer between 1 and 65535.');
  }
  return value;
}

function parseMcpApproval(value: unknown): {
  requestId: string;
  approved: boolean;
} {
  if (!isRecord(value)) throw new Error('MCP approval request is invalid.');
  const requestId = typeof value.requestId === 'string' ? value.requestId.trim() : '';
  if (!requestId || requestId.length > 128) throw new Error('MCP approval request is invalid.');
  if (typeof value.approved !== 'boolean') throw new Error('MCP approval decision is invalid.');
  return { requestId, approved: value.approved };
}

function registerIpcHandlers(sshBackend: NativeSshBackend): void {
  ipcMain.on('lifecycle:close-confirmation-ready', (event) => {
    const owner = BrowserWindow.fromWebContents(event.sender);
    if (owner) closeConfirmationReadyWindows.add(owner);
  });
  ipcMain.on('lifecycle:close-confirmation-unready', (event) => {
    const owner = BrowserWindow.fromWebContents(event.sender);
    if (owner) closeConfirmationReadyWindows.delete(owner);
  });
  ipcMain.on(
    'lifecycle:close-confirmation-response',
    (event, requestId: unknown, value: unknown) => {
      if (typeof requestId !== 'string' || typeof value !== 'boolean') return;
      const waiter = closeConfirmationWaiters.get(requestId);
      if (waiter?.webContentsId === event.sender.id) waiter.resolve(value);
    },
  );
  ipcMain.on('lifecycle:active-session-count', (event, value: unknown) => {
    const owner = BrowserWindow.fromWebContents(event.sender);
    if (!owner) return;
    windowCloseCoordinators.get(owner)?.updateActiveCount(value);
  });
  ipcMain.on('lifecycle:teardown-complete', (event, requestId: unknown) => {
    if (typeof requestId !== 'string') return;
    const waiter = rendererTeardownWaiters.get(requestId);
    if (waiter?.webContentsId === event.sender.id) waiter.resolve();
  });
  ipcMain.on('startup:ready', (event) => {
    const owner = BrowserWindow.fromWebContents(event.sender);
    if (!owner || owner.isDestroyed()) return;
    startupReadyWindows.add(owner);
    if (owner.isVisible()) owner.setOpacity(1);
    scheduleUnlockedBackgroundWork();
  });

  ipcMain.handle('startup:load', async (_event, value: unknown) => {
    const request = parseThemeStartupRequest(value);
    return serializeAuthOperation(async () => {
      const startup = await runBackend<StartupResponse>('startup', request);
      if (startup.auth.configured && startup.workspace) {
        throw new Error('Wormhole could not load the locked workspace.');
      }
      rememberAuthState(startup.auth, false);
      scheduleStartupUpdateCheck(startup.settings);
      if (startup.migrationFailed) {
        console.error(
          '[Wormhole] Credential Manager migration failed. It will be retried next launch.',
        );
      } else if (startup.migration.status === 'completed') {
        console.info(
          `[Wormhole] Credential Manager migration completed: ${startup.migration.migrated} migrated, ${startup.migration.missing} missing.`,
        );
      }
      return startup;
    });
  });

  ipcMain.handle('startup:unlock', async (_event, request: unknown) => {
    return serializeAuthOperation(async () => {
      await ensureAuthSession();
      const result = await runBackend<StartupUnlockResponse>('startup-unlock', request);
      if (result.succeeded) {
        if (!result.workspace) throw new Error('Wormhole returned no workspace.');
        authSession.markUnlocked();
      } else if (result.workspace) {
        throw new Error('Wormhole could not verify the workspace lock.');
      }
      return result;
    });
  });

  ipcMain.handle('workspace:load', async () => {
    return runAuthorizedOperation(async () => {
      const workspace = await runBackend<WorkspaceResponse>('workspace');
      console.info(
        `[Wormhole] Workspace loaded: ${workspace.tree.length} roots, ${workspace.credentials.length} credentials, ${workspace.tunnels.length} tunnels.`,
      );
      return workspace;
    });
  });

  ipcMain.handle('workspace:duplicate-node', async (_event, value: unknown) => {
    const request = parseWorkspaceNodeRequest(value);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<WorkspaceDuplicateNodeResponse>('workspace-duplicate-node', request);
    });
  });

  ipcMain.handle('workspace:delete-node', async (_event, value: unknown) => {
    const request = parseWorkspaceNodeRequest(value);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<WorkspaceDeleteNodeResponse>('workspace-delete-node', request);
    });
  });

  ipcMain.handle('workspace:delete-nodes', async (_event, value: unknown) => {
    const request = parseWorkspaceNodesRequest(value);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<WorkspaceDeleteNodeResponse>('workspace-delete-nodes', request);
    });
  });

  ipcMain.handle('workspace:show-credentials', async (_event, value: unknown) => {
    const request = parseWorkspaceNodeRequest(value);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<WorkspaceCredentialRevealResponse>('workspace-show-credentials', request);
    });
  });

  ipcMain.handle('mremote-import:select', async (event) => {
    await serializeAuthOperation(requireWorkspaceAuth);
    mremoteImportAnalysis.get(event.sender)?.abort();
    mremoteImportAnalysis.delete(event.sender);
    mremoteImportSelections.delete(event.sender);
    const owner = BrowserWindow.fromWebContents(event.sender);
    const options: Electron.OpenDialogOptions = {
      title: 'Import connections from mRemoteNG',
      properties: ['openFile'],
      filters: [
        {
          name: 'mRemoteNG connections',
          extensions: ['xml', 'conf', 'config'],
        },
        { name: 'All files', extensions: ['*'] },
      ],
    };
    const selection = owner
      ? await dialog.showOpenDialog(owner, options)
      : await dialog.showOpenDialog(options);
    if (selection.canceled || selection.filePaths.length !== 1) return null;
    const selectedPath = selection.filePaths[0];
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      const inspected = parseMRemoteImportInspection(
        await runBackend('mremote-import-inspect', { path: selectedPath }),
        path.basename(selectedPath),
      );
      mremoteImportSelections.set(event.sender, { path: selectedPath });
      return inspected;
    });
  });

  ipcMain.handle('mremote-import:analyze', async (event, value: unknown) => {
    const options = parseMRemoteImportOptions(value);
    const selection = mremoteImportSelections.get(event.sender);
    if (!selection) throw new Error('Choose an mRemoteNG file before analyzing it.');
    mremoteImportAnalysis.get(event.sender)?.abort();
    const controller = new AbortController();
    mremoteImportAnalysis.set(event.sender, controller);
    const abortWhenRendererCloses = () => controller.abort();
    event.sender.once('destroyed', abortWhenRendererCloses);
    const planNonce = randomUUID();
    try {
      return await runAuthorizedOperation(
        async () =>
          parseMRemoteImportPlan(
            await runBackend<MRemoteImportPlan>(
              'mremote-import-analyze',
              {
                path: selection.path,
                password: options.password,
                structureOnly: options.structureOnly,
                planNonce,
              },
              backupTimeoutMs,
              controller.signal,
            ),
          ),
        undefined,
        (plan) => {
          mremoteImportSelections.set(event.sender, {
            path: selection.path,
            planNonce,
            planToken: plan.planToken,
            structureOnly: options.structureOnly,
          });
          return plan;
        },
      );
    } finally {
      event.sender.removeListener('destroyed', abortWhenRendererCloses);
      if (mremoteImportAnalysis.get(event.sender) === controller)
        mremoteImportAnalysis.delete(event.sender);
    }
  });

  ipcMain.on('mremote-import:cancel-analysis', (event) => {
    mremoteImportAnalysis.get(event.sender)?.abort();
  });

  ipcMain.on('mremote-import:clear', (event) => {
    mremoteImportAnalysis.get(event.sender)?.abort();
    mremoteImportAnalysis.delete(event.sender);
    mremoteImportSelections.delete(event.sender);
  });

  ipcMain.handle('mremote-import:commit', async (event, value: unknown) => {
    const options = parseMRemoteImportOptions(value);
    const selection = mremoteImportSelections.get(event.sender);
    if (
      !selection?.planNonce ||
      !selection.planToken ||
      selection.structureOnly !== options.structureOnly
    ) {
      throw new Error('Analyze the mRemoteNG file with these options before importing it.');
    }
    const result = parseMRemoteImportResult(
      await runOwnedNativeOperation(event.sender, 'mremote-import', 'mremote.import.commit', {
        path: selection.path,
        password: options.password,
        structureOnly: options.structureOnly,
        planNonce: selection.planNonce,
        planToken: selection.planToken,
      }),
    );
    mremoteImportSelections.delete(event.sender);
    return result;
  });

  ipcMain.handle('mremote-import:cancel-commit', (event) =>
    cancelOwnedNativeOperation(event.sender, 'mremote-import'),
  );

  ipcMain.handle('backup:export', async (event, value: unknown) => {
    const request = parseBackupPasswordRequest(value);
    await serializeAuthOperation(requireWorkspaceAuth);
    const owner = BrowserWindow.fromWebContents(event.sender);
    const date = new Date().toISOString().slice(0, 10).replaceAll('-', '');
    const options: Electron.SaveDialogOptions = {
      title: 'Export Wormhole backup',
      defaultPath: path.join(app.getPath('documents'), `wormhole-backup-${date}.json`),
      filters: [
        { name: 'Wormhole backup', extensions: ['json'] },
        { name: 'All files', extensions: ['*'] },
      ],
    };
    const selection = owner
      ? await dialog.showSaveDialog(owner, options)
      : await dialog.showSaveDialog(options);
    if (selection.canceled || !selection.filePath) return null;
    const backendResult = await runOwnedNativeOperation(
      event.sender,
      'backup-export',
      'backup.export',
      {
        path: selection.filePath,
        password: request.password,
      },
    );
    return parseBackupExportResponse(backendResult, selection.filePath);
  });

  ipcMain.handle('backup:cancel-export', (event) =>
    cancelOwnedNativeOperation(event.sender, 'backup-export'),
  );

  ipcMain.handle('backup:select-import', async (event) => {
    await serializeAuthOperation(requireWorkspaceAuth);
    backupImportSelections.delete(event.sender);
    const owner = BrowserWindow.fromWebContents(event.sender);
    const options: Electron.OpenDialogOptions = {
      title: 'Import Wormhole backup',
      properties: ['openFile'],
      filters: [
        { name: 'Wormhole backup', extensions: ['json'] },
        { name: 'All files', extensions: ['*'] },
      ],
    };
    const selection = owner
      ? await dialog.showOpenDialog(owner, options)
      : await dialog.showOpenDialog(options);
    if (selection.canceled || selection.filePaths.length !== 1) return null;
    const selectedPath = selection.filePaths[0];
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      const inspected = parseBackupInspectResponse(
        await runBackend<BackupInspectBackendResponse>('backup-inspect', {
          path: selectedPath,
        }),
      );
      backupImportSelections.set(event.sender, selectedPath);
      const response: BackupImportSelection = {
        ...inspected,
        fileName: path.basename(selectedPath),
      };
      return response;
    });
  });

  ipcMain.on('backup:clear-import', (event) => {
    backupImportSelections.delete(event.sender);
  });

  ipcMain.handle('backup:import', async (event, value: unknown) => {
    const request = parseBackupPasswordRequest(value);
    const selectedPath = backupImportSelections.get(event.sender);
    if (!selectedPath) throw new Error('Choose a backup file before importing.');
    const backendResult = await runOwnedNativeOperation(
      event.sender,
      'backup-import',
      'backup.import',
      {
        path: selectedPath,
        password: request.password,
      },
    );
    backupImportSelections.delete(event.sender);
    return parseBackupImportResponse(backendResult);
  });

  ipcMain.handle('backup:cancel-import', (event) =>
    cancelOwnedNativeOperation(event.sender, 'backup-import'),
  );

  ipcMain.handle('workspace:create-node', async (_event, value: unknown) => {
    const request = parseWorkspaceNodeWriteRequest(value, false);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<{ nodeId: string }>('workspace-node-create', request);
    });
  });

  ipcMain.handle('workspace:update-node', async (_event, value: unknown) => {
    const request = parseWorkspaceNodeWriteRequest(value, true);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<{ updated: boolean }>('workspace-node-update', request);
    });
  });

  ipcMain.handle('rdp:external-client-requirement', async (_event, value: unknown) => {
    const request = parseRdpExternalClientRequirementRequest(value);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return { required: await resolveRdpExternalClientRequirement(request) };
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

  ipcMain.handle('credential:select-ssh-private-key', async (event) => {
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      const authorizationEpoch = authSession.authorizationEpoch;
      const owner = BrowserWindow.fromWebContents(event.sender);
      const options: Electron.OpenDialogOptions = {
        title: 'Select SSH private key',
        properties: ['openFile'],
        filters: [
          { name: 'SSH private keys', extensions: ['key', 'pem'] },
          { name: 'All files', extensions: ['*'] },
        ],
      };
      const selection = owner
        ? await dialog.showOpenDialog(owner, options)
        : await dialog.showOpenDialog(options);
      if (selection.canceled || selection.filePaths.length !== 1) return null;
      requireAuthorizationEpoch(authorizationEpoch);
      const selectedPath = selection.filePaths[0];
      const selected: SshPrivateKeySelection = {
        id: randomUUID(),
        path: selectedPath,
        fileName: sshPrivateKeyDisplayName(selectedPath),
      };
      sshPrivateKeySelections.set(event.sender, selected);
      return { selectionId: selected.id, fileName: selected.fileName };
    });
  });

  ipcMain.handle('credential:discard-ssh-private-key', (event, value: unknown) => {
    const selectionId = isRecord(value) ? value.selectionId : undefined;
    if (!isUuid(selectionId)) {
      throw new Error('SSH private key selection is invalid.');
    }
    const selected = sshPrivateKeySelections.get(event.sender);
    if (selected?.id !== selectionId) return { discarded: false };
    sshPrivateKeySelections.delete(event.sender);
    return { discarded: true };
  });

  ipcMain.handle('workspace:create-credential', async (event, value: unknown) => {
    const request = parseCredentialCreateRequest(value);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      const selection = request.privateKeySelectionId
        ? sshPrivateKeySelections.get(event.sender)
        : undefined;
      if (request.privateKeySelectionId && selection?.id !== request.privateKeySelectionId) {
        throw new Error('Select the SSH private key again.');
      }
      const { privateKeySelectionId: _selectionId, ...backendRequest } = request;
      const credential = await runBackend<WorkspaceCredential>('credential-create', {
        ...backendRequest,
        ...(selection ? { privateKeyPath: selection.path } : {}),
      });
      if (selection) sshPrivateKeySelections.delete(event.sender);
      return credential;
    });
  });

  ipcMain.handle('workspace:update-credential', async (event, value: unknown) => {
    const request = parseCredentialUpdateRequest(value);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      const selection = request.privateKeySelectionId
        ? sshPrivateKeySelections.get(event.sender)
        : undefined;
      if (request.privateKeySelectionId && selection?.id !== request.privateKeySelectionId) {
        throw new Error('Select the SSH private key again.');
      }
      const { privateKeySelectionId: _selectionId, ...backendRequest } = request;
      const credential = await runBackend<WorkspaceCredential>('credential-update', {
        ...backendRequest,
        ...(selection ? { privateKeyPath: selection.path } : {}),
      });
      if (selection) sshPrivateKeySelections.delete(event.sender);
      return credential;
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

  ipcMain.handle('settings:set-theme', async (_event, value: unknown) => {
    if (!isAppTheme(value)) throw new Error('Application theme is invalid.');
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<{ updated: boolean }>('settings-set-theme', {
        theme: value,
      });
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

  ipcMain.handle('settings:set-auto-copy-on-select', async (_event, value: unknown) => {
    if (typeof value !== 'boolean') throw new Error('Terminal clipboard setting is invalid.');
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<{ updated: boolean }>('settings-set-auto-copy-on-select', {
        enabled: value,
      });
    });
  });

  ipcMain.handle('settings:set-confirm-on-tab-close', async (_event, value: unknown) => {
    if (typeof value !== 'boolean') throw new Error('Connected-tab close setting is invalid.');
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<{ updated: boolean }>('settings-set-confirm-on-tab-close', {
        enabled: value,
      });
    });
  });

  ipcMain.handle('settings:set-sidebar-width', async (_event, value: unknown) => {
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 10_000) {
      throw new Error('Sidebar width setting is invalid.');
    }
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<{ updated: boolean; sidebarWidth: number }>('settings-set-sidebar-width', {
        width: value,
      });
    });
  });

  ipcMain.handle('settings:set-connection-tree-expansion', async (_event, value: unknown) => {
    const state = parseConnectionTreeExpansionSetting(value);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<{ updated: boolean }>('settings-set-connection-tree-expansion', {
        ...state,
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
      return {
        currentVersion: app.getVersion(),
        result: latestUpdateCheck ?? null,
      };
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
    const expected = latestUpdateCheck;
    if (
      !installerUrl ||
      !installerFileName ||
      path.basename(installerFileName) !== installerFileName ||
      !/^https:\/\//i.test(installerUrl) ||
      !/^[0-9a-f]{64}$/i.test(installerSha256) ||
      !expected?.isUpdateAvailable ||
      installerUrl !== expected.installerUrl ||
      installerFileName !== expected.installerFileName ||
      installerSha256.toLowerCase() !== expected.installerSha256?.toLowerCase() ||
      installerSize !== (expected.installerSize ?? null)
    ) {
      throw new Error('The update download request is invalid.');
    }
    const target = event.sender;
    return downloadUpdateInstaller(
      {
        installerUrl,
        installerFileName,
        installerSha256,
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
    return handleDownloadedUpdate(installerPath);
  });

  ipcMain.handle('update:open-release', async (_event, value: unknown) => {
    if (typeof value !== 'string' || !/^https:\/\/github\.com\//i.test(value)) {
      throw new Error('The release URL is invalid.');
    }
    await shell.openExternal(value);
  });

  ipcMain.handle('settings:logs-info', async () => {
    return serializeAuthOperation(async () => {
      return runBackend<WormholeLogsInfo>('logs-info');
    });
  });

  ipcMain.handle('settings:set-log-retention', async (_event, value: unknown) => {
    const days = typeof value === 'number' && Number.isInteger(value) ? value : NaN;
    if (!Number.isInteger(days)) throw new Error('Log retention setting is invalid.');
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<{ updated: boolean; logRetentionDays: number }>(
        'settings-set-log-retention',
        { days },
      );
    });
  });

  ipcMain.handle('settings:set-log-level', async (_event, value: unknown) => {
    const level = typeof value === 'string' ? value : '';
    if (level !== 'info' && level !== 'debug') {
      throw new Error('Log level setting is invalid.');
    }
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<{ updated: boolean; logLevel: string }>('settings-set-log-level', {
        level,
      });
    });
  });

  ipcMain.handle('extensions:read', async () => {
    return runAuthorizedBitwardenExtensionOperation(() =>
      runBackend<BitwardenExtensionState>('extension-read'),
    );
  });

  ipcMain.handle('extensions:set-enabled', async (_event, value: unknown) => {
    if (typeof value !== 'boolean') throw new Error('Bitwarden extension setting is invalid.');
    return runAuthorizedBitwardenExtensionOperation(() =>
      runBackend<BitwardenExtensionState>('extension-set-enabled', {
        enabled: value,
      }),
    );
  });

  ipcMain.handle('extensions:install', async () => {
    return runAuthorizedBitwardenExtensionOperation((authorizationEpoch) =>
      webSurfaces.runBitwardenExtensionMutation(() => {
        requireAuthorizationEpoch(authorizationEpoch);
        return runBackend<BitwardenExtensionState>(
          'extension-install',
          undefined,
          extensionOperationTimeoutMs,
        );
      }),
    );
  });

  ipcMain.handle('extensions:ensure-installed', async () => {
    return runAuthorizedBitwardenExtensionOperation((authorizationEpoch) =>
      webSurfaces.runBitwardenExtensionMutation(() => {
        requireAuthorizationEpoch(authorizationEpoch);
        return runBackend<BitwardenExtensionState>(
          'extension-ensure-installed',
          undefined,
          extensionOperationTimeoutMs,
        );
      }),
    );
  });

  ipcMain.handle('extensions:import-zip', async (event) => {
    await serializeAuthOperation(requireWorkspaceAuth);
    const owner = BrowserWindow.fromWebContents(event.sender);
    const options: Electron.OpenDialogOptions = {
      title: 'Import Bitwarden browser extension ZIP',
      properties: ['openFile'],
      filters: [{ name: 'Bitwarden extension ZIP', extensions: ['zip'] }],
    };
    const selection = owner
      ? await dialog.showOpenDialog(owner, options)
      : await dialog.showOpenDialog(options);
    if (selection.canceled || selection.filePaths.length !== 1) return null;
    return runAuthorizedBitwardenExtensionOperation((authorizationEpoch) =>
      webSurfaces.runBitwardenExtensionMutation(() => {
        requireAuthorizationEpoch(authorizationEpoch);
        return runBackend<BitwardenExtensionState>(
          'extension-import-zip',
          {
            path: selection.filePaths[0],
          },
          extensionOperationTimeoutMs,
        );
      }),
    );
  });

  ipcMain.handle('extensions:import-folder', async (event) => {
    await serializeAuthOperation(requireWorkspaceAuth);
    const owner = BrowserWindow.fromWebContents(event.sender);
    const options: Electron.OpenDialogOptions = {
      title: 'Import unpacked Bitwarden browser extension folder',
      properties: ['openDirectory'],
    };
    const selection = owner
      ? await dialog.showOpenDialog(owner, options)
      : await dialog.showOpenDialog(options);
    if (selection.canceled || selection.filePaths.length !== 1) return null;
    return runAuthorizedBitwardenExtensionOperation((authorizationEpoch) =>
      webSurfaces.runBitwardenExtensionMutation(() => {
        requireAuthorizationEpoch(authorizationEpoch);
        return runBackend<BitwardenExtensionState>(
          'extension-import-folder',
          {
            path: selection.filePaths[0],
          },
          extensionOperationTimeoutMs,
        );
      }),
    );
  });

  ipcMain.handle('workspace:credentials-for-protocol', async (_event, protocol: unknown) => {
    if (protocol !== 'ssh' && protocol !== 'rdp' && protocol !== 'vnc') {
      throw new Error('Credential protocol is invalid.');
    }
    return runAuthorizedOperation(async () => {
      return runBackend<WorkspaceCredential[]>('credentials-for-protocol', {
        protocol,
      });
    });
  });

  ipcMain.handle('workspace:update-node-credential', async (_event, request: unknown) => {
    if (!isWorkspaceNodeCredentialSettingsRequest(request)) {
      throw new Error('Workspace credential setting is invalid.');
    }
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<{ updated: boolean }>('workspace-update-node-credential', request);
    });
  });

  ipcMain.handle('workspace:update-node-inline-credential', async (_event, request: unknown) => {
    if (!isWorkspaceNodeInlineCredentialRequest(request)) {
      throw new Error('Workspace inline credential is invalid.');
    }
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<{ updated: boolean }>('workspace-update-node-inline-credential', request);
    });
  });

  ipcMain.handle('bitwarden:read', async () => {
    return runAuthorizedOperation(async () => {
      return runBitwardenBackend<BitwardenCliState>('bitwarden.read');
    });
  });

  ipcMain.handle('bitwarden:set-enabled', async (_event, value: unknown) => {
    if (typeof value !== 'boolean') throw new Error('Bitwarden vault setting is invalid.');
    return runAuthorizedOperation(
      () =>
        runBitwardenBackend<BitwardenCliState>('bitwarden.set-enabled', {
          enabled: value,
        }),
      clearBitwardenSessionAfterAuthorizationLoss,
    );
  });

  ipcMain.handle('bitwarden:set-config', async (_event, value: unknown) => {
    const path = isRecord(value) && typeof value.path === 'string' ? value.path : '';
    const serverRegion =
      isRecord(value) && typeof value.serverRegion === 'number' ? value.serverRegion : 0;
    if (
      path.length > 4096 ||
      !Number.isInteger(serverRegion) ||
      serverRegion < 0 ||
      serverRegion > 2
    )
      throw new Error('Bitwarden CLI configuration is invalid.');
    return runAuthorizedOperation(
      () =>
        runBitwardenBackend<BitwardenCliState>('bitwarden.set-config', {
          path,
          serverRegion,
        }),
      clearBitwardenSessionAfterAuthorizationLoss,
    );
  });

  ipcMain.handle('bitwarden:install', async () => {
    return runAuthorizedOperation(() =>
      runBitwardenBackend<BitwardenCliState>('bitwarden.install'),
    );
  });

  ipcMain.handle('bitwarden:status', async () => {
    return runAuthorizedOperation(() =>
      runBitwardenBackend<BitwardenCliStatusResponse>('bitwarden.status'),
    );
  });

  ipcMain.handle('bitwarden:login', async (_event, value: unknown) => {
    const { email, masterPassword, authenticatorCode, serverRegion } = parseCliLoginRequest(value);
    return runAuthorizedOperation(async (authorizationEpoch) => {
      let state = await runBitwardenBackend<BitwardenCliState>('bitwarden.read');
      if (!state.enabled) throw new Error('Bitwarden credential vault is disabled in Settings.');
      if (!state.installed) {
        state = await runBitwardenBackend<BitwardenCliState>('bitwarden.ensure-installed');
      }
      requireAuthorizationEpoch(authorizationEpoch);
      await runBitwardenBackend('bitwarden.set-config', {
        path: state.path,
        serverRegion,
      });
      requireAuthorizationEpoch(authorizationEpoch);
      await runBitwardenBackend('bitwarden.login', {
        email,
        masterPassword,
        authenticatorCode,
      });
      return { loggedIn: true };
    }, clearBitwardenSessionAfterAuthorizationLoss);
  });

  ipcMain.handle('bitwarden:unlock', async (_event, value: unknown) => {
    const masterPassword =
      isRecord(value) && typeof value.masterPassword === 'string' ? value.masterPassword : '';
    if (masterPassword.length === 0 || masterPassword.length > 4096)
      throw new Error('Bitwarden master password is invalid.');
    return runAuthorizedOperation(async () => {
      await runBitwardenBackend('bitwarden.unlock', { masterPassword });
      return { unlocked: true };
    }, clearBitwardenSessionAfterAuthorizationLoss);
  });

  ipcMain.handle('bitwarden:logout', async () => {
    return runAuthorizedOperation(() =>
      runBitwardenBackend<{ loggedOut: boolean }>('bitwarden.logout'),
    );
  });

  ipcMain.handle('bitwarden:sync', async () => {
    return runAuthorizedOperation(
      () =>
        runBitwardenBackend<{
          lastSyncUtc: string;
          lastSyncStatus: string;
          availableCount: number;
          usedCache: boolean;
          lastSyncError?: string;
        }>('bitwarden.sync'),
      clearBitwardenSessionAfterAuthorizationLoss,
    );
  });

  ipcMain.handle('bitwarden:search-items', async (_event, value: unknown) => {
    if (typeof value !== 'string' || value.length > 2048) {
      throw new Error('Bitwarden search query is invalid.');
    }
    return runAuthorizedOperation(
      () =>
        runBitwardenBackend<{ items: BitwardenCliLoginItem[] }>('bitwarden.search', {
          query: value,
        }),
      clearBitwardenSessionAfterAuthorizationLoss,
    );
  });

  ipcMain.handle('bitwarden:node-uses-vault', async (_event, value: unknown) => {
    if (!isRecord(value)) throw new Error('Bitwarden connection request is invalid.');
    if (!isSshSessionId(value.nodeId)) throw new Error('Connection id is invalid.');
    const nodeId = value.nodeId;
    const protocol = value.protocol;
    if (protocol !== 'ssh' && protocol !== 'rdp' && protocol !== 'vnc') {
      throw new Error('Bitwarden connection protocol is invalid.');
    }
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBitwardenBackend<{ bitwarden: boolean }>('bitwarden.node-reference', {
        nodeId,
        protocol,
      });
    });
  });

  ipcMain.handle('logs:open-current-file', async () => {
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<{ opened: boolean }>('open-log-file');
    });
  });

  ipcMain.handle('logs:open-folder', async () => {
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<{ opened: boolean }>('open-logs-folder');
    });
  });

  ipcMain.handle('web:bitwarden-popup-open', async (_event, request: unknown) => {
    if (!isBitwardenPopupOpenRequest(request)) {
      throw new Error('Bitwarden popup request is invalid.');
    }
    if (mcpApprovalWindowCoordinator.hasPendingApprovals) return { open: false };
    return runAuthorizedOperation(() => webSurfaces.openBitwardenPopup(request));
  });

  ipcMain.handle('web:bitwarden-popup-close', async (_event, sessionId: unknown) => {
    if (!isSshSessionId(sessionId)) throw new Error('Web session id is invalid.');
    return afterBitwardenPopupInputEvent(() => webSurfaces.closeBitwardenPopup(sessionId));
  });

  ipcMain.handle('tunnel:create', async (_event, value: unknown) => {
    const request = parseTunnelWriteRequest(value, false);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return parseTunnelDetailsResponse(await runBackend<unknown>('tunnel-create', request));
    });
  });

  ipcMain.handle('tunnel:list', async () => {
    return runAuthorizedOperation(async () =>
      parseTunnelSummaryList(await runBackend<unknown>('tunnel-list')),
    );
  });

  ipcMain.handle('tunnel:read', async (_event, value: unknown) => {
    const request = parseTunnelIDRequest(value);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return parseTunnelDetailsResponse(await runBackend<unknown>('tunnel-read', request));
    });
  });

  ipcMain.handle('tunnel:update', async (_event, value: unknown) => {
    const request = parseTunnelWriteRequest(value, true);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return parseTunnelDetailsResponse(await runBackend<unknown>('tunnel-update', request));
    });
  });

  ipcMain.handle('tunnel:delete', async (_event, value: unknown) => {
    const request = parseTunnelIDRequest(value) as TunnelDeleteRequest;
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runUserDeletion<{ deleted: boolean }>('tunnel-delete', request, 'VPN tunnel');
    });
  });

  ipcMain.handle('tunnel:test', async (event, value: unknown) => {
    requireNativeResourcesRunning();
    const request = parseTunnelTestRequest(value);
    const senderID = event.sender.id;
    if (activeTunnelTests.has(senderID)) throw new Error('A VPN tunnel test is already running.');
    const test: ActiveTunnelTest = {
      leaseId: randomUUID(),
      attempt: request.attempt,
      cancelled: false,
      leases: new TunnelLeaseRegistry(),
      sender: event.sender,
    };
    activeTunnelTests.set(senderID, test);
    sendTunnelTestProgress(test, 'preparing', 'Preparing the VPN tunnel test…');
    const cancelWhenRendererCloses = () => void cancelTunnelTest(test).catch(() => undefined);
    event.sender.once('destroyed', cancelWhenRendererCloses);
    try {
      await runAuthorizedOperation(
        async () => {
          requireNativeResourcesRunning();
          if (test.cancelled) throw new Error('VPN tunnel test was cancelled.');
          const backend = getNativeBackend();
          test.backend = backend;
          test.leases.claim('tunnel-test', test.leaseId);
          const socksEndpoint = await backend.acquireTunnel({
            leaseId: test.leaseId,
            tunnelConfigId: request.id,
            dedicated: true,
          });
          if (test.cancelled) throw new Error('VPN tunnel test was cancelled.');
          if (!socksEndpoint) throw new Error('The VPN tunnel returned no SOCKS endpoint.');
          if (request.targetHost && request.targetPort) {
            sendTunnelTestProgress(
              test,
              'probing',
              `Testing ${request.targetHost}:${request.targetPort} through the VPN tunnel…`,
            );
            try {
              await backend.probeTunnelTarget(test.leaseId, request.targetHost, request.targetPort);
              sendTunnelTestProgress(
                test,
                'reachable',
                'The target is reachable through the VPN tunnel.',
              );
            } catch (error) {
              if (test.cancelled) throw new Error('VPN tunnel test was cancelled.');
              const message = error instanceof Error ? error.message : String(error);
              throw new Error(
                `The VPN tunnel started, but target ${request.targetHost}:${request.targetPort} could not be reached through it: ${message}`,
              );
            }
          }
        },
        () => cancelTunnelTest(test),
      );
      return { connected: true };
    } catch (error) {
      // Cancellation is a normal user outcome. Other test failures are expected user-facing data
      // too, so do not reject the IPC call and make Electron log an unhandled handler error.
      const baseMessage = test.cancelled
        ? 'VPN tunnel test was cancelled.'
        : error instanceof Error
          ? error.message
          : String(error);
      const message =
        !test.cancelled && test.lastProgress && !baseMessage.includes(test.lastProgress)
          ? `${baseMessage}\nLast step: ${test.lastProgress}`
          : baseMessage;
      if (test.cancelled || /cancell/i.test(message)) {
        console.info(`[Wormhole] VPN tunnel test cancelled (${request.id}).`);
      } else {
        console.warn(`[Wormhole] VPN tunnel test failed (${request.id}).`);
      }
      return { connected: false, error: message };
    } finally {
      if (!event.sender.isDestroyed()) {
        event.sender.removeListener('destroyed', cancelWhenRendererCloses);
      }
      await releaseTunnelTest(test).catch((error) => {
        console.warn('[Wormhole] Could not release the VPN tunnel test lease.', error);
      });
      sendTunnelTestProgress(test, 'closed', 'The temporary VPN tunnel is closed.');
      if (activeTunnelTests.get(senderID) === test) activeTunnelTests.delete(senderID);
    }
  });

  ipcMain.handle('tunnel:test-cancel', async (event) => {
    const test = activeTunnelTests.get(event.sender.id);
    if (!test) return { cancelled: false };
    await cancelTunnelTest(test);
    return { cancelled: true };
  });

  ipcMain.handle('tunnel:import-watchguard', async (event) => {
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      const owner = BrowserWindow.fromWebContents(event.sender);
      const options: Electron.OpenDialogOptions = {
        title: 'Import WatchGuard Mobile VPN profile',
        properties: ['openFile'],
        filters: [
          {
            name: 'WatchGuard SSL VPN profile',
            extensions: ['wgssl', 'tgz', 'tar', 'gz'],
          },
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
      const imported = await runBackend<{
        name?: string;
        settings: Record<string, unknown>;
      }>('azure-vpn-import', { path: selection.filePaths[0] });
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
    await getNativeBackend().respondTunnelRoute({
      leaseId,
      promptId,
      value: choice,
    });
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
    return serializeAuthStateMutation(async () => {
      await ensureAuthSession();
      authSession.requireUnlocked();
      const state = await runBackend<AuthStateResponse>('auth-set-secret', request);
      return rememberAuthState(state, true);
    });
  });

  ipcMain.handle('auth:update-settings', async (_event, request: unknown) => {
    return serializeAuthStateMutation(async () => {
      await ensureAuthSession();
      authSession.requireUnlocked();
      const state = await runBackend<AuthStateResponse>('auth-update-settings', request);
      return rememberAuthState(state, true);
    });
  });

  ipcMain.handle('auth:lock', async (event) => {
    authLockRequested = true;
    try {
      await authStateMutationQueue.catch(() => undefined);
      await ensureAuthSession();
      authSession.lock();
      cancelAllUserOperations();
      backupImportSelections.delete(event.sender);
      sshPrivateKeySelections.delete(event.sender);
      mremoteImportAnalysis.get(event.sender)?.abort();
      mremoteImportAnalysis.delete(event.sender);
      mremoteImportSelections.delete(event.sender);
    } finally {
      authLockRequested = false;
    }
    sshBackend.prepareForLock();
    sshBackend.closeAllSftp();
    sshBackend.cancelPendingConnections();
    webSurfaces.hideAll();
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    // Lock is deliberately not queued behind ordinary authorized operations: a VPN test or CLI
    // call can run for minutes. The epoch invalidates their eventual results and the renderer gets
    // an immediate acknowledgement that covers cached SSH/VNC frames.
    void nativeBackend?.send({ action: 'bitwarden.clear-session' }).catch(() => undefined);
    void sshBackend.setMcpLocked(true).catch(() => undefined);
    cancelPreparingRdpStarts();
    if (ownerWindow && !ownerWindow.isDestroyed()) {
      rdpClient?.cancelPendingStarts(nativeWindowHandle(ownerWindow));
      void rdpClient?.hideAll(nativeWindowHandle(ownerWindow)).catch(() => undefined);
    }
  });

  ipcMain.handle('auth:hello-status', async () => {
    if (process.platform !== 'win32') {
      return {
        available: false,
        message: 'Windows Hello only works on Windows.',
      };
    }
    return runBackend('auth-hello-status');
  });

  ipcMain.handle('auth:hello-verify', async (event) => {
    if (process.platform !== 'win32') {
      return {
        succeeded: false,
        message: 'Windows Hello only works on Windows.',
      };
    }
    return serializeAuthOperation(async () => {
      await ensureAuthSession();
      const state = currentAuthState;
      if (!state) throw new Error('Authentication state is not initialized.');
      if (state.mode !== 'windowsHello' || !state.configured) {
        return {
          succeeded: false,
          message: 'Choose Windows Hello in Settings first.',
        };
      }
      const ownerWindow = BrowserWindow.fromWebContents(event.sender);
      if (!ownerWindow || ownerWindow.isDestroyed()) {
        return {
          succeeded: false,
          message: 'Bring Wormhole to the front and try again.',
        };
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
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return sshBackend.mcpStatus();
    });
  });
  ipcMain.handle('mcp:start', async (_event, port: unknown) => {
    const parsedPort = parseMcpPort(port);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return sshBackend.startMcp(parsedPort);
    });
  });
  ipcMain.handle('mcp:stop', async () => {
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return sshBackend.stopMcp();
    });
  });
  ipcMain.handle('mcp:set-port', async (_event, port: unknown) => {
    const parsedPort = parseMcpPort(port);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return sshBackend.setMcpPort(parsedPort);
    });
  });
  ipcMain.handle('mcp:get-token', async () => {
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return sshBackend.getMcpToken();
    });
  });
  ipcMain.handle('mcp:regenerate-token', async () => {
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return sshBackend.regenerateMcpToken();
    });
  });
  ipcMain.handle('mcp:approval', async (_event, value: unknown) => {
    const approval = parseMcpApproval(value);
    return serializeAuthOperation(async () => {
      try {
        await requireWorkspaceAuth();
        await sshBackend.respondMcpApproval(approval.requestId, approval.approved);
      } finally {
        mcpApprovalWindowCoordinator.finishApproval(approval.requestId);
      }
    });
  });

  ipcMain.handle('workspace:update-node-web-settings', async (_event, request: unknown) => {
    if (!isWorkspaceNodeWebSettingsRequest(request)) {
      throw new Error('Workspace web node settings are invalid.');
    }
    return serializeAuthOperation(async () => {
      await ensureAuthSession();
      authSession.requireUnlocked();
      return runBackend<{ updated: boolean }>('workspace-update-node-web-settings', request);
    });
  });
  ipcMain.handle('tree-tooltip:show', (event, request: unknown) => {
    if (!isTreeTooltipRequest(request)) throw new Error('Tree tooltip request is invalid.');
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow || ownerWindow.isDestroyed()) return;
    treeTooltips.show(ownerWindow, request);
  });
  ipcMain.handle('tree-tooltip:hide', (event) => {
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow || ownerWindow.isDestroyed()) return;
    treeTooltips.hide(ownerWindow);
  });
  ipcMain.handle('web:open', async (event, request: unknown) => {
    requireNativeResourcesRunning();
    if (!isWebOpenRequest(request)) throw new Error('Web connection request is invalid.');
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow || ownerWindow.isDestroyed())
      throw new Error('Web session owner window is unavailable.');
    return runAuthorizedOperation(
      () => {
        requireNativeResourcesRunning();
        return webSurfaces.open(ownerWindow, request);
      },
      () => webSurfaces.closeForOwner(ownerWindow, request.sessionId),
    );
  });
  ipcMain.handle('web:set-bounds', async (event, request: unknown) => {
    if (!isWebBoundsRequest(request)) throw new Error('Web surface bounds are invalid.');
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow || ownerWindow.isDestroyed()) return;
    // Bounds updates are intentionally lightweight, but never make private page contents visible
    // after the native workspace was locked.
    if (!authSession.isAccessAllowed) {
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
      await webSurfaces.command(ownerWindow, request);
    });
  });
  ipcMain.handle('web:close', async (event, sessionId: unknown) => {
    if (!isSshSessionId(sessionId)) throw new Error('Web session id is invalid.');
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow || ownerWindow.isDestroyed()) return;
    webSurfaces.closeForOwner(ownerWindow, sessionId);
  });
  ipcMain.handle('ssh:open', async (_event, request: unknown) => {
    requireNativeResourcesRunning();
    if (!isSshOpenRequest(request)) throw new Error('SSH open request is invalid.');
    return runAuthorizedOperation(
      (authorizationEpoch) => {
        requireNativeResourcesRunning();
        return sshBackend.open(request, authorizationEpoch);
      },
      () => sshBackend.close(request.sessionId),
    );
  });
  ipcMain.handle('ssh:trust-host-key', async (_event, request: unknown) => {
    requireNativeResourcesRunning();
    if (!isSshHostKeyTrustRequest(request)) {
      throw new Error('SSH host-key trust request is invalid.');
    }
    return runAuthorizedOperation(
      () => {
        requireNativeResourcesRunning();
        return sshBackend.trustHostKey(request);
      },
      () => sshBackend.close(request.sessionId),
    );
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
  ipcMain.handle('ssh:paste-clipboard', async (_event, sessionId: unknown) => {
    if (!isSshSessionId(sessionId)) throw new Error('SSH paste request is invalid.');
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      const data = encodeTerminalClipboardText(clipboard.readText());
      if (!data) return { pasted: false };
      sshBackend.sendInput(sessionId, data);
      return { pasted: true };
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
    await sshBackend.close(sessionId);
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
      return { id: '', ok: false, error: 'Wormhole service is stopping.' };
    }
    let command: NativeBackendCommand;
    try {
      command = parseVncCommand(input);
    } catch (error) {
      return {
        id: '',
        ok: false,
        error: error instanceof Error ? error.message : 'Invalid VNC command.',
      };
    }
    // Disconnect is an idempotent cleanup boundary, not workspace access. It must remain
    // reachable when a concurrent lock invalidates ordinary VNC commands, otherwise the renderer
    // can remove a closing tab while its native socket and tunnel continue running.
    if (command.action === 'vnc.disconnect') {
      vncSessionAttempts.cancel(command.sessionId!);
      // A disconnect waits for an in-flight credential/tunnel start to observe cancellation and
      // release its eventual resources. Match the longest native credential path instead of
      // timing out at the ordinary 15-second control-command deadline.
      return getNativeBackend().send(command, cliOperationTimeoutMs);
    }
    const attempt =
      command.action === 'vnc.connect' ? vncSessionAttempts.begin(command.sessionId!) : undefined;
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      if (isQuitting) {
        return { id: '', ok: false, error: 'Wormhole service is stopping.' };
      }
      if (attempt !== undefined && !vncSessionAttempts.isCurrent(command.sessionId!, attempt)) {
        return {
          id: '',
          ok: false,
          error: 'VNC connection closed before it could start.',
        };
      }
      return getNativeBackend().send(command);
    });
  });

  ipcMain.handle('rdp:start', async (event, value: unknown) => {
    requireNativeResourcesRunning();
    const request = parseRdpStartRequest(value);
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow) throw new Error('RDP owner window is unavailable.');
    if (request.bounds) rememberRdpSurfacePlacement(ownerWindow, request.sessionId, request.bounds);
    return rdpStartOperations.runExclusive(
      request.sessionId,
      async () => {
        const requestAttempt = rdpStartAttempts.begin(request.sessionId);
        let ownsLifecycle = false;
        const client = getRdpClient();
        let lifecycleId: string | undefined;
        return runAuthorizedOperation(
          async (authorizationEpoch) => {
            requireNativeResourcesRunning();
            let resolvedProfile = request.profile;
            if (request.profile.nodeId) {
              try {
                resolvedProfile = await resolveNativeRdpProfile(
                  request.profile.nodeId,
                  request.manualCredentials === true,
                  request.profile,
                );
              } catch (error) {
                const message =
                  error instanceof Error ? error.message : 'The RDP profile could not be read.';
                throw new Error(`RDP profile is unavailable: ${message}`);
              }
            } else {
              resolvedProfile = { ...request.profile };
              const requiresExternalClient =
                request.profile.useExternalClient === true ||
                (await resolveRdpExternalClientRequirement({
                  username: request.profile.username ?? '',
                  domain: request.profile.domain ?? '',
                  credentialId:
                    request.manualCredentials === true ? undefined : request.profile.credentialId,
                }));
              if (requiresExternalClient) {
                resolvedProfile.useExternalClient = true;
                delete resolvedProfile.username;
                delete resolvedProfile.domain;
                delete resolvedProfile.password;
                delete resolvedProfile.gatewayUsername;
                delete resolvedProfile.gatewayPassword;
              } else {
                if (request.profile.credentialId && request.manualCredentials !== true) {
                  const credential = await resolveNativeRdpCredential(request.profile.credentialId);
                  resolvedProfile.username = credential.username;
                  resolvedProfile.domain = credential.domain;
                  resolvedProfile.password = credential.password;
                }
                const gatewayCredentialId = rdpGatewayCredentialIdForResolution(request.profile);
                if (request.profile.gatewayUsageMethod && request.profile.gatewayUseSameCreds) {
                  resolvedProfile.gatewayUsername = rdpGatewayUsername(
                    resolvedProfile.username,
                    resolvedProfile.domain,
                  );
                  resolvedProfile.gatewayPassword = resolvedProfile.password;
                } else if (gatewayCredentialId) {
                  let gateway: BitwardenResolvedCredential;
                  try {
                    gateway = await resolveNativeRdpCredential(gatewayCredentialId);
                  } catch (error) {
                    const message =
                      error instanceof Error ? error.message : 'credential resolution failed';
                    throw new Error(`RDP Gateway credential is unavailable: ${message}`);
                  }
                  resolvedProfile.gatewayUsername = rdpGatewayUsername(
                    gateway.username,
                    gateway.domain,
                  );
                  resolvedProfile.gatewayPassword = gateway.password;
                }
              }
              delete resolvedProfile.credentialId;
              delete resolvedProfile.gatewayCredentialId;
            }
            assertRdpStartCurrent(request.sessionId, requestAttempt);
            if (client.hasSession(request.sessionId)) {
              throw new Error('RDP session is already running.');
            }
            const generation = rdpSessionAttempts.begin(request.sessionId);
            ownsLifecycle = true;
            requireAuthorizationEpoch(authorizationEpoch);
            const ownerHandle = nativeWindowHandle(ownerWindow);
            const bounds = currentRdpSurfaceScreenBounds(ownerWindow, request.sessionId);
            // A retry reuses the renderer session id. Retire the previous native attempt before its
            // broker lease is released so it cannot overlap the replacement through a closing proxy.
            const previousLifecycleId = client.currentLifecycleId(request.sessionId);
            await client
              .command('disconnect', request.sessionId, ownerHandle, bounds, previousLifecycleId)
              .catch(() => undefined);
            assertRdpStartCurrent(request.sessionId, requestAttempt, generation);
            await releaseRdpTunnelsForSession(request.sessionId);
            assertRdpStartCurrent(request.sessionId, requestAttempt, generation);
            lifecycleId = client.beginStart(request.sessionId);
            rdpConnectingLifecycles.set(lifecycleId, request.sessionId);
            try {
              let socksEndpoint = '';
              if (resolvedProfile.nodeId || resolvedProfile.tunnelConfigId) {
                const leaseId = randomUUID();
                rdpTunnelLeases.claim(lifecycleId, leaseId);
                rdpTunnelLeaseSessions.set(lifecycleId, request.sessionId);
                let route: { active: boolean; socksEndpoint: string };
                try {
                  route = await getNativeBackend().acquireTunnelRoute({
                    leaseId,
                    nodeId: resolvedProfile.nodeId,
                    tunnelConfigId: resolvedProfile.tunnelConfigId,
                    progressSessionId: request.sessionId,
                  });
                } catch (error) {
                  await releaseRdpTunnel(lifecycleId).catch(() => undefined);
                  const message =
                    error instanceof Error ? error.message : 'VPN tunnel establishment failed.';
                  throw new Error(`RDP VPN tunnel is unavailable: ${message}`);
                }
                if (!canProceedWithRdpTunnelRoute(resolvedProfile, route)) {
                  await releaseRdpTunnel(lifecycleId);
                  throw new Error('RDP VPN tunnel returned an invalid route.');
                }
                socksEndpoint = route.socksEndpoint;
                assertRdpStartCurrent(request.sessionId, requestAttempt, generation);
                if (!rdpTunnelLeases.isActive(lifecycleId, leaseId)) {
                  throw new Error('RDP connection closed while opening its VPN tunnel.');
                }
                if (!socksEndpoint) await releaseRdpTunnel(lifecycleId);
              }
              if (!isAuthorizationEpochCurrent(authorizationEpoch)) {
                await releaseRdpTunnel(lifecycleId);
                throw new Error('Authentication is required before opening the RDP connection.');
              }
              if (!socksEndpoint) await releaseRdpTunnel(lifecycleId);
              assertRdpStartCurrent(request.sessionId, requestAttempt, generation);
              const { manualCredentials: _manualCredentials, ...nativeRequest } = request;
              const response = await client.start(
                {
                  ...nativeRequest,
                  profile: {
                    ...resolvedProfile,
                    socksEndpoint: socksEndpoint || undefined,
                    tunnelEnabled: rdpTunnelEnabledForNative(resolvedProfile, socksEndpoint),
                  },
                },
                ownerHandle,
                bounds,
                lifecycleId,
                generation,
              );
              if (
                !rdpStartAttempts.isCurrent(request.sessionId, requestAttempt) ||
                !rdpSessionAttempts.isCurrent(request.sessionId, generation)
              ) {
                throw new Error('RDP connection closed while it was starting.');
              }
              rdpConnectingLifecycles.delete(lifecycleId);
              return response;
            } catch (error) {
              rdpConnectingLifecycles.delete(lifecycleId);
              await settleTunnelCleanup(
                client.command('disconnect', request.sessionId, ownerHandle, bounds, lifecycleId),
                releaseRdpTunnel(lifecycleId),
              ).catch(() => undefined);
              client.cancelStart(request.sessionId, lifecycleId);
              throw error;
            }
          },
          async () => {
            if (!ownsLifecycle) return;
            if (lifecycleId) rdpConnectingLifecycles.delete(lifecycleId);
            if (lifecycleId) {
              const ownerWindowAvailable = !ownerWindow.isDestroyed();
              await settleTunnelCleanup(
                client.command(
                  'disconnect',
                  request.sessionId,
                  ownerWindowAvailable ? nativeWindowHandle(ownerWindow) : '',
                  ownerWindowAvailable ? toScreenBounds(ownerWindow, request.bounds) : undefined,
                  lifecycleId,
                ),
                releaseRdpTunnel(lifecycleId),
              ).catch(() => undefined);
            }
          },
        );
      },
      'RDP session is already starting.',
    );
  });

  ipcMain.handle('rdp:system-client-capability', async (_event, value: unknown) => {
    const request = parseRdpSystemClientCapabilityRequest(value);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return resolveNativeRdpSystemClientCapability(request.nodeId);
    });
  });

  ipcMain.handle('rdp:open-system', async (event, value: unknown) => {
    const request = parseRdpSystemClientOpenRequest(value);
    let ownsLifecycle = false;
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow) throw new Error('RDP owner window is unavailable.');
    let lifecycleId: string | undefined;

    try {
      const result = await rdpStartOperations.runExclusive(
        request.sessionId,
        async () => {
          const requestAttempt = rdpStartAttempts.begin(request.sessionId);
          return runAuthorizedOperation(
            async (authorizationEpoch) => {
              const profile = await resolveNativeRdpSystemProfile(request.nodeId);
              if (!rdpStartAttempts.isCurrent(request.sessionId, requestAttempt)) {
                throw new Error('RDP connection closed before System Remote Desktop could start.');
              }
              const generation = rdpSessionAttempts.begin(request.sessionId);
              ownsLifecycle = true;
              requireAuthorizationEpoch(authorizationEpoch);
              if (ownerWindow.isDestroyed()) throw new Error('RDP owner window is unavailable.');
              const ownerHandle = nativeWindowHandle(ownerWindow);
              const client = getRdpClient();
              const previousLifecycleId = client.currentLifecycleId(request.sessionId);
              await settleTunnelCleanup(
                client.command(
                  'disconnect',
                  request.sessionId,
                  ownerHandle,
                  undefined,
                  previousLifecycleId,
                ),
                releaseRdpTunnelsForSession(request.sessionId),
              );
              forgetRdpSurfacePlacement(request.sessionId);
              if (
                !rdpStartAttempts.isCurrent(request.sessionId, requestAttempt) ||
                !rdpSessionAttempts.isCurrent(request.sessionId, generation)
              ) {
                throw new Error('RDP connection closed before System Remote Desktop could start.');
              }
              requireAuthorizationEpoch(authorizationEpoch);
              lifecycleId = client.beginStart(request.sessionId);
              rdpConnectingLifecycles.set(lifecycleId, request.sessionId);
              try {
                const result = await client.start(
                  { sessionId: request.sessionId, profile },
                  ownerHandle,
                  undefined,
                  lifecycleId,
                  generation,
                );
                if (
                  !rdpStartAttempts.isCurrent(request.sessionId, requestAttempt) ||
                  !rdpSessionAttempts.isCurrent(request.sessionId, generation)
                ) {
                  throw new Error('System Remote Desktop closed while its process was starting.');
                }
                rdpConnectingLifecycles.delete(lifecycleId);
                return result;
              } catch (error) {
                rdpConnectingLifecycles.delete(lifecycleId);
                await settleTunnelCleanup(
                  client.command(
                    'disconnect',
                    request.sessionId,
                    ownerWindow.isDestroyed() ? '' : ownerHandle,
                    undefined,
                    lifecycleId,
                  ),
                  releaseRdpTunnel(lifecycleId),
                ).catch(() => undefined);
                client.cancelStart(request.sessionId, lifecycleId);
                throw error;
              }
            },
            async () => {
              if (!ownsLifecycle) return;
              if (lifecycleId) {
                rdpConnectingLifecycles.delete(lifecycleId);
                await Promise.allSettled([
                  rdpClient?.command(
                    'disconnect',
                    request.sessionId,
                    ownerWindow.isDestroyed() ? '' : nativeWindowHandle(ownerWindow),
                    undefined,
                    lifecycleId,
                  ),
                  releaseRdpTunnel(lifecycleId),
                ]);
              }
            },
          );
        },
        'RDP session is already starting.',
      );
      return { ok: true, event: result } satisfies RdpSystemClientOpenResult;
    } catch (error) {
      const message =
        error instanceof Error ? error.message : 'System Remote Desktop could not start.';
      return {
        ok: false,
        lifecycleCommitted: ownsLifecycle,
        error: message.slice(0, 1024),
      } satisfies RdpSystemClientOpenResult;
    }
  });

  ipcMain.handle('rdp:resize', async (event, value: unknown) => {
    const request = parseRdpCommandRequest(value);
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow) throw new Error('RDP owner window is unavailable.');
    // Geometry is high-frequency, non-secret state. Checking the current auth snapshot keeps it
    // off the global auth-operation queue, where native resize acknowledgements would otherwise
    // serialize every animation frame and make the overlay trail the BrowserWindow.
    await ensureAuthSession();
    authSession.requireUnlocked();
    if (request.bounds) rememberRdpSurfacePlacement(ownerWindow, request.sessionId, request.bounds);
    const client = getRdpClient();
    const bounds = request.bounds ? toScreenBounds(ownerWindow, request.bounds) : undefined;
    return client.resize({ ...request, bounds }, nativeWindowHandle(ownerWindow));
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
    if (request.bounds) rememberRdpSurfacePlacement(ownerWindow, request.sessionId, request.bounds);
    const bounds = request.bounds ? toScreenBounds(ownerWindow, request.bounds) : undefined;
    const client = getRdpClient();
    const lifecycleId =
      operation === 'disconnect' ? client.currentLifecycleId(request.sessionId) : undefined;
    let resumeStarts: (() => void) | undefined;
    if (operation === 'disconnect') {
      resumeStarts = rdpStartOperations.suspend(request.sessionId);
      rdpStartAttempts.cancel(request.sessionId);
      rdpSessionAttempts.cancel(request.sessionId);
      if (lifecycleId) rdpConnectingLifecycles.delete(lifecycleId);
    }
    const command = () =>
      client.command(
        operation,
        request.sessionId,
        nativeWindowHandle(ownerWindow),
        bounds,
        lifecycleId,
      );
    if (operation === 'hide' || operation === 'disconnect') {
      if (operation === 'disconnect') {
        try {
          return await settleTunnelCleanup(
            command(),
            releaseRdpTunnelsForSession(request.sessionId),
          );
        } finally {
          await rdpStartOperations.waitForIdle(request.sessionId);
          forgetRdpSurfacePlacement(request.sessionId);
          resumeStarts?.();
        }
      }
      return command();
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
    if (!isRdpLifecycleEvent(event)) return;
    if (
      event.sessionId &&
      event.lifecycleGeneration !== undefined &&
      !rdpSessionAttempts.isCurrent(event.sessionId, event.lifecycleGeneration)
    ) {
      return;
    }
    const terminalEvent =
      event.type === 'disconnected' ||
      event.type === 'fatalError' ||
      event.type === 'exited' ||
      event.type === 'error';
    if (
      event.sessionId &&
      event.lifecycleId &&
      (terminalEvent || (event.type === 'logonError' && event.credentialFailure === true))
    ) {
      rdpConnectingLifecycles.delete(event.lifecycleId);
      void releaseRdpTunnel(event.lifecycleId).catch((error) => {
        console.warn('[Wormhole] Could not release the RDP VPN tunnel.', error);
      });
    }
    if (event.sessionId && terminalEvent) forgetRdpSurfacePlacement(event.sessionId);
    for (const window of BrowserWindow.getAllWindows()) {
      if (!window.isDestroyed()) window.webContents.send('rdp:event', event);
    }
  });
  return rdpClient;
}

async function releaseRdpTunnel(lifecycleId: string): Promise<void> {
  await rdpTunnelLeases.release(lifecycleId, releaseNativeTunnelLease);
  if (!rdpTunnelLeases.has(lifecycleId)) rdpTunnelLeaseSessions.delete(lifecycleId);
}

async function releaseRdpTunnelsForSession(sessionId: string): Promise<void> {
  const lifecycleIds = [...rdpTunnelLeaseSessions]
    .filter(([, ownerSessionId]) => ownerSessionId === sessionId)
    .map(([lifecycleId]) => lifecycleId);
  const results = await Promise.allSettled(
    lifecycleIds.map((lifecycleId) => releaseRdpTunnel(lifecycleId)),
  );
  const failed = results.find((result) => result.status === 'rejected');
  if (failed?.status === 'rejected') throw failed.reason;
}

function assertRdpStartCurrent(
  sessionId: string,
  requestAttempt: number,
  sessionGeneration?: number,
): void {
  if (
    !rdpStartAttempts.isCurrent(sessionId, requestAttempt) ||
    (sessionGeneration !== undefined && !rdpSessionAttempts.isCurrent(sessionId, sessionGeneration))
  ) {
    throw new Error('RDP connection was closed or superseded before it could start.');
  }
}

function cancelPreparingRdpStarts(): void {
  rdpStartAttempts.cancelAll();
  rdpSessionAttempts.cancelAll();
  for (const [lifecycleId, sessionId] of rdpConnectingLifecycles) {
    rdpConnectingLifecycles.delete(lifecycleId);
    rdpClient?.cancelStart(sessionId, lifecycleId);
    void releaseRdpTunnel(lifecycleId).catch((error) => {
      console.warn('[Wormhole] Could not release a pending RDP VPN tunnel.', error);
    });
  }
}

async function releaseAllRdpTunnels(): Promise<void> {
  const results = await rdpTunnelLeases.releaseAll(releaseNativeTunnelLease);
  for (const lifecycleId of [...rdpTunnelLeaseSessions.keys()]) {
    if (!rdpTunnelLeases.has(lifecycleId)) rdpTunnelLeaseSessions.delete(lifecycleId);
  }
  if (results.some((result) => result.status === 'rejected')) {
    console.warn('[Wormhole] One or more RDP VPN tunnel leases could not be released cleanly.');
  }
}

function rememberRdpSurfacePlacement(
  owner: BrowserWindow,
  sessionId: string,
  rendererBounds: RdpSurfaceRect,
): void {
  rdpSurfacePlacements.set(sessionId, {
    owner,
    rendererBounds: { ...rendererBounds },
  });
}

function forgetRdpSurfacePlacement(sessionId: string): void {
  rdpSurfacePlacements.delete(sessionId);
}

function currentRdpSurfaceScreenBounds(
  owner: BrowserWindow,
  sessionId: string,
): RdpSurfaceRect | undefined {
  const placement = rdpSurfacePlacements.get(sessionId);
  if (!placement || placement.owner !== owner) return undefined;
  return toScreenBounds(owner, placement.rendererBounds);
}

function clearRdpSurfacePlacements(owner: BrowserWindow): void {
  const task = rdpOwnerSyncTasks.get(owner.id);
  if (task) clearImmediate(task);
  rdpOwnerSyncTasks.delete(owner.id);
  for (const [sessionId, placement] of rdpSurfacePlacements) {
    if (placement.owner === owner) rdpSurfacePlacements.delete(sessionId);
  }
}

function scheduleRdpSurfacePlacementSync(owner: BrowserWindow): void {
  if (owner.isDestroyed() || rdpOwnerSyncTasks.has(owner.id)) return;
  const task = setImmediate(() => {
    rdpOwnerSyncTasks.delete(owner.id);
    if (owner.isDestroyed() || !rdpClient) return;
    const ownerWindow = nativeWindowHandle(owner);
    for (const [sessionId, placement] of rdpSurfacePlacements) {
      if (placement.owner !== owner) continue;
      const bounds = toScreenBounds(owner, placement.rendererBounds);
      if (!bounds) continue;
      void rdpClient.resize({ sessionId, bounds }, ownerWindow).catch(() => {
        // Moving the owner can race with an RDP close. The terminal event owns cleanup.
      });
    }
  });
  rdpOwnerSyncTasks.set(owner.id, task);
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
  throw new Error('The RDP window is unavailable.');
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
  if (!sessionId || sessionId.length > 128 || !host || host.length > 253 || /[\r\n\0]/.test(host)) {
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
  if (profile.nodeId !== undefined && profile.tunnelConfigId !== undefined) {
    throw new Error('RDP tunnel configuration cannot override a saved connection.');
  }
  if (
    profile.nodeId !== undefined &&
    (profile.credentialId !== undefined || profile.gatewayCredentialId !== undefined)
  ) {
    throw new Error('RDP credentials cannot override a saved connection.');
  }
  if (
    (profile.credentialId !== undefined && !isTunnelID(profile.credentialId)) ||
    (profile.credentialIdOverride !== undefined && !isTunnelID(profile.credentialIdOverride)) ||
    (profile.gatewayCredentialId !== undefined && !isTunnelID(profile.gatewayCredentialId))
  ) {
    throw new Error('RDP credential selection is invalid.');
  }
  if (profile.tunnelConfigId !== undefined && !isTunnelID(profile.tunnelConfigId)) {
    throw new Error('RDP tunnel configuration is invalid.');
  }
  if (typeof profile.password === 'string' && profile.password.length > 4096) {
    throw new Error('RDP password is too long.');
  }
  if (typeof profile.gatewayPassword === 'string' && profile.gatewayPassword.length > 4096) {
    throw new Error('RDP gateway password is too long.');
  }
  const manualCredentials = valueAsUnknown(value, 'manualCredentials');
  if (manualCredentials !== undefined && typeof manualCredentials !== 'boolean') {
    throw new Error('RDP credential source is invalid.');
  }
  if (profile.nodeId === undefined && profile.credentialIdOverride !== undefined) {
    throw new Error('RDP credential override requires a saved connection.');
  }
  if (manualCredentials === true && profile.credentialIdOverride !== undefined) {
    throw new Error('RDP manual credentials cannot be combined with a saved credential override.');
  }
  return {
    sessionId,
    profile: { ...profile, host },
    bounds: parseOptionalBounds(valueAsUnknown(value, 'bounds')),
    manualCredentials,
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

function parseRdpSystemClientCapabilityRequest(value: unknown): RdpSystemClientCapabilityRequest {
  if (!value || typeof value !== 'object') {
    throw new Error('Invalid RDP system client capability request.');
  }
  const nodeId = valueAsString(value, 'nodeId');
  if (!nodeId || nodeId.length > 128) throw new Error('RDP connection identity is invalid.');
  return { nodeId };
}

function parseRdpSystemClientOpenRequest(value: unknown): RdpSystemClientOpenRequest {
  const capability = parseRdpSystemClientCapabilityRequest(value);
  const command = parseRdpCommandRequest(value);
  return { ...capability, sessionId: command.sessionId };
}

function parseOptionalBounds(value: unknown): RdpSurfaceRect | undefined {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object') throw new Error('RDP surface bounds are invalid.');
  const rawBounds = value as Record<string, unknown>;
  const numbers = ['x', 'y', 'width', 'height'].map((key) => rawBounds[key]);
  if (!numbers.every((number) => typeof number === 'number' && Number.isFinite(number))) {
    throw new Error('RDP surface bounds are invalid.');
  }
  const [x, y, width, height] = numbers as number[];
  const parsed = { x, y, width, height };
  if (!isRdpSurfaceRectWithinNativeBounds(parsed)) {
    throw new Error('RDP surface bounds are invalid.');
  }
  return parsed;
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
    icon: applicationIconPath,
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
  const closeCoordinator = new WindowCloseCoordinator();
  windowCloseCoordinators.set(window, closeCoordinator);
  window.on('move', () => scheduleRdpSurfacePlacementSync(window));
  window.on('resize', () => scheduleRdpSurfacePlacementSync(window));
  window.once('closed', () => clearRdpSurfacePlacements(window));

  // Wormhole has no user-facing page zoom. Normalize the renderer to its native CSS scale so a
  // previously persisted Chromium zoom level cannot make the whole workspace look oversized.
  window.webContents.setZoomLevel(0);
  window.webContents.setZoomFactor(1);
  window.setOpacity(startupWindowOpacity);

  // Safety net: if the first paint never arrives (failed page load, hung dev
  // server), show the window anyway so the app is never left invisible.
  let showFallbackTimer: NodeJS.Timeout | undefined;
  const showWindow = () => {
    if (showFallbackTimer) clearTimeout(showFallbackTimer);
    if (window.isDestroyed()) return;
    window.show();
    if (startupReadyWindows.has(window)) window.setOpacity(1);
  };
  window.once('ready-to-show', showWindow);
  showFallbackTimer = setTimeout(showWindow, 10_000);

  window.webContents.on('did-start-loading', () => {
    startupReadyWindows.delete(window);
    window.setOpacity(startupWindowOpacity);
    webSurfaces.closeForWindow(window);
    clearRdpSurfacePlacements(window);
    vncSessionAttempts.cancelAll();
    cancelPreparingRdpStarts();
    void serializeAuthOperation(async () => {
      // A renderer reload creates a fresh UI process context. Do not let a previous renderer's
      // native unlock survive into the new context before it proves possession of the secret.
      authSession.lock();
      backupImportSelections.delete(window.webContents);
      sshPrivateKeySelections.delete(window.webContents);
      mremoteImportAnalysis.get(window.webContents)?.abort();
      mremoteImportAnalysis.delete(window.webContents);
      mremoteImportSelections.delete(window.webContents);
      await nativeBackend?.send({ action: 'bitwarden.clear-session' }).catch(() => undefined);
      sshBackend.prepareForLock();
      sshBackend.closeAllSftp();
      sshBackend.cancelPendingConnections();
      try {
        await sshBackend.setMcpLocked(true);
      } catch {
        // The MCP process is allowed to exit while the renderer is being re-authenticated.
      }
      await shutdownNativeResources();
    }).catch((error) => {
      console.error('[Wormhole] Could not reset app authentication.', error);
    });
  });

  window.webContents.on('preload-error', (_event, preloadPath, error) => {
    console.error(`[Wormhole] Preload failed (${path.basename(preloadPath)}).`, error.message);
  });

  const closeReason = new WindowCloseReasonTracker();
  window.on('query-session-end', () => {
    closeReason.beginSystemShutdown();
  });
  window.on('session-end', () => {
    closeReason.confirmSystemShutdown();
    skipQuitConfirmation = true;
    isQuitting = true;
    void shutdownNativeResources();
  });
  window.webContents.on('render-process-gone', () => {
    closeReason.rendererFailed();
    if (!window.isDestroyed()) window.close();
  });
  window.on('close', (event) => {
    if (isQuitting || closeCoordinator.isComplete) return;
    event.preventDefault();
    void closeCoordinator
      .request({
        reason: closeReason.reason,
        confirm: (activeCount) => requestRendererCloseConfirmation(window, activeCount, 'window'),
        teardown: async () => {
          await runWindowTeardown(
            async () => {
              try {
                await withBitwardenBrowserTimeout(
                  webSurfaces.flushAndCloseForWindow(window),
                  30_000,
                  'Bitwarden browser storage window-close flush timed out.',
                );
              } catch (error) {
                console.warn('[Wormhole] Browser window shutdown did not finish cleanly.', error);
              }
            },
            async () => {
              if (closeReason.reason !== 'renderer-failure') {
                await requestRendererTeardown(window);
              }
              // The renderer can no longer enumerate or close its sessions. Dispose every native
              // owner here so macOS cannot keep headless sessions alive after the last window closes.
              await shutdownNativeResources();
            },
          );
        },
        close: () => {
          if (!window.isDestroyed()) window.destroy();
        },
      })
      .catch((error) => {
        console.warn('[Wormhole] Window close cleanup failed.', error);
      });
  });
  window.once('closed', () => {
    closeReason.dispose();
    treeTooltips.closeForWindow(window);
    webSurfaces.closeForWindow(window);
  });
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
let nativeResourceShutdownPromise: Promise<void> | undefined;

function shutdownNativeResources(): Promise<void> {
  if (nativeResourceShutdownPromise) return nativeResourceShutdownPromise;
  const task = (async () => {
    vncSessionAttempts.cancelAll();
    cancelPreparingRdpStarts();
    serialBackend?.dispose();
    serialBackend = undefined;
    const results = await Promise.allSettled([sshBackend.dispose(), rdpClient?.dispose()]);
    if (results.some((result) => result.status === 'rejected')) {
      console.warn('[Wormhole] One or more connection services did not stop cleanly.');
    }
    await releaseAllRdpTunnels();
    const backend = nativeBackend;
    if (nativeBackend === backend) nativeBackend = undefined;
    await backend?.stop(true);
    webSurfaces.backendStopped();
    sshBackend.backendStopped();
    rdpTunnelLeases.clear();
    rdpTunnelLeaseSessions.clear();
  })();
  const tracked = task.finally(() => {
    if (nativeResourceShutdownPromise === tracked) nativeResourceShutdownPromise = undefined;
  });
  nativeResourceShutdownPromise = tracked;
  return tracked;
}

function scheduleUnlockedBackgroundWork(): void {
  const hasReadyWindow = BrowserWindow.getAllWindows().some(
    (window) => !window.isDestroyed() && startupReadyWindows.has(window),
  );
  if (!hasReadyWindow || !authSession.isAccessAllowed || isQuitting || startupBackgroundTimer) {
    return;
  }
  startupBackgroundTimer = setTimeout(() => {
    startupBackgroundTimer = undefined;
    const stillHasReadyWindow = BrowserWindow.getAllWindows().some(
      (window) => !window.isDestroyed() && startupReadyWindows.has(window),
    );
    if (!stillHasReadyWindow || !authSession.isAccessAllowed || isQuitting) return;
    const authorizationEpoch = authSession.authorizationEpoch;
    startBitwardenBackgroundMaintenance();
    void showBitwardenOnboardingNoticeIfNeeded();
    void sshBackend.syncMcpAfterUnlock(authorizationEpoch).catch((error) => {
      console.error('[Wormhole] Could not synchronize the MCP service after unlock.', error);
    });
  }, startupBackgroundDelayMs);
}

authSession.onUnlocked(() => {
  sshBackend.requestSnapshots();
  serialBackend?.requestSnapshots();
  scheduleUnlockedBackgroundWork();
});

app.whenReady().then(() => {
  registerIpcHandlers(sshBackend);
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

let quitCleanupStarted = false;
let quitCleanupComplete = false;

app.on('before-quit', (event) => {
  if (quitCleanupComplete) {
    isQuitting = true;
    return;
  }
  event.preventDefault();
  if (quitCleanupStarted) return;
  quitCleanupStarted = true;
  void (async () => {
    if (!skipQuitConfirmation) {
      const windows = BrowserWindow.getAllWindows();
      const activeCount = windows.reduce(
        (count, window) =>
          count + (windowCloseCoordinators.get(window)?.connectedSessionCount ?? 0),
        0,
      );
      if (activeCount > 0) {
        const owner = BrowserWindow.getFocusedWindow() ?? windows[0];
        const confirmed = await requestRendererCloseConfirmation(owner, activeCount, 'quit');
        if (!confirmed) {
          quitCleanupStarted = false;
          return;
        }
      }
    }

    isQuitting = true;
    if (startupUpdateTimer) clearTimeout(startupUpdateTimer);
    startupUpdateTimer = undefined;
    if (startupBackgroundTimer) clearTimeout(startupBackgroundTimer);
    startupBackgroundTimer = undefined;
    updateDownloadChild?.kill();
    updateDownloadChild = undefined;
    if (bitwardenBackgroundTimer) {
      clearInterval(bitwardenBackgroundTimer);
      bitwardenBackgroundTimer = undefined;
    }
    try {
      await withBitwardenBrowserTimeout(
        webSurfaces.flushAndCloseAll(),
        30_000,
        'Bitwarden browser storage shutdown flush timed out.',
      );
    } catch (error) {
      console.warn('[Wormhole] Browser session shutdown did not finish cleanly.', error);
    } finally {
      await Promise.allSettled(
        BrowserWindow.getAllWindows().map((window) => requestRendererTeardown(window)),
      );
      await shutdownNativeResources();
      quitCleanupComplete = true;
      app.quit();
    }
  })();
});

app.on('window-all-closed', () => {
  void shutdownNativeResources();
  if (process.platform !== 'darwin') app.quit();
});
