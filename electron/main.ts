import { VaultTunnelBrowserDialog } from './vault-tunnel-browser-dialog.js';
import { VaultVPNBrowserSession } from './vault-vpn-browser-session.js';
import { VaultTunnelAuthenticationDialog } from './vault-tunnel-authentication-dialog.js';
import { registerVaultProtectionIpc } from './vault-protection-ipc.js';
import { registerVaultLocalBackupIpc } from './vault-local-backup-ipc.js';
import { VaultMigrationSetupDialog } from './vault-migration-setup-dialog.js';
import { registerVaultMigrationIpc, registerVaultRootRotationIpc } from './vault-migration-ipc.js';
import { registerVaultUpgradeIpc } from './vault-upgrade-ipc.js';
import { registerVaultUnprotectedIpc } from './vault-unprotected-ipc.js';
import { registerVaultOSMigrationIpc } from './vault-os-migration-ipc.js';
import type { IpcMainInvokeEvent } from 'electron';
import { selectVaultNativePaths } from './vault-native-paths.js';
import { prepareVaultMigrationBoot, type VaultMigrationBoot } from './vault-migration-boot.js';
import type { VaultQuickTarget } from './vault-quick-target.ts';
import { VaultRdpCredentialsDialog } from './vault-rdp-credentials-dialog.js';
import { SealedRdpBackend } from './sealed-rdp.ts';
import { resolveVaultRDPBitwarden } from './vault-rdp-bitwarden.ts';
import { rdpManualTarget } from './vault-rdp-manual.ts';
import { VaultRdpController } from './vault-rdp-controller.ts';
import { VaultRdpIpc } from './vault-rdp-ipc.ts';
import { VaultVncPasswordDialog } from './vault-vnc-password-dialog.js';
import { VaultProtectedEntryDialog } from './vault-protected-entry-dialog.js';
import {
  parseVaultBitwardenCLIUnlockContext,
  parseVaultBitwardenCLIPassword,
} from './vault-bitwarden-cli-unlock.js';
import { VaultBitwardenCLIUnlockController } from './vault-bitwarden-cli-unlock-controller.js';
import { VaultSshCredentialsDialog } from './vault-ssh-credentials-dialog.js';
import { SealedVncBackend } from './sealed-vnc.ts';
import { resolveVaultVNCBitwarden } from './vault-vnc-bitwarden.ts';
import { VaultVncController } from './vault-vnc-controller.ts';
import { VaultVncIpc } from './vault-vnc-ipc.ts';
import { LinuxVaultClipboard, linuxClipboardIO } from './vault-linux-clipboard.ts';
import { SealedRouteBroker } from './sealed-route.ts';
import {
  VaultWebConnections,
  parseVaultWebRequest,
  type PreparedVaultWebConnection,
} from './vault-web-connections.ts';
import { VaultWebIpc } from './vault-web-ipc.ts';
import { VaultWebCookieCheckpoint } from './vault-web-cookies.ts';
import { SealedSshBackend, type SealedSshAdmission } from './sealed-ssh.ts';
import { VaultSshIpc } from './vault-ssh-ipc.ts';
import type { VaultSshOpen } from './vault-ssh-open.ts';
import { SharedSshRoutes } from './ssh-shared-route.js';
import { assertRdpSurfaceOwner, isRdpInput } from './rdp-framebuffer.js';
import { confirmRdpCertificate } from './rdp-certificate.js';
import { loadShellPage } from './shell-page-load.js';
import {
  isSftpEditRequest,
  parseSftpEditEvent,
  type SftpEditRequest,
  type SftpEditEvent,
} from './sftp-contract.js';
import {
  parseSshTerminalOutput,
  SshTerminalDelivery,
  type SshTerminalOutput,
} from './ssh-terminal-stream.js';
import {
  app,
  BrowserWindow,
  clipboard,
  ClipboardItem,
  crashReporter,
  dialog,
  ipcMain,
  Menu,
  powerMonitor,
  net as electronNet,
  screen,
  session as electronSession,
  shell,
  webContents as electronWebContents,
  WebContentsView,
} from 'electron';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { stat as statFile } from 'node:fs/promises';
import path from 'node:path';
import { createInterface, type Interface } from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';
import type { ElectronChromeExtensions } from 'electron-chrome-extensions';
import { AuthSession } from './auth-session.js';
import { VaultBackendClient } from './vault-client.js';
import { launchVaultTouchIDBroker } from './vault-touchid-broker.js';
import { resolveVaultSSHBitwarden } from './vault-ssh-bitwarden.js';
import { VaultLockMonitor, bindVaultPowerEvents } from './vault-lock-monitor.js';
import { stricterVaultProfile, type VaultProfile } from './vault-security.js';
import type { VaultUpdatePreferences } from './vault-preferences.js';
import { bindNativeVaultSession } from './vault-session-monitor.js';
import { VaultWindowPolicy } from './vault-window-policy.js';
import { VaultCreateDialog } from './vault-create-dialog.js';
import { VaultTunnelDialog } from './vault-tunnel-dialog.js';
import { VaultCredentialsDialog } from './vault-credentials-dialog.js';
import { VaultNotesDialog } from './vault-notes-dialog.js';
import { VaultReauthenticationDialog } from './vault-reauth-dialog.js';
import { VaultSharedAuthenticationDialog } from './vault-shared-dialog.js';
import { VaultSharedSetupDialog } from './vault-shared-setup-dialog.js';
import { pickSharedBackupDestination } from './vault-shared-backup-destination.js';
import { isSharedInitialStartup } from './vault-shared-invitation.js';
import {
  registerSharedAuthenticationIpc,
  registerSharedAdminRecoveryIpc,
  registerSharedCatalogIpc,
  registerSharedNodeEditIpc,
  registerSharedCertificateRenewalIpc,
  registerSharedChangesIpc,
  registerSharedConnectionContextIpc,
  registerSharedRecoveryBackupIpc,
  registerSharedAccountResetIpc,
  registerSharedAdministrationIpc,
  registerSharedRecoveryInspectionIpc,
} from './vault-shared-ipc.js';
import { prepareVaultCredentialSelections } from './vault-credential-selection.js';
import { VaultBackendHost, isTrustedVaultDocument, registerVaultIpc } from './vault-host.js';
import { registerVaultPresenceIpc } from './vault-presence-ipc.js';
import { TreeTooltipManager, type TreeTooltipRequest } from './tree-tooltip.js';
import { parseWorkspaceNotes, workspaceNodeWriteMaxRequestBytes } from './workspace-notes.js';
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
import { initializeLocalCrashDiagnostics, VaultCrashCapturePolicy } from './crash-diagnostics.js';
import {
  backendErrorText,
  createRuntimeDiagnostics,
  diagnosticErrorCode,
  expectBackendExit,
  observeBackendProcess,
  withIpcDiagnostics,
} from './runtime-diagnostics.js';
import { isAppTheme, parseThemeStartupRequest, type AppTheme } from './theme-settings.js';
import { isSshTerminalTheme, type SshTerminalTheme } from './terminal-theme-settings.js';
import { nativeTitlebarOverlay, syncNativeTitlebarTheme } from './native-titlebar-theme.js';
import {
  normalizeWindowCloseConfirmation,
  parseWindowCloseSettingUpdate,
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
  describeBitwardenBrowserFailure,
  closeBitwardenPopupContents,
  flushAndCloseBitwardenPopupContents,
  prepareBitwardenPopupStorage,
  type BitwardenBrowserFailure,
  type BitwardenBrowserStage,
} from './bitwarden-popup-lifecycle.js';
import {
  captureBitwardenExtensionStorage,
  markBitwardenStorageRevision,
  prepareBitwardenStorageMigrations,
  readBitwardenStorageRevision,
  restoreBitwardenExtensionStorage,
  waitForBitwardenBackgroundStorage,
} from './bitwarden-storage.js';
import {
  BitwardenStorageCheckpoint,
  BitwardenStorageCheckpointError,
  checkpointBitwardenStorageBeforeClose,
  synchronizeBitwardenStorage,
  type BitwardenBrowserStorageSnapshot,
  type BitwardenStorageSyncOptions,
} from './bitwarden-storage-sync.js';
import {
  buildBitwardenCookieSetDetails,
  buildBitwardenCookieRefreshPlan,
  selectBitwardenCookiesForTarget,
} from './bitwarden-cookie-seed.js';
import { ExtensionMutationGuard } from './extension-mutation-guard.js';
import { readBitwardenStartupState } from './bitwarden-startup.js';
import { readDarwinHardwareModel, shouldDisableHardwareAcceleration } from './gpu-compatibility.js';
import { KeyedSingleFlight } from './keyed-single-flight.js';
import {
  blockedWebTunnelProxy,
  parseWebTunnelSocksPort,
  type WebTunnelEndpoint,
  WebTunnelProxy,
} from './web-tunnel-endpoint.js';
import {
  parseWorkspaceNodesRequest,
  parseWorkspaceMoveNodesRequest,
  workspaceDeleteNodesMaxRequestBytes,
} from './workspace-delete-contract.js';
import { KeyedTaskTracker } from './keyed-task-tracker.js';
import { runWithNativeAuthenticationWindow } from './native-auth-window.js';
import { shouldDeferExtensionReload } from './extension-reload-policy.js';
import { encodeTerminalClipboardText, isEncodedSshInput } from './terminal-clipboard.js';
import { parseTerminalLink } from './terminal-link.js';
import {
  isLocalSftpPath,
  isSftpName,
  sshMaxSftpEntryNameLength,
  sshMaxSftpPathLength,
  type SftpNameDestination,
} from './sftp-contract.js';
import { RdpBackendClient, stopChildProcess } from './rdp.js';
import { drainSshBackendSessionIds } from './ssh-backend-lifecycle.js';
import { sshOpenCredentialFields } from './ssh-open-credentials.js';
import { settleTunnelCleanup, TunnelLeaseRegistry } from './tunnel-lease-registry.js';
import { assertTunnelRouteUnchanged } from './tunnel-route-snapshot.js';
import { TunnelFailureRegistry, tunnelClosedMessage } from './tunnel-failure.js';
import {
  isTunnelIdentifier,
  parseTunnelDetailsResponse,
  parseTunnelCapabilities,
  parseTunnelWriteRequest,
  parseTunnelSummaryList,
  parseTunnelTestRequest,
} from './tunnel-test-contract.js';
import {
  encodeTunnelOAuthCallback,
  isFortinetIPsecRedirect,
  fortinetIPsecCallbackToken,
  fortinetSSLCallbackAuthId,
  fortinetSSLLoopback,
  isFortinetSSLCallbackSource,
  isSameCertificateHostname,
  isMatchingOAuthRedirect,
  tunnelPromptValueMaxBytes,
  tunnelAuthPartition,
  tunnelBrowserLoadFailure,
  TunnelBrowserPromptTracker,
  type TunnelBrowserCompletion,
  type TunnelBrowserFailure,
} from './tunnel-auth.js';
import {
  FortinetIPsecCredentialDrafts,
  FortinetIPsecEntryCancelled,
  isFortinetIPsecEditableSecret,
  prepareFortinetIPsecWrite,
  promptFortinetIPsecSecret,
  type FortinetIPsecCertificate,
  type FortinetIPsecDraftReferences,
  type FortinetIPsecEditableSecret,
} from './fortinet-ipsec-secret.js';
import {
  SerialBackendClient,
  isSerialInput,
  isSerialOpenRequest,
  isSerialSessionId,
  type SerialBackendEvent,
  type SerialConnectedResponse,
  type SerialOpenRequest,
} from './serial.js';
import { SealedSerialBackend } from './sealed-serial.ts';
import { WebSessionAttemptTracker } from './web-session-attempt.js';
import { getInSessionNavigationUrl } from './web-new-window-navigation.js';
import { adjustWebZoom } from './web-zoom.js';
import {
  WebBrowserTabs,
  isWebBrowserCommand,
  isAbortedWebNavigation,
  isWebBrowserRouteRequestAllowed,
  fetchWebBrowserFavicon,
  webBrowserFaviconUrlLimit,
  resolveWebBrowserAddress,
  webBrowserTabLimit,
  type WebBrowserCommand,
  type WebBrowserState,
} from './web-browser-tabs.js';
import { webTargetURLMatchesEndpoint } from './web-target-validation.js';
import {
  completeWindowsUpdateHandoff,
  isSafeUpdateInstallerPath,
  launchDownloadedUpdate,
  updateInstallAction,
} from './update-installer.js';
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
const productionRendererPath = path.resolve(__dirname, '..', 'dist', 'index.html');
const applicationIconPath = path.join(
  __dirname,
  '..',
  'Assets',
  process.platform === 'win32' ? 'Wormhole.ico' : 'Wormhole.png',
);
const startupWindowOpacity = 0.96;
let nativeVaultPaths: ReturnType<typeof selectVaultNativePaths>;
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

const recordDiagnostic = createRuntimeDiagnostics({
  databasePath: wormholeDatabasePath,
  fallbackPath: () => path.join(app.getPath('userData'), 'wormhole-diagnostics.log'),
});

function reportWarning(event: string, error?: unknown): void {
  recordDiagnostic('WRN', event, { code: diagnosticErrorCode(error) });
}

function recordCrashDiagnostic(level: 'INF' | 'WRN' | 'ERR', message: string): void {
  if (!recordDiagnostic(level, message, {}, true)) {
    throw new Error('Could not persist crash diagnostics.');
  }
}

process.on('uncaughtExceptionMonitor', (error, origin) => {
  recordDiagnostic(
    'ERR',
    'Main process exception',
    { origin, code: diagnosticErrorCode(error) },
    true,
  );
});

app.on('child-process-gone', (_event, details) => {
  if (details.reason === 'clean-exit') return;
  recordDiagnostic('ERR', 'Chromium child process exited', {
    type: details.type,
    reason: details.reason,
    exitCode: details.exitCode,
  });
});

// Own the original Chromium profile for this app lifetime. A pending native
// migration isolates Chromium before readiness; Go retains the
// original userData/database selections. No renderer may grant this authority.
let vaultMigrationBoot: VaultMigrationBoot;
try {
  nativeVaultPaths = selectVaultNativePaths(app.getPath('userData'), process.env);
  vaultMigrationBoot = prepareVaultMigrationBoot({
    app,
    executable: backendPath,
    databasePath: wormholeDatabasePath(),
    prepareProtection: process.argv.includes('--prepare-vault-protection'),
  });
  if (!vaultMigrationBoot.primary) app.exit(0);
} catch {
  dialog.showErrorBox('Wormhole', 'Wormhole could not prepare its browser session safely.');
  app.exit(1);
  throw Error('Vault startup unavailable.');
}
app.on('second-instance', () => {
  const window = BrowserWindow.getAllWindows().find((w) => !w.isDestroyed());
  if (window) {
    if (window.isMinimized()) window.restore();
    window.focus();
  }
});

const vaultCrashCapture = new VaultCrashCapturePolicy(() => {
  initializeLocalCrashDiagnostics({
    app,
    reporter: crashReporter,
    platform: process.platform,
    arch: process.arch,
    electronVersion: process.versions.electron ?? 'unknown',
    processId: process.pid,
    localAppData: process.env.LOCALAPPDATA,
    logger: {
      info: (message) => recordCrashDiagnostic('INF', message),
      warn: (message) => recordCrashDiagnostic('WRN', message),
      error: (message) => recordCrashDiagnostic('ERR', message),
    },
  });
});
// A native vault opens with Crashpad off until its effective policy is
// authenticated. An existing legacy workspace under the Default machine
// floor can retain the pre-renderer local diagnostics path.
if (vaultMigrationBoot.legacyLocalCrashCapture) vaultCrashCapture.apply('default');

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
  reportWarning(
    forceSoftwareRendering
      ? 'Hardware acceleration disabled by startup override.'
      : 'Hardware acceleration disabled for legacy Intel macOS GPU compatibility.',
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
  { owner: BrowserWindow; rendererBounds: RdpSurfaceRect; showRequest?: symbol }
>();
const rdpOwnerSyncTasks = new Map<number, NodeJS.Immediate>();
let serialBackend: SerialBackendClient | undefined;
const sealedSerial = new SealedSerialBackend({
  executable: backendPath,
  workspaceId: () => vaultBackend.unlockedWorkspaceId,
  authorize: (request, accepted) => vaultBackend.serialBundle(request, accepted),
  sharedUse: {
    active: () => vaultBackend.isSharedWorkspace,
    check: (workspaceId, nodeIds) => vaultBackend.checkSharedSerialUse(workspaceId, nodeIds),
  },
});
let latestUpdateCheck: UpdateCheckResult | undefined;
let latestUpdateManifest: string | undefined;
let latestUpdatePublisherVerification = false;
let latestUpdateScope: VaultUpdateScope | undefined;
let updateProfileFloor: { scope: VaultUpdateScope; profile: VaultProfile } | undefined;
let downloadedUpdate: DownloadedUpdate | undefined;
let updateCheckInFlight:
  | { scope?: VaultUpdateScope; result: Promise<UpdateCheckResult>; cancellation: AbortController }
  | undefined;
let updateDownloadChild: ChildProcessWithoutNullStreams | undefined;
const updateInstallTasks = new KeyedSingleFlight<string>();
let pendingUpdateQuit:
  | { launch(): Promise<void>; resolve(): void; reject(error: Error): void }
  | undefined;
let startupUpdateTimer: NodeJS.Timeout | undefined;
let startupUpdateScheduled: { scope?: VaultUpdateScope } | undefined;
let startupBackgroundTimer: NodeJS.Timeout | undefined;
const startupReadyWindows = new WeakSet<BrowserWindow>();
const failedWorkspaceWindows = new WeakSet<BrowserWindow>();

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
  | 'workspace-move-nodes'
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
  | 'workspace-node-notes'
  | 'tunnel-create'
  | 'tunnel-list'
  | 'tunnel-capabilities'
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
  | 'settings-file-transfer-read'
  | 'settings-file-transfer-write'
  | 'settings-read'
  | 'settings-set-theme'
  | 'settings-set-ssh-terminal-theme'
  | 'settings-set-prompt-before-tunnel'
  | 'settings-set-update-preferences'
  | 'update-check'
  | 'update-download'
  | 'update-verify-installer'
  | 'update-check-release'
  | 'logs-info'
  | 'settings-set-log-retention'
  | 'settings-set-log-level'
  | 'open-log-file'
  | 'open-logs-folder'
  | 'settings-set-auto-copy-on-select'
  | 'settings-set-confirm-on-tab-close'
  | 'settings-set-confirm-on-window-close'
  | 'settings-set-sidebar-width'
  | 'settings-set-sidebar-pinned'
  | 'settings-set-connection-tree-expansion'
  | 'bitwarden-onboarding-read'
  | 'bitwarden-onboarding-dismiss'
  | 'visual-changelog-claim'
  | 'mcp-status'
  | 'extension-read'
  | 'extension-set-enabled'
  | 'extension-install'
  | 'extension-ensure-installed'
  | 'extension-import-zip'
  | 'extension-import-folder'
  | 'extension-update-if-stale';
type NativeBackendAction =
  | 'browser-relay.open'
  | 'browser-relay.route'
  | 'browser-relay.close'
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
  | 'tunnel.ipsec-stage'
  | 'tunnel.ipsec-discard'
  | 'tunnel.ipsec-clear'
  | 'tunnel.ipsec-create'
  | 'tunnel.ipsec-update'
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
  | 'bitwarden.browser-failure'
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
  browserFailure?: TunnelBrowserFailure;
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
  reuseExisting?: boolean;
  planNonce?: string;
  planToken?: string;
  ipsecField?: FortinetIPsecEditableSecret;
  ipsecSecret?: string;
  ipsecReferences?: FortinetIPsecDraftReferences;
  ipsecWrite?: ReturnType<typeof parseTunnelWriteRequest>;
};
type BackendResponse = {
  id: string;
  ok: boolean;
  error?: string;
  socksEndpoint?: string;
  forwardHost?: string;
  forwardPort?: number;
  tunnelActive?: boolean;
  configuredTunnelId?: string;
  tunnelName?: string;
  tunnelKind?: string;
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
  sshTerminalTheme: SshTerminalTheme;
  theme: AppTheme;
  promptBeforeTunnelConnect: boolean;
  autoCopyOnSelect: boolean;
  confirmOnTabClose: boolean;
  confirmOnWindowClose: boolean;
  sidebarWidth: number;
  sidebarPinned: boolean;
  connectionTreeExpansion: ConnectionTreeExpansionSetting | null;
  autoCheckForUpdates: boolean;
  lastUpdateCheck: string | null;
  skippedUpdateVersion: string | null;
};

const windowCloseCoordinators = new WeakMap<BrowserWindow, WindowCloseCoordinator>();
const fortinetIPsecDrafts = new FortinetIPsecCredentialDrafts((reference) => {
  void nativeBackend
    ?.send({ action: 'tunnel.ipsec-discard', sessionId: reference })
    .catch(() => undefined);
});
let confirmOnWindowClose = true;
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
  if (!window || window.isDestroyed() || !closeConfirmationReadyWindows.has(window)) {
    return Promise.resolve(false);
  }
  const contents = window.webContents;
  if (contents.isDestroyed() || contents.isCrashed()) return Promise.resolve(false);
  const requestId = randomUUID();
  return new Promise((resolve) => {
    const finish = (confirmed: boolean) => {
      closeConfirmationWaiters.delete(requestId);
      contents.removeListener('destroyed', rendererGone);
      contents.removeListener('render-process-gone', rendererGone);
      resolve(confirmed);
    };
    const rendererGone = () => finish(false);
    closeConfirmationWaiters.set(requestId, {
      webContentsId: contents.id,
      resolve: finish,
    });
    contents.once('destroyed', rendererGone);
    contents.once('render-process-gone', rendererGone);
    try {
      contents.send('lifecycle:confirm-close', requestId, {
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
  lastUpdateCheck?: string;
  updatePolicy?: 'notify' | 'managed';
};
type UpdateDownloadRequest = {
  installerUrl: string;
  installerFileName: string;
  installerSha256?: string;
  installerSize?: number | null;
};
type NativeUpdateDownloadRequest = {
  installerUrl: string;
  installerFileName: string;
  installerSha256: string;
  installerSize: number;
  currentVersion: string;
  signedManifest?: string;
};
type VaultUpdateScope = { workspaceId: string; epoch: number };
type DownloadedUpdate = {
  path: string;
  request: NativeUpdateDownloadRequest;
  scope?: VaultUpdateScope;
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
  hasCertificate?: boolean;
  certificateFileName?: string;
  certificate?: {
    keyId: string;
    principals: string[];
    validAfter?: string;
    validBefore?: string;
    signingCaFingerprint: string;
  };
  isVirtualBitwarden?: boolean;
};
type CredentialProtocol = 'ssh' | 'rdp' | 'vnc' | 'smb';
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
  certificateSelectionId?: string;
  clearCertificate: boolean;
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
  notes?: string;
  kind: 'folder' | 'connection';
  protocol: '' | 'ssh' | 'sftp' | 'smb' | 'rdp' | 'http' | 'https' | 'vnc' | 'serial';
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
  browser?: WebBrowserState;
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
  protocol: 'ssh' | 'rdp' | 'smb';
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
  quickTarget?: VaultQuickTarget;
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
  capturePreview?: boolean;
  previewId?: string;
};
type WebCommandRequest = WebBrowserCommand;
type BitwardenPopupOpenRequest = {
  sessionId: string;
  anchor: BitwardenPopupAnchor;
};
type WorkspaceNodeTunnelSettingsRequest = {
  nodeId: string;
  tunnelEnabled: boolean | null;
  tunnelConfigId: string;
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
type SshPrivateKeySelection = {
  id: string;
  path: string;
  fileName: string;
  authorizationEpoch: number;
};
const sshPrivateKeySelections = new WeakMap<Electron.WebContents, SshPrivateKeySelection>();
const sshCertificateSelections = new WeakMap<Electron.WebContents, SshPrivateKeySelection>();
type MRemoteImportSelection = {
  path: string;
  planNonce?: string;
  planToken?: string;
  structureOnly?: boolean;
  reuseExisting?: boolean;
};
const mremoteImportSelections = new WeakMap<Electron.WebContents, MRemoteImportSelection>();
const mremoteImportAnalysis = new WeakMap<Electron.WebContents, AbortController>();
let authStateMutationQueue: Promise<void> = Promise.resolve();
let authLockRequested = false;
let authLocksInProgress = 0;
let activeHelloVerification: AbortController | undefined;
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
  | SftpEditEvent
  | SshTerminalOutput
  | { type: 'mcp.access'; sessionId: string; accessible: boolean }
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
      credentialId?: string;
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
  mode?: 'terminal' | 'sftp' | 'smb';
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
  approvalMode: McpApprovalMode;
};

type McpApprovalMode = 'full-access' | 'always-ask' | 'first-access';

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
  approvalKind: 'session_control' | 'open_connection' | 'tool';
  approvalMode: McpApprovalMode;
  host: string;
  port: number;
  username: string;
  title: string;
  tool: string;
  executionPreview?: { content: string; truncated: boolean; redacted: boolean };
  connectionId?: string;
  connectionFolder?: string;
  protocol?: 'ssh' | 'smb' | 'rdp' | 'http' | 'https' | 'vnc' | 'serial';
  path?: string;
};

type McpApprovalCancelledEvent = {
  type: 'mcp.approval-cancelled';
  requestId: string;
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

const webMaxUrlLength = 4096;
const webMaxAddressLength = 4096;
const webMaxSurfaceCoordinate = 100_000;

function isWebOpenRequest(value: unknown): value is WebOpenRequest {
  if (isRecord(value) && value.quickTarget !== undefined)
    return Boolean(parseVaultWebRequest(value));
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
  if (value.capturePreview !== undefined && typeof value.capturePreview !== 'boolean') return false;
  if (value.previewId !== undefined && !isUuid(value.previewId)) return false;
  if (value.capturePreview && !value.previewId) return false;
  if (value.visible && (value.capturePreview || value.previewId)) return false;
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
  return isWebBrowserCommand(value);
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
    (value.mode !== undefined &&
      value.mode !== 'terminal' &&
      value.mode !== 'sftp' &&
      value.mode !== 'smb') ||
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
  const certificateSelectionId =
    typeof value.certificateSelectionId === 'string' && value.certificateSelectionId.length > 0
      ? value.certificateSelectionId
      : undefined;
  const clearCertificate = value.clearCertificate === undefined ? false : value.clearCertificate;
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
    (value.privateKeySelectionId !== undefined &&
      typeof value.privateKeySelectionId !== 'string') ||
    (value.certificateSelectionId !== undefined &&
      typeof value.certificateSelectionId !== 'string') ||
    (certificateSelectionId !== undefined && !isUuid(certificateSelectionId)) ||
    typeof clearCertificate !== 'boolean' ||
    (clearCertificate && (!updating || certificateSelectionId !== undefined)) ||
    (kind === 'password' && provider === 'Local' && password.length === 0 && !updating) ||
    (kind === 'password' &&
      provider === 'Bitwarden' &&
      (bitwardenItemId.trim().length === 0 ||
        bitwardenItemId.length > credentialMaxBitwardenItemIdLength ||
        bitwardenItemName.length > credentialMaxBitwardenItemNameLength)) ||
    (kind === 'password' &&
      (passphrase.length !== 0 ||
        clearPassphrase ||
        privateKeySelectionId !== undefined ||
        certificateSelectionId !== undefined ||
        clearCertificate)) ||
    (kind === 'sshKey' &&
      (protocol !== 'ssh' ||
        provider !== 'Local' ||
        password.length !== 0 ||
        domain.trim().length !== 0 ||
        bitwardenItemId.length !== 0 ||
        bitwardenItemName.length !== 0 ||
        (clearPassphrase && (!updating || passphrase.length !== 0)) ||
        (!updating && privateKeySelectionId === undefined))) ||
    (protocol !== 'ssh' && protocol !== 'rdp' && protocol !== 'vnc' && protocol !== 'smb')
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
    certificateSelectionId,
    clearCertificate,
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
    certificateSelectionId: request.certificateSelectionId,
    clearCertificate: request.clearCertificate,
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
  const notes = parseWorkspaceNotes(value.notes);
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
    protocol === 'sftp' ||
    protocol === 'smb' ||
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
    (protocol !== 'ssh' &&
      protocol !== 'sftp' &&
      protocol !== 'smb' &&
      protocol !== 'rdp' &&
      inlinePasswordAction !== 'clear')
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
    notes,
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
    (value.protocol === 'ssh' || value.protocol === 'rdp' || value.protocol === 'smb') &&
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

function isSshInput(value: unknown, paste = false): value is string {
  return isEncodedSshInput(value, paste);
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

  if (value.type === 'sftp.edit') return parseSftpEditEvent(value);

  if (
    value.type === 'connected' &&
    typeof value.host === 'string' &&
    typeof value.port === 'number' &&
    Number.isInteger(value.port) &&
    value.port > 0 &&
    value.port <= 65535 &&
    typeof value.username === 'string' &&
    (value.fingerprint === undefined || typeof value.fingerprint === 'string')
  ) {
    return {
      type: 'connected',
      sessionId: value.session_id,
      host: value.host,
      port: value.port,
      username: value.username,
      // SMB has no SSH host key; Go omits the empty fingerprint on the wire.
      fingerprint: value.fingerprint ?? '',
    };
  }
  if (value.type === 'terminal-output') return parseSshTerminalOutput(value);
  if (value.type === 'screen') {
    const frame = parseSshTerminalFrame(value.frame);
    return frame ? { type: 'screen', sessionId: value.session_id, frame } : undefined;
  }
  if (value.type === 'mcp.access') {
    return typeof value.mcp_accessible === 'boolean'
      ? { type: 'mcp.access', sessionId: value.session_id, accessible: value.mcp_accessible }
      : undefined;
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
      credentialId: isUuid(value.credential_id) ? value.credential_id : undefined,
      hostKeyReceived: hasHostKeyMismatch ? hostKeyReceived : undefined,
      retainTunnelLease,
    };
  }
  return undefined;
}

function isMcpRequestId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 128;
}

function isMcpConnectionProtocol(
  value: unknown,
): value is 'ssh' | 'smb' | 'rdp' | 'http' | 'https' | 'vnc' | 'serial' {
  return (
    value === 'ssh' ||
    value === 'smb' ||
    value === 'rdp' ||
    value === 'http' ||
    value === 'https' ||
    value === 'vnc' ||
    value === 'serial'
  );
}

function isMcpApprovalMode(value: unknown): value is McpApprovalMode {
  return value === 'full-access' || value === 'always-ask' || value === 'first-access';
}

function parseMcpBackendMessage(
  line: string,
): McpControlResponse | McpApprovalEvent | McpApprovalCancelledEvent | undefined {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return undefined;
  }
  if (!isRecord(value) || typeof value.type !== 'string') return undefined;

  if (value.type === 'mcp.response' && isMcpRequestId(value.request_id)) {
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
        rawStatus.endpoint.length > 512 ||
        !isMcpApprovalMode(rawStatus.approvalMode)
      ) {
        return undefined;
      }
      response.status = {
        enabled: rawStatus.enabled,
        running: rawStatus.running,
        port: rawStatus.port,
        endpoint: rawStatus.endpoint,
        approvalMode: rawStatus.approvalMode,
      };
    }
    return response;
  }

  if (value.type === 'mcp.approval-cancelled' && isMcpRequestId(value.request_id)) {
    return { type: 'mcp.approval-cancelled', requestId: value.request_id };
  }

  const approvalKind =
    value.approval_kind === undefined || value.approval_kind === 'session_control'
      ? 'session_control'
      : value.approval_kind === 'open_connection'
        ? 'open_connection'
        : value.approval_kind === 'tool'
          ? 'tool'
          : undefined;
  const openConnectionApproval = approvalKind === 'open_connection';
  const inventoryApproval = approvalKind === 'tool';
  const optionalSessionTarget = openConnectionApproval || inventoryApproval;
  const approvalMode = value.approval_mode === undefined ? 'first-access' : value.approval_mode;
  const rawPreview = value.execution_preview;
  let executionPreview: McpApprovalEvent['executionPreview'];
  if (rawPreview !== undefined) {
    if (
      !isRecord(rawPreview) ||
      typeof rawPreview.content !== 'string' ||
      rawPreview.content.length > 64 * 1024 ||
      typeof rawPreview.truncated !== 'boolean' ||
      typeof rawPreview.redacted !== 'boolean'
    ) {
      return undefined;
    }
    executionPreview = {
      content: rawPreview.content,
      truncated: rawPreview.truncated,
      redacted: rawPreview.redacted,
    };
  }
  const approvalHost =
    typeof value.host === 'string'
      ? value.host
      : optionalSessionTarget && value.host === undefined
        ? ''
        : undefined;
  const approvalPort =
    typeof value.port === 'number'
      ? value.port
      : optionalSessionTarget && value.port === undefined
        ? 0
        : undefined;
  const approvalUsername =
    typeof value.username === 'string'
      ? value.username
      : optionalSessionTarget && value.username === undefined
        ? ''
        : undefined;
  if (
    value.type === 'mcp.approval' &&
    approvalKind !== undefined &&
    isMcpApprovalMode(approvalMode) &&
    (approvalMode !== 'full-access' || openConnectionApproval) &&
    (!inventoryApproval ||
      (approvalMode === 'always-ask' &&
        (value.tool === 'list_sessions' || value.tool === 'list_connections'))) &&
    isMcpRequestId(value.request_id) &&
    isSshSessionId(value.session_id) &&
    approvalHost !== undefined &&
    approvalHost.length <= (openConnectionApproval ? 4096 : 1024) &&
    approvalPort !== undefined &&
    Number.isInteger(approvalPort) &&
    approvalPort >= (optionalSessionTarget ? 0 : 1) &&
    approvalPort <= 65535 &&
    approvalUsername !== undefined &&
    approvalUsername.length <= 1024 &&
    typeof value.title === 'string' &&
    value.title.length <= 2048 &&
    typeof value.tool === 'string' &&
    value.tool.length <= 128 &&
    (!openConnectionApproval ||
      (value.tool === 'open_connection' &&
        isSshSessionId(value.connection_id) &&
        value.connection_id === value.session_id &&
        isMcpConnectionProtocol(value.protocol) &&
        (value.connection_folder === undefined ||
          (typeof value.connection_folder === 'string' &&
            value.connection_folder.length <= 4096)) &&
        (value.path === undefined ||
          (typeof value.path === 'string' && value.path.length <= 4096))))
  ) {
    return {
      type: 'mcp.approval',
      requestId: value.request_id,
      sessionId: value.session_id,
      approvalKind,
      approvalMode,
      host: approvalHost,
      port: approvalPort,
      username: approvalUsername,
      title: value.title,
      tool: value.tool,
      executionPreview,
      connectionId:
        openConnectionApproval && typeof value.connection_id === 'string'
          ? value.connection_id
          : undefined,
      connectionFolder:
        openConnectionApproval && typeof value.connection_folder === 'string'
          ? value.connection_folder
          : undefined,
      protocol:
        openConnectionApproval && isMcpConnectionProtocol(value.protocol)
          ? value.protocol
          : undefined,
      path: openConnectionApproval && typeof value.path === 'string' ? value.path : undefined,
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
    (completion !== 'query-token' &&
      completion !== 'oauth-code' &&
      completion !== 'cookie' &&
      completion !== 'fortinet-ssl' &&
      completion !== 'fortinet-ipsec') ||
    (completion === 'fortinet-ipsec' && !isFortinetIPsecRedirect(redirectPrefix)) ||
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

function runCoordinatedFileDialog<TResult>(
  cancelledResult: TResult,
  open: () => Promise<TResult>,
): Promise<TResult> {
  if (mcpApprovalWindowCoordinator.hasPendingApprovals) {
    return Promise.resolve(cancelledResult);
  }
  return mcpApprovalWindowCoordinator.runNativeDialog(open);
}

function showCoordinatedOpenDialog(
  owner: BrowserWindow | null | undefined,
  options: Electron.OpenDialogOptions,
): Promise<Electron.OpenDialogReturnValue> {
  return runCoordinatedFileDialog({ canceled: true, filePaths: [] }, () =>
    owner ? dialog.showOpenDialog(owner, options) : dialog.showOpenDialog(options),
  );
}

function showCoordinatedSaveDialog(
  owner: BrowserWindow | null | undefined,
  options: Electron.SaveDialogOptions,
): Promise<Electron.SaveDialogReturnValue> {
  return runCoordinatedFileDialog({ canceled: true, filePath: '' }, () =>
    owner ? dialog.showSaveDialog(owner, options) : dialog.showSaveDialog(options),
  );
}

function showCoordinatedMessageBox(
  owner: BrowserWindow,
  options: Electron.MessageBoxOptions,
): Promise<Electron.MessageBoxReturnValue> {
  return mcpApprovalWindowCoordinator.runNativeDialog(() => dialog.showMessageBox(owner, options));
}

function enqueueTunnelBrowserAuth(backend: NativeBackendProcess, event: TunnelBrowserEvent): void {
  const signal = backend.browserPrompts.begin(event.sessionId, event.promptId);
  if (!signal) return;
  const authorizationEpoch =
    authSession.isAccessAllowed && !authLockRequested && !isQuitting
      ? authSession.authorizationEpoch
      : undefined;
  tunnelBrowserAuthQueue = tunnelBrowserAuthQueue
    .catch(() => undefined)
    .then(() => runTunnelBrowserAuth(backend, event, signal, authorizationEpoch))
    .catch(async () => {
      if (!signal.aborted) {
        await backend
          .respondTunnelPrompt({
            leaseId: event.sessionId,
            promptId: event.promptId,
            value: '',
            cancelled: false,
            failure: 'session',
          })
          .catch(() => undefined);
      }
    })
    .finally(() => backend.browserPrompts.finish(event.promptId, signal));
}

async function runTunnelBrowserAuth(
  backend: NativeBackendProcess,
  event: TunnelBrowserEvent,
  signal: AbortSignal,
  authorizationEpoch: number | undefined,
): Promise<void> {
  if (signal.aborted) return;
  const isAuthorized = () =>
    authorizationEpoch !== undefined &&
    !authLockRequested &&
    !isQuitting &&
    isAuthorizationEpochCurrent(authorizationEpoch);
  if (!isAuthorized()) {
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
  const authWindow = createApplicationWindow({
    width: 900,
    height: 700,
    minWidth: 640,
    minHeight: 480,
    title: event.title,
    icon: applicationIconPath,
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
  const complete = async (cancelled: boolean, value = '', failure?: TunnelBrowserFailure) => {
    if (settled) return;
    settled = true;
    if (authTimeout) clearTimeout(authTimeout);
    try {
      if (
        (event.completion === 'fortinet-ssl' ||
          event.completion === 'fortinet-ipsec' ||
          event.completion === 'oauth-code') &&
        !authWindow.isDestroyed()
      ) {
        // These callbacks can complete synchronously within Chromium's navigation dispatch.
        await new Promise<void>((resolve) => setImmediate(resolve));
      }
      if (!authWindow.isDestroyed()) authWindow.destroy();
      if (!signal.aborted) {
        const promptCancelled = cancelled || !isAuthorized();
        await backend
          .respondTunnelPrompt({
            leaseId: event.sessionId,
            promptId: event.promptId,
            value: promptCancelled ? '' : value,
            cancelled: promptCancelled,
            failure: promptCancelled ? undefined : failure,
          })
          .catch(() => undefined);
      }
    } finally {
      finish();
    }
  };
  const abort = () => void complete(true);
  signal.addEventListener('abort', abort, { once: true });
  authTimeout = setTimeout(
    () => void complete(false, '', 'timeout'),
    nativeConnectionTimeoutMs - 5_000,
  );
  const matchesOAuthRedirect = (current: URL) =>
    (event.completion === 'oauth-code' || event.completion === 'fortinet-ipsec') &&
    isMatchingOAuthRedirect(current, event.redirectPrefix!);
  const nextCandidate = (failure: TunnelBrowserFailure) => {
    if (settled) return;
    candidate++;
    if (candidate < event.urls.length) {
      void authWindow.loadURL(event.urls[candidate]).catch(() => undefined);
    } else {
      void complete(false, '', failure);
    }
  };
  let hostCheckForbidden = false;
  const inspectNavigation = async (rawURL: string, status?: number) => {
    if (settled) return;
    let current: URL;
    try {
      current = new URL(rawURL);
    } catch {
      return;
    }
    if (event.completion === 'cookie' || event.completion === 'fortinet-ssl') {
      if (
        status === 403 &&
        current.origin === fireboxOrigin &&
        current.pathname === '/remote/hostcheck_install'
      ) {
        if (event.completion === 'cookie') {
          hostCheckForbidden = true;
          await inspectCookie();
        } else {
          await complete(false, '', 'fortinet-hostcheck-forbidden');
        }
      }
      return;
    }
    if (event.completion === 'fortinet-ipsec') {
      if (!matchesOAuthRedirect(current)) return;
      const token = fortinetIPsecCallbackToken(current);
      await complete(false, token ?? '', token ? undefined : 'response');
      return;
    }
    if (event.completion === 'oauth-code') {
      if (!matchesOAuthRedirect(current)) return;
      const value = encodeTunnelOAuthCallback(current);
      if (value === undefined) {
        await complete(false, '', 'response');
        return;
      }
      await complete(false, value);
      return;
    }
    if (event.completion !== 'query-token' || current.origin !== fireboxOrigin) return;
    const username = current.searchParams.get('user')?.trim() ?? '';
    const token = current.searchParams.get('token') ?? '';
    if (!username || !token) return;
    if (username.length > 1024 || Buffer.byteLength(token, 'utf8') > tunnelPromptValueMaxBytes) {
      await complete(false, '', 'response');
      return;
    }
    const cookies = await browserSession.cookies.get({ url: cookieScopeURL });
    if (cookies.length > 256) {
      await complete(false, '', 'response');
      return;
    }
    const value = JSON.stringify({
      username,
      token,
      cookies: cookies.map((cookie) => ({
        name: cookie.name,
        value: cookie.value,
        path: cookie.path || '/',
        domain: cookie.domain,
        secure: cookie.secure,
        httpOnly: cookie.httpOnly,
      })),
    });
    if (Buffer.byteLength(value, 'utf8') > tunnelPromptValueMaxBytes) {
      await complete(false, '', 'response');
      return;
    }
    await complete(false, value);
  };
  let inspectingCookie = false;
  const inspectCookie = async () => {
    if (settled || inspectingCookie || event.completion !== 'cookie') return;
    inspectingCookie = true;
    // A poll started before the 403 may have read the cookie store before the final redirect.
    const checkForDenial = hostCheckForbidden;
    try {
      const cookies = await browserSession.cookies.get({ url: cookieScopeURL });
      const cookie = cookies.find(
        (candidate) =>
          candidate.name === event.cookieName &&
          candidate.value &&
          (!event.requireHttpOnly || candidate.httpOnly),
      );
      if (cookie) {
        if (Buffer.byteLength(cookie.value, 'utf8') > tunnelPromptValueMaxBytes) {
          await complete(false, '', 'response');
        } else {
          await complete(false, cookie.value);
        }
      } else if (checkForDenial) {
        await complete(false, '', 'fortinet-hostcheck-forbidden');
      }
    } finally {
      inspectingCookie = false;
    }
  };
  let cookieRemovals: Promise<PromiseSettledResult<void>[]> | undefined;
  const clearCompletionCookie = async (isCurrent = () => true) => {
    if (event.completion !== 'cookie') return;
    const cookies = await browserSession.cookies.get({ url: cookieScopeURL });
    if (!isCurrent()) return;
    cookieRemovals = Promise.allSettled(
      cookies
        .filter((cookie) => cookie.name === event.cookieName)
        .map((cookie) =>
          Promise.resolve().then(() => browserSession.cookies.remove(cookieScopeURL, cookie.name)),
        ),
    );
    const results = await cookieRemovals;
    if (results.some((result) => result.status === 'rejected')) {
      throw new Error('VPN authentication cookie cleanup failed.');
    }
  };
  const fortinetLoopbackTarget = (url: string) => fortinetSSLLoopback(url, fireboxOrigin);
  authWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (settled || !isAuthorized()) return { action: 'deny' };
    try {
      if (event.completion === 'fortinet-ssl' && fortinetLoopbackTarget(url)) {
        return { action: 'deny' };
      }
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
  const inspectNavigationSafely = (url: string, status?: number) =>
    void inspectNavigation(url, status).catch(() => complete(false, '', 'session'));
  authWindow.webContents.on('did-navigate', (_event, url, status) => {
    if (
      event.completion === 'query-token' &&
      (status === 404 || status === 410) &&
      url === initialURLs[candidate]?.href
    ) {
      nextCandidate('load');
      return;
    }
    inspectNavigationSafely(url, status);
  });
  authWindow.webContents.on('did-navigate-in-page', (_event, url, isMainFrame) => {
    if (isMainFrame) inspectNavigationSafely(url);
  });
  authWindow.webContents.on('render-process-gone', (_event, { reason, exitCode }) => {
    recordDiagnostic('ERR', 'VPN sign-in renderer exited', { reason, exitCode });
    void complete(false, '', 'session');
  });
  const captureOAuthRedirect = (
    navigationEvent: Electron.Event<{ isMainFrame: boolean; url: string }>,
  ) => {
    if (!navigationEvent.isMainFrame) return;
    if (event.completion === 'oauth-code' || event.completion === 'fortinet-ipsec') {
      try {
        if (matchesOAuthRedirect(new URL(navigationEvent.url))) {
          navigationEvent.preventDefault();
          void inspectNavigation(navigationEvent.url);
        }
      } catch {
        // Chromium handles malformed navigation attempts as ordinary load failures.
      }
    }
  };
  authWindow.webContents.on('will-navigate', captureOAuthRedirect);
  // Microsoft completes Entra ID authorization with an HTTP redirect to the loopback callback.
  // Chromium reports server-side redirects through will-redirect rather than will-navigate; catch
  // the callback before localhost:2023 can fail with ERR_CONNECTION_REFUSED.
  authWindow.webContents.on('will-redirect', captureOAuthRedirect);
  if (event.completion === 'fortinet-ssl') {
    const webContentsId = authWindow.webContents.id;
    const completeCallback = (target: URL, unambiguous = true) => {
      const id = unambiguous ? fortinetSSLCallbackAuthId(target) : undefined;
      void complete(false, id ?? '', id ? undefined : 'response');
    };
    // Capture the HTTPS gateway's response before Chromium can send the ID to a local process.
    browserSession.webRequest.onHeadersReceived((details, callback) => {
      if (
        settled ||
        details.webContentsId !== webContentsId ||
        details.resourceType !== 'mainFrame' ||
        ![301, 302, 303, 307, 308].includes(details.statusCode) ||
        !isFortinetSSLCallbackSource(details.url, fireboxOrigin)
      ) {
        callback({});
        return;
      }
      const locations = Object.entries(details.responseHeaders ?? {})
        .filter(([name]) => name.toLowerCase() === 'location')
        .flatMap(([, values]) => values);
      const target = locations.map(fortinetLoopbackTarget).find((url) => url !== undefined);
      if (!target) {
        callback({});
        return;
      }
      callback({ cancel: true });
      completeCallback(target, locations.length === 1);
    });
    authWindow.webContents.on('will-navigate', (navigationEvent) => {
      const target = fortinetLoopbackTarget(navigationEvent.url);
      if (!target) return;
      navigationEvent.preventDefault();
      if (isFortinetSSLCallbackSource(navigationEvent.initiator?.url ?? '', fireboxOrigin)) {
        completeCallback(target);
      }
    });
    authWindow.webContents.on('will-redirect', (navigationEvent) => {
      if (fortinetLoopbackTarget(navigationEvent.url)) navigationEvent.preventDefault();
    });
  }
  authWindow.webContents.on('did-fail-load', (_event, code, _description, url, isMainFrame) => {
    const failure = tunnelBrowserLoadFailure(code);
    if (!isMainFrame || settled) return;
    // Keep a defensive fallback for Chromium versions that report an unreachable loopback target
    // without first delivering a cancellable navigation event.
    try {
      if (matchesOAuthRedirect(new URL(url))) {
        void inspectNavigation(url);
        return;
      }
    } catch {
      // A malformed failure URL cannot be an OAuth callback and follows normal fallback handling.
    }
    if (failure === undefined) return;
    reportWarning('VPN sign-in page failed to load');
    nextCandidate(failure);
  });
  authWindow.once('closed', () => {
    mcpApprovalWindowCoordinator.forgetTunnelAuthWindow(authWindow);
    if (event.completion === 'fortinet-ssl') browserSession.webRequest.onHeadersReceived(null);
    void complete(true);
  });
  // Keep this child non-modal so an MCP approval can safely preempt it on every supported desktop.
  authWindow.once('ready-to-show', () => {
    if (!settled && isAuthorized())
      mcpApprovalWindowCoordinator.presentTunnelAuthWindow(authWindow);
  });
  let cookieTimer: NodeJS.Timeout | undefined;
  authWindow.once('closed', () => {
    if (cookieTimer) clearInterval(cookieTimer);
  });
  const initialize = async () => {
    await clearCompletionCookie(() => !settled);
    if (!settled) {
      if (event.completion === 'cookie') {
        cookieTimer = setInterval(
          () => void inspectCookie().catch(() => complete(false, '', 'session')),
          250,
        );
      }
      // Load events own retries and errors. An old rejected promise must not end a newer load.
      void authWindow.loadURL(event.urls[0]).catch(() => undefined);
    }
  };
  void initialize().catch(() => complete(false, '', 'session'));
  await finished;
  signal.removeEventListener('abort', abort);
  if (event.completion === 'fortinet-ssl') {
    // The callback partitions are never reused. Cleanup can finish while the next prompt starts.
    void Promise.resolve()
      .then(() => browserSession.clearStorageData())
      .catch(() => undefined);
  }
  // Remove Fortinet's ephemeral VPN credential from its temporary cookie store after it
  // has crossed the one-shot Go sidecar boundary.
  if (event.completion === 'cookie') {
    let cleanupCurrent = true;
    let cleanupTimeout: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        (async () => {
          // Startup may have issued removals before cancellation. Bound those too.
          await cookieRemovals;
          if (cleanupCurrent) await clearCompletionCookie(() => cleanupCurrent);
        })().catch(() => undefined),
        new Promise<void>((resolve) => {
          cleanupTimeout = setTimeout(resolve, 1_000);
        }),
      ]);
    } finally {
      cleanupCurrent = false;
      if (cleanupTimeout) clearTimeout(cleanupTimeout);
    }
  }
  // A timed-out native removal can finish later: each Fortinet attempt owns a unique
  // in-memory partition, so it cannot touch another login or block the global auth queue.
}

class NativeBackendProcess {
  private readonly tunnelFailures = new TunnelFailureRegistry();
  readonly browserPrompts = new TunnelBrowserPromptTracker();
  private readonly rendererTunnelPrompts = new Map<string, string>();
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

  private readonly operation: 'serve' | 'browser-relay';

  constructor(operation: 'serve' | 'browser-relay' = 'serve') {
    this.operation = operation;
  }

  async send(
    command: NativeBackendCommand,
    timeoutMs: number | null = nativeBackendCommandTimeoutMs,
  ): Promise<BackendResponse> {
    await this.start();
    if (this.stopping || this.permanentlyStopped) throw new Error('Wormhole service is stopping.');
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

    if (timeoutMs === null) return response;

    const timeout = setTimeout(() => {
      const pending = this.pending.get(id);
      if (!pending) return;
      this.pending.delete(id);
      recordDiagnostic('ERR', 'Native backend request timed out (' + command.action + ')', {
        childPid: child.pid,
        timeoutMs,
      });
      pending.reject(new Error('Wormhole service did not respond in time.'));
    }, timeoutMs);

    return response.finally(() => clearTimeout(timeout));
  }

  async acquireTunnel(request: {
    onExit?: () => void;
    leaseId: string;
    nodeId?: string;
    tunnelConfigId?: string;
    progressSessionId?: string;
    dedicated?: boolean;
  }): Promise<string> {
    return (await this.acquireTunnelRoute(request)).socksEndpoint;
  }

  async openWebTunnelEndpoint(onExit: () => void): Promise<WebTunnelEndpoint> {
    const sessionId = randomUUID();
    let available = true;
    let disconnecting: Promise<void> | undefined;
    this.tunnelFailures.watch(sessionId, () => {
      available = false;
      onExit();
    });
    const send = async (
      action: 'browser-relay.open' | 'browser-relay.route' | 'browser-relay.close',
      port?: number,
    ) => {
      if (!available) throw new Error('The browser VPN endpoint is closed.');
      const response = await this.send({ action, sessionId, port });
      if (!response.ok || !available) throw new Error('The browser VPN endpoint is unavailable.');
      return response;
    };
    const retire = async (action: 'browser-relay.route' | 'browser-relay.close') => {
      if (!available) return;
      try {
        await send(action, action === 'browser-relay.route' ? 0 : undefined);
      } catch {
        // An unacknowledged pause or close leaves the upstream state unknown.
        if (available) await this.stop();
      }
    };
    const close = async () => {
      await retire('browser-relay.close');
      available = false;
      this.tunnelFailures.forget(sessionId);
    };
    try {
      const { forwardPort: port } = await send('browser-relay.open');
      if (typeof port !== 'number' || !Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error('The browser VPN endpoint returned an invalid port.');
      }
      return {
        port,
        connect: async (upstreamPort) => {
          disconnecting = undefined;
          await send('browser-relay.route', upstreamPort);
        },
        disconnect: () => (disconnecting ??= retire('browser-relay.route')),
        close,
      };
    } catch (error) {
      await close();
      throw error;
    }
  }

  async acquireTunnelRoute(request: {
    onExit?: () => void;
    leaseId: string;
    nodeId?: string;
    tunnelConfigId?: string;
    progressSessionId?: string;
    dedicated?: boolean;
  }): Promise<{
    active: boolean;
    socksEndpoint: string;
    configuredTunnelId?: string;
    tunnel?: WebBrowserState['tunnel'];
  }> {
    this.tunnelFailures.watch(request.leaseId, request.onExit);
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
      configuredTunnelId: response.configuredTunnelId,
      socksEndpoint: response.socksEndpoint ?? '',
      tunnel: {
        name: typeof response.tunnelName === 'string' ? response.tunnelName.slice(0, 256) : '',
        kind: typeof response.tunnelKind === 'string' ? response.tunnelKind.slice(0, 128) : '',
      },
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

  async releaseTunnel(leaseId: string, beforeRelease?: Promise<void>): Promise<void> {
    const child = this.child;
    this.tunnelFailures.forget(leaseId);
    if (beforeRelease) await beforeRelease;
    if (!child || this.child !== child) return;
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
    failure?: TunnelBrowserFailure;
  }): Promise<void> {
    const response = await this.send({
      action: 'tunnel.prompt-response',
      sessionId: request.leaseId,
      promptId: request.promptId,
      value: request.value,
      cancelled: request.cancelled,
      browserFailure: request.failure,
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
      'path' | 'password' | 'structureOnly' | 'reuseExisting' | 'planNonce' | 'planToken'
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
    this.stopPromise = Promise.resolve()
      .then(async () => {
        if (child) {
          const exited = await stopChildProcess(child, {
            gracefulTimeoutMs: nativeBackendShutdownTimeoutMs,
            nativeExecutable: backendPath(),
          });
          if (!exited) throw new Error('App service termination could not be confirmed.');
          if (this.child === child) this.child = undefined;
        }
        this.stopping = false;
      })
      .finally(() => {
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
        this.operation === 'browser-relay'
          ? ['--operation', this.operation]
          : [
              '--operation',
              this.operation,
              '--database',
              wormholeDatabasePath(),
              '--electron-user-data',
              electronUserDataPath(),
            ],
        { windowsHide: true, stdio: 'pipe' },
      );
      this.child = child;
      observeBackendProcess(child, this.operation, recordDiagnostic);
      child.stdout?.setEncoding('utf8');
      child.stdout?.on('data', (chunk: string | Buffer) => {
        if (this.child === child) this.readOutput(String(chunk));
      });
      child.stdout?.once('error', (error) => {
        if (this.child !== child) return;
        reportWarning('Native backend output stream failed', error);
        this.rejectAll(error instanceof Error ? error : new Error(String(error)));
        void this.stop().catch(() =>
          console.warn('[Wormhole] App service termination is unconfirmed.'),
        );
      });
      child.stdin?.once('error', (error) => {
        if (this.child !== child) return;
        if (!this.stopping) reportWarning('Native backend input stream failed', error);
        this.rejectAll(error instanceof Error ? error : new Error(String(error)));
      });
      child.once('spawn', () => {
        settled = true;
        resolve();
      });
      child.once('error', (error) => {
        if (this.child !== child) {
          if (!settled) reject(new Error('Wormhole service stopped.'));
          return;
        }
        if (child.pid === undefined) this.child = undefined;
        this.rejectAll(error instanceof Error ? error : new Error(String(error)));
        if (!settled) reject(error instanceof Error ? error : new Error(String(error)));
        if (child.pid !== undefined)
          void this.stop().catch(() =>
            console.warn('[Wormhole] App service termination is unconfirmed.'),
          );
      });
      child.once('close', (code) => {
        if (this.child !== child) {
          if (!settled) reject(new Error('Wormhole service stopped.'));
          return;
        }
        this.child = undefined;
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
      recordDiagnostic('ERR', 'Native backend response exceeded the stream limit');
      void this.stop().catch(() => reportWarning('App service termination is unconfirmed.'));
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
        reportWarning('Native backend sent invalid JSON');
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
        if (this.tunnelFailures.fail(message)) continue;
        if (message.type === 'tunnel.prompt-closed') {
          const prompt = message as BackendEvent;
          this.browserPrompts.close(prompt.sessionId, prompt.promptId);
          if (
            prompt.promptId &&
            this.rendererTunnelPrompts.get(prompt.promptId) === prompt.sessionId &&
            this.rendererTunnelPrompts.delete(prompt.promptId)
          ) {
            this.broadcastBackendEvent({
              type: 'tunnel.prompt-closed',
              sessionId: prompt.sessionId,
              promptId: prompt.promptId,
            });
          }
          continue;
        }
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
        const event = message as BackendEvent;
        if (event.type === 'tunnel.prompt') {
          if (!isSshSessionId(event.promptId) || !isSshSessionId(event.sessionId)) continue;
          this.rendererTunnelPrompts.set(event.promptId, event.sessionId);
        }
        this.broadcastBackendEvent(event);
      }
    }
  }

  private broadcastBackendEvent(event: BackendEvent): void {
    for (const window of BrowserWindow.getAllWindows()) {
      if (window.isDestroyed() || !windowCloseCoordinators.has(window)) continue;
      try {
        window.webContents.send('backend:event', event);
      } catch {
        // The window may be destroyed between isDestroyed() and send().
      }
    }
  }

  private rejectAll(error: Error): void {
    this.tunnelFailures.failAll();
    this.browserPrompts.clear();
    for (const [promptId, sessionId] of this.rendererTunnelPrompts) {
      this.broadcastBackendEvent({ type: 'tunnel.prompt-closed', sessionId, promptId });
    }
    this.rendererTunnelPrompts.clear();
    for (const pending of this.pending.values()) pending.reject(error);
    this.pending.clear();
  }
}

let nativeBackend: NativeBackendProcess | undefined;
let browserRelayBackend: NativeBackendProcess | undefined;
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
let bitwardenVaultAccessed = false;

function requireNativeResourcesRunning(): void {
  if (isQuitting) throw new Error('Wormhole service is stopping.');
}

function getNativeBackend(): NativeBackendProcess {
  nativeBackend ??= new NativeBackendProcess();
  return nativeBackend;
}

function getBrowserRelayBackend(): NativeBackendProcess {
  browserRelayBackend ??= new NativeBackendProcess('browser-relay');
  return browserRelayBackend;
}

async function releaseNativeTunnelLease(
  leaseId: string,
  beforeRelease?: Promise<void>,
): Promise<void> {
  const backend = nativeBackend;
  await (backend ? backend.releaseTunnel(leaseId, beforeRelease) : beforeRelease);
}

async function runBitwardenCredentialMaintenance(): Promise<void> {
  // WinUI starts both Bitwarden services only after startup authentication. Keep the same native
  // trust boundary here: a locked or not-yet-initialized renderer cannot trigger vault/installer
  // work merely because the background timer fired.
  if (isQuitting || !authSession.isAccessAllowed || !bitwardenVaultAccessed) return;
  const authorizationEpoch = authSession.authorizationEpoch;
  try {
    const state = await runBitwardenBackend<BitwardenCliState>('bitwarden.read');
    if (!isAuthorizationEpochCurrent(authorizationEpoch)) return;
    // Only an explicit vault action may install the CLI. Background maintenance must not
    // install it or touch the vault before the user needs Bitwarden in this app session.
    if (state.enabled && state.installed) {
      await runBitwardenBackend('bitwarden.sync-if-stale');
    }
  } catch (error) {
    reportWarning('Bitwarden credential background maintenance failed.', error);
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
    reportWarning('Bitwarden browser extension background maintenance failed.', error);
  }
}

function runBitwardenStartupMaintenance(): Promise<void> {
  bitwardenStartupMaintenancePromise ??= Promise.all([
    runBitwardenCredentialMaintenance(),
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
    () => void runBitwardenCredentialMaintenance(),
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
    if (mcpApprovalWindowCoordinator.hasPendingApprovals) return;
    await showCoordinatedMessageBox(owner, {
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
      reportWarning('Could not show the Bitwarden onboarding notice.', error);
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
  if (
    action === 'bitwarden.search' ||
    action === 'bitwarden.login' ||
    action === 'bitwarden.unlock'
  ) {
    bitwardenVaultAccessed = true;
  }
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
    'path' | 'password' | 'structureOnly' | 'reuseExisting' | 'planNonce' | 'planToken'
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
  return nativeVaultPaths.databasePath;
}
function electronUserDataPath(): string {
  return nativeVaultPaths.userDataPath;
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
    recordDiagnostic('ERR', 'Required backend executable missing', { architecture });
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

const vaultWindowPolicy = new VaultWindowPolicy({
  platform: process.platform,
  getWindows: () => BrowserWindow.getAllWindows(),
  createWindow: (options) => new BrowserWindow(options),
});
const createApplicationWindow = (options: Electron.BrowserWindowConstructorOptions) =>
  vaultWindowPolicy.createWindow(options);

const vaultLockMonitor = new VaultLockMonitor({
  profileChanged: () => broadcastVaultChange('vault:profile-changed'),
  applyProfile: (profile, source) => {
    vaultCrashCapture.apply(profile);
    if (source === 'refresh') retireVaultUpdates();
    const protectedWindows = vaultWindowPolicy.requiresContentProtection;
    vaultWindowPolicy.apply(profile);
    if (
      process.platform === 'win32' &&
      source === 'refresh' &&
      !protectedWindows &&
      vaultWindowPolicy.requiresContentProtection
    ) {
      // Existing ActiveX overlays belong to a separate process. Retire them
      // through the workspace lock before admitting the stronger policy.
      throw Error('Native RDP content protection requires a new vault unlock.');
    }
  },
  idleSeconds: () => powerMonitor.getSystemIdleTime(),
  idleState: (threshold) => powerMonitor.getSystemIdleState(threshold),
  security: () => vaultBackend.security(),
  lock: () =>
    lockApplication().catch(() => {
      console.warn('[Wormhole] Vault lock cleanup could not be confirmed.');
    }),
});

function hasAutomaticVaultLockTarget(): boolean {
  return (
    vaultBackend.isVaultWorkspace ||
    vaultCreateDialog.active ||
    vaultOSMigrationDialog.active ||
    vaultMigrationSetupDialog.active ||
    vaultSharedSetupDialog.active
  );
}

function requestAutomaticVaultLock(): void {
  if (!hasAutomaticVaultLockTarget()) return;
  void lockApplication().catch(() => {
    console.warn('[Wormhole] Vault lock cleanup could not be confirmed.');
  });
}

function beginLinuxVaultSleep() {
  const needsRetirement =
    authLocksInProgress > 0 || vaultBackend.hasOwner || hasAutomaticVaultLockTarget();
  const release = holdApplicationLock();
  return {
    retired: needsRetirement
      ? lockApplication(undefined, { refreshLegacy: false }).catch((error) => {
          console.warn('[Wormhole] Vault retirement before suspend could not be confirmed.');
          throw error;
        })
      : Promise.resolve(),
    release,
  };
}

function broadcastVaultChange(channel: 'vault:profile-changed' | 'vault:shared-catalog-changed') {
  for (const window of BrowserWindow.getAllWindows()) {
    if (
      !window.isDestroyed() &&
      windowCloseCoordinators.has(window) &&
      !window.webContents.isDestroyed()
    ) {
      try {
        window.webContents.send(channel);
      } catch {
        // The window closed while delivering the change notification.
      }
    }
  }
}

const vaultBackend = new VaultBackendHost(
  () =>
    new VaultBackendClient({
      executable: backendPath(),
      databasePath: wormholeDatabasePath(),
      userDataPath: electronUserDataPath(),
      migrationSessionData: vaultMigrationBoot.migrationSessionData,
      openTouchIDBroker:
        process.platform === 'darwin' && app.isPackaged ? launchVaultTouchIDBroker : undefined,
      onSharedCatalogChanged: () => {
        void vaultWebConnections.verifyViews();
        void sealedSerial.verifySharedUse();
        broadcastVaultChange('vault:shared-catalog-changed');
      },
      onUnavailable: () => {
        if (!vaultBackend.isVaultWorkspace) {
          void vaultBackend.stop().catch(() => {
            console.warn('[Wormhole] Vault metadata process shutdown could not be confirmed.');
          });
          return;
        }
        vaultLockMonitor.deactivate();
        authSession.lock();
        if (!authLockRequested && !isQuitting) requestAutomaticVaultLock();
      },
    }),
  () => !isQuitting && !authLockRequested && !nativeResourceShutdownPromise,
  (security) => vaultLockMonitor.activate(security),
  () => {
    rememberAuthState(vaultAuthState(), false);
    authSession.lock();
  },
  vaultMigrationBoot.legacyMigrationRequired === true,
);

const vaultCreateDialog = new VaultCreateDialog({
  host: vaultBackend,
  ipc: ipcMain,
  createWindow: createApplicationWindow,
  url:
    rendererUrl && !app.isPackaged
      ? new URL('vault-create.html', rendererUrl.endsWith('/') ? rendererUrl : rendererUrl + '/')
          .href
      : pathToFileURL(path.resolve(__dirname, '..', 'dist', 'vault-create.html')).href,
  preload: path.join(__dirname, 'vault-create-preload.cjs'),
  activate: () => {
    rememberAuthState(vaultAuthState(), false);
    authSession.markUnlocked();
  },
});

const vaultMigrationSetupDialog = new VaultMigrationSetupDialog({
  host: vaultBackend,
  ipc: ipcMain,
  createWindow: createApplicationWindow,
  url:
    rendererUrl && !app.isPackaged
      ? new URL('vault-create.html', rendererUrl.endsWith('/') ? rendererUrl : rendererUrl + '/')
          .href
      : pathToFileURL(path.resolve(__dirname, '..', 'dist', 'vault-create.html')).href,
  preload: path.join(__dirname, 'vault-migration-setup-preload.cjs'),
});

const vaultOSMigrationDialog = new VaultMigrationSetupDialog({
  host: vaultBackend,
  ipc: ipcMain,
  mode: 'os-migration',
  createWindow: createApplicationWindow,
  url:
    rendererUrl && !app.isPackaged
      ? new URL('vault-create.html', rendererUrl.endsWith('/') ? rendererUrl : rendererUrl + '/')
          .href
      : pathToFileURL(path.resolve(__dirname, '..', 'dist', 'vault-create.html')).href,
  preload: path.join(__dirname, 'vault-os-migration-preload.cjs'),
});

const vaultRootSetupDialog = new VaultMigrationSetupDialog({
  host: vaultBackend,
  ipc: ipcMain,
  mode: 'rotation',
  createWindow: createApplicationWindow,
  url:
    rendererUrl && !app.isPackaged
      ? new URL('vault-create.html', rendererUrl.endsWith('/') ? rendererUrl : rendererUrl + '/')
          .href
      : pathToFileURL(path.resolve(__dirname, '..', 'dist', 'vault-create.html')).href,
  preload: path.join(__dirname, 'vault-root-setup-preload.cjs'),
});

const vaultUpgradeSetupDialog = new VaultMigrationSetupDialog({
  host: vaultBackend,
  ipc: ipcMain,
  mode: 'upgrade',
  createWindow: createApplicationWindow,
  url:
    rendererUrl && !app.isPackaged
      ? new URL('vault-create.html', rendererUrl.endsWith('/') ? rendererUrl : rendererUrl + '/')
          .href
      : pathToFileURL(path.resolve(__dirname, '..', 'dist', 'vault-create.html')).href,
  preload: path.join(__dirname, 'vault-upgrade-preload.cjs'),
});

const vaultTunnelBrowserDialog = new VaultTunnelBrowserDialog({
  createWindow: createApplicationWindow,
  present: (window) => mcpApprovalWindowCoordinator.presentTunnelAuthWindow(window),
  forget: (window) => mcpApprovalWindowCoordinator.forgetTunnelAuthWindow(window),
  storage: ({ window, current, failed, context, signal, request, fallback }) => {
    if (!request) throw Error('VPN source request unavailable.');
    return new VaultVPNBrowserSession({
      window,
      current,
      failed,
      context,
      signal,
      request,
      ...(fallback ? { fallback } : {}),
      executable: backendPath(),
      authority: vaultBackend.vpnSSOAuthority(current),
    });
  },
});

const vaultTunnelAuthenticationDialog = new VaultTunnelAuthenticationDialog({
  ipc: ipcMain,
  createWindow: createApplicationWindow,
  url:
    rendererUrl && !app.isPackaged
      ? new URL(
          'vault-tunnel-authentication.html',
          rendererUrl.endsWith('/') ? rendererUrl : rendererUrl + '/',
        ).href
      : pathToFileURL(path.resolve(__dirname, '..', 'dist', 'vault-tunnel-authentication.html'))
          .href,
  preload: path.join(__dirname, 'vault-tunnel-authentication-preload.cjs'),
});

const vaultReauthenticationDialog = new VaultReauthenticationDialog({
  ipc: ipcMain,
  createWindow: createApplicationWindow,
  stop: () => vaultBackend.stop(),
  url:
    rendererUrl && !app.isPackaged
      ? new URL('vault-reauth.html', rendererUrl.endsWith('/') ? rendererUrl : rendererUrl + '/')
          .href
      : pathToFileURL(path.resolve(__dirname, '..', 'dist', 'vault-reauth.html')).href,
  preload: path.join(__dirname, 'vault-reauth-preload.cjs'),
});

const vaultSharedDialog = new VaultSharedAuthenticationDialog({
  host: vaultBackend,
  ipc: ipcMain,
  createWindow: createApplicationWindow,
  appVersion: app.getVersion(),
  pickInvitation: async (window) => {
    const result = await showCoordinatedOpenDialog(window, {
      title: 'Open workspace invitation',
      properties: ['openFile'],
      filters: [
        { name: 'Wormhole invitation', extensions: ['whinv', 'txt'] },
        { name: 'All files', extensions: ['*'] },
      ],
    });
    return result.canceled ? null : (result.filePaths[0] ?? null);
  },
  pickTLSUpdate: async (window) => {
    const result = await showCoordinatedOpenDialog(window, {
      title: 'Open signed workspace trust update',
      properties: ['openFile'],
      filters: [{ name: 'Wormhole trust bundle', extensions: ['whtls'] }],
    });
    return result.canceled ? null : (result.filePaths[0] ?? null);
  },
  pickResetOffer: async (window) => {
    const result = await showCoordinatedOpenDialog(window, {
      title: 'Open account reset file',
      properties: ['openFile'],
      filters: [{ name: 'Wormhole account reset', extensions: ['whreset'] }],
    });
    return result.canceled ? null : (result.filePaths[0] ?? null);
  },
  url:
    rendererUrl && !app.isPackaged
      ? new URL('vault-shared.html', rendererUrl.endsWith('/') ? rendererUrl : rendererUrl + '/')
          .href
      : pathToFileURL(path.resolve(__dirname, '..', 'dist', 'vault-shared.html')).href,
  preload: path.join(__dirname, 'vault-shared-preload.cjs'),
});

const vaultSharedSetupDialog = new VaultSharedSetupDialog({
  host: vaultBackend,
  pickBackup: (window, accepted) =>
    pickSharedBackupDestination(
      { showSaveDialog: showCoordinatedSaveDialog, showMessageBox: showCoordinatedMessageBox },
      window,
      accepted,
    ),
  pickAccountReset: async (window) => {
    const choice = await showCoordinatedSaveDialog(window, {
      title: 'Save account reset offer',
      defaultPath: 'account.whreset',
      filters: [{ name: 'Wormhole account reset', extensions: ['whreset'] }],
    });
    return choice.canceled ? null : (choice.filePath ?? null);
  },
  restore: {
    choose: async (window) => {
      const choice = await showCoordinatedOpenDialog(window, {
        title: 'Open encrypted workspace recovery backup',
        filters: [{ name: 'Wormhole recovery backup', extensions: ['json'] }],
        properties: ['openFile'],
      });
      return choice.canceled ? null : (choice.filePaths[0] ?? null);
    },
    inspect: (input, accepted) => vaultBackend.inspectSharedRecoveryBackup(input, accepted),
    apply: (input, accepted) => vaultBackend.restoreSharedRecoveryBackup(input, accepted),
  },
  recover: {
    choose: async (window, artifact) => {
      const kit = artifact === 'kit';
      const choice = await showCoordinatedOpenDialog(window, {
        title: kit ? 'Open the offline recovery kit' : 'Open the signed TLS trust bundle',
        filters: [
          {
            name: kit ? 'Wormhole recovery kit' : 'Wormhole trust bundle',
            extensions: [kit ? 'whrecovery' : 'whtls'],
          },
        ],
        properties: ['openFile'],
      });
      return choice.canceled ? null : (choice.filePaths[0] ?? null);
    },
    submit: (input, accepted) =>
      vaultBackend.sharedRecoverAdministrator(input, app.getVersion(), accepted),
  },
  join: (input, accepted) =>
    vaultBackend.sharedJoinAdministrator(input, app.getVersion(), accepted),
  ipc: ipcMain,
  createWindow: createApplicationWindow,
  pickExport: async (window, format) => {
    const choice = await showCoordinatedSaveDialog(
      window,
      format === 'hba'
        ? {
            title: 'Export PostgreSQL client access rules',
            defaultPath: 'wormhole-workspace-hba.conf',
            filters: [{ name: 'PostgreSQL configuration', extensions: ['conf'] }],
          }
        : {
            title: 'Export PostgreSQL deployment script',
            defaultPath: 'wormhole-workspace.sql',
            filters: [{ name: 'PostgreSQL SQL script', extensions: ['sql'] }],
          },
    );
    return choice.canceled ? null : (choice.filePath ?? null);
  },
  pickRecovery: async (window) => {
    const choice = await showCoordinatedSaveDialog(window, {
      title: 'Save the organisation recovery kit offline',
      defaultPath: 'wormhole-organisation.whrecovery',
      filters: [{ name: 'Wormhole organisation recovery kit', extensions: ['whrecovery'] }],
    });
    return choice.canceled ? null : (choice.filePath ?? null);
  },
  url:
    rendererUrl && !app.isPackaged
      ? new URL(
          'vault-shared-setup.html',
          rendererUrl.endsWith('/') ? rendererUrl : rendererUrl + '/',
        ).href
      : pathToFileURL(path.resolve(__dirname, '..', 'dist', 'vault-shared-setup.html')).href,
  preload: path.join(__dirname, 'vault-shared-setup-preload.cjs'),
});

const vaultNotesDialog = new VaultNotesDialog({
  host: vaultBackend,
  ipc: ipcMain,
  createWindow: createApplicationWindow,
  url:
    rendererUrl && !app.isPackaged
      ? new URL('vault-notes.html', rendererUrl.endsWith('/') ? rendererUrl : rendererUrl + '/')
          .href
      : pathToFileURL(path.resolve(__dirname, '..', 'dist', 'vault-notes.html')).href,
  preload: path.join(__dirname, 'vault-notes-preload.cjs'),
});

const vaultLinuxClipboard =
  process.platform === 'linux'
    ? new LinuxVaultClipboard({
        host: vaultBackend,
        io: linuxClipboardIO(clipboard, ClipboardItem),
      })
    : undefined;

const vaultCredentialsDialog = new VaultCredentialsDialog({
  linuxClipboard: vaultLinuxClipboard,
  host: vaultBackend,
  authenticate: (parent, accepted) => async (operation, descriptor, submit) =>
    vaultReauthenticationDialog.open(
      parent,
      () => accepted() && vaultBackend.unlockedWorkspaceId === descriptor.vaultId,
      operation,
      descriptor,
      submit,
    ),
  ipc: ipcMain,
  createWindow: createApplicationWindow,
  url:
    rendererUrl && !app.isPackaged
      ? new URL(
          'vault-credentials.html',
          rendererUrl.endsWith('/') ? rendererUrl : rendererUrl + '/',
        ).href
      : pathToFileURL(path.resolve(__dirname, '..', 'dist', 'vault-credentials.html')).href,
  preload: path.join(__dirname, 'vault-credentials-preload.cjs'),
});

const vaultSshCredentialsDialog = new VaultSshCredentialsDialog({
  ipc: ipcMain,
  createWindow: createApplicationWindow,
  url:
    rendererUrl && !app.isPackaged
      ? new URL(
          'vault-ssh-credentials.html',
          rendererUrl.endsWith('/') ? rendererUrl : rendererUrl + '/',
        ).href
      : pathToFileURL(path.resolve(__dirname, '..', 'dist', 'vault-ssh-credentials.html')).href,
  preload: path.join(__dirname, 'vault-ssh-credentials-preload.cjs'),
});

const vaultVncPasswordDialog = new VaultVncPasswordDialog({
  ipc: ipcMain,
  createWindow: createApplicationWindow,
  url:
    rendererUrl && !app.isPackaged
      ? new URL(
          'vault-vnc-password.html',
          rendererUrl.endsWith('/') ? rendererUrl : rendererUrl + '/',
        ).href
      : pathToFileURL(path.resolve(__dirname, '..', 'dist', 'vault-vnc-password.html')).href,
  preload: path.join(__dirname, 'vault-vnc-password-preload.cjs'),
});
const vaultBitwardenCLIUnlockDialog = new VaultProtectedEntryDialog({
  ipc: ipcMain,
  createWindow: createApplicationWindow,
  url:
    rendererUrl && !app.isPackaged
      ? new URL(
          'vault-bitwarden-cli-unlock.html',
          rendererUrl.endsWith('/') ? rendererUrl : rendererUrl + '/',
        ).href
      : pathToFileURL(path.resolve(__dirname, '..', 'dist', 'vault-bitwarden-cli-unlock.html'))
          .href,
  preload: path.join(__dirname, 'vault-bitwarden-cli-unlock-preload.cjs'),
  channel: 'vault-bitwarden-cli-unlock',
  title: 'Unlock Bitwarden CLI',
  height: 390,
  parseContext: parseVaultBitwardenCLIUnlockContext,
  parseEnvelope: parseVaultBitwardenCLIPassword,
});
const vaultBitwardenCLIUnlock = new VaultBitwardenCLIUnlockController({
  host: vaultBackend,
  executable: backendPath,
  databasePath: wormholeDatabasePath,
});
const vaultRdpCredentialsDialog = new VaultRdpCredentialsDialog({
  ipc: ipcMain,
  createWindow: createApplicationWindow,
  url:
    rendererUrl && !app.isPackaged
      ? new URL(
          'vault-rdp-credentials.html',
          rendererUrl.endsWith('/') ? rendererUrl : rendererUrl + '/',
        ).href
      : pathToFileURL(path.resolve(__dirname, '..', 'dist', 'vault-rdp-credentials.html')).href,
  preload: path.join(__dirname, 'vault-rdp-credentials-preload.cjs'),
});

const vaultTunnelDialog = new VaultTunnelDialog({
  pickImport: async (parent, format) => {
    const filters = {
      openvpn: { name: 'OpenVPN profile', extensions: ['ovpn', 'conf'] },
      watchguard: { name: 'WatchGuard bundle', extensions: ['wgssl', 'zip'] },
      azure: { name: 'Azure VPN profile', extensions: ['xml'] },
      cisco: { name: 'Cisco VPN profile', extensions: ['xml'] },
      'ipsec-cert': { name: 'Client certificate', extensions: ['pem', 'crt', 'cer'] },
      'ipsec-key': { name: 'Client private key', extensions: ['pem', 'key'] },
      'ipsec-ca': { name: 'CA certificates', extensions: ['pem', 'crt', 'cer'] },
    };
    const result = await showCoordinatedOpenDialog(parent, {
      title: 'Import VPN profile',
      properties: ['openFile', 'dontAddToRecent'],
      filters: [filters[format]],
    });
    return result.canceled || result.filePaths.length !== 1 ? null : result.filePaths[0]!;
  },
  capabilities: async () =>
    parseTunnelCapabilities(await runBackend<unknown>('tunnel-capabilities')),
  host: vaultBackend,
  ipc: ipcMain,
  createWindow: createApplicationWindow,
  confirm: (parent, accepted) => (operation, descriptor, submit) =>
    vaultReauthenticationDialog.open(
      parent,
      () => accepted() && vaultBackend.unlockedWorkspaceId === descriptor.vaultId,
      operation,
      descriptor,
      submit,
    ),
  url:
    rendererUrl && !app.isPackaged
      ? new URL('vault-tunnel.html', rendererUrl.endsWith('/') ? rendererUrl : rendererUrl + '/')
          .href
      : pathToFileURL(path.resolve(__dirname, '..', 'dist', 'vault-tunnel.html')).href,
  preload: path.join(__dirname, 'vault-tunnel-preload.cjs'),
});

function isTrustedVaultSender(event: Electron.IpcMainInvokeEvent): boolean {
  if (event.sender.isDestroyed()) return false;
  const owner = BrowserWindow.fromWebContents(event.sender);
  const frame = event.senderFrame;
  if (
    !owner ||
    owner.isDestroyed() ||
    !windowCloseCoordinators.has(owner) ||
    !frame ||
    frame !== event.sender.mainFrame
  )
    return false;
  return isTrustedVaultDocument(
    frame.url,
    pathToFileURL(path.resolve(__dirname, '..', 'dist', 'index.html')).href,
    rendererUrl,
    app.isPackaged,
  );
}

async function runBackend<T>(
  operation: BackendOperation,
  request?: unknown,
  timeoutMs: number = backendTimeoutMs,
  signal?: AbortSignal,
): Promise<T> {
  if (signal?.aborted) throw new Error('Operation cancelled.');
  if (
    (vaultBackend.isVaultWorkspace || vaultBackend.requiresLegacyMigration) &&
    operation !== 'tunnel-capabilities' &&
    !(
      operation === 'visual-changelog-claim' &&
      vaultBackend.isVaultWorkspace &&
      vaultBackend.unlockedWorkspaceId
    ) &&
    operation !== 'update-check-release' &&
    operation !== 'update-verify-installer'
  )
    throw new Error('This operation is not yet available for encrypted vaults.');
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
      operation === 'workspace-delete-nodes' || operation === 'workspace-move-nodes'
        ? workspaceDeleteNodesMaxRequestBytes
        : operation === 'settings-set-connection-tree-expansion'
          ? connectionTreeExpansionMaxRequestBytes
          : operation === 'workspace-node-create' || operation === 'workspace-node-update'
            ? workspaceNodeWriteMaxRequestBytes
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
    let abortRequested = false;
    observeBackendProcess(
      child,
      operation,
      recordDiagnostic,
      (code) => abortRequested || code === 0,
    );
    const cancellationError = new Error('Operation cancelled.');
    const effectiveTimeoutMs =
      timeoutMs === backendTimeoutMs && operation.startsWith('backup-')
        ? backupTimeoutMs
        : timeoutMs;
    // Hello is interactive and may open while the user is away after an idle lock.
    // Keep it alive until Windows settles it or the owning operation is cancelled.
    const timeout =
      operation === 'auth-hello-verify'
        ? undefined
        : setTimeout(() => {
            if (abortRequested) {
              finishReject(cancellationError);
              return;
            }
            recordDiagnostic('ERR', 'Backend request timed out (' + operation + ')', {
              childPid: child.pid,
              timeoutMs: effectiveTimeoutMs,
            });
            child.kill();
            finishReject(new Error('Wormhole did not respond in time.'));
          }, effectiveTimeoutMs);
    const abort = () => {
      if (settled) return;
      abortRequested = true;
      child.kill();
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
      if (settled || abortRequested) return;
      stdout += chunk;
      stdoutBytes += Buffer.byteLength(chunk, 'utf8');
      if (stdoutBytes > backendMaxBuffer) {
        recordDiagnostic('ERR', 'Backend response exceeded the limit (' + operation + ')', {
          childPid: child.pid,
        });
        child.kill();
        finishReject(new Error('Wormhole returned too much data.'));
      }
    });
    child.stderr?.on('data', (chunk: string) => {
      if (settled || abortRequested) return;
      stderr += chunk;
      if (stderr.length > backendMaxBuffer) stderr = stderr.slice(-backendMaxBuffer);
    });
    child.on('error', (error) => {
      if (!abortRequested) finishReject(error);
    });
    child.stdin?.on('error', (error) => {
      if (!abortRequested) finishReject(error);
    });
    child.on('close', (code) => {
      if (settled) return;
      if (abortRequested) {
        finishReject(cancellationError);
        return;
      }
      settled = true;
      clearTimeout(timeout);
      signal?.removeEventListener('abort', abort);
      if (code !== 0) {
        reject(new Error(backendErrorText(stderr) || 'Wormhole could not complete the request.'));
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
    recordDiagnostic('ERR', 'Backend returned invalid JSON (' + operation + ')', {
      childPid: child.pid,
    });
    throw new Error('Wormhole returned invalid data.');
  }
}

// ---- update checks / downloads ----

function captureUpdateScope(): VaultUpdateScope | undefined {
  if (vaultBackend.requiresLegacyMigration || authLockRequested || isQuitting)
    throw Error('Update services are unavailable.');
  if (!vaultBackend.isVaultWorkspace) return undefined;
  const workspaceId = vaultBackend.unlockedWorkspaceId;
  if (!workspaceId || !authSession.isAccessAllowed) throw Error('Vault is locked.');
  return { workspaceId, epoch: authSession.authorizationEpoch };
}

function sameUpdateScope(a?: VaultUpdateScope, b?: VaultUpdateScope): boolean {
  return a?.workspaceId === b?.workspaceId && a?.epoch === b?.epoch;
}

function requireUpdateScope(scope?: VaultUpdateScope): void {
  if (!sameUpdateScope(scope, captureUpdateScope())) throw Error('The update workspace changed.');
}

async function readVaultUpdateProfile(scope?: VaultUpdateScope): Promise<VaultProfile | undefined> {
  requireUpdateScope(scope);
  if (!scope) return undefined;
  const security = await vaultBackend.security();
  requireUpdateScope(scope);
  const minimum = vaultLockMonitor.effectiveProfile;
  if (!minimum) throw Error('The vault security policy is unavailable.');
  const fresh = stricterVaultProfile(minimum, security.effective);
  const profile =
    updateProfileFloor && sameUpdateScope(scope, updateProfileFloor.scope)
      ? stricterVaultProfile(updateProfileFloor.profile, fresh)
      : fresh;
  updateProfileFloor = { scope, profile };
  return profile;
}

function applyUpdatePolicy(
  result: UpdateCheckResult,
  profile: VaultProfile | undefined,
  signed: boolean,
  publisherVerification = false,
): UpdateCheckResult {
  const managed = result.updatePolicy === 'managed';
  if (profile === 'paranoid' && !managed)
    return { ...emptyUpdateResult(), updatePolicy: 'managed' };
  if (
    profile &&
    (!signed || !updateProfileAllowsInstaller(profile, publisherVerification, managed))
  ) {
    const {
      installerUrl: _installerUrl,
      installerFileName: _installerFileName,
      installerSize: _installerSize,
      installerSha256: _installerSha256,
      ...release
    } = result;
    return {
      ...release,
      isUpdateAvailable: false,
      updatePolicy: managed ? 'managed' : profile === 'default' ? undefined : 'notify',
    };
  }
  return result;
}

function updateProfileAllowsInstaller(
  profile: VaultProfile | undefined,
  publisherVerification: boolean,
  managed: boolean,
): boolean {
  if (managed) return profile === 'hardened' || profile === 'paranoid';
  return profile === 'default' || (profile === 'standard' && publisherVerification);
}

function emptyUpdateResult(): UpdateCheckResult {
  return {
    currentVersion: app.getVersion(),
    latestVersion: '',
    isNewerRelease: false,
    isUpdateAvailable: false,
    checkFailed: false,
  };
}

async function requireUpdateInstaller(scope?: VaultUpdateScope): Promise<VaultProfile | undefined> {
  const profile = await readVaultUpdateProfile(scope);
  if (
    scope &&
    (!latestUpdateManifest ||
      !updateProfileAllowsInstaller(
        profile,
        latestUpdatePublisherVerification,
        latestUpdateCheck?.updatePolicy === 'managed',
      ))
  )
    throw Error('The vault update policy does not allow this installer.');
  return profile;
}

function retireVaultUpdates(): void {
  const notify = !!latestUpdateScope;
  latestUpdateScope = undefined;
  latestUpdateManifest = undefined;
  latestUpdatePublisherVerification = false;
  latestUpdateCheck = undefined;
  downloadedUpdate = undefined;
  updateCheckInFlight?.cancellation.abort();
  updateCheckInFlight = undefined;
  clearTimeout(startupUpdateTimer);
  startupUpdateTimer = undefined;
  startupUpdateScheduled = undefined;
  updateDownloadChild?.kill();
  if (notify) broadcastUpdateResult(emptyUpdateResult());
}

// Coalesce checks within one unlock. An old owner cannot update preferences
// or make a release installable in a replacement workspace.
function performUpdateCheck(): Promise<UpdateCheckResult> {
  if (quitCleanupStarted) throw Error('Wormhole is already closing.');
  const scope = captureUpdateScope();
  if (updateCheckInFlight && sameUpdateScope(scope, updateCheckInFlight.scope))
    return updateCheckInFlight.result;
  updateCheckInFlight?.cancellation.abort();
  const cancellation = new AbortController();
  const result = (async () => {
    const profile = await readVaultUpdateProfile(scope);
    const managedMode =
      profile === 'paranoid' ? 'required' : profile === 'hardened' ? 'preferred' : undefined;
    const { signedManifest, publisherVerification, managed, ...release } = await runBackend<
      UpdateCheckResult & {
        signedManifest?: string;
        publisherVerification?: boolean;
        managed?: boolean;
      }
    >(
      scope ? 'update-check-release' : 'update-check',
      { currentVersion: app.getVersion(), ...(managedMode ? { managedMode } : {}) },
      65_000,
      cancellation.signal,
    );
    if (scope) {
      const confirmed = await readVaultUpdateProfile(scope);
      if (confirmed !== profile) throw Error('The vault update policy changed.');
      if (cancellation.signal.aborted) throw Error('The update check was cancelled.');
      if (release.lastUpdateCheck)
        await vaultBackend.updatePreferences({ lastUpdateCheck: release.lastUpdateCheck });
    }
    requireUpdateScope(scope);
    if (cancellation.signal.aborted) throw Error('The update check was cancelled.');
    const verifiesPublisher = publisherVerification === true && !!signedManifest;
    const visible = applyUpdatePolicy(
      managed ? { ...release, updatePolicy: 'managed' } : release,
      profile,
      !!signedManifest,
      verifiesPublisher,
    );
    latestUpdateManifest = visible.isUpdateAvailable ? signedManifest : undefined;
    latestUpdatePublisherVerification = visible.isUpdateAvailable && verifiesPublisher;
    latestUpdateScope = scope;
    latestUpdateCheck = visible;
    broadcastUpdateResult(visible);
    return visible;
  })().finally(() => {
    if (updateCheckInFlight?.result === result) updateCheckInFlight = undefined;
  });
  updateCheckInFlight = { scope, result, cancellation };
  return result;
}

function broadcastUpdateResult(result: UpdateCheckResult): void {
  for (const window of BrowserWindow.getAllWindows()) {
    if (
      !window.isDestroyed() &&
      windowCloseCoordinators.has(window) &&
      !window.webContents.isDestroyed()
    ) {
      try {
        window.webContents.send('update:result', result);
      } catch {
        // A closing renderer cannot affect the updater or vault retirement.
      }
    }
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
  return isSafeUpdateInstallerPath(
    value,
    updateCacheRoot(),
    process.platform,
    latestUpdateCheck?.updatePolicy === 'managed',
  );
}

// downloadUpdateInstaller runs a dedicated backend process that streams the installer to the
// update cache. The backend reports {"type":"progress",...} JSON lines and finishes with
// {"type":"complete","path":...}; the final path resolves this promise. The 30s runBackend
// timeout would kill a large installer on a slow connection, so this spawn deliberately bypasses
// it (matching the WinUI download client's long timeout).
function downloadUpdateInstaller(
  request: NativeUpdateDownloadRequest,
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
  observeBackendProcess(child, 'update-download', recordDiagnostic, (code) => code === 0);
  const cleanup = () => {
    if (updateDownloadChild === child) updateDownloadChild = undefined;
  };

  return new Promise<string>((resolve, reject) => {
    let stdoutBytes = 0;
    let stderr = '';
    let completedPath: string | undefined;
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
        finishReject(new Error(backendErrorText(stderr) || 'The installer download failed.'));
        return;
      }
      if (completedPath) finishResolve(completedPath);
      else {
        recordDiagnostic('ERR', 'Update download ended before reporting completion');
        finishReject(new Error('The installer download ended before completing.'));
      }
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
        if (completedPath) {
          child.kill();
          finishReject(new Error('The installer download returned duplicate completion data.'));
          return;
        }
        completedPath = message.path;
      }
    });

    child.stdin?.end(JSON.stringify(request));
  });
}

async function handleDownloadedUpdate(
  download: DownloadedUpdate,
  accepted: () => boolean,
): Promise<{ appWillQuit: boolean }> {
  if (quitCleanupStarted || isQuitting) throw new Error('Wormhole is already closing.');
  return updateInstallTasks.runExclusive(
    'install',
    async () => {
      const action = updateInstallAction(process.platform);
      const launch = async () => {
        const profile = await requireUpdateInstaller(download.scope);
        if (!accepted() || download !== downloadedUpdate || !updateMatchesLatest(download.request))
          throw Error('The selected update changed. Download it again.');
        const requirePublisher = latestUpdatePublisherVerification || profile === 'standard';
        const request = { ...download.request, requirePublisher };
        type Receipt = {
          verified: boolean;
          publisherVerified?: boolean;
          managedPackagePath?: string;
        };
        const checkReceipt = (result: Receipt, currentProfile: VaultProfile | undefined) => {
          requireUpdateScope(download.scope);
          if (
            result.verified !== true ||
            !accepted() ||
            download !== downloadedUpdate ||
            !updateMatchesLatest(download.request)
          )
            throw Error('The installer could not be verified.');
          if (
            (requirePublisher ||
              latestUpdatePublisherVerification ||
              currentProfile === 'standard') &&
            result.publisherVerified !== true
          )
            throw Error('The installer publisher could not be verified.');
        };
        let handoffPath = download.path;
        if (action !== 'execute') {
          const result = await runBackend<Receipt>('update-verify-installer', request, 120_000);
          checkReceipt(result, await requireUpdateInstaller(download.scope));
          if (action === 'open') isQuitting = true;
          if (process.platform === 'linux' && latestUpdateCheck?.updatePolicy === 'managed') {
            const staged = result.managedPackagePath;
            if (
              typeof staged !== 'string' ||
              !path.posix.isAbsolute(staged) ||
              path.posix.normalize(staged) !== staged ||
              staged === download.path ||
              path.posix.basename(staged) !== download.request.installerFileName
            )
              throw Error('The administrator-staged system package could not be verified.');
            handoffPath = staged;
          }
        }
        await launchDownloadedUpdate(handoffPath, process.platform, {
          execute: () =>
            completeWindowsUpdateHandoff(
              spawn(
                backendPath(),
                ['--operation', 'update-install-windows', '--database', wormholeDatabasePath()],
                {
                  stdio: ['pipe', 'pipe', 'ignore'],
                  windowsHide: true,
                },
              ),
              request,
              async (publisherVerified, commit) => {
                const currentProfile = await requireUpdateInstaller(download.scope);
                checkReceipt({ verified: true, publisherVerified }, currentProfile);
                commit(currentProfile !== 'paranoid');
                isQuitting = true;
              },
            ),
          openPath: (installerPath) => shell.openPath(installerPath),
          showItemInFolder: (installerPath) => shell.showItemInFolder(installerPath),
        });
        downloadedUpdate = undefined;
      };
      if (action === 'execute' || action === 'open') {
        await requestUpdateQuit(launch);
        return { appWillQuit: true };
      }
      await launch();
      return { appWillQuit: false };
    },
    'An update installation is already in progress.',
  );
}

function updateMatchesLatest(request: UpdateDownloadRequest): boolean {
  const expected = latestUpdateCheck;
  return (
    !!expected?.isUpdateAvailable &&
    request.installerUrl === expected.installerUrl &&
    request.installerFileName === expected.installerFileName &&
    request.installerSha256 === expected.installerSha256 &&
    request.installerSize === expected.installerSize
  );
}

function requestUpdateQuit(launch: () => Promise<void>): Promise<void> {
  if (quitCleanupStarted || isQuitting)
    return Promise.reject(new Error('Wormhole is already closing.'));
  return new Promise((resolve, reject) => {
    // app.quit() is asynchronous and before-quit can cancel it. Keep the IPC pending until
    // cleanup succeeds, or reject it so the renderer can offer another update attempt.
    pendingUpdateQuit = { launch, resolve, reject };
    skipQuitConfirmation = true;
    try {
      app.quit();
    } catch {
      settleUpdateQuit(new Error('Wormhole could not close for the update.'));
    }
  });
}

function settleUpdateQuit(error?: Error): void {
  const pending = pendingUpdateQuit;
  if (!pending) return;
  pendingUpdateQuit = undefined;
  if (error) {
    skipQuitConfirmation = false;
    pending.reject(error);
  } else {
    pending.resolve();
  }
}

function scheduleStartupUpdateCheck(
  settings: Pick<AppSettings, 'autoCheckForUpdates'>,
  scope?: VaultUpdateScope,
): void {
  if (
    !settings.autoCheckForUpdates ||
    (startupUpdateScheduled && sameUpdateScope(startupUpdateScheduled.scope, scope))
  )
    return;
  const scheduled = { scope };
  startupUpdateScheduled = scheduled;
  clearTimeout(startupUpdateTimer);
  startupUpdateTimer = setTimeout(() => {
    startupUpdateTimer = undefined;
    void (async () => {
      requireUpdateScope(scope);
      if (scope && !(await vaultBackend.preferences()).autoCheckForUpdates) {
        if (startupUpdateScheduled === scheduled) startupUpdateScheduled = undefined;
        return;
      }
      requireUpdateScope(scope);
      await performUpdateCheck();
    })().catch((error) => {
      if (
        scope &&
        (scope.workspaceId !== vaultBackend.unlockedWorkspaceId ||
          !isAuthorizationEpochCurrent(scope.epoch))
      )
        return;
      // A failed startup check must never block the app: the settings page still exposes
      // "Check now", and a later result arrives through the update:result event.
      reportWarning('Startup update check failed.', error);
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
    recordDiagnostic('INF', 'Deleted ' + what);
    return result;
  } catch (error) {
    // A refused or already-missing item is a normal user outcome, not an app error.
    const message = error instanceof Error ? error.message : String(error);
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

type WebBrowserWindowOptions = Electron.BrowserWindowConstructorOptions & {
  webContents?: Electron.WebContents;
};

type WebSurfaceRecord = {
  sessionId: string;
  owner: BrowserWindow;
  readonly view: WebContentsView;
  tabs: WebBrowserTabs<WebContentsView>;
  displayedTabId: string;
  target: WebTargetResponse;
  partition: string;
  bounds?: WebBoundsRequest;
  preview?: {
    id: string;
    tabId: string;
    authorizationEpoch: number;
    image: Promise<string | undefined>;
  };
  route: 'direct' | 'vpn';
  tunnel?: WebBrowserState['tunnel'];
  vpn?: {
    configId: string;
    endpoint: WebTunnelEndpoint;
    session: Electron.Session;
    status: NonNullable<WebBrowserState['vpnStatus']>;
  };
  attempt: number;
  disposed: boolean;
  navigation: {
    navigateUrl: string;
    originalUrl?: string;
  };
  tunnelLeaseId?: string;
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
  if (!webTargetURLMatchesEndpoint(targetUrl, value)) {
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

const treeTooltips = new TreeTooltipManager(createApplicationWindow);

type VaultWebSurfaceOwner = {
  owner: BrowserWindow;
  contents: Electron.WebContents;
  generation: number;
  partition?: string;
  cookies?: VaultWebCookieCheckpoint;
  cleanup?: Promise<void>;
  views?: Map<Electron.WebContents, Promise<void> | undefined>;
};

class WebSurfaceManager {
  private readonly vault?: {
    active: () => boolean;
    connections: Pick<
      VaultWebConnections,
      'open' | 'close' | 'closeAll' | 'retireRoute' | 'retireAllRoutes'
    >;
  };
  private readonly vaultSessionOwners = new Map<string, VaultWebSurfaceOwner>();
  private readonly vaultOwnerHooks = new Map<BrowserWindow, () => void>();

  constructor(vault?: WebSurfaceManager['vault']) {
    this.vault = vault;
  }

  private watchVaultOwner(owner: BrowserWindow): void {
    if (this.vaultOwnerHooks.has(owner)) return;
    const close = () => this.closeForWindow(owner);
    const contents = owner.webContents;
    contents.on('did-start-loading', close);
    contents.on('render-process-gone', close);
    contents.on('destroyed', close);
    owner.on('closed', close);
    this.vaultOwnerHooks.set(owner, () => {
      contents.off('did-start-loading', close);
      contents.off('render-process-gone', close);
      contents.off('destroyed', close);
      owner.off('closed', close);
    });
  }

  private forgetVaultOwner(sessionId: string, token: VaultWebSurfaceOwner): void {
    if (this.vaultSessionOwners.get(sessionId) !== token) return;
    this.vaultSessionOwners.delete(sessionId);
    if (![...this.vaultSessionOwners.values()].some((entry) => entry.owner === token.owner)) {
      this.vaultOwnerHooks.get(token.owner)?.();
      this.vaultOwnerHooks.delete(token.owner);
    }
  }

  async stopVaultSessions(): Promise<void> {
    const routes = this.vault?.connections.retireAllRoutes();
    const owned = [...this.vaultSessionOwners];
    for (const [id] of owned) this.close(id);
    const results = await Promise.allSettled([
      ...owned.map(([id]) => this.releaseTunnel(id)),
      routes,
    ]);
    if (results.some((result) => result.status === 'rejected'))
      throw Error('Web shutdown could not be confirmed.');
    await this.vault?.connections.closeAll();
  }

  private readonly surfaces = new Map<string, WebSurfaceRecord>();
  private readonly tunnelProxy = new WebTunnelProxy();
  private readonly pendingOpenOwners = new Map<string, BrowserWindow>();
  private readonly tunnelLeases = new TunnelLeaseRegistry();
  private readonly tunnelEndpoints = new Map<string, WebTunnelEndpoint>();
  private readonly tunnelLeaseOwners = new Map<string, BrowserWindow>();
  private readonly attempts = new WebSessionAttemptTracker();
  private readonly extensionLoads = new Map<string, Promise<void>>();
  private readonly extensionLoadKeys = new Map<string, string>();
  private readonly extensionIds = new Map<string, string>();
  private readonly extensionPopupPaths = new Map<string, string>();
  private readonly retiringBitwardenProfiles = new Set<string>();
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
  private bitwardenPopupRequest: { sessionId: string } | undefined;
  private readonly bitwardenStorageTasks = new KeyedTaskTracker<string>();
  private readonly bitwardenExtensionMutation = new ExtensionMutationGuard();
  private bitwardenStorageQueue: Promise<void> = Promise.resolve();
  private readonly bitwardenCheckpoints = new WeakMap<
    Electron.WebContents,
    BitwardenStorageCheckpoint
  >();
  private readonly initializedBitwardenStorage = new WeakSet<Electron.WebContents>();
  private bitwardenStoragePaused = false;
  private bitwardenCheckpointTimer: NodeJS.Timeout | undefined;
  private isolatedPartitionSequence = 0;

  async open(
    owner: BrowserWindow,
    request: WebOpenRequest,
    trusted: () => boolean = () => true,
  ): Promise<WebTargetResponse> {
    const vaultOpen = this.vault?.active() === true;
    if (vaultOpen) {
      const reserved = new Set([
        ...this.vaultSessionOwners.keys(),
        ...this.pendingOpenOwners.keys(),
      ]);
      if (!reserved.has(request.sessionId) && reserved.size >= 32)
        throw Error('Vault web connection is unavailable.');
      const previous =
        this.vaultSessionOwners.get(request.sessionId)?.owner ??
        this.pendingOpenOwners.get(request.sessionId) ??
        this.surfaces.get(request.sessionId)?.owner;
      if (!trusted() || !parseVaultWebRequest(request) || (previous && previous !== owner))
        throw Error('Vault web connection is unavailable.');
    }
    const authorizationEpoch = authSession.authorizationEpoch;
    const generation = this.attempts.begin(request.sessionId);
    this.pendingOpenOwners.set(request.sessionId, owner);
    this.dispose(request.sessionId);
    let openingLeaseId: string | undefined;
    let openingEndpoint: WebTunnelEndpoint | undefined;
    let openingProxySession: Electron.Session | undefined;
    let openingTunnelBackend: NativeBackendProcess | undefined;
    let bitwardenUseRelease: (() => void) | undefined;
    let openingRecord: WebSurfaceRecord | undefined;
    let openingVaultOwner: VaultWebSurfaceOwner | undefined;
    let prepared: PreparedVaultWebConnection | undefined;
    try {
      await this.releaseTunnel(request.sessionId);
      this.assertOpenCurrent(
        request.sessionId,
        generation,
        owner,
        'Web session was superseded before its VPN tunnel could open.',
      );
      const resolveTarget = async () =>
        validateWebTarget(
          await runBackend<WebTargetResponse>('web-target', {
            nodeId: request.nodeId,
            address: request.address,
            port: request.port,
            protocol: request.protocol,
            ignoreCertErrors: request.ignoreCertErrors,
            tunnelConfigId: request.tunnelConfigId,
          }),
        );
      let target: WebTargetResponse | undefined;
      if (vaultOpen) {
        const token = { owner, contents: owner.webContents, generation };
        openingVaultOwner = token;
        this.vaultSessionOwners.set(request.sessionId, token);
        this.watchVaultOwner(owner);
        prepared = await this.vault!.connections.open(
          request.quickTarget
            ? { sessionId: request.sessionId, quickTarget: request.quickTarget }
            : { sessionId: request.sessionId, nodeId: request.nodeId! },
          authorizationEpoch + 1,
          () =>
            this.vaultSessionOwners.get(request.sessionId) === token &&
            isAuthorizationEpochCurrent(authorizationEpoch) &&
            trusted() &&
            !owner.isDestroyed() &&
            !owner.webContents.isDestroyed() &&
            this.attempts.isCurrent(request.sessionId, generation) &&
            (this.pendingOpenOwners.get(request.sessionId) === owner ||
              this.surfaces.get(request.sessionId)?.owner === owner),
          (reason) => {
            if (this.vaultSessionOwners.get(request.sessionId) !== token) return;
            const record = this.surfaces.get(request.sessionId);
            if (record)
              this.sendEvent(request.sessionId, record, 'failed', {
                error:
                  reason === 'route'
                    ? tunnelClosedMessage
                    : reason === 'view-revoked'
                      ? 'Access to the shared browser was revoked.'
                      : 'Access to the shared browser could not be verified.',
              });
            this.close(request.sessionId);
          },
        );
        const { proxyUrl, ...publicTarget } = prepared.target;
        target = { ...validateWebTarget(publicTarget), ...(proxyUrl ? { proxyUrl } : {}) };
      } else if (!request.nodeId) {
        target = await resolveTarget();
      }
      this.assertOpenCurrent(
        request.sessionId,
        generation,
        owner,
        'Web session was superseded before its VPN tunnel could open.',
      );
      if (!isAuthorizationEpochCurrent(authorizationEpoch)) {
        throw new Error('Web session was superseded before its VPN tunnel could open.');
      }
      let resolvedTunnelRoute: 'direct' | 'socks5' | 'forwarder' = prepared?.route ?? 'direct';
      let tunnel: WebBrowserState['tunnel'];
      let tunnelRoute: Awaited<ReturnType<NativeBackendProcess['acquireTunnelRoute']>> | undefined;
      // Ask for the route before a one-shot backend process resolves the browser target.
      if (!vaultOpen && (request.nodeId || request.tunnelConfigId)) {
        const leaseId = randomUUID();
        openingLeaseId = leaseId;
        this.tunnelLeases.claim(request.sessionId, leaseId);
        this.tunnelLeaseOwners.set(request.sessionId, owner);
        openingTunnelBackend = getNativeBackend();
        tunnelRoute = await openingTunnelBackend.acquireTunnelRoute({
          onExit: () => this.webTunnelExited(request.sessionId, leaseId),
          leaseId,
          nodeId: request.nodeId,
          tunnelConfigId: request.tunnelConfigId,
          progressSessionId: request.sessionId,
        });
      }
      this.assertOpenCurrent(
        request.sessionId,
        generation,
        owner,
        'Web session was superseded before its target could be resolved.',
      );
      if (!isAuthorizationEpochCurrent(authorizationEpoch)) {
        throw new Error('Web session was superseded before its target could be resolved.');
      }
      if (!vaultOpen) {
        target ??= await resolveTarget();
        if (request.nodeId || tunnelRoute?.active) {
          assertTunnelRouteUnchanged(tunnelRoute?.configuredTunnelId, target.tunnelConfigId ?? '');
        }
      }
      if (!target) throw Error('Vault web connection is unavailable.');
      this.assertOpenCurrent(
        request.sessionId,
        generation,
        owner,
        'Web session was superseded before its VPN tunnel could open.',
      );
      const logicalTargetUrl = target.url;
      if (!tunnelRoute?.active && (request.tunnelConfigId || tunnelRoute?.socksEndpoint)) {
        throw new Error('The requested VPN tunnel is unavailable.');
      }
      if (tunnelRoute?.active) {
        if (!target.tunnelConfigId)
          throw new Error('The browser VPN configuration is unavailable.');
        tunnel = tunnelRoute.tunnel;
        const port = await this.webTunnelUpstreamPort(
          openingTunnelBackend!,
          openingLeaseId!,
          target,
          tunnelRoute.socksEndpoint,
        );
        openingEndpoint = await getBrowserRelayBackend().openWebTunnelEndpoint(() => {
          if (!this.attempts.isCurrent(request.sessionId, generation)) return;
          const record = this.surfaces.get(request.sessionId);
          if (record) {
            this.sendEvent(request.sessionId, record, 'failed', {
              error: 'The browser VPN endpoint stopped. Reconnect this browser to continue.',
            });
          }
          this.close(request.sessionId);
        });
        if (!this.tunnelLeases.isActive(request.sessionId, openingLeaseId!)) {
          throw new Error('The VPN connection stopped while preparing this browser.');
        }
        this.tunnelEndpoints.set(openingLeaseId!, openingEndpoint);
        await openingEndpoint.connect(port);
        if (tunnelRoute.socksEndpoint) {
          resolvedTunnelRoute = 'socks5';
          target.proxyUrl = `socks5://${tunnelRoute.socksEndpoint}`;
        } else {
          resolvedTunnelRoute = 'forwarder';
          const forwardedUrl = new URL(target.url);
          forwardedUrl.hostname = '127.0.0.1';
          forwardedUrl.port = String(openingEndpoint.port);
          target.url = forwardedUrl.toString();
        }
      } else if (openingLeaseId) {
        await this.releaseTunnel(request.sessionId);
        openingLeaseId = undefined;
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
      if (!vaultOpen && target.url.startsWith('https://')) {
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
          reportWarning('Bitwarden browser extension setup failed for this HTTPS tab.', error);
        }
        const freshInstall = freshState?.installed;
        if (freshState?.enabled && freshInstall) {
          // Each dedicated browser has its own profile. SOCKS endpoints can change on reconnect;
          // the stable browser/route identity preserves only that browser's appliance cookies.
          let routeKey = '';
          if (target.tunnelConfigId && resolvedTunnelRoute !== 'direct') {
            routeKey = buildBitwardenPersistentRouteKey(
              target.tunnelConfigId,
              resolvedTunnelRoute,
              logicalTargetUrl,
              request.sessionId,
            );
          }
          const browserContext = `${buildBitwardenBrowserContext(target.proxyUrl, routeKey)}\0browser=${request.sessionId}`;
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
        bitwardenPartition ?? `wormhole-web-browser-${++this.isolatedPartitionSequence}`;
      const browserSession = electronSession.fromPartition(partition, {
        cache: true,
      });
      if (openingVaultOwner) openingVaultOwner.partition = partition;
      const routedOrigin =
        resolvedTunnelRoute === 'forwarder' ? new URL(target.url).origin : undefined;
      if (openingEndpoint) {
        const proxyConfig = { ...blockedWebTunnelProxy };
        if (routedOrigin) {
          // Permit direct connections only to this browser's loopback forwarder.
          proxyConfig.proxyBypassRules += `;${routedOrigin};${routedOrigin.replace(/^http/, 'ws')}`;
        } else {
          target.proxyUrl = `socks5://127.0.0.1:${openingEndpoint.port}`;
          proxyConfig.proxyRules = target.proxyUrl;
        }
        openingProxySession = browserSession;
        await this.tunnelProxy.attach(browserSession, openingEndpoint, proxyConfig);
      } else if (vaultOpen) {
        await browserSession.setProxy(
          target.proxyUrl
            ? {
                mode: 'fixed_servers',
                proxyRules: target.proxyUrl,
                proxyBypassRules: '<-loopback>',
              }
            : { mode: 'direct' },
        );
      }
      if (routedOrigin) {
        const routedUrl = target.url;
        browserSession.webRequest.onBeforeRequest((details, callback) => {
          const navigationUrl =
            details.resourceType === 'mainFrame'
              ? getInSessionNavigationUrl(details.url, routedUrl, logicalTargetUrl)
              : undefined;
          if (
            navigationUrl &&
            navigationUrl !== details.url &&
            isAllowedWebNavigation(navigationUrl)
          ) {
            // Redirect the native request so a popup keeps its guest, opener and POST body.
            callback({ redirectURL: navigationUrl });
            return;
          }
          callback({
            cancel: !isWebBrowserRouteRequestAllowed(details.url, routedOrigin),
          });
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
      if (openingLeaseId && !this.tunnelLeases.isActive(request.sessionId, openingLeaseId)) {
        throw new Error(
          'The VPN connection stopped while preparing this browser. Reconnect to continue.',
        );
      }

      if (prepared && !prepared.active()) throw Error('Vault web connection is unavailable.');
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
      const tabs = new WebBrowserTabs<WebContentsView>();
      const initialTabId = randomUUID();
      tabs.add(initialTabId, view, logicalTargetUrl);
      const record: WebSurfaceRecord = {
        sessionId: request.sessionId,
        owner,
        get view() {
          return tabs.get()!;
        },
        tabs,
        displayedTabId: initialTabId,
        target,
        partition,
        route: resolvedTunnelRoute === 'direct' ? 'direct' : 'vpn',
        tunnel,
        vpn: openingEndpoint
          ? {
              configId: target.tunnelConfigId!,
              endpoint: openingEndpoint,
              session: browserSession,
              status: 'active',
            }
          : undefined,
        attempt: request.attempt,
        disposed: false,
        navigation: {
          navigateUrl: target.url,
          originalUrl: resolvedTunnelRoute === 'forwarder' ? logicalTargetUrl : undefined,
        },
        tunnelLeaseId: openingLeaseId,
        bitwardenUseRelease,
        bitwarden: target.bitwarden,
      };
      this.surfaces.set(request.sessionId, record);
      openingRecord = record;
      openingEndpoint = undefined;
      bitwardenUseRelease = undefined;
      this.pendingOpenOwners.delete(request.sessionId);
      owner.contentView.addChildView(view);
      view.setVisible(false);
      if (prepared?.archive && openingVaultOwner) {
        const checkpoint = new VaultWebCookieCheckpoint({
          url: target.url,
          store: prepared.archive,
          jar: browserSession.cookies,
          views: () => tabs.all().map((tab) => tab.webContents),
          authorized: prepared.active,
        });
        openingVaultOwner.cookies = checkpoint;
        await checkpoint.restore(view.webContents);
        if (!prepared.active() || this.surfaces.get(request.sessionId) !== record)
          throw Error('Vault web connection is unavailable.');
      }
      this.configureWebContents(request.sessionId, record, tabs.activeId, view);
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
        if (isAbortedWebNavigation(error)) return;
        this.failBrowserTab(
          request.sessionId,
          record,
          initialTabId,
          describeWebNavigationError(error),
        );
      });
      target.browser = this.browserState(record);
      this.sendEvent(request.sessionId, record, 'connected');
      openingLeaseId = undefined;
      if (vaultOpen) {
        const { proxyUrl: _proxy, ...publicTarget } = target;
        return publicTarget;
      }
      return target;
    } catch (error) {
      if (openingEndpoint) {
        if (openingProxySession) this.detachTunnelProxy(openingProxySession, openingEndpoint);
        else await openingEndpoint.close();
      }
      bitwardenUseRelease?.();
      if (openingRecord && this.surfaces.get(request.sessionId) === openingRecord) {
        this.dispose(request.sessionId);
      }
      if (
        openingVaultOwner &&
        this.vaultSessionOwners.get(request.sessionId) === openingVaultOwner
      ) {
        await this.releaseTunnel(request.sessionId).catch(() => undefined);
      }
      if (openingLeaseId && this.tunnelLeases.isActive(request.sessionId, openingLeaseId)) {
        await this.releaseTunnel(request.sessionId).catch(() => undefined);
      }
      if (
        this.attempts.isCurrent(request.sessionId, generation) &&
        this.pendingOpenOwners.get(request.sessionId) === owner
      ) {
        this.pendingOpenOwners.delete(request.sessionId);
      }
      throw vaultOpen ? Error('Vault web connection could not be opened.') : error;
    }
  }

  async setBounds(owner: BrowserWindow, request: WebBoundsRequest): Promise<string | undefined> {
    const record = this.surfaces.get(request.sessionId);
    if (!record || record.owner !== owner || record.disposed) return;
    if (request.previewId && !request.capturePreview) {
      const preview = record.preview;
      if (
        !preview ||
        preview.id !== request.previewId ||
        preview.tabId !== record.tabs.activeId ||
        !isAuthorizationEpochCurrent(preview.authorizationEpoch)
      )
        return;
      // The renderer acknowledges only after decoding and painting this exact preview.
      record.bounds = { ...request, capturePreview: true };
      for (const view of record.tabs.all()) if (view.getVisible()) view.setVisible(false);
      return;
    }
    record.bounds = request;
    if (request.capturePreview) {
      const authorizationEpoch = authSession.authorizationEpoch;
      if (!isAuthorizationEpochCurrent(authorizationEpoch)) return;
      const tabId = record.tabs.activeId;
      if (
        record.preview?.tabId !== tabId ||
        record.preview.id !== request.previewId ||
        record.preview.authorizationEpoch !== authorizationEpoch
      ) {
        // A dialog can release preview suppression before its overlay has cleared.
        // A hidden Chromium view cannot supply a fresh frame for that handoff.
        if (!record.view.getVisible()) {
          record.preview = undefined;
          return;
        }
        record.preview = {
          id: request.previewId!,
          tabId,
          authorizationEpoch,
          image: this.capturePreview(record.view),
        };
      }
      const preview = record.preview;
      const image = await preview.image;
      if (
        record.disposed ||
        record.owner.isDestroyed() ||
        record.preview !== preview ||
        !isAuthorizationEpochCurrent(authorizationEpoch)
      )
        return;
      // Keep Chromium visible until its renderer replacement is painted. A failed capture
      // must still leave the menu accessible, without waiting for an acknowledgement.
      if (!image) for (const view of record.tabs.all()) view.setVisible(false);
      return image;
    }
    record.preview = undefined;
    const x = Math.round(request.x);
    const y = Math.round(request.y);
    const bounds = {
      x,
      y,
      width: Math.max(1, Math.round(request.x + request.width) - x),
      height: Math.max(1, Math.round(request.y + request.height) - y),
    };
    const previous = record.view.getBounds();
    if (
      previous.x !== bounds.x ||
      previous.y !== bounds.y ||
      previous.width !== bounds.width ||
      previous.height !== bounds.height
    ) {
      record.view.setBounds(bounds);
    }
    for (const view of record.tabs.all()) {
      const visible = view === record.view && request.visible;
      if (view.getVisible() !== visible) view.setVisible(visible);
    }
    if (request.visible && record.bitwardenTabRegistered && record.bitwarden) {
      this.activeBitwardenSessions.set(record.bitwarden.partition, request.sessionId);
      this.chromeExtensionApis.get(record.bitwarden.partition)?.selectTab(record.view.webContents);
    }
  }

  private async capturePreview(view: WebContentsView): Promise<string | undefined> {
    let timeout: ReturnType<typeof setTimeout> | undefined;
    try {
      const bounds = view.getBounds();
      const image = await Promise.race([
        view.webContents.capturePage(
          {
            x: 0,
            y: 0,
            width: Math.min(bounds.width, 4096),
            height: Math.min(bounds.height, 4096),
          },
          { stayHidden: true },
        ),
        new Promise<undefined>((resolve) => {
          // A stalled compositor must not keep the native page above a renderer dialog.
          timeout = setTimeout(() => resolve(undefined), 250);
        }),
      ]);
      if (!image || image.isEmpty()) return;
      const size = image.getSize();
      const scale = Math.min(1, 2048 / Math.max(size.width, size.height));
      const bounded =
        scale < 1 ? image.resize({ width: Math.max(1, Math.round(size.width * scale)) }) : image;
      const bytes = bounded.toJPEG(90);
      if (bytes.length > 4 * 1024 * 1024) return;
      return `data:image/jpeg;base64,${bytes.toString('base64')}`;
    } catch {
      // Closing or crashing a tab during capture must not leave a native view over the menu.
      return;
    } finally {
      clearTimeout(timeout);
    }
  }

  async command(owner: BrowserWindow, request: WebCommandRequest): Promise<boolean> {
    if (!authSession.isAccessAllowed) return false;
    const record = this.surfaces.get(request.sessionId);
    if (!record || record.owner !== owner || record.disposed) return false;
    if (request.operation === 'reconnect-vpn') return this.reconnectTunnel(record);
    const sourceTabId = record.tabs.activeId;
    if (this.bitwardenPopups.has(request.sessionId)) {
      const authorizationEpoch = authSession.authorizationEpoch;
      const isCurrent = () =>
        this.surfaces.get(request.sessionId) === record &&
        !record.disposed &&
        record.tabs.activeId === sourceTabId &&
        isAuthorizationEpochCurrent(authorizationEpoch);
      await afterBitwardenPopupInputEvent(async () => {
        if (isCurrent()) await this.closeBitwardenPopup(request.sessionId);
      });
      if (!isCurrent()) return false;
    }
    if (
      record.vpn &&
      record.vpn.status !== 'active' &&
      ['navigate', 'back', 'forward', 'reload'].includes(request.operation)
    ) {
      throw new Error('Reconnect the VPN to navigate.');
    }
    const contents = record.view.webContents;
    if (request.operation === 'new-tab') {
      this.addBrowserTab(request.sessionId, record, 'about:blank');
    } else if (request.operation === 'select-tab') {
      if (record.tabs.select(request.tabId!)) this.showBrowserTab(record);
    } else if (request.operation === 'close-tab') {
      const view = record.tabs.remove(request.tabId!);
      if (view) {
        this.destroyBrowserTab(record, view);
        this.showBrowserTab(record);
      }
    } else if (request.operation === 'navigate') {
      const url = resolveWebBrowserAddress(request.url!);
      const navigationUrl = url && this.browserNavigationUrl(record, url);
      if (!navigationUrl)
        throw new Error('Enter an HTTP or HTTPS address allowed by this browser’s VPN route.');
      const tabId = record.tabs.activeId;
      record.tabs.update(tabId, { error: undefined, url: url!, isLoading: true });
      void contents.loadURL(navigationUrl).catch((error: unknown) => {
        if (isAbortedWebNavigation(error)) return;
        this.failBrowserTab(request.sessionId, record, tabId, describeWebNavigationError(error));
      });
    } else if (request.operation === 'back') {
      if (contents.navigationHistory.canGoBack()) contents.navigationHistory.goBack();
    } else if (request.operation === 'forward') {
      if (contents.navigationHistory.canGoForward()) contents.navigationHistory.goForward();
    } else if (request.operation === 'stop') {
      contents.stop();
    } else if (request.operation === 'zoom-in' || request.operation === 'zoom-out') {
      adjustWebZoom(contents, request.operation);
    } else {
      record.tabs.update(record.tabs.activeId, { error: undefined });
      contents.reload();
    }
    this.sendEvent(request.sessionId, record, 'navigation');
    return true;
  }

  private browserNavigationUrl(record: WebSurfaceRecord, url: string): string | undefined {
    if (url === 'about:blank') return url;
    if (record.vpn && record.vpn.status !== 'active') return;
    const navigationUrl = getInSessionNavigationUrl(
      url,
      record.navigation.originalUrl ? record.navigation.navigateUrl : undefined,
      record.navigation.originalUrl,
    );
    return navigationUrl && isAllowedWebNavigation(navigationUrl) ? navigationUrl : undefined;
  }

  private addBrowserTab(
    sessionId: string,
    record: WebSurfaceRecord,
    url: string,
    windowOptions?: WebBrowserWindowOptions,
    loadOptions?: Electron.LoadURLOptions,
  ): WebContentsView {
    if (record.disposed || !authSession.isAccessAllowed || record.tabs.size >= webBrowserTabLimit) {
      throw new Error('This browser cannot open another tab.');
    }
    const navigationUrl = this.browserNavigationUrl(record, url);
    if (!navigationUrl)
      throw new Error('This address cannot be opened through the selected route.');
    const view = new WebContentsView({
      // window.open supplies its Chromium guest. Adopting it preserves window.opener,
      // POST targets and the synchronous reply expected by the opening page.
      ...(windowOptions?.webContents ? { webContents: windowOptions.webContents } : {}),
      webPreferences: {
        ...windowOptions?.webPreferences,
        partition: record.partition,
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
        webSecurity: true,
        allowRunningInsecureContent: false,
        devTools: false,
        preload: undefined,
      },
    });
    const tabId = randomUUID();
    const previousTabId = record.tabs.activeId;
    record.tabs.add(tabId, view, url);
    try {
      record.owner.contentView.addChildView(view);
      view.setVisible(false);
      this.configureWebContents(sessionId, record, tabId, view);
      if (record.bitwarden) {
        view.webContents.setMaxListeners(bitwardenExtensionHostMaxListeners);
        this.chromeExtensionApis
          .get(record.bitwarden.partition)
          ?.addTab(view.webContents, record.owner);
      }
      this.showBrowserTab(record);
    } catch (error) {
      record.tabs.remove(tabId);
      record.tabs.select(previousTabId);
      this.destroyBrowserTab(record, view);
      if (!record.owner.isDestroyed()) this.showBrowserTab(record);
      throw error;
    }
    this.sendEvent(sessionId, record, 'navigation');
    if (!windowOptions?.webContents) {
      void view.webContents.loadURL(navigationUrl, loadOptions).catch((error: unknown) => {
        if (isAbortedWebNavigation(error)) return;
        this.failBrowserTab(sessionId, record, tabId, describeWebNavigationError(error));
      });
    }
    return view;
  }

  private showBrowserTab(record: WebSurfaceRecord): void {
    if (record.displayedTabId !== record.tabs.activeId) {
      record.displayedTabId = record.tabs.activeId;
      if (this.bitwardenPopupRequest?.sessionId === record.sessionId) {
        this.bitwardenPopupRequest = undefined;
      }
      const popup = this.bitwardenPopups.get(record.sessionId);
      if (popup) {
        try {
          popup.setVisible(false);
        } catch {
          /* The extension already closed it. */
        }
        void afterBitwardenPopupInputEvent(async () => {
          if (this.bitwardenPopups.get(record.sessionId) === popup) {
            await this.closeBitwardenPopup(record.sessionId);
          }
        }).catch(() => {
          reportWarning('Could not dismiss the previous browser tab’s Bitwarden popup.');
        });
      }
    }
    if (record.bounds) this.setBounds(record.owner, record.bounds);
    else for (const view of record.tabs.all()) view.setVisible(false);
  }

  private closeVaultContents(contents: Electron.WebContents): Promise<void> {
    if (contents.isDestroyed()) return Promise.resolve();
    return new Promise<void>((resolve, reject) => {
      const finish = (failed = false) => {
        clearTimeout(timer);
        contents.off('destroyed', destroyed);
        if (failed) reject(Error('Web surface shutdown could not be confirmed.'));
        else resolve();
      };
      const destroyed = () => finish();
      const timer = setTimeout(() => finish(!contents.isDestroyed()), 5000);
      timer.unref();
      contents.once('destroyed', destroyed);
      try {
        contents.close({ waitForBeforeUnload: false });
      } catch {
        finish(true);
      }
    });
  }

  private destroyBrowserTab(record: WebSurfaceRecord, view: WebContentsView): void {
    const contents = view.webContents;
    if (record.bitwarden && contents) {
      try {
        this.chromeExtensionApis.get(record.bitwarden.partition)?.removeTab(contents);
      } catch {
        /* Already removed. */
      }
    }
    try {
      record.owner.contentView.removeChildView(view);
    } catch {
      /* Owner is closing. */
    }
    if (!contents) return;
    const token = this.vaultSessionOwners.get(record.sessionId);
    if (token) {
      const closed = this.closeVaultView(token, view.webContents);
      void closed.catch(() => undefined);
    } else if (!view.webContents.isDestroyed()) view.webContents.close();
  }

  private closeVaultView(
    token: VaultWebSurfaceOwner,
    contents: Electron.WebContents,
  ): Promise<void> {
    const views = (token.views ??= new Map());
    const previous = views.get(contents);
    if (previous) return previous;
    const closed = this.closeVaultContents(contents).then(
      () => {
        views.delete(contents);
      },
      () => {
        views.set(contents, undefined);
        throw Error('Web surface shutdown could not be confirmed.');
      },
    );
    views.set(contents, closed);
    return closed;
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
    const pageContents = record.view.webContents;
    if (this.bitwardenPopups.has(sessionId)) {
      return { open: true };
    }
    const openRequest = { sessionId };
    this.bitwardenPopupRequest = openRequest;
    // Only one Bitwarden popup at a time: a popup on another tab would otherwise float over the
    // window independently of the tab that owns it.
    for (const otherSessionId of [...this.bitwardenPopups.keys()]) {
      if (otherSessionId !== sessionId) await this.closeBitwardenPopup(otherSessionId);
    }
    // Closing another popup can wait on storage. A newer click, a disconnected tab, or a lock
    // must win before this request allocates and attaches a native view.
    if (
      this.bitwardenPopupRequest !== openRequest ||
      this.surfaces.get(sessionId) !== record ||
      record.view.webContents !== pageContents ||
      record.disposed ||
      record.owner.isDestroyed() ||
      !isAuthorizationEpochCurrent(authorizationEpoch) ||
      mcpApprovalWindowCoordinator.hasPendingApprovals
    ) {
      return { open: false };
    }

    const { partition, popupUrl } = record.bitwarden;
    const popup = new WebContentsView({
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
    popup.webContents.setMaxListeners(bitwardenExtensionHostMaxListeners);
    this.activeBitwardenSessions.set(partition, sessionId);
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
        reportWarning('Could not dismiss the Bitwarden browser popup.', error);
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
    pageContents.on('before-mouse-event', onPageMouse);
    popup.webContents.once('destroyed', () => {
      // Bitwarden can close its own popup after completing an extension action. Route that path
      // through the ordinary cleanup so the background page gets a final storage flush and the
      // renderer does not keep reporting a destroyed popup as open.
      if (this.bitwardenPopups.get(sessionId) !== popup) return;
      void this.closeBitwardenPopup(sessionId).catch((error) => {
        reportWarning('Could not clean up the closed Bitwarden browser popup.', error);
      });
    });
    record.owner.contentView.addChildView(popup);
    popup.setVisible(false);
    this.bitwardenPopups.set(sessionId, popup);
    this.bitwardenPopupDismissHandlers.set(sessionId, {
      owner: record.owner,
      pageContents,
      ownerBlur: dismiss,
      ownerMouse: onOwnerMouse,
      pageMouse: onPageMouse,
    });
    let stage: BitwardenBrowserStage = 'prepare';
    try {
      // The MV2 vault session lives in background memory. Restore it before the popup initializes
      // its account services so an older profile cannot initialize the UI as logged out.
      await prepareBitwardenPopupStorage(
        async () => {
          await this.synchronizeBitwardenStorageInBridge(record.owner, partition, popupUrl);
        },
        (error) => {
          if (!(error instanceof BitwardenStorageCheckpointError)) return false;
          const background = this.bitwardenBackgroundContents(
            partition,
            new URL(popupUrl).hostname,
          );
          return !!background && this.initializedBitwardenStorage.has(background);
        },
      );
      if (this.bitwardenPopups.get(sessionId) !== popup || record.disposed) {
        return { open: false };
      }
      if (record.view.webContents !== pageContents || this.bitwardenPopupRequest !== openRequest) {
        await this.closeBitwardenPopup(sessionId, false);
        return { open: false };
      }
      stage = 'popup';
      await withBitwardenBrowserTimeout(
        popup.webContents.loadURL(popupUrl),
        bitwardenBrowserNavigationTimeoutMs,
        'Bitwarden browser popup navigation timed out.',
      );
      if (this.bitwardenPopups.get(sessionId) !== popup || record.disposed) {
        return { open: false };
      }
      if (
        mcpApprovalWindowCoordinator.hasPendingApprovals ||
        record.view.webContents !== pageContents ||
        this.bitwardenPopupRequest !== openRequest ||
        !isAuthorizationEpochCurrent(authorizationEpoch)
      ) {
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
      if (this.bitwardenPopups.get(sessionId) !== popup || record.disposed) {
        return { open: false };
      }
      if (record.view.webContents !== pageContents || this.bitwardenPopupRequest !== openRequest) {
        await this.closeBitwardenPopup(sessionId, false);
        return { open: false };
      }
      const failure = this.reportBitwardenBrowserFailure(error, stage);
      // This hidden popup never accepted user edits. Retrying the failed synchronization while
      // closing it delays feedback and can initialize another extension page unnecessarily.
      await this.closeBitwardenPopup(sessionId, false);
      if (
        !record.disposed &&
        record.view.webContents === pageContents &&
        !record.owner.isDestroyed() &&
        isAuthorizationEpochCurrent(authorizationEpoch) &&
        !mcpApprovalWindowCoordinator.hasPendingApprovals
      ) {
        // Keep extension/backend diagnostics out of the dialog: they may contain vault data.
        await showCoordinatedMessageBox(record.owner, {
          type: 'error',
          title: 'Bitwarden',
          message: 'Could not open Bitwarden.',
          detail: `The browser session could not be prepared. Please try again or reconnect the HTTPS session.\n\nDiagnostic code: ${failure.code}`,
          buttons: ['OK'],
        }).catch(() => undefined);
      }
      return { open: false };
    }
    return { open: true };
  }

  private reportBitwardenBrowserFailure(
    error: unknown,
    stage: BitwardenBrowserStage,
  ): BitwardenBrowserFailure {
    const failure = describeBitwardenBrowserFailure(error, stage);
    void runBitwardenBackend('bitwarden.browser-failure', { value: failure.code }, 5_000).catch(
      () => recordDiagnostic('ERR', 'Bitwarden browser operation failed', { code: failure.code }),
    );
    return failure;
  }

  async closeBitwardenPopup(sessionId: string, flushStorage = true): Promise<{ open: false }> {
    if (this.bitwardenPopupRequest?.sessionId === sessionId) {
      this.bitwardenPopupRequest = undefined;
    }
    const popup = this.bitwardenPopups.get(sessionId);
    const record = this.surfaces.get(sessionId);
    const owner = record?.owner;
    const bitwarden = record?.bitwarden;
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
    if (!flushStorage) {
      closeBitwardenPopupContents(popup);
      return { open: false };
    }
    let flushedFromPopup = false;
    if (popup && bitwarden && owner && !owner.isDestroyed()) {
      try {
        flushedFromPopup = await flushAndCloseBitwardenPopupContents(popup, async (contents) => {
          await this.synchronizeBitwardenStorageInContents(bitwarden.partition, contents);
        });
      } catch (error) {
        reportWarning('Could not flush Bitwarden browser storage from its popup.', error);
      }
    } else if (popup) {
      closeBitwardenPopupContents(popup);
    }
    if (!flushedFromPopup && popup && bitwarden && owner && !owner.isDestroyed()) {
      try {
        // Bitwarden can close its own extension page after an autofill. In that case the persistent
        // background page (or a temporary bridge) is the only remaining storage context.
        await this.synchronizeBitwardenStorageInBridge(
          owner,
          bitwarden.partition,
          bitwarden.popupUrl,
        );
      } catch (error) {
        reportWarning('Could not flush Bitwarden browser storage when its popup closed.', error);
      }
    }
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
    options: BitwardenStorageSyncOptions = {},
  ): Promise<boolean> {
    let stage: BitwardenBrowserStage = 'profile';
    return this.serializeBitwardenStorage(async () => {
      if (contents.isDestroyed()) return false;
      const profilePath = electronSession.fromPartition(partition).storagePath;
      if (!profilePath)
        throw new Error('Bitwarden browser profile has no persistent storage path.');
      // A temporary popup bridge may be the first context after background teardown, too.
      const initialize = !this.initializedBitwardenStorage.has(contents);
      if (initialize) {
        if (contents.getType() === 'backgroundPage') {
          stage = 'background';
          await waitForBitwardenBackgroundStorage(contents);
        }
        stage = 'migrations';
        await prepareBitwardenStorageMigrations(contents);
      }
      await synchronizeBitwardenStorage(
        {
          read: async () => {
            stage = 'read';
            return validateBitwardenBrowserStorageSnapshot(
              await runBitwardenBackend<BitwardenBrowserStorageSnapshot>(
                'bitwarden.browser-storage-read',
                { profilePath },
              ),
            );
          },
          capture: () => {
            stage = 'capture';
            return captureBitwardenExtensionStorage(contents);
          },
          restore: async (snapshot, expected) => {
            stage = 'restore';
            await restoreBitwardenExtensionStorage(contents, snapshot, expected);
            // An extension update can restore a snapshot from the previous storage schema.
            if (initialize) {
              stage = 'migrations';
              await prepareBitwardenStorageMigrations(contents, true);
            }
          },
          hydrated: () => this.initializedBitwardenStorage.add(contents),
          markRevision: (revision) => {
            stage = 'marker';
            return markBitwardenStorageRevision(contents, revision);
          },
          commit: async (captured, sourceRevision) => {
            stage = 'commit';
            return validateBitwardenBrowserStorageSnapshot(
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
          },
          flush: async () => {
            stage = 'flush';
            const browserSession = electronSession.fromPartition(partition);
            browserSession.flushStorageData();
            await browserSession.cookies.flushStore();
          },
        },
        initialize,
        options,
      );
      return true;
    }).catch((error: unknown) => {
      // Neither renderer exceptions nor backend diagnostics may expose extension secrets.
      if (error instanceof BitwardenStorageCheckpointError) throw error;
      throw describeBitwardenBrowserFailure(error, stage);
    });
  }

  private bitwardenBackgroundContents(
    partition: string,
    extensionId: string,
  ): Electron.WebContents | undefined {
    const browserSession = electronSession.fromPartition(partition);
    return electronWebContents.getAllWebContents().find((contents) => {
      if (
        contents.isDestroyed() ||
        contents.session !== browserSession ||
        contents.getType() !== 'backgroundPage'
      )
        return false;
      try {
        const url = new URL(contents.getURL());
        return url.protocol === 'chrome-extension:' && url.hostname === extensionId;
      } catch {
        return false;
      }
    });
  }

  private startBitwardenStorageCheckpoints(): void {
    this.bitwardenCheckpointTimer ??= setInterval(() => {
      if (isQuitting || !authSession.isAccessAllowed || this.bitwardenStoragePaused) return;
      for (const [partition, extensionId] of this.extensionIds) {
        if (this.extensionLoads.has(partition) || this.retiringBitwardenProfiles.has(partition))
          continue;
        if (this.isBitwardenProfileUnused(partition)) {
          void this.retireBitwardenProfile(partition).catch(() => {
            // Preserve the live background on save failures and retry next tick.
          });
          continue;
        }
        const contents = this.bitwardenBackgroundContents(partition, extensionId);
        if (!contents) continue;
        let checkpoint = this.bitwardenCheckpoints.get(contents);
        if (!checkpoint) {
          checkpoint = new BitwardenStorageCheckpoint();
          this.bitwardenCheckpoints.set(contents, checkpoint);
        }
        if (checkpoint.isPending) continue;
        void this.bitwardenStorageTasks
          .run(partition, () =>
            checkpoint.run(
              () => readBitwardenStorageRevision(contents),
              async () => {
                if (!(await this.synchronizeBitwardenStorageCore(partition, contents))) {
                  throw new Error('Bitwarden background page closed before checkpoint.');
                }
              },
            ),
          )
          .catch(() => {
            // Keep the revision dirty and retry on the next tick. Lifecycle flushes report errors.
            // Renderer errors may contain extension data and must not be written to diagnostics.
          });
      }
    }, 1_000);
    this.bitwardenCheckpointTimer.unref();
  }

  private async synchronizeBitwardenStorageInBridge(
    owner: BrowserWindow,
    partition: string,
    popupUrl: string,
  ): Promise<void> {
    await this.bitwardenStorageTasks.run(partition, async () => {
      const extensionId = new URL(popupUrl).hostname;
      const backgroundContents = this.bitwardenBackgroundContents(partition, extensionId);
      if (backgroundContents) {
        try {
          await waitForBitwardenBackgroundStorage(backgroundContents);
          if (await this.synchronizeBitwardenStorageCore(partition, backgroundContents)) return;
        } catch (error) {
          if (!backgroundContents.isDestroyed()) {
            if (error instanceof BitwardenStorageCheckpointError) throw error;
            throw describeBitwardenBrowserFailure(error, 'background');
          }
          // The MV2 background page can disappear while waiting behind another profile's storage
          // transaction. Continue with a fresh extension page in the same persistent partition.
        }
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
      try {
        owner.contentView.addChildView(bridge);
        bridge.setBounds({ x: 0, y: 0, width: 1, height: 1 });
        bridge.setVisible(false);
        await withBitwardenBrowserTimeout(
          bridge.webContents.loadURL(popupUrl),
          bitwardenBrowserNavigationTimeoutMs,
          'Bitwarden browser storage page navigation timed out.',
        );
        if (!(await this.synchronizeBitwardenStorageCore(partition, bridge.webContents))) {
          throw new Error('Bitwarden browser storage page closed before synchronization.');
        }
      } catch (error) {
        if (error instanceof BitwardenStorageCheckpointError) throw error;
        throw describeBitwardenBrowserFailure(error, 'bridge');
      } finally {
        try {
          owner.contentView.removeChildView(bridge);
        } catch {
          // The owner can already be closing.
        }
        closeBitwardenPopupContents(bridge);
      }
    });
  }

  private synchronizeBitwardenStorageInContents(
    partition: string,
    contents: Electron.WebContents,
  ): Promise<void> {
    return this.bitwardenStorageTasks.run(partition, async () => {
      const extensionId = this.extensionIds.get(partition);
      const background = extensionId
        ? this.bitwardenBackgroundContents(partition, extensionId)
        : undefined;
      if (!(await this.synchronizeBitwardenStorageCore(partition, background ?? contents))) {
        throw new Error('Bitwarden browser popup closed before storage synchronization.');
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
      createTab: async (details) => this.openExtensionTabInSession(partition, details),
      selectTab: (contents) => {
        for (const [sessionId, record] of this.surfaces) {
          const tab = record.tabs
            .snapshot(record.route)
            .tabs.find((candidate) => record.tabs.get(candidate.id)?.webContents === contents);
          if (!tab || record.disposed) continue;
          record.tabs.select(tab.id);
          this.showBrowserTab(record);
          this.sendEvent(sessionId, record, 'navigation');
          break;
        }
      },
      removeTab: (contents) => {
        for (const [sessionId, record] of this.surfaces) {
          const tab = record.tabs
            .snapshot(record.route)
            .tabs.find((candidate) => record.tabs.get(candidate.id)?.webContents === contents);
          if (!tab || record.disposed) continue;
          if (record.tabs.size === 1) this.addBrowserTab(sessionId, record, 'about:blank');
          const view = record.tabs.remove(tab.id);
          if (view) this.destroyBrowserTab(record, view);
          this.showBrowserTab(record);
          this.sendEvent(sessionId, record, 'navigation');
          break;
        }
      },
      createWindow: async (details) =>
        this.openExtensionWindow(partition, instance, details as ExtensionWindowCreateDetails),
      assignTabDetails: (details, contents) => {
        const record = [...this.surfaces.values()].find(
          (candidate) =>
            !candidate.disposed &&
            candidate.bitwarden?.partition === partition &&
            candidate.tabs.all().some((view) => view.webContents === contents),
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
    const view = this.addBrowserTab(selectedSessionId, record, navigationUrl);
    this.activeBitwardenSessions.set(partition, selectedSessionId);
    return [view.webContents, record.owner];
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

    const extensionWindow = createApplicationWindow({
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
          reportWarning(
            'Could not flush Bitwarden browser storage after its auxiliary window closed.',
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
          const background = this.bitwardenBackgroundContents(partition, previousId);
          if (background) {
            try {
              await this.synchronizeBitwardenStorageCore(partition, background);
            } catch {
              reportWarning('Bitwarden update deferred until its session can be saved.');
              return;
            }
          }
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
            reportWarning('Bitwarden browser profile state could not be seeded.', error);
          }
        }
        // Initialize the chrome.* API bridge before Electron starts Bitwarden's persistent MV2
        // background page. Loading without this bridge produces a popup that looks healthy but
        // cannot communicate with the vault background context.
        await this.ensureChromeExtensionApis(partition);
        const extension = await loadBitwardenExtensionWhenReady(browserSession, extensionPath);
        this.extensionIds.set(partition, extension.id);
        this.extensionLoadKeys.set(partition, installKey);
        // Hydrate each background before its first user-visible tab or popup can edit storage.
        // A failed save stays retryable; do not discard the loaded extension or its live state.
        const background = this.bitwardenBackgroundContents(partition, extension.id);
        if (background) {
          try {
            await this.synchronizeBitwardenStorageCore(partition, background);
          } catch {
            reportWarning('Bitwarden browser storage initialization will be retried.');
          }
        }
        this.startBitwardenStorageCheckpoints();
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
            reportWarning('Bitwarden browser profile could not be registered.', error);
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
        reportWarning('Bitwarden browser extension could not be loaded for this HTTPS tab.', error);
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
      async () => {
        this.bitwardenStoragePaused = true;
        try {
          await this.bitwardenStorageTasks.waitForAllIdle();
          await this.unloadBitwardenExtensionsForUpdate();
        } catch (error) {
          this.bitwardenStoragePaused = false;
          throw error;
        }
      },
      async () => {
        try {
          return await operation();
        } finally {
          this.bitwardenStoragePaused = false;
        }
      },
    );
  }

  private async flushBitwardenBackgroundStorage(): Promise<void> {
    const pending: { contents: Electron.WebContents; save: Promise<boolean> }[] = [];
    for (const [partition, extensionId] of this.extensionIds) {
      const contents = this.bitwardenBackgroundContents(partition, extensionId);
      if (contents)
        pending.push({
          contents,
          save: this.synchronizeBitwardenStorageCore(partition, contents),
        });
    }
    const results = await Promise.allSettled(pending.map(({ save }) => save));
    const failed = results.find(
      (result, index) =>
        result.status === 'rejected' || (!result.value && !pending[index].contents.isDestroyed()),
    );
    if (failed) {
      const failure = this.reportBitwardenBrowserFailure(
        failed.status === 'rejected'
          ? failed.reason
          : new Error('Bitwarden browser storage page closed before saving.'),
        'checkpoint',
      );
      throw new Error(
        `Bitwarden browser storage could not be saved for every profile. Diagnostic code: ${failure.code}`,
      );
    }
  }

  private async unloadBitwardenExtensionsForUpdate(): Promise<void> {
    try {
      const loaded = [...this.extensionIds];
      if (loaded.some(([partition]) => !this.isBitwardenProfileUnused(partition))) {
        throw new Error('Bitwarden browser profiles are still in use.');
      }
      for (const [partition, extensionId] of loaded) {
        if (this.extensionIds.get(partition) !== extensionId) continue;
        if (!(await this.checkpointAndUnloadBitwardenProfile(partition, extensionId))) {
          throw new Error('Bitwarden browser profiles are still in use.');
        }
      }
    } catch (error) {
      const failure = this.reportBitwardenBrowserFailure(error, 'checkpoint');
      throw new Error(
        `Bitwarden browser profiles could not be prepared for the update. Diagnostic code: ${failure.code}`,
      );
    }
  }

  private async checkpointAndUnloadBitwardenProfile(
    partition: string,
    extensionId: string,
  ): Promise<boolean> {
    let stage: BitwardenBrowserStage = 'checkpoint';
    try {
      if (!this.isBitwardenProfileUnused(partition)) return false;
      const contents = this.bitwardenBackgroundContents(partition, extensionId);
      const close = (): boolean => {
        stage = 'checkpoint';
        if (!this.isBitwardenProfileUnused(partition)) return false;
        const loadedId = this.extensionIds.get(partition);
        if (!loadedId) return true;
        const current = this.bitwardenBackgroundContents(partition, extensionId);
        if (loadedId !== extensionId || (current && current !== contents)) {
          throw new Error(
            'Bitwarden background page changed during synchronization; retry required.',
          );
        }
        electronSession.fromPartition(partition).extensions.removeExtension(extensionId);
        this.extensionIds.delete(partition);
        this.extensionLoadKeys.delete(partition);
        this.extensionPopupPaths.delete(partition);
        return true;
      };
      if (!contents || contents.isDestroyed()) {
        return close();
      }
      try {
        stage = 'background';
        await waitForBitwardenBackgroundStorage(contents);
        stage = 'checkpoint';
        return await checkpointBitwardenStorageBeforeClose(
          () => readBitwardenStorageRevision(contents),
          async () => {
            if (
              !(await this.synchronizeBitwardenStorageCore(partition, contents, {
                checkpointOnly: true,
              }))
            ) {
              throw new Error('Bitwarden browser storage page closed before saving.');
            }
          },
          close,
        );
      } catch (error) {
        if (!contents.isDestroyed()) throw error;
        // A dead host has no remaining runtime state; never close a replacement host.
        return close();
      }
    } catch (error) {
      if (error instanceof BitwardenStorageCheckpointError) throw error;
      throw describeBitwardenBrowserFailure(error, stage);
    }
  }

  async checkpointBitwardenStorage(): Promise<void> {
    await this.bitwardenStorageTasks.waitForAllIdle();
    await this.flushBitwardenBackgroundStorage();
  }

  close(sessionId: string): void {
    this.attempts.cancel(sessionId);
    this.pendingOpenOwners.delete(sessionId);
    this.dispose(sessionId);
    void this.releaseTunnel(sessionId).catch((error) => {
      reportWarning('Could not release the web VPN tunnel.', error);
    });
  }

  private isBitwardenProfileUnused(partition: string): boolean {
    return (
      this.pendingOpenOwners.size === 0 &&
      !this.extensionLoads.has(partition) &&
      ![...this.surfaces.values()].some(
        (record) => !record.disposed && record.bitwarden?.partition === partition,
      )
    );
  }

  private async retireBitwardenProfile(partition: string): Promise<void> {
    if (this.retiringBitwardenProfiles.has(partition)) return;
    this.retiringBitwardenProfiles.add(partition);
    try {
      await this.bitwardenStorageTasks.waitForIdle(partition);
      if (!this.isBitwardenProfileUnused(partition)) return;
      await this.bitwardenStorageTasks.run(partition, async () => {
        const extensionId = this.extensionIds.get(partition);
        if (!extensionId) return;
        await this.checkpointAndUnloadBitwardenProfile(partition, extensionId);
      });
    } finally {
      this.retiringBitwardenProfiles.delete(partition);
    }
  }

  private dispose(sessionId: string, bitwardenAlreadyFlushed = false): void {
    const record = this.surfaces.get(sessionId);
    if (!record) return;
    record.disposed = true;
    this.vaultSessionOwners.get(sessionId)?.cookies?.stop();
    record.preview = undefined;
    if (record.vpn) this.detachTunnelProxy(record.vpn.session, record.vpn.endpoint);
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
        reportWarning(
          'Could not flush Bitwarden browser storage when its HTTPS tab closed.',
          error,
        );
      });
    }
    record.bitwardenUseRelease?.();
    record.bitwardenUseRelease = undefined;
    if (
      record.bitwarden &&
      this.activeBitwardenSessions.get(record.bitwarden.partition) === sessionId
    ) {
      this.activeBitwardenSessions.delete(record.bitwarden.partition);
    }
    for (const view of record.tabs.all()) this.destroyBrowserTab(record, view);
    if (record.tunnelLeaseId || this.vaultSessionOwners.has(sessionId)) {
      record.tunnelLeaseId = undefined;
      void this.releaseTunnel(sessionId).catch((error) => {
        reportWarning('Could not release the web VPN tunnel.', error);
      });
    }
    if (record.bitwarden) {
      void this.retireBitwardenProfile(record.bitwarden.partition).catch(() => {
        reportWarning('Bitwarden profile remains loaded until its storage can be saved.');
      });
    }
  }

  vaultOwnerForSession(sessionId: string): BrowserWindow | undefined {
    return this.vaultSessionOwners.get(sessionId)?.owner;
  }
  async closeForOwner(owner: BrowserWindow, sessionId: string): Promise<void> {
    const record = this.surfaces.get(sessionId);
    const token = this.vaultSessionOwners.get(sessionId);
    if (
      record?.owner === owner ||
      this.pendingOpenOwners.get(sessionId) === owner ||
      token?.owner === owner
    ) {
      if (token?.cookies) {
        await token.cookies.flush().catch(() => {});
        if (this.vaultSessionOwners.get(sessionId) !== token) return;
      }
      this.close(sessionId);
      await this.releaseTunnel(sessionId);
    }
  }

  async closeForContents(contents: Electron.WebContents, sessionId: string): Promise<void> {
    const token = this.vaultSessionOwners.get(sessionId);
    if (token?.contents === contents) {
      await this.closeForOwner(token.owner, sessionId);
      return;
    }
    const owner = this.pendingOpenOwners.get(sessionId) ?? this.surfaces.get(sessionId)?.owner;
    if (owner && !owner.isDestroyed() && owner.webContents === contents)
      await this.closeForOwner(owner, sessionId);
  }

  private async releaseTunnel(sessionId: string): Promise<void> {
    const token = this.vaultSessionOwners.get(sessionId);
    if (token) {
      token.cookies?.stop();
      token.cleanup ??= Promise.resolve()
        .then(async () => {
          const profile = async () => {
            const views = await Promise.allSettled(
              [...(token.views?.keys() ?? [])].map((contents) =>
                this.closeVaultView(token, contents),
              ),
            );
            if (views.some((result) => result.status === 'rejected'))
              throw Error('Web profile cleanup could not be confirmed.');
            if (token.partition) {
              const browserSession = electronSession.fromPartition(token.partition!);
              const results = await Promise.allSettled([
                browserSession.closeAllConnections(),
                browserSession.clearStorageData(),
                browserSession.clearCache(),
              ]);
              if (results.some((result) => result.status === 'rejected'))
                throw Error('Web profile cleanup could not be confirmed.');
            }
          };
          const results = await Promise.allSettled([
            this.vault!.connections.retireRoute(sessionId),
            profile(),
          ]);
          if (results.some((result) => result.status === 'rejected'))
            throw Error('Web shutdown could not be confirmed.');
          await this.vault!.connections.close(sessionId);
          this.forgetVaultOwner(sessionId, token);
        })
        .finally(() => {
          token.cleanup = undefined;
        });
      await token.cleanup;
    }
    await this.tunnelLeases.release(sessionId, async (leaseId) => {
      const endpoint = this.tunnelEndpoints.get(leaseId);
      await releaseNativeTunnelLease(leaseId, endpoint?.disconnect());
      this.tunnelEndpoints.delete(leaseId);
    });
    if (!this.tunnelLeases.has(sessionId)) this.tunnelLeaseOwners.delete(sessionId);
  }

  private detachTunnelProxy(session: Electron.Session, endpoint: WebTunnelEndpoint): void {
    void this.tunnelProxy.detach(session, endpoint).catch(() => {
      console.warn('[Wormhole] Could not clear the browser VPN proxy.');
    });
  }

  cancelTunnelReconnects(): void {
    for (const record of this.surfaces.values()) {
      if (record.vpn?.status === 'reconnecting') this.disconnectTunnel(record);
    }
  }

  private async webTunnelUpstreamPort(
    backend: NativeBackendProcess,
    leaseId: string,
    target: WebTargetResponse,
    socksEndpoint: string,
  ): Promise<number> {
    if (socksEndpoint) return parseWebTunnelSocksPort(socksEndpoint);
    return (await backend.bindTunnelForwarder(leaseId, target.host, target.port)).port;
  }

  private webTunnelExited(sessionId: string, leaseId: string): void {
    if (!this.tunnelLeases.isActive(sessionId, leaseId)) return;
    const record = this.surfaces.get(sessionId);
    if (record?.tunnelLeaseId !== leaseId) {
      this.close(sessionId);
      return;
    }
    this.disconnectTunnel(record);
  }

  private disconnectTunnel(record: WebSurfaceRecord): void {
    const { sessionId, tunnelLeaseId, vpn } = record;
    record.tunnelLeaseId = undefined;
    if (!vpn || vpn.status === 'disconnected') return;
    const wasActive = vpn.status === 'active';
    vpn.status = 'disconnected';
    if (wasActive) {
      for (const view of record.tabs.all()) {
        const contents = view.webContents;
        if (contents && !contents.isDestroyed() && contents.isLoadingMainFrame()) contents.stop();
      }
    }
    this.sendEvent(sessionId, record, 'vpn-state');
    if (tunnelLeaseId && this.tunnelLeases.isActive(sessionId, tunnelLeaseId))
      void this.releaseTunnel(sessionId).catch(() => undefined);
  }

  private async reconnectTunnel(record: WebSurfaceRecord): Promise<boolean> {
    const { sessionId, owner, vpn } = record;
    if (!vpn || vpn.status !== 'disconnected') return false;
    const authorizationEpoch = authSession.authorizationEpoch;
    // Reserve the attempt's identity before waiting for the previous lease to drain.
    const leaseId = randomUUID();
    record.tunnelLeaseId = leaseId;
    const isCurrent = () =>
      !record.disposed &&
      !owner.isDestroyed() &&
      this.surfaces.get(sessionId) === record &&
      record.tunnelLeaseId === leaseId &&
      isAuthorizationEpochCurrent(authorizationEpoch);
    vpn.status = 'reconnecting';
    this.sendEvent(sessionId, record, 'vpn-state');
    try {
      await this.releaseTunnel(sessionId);
      if (!isCurrent()) return false;
      this.tunnelLeases.claim(sessionId, leaseId);
      this.tunnelLeaseOwners.set(sessionId, owner);
      const backend = getNativeBackend();
      const route = await backend.acquireTunnelRoute({
        onExit: () => this.webTunnelExited(sessionId, leaseId),
        leaseId,
        tunnelConfigId: vpn.configId,
        progressSessionId: sessionId,
      });
      if (!isCurrent()) return false;
      assertTunnelRouteUnchanged(route.configuredTunnelId, vpn.configId);
      const usesForwarder = Boolean(record.navigation.originalUrl);
      const acquiredForwarder = !route.socksEndpoint;
      if (!route.active || acquiredForwarder !== usesForwarder) {
        throw new Error('The VPN returned a different route for this browser.');
      }
      const port = await this.webTunnelUpstreamPort(
        backend,
        leaseId,
        record.target,
        route.socksEndpoint,
      );
      if (!isCurrent()) return false;
      if (!this.tunnelLeases.isActive(sessionId, leaseId)) {
        throw new Error('The VPN connection stopped while reconnecting.');
      }
      this.tunnelEndpoints.set(leaseId, vpn.endpoint);
      await vpn.endpoint.connect(port);
      if (!isCurrent() || !this.tunnelLeases.isActive(sessionId, leaseId)) return false;
      record.tunnel = route.tunnel;
      vpn.status = 'active';
      this.sendEvent(sessionId, record, 'vpn-state');
      return true;
    } finally {
      if (record.tunnelLeaseId === leaseId && vpn.status === 'reconnecting') {
        this.disconnectTunnel(record);
      }
    }
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
      if (!record.disposed) {
        record.preview = undefined;
        if (record.bounds)
          record.bounds = { ...record.bounds, visible: false, capturePreview: false };
        for (const view of record.tabs.all()) view.setVisible(false);
      }
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
    for (const [sessionId, token] of this.vaultSessionOwners) {
      if (token.owner === owner) sessionIds.add(sessionId);
    }
    for (const sessionId of sessionIds) this.close(sessionId);
  }

  async flushAndCloseForWindow(owner: BrowserWindow): Promise<void> {
    const vaultIds = [...this.vaultSessionOwners]
      .filter(([, token]) => token.owner === owner)
      .map(([id]) => id);
    const vaultStopped = await Promise.allSettled(
      vaultIds.map((id) => this.closeForOwner(owner, id)),
    );
    if (vaultStopped.some((result) => result.status === 'rejected'))
      throw Error('Web shutdown could not be confirmed.');
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
    for (const [sessionId, token] of this.vaultSessionOwners) {
      if (token.owner === owner) sessionIds.add(sessionId);
    }
    const popupSessions = new Set(
      [...this.bitwardenPopups.keys()].filter(
        (sessionId) => this.surfaces.get(sessionId)?.owner === owner,
      ),
    );
    for (const sessionId of popupSessions) {
      await this.closeBitwardenPopup(sessionId);
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
        reportWarning('Could not flush Bitwarden browser storage while closing its window.', error);
      }
    }
    // The final tab may already be gone while its persistent background still refreshes tokens.
    // Save those profiles before window teardown shuts down the Go process.
    try {
      await this.checkpointBitwardenStorage();
    } catch {
      reportWarning('Could not save Bitwarden background storage while closing its window.');
    }
    for (const sessionId of sessionIds) {
      this.attempts.cancel(sessionId);
      this.pendingOpenOwners.delete(sessionId);
      this.dispose(sessionId, true);
      await this.releaseTunnel(sessionId).catch(() => undefined);
    }
  }

  async flushAndCloseAll(): Promise<void> {
    await Promise.allSettled(
      [...this.vaultSessionOwners.values()].map((token) => token.cookies?.flush()),
    );
    await this.stopVaultSessions();
    clearInterval(this.bitwardenCheckpointTimer);
    this.bitwardenCheckpointTimer = undefined;
    await this.bitwardenStorageTasks.waitForAllIdle();
    const sessionIds = new Set([
      ...this.surfaces.keys(),
      ...this.pendingOpenOwners.keys(),
      ...this.tunnelLeases.keys(),
      ...this.vaultSessionOwners.keys(),
    ]);
    const popupSessions = new Set(this.bitwardenPopups.keys());
    for (const sessionId of popupSessions) {
      await this.closeBitwardenPopup(sessionId);
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
        reportWarning(
          'Could not flush Bitwarden browser storage during application shutdown.',
          error,
        );
      }
    }
    for (const sessionId of sessionIds) {
      this.attempts.cancel(sessionId);
      this.pendingOpenOwners.delete(sessionId);
      this.dispose(sessionId, true);
      await this.releaseTunnel(sessionId).catch(() => undefined);
    }
    // Background token refreshes can outlive the final HTTPS tab. Flush those profiles too.
    try {
      await this.flushBitwardenBackgroundStorage();
    } catch {
      reportWarning('Could not save Bitwarden background storage during shutdown.');
    }
  }

  async checkpointVaultCookies(): Promise<void> {
    await Promise.allSettled(
      [...this.vaultSessionOwners.values()].map((token) => token.cookies?.checkpointNow()),
    );
  }

  backendStopped(): void {
    for (const endpoint of this.tunnelEndpoints.values()) {
      void endpoint.disconnect().catch(() => undefined);
    }
    this.tunnelEndpoints.clear();
    this.tunnelLeases.clear();
    this.tunnelLeaseOwners.clear();
    for (const [sessionId, record] of this.surfaces) {
      this.disconnectTunnel(record);
      if (record.vpn && (!authSession.isAccessAllowed || isQuitting)) this.dispose(sessionId);
    }
  }

  private configureWebContents(
    sessionId: string,
    record: WebSurfaceRecord,
    tabId: string,
    view: WebContentsView,
  ): void {
    view.setBorderRadius(12); // Match --workspace-canvas-radius in the renderer.
    const contents = view.webContents;
    const cookieCheckpoint = this.vaultSessionOwners.get(sessionId)?.cookies;
    if (cookieCheckpoint) contents.on('did-finish-load', () => cookieCheckpoint.ready());
    let faviconRequest: AbortController | undefined;
    let faviconSource: string | undefined;
    contents.setWebRTCIPHandlingPolicy('disable_non_proxied_udp');
    contents.on('before-input-event', (event, input) => {
      if (
        input.type !== 'keyDown' ||
        !(input.control || input.meta) ||
        !authSession.isAccessAllowed ||
        record.disposed
      )
        return;
      const key = input.key.toLowerCase();
      if (!['t', 'w', 'l', 'tab'].includes(key)) return;
      event.preventDefault();
      if (key === 'l') {
        record.owner.webContents.focus();
        this.sendEvent(sessionId, record, 'focus-address');
        return;
      }
      const operation: WebBrowserCommand =
        key === 't'
          ? { sessionId, operation: 'new-tab' }
          : {
              sessionId,
              operation: key === 'w' ? 'close-tab' : 'select-tab',
              tabId: key === 'w' ? tabId : record.tabs.adjacent(input.shift ? -1 : 1),
            };
      void this.command(record.owner, operation)
        .then((applied) => {
          if (!applied || record.disposed || record.owner.isDestroyed()) return;
          if (key === 't') {
            record.owner.webContents.focus();
            this.sendEvent(sessionId, record, 'focus-address');
          } else record.view.webContents.focus();
        })
        .catch(() => undefined);
    });
    const routeNavigation = (url: string) => this.browserNavigationUrl(record, url);
    contents.setWindowOpenHandler(({ url, referrer, postBody }) => {
      const navigationUrl = routeNavigation(url);
      if (
        !navigationUrl ||
        !authSession.isAccessAllowed ||
        record.disposed ||
        record.tabs.size >= webBrowserTabLimit
      )
        return { action: 'deny' };
      const loadOptions: Electron.LoadURLOptions = {
        httpReferrer: referrer,
        postData: postBody?.data,
        extraHeaders: postBody
          ? `content-type: ${postBody.contentType}${postBody.boundary ? `; boundary=${postBody.boundary}` : ''}`
          : undefined,
      };
      return {
        action: 'allow',
        outlivesOpener: true,
        overrideBrowserWindowOptions: {
          webPreferences: {
            partition: record.partition,
            contextIsolation: true,
            nodeIntegration: false,
            sandbox: true,
            webSecurity: true,
            allowRunningInsecureContent: false,
            devTools: false,
          },
        },
        createWindow: (options) =>
          this.addBrowserTab(sessionId, record, navigationUrl, options, loadOptions).webContents,
      };
    });
    const enforceRoutedNavigation = (event: Electron.Event, url: string) => {
      const navigationUrl = routeNavigation(url);
      if (!navigationUrl || !authSession.isAccessAllowed || record.disposed) {
        event.preventDefault();
        return;
      }
      // The forwarder's request filter rewrites allowed main-frame requests without
      // replacing their Chromium navigation, which would discard POST data and its initiator.
    };
    contents.on('will-navigate', enforceRoutedNavigation);
    contents.on('will-redirect', enforceRoutedNavigation);
    contents.on('context-menu', (_event, params) => {
      const epoch = authSession.authorizationEpoch;
      const isCurrent = () =>
        isAuthorizationEpochCurrent(epoch) &&
        !record.disposed &&
        this.surfaces.get(sessionId) === record &&
        record.tabs.activeId === tabId &&
        !record.owner.isDestroyed() &&
        !contents.isDestroyed();
      if (!isCurrent()) return;
      const click = (action: () => unknown) => () => {
        void Promise.resolve()
          .then(() => {
            if (isCurrent()) return action();
          })
          .catch(() => undefined);
      };
      const navigate = (operation: 'back' | 'forward' | 'reload') =>
        click(() => this.command(record.owner, { sessionId, operation }));
      const template: Electron.MenuItemConstructorOptions[] = [
        { label: 'Back', enabled: contents.navigationHistory.canGoBack(), click: navigate('back') },
        {
          label: 'Forward',
          enabled: contents.navigationHistory.canGoForward(),
          click: navigate('forward'),
        },
        { label: 'Reload', click: navigate('reload') },
      ];
      if (isAllowedWebNavigation(params.linkURL)) {
        const logicalUrl = createBitwardenActiveTabContext(
          record.navigation.navigateUrl,
          record.navigation.originalUrl,
          params.linkURL,
        )!.logicalUrl;
        template.push(
          { type: 'separator' },
          {
            label: 'Open link in new tab',
            enabled: !!routeNavigation(params.linkURL) && record.tabs.size < webBrowserTabLimit,
            click: click(() => this.addBrowserTab(sessionId, record, params.linkURL)),
          },
          {
            label: 'Copy link address',
            click: click(() => {
              void clipboard.writeText(logicalUrl).catch(() => {});
            }),
          },
        );
      }
      const flags = params.editFlags;
      template.push({ type: 'separator' });
      if (params.isEditable) {
        template.push(
          { label: 'Undo', enabled: flags.canUndo, click: click(() => contents.undo()) },
          { label: 'Redo', enabled: flags.canRedo, click: click(() => contents.redo()) },
          { type: 'separator' },
          { label: 'Cut', enabled: flags.canCut, click: click(() => contents.cut()) },
          { label: 'Copy', enabled: flags.canCopy, click: click(() => contents.copy()) },
          { label: 'Paste', enabled: flags.canPaste, click: click(() => contents.paste()) },
        );
      } else if (params.selectionText) {
        template.push({
          label: 'Copy',
          enabled: flags.canCopy,
          click: click(() => contents.copy()),
        });
      }
      template.push({
        label: 'Select all',
        enabled: flags.canSelectAll,
        click: click(() => contents.selectAll()),
      });
      let extensionItems: Electron.MenuItem[] = [];
      try {
        if (record.bitwarden)
          extensionItems =
            this.chromeExtensionApis
              .get(record.bitwarden.partition)
              ?.getContextMenuItems(contents, params) ?? [];
      } catch {
        // Extension teardown must not suppress the browser's own menu.
      }
      if (extensionItems.length) template.push({ type: 'separator' });
      const menu = Menu.buildFromTemplate(template);
      for (const item of extensionItems) menu.append(item);
      menu.popup({ window: record.owner });
    });
    if (record.target.ignoreCertErrors) {
      const origin = new URL(record.navigation.navigateUrl).origin;
      contents.on('certificate-error', (event, url, _error, _certificate, callback) => {
        if (URL.parse(url)?.origin !== origin) return;
        const epoch = authSession.authorizationEpoch;
        const leaseId = record.tunnelLeaseId;
        const canTrust = () =>
          !authLockRequested &&
          !isQuitting &&
          isAuthorizationEpochCurrent(epoch) &&
          !record.disposed &&
          record.tabs.get(tabId) === view &&
          !contents.isDestroyed() &&
          (!record.vpn || (record.vpn.status === 'active' && record.tunnelLeaseId === leaseId));
        if (!canTrust()) return;
        event.preventDefault();
        // Electron emits the same event on app after this listener returns. Resolving it
        // inline can release the native request while Electron still uses its URL.
        setImmediate(() => callback(canTrust()));
      });
    }
    const update = (values: Partial<import('./web-browser-tabs.js').WebBrowserTabState> = {}) => {
      if (record.disposed || record.tabs.get(tabId) !== view || contents.isDestroyed()) return;
      const currentUrl = contents.getURL();
      const context =
        currentUrl && currentUrl !== 'about:blank'
          ? createBitwardenActiveTabContext(
              record.navigation.navigateUrl,
              record.navigation.originalUrl,
              currentUrl,
            )
          : undefined;
      record.tabs.update(tabId, {
        title:
          contents.getTitle() || (contents.getURL() === 'about:blank' ? 'New tab' : 'Loading…'),
        url:
          context?.logicalUrl ||
          currentUrl ||
          record.tabs.snapshot(record.route).tabs.find((tab) => tab.id === tabId)!.url,
        isLoading: contents.isLoading(),
        canGoBack: contents.navigationHistory.canGoBack(),
        canGoForward: contents.navigationHistory.canGoForward(),
        ...values,
      });
      this.sendEvent(sessionId, record, 'navigation');
    };
    contents.on('did-navigate', () => {
      faviconRequest?.abort();
      faviconSource = undefined;
      update({ favicon: undefined });
    });
    contents.on('page-favicon-updated', (_event, favicons: string[]) => {
      if (record.disposed || record.tabs.get(tabId) !== view || !authSession.isAccessAllowed)
        return;
      const url = favicons
        .slice(0, 4)
        .find(
          (candidate) =>
            candidate.length <= webBrowserFaviconUrlLimit &&
            (candidate.startsWith('data:image/') || !!routeNavigation(candidate)),
        );
      if (!url || url === faviconSource) return;
      faviconSource = url;
      faviconRequest?.abort();
      const request = new AbortController();
      faviconRequest = request;
      const pageUrl = contents.getURL();
      const timeout = setTimeout(() => request.abort(), 5_000);
      timeout.unref();
      void (async () => {
        const favicon = await fetchWebBrowserFavicon(
          {
            fetchData: (url, signal) =>
              contents.session.fetch(url, { signal, credentials: 'omit' }),
            request: (url, origin) =>
              electronNet.request({
                url,
                credentials: origin === 'null' ? 'omit' : 'same-origin',
                origin: origin === 'null' ? undefined : origin,
                session: contents.session,
                redirect: 'follow',
              }),
          },
          pageUrl,
          url,
          routeNavigation,
          request.signal,
        );
        if (!request.signal.aborted && contents.getURL() === pageUrl) update({ favicon });
      })()
        .catch(() => undefined)
        .finally(() => clearTimeout(timeout));
    });
    contents.on('did-navigate-in-page', () => update());
    contents.on('page-title-updated', () => update());
    contents.on('did-start-loading', () => update({ isLoading: true, error: undefined }));
    contents.on('did-stop-loading', () => update({ isLoading: false }));
    contents.on('did-finish-load', () => {
      // Chromium can finish loading its own error document after did-fail-load.
      // Retain the failure until the user starts another navigation.
      update({ isLoading: false });
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
        recordDiagnostic('ERR', 'Browser navigation failed', { errorCode });
        update({ isLoading: false, error: describeWebLoadFailure(errorCode, errorDescription) });
      },
    );
    contents.on('render-process-gone', (_event, { reason, exitCode }) => {
      if (record.disposed || this.surfaces.get(sessionId) !== record) return;
      recordDiagnostic('ERR', 'Browser renderer exited', { reason, exitCode });
      update({
        isLoading: false,
        error: 'This tab stopped unexpectedly. Reload the page to continue.',
      });
    });
    contents.once('destroyed', () => {
      faviconRequest?.abort();
      if (
        record.disposed ||
        this.surfaces.get(sessionId) !== record ||
        record.tabs.get(tabId) !== view
      )
        return;
      const removedView = record.tabs.remove(tabId);
      if (!removedView) {
        this.sendEvent(sessionId, record, 'failed', {
          error: 'The browser closed unexpectedly. Reconnect to continue.',
        });
        record.disposed = true;
      }
      // Retire the dead tab immediately, then detach its view after Chromium's teardown.
      setImmediate(() => {
        if (removedView) this.destroyBrowserTab(record, removedView);
        if (this.surfaces.get(sessionId) !== record) return;
        if (!removedView) {
          this.close(sessionId);
        } else if (!record.disposed) {
          this.showBrowserTab(record);
          this.sendEvent(sessionId, record, 'navigation');
        }
      });
    });
  }

  private failBrowserTab(
    sessionId: string,
    record: WebSurfaceRecord,
    tabId: string,
    error: string,
  ): void {
    if (record.disposed || this.surfaces.get(sessionId) !== record) return;
    record.tabs.update(tabId, { isLoading: false, error });
    this.sendEvent(sessionId, record, 'navigation');
  }

  private browserState(record: WebSurfaceRecord): WebBrowserState {
    return {
      ...record.tabs.snapshot(
        record.route,
        record.navigation.originalUrl ? new URL(record.navigation.originalUrl).origin : undefined,
        record.tunnel,
      ),
      vpnStatus: record.vpn?.status,
    };
  }

  private sendEvent(
    sessionId: string,
    record: WebSurfaceRecord,
    type: 'connected' | 'failed' | 'vpn-state' | 'navigation' | 'focus-address',
    values: { error?: string; isLoading?: boolean } = {},
  ): void {
    if (record.disposed || record.owner.isDestroyed()) return;
    const browser = this.browserState(record);
    const tab = browser.tabs.find((candidate) => candidate.id === browser.activeTabId);
    if (!tab) return;
    try {
      record.owner.webContents.send('web:event', {
        type,
        sessionId,
        attempt: record.attempt,
        url: tab.url.slice(0, webMaxUrlLength),
        canGoBack: tab.canGoBack,
        canGoForward: tab.canGoForward,
        isLoading: values.isLoading ?? tab.isLoading,
        browser,
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
    return (
      (target.protocol === 'http:' || target.protocol === 'https:') &&
      !target.username &&
      !target.password
    );
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
  const failure =
    error && typeof error === 'object' ? (error as { errno?: unknown; code?: unknown }) : undefined;
  const code =
    typeof failure?.code === 'string' && /^ERR_[A-Z0-9_]{1,64}$/.test(failure.code)
      ? failure.code
      : '';
  if (typeof failure?.errno === 'number' && Number.isInteger(failure.errno)) {
    return describeWebLoadFailure(failure.errno, code);
  }
  // Electron's raw loadURL error contains the complete URL, including authentication parameters.
  return code
    ? `The browser could not start the page (${code}).`
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
      return /^ERR_[A-Z0-9_]{1,64}$/.test(description)
        ? `Navigation failed (${description}).`
        : 'Navigation failed.';
  }
}

const vaultWebConnections = new VaultWebConnections({
  workspaceId: () => vaultBackend.unlockedWorkspaceId,
  authorized: (epoch) =>
    Boolean(vaultBackend.unlockedWorkspaceId) && isAuthorizationEpochCurrent(epoch - 1),
  plan: (q) => vaultBackend.webPlan(q),
  archive: (plan, active) => vaultBackend.webSessionArchive(plan, active),
  checkViews: (workspaceId, views) => vaultBackend.checkWebSessionViews(workspaceId, views),
  quickTarget: (target, sessionId, epoch, accepted) => {
    const workspaceId = vaultBackend.unlockedWorkspaceId;
    if (!workspaceId) throw Error('Protected Quick Connect is locked.');
    return vaultBackend.beginQuickTarget({ workspaceId, sessionId, epoch, target }, accepted);
  },
  routes: new SealedRouteBroker({
    authentication: {
      prompt: (context, current, signal, request, fallback) => {
        const parent = webSurfaces.vaultOwnerForSession(context.binding.sessionId);
        if (!parent) return Promise.reject(Error('VPN authentication owner unavailable.'));
        return 'startURL' in context
          ? vaultTunnelBrowserDialog.open(parent, current, context, signal, request, fallback)
          : vaultTunnelAuthenticationDialog.open(parent, current, context, signal);
      },
      close: (context) =>
        'startURL' in context
          ? vaultTunnelBrowserDialog.cancelChallenge(context)
          : vaultTunnelAuthenticationDialog.cancelChallenge(context),
    },

    executable: backendPath,
    workspaceId: () => vaultBackend.unlockedWorkspaceId,
    authorized: (epoch) =>
      Boolean(vaultBackend.unlockedWorkspaceId) && isAuthorizationEpochCurrent(epoch - 1),
    plan: (q) => vaultBackend.tunnelPlan(q),
    bundle: (q) => vaultBackend.tunnelBundle(q),
    fallback: {
      plan: (q) => vaultBackend.tunnelFallbackPlan(q),
      bundle: (q) => vaultBackend.tunnelFallbackBundle(q),
    },
  }),
});
const webSurfaces = new WebSurfaceManager({
  active: () => vaultBackend.isVaultWorkspace,
  connections: vaultWebConnections,
});
const vaultWebIpc = new VaultWebIpc({
  workspace: () => vaultBackend.isVaultWorkspace,
  trusted: (event) => isTrustedVaultSender(event as Electron.IpcMainInvokeEvent),
  authorize: (run, cleanup) =>
    runAuthorizedOperation(async () => {
      requireNativeResourcesRunning();
      return run();
    }, cleanup),
  open: (owner, request, current) => {
    const window = BrowserWindow.fromWebContents(owner as Electron.WebContents);
    if (!window || window.isDestroyed()) throw Error('Web session owner window is unavailable.');
    return webSurfaces.open(window, request, current);
  },
  close: (owner, id) => webSurfaces.closeForContents(owner as Electron.WebContents, id),
  closeAll: () => webSurfaces.stopVaultSessions(),
});

class NativeSshBackend {
  private disposing: Promise<void> | undefined;
  private shutdownUnconfirmed = false;
  private readonly routes = new SealedRouteBroker({
    authentication: {
      prompt: (context, current, signal, request, fallback) => {
        const owner = this.terminalOwners.get(context.binding.sessionId);
        const parent = BrowserWindow.getAllWindows().find((window) => window.webContents === owner);
        if (!parent) return Promise.reject(Error('VPN authentication owner unavailable.'));
        return 'startURL' in context
          ? vaultTunnelBrowserDialog.open(parent, current, context, signal, request, fallback)
          : vaultTunnelAuthenticationDialog.open(parent, current, context, signal);
      },
      close: (context) =>
        'startURL' in context
          ? vaultTunnelBrowserDialog.cancelChallenge(context)
          : vaultTunnelAuthenticationDialog.cancelChallenge(context),
    },

    executable: backendPath,
    workspaceId: () => vaultBackend.unlockedWorkspaceId,
    authorized: (epoch) =>
      Boolean(vaultBackend.unlockedWorkspaceId) && isAuthorizationEpochCurrent(epoch - 1),
    plan: (request) => vaultBackend.tunnelPlan(request),
    bundle: (request) => vaultBackend.tunnelBundle(request),
    fallback: {
      plan: (q) => vaultBackend.tunnelFallbackPlan(q),
      bundle: (q) => vaultBackend.tunnelFallbackBundle(q),
    },
  });
  private readonly sealed = new SealedSshBackend({
    executable: backendPath,
    fileEditing: () => ({
      databasePath: wormholeDatabasePath(),
      userDataPath: electronUserDataPath(),
    }),
    workspaceId: () => vaultBackend.unlockedWorkspaceId,
    authorized: (epoch) =>
      Boolean(vaultBackend.unlockedWorkspaceId) && isAuthorizationEpochCurrent(epoch - 1),
    bundle: (request) => vaultBackend.sshBundle(request),
    bitwarden: (request, signal, accepted) =>
      vaultBackend.isSharedWorkspace
        ? Promise.resolve(undefined)
        : resolveVaultSSHBitwarden({
            executable: backendPath(),
            databasePath: wormholeDatabasePath(),
            request,
            signal,
            prepare: (recipient) =>
              vaultBackend.prepareSSHBitwarden(
                request,
                recipient,
                () => !signal.aborted && accepted(),
              ),
          }),
    manual: {
      close: (id) => vaultSshCredentialsDialog.cancelSession(id),
      plan: (request) => vaultBackend.sshManualPlan(request),
      bundle: (request) => vaultBackend.sshManualBundle(request),
      prompt: (context, current, signal) => {
        const owner = this.terminalOwners.get(context.plan.host.binding.sessionId);
        const parent = owner && BrowserWindow.fromWebContents(owner);
        if (!parent) return Promise.reject(Error('SSH credential owner unavailable.'));
        return vaultSshCredentialsDialog.open(parent, current, context, signal);
      },
    },
    route: {
      resolve: (request) => vaultBackend.connectionRoute(request),
      broker: this.routes,
      bundle: (request) => vaultBackend.routedSshBundle(request),
    },
    host: {
      plan: (request) => vaultBackend.sshHostPlan(request),
      confirm: async (request, plan, received, accepted, signal) => {
        const owner = this.terminalOwners.get(request.sessionId);
        const parent = owner && BrowserWindow.fromWebContents(owner);
        if (!parent || parent.isDestroyed() || !accepted() || signal.aborted)
          throw Error('SSH host confirmation is unavailable.');
        const changed = plan.fingerprint !== '';
        const result = await showCoordinatedMessageBox(parent, {
          type: changed ? 'warning' : 'question',
          title: changed ? 'SSH host key changed' : 'Verify SSH host key',
          message: changed
            ? 'The server identity has changed.'
            : 'This server identity has not been verified.',
          detail: `${plan.binding.host}:${plan.binding.port}\n\n${changed ? `Saved: ${plan.fingerprint}\n` : ''}Received: ${received}\n\nVerify this fingerprint with the server administrator before trusting it.`,
          buttons: ['Cancel', 'Trust and connect'],
          defaultId: 0,
          cancelId: 0,
          noLink: true,
          signal,
        });
        if (result.response !== 1 || !accepted() || signal.aborted)
          throw Error('SSH host confirmation was cancelled.');
        if (vaultBackend.isSharedWorkspace) {
          await vaultBackend.trustSharedSshHost(
            { ...request, expected: plan, received },
            (startup, current, submit) =>
              vaultSharedDialog.open(parent, current, 'trust-ssh-host', startup, submit, signal),
            () => accepted() && !signal.aborted,
          );
          return;
        }
        const trust = vaultSshIpc.isQuickTarget(request)
          ? vaultBackend.trustQuickSshHost.bind(vaultBackend)
          : vaultBackend.trustSshHost.bind(vaultBackend);
        await trust(
          { ...request, expected: plan, received },
          (operation, descriptor, submit) =>
            vaultReauthenticationDialog.open(
              parent,
              () => accepted() && !signal.aborted,
              operation,
              descriptor,
              submit,
              signal,
            ),
          accepted,
        );
      },
    },
    parseEvent: parseSshBackendEvent,
    onLine: (line) => this.handleLine(line),
  });
  private terminalDelivery = new SshTerminalDelivery();
  private terminalOwners = new Map<string, Electron.WebContents>();
  private readonly terminalAdmissions = new Map<string, object>();
  private readonly protectedMembers = new Map<
    string,
    {
      id: string;
      owner: Electron.WebContents;
      members: Set<string>;
    }
  >();

  hasProtectedReservation(id: string): boolean {
    return this.protectedMembers.has(id) || this.sealed.hasReservation(id);
  }

  ownsProtected(owner: Electron.WebContents, id: string): boolean {
    return this.protectedMembers.get(id)?.owner === owner || this.terminalOwners.get(id) === owner;
  }

  captureOwner(event: Electron.IpcMainInvokeEvent, id: string, allowRetired = false): () => void {
    if (
      !vaultBackend.isVaultWorkspace &&
      !vaultBackend.unlockedWorkspaceId &&
      !this.hasProtectedReservation(id)
    )
      return () => {};
    const owner = event.sender,
      token = this.terminalAdmissions.get(id),
      epoch = authSession.authorizationEpoch;
    const retired =
      allowRetired && !this.hasProtectedReservation(id) && !this.terminalOwners.has(id);
    const current = () => {
      if (!isTrustedVaultSender(event) || owner.isDestroyed())
        throw Error('Invalid vault SSH owner.');
      if (!isAuthorizationEpochCurrent(epoch)) throw Error('Vault SSH session is unavailable.');
      if (retired) {
        if (
          this.hasProtectedReservation(id) ||
          this.terminalOwners.has(id) ||
          this.terminalAdmissions.has(id)
        )
          throw Error('Vault SSH session is unavailable.');
      } else if (
        !token ||
        this.terminalAdmissions.get(id) !== token ||
        !this.ownsProtected(owner, id) ||
        !this.sealed.has(id)
      )
        throw Error('Vault SSH session is unavailable.');
    };
    current();
    return current;
  }

  admitProtected(
    owner: Electron.WebContents,
    q: Extract<VaultSshOpen, { nodeId: string }>,
    epoch: number,
    current: () => boolean,
    retired: () => Promise<void>,
  ): SealedSshAdmission {
    const rejected = (): SealedSshAdmission => ({
      accepted: false,
      result: Promise.reject(Error('Vault SSH is unavailable.')),
    });
    if (
      !vaultBackend.unlockedWorkspaceId ||
      !isAuthorizationEpochCurrent(epoch - 1) ||
      !current() ||
      owner.isDestroyed() ||
      (q.manualCredentials && (q.manualKeyPassphrase || q.credentialId !== undefined)) ||
      this.hasProtectedReservation(q.sessionId) ||
      this.pendingConnections.has(q.sessionId) ||
      this.openWaiters.has(q.sessionId) ||
      this.activeSessions.has(q.sessionId)
    )
      return rejected();
    const documentURL = owner.getURL();
    const cohort = { id: q.sessionId, owner, members: new Set([q.sessionId]) },
      token = {};
    this.protectedMembers.set(q.sessionId, cohort);
    this.terminalOwners.set(q.sessionId, owner);
    this.terminalAdmissions.set(q.sessionId, token);
    const generation = this.connectionAttempts.begin(q.sessionId);
    this.pendingConnections.set(q.sessionId, generation);
    const admission = this.sealed.admit(
      {
        sessionId: q.sessionId,
        nodeId: q.nodeId,
        columns: q.columns,
        rows: q.rows,
        ...(q.mode ? { mode: q.mode } : {}),
        ...(q.credentialId ? { credentialId: q.credentialId } : {}),
        ...(q.manualCredentials ? { manualCredentials: true } : {}),
        ...(q.manualKeyPassphrase ? { manualKeyPassphrase: true } : {}),
      },
      epoch,
      () =>
        current() &&
        !owner.isDestroyed() &&
        owner.getURL() === documentURL &&
        this.terminalAdmissions.get(q.sessionId) === token &&
        this.terminalOwners.get(q.sessionId) === owner,
      async () => {
        await retired();
        for (const id of cohort.members) {
          if (this.protectedMembers.get(id) !== cohort) continue;
          this.protectedMembers.delete(id);
          this.terminalAdmissions.delete(id);
        }
      },
    );
    if (!admission.accepted) {
      this.protectedMembers.delete(q.sessionId);
      this.terminalOwners.delete(q.sessionId);
      this.terminalAdmissions.delete(q.sessionId);
    }
    return {
      accepted: admission.accepted,
      result: admission.result.finally(() => {
        if (this.pendingConnections.get(q.sessionId) === generation)
          this.pendingConnections.delete(q.sessionId);
      }),
    };
  }

  async closeProtected(owner: Electron.WebContents, id: string): Promise<void> {
    if (!this.hasProtectedReservation(id)) return;
    if (!this.ownsProtected(owner, id)) throw Error('Invalid vault SSH owner.');
    await this.close(id);
  }

  async retireProtected(
    owner: Electron.WebContents,
    ids: readonly string[],
    allOwned = false,
  ): Promise<void> {
    const selected = new Set(ids);
    if (allOwned)
      for (const [id, cohort] of this.protectedMembers)
        if (cohort.owner === owner) selected.add(id);
    for (const id of selected) {
      if (!this.hasProtectedReservation(id)) continue;
      if (!this.ownsProtected(owner, id)) throw Error('Invalid vault SSH owner.');
      this.terminalAdmissions.delete(id);
    }
    await this.sealed.closeCohorts([...selected]);
  }

  acknowledgeTerminal(owner: Electron.WebContents, sessionId: string, sequence: number): void {
    if (!authSession.isAccessAllowed || this.terminalOwners.get(sessionId) !== owner) return;
    if (this.terminalDelivery.acknowledge(sessionId, sequence)) {
      try {
        this.write({ type: 'terminal-ack', session_id: sessionId, sequence });
      } catch {
        // A late parse callback can race with backend shutdown; its lifecycle owns the error.
      }
    }
  }

  private deliverTerminal(packet: SshTerminalOutput): void {
    const owner = this.terminalOwners.get(packet.sessionId);
    if (owner && !owner.isDestroyed() && authSession.isAccessAllowed) {
      owner.send('ssh:event', packet);
    }
  }

  private readonly editWaiters = new Map<
    string,
    {
      sessionId: string;
      resolve: (event: SftpEditEvent) => void;
      reject: (error: Error) => void;
      timeout: NodeJS.Timeout;
    }
  >();
  async edit(sessionId: string, request: SftpEditRequest): Promise<SftpEditEvent> {
    if (!this.sealed.has(sessionId)) this.ensureStarted();
    if (this.editWaiters.size >= 128) throw Error('Too many file edit requests.');
    const requestId = randomUUID();
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.editWaiters.delete(requestId);
        reject(new Error('File edit operation timed out; working copies are retained.'));
      }, 60_000);
      this.editWaiters.set(requestId, { sessionId, resolve, reject, timeout });
      try {
        this.write({
          type: 'sftp-edit',
          session_id: sessionId,
          request_id: requestId,
          operation: request.operation,
          pane: request.pane,
          path: request.path,
          edit_id: request.editId,
          editor_id: request.editorId,
          allow_binary: request.allowBinary,
          decision: request.decision,
          destination_path: request.destinationPath,
        });
      } catch (error) {
        clearTimeout(timeout);
        this.editWaiters.delete(requestId);
        reject(error);
      }
    });
  }

  private editCloseTargets(sessionId: string, owner?: Electron.WebContents): string[] {
    if (this.sealed.has(sessionId)) return [sessionId];
    if (vaultBackend.unlockedWorkspaceId) {
      return sessionId === 'sftp-recovery'
        ? this.sealed
            .connectedSessionIds()
            .filter((id) => !owner || this.terminalOwners.get(id) === owner)
        : [];
    }
    return this.child && !this.child.killed ? [sessionId] : [];
  }

  async prepareEditClose(
    sessionId = 'sftp-recovery',
    document?: Electron.WebContents,
  ): Promise<boolean> {
    const pending = new Set<string>();
    for (const id of this.editCloseTargets(sessionId, document)) {
      const snapshot = await this.edit(id, { operation: 'prepare-close' });
      if (snapshot.error) throw new Error(snapshot.error);
      for (const edit of snapshot.edits) if (edit.pending && !edit.recovered) pending.add(edit.id);
    }
    if (pending.size) {
      const source = document ?? this.terminalOwners.get(sessionId);
      const owner =
        (source ? BrowserWindow.fromWebContents(source) : undefined) ??
        BrowserWindow.getFocusedWindow() ??
        BrowserWindow.getAllWindows().find((window) => windowCloseCoordinators.has(window));
      if (!owner) return false;
      const answer = await showCoordinatedMessageBox(owner, {
        type: 'warning',
        title: 'Pending file edits',
        message: `${pending.size} edited file(s) have changes that have not been uploaded.`,
        detail:
          'Keep the private working copies for recovery after reconnecting, or return to File transfer to finish uploading.',
        buttons: ['Return to editing', 'Keep copies and close'],
        defaultId: 0,
        cancelId: 0,
      });
      if (answer.response !== 1) return false;
    }

    return true;
  }

  async finishEditClose(sessionId = 'sftp-recovery'): Promise<void> {
    for (const id of this.editCloseTargets(sessionId)) {
      const finished = await this.edit(id, { operation: 'finish-close', decision: 'keep' });
      if (finished.error) throw new Error(finished.error);
    }
  }

  private child: ChildProcessWithoutNullStreams | undefined;
  private lineReader: Interface | undefined;
  private controlSequence = 0;
  private readonly activeSessions = new Set<string>();
  // Go remains the lifecycle source of truth. Electron retains only the IDs Go explicitly marks
  // so an unexpected child exit can deliver the terminal closed event to the renderer.
  private readonly retainedMismatchSessions = new Set<string>();
  private readonly tunnelLeases = new TunnelLeaseRegistry();
  private readonly connectionAttempts = new WebSessionAttemptTracker();
  private readonly closingConnections = new KeyedSingleFlight<string, void>();
  private readonly pendingConnections = new Map<string, number>();
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

  async open(
    request: SshOpenRequest,
    authorizationEpoch: number,
    owner: Electron.WebContents,
  ): Promise<SshConnectedResponse> {
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
      await this.closingConnections.waitForIdle(request.sessionId);
      if (!this.connectionAttempts.isCurrent(request.sessionId, generation)) {
        throw new Error('SSH connection closed before it could start.');
      }
      this.terminalOwners.set(request.sessionId, owner);
      this.terminalAdmissions.set(request.sessionId, {});
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
    if (vaultBackend.unlockedWorkspaceId) {
      if (
        !request.nodeId ||
        request.mode === 'smb' ||
        request.manualCredentials ||
        request.manualKeyPassphrase ||
        request.password !== undefined ||
        request.keyPassphrase !== undefined ||
        request.username !== undefined ||
        request.host !== undefined ||
        request.tunnelConfigId !== undefined
      ) {
        throw new Error('This connection requires a vault SSH flow that is not available yet.');
      }
      requireAuthorizationEpoch(authorizationEpoch);
      if (!this.connectionAttempts.isCurrent(request.sessionId, generation))
        throw new Error('SSH connection was cancelled.');
      const owner = this.terminalOwners.get(request.sessionId);
      const admission = this.terminalAdmissions.get(request.sessionId);
      const documentURL = owner?.getURL();
      return this.sealed.open(
        {
          sessionId: request.sessionId,
          nodeId: request.nodeId,
          mode: request.mode,
          credentialId: request.credentialId,
          columns: request.columns,
          rows: request.rows,
        },
        authorizationEpoch + 1,
        () =>
          Boolean(
            owner &&
            !owner.isDestroyed() &&
            this.terminalOwners.get(request.sessionId) === owner &&
            this.terminalAdmissions.get(request.sessionId) === admission &&
            owner.getURL() === documentURL,
          ),
      );
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
    let configuredTunnelId: string | undefined;
    const tunnelRequested = Boolean(request.nodeId || request.tunnelConfigId);
    let leaseId: string | undefined;
    if (tunnelRequested) {
      leaseId = randomUUID();
      this.tunnelLeases.claim(request.sessionId, leaseId);
      try {
        const route = await getNativeBackend().acquireTunnelRoute({
          onExit: () => {
            if (!this.tunnelLeases.isActive(request.sessionId, leaseId!)) return;
            this.broadcast({
              type: 'error',
              sessionId: request.sessionId,
              error: tunnelClosedMessage,
              retainTunnelLease: false,
            });
            void this.close(request.sessionId).catch(() => undefined);
          },
          leaseId,
          nodeId: request.nodeId,
          tunnelConfigId: request.tunnelConfigId,
          progressSessionId: request.sessionId,
        });
        socksEndpoint = route.socksEndpoint;
        configuredTunnelId = route.configuredTunnelId;
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
    let credentialFields: ReturnType<typeof sshOpenCredentialFields>;
    try {
      requireAuthorizationEpoch(authorizationEpoch);
      // Vault access can wait on CLI synchronization; the route choice must precede it.
      let bitwardenCredential: BitwardenResolvedCredential = { bitwarden: false };
      if ((request.nodeId || request.credentialId) && !request.manualCredentials) {
        try {
          bitwardenCredential = await runBitwardenBackend<BitwardenResolvedCredential>(
            request.credentialId ? 'bitwarden.resolve-credential' : 'bitwarden.resolve-node',
            request.credentialId
              ? {
                  credentialId: request.credentialId,
                  protocol: request.mode === 'smb' ? 'smb' : 'ssh',
                }
              : { nodeId: request.nodeId, protocol: request.mode === 'smb' ? 'smb' : 'ssh' },
          );
        } catch (error) {
          const message = error instanceof Error ? error.message : 'The vault could not be read.';
          throw new Error(`Bitwarden credential is unavailable: ${message}`);
        }
      }
      credentialFields = sshOpenCredentialFields(request, bitwardenCredential);

      if (!this.connectionAttempts.isCurrent(request.sessionId, generation)) {
        throw new Error('SSH connection closed before it could start.');
      }
      requireAuthorizationEpoch(authorizationEpoch);
      this.ensureStarted();
    } catch (error) {
      await this.releaseTunnel(request.sessionId);
      throw error;
    }

    return await this.waitForConnection(request.sessionId, () => {
      this.write({
        type: 'open',
        terminal_stream: request.mode !== 'sftp' && request.mode !== 'smb',
        mode: request.mode ?? 'terminal',
        session_id: request.sessionId,
        node_id: request.nodeId,
        ...credentialFields,
        auto_sudo: request.autoSudo,
        host: request.host,
        port: request.port,
        tunnel_config_id: request.tunnelConfigId,
        configured_tunnel_id: request.nodeId ? configuredTunnelId : undefined,
        socks_endpoint: socksEndpoint,
        tunnel_enabled: request.nodeId && !socksEndpoint ? false : undefined,
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
    return this.waitForConnection(request.sessionId, () => {
      this.write({
        type: 'host-key-trust',
        session_id: request.sessionId,
        node_id: request.nodeId,
        host_key_expected: request.expected,
        host_key_received: request.received,
      });
    });
  }

  private waitForConnection(sessionId: string, start: () => void): Promise<SshConnectedResponse> {
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

  sendInput(sessionId: string, data: string, paste = false): void {
    this.write({ type: 'input', session_id: sessionId, data, paste });
  }

  resize(sessionId: string, columns: number, rows: number): void {
    this.write({ type: 'resize', session_id: sessionId, columns, rows });
  }

  assertSftpOwner(
    event: Electron.IpcMainInvokeEvent,
    sessionId: string,
    allowRetired = false,
  ): void {
    if (!this.sealed.has(sessionId) && !vaultBackend.unlockedWorkspaceId) return;
    const retired =
      allowRetired && !this.sealed.has(sessionId) && !this.terminalOwners.has(sessionId);
    if (
      !isTrustedVaultSender(event) ||
      (!retired && this.terminalOwners.get(sessionId) !== event.sender)
    )
      throw new Error('Invalid vault SFTP owner.');
  }

  private readonly sharedRoutes = new SharedSshRoutes();

  async shareSftp(
    sourceId: string,
    sessionId: string,
    owner?: Electron.WebContents,
    accepted: () => boolean = () => true,
  ): Promise<SshConnectedResponse> {
    if (
      !this.activeSessions.has(sourceId) ||
      this.activeSessions.has(sessionId) ||
      this.openWaiters.has(sessionId) ||
      this.pendingConnections.has(sessionId) ||
      this.hasProtectedReservation(sessionId)
    )
      throw new Error('Source SSH connection is unavailable.');
    if (this.sealed.has(sourceId) || vaultBackend.unlockedWorkspaceId) {
      if (
        !owner ||
        owner.isDestroyed() ||
        this.terminalOwners.get(sourceId) !== owner ||
        !this.sealed.has(sourceId)
      )
        throw new Error('Source vault SSH connection is unavailable.');
      const documentURL = owner.getURL();
      const token = {},
        cohort = this.protectedMembers.get(sourceId);
      const generation = this.connectionAttempts.begin(sessionId);
      this.pendingConnections.set(sessionId, generation);
      this.terminalOwners.set(sessionId, owner);
      this.terminalAdmissions.set(sessionId, token);
      if (cohort) {
        cohort.members.add(sessionId);
        this.protectedMembers.set(sessionId, cohort);
      }
      try {
        return await this.sealed.shareSftp(
          sourceId,
          sessionId,
          () =>
            accepted() &&
            !owner.isDestroyed() &&
            owner.getURL() === documentURL &&
            this.terminalAdmissions.get(sessionId) === token &&
            this.terminalOwners.get(sessionId) === owner,
        );
      } finally {
        if (this.pendingConnections.get(sessionId) === generation) {
          this.pendingConnections.delete(sessionId);
          if (!this.sealed.has(sessionId)) {
            this.terminalOwners.delete(sessionId);
            this.terminalAdmissions.delete(sessionId);
            if (this.protectedMembers.get(sessionId) === cohort)
              this.protectedMembers.delete(sessionId);
            cohort?.members.delete(sessionId);
          }
        }
      }
    }
    this.sharedRoutes.attach(sourceId, sessionId);
    try {
      return await this.waitForConnection(sessionId, () =>
        this.write({
          type: 'open',
          mode: 'sftp',
          source_session_id: sourceId,
          session_id: sessionId,
        }),
      );
    } catch (error) {
      await this.releaseTunnel(sessionId);
      throw error;
    }
  }

  listSftpTree(sessionId: string, pane: 'local' | 'remote', path: string, requestId: string): void {
    this.write({
      type: 'sftp-tree-list',
      session_id: sessionId,
      pane,
      path,
      request_id: requestId,
    });
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
    this.terminalAdmissions.clear();
    void this.sealed.closeAll().catch(() => undefined);
    mcpApprovalWindowCoordinator.reset();
    try {
      this.write({ type: 'app-lock-all' });
    } catch {
      // A broken pipe during lock/reload is already a terminal cleanup state.
    }
  }

  stopSealedSessions(): Promise<void> {
    this.terminalAdmissions.clear();
    return Promise.allSettled([this.sealed.closeAll(), vaultSshCredentialsDialog.cancel()]).then(
      (results) => {
        if (results.some((result) => result.status === 'rejected'))
          throw Error('SSH shutdown could not be confirmed.');
      },
    );
  }

  async close(sessionId: string): Promise<void> {
    if (this.hasProtectedReservation(sessionId)) {
      this.connectionAttempts.cancel(sessionId);
      this.terminalDelivery.remove(sessionId);
      this.terminalAdmissions.delete(sessionId);
      await this.sealed.close(sessionId);
      this.terminalOwners.delete(sessionId);
      return;
    }
    // A journal RPC can wait while credentials resolve. Invalidate the open before awaiting it.
    this.connectionAttempts.cancel(sessionId);
    this.terminalAdmissions.delete(sessionId);
    return this.closingConnections.run(sessionId, async () => {
      // Native resources must still close when retaining a journal fails. Go also
      // freezes copies on native close, and the existing journal stays recoverable.
      try {
        await this.finishEditClose(sessionId);
      } catch {
        reportWarning('File edit journal could not be finalized; working copies retained.');
      }
      this.terminalDelivery.remove(sessionId);
      this.terminalOwners.delete(sessionId);
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
    });
  }

  cancelPendingConnections(): void {
    for (const sessionId of this.pendingConnections.keys()) {
      void this.close(sessionId).catch((error) => {
        reportWarning('Could not release a pending SSH VPN tunnel.', error);
      });
    }
  }

  private async releaseTunnel(sessionId: string): Promise<void> {
    const owner = this.sharedRoutes.release(sessionId);
    if (owner) await this.tunnelLeases.release(owner, releaseNativeTunnelLease);
  }

  requestSnapshots(): void {
    if (!authSession.isAccessAllowed || !this.child || this.child.killed) return;
    for (const packet of this.terminalDelivery.pending()) this.deliverTerminal(packet);
    for (const sessionId of this.activeSessions) {
      try {
        if (!this.terminalOwners.has(sessionId))
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

  async setMcpApprovalMode(approvalMode: McpApprovalMode): Promise<McpStatusResponse> {
    const response = await this.sendMcpControl({
      type: 'mcp.set-approval-mode',
      approval_mode: approvalMode,
    });
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
    // The approval is shown in every main window, but only one window can resolve it. Remove the
    // stale copy everywhere only after the backend has accepted this window's decision. Backend
    // revalidation failures emit their own cancellation event.
    this.broadcastMcpApprovalCancellation(approvalId);
  }

  async revokeMcpSessionAccess(sessionId: string): Promise<void> {
    await this.sendMcpControl({ type: 'mcp.revoke-session', session_id: sessionId });
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
    if (this.disposing) return this.disposing;
    this.shutdownUnconfirmed = true;
    this.disposing = Promise.resolve()
      .then(() => this.disposeOwnedProcess())
      .finally(() => {
        this.disposing = undefined;
      });
    return this.disposing;
  }

  private async disposeOwnedProcess(): Promise<void> {
    const sealedStopped = this.sealed.closeAll();
    void sealedStopped.catch(() => undefined);
    this.terminalDelivery.clear();
    this.terminalOwners.clear();
    this.terminalAdmissions.clear();
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
    this.sharedRoutes.clear();
    const child = this.child;
    const stopped = child
      ? stopChildProcess(child, { nativeExecutable: backendPath() }).then((exited) => {
          if (!exited) throw new Error('SSH service termination could not be confirmed.');
        })
      : Promise.resolve();
    // Keep draining protocol output until the process is actually gone. Closing
    // readline first can block a native writer during its shutdown.
    const results = await Promise.allSettled([stopped, tunnelReleases, sealedStopped]);
    if (results.some((result) => result.status === 'rejected'))
      throw new Error('SSH service termination could not be confirmed.');
    if (this.child === child) this.child = undefined;
    this.lineReader?.close();
    this.lineReader = undefined;
    this.shutdownUnconfirmed = false;
  }

  backendStopped(): void {
    this.tunnelLeases.clear();
    this.sharedRoutes.clear();
    this.retainedMismatchSessions.clear();
  }

  private ensureStarted(): void {
    if (this.disposing || this.shutdownUnconfirmed)
      throw new Error('SSH service shutdown is unconfirmed.');
    if (vaultBackend.unlockedWorkspaceId)
      throw new Error('Legacy SSH operations are unavailable for this vault.');
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
    observeBackendProcess(child, 'ssh', recordDiagnostic);
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
      reportWarning('SSH input stream failed', error);
      const failure = new Error(`SSH service connection failed: ${error.message}`);
      this.failOpenWaiters(failure);
      this.failControlWaiters(failure);
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
      this.terminalDelivery.clear();
      this.terminalOwners.clear();
      for (const sessionId of closedSessions) {
        this.broadcast({ type: 'closed', sessionId });
      }
      const failure = new Error('SSH service stopped.');
      this.failOpenWaiters(failure);
      this.failControlWaiters(failure);
      for (const requestId of mcpApprovalWindowCoordinator.reset()) {
        this.broadcastMcpApprovalCancellation(requestId);
      }
      void this.tunnelLeases.releaseAll(releaseNativeTunnelLease);
      this.sharedRoutes.clear();
    });
  }

  private write(command: Record<string, unknown>): void {
    if (typeof command.session_id === 'string' && this.sealed.has(command.session_id)) {
      this.sealed.send(command.session_id, command);
      return;
    }
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
    if (mcpMessage?.type === 'mcp.approval-cancelled') {
      mcpApprovalWindowCoordinator.finishApproval(mcpMessage.requestId);
      this.broadcastMcpApprovalCancellation(mcpMessage.requestId);
      return;
    }
    if (mcpMessage?.type === 'mcp.approval') {
      if (!authSession.isAccessAllowed) return;
      if (mcpMessage.approvalMode === 'full-access') {
        // Go has authorized this open. One main window acknowledges and opens it without a popup.
        const target = selectMcpApprovalWindow(
          BrowserWindow.getAllWindows(),
          BrowserWindow.getFocusedWindow(),
          (window) => windowCloseCoordinators.has(window),
        );
        target?.webContents.send('mcp:approval', mcpMessage);
        return;
      }
      const presentationReady = mcpApprovalWindowCoordinator.beginApproval(mcpMessage.requestId);
      webSurfaces.closeBitwardenFloatingWindows();
      void presentationReady.then(() => {
        mcpApprovalWindowCoordinator.presentApprovalWhenNativeDialogsClose(
          mcpMessage.requestId,
          () => {
            const windows = BrowserWindow.getAllWindows();
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
          },
        );
      });
      return;
    }
    const event = parseSshBackendEvent(line);
    if (!event) return;

    if (event.type === 'terminal-output') {
      if (this.terminalDelivery.receive(event)) this.deliverTerminal(event);
      return;
    }
    if (event.type === 'connected') {
      this.terminalDelivery.remove(event.sessionId);
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
        waiter.reject(new Error(message));
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
      this.terminalDelivery.remove(event.sessionId);
      this.terminalOwners.delete(event.sessionId);
      this.terminalAdmissions.delete(event.sessionId);
      const cohort = this.protectedMembers.get(event.sessionId);
      if (cohort && cohort.id !== event.sessionId) {
        cohort.members.delete(event.sessionId);
        this.protectedMembers.delete(event.sessionId);
      }
      this.activeSessions.delete(event.sessionId);
      this.retainedMismatchSessions.delete(event.sessionId);
      void this.releaseTunnel(event.sessionId).catch(() => undefined);
    }

    if (event.type === 'closed') {
      for (const [id, waiter] of this.editWaiters) {
        if (waiter.sessionId !== event.sessionId) continue;
        clearTimeout(waiter.timeout);
        this.editWaiters.delete(id);
        waiter.reject(Error('File editing connection closed; working copies are retained.'));
      }
    }

    if (event.type === 'sftp.edit' && event.requestId) {
      const waiter = this.editWaiters.get(event.requestId);
      if (waiter && waiter.sessionId === event.sessionId) {
        clearTimeout(waiter.timeout);
        this.editWaiters.delete(event.requestId);
        waiter.resolve(event);
      }
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
    if (event.type.startsWith('sftp.') && this.sealed.has(event.sessionId)) {
      const owner = this.terminalOwners.get(event.sessionId);
      if (owner && !owner.isDestroyed()) owner.send('ssh:event', event);
      return;
    }
    for (const window of BrowserWindow.getAllWindows()) {
      if (!window.isDestroyed() && windowCloseCoordinators.has(window)) {
        window.webContents.send('ssh:event', event);
      }
    }
  }

  private broadcastMcpApprovalCancellation(requestId: string): void {
    const event: McpApprovalCancelledEvent = { type: 'mcp.approval-cancelled', requestId };
    for (const window of BrowserWindow.getAllWindows()) {
      if (!window.isDestroyed() && windowCloseCoordinators.has(window)) {
        window.webContents.send('mcp:approval', event);
      }
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
    for (const waiter of this.editWaiters.values()) {
      clearTimeout(waiter.timeout);
      waiter.reject(error);
    }
    this.editWaiters.clear();
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
  const epoch = authSession.authorizationEpoch;
  authSession.remember(state, assumeUnlocked);
  if (authSession.authorizationEpoch !== epoch) clearFortinetIPsecDrafts();
  currentAuthState = state;
  return state;
}

function vaultAuthState() {
  return {
    mode: 'vault' as const,
    configured: true,
    fallback: 'password' as const,
    idleTimeoutMinutes: null,
    hasPin: false,
    hasPassword: false,
    isCorrupted: false,
    windowsHello: { available: false, message: 'Unlock using a vault factor.' },
  };
}

function refreshAuthSession(): Promise<AuthStateResponse> {
  if (vaultBackend.isVaultWorkspace || vaultBackend.requiresLegacyMigration)
    return Promise.resolve(rememberAuthState(vaultAuthState(), false));
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

function clearFortinetIPsecDrafts(): void {
  fortinetIPsecDrafts.clear();
  void nativeBackend?.send({ action: 'tunnel.ipsec-clear' }).catch(() => undefined);
}

function queueFortinetIPsecSecret(
  kind: FortinetIPsecEditableSecret | FortinetIPsecCertificate,
  owner: BrowserWindow,
  isCurrent: () => boolean,
) {
  const pending = tunnelBrowserAuthQueue
    .catch(() => undefined)
    .then(() =>
      promptFortinetIPsecSecret({
        kind,
        createWindow: createApplicationWindow,
        ipc: ipcMain,
        preload: path.join(__dirname, 'fortinet-ipsec-secret-preload.cjs'),
        parent: owner,
        isAuthorized: () => !owner.isDestroyed() && !authLockRequested && isCurrent(),
        present: (window) => mcpApprovalWindowCoordinator.presentTunnelAuthWindow(window),
        forget: (window) => mcpApprovalWindowCoordinator.forgetTunnelAuthWindow(window),
      }),
    );
  tunnelBrowserAuthQueue = pending.then(
    () => undefined,
    () => undefined,
  );
  return pending;
}

function fortinetIPsecEditorOwner(event: Electron.IpcMainInvokeEvent): BrowserWindow {
  const owner = BrowserWindow.fromWebContents(event.sender);
  if (
    !owner ||
    owner.isDestroyed() ||
    !windowCloseCoordinators.has(owner) ||
    !event.senderFrame ||
    event.senderFrame !== event.sender.mainFrame
  )
    throw new Error('Fortinet IPsec editor is unavailable.');
  return owner;
}

async function finishFortinetIPsecSave<T>(sender: Electron.WebContents, pending: Promise<T>) {
  const lifetime = new AbortController();
  const cancel = () => lifetime.abort();
  sender.once('destroyed', cancel);
  sender.once('did-start-loading', cancel);
  try {
    const [outcome] = await Promise.allSettled([pending]);
    // A committed write survives a lock. Deliver its result to the same workspace after unlock.
    while (!lifetime.signal.aborted && !authSession.isAccessAllowed) {
      await new Promise<void>((resolve) => {
        const resume = () => {
          unsubscribe();
          lifetime.signal.removeEventListener('abort', resume);
          resolve();
        };
        const unsubscribe = authSession.onUnlocked(resume);
        lifetime.signal.addEventListener('abort', resume, { once: true });
      });
    }
    if (lifetime.signal.aborted) throw new Error('Fortinet IPsec editor is unavailable.');
    if (outcome.status === 'rejected') throw outcome.reason;
    return outcome.value;
  } finally {
    sender.removeListener('destroyed', cancel);
    sender.removeListener('did-start-loading', cancel);
  }
}

async function saveTunnelWithNativeSecret(
  operation: 'tunnel-create' | 'tunnel-update',
  event: Electron.IpcMainInvokeEvent,
  value: unknown,
  draftId: unknown,
) {
  const request = parseTunnelWriteRequest(value, operation === 'tunnel-update');
  if (draftId !== undefined && (request.kind !== 9 || !isTunnelIdentifier(draftId)))
    throw new Error('Fortinet IPsec credential draft is invalid.');
  const save = async (epoch: number) => {
    if (request.kind !== 9)
      return parseTunnelDetailsResponse(await runBackend<unknown>(operation, request));
    const owner = fortinetIPsecEditorOwner(event);
    const references = fortinetIPsecDrafts.read(event.sender, draftId, epoch);
    const native = await prepareFortinetIPsecWrite(
      request,
      (kind) => queueFortinetIPsecSecret(kind, owner, () => isAuthorizationEpochCurrent(epoch)),
      references,
    );
    try {
      requireAuthorizationEpoch(epoch);
      if (authLockRequested) throw new Error('Authentication is required before saving the VPN.');
      if (!draftId) return parseTunnelDetailsResponse(await runBackend<unknown>(operation, native));
      // Only the service can confirm whether it committed the write and consumed the draft.
      const response = await getNativeBackend().send(
        {
          action: operation === 'tunnel-create' ? 'tunnel.ipsec-create' : 'tunnel.ipsec-update',
          ipsecWrite: native,
          ipsecReferences: references,
        },
        null,
      );
      if (!response.ok)
        throw new Error(response.error || 'Could not save the Fortinet IPsec tunnel.');
      fortinetIPsecDrafts.discard(event.sender, draftId, true);
      return parseTunnelDetailsResponse(response.result);
    } finally {
      for (const key of ['PreSharedKey', 'Password', 'ClientCert', 'ClientKey', 'CaCert'])
        delete native.settings[key];
    }
  };
  const { result } = await serializeAuthOperation(async () => {
    await requireWorkspaceAuth();
    const pending = save(authSession.authorizationEpoch);
    if (!draftId) return { result: await pending };
    return { result: finishFortinetIPsecSave(event.sender, pending) };
  });
  return result;
}

function holdApplicationLock(): () => void {
  authLocksInProgress++;
  authLockRequested = true;
  const releaseAuthLock = authSession.holdLock();
  let held = true;
  return () => {
    if (!held) return;
    held = false;
    releaseAuthLock();
    authLocksInProgress--;
    authLockRequested = authLocksInProgress > 0;
  };
}

async function lockApplication(
  sender?: Electron.WebContents,
  options: { refreshLegacy?: boolean } = {},
): Promise<void> {
  vaultNotesDialog.cancel();
  vaultCredentialsDialog.cancel();
  const creatingVault =
    vaultCreateDialog.active ||
    vaultMigrationSetupDialog.active ||
    vaultOSMigrationDialog.active ||
    vaultSharedSetupDialog.active;
  const creationStopped = Promise.all([
    vaultLinuxClipboard?.reset(),
    vaultCreateDialog.cancel(),
    vaultMigrationSetupDialog.cancel(),
    vaultOSMigrationDialog.cancel(),
    vaultReauthenticationDialog.cancel(),
    vaultSharedDialog.cancel(),
    vaultSharedSetupDialog.cancel(),
    vaultTunnelDialog.cancel(),
  ]).then(
    () => true,
    () => false,
  );
  const ownedVault = vaultBackend.isVaultWorkspace;
  const releaseApplicationLock = holdApplicationLock();
  clearFortinetIPsecDrafts();
  vaultLockMonitor.deactivate();
  if (ownedVault) retireVaultUpdates();
  activeHelloVerification?.abort();
  // An authenticated vault must stay locked even if legacy app authentication
  // has never been configured. Never refresh legacy storage while it owns SQL.
  if (ownedVault) authSession.remember({ configured: true }, false);
  authSession.lock();
  if (ownedVault) {
    for (const window of BrowserWindow.getAllWindows()) {
      if (
        !window.isDestroyed() &&
        windowCloseCoordinators.has(window) &&
        !window.webContents.isDestroyed()
      )
        try {
          window.webContents.send('vault:locked');
        } catch {
          // A renderer may disappear during notification. Native key retirement must continue.
        }
    }
  }
  const bitwardenCLIStopped = stopVaultBitwardenCLIUnlock().then(
    () => true,
    () => false,
  );
  const vaultStopped = vaultBackend.stop().then(
    () => true,
    () => false,
  );
  const sshStopped = vaultSshIpc.closeAll().then(
    () => true,
    () => false,
  );
  const serialStopped = sealedSerial.closeAll().then(
    () => true,
    () => false,
  );
  const webStopped = vaultWebIpc.closeAll().then(
    () => true,
    () => false,
  );
  const rdpStopped = stopVaultRdpSessions().then(
    () => true,
    () => false,
  );
  const vncStopped = stopVaultVncSessions().then(
    () => true,
    () => false,
  );
  try {
    cancelAllUserOperations();
    const owners = sender
      ? [BrowserWindow.fromWebContents(sender)]
      : BrowserWindow.getAllWindows().filter((window) => windowCloseCoordinators.has(window));
    const senders = sender
      ? [sender]
      : owners
          .filter((window) => window && !window.isDestroyed())
          .map((window) => window!.webContents);
    for (const owner of senders) {
      backupImportSelections.delete(owner);
      sshPrivateKeySelections.delete(owner);
      sshCertificateSelections.delete(owner);
      mremoteImportAnalysis.get(owner)?.abort();
      mremoteImportAnalysis.delete(owner);
      mremoteImportSelections.delete(owner);
    }
    sshBackend.prepareForLock();
    sshBackend.closeAllSftp();
    sshBackend.cancelPendingConnections();
    webSurfaces.cancelTunnelReconnects();
    webSurfaces.hideAll();
    void nativeBackend?.send({ action: 'bitwarden.clear-session' }).catch(() => undefined);
    void sshBackend.setMcpLocked(true).catch(() => undefined);
    cancelPreparingRdpStarts();
    for (const owner of owners) {
      if (owner && !owner.isDestroyed()) {
        rdpClient?.cancelPendingStarts(nativeWindowHandle(owner));
        void rdpClient?.hideAll(nativeWindowHandle(owner)).catch(() => undefined);
      }
    }
    await authStateMutationQueue.catch(() => undefined);
    let refreshed = true;
    try {
      // Pending enrollment owns an empty destination. Legacy auth-status also
      // initializes SQLite and must not create a legacy DB after cancellation.
      if (!ownedVault && !creatingVault && options.refreshLegacy !== false)
        await ensureAuthSession();
    } catch {
      refreshed = false;
    }
    // A legacy settings mutation already in flight may have disabled its auth
    // while we drained the queue. It cannot remove the vault's lock boundary.
    if (ownedVault) authSession.remember({ configured: true }, false);
    authSession.lock();
    clearFortinetIPsecDrafts();
    activeHelloVerification?.abort();
    const protectedContentStopped = await creationStopped;
    const bitwardenCLIConfirmed = await bitwardenCLIStopped;
    if (!(await vaultStopped)) throw new Error('Vault shutdown could not be confirmed.');
    if (!(await sshStopped)) throw new Error('SSH shutdown could not be confirmed.');
    if (!(await serialStopped)) throw new Error('Serial shutdown could not be confirmed.');
    if (!(await vncStopped)) throw new Error('VNC shutdown could not be confirmed.');
    if (!(await rdpStopped)) throw new Error('RDP shutdown could not be confirmed.');
    if (!(await webStopped)) throw new Error('Web shutdown could not be confirmed.');
    if (!bitwardenCLIConfirmed) throw new Error('Bitwarden CLI shutdown could not be confirmed.');
    if (!protectedContentStopped)
      throw new Error('Protected content cleanup could not be confirmed.');
    if (!refreshed) throw new Error('Authentication lock could not be confirmed.');
  } finally {
    releaseApplicationLock();
  }
}

function registerIpcHandlers(
  sshBackend: NativeSshBackend,
  ipcMain: Pick<Electron.IpcMain, 'handle' | 'on'>,
): void {
  ipcMain.handle('vault:bitwarden-cli-available', (event, ...args: unknown[]) => {
    if (args.length || !isTrustedVaultSender(event)) throw Error('Invalid Bitwarden CLI request.');
    return Boolean(
      authSession.isAccessAllowed &&
      vaultBackend.unlockedWorkspaceId &&
      !vaultBackend.isSharedWorkspace,
    );
  });
  ipcMain.handle('vault:bitwarden-cli-unlock', async (event, ...args: unknown[]) => {
    if (args.length || !isTrustedVaultSender(event)) throw Error('Invalid Bitwarden CLI request.');
    const sender = event.sender;
    const parent = BrowserWindow.fromWebContents(sender);
    if (!parent) throw Error('Bitwarden CLI unlock is unavailable.');
    const abort = new AbortController();
    const cancel = () => abort.abort();
    const navigation = (
      _event: Electron.Event,
      _url: string,
      inPlace: boolean,
      mainFrame: boolean,
    ) => {
      if (mainFrame && !inPlace) cancel();
    };
    sender.on('did-start-navigation', navigation);
    sender.once('render-process-gone', cancel);
    sender.once('destroyed', cancel);
    try {
      return await runAuthorizedOperation((epoch) => {
        requireNativeResourcesRunning();
        const accepted = () =>
          !abort.signal.aborted &&
          isAuthorizationEpochCurrent(epoch) &&
          isTrustedVaultSender(event);
        return vaultBitwardenCLIUnlock.unlock({
          accepted,
          signal: abort.signal,
          prompt: (context, signal) =>
            vaultBitwardenCLIUnlockDialog.open(parent, accepted, context, signal),
        });
      });
    } finally {
      sender.removeListener('did-start-navigation', navigation);
      sender.removeListener('render-process-gone', cancel);
      sender.removeListener('destroyed', cancel);
    }
  });
  ipcMain.handle('vault:edit-tunnel', async (event, ...args: unknown[]) => {
    if (!isTrustedVaultSender(event) || args.length !== 1)
      throw Error('Invalid tunnel editor request.');
    const parent = BrowserWindow.fromWebContents(event.sender);
    if (!parent) throw Error('Tunnel editor unavailable.');
    return vaultTunnelDialog.open(parent, () => isTrustedVaultSender(event), args[0]);
  });
  ipcMain.handle('vault:show-notes', async (event, ...args: unknown[]) => {
    if (!isTrustedVaultSender(event) || args.length !== 1)
      throw new Error('Invalid notes request.');
    const parent = BrowserWindow.fromWebContents(event.sender);
    if (!parent) throw new Error('Stored notes are unavailable.');
    await vaultNotesDialog.open(parent, () => isTrustedVaultSender(event), args[0]);
  });
  ipcMain.handle('vault:show-credentials', async (event, ...args: unknown[]) => {
    if (!isTrustedVaultSender(event) || args.length !== 1)
      throw new Error('Invalid credentials request.');
    const parent = BrowserWindow.fromWebContents(event.sender);
    if (!parent) throw new Error('Credentials are unavailable.');
    await vaultCredentialsDialog.open(parent, () => isTrustedVaultSender(event), args[0]);
  });
  for (const action of ['read', 'install-folder', 'install-zip', 'cleanup'] as const) {
    ipcMain.handle(`vault:bitwarden-${action}`, async (event, ...args: unknown[]) => {
      if (args.length || !isTrustedVaultSender(event))
        throw Error('Bitwarden installation is unavailable.');
      const parent = BrowserWindow.fromWebContents(event.sender);
      const epoch = authSession.authorizationEpoch;
      const frame = event.senderFrame;
      let valid = true;
      const invalidate = () => {
        valid = false;
      };
      const navigation = (
        _event: Electron.Event,
        _url: string,
        inPlace: boolean,
        mainFrame: boolean,
      ) => {
        if (mainFrame && !inPlace) invalidate();
      };
      const accepted = () =>
        Boolean(
          valid &&
          parent &&
          !parent.isDestroyed() &&
          event.sender.mainFrame === frame &&
          isTrustedVaultSender(event) &&
          isAuthorizationEpochCurrent(epoch),
        );
      if (!parent || !accepted()) throw Error('Bitwarden installation is unavailable.');
      event.sender.on('did-start-navigation', navigation);
      event.sender.on('render-process-gone', invalidate);
      event.sender.on('destroyed', invalidate);
      try {
        if (action === 'read') {
          const workspaceId = vaultBackend.unlockedWorkspaceId;
          if (!workspaceId) throw Error('Bitwarden installation is unavailable.');
          return await vaultBackend.bitwardenInstallationPlan(
            { workspaceId, minimumRevision: '0' },
            accepted,
          );
        }
        if (action === 'cleanup')
          return await vaultBackend.cleanupBitwardenInstallations(
            accepted,
            (operation, descriptor, submit) =>
              vaultReauthenticationDialog.open(parent, accepted, operation, descriptor, submit),
          );
        const archive = action === 'install-zip';
        const choose = archive
          ? vaultBackend.chooseBitwardenZip.bind(vaultBackend)
          : vaultBackend.chooseBitwardenFolder.bind(vaultBackend);
        return await choose(
          async () => {
            const selection = await showCoordinatedOpenDialog(parent, {
              title: archive
                ? 'Import Bitwarden browser extension ZIP'
                : 'Import unpacked Bitwarden browser extension folder',
              properties: archive ? ['openFile'] : ['openDirectory'],
              ...(archive ? { filters: [{ name: 'Extension ZIP', extensions: ['zip'] }] } : {}),
            });
            if (selection.canceled) return null;
            if (selection.filePaths.length !== 1)
              throw Error('Invalid Bitwarden package selection.');
            return selection.filePaths[0];
          },
          accepted,
          (operation, descriptor, submit) =>
            vaultReauthenticationDialog.open(parent, accepted, operation, descriptor, submit),
        );
      } finally {
        invalidate();
        event.sender.removeListener('did-start-navigation', navigation);
        event.sender.removeListener('render-process-gone', invalidate);
        event.sender.removeListener('destroyed', invalidate);
      }
    });
  }
  const vaultProtectionOptions: Parameters<typeof registerVaultProtectionIpc>[0] = {
    ipc: ipcMain,
    host: vaultBackend,
    dialog: vaultMigrationSetupDialog,
    osDialog: vaultOSMigrationDialog,
    rootDialog: vaultRootSetupDialog,
    // The platform storage-fault matrix in #495 gates packaged availability.
    allowDatabaseEncryption:
      !app.isPackaged && (process.arch === 'x64' || process.arch === 'arm64'),
    restartUpgrade: () => {
      app.relaunch({
        args: [
          ...process.argv.slice(1).filter((arg) => arg !== '--prepare-vault-protection'),
          '--prepare-vault-protection',
        ],
      });
      app.exit(0);
    },
    trusted: (event) => isTrustedVaultSender(event) && !isQuitting && !authLockRequested,
    parent: (event) => BrowserWindow.fromWebContents(event.sender) ?? undefined,
    requireAccess: () => authSession.requireUnlocked(),
    canStart: () => !isQuitting && !quitCleanupStarted && !nativeResourceShutdownPromise,
    hold: () => authSession.holdLock(),
    quiesce: async (parent, retainVaultOwner = false) => {
      if (!(await sshBackend.prepareEditClose())) return false;
      const active = BrowserWindow.getAllWindows().reduce(
        (count, window) =>
          count + (windowCloseCoordinators.get(window)?.connectedSessionCount ?? 0),
        0,
      );
      if (active > 0 && !(await requestRendererCloseConfirmation(parent, active, 'quit')))
        return false;
      await sshBackend.finishEditClose();
      await withBitwardenBrowserTimeout(
        webSurfaces.flushAndCloseAll(),
        30_000,
        'Browser shutdown could not be confirmed.',
      );
      await Promise.all(
        BrowserWindow.getAllWindows().map((window) => requestRendererTeardown(window)),
      );
      if (retainVaultOwner) await shutdownNativeResourcesRetainingVault();
      else await shutdownNativeResources();
      return true;
    },
    restart: () => {
      app.relaunch({ args: process.argv.slice(1) });
      app.exit(0);
    },
    fatal: () => {
      dialog.showErrorBox(
        'Wormhole',
        'Workspace preparation stopped because cleanup could not be confirmed. Close Wormhole and reopen it to continue safely.',
      );
      app.exit(1);
    },
  };
  registerVaultProtectionIpc(vaultProtectionOptions);
  registerVaultLocalBackupIpc({
    ipc: ipcMain,
    host: vaultBackend,
    trusted: vaultProtectionOptions.trusted,
    parent: vaultProtectionOptions.parent,
    pickExport: async (parent) => {
      const date = new Date().toISOString().slice(0, 10);
      const selection = await showCoordinatedSaveDialog(parent, {
        title: 'Save encrypted vault backup',
        defaultPath: path.join(app.getPath('documents'), `wormhole-vault-${date}.whvault`),
        filters: [{ name: 'Wormhole vault backup', extensions: ['whvault'] }],
      });
      if (selection.canceled || !selection.filePath) return null;
      const destination = selection.filePath;
      return path.extname(destination) ? destination : `${destination}.whvault`;
    },
    pickRestore: async (parent) => {
      const selection = await showCoordinatedOpenDialog(parent, {
        title: 'Open encrypted vault backup',
        properties: ['openFile'],
        filters: [{ name: 'Wormhole vault backup', extensions: ['whvault'] }],
      });
      return !selection.canceled && selection.filePaths.length === 1
        ? selection.filePaths[0]
        : null;
    },
    authenticate: (parent, accepted) => (operation, descriptor, submit) =>
      vaultReauthenticationDialog.open(parent, accepted, operation, descriptor, submit),
    restart: async () => {
      await shutdownNativeResources();
      vaultProtectionOptions.restart();
    },
  });
  registerVaultUnprotectedIpc({
    ...vaultProtectionOptions,
    host: vaultBackend,
    activate: () => {
      rememberAuthState(vaultAuthState(), false);
      authSession.markUnlocked();
    },
    retire: () => lockApplication(),
    restartUpgrade: vaultProtectionOptions.restartUpgrade!,
  });
  const vaultResumeOptions = {
    ipc: ipcMain,
    host: vaultBackend,
    dialog: vaultReauthenticationDialog,
    parent: (event: IpcMainInvokeEvent) => BrowserWindow.fromWebContents(event.sender) ?? undefined,
    trusted: (event: IpcMainInvokeEvent) =>
      isTrustedVaultSender(event) && !isQuitting && !authLockRequested,
    quiesced: () => !!vaultMigrationBoot.migrationSessionData,
    retire: () => lockApplication(),
    activate: () => {
      rememberAuthState(vaultAuthState(), false);
      authSession.markUnlocked();
    },
  };
  registerVaultMigrationIpc(vaultResumeOptions);
  registerVaultRootRotationIpc(vaultResumeOptions);
  registerVaultOSMigrationIpc({ ...vaultResumeOptions, fatal: vaultProtectionOptions.fatal });
  registerVaultUpgradeIpc({
    ...vaultResumeOptions,
    dialog: vaultUpgradeSetupDialog,
    hold: () => authSession.holdLock(),
    restart: () => {
      app.relaunch({
        args: process.argv.slice(1).filter((arg) => arg !== '--prepare-vault-protection'),
      });
      app.exit(0);
    },
    fatal: () => {
      dialog.showErrorBox(
        'Wormhole',
        'Workspace preparation stopped because cleanup could not be confirmed. Close Wormhole and reopen it to continue safely.',
      );
      app.exit(1);
    },
  });
  ipcMain.handle('vault:create', async (event, ...args: unknown[]) => {
    if (!isTrustedVaultSender(event) || args.length)
      throw new Error('Invalid vault creation request.');
    const startup = await vaultBackend.startup();
    if (!isTrustedVaultSender(event) || startup.slots || !startup.newWorkspace)
      throw new Error('Vault creation unavailable.');
    const parent = BrowserWindow.fromWebContents(event.sender);
    if (!parent) throw new Error('Vault creation unavailable.');
    return vaultCreateDialog.open(parent, () => isTrustedVaultSender(event));
  });
  ipcMain.handle('vault:profile-status', (event, ...args: unknown[]) => {
    if (!isTrustedVaultSender(event) || args.length) throw Error('Invalid vault profile request.');
    if (
      isQuitting ||
      authLockRequested ||
      !authSession.isAccessAllowed ||
      !vaultBackend.unlockedWorkspaceId
    )
      throw Error('Vault profile unavailable.');
    const status = vaultLockMonitor.profileStatus;
    if (!status) throw Error('Vault profile unavailable.');
    return status;
  });
  ipcMain.handle('vault:tighten-local-profile', async (event, ...args: unknown[]) => {
    const accepted = () =>
      !isQuitting &&
      !authLockRequested &&
      authSession.isAccessAllowed &&
      isTrustedVaultSender(event);
    if (args.length || !accepted()) throw Error('Invalid vault profile request.');
    const parent = BrowserWindow.fromWebContents(event.sender);
    if (!parent) throw Error('Local profile change unavailable.');
    await vaultBackend.tightenLocalProfile(
      (operation, descriptor, submit) =>
        vaultReauthenticationDialog.open(
          parent,
          () => accepted() && vaultBackend.unlockedWorkspaceId === descriptor.vaultId,
          operation,
          descriptor,
          submit,
        ),
      accepted,
      () => lockApplication(),
    );
  });
  ipcMain.handle('vault:tighten-shared-profile', async (event, ...args: unknown[]) => {
    const accepted = () =>
      !isQuitting &&
      !authLockRequested &&
      authSession.isAccessAllowed &&
      isTrustedVaultSender(event);
    if (args.length || !accepted()) throw Error('Invalid shared profile request.');
    const parent = BrowserWindow.fromWebContents(event.sender);
    if (!parent) throw Error('Shared profile change unavailable.');
    await vaultBackend.tightenSharedProfile(
      (startup, current, submit) =>
        vaultSharedDialog.open(parent, current, 'tighten-profile', startup, submit),
      accepted,
      () => lockApplication(),
    );
  });
  ipcMain.handle('vault:create-shared-workspace', async (event, ...args: unknown[]) => {
    const trusted = () => authLocksInProgress === 0 && isTrustedVaultSender(event);
    if (!trusted() || args.length) throw Error('Invalid shared workspace setup request.');
    const startup = await vaultBackend.startup();
    const localWorkspace = vaultBackend.unlockedWorkspaceId;
    const fresh = isSharedInitialStartup(startup);
    const accepted = () =>
      trusted() &&
      !vaultBackend.isSharedWorkspace &&
      (fresh
        ? !vaultBackend.isVaultWorkspace
        : localWorkspace !== undefined && vaultBackend.unlockedWorkspaceId === localWorkspace);
    const parent = BrowserWindow.fromWebContents(event.sender);
    if (!parent || !accepted()) throw Error('Shared workspace setup is unavailable.');
    const completion = await vaultSharedSetupDialog.open(
      parent,
      accepted,
      fresh ? trusted : accepted,
      !fresh,
    );
    if (completion && 'admitted' in completion && trusted()) {
      rememberAuthState(vaultAuthState(), false);
      authSession.markUnlocked();
    }
    if (trusted()) return completion;
  });
  registerSharedAdminRecoveryIpc({
    ipc: ipcMain,
    host: vaultBackend,
    dialog: vaultSharedSetupDialog,
    trusted: (event) => authLocksInProgress === 0 && isTrustedVaultSender(event),
    parent: (event) => BrowserWindow.fromWebContents(event.sender),
    activate: () => {
      rememberAuthState(vaultAuthState(), false);
      authSession.markUnlocked();
    },
  });
  registerSharedRecoveryBackupIpc({
    ipc: ipcMain,
    host: vaultBackend,
    dialog: vaultSharedSetupDialog,
    trusted: (event) => authLocksInProgress === 0 && isTrustedVaultSender(event),
    parent: (event) => BrowserWindow.fromWebContents(event.sender),
  });
  registerSharedAccountResetIpc({
    ipc: ipcMain,
    host: vaultBackend,
    dialog: vaultSharedSetupDialog,
    trusted: (event) => authLocksInProgress === 0 && isTrustedVaultSender(event),
    parent: (event) => BrowserWindow.fromWebContents(event.sender),
  });
  registerSharedAdministrationIpc({
    ipc: ipcMain,
    host: vaultBackend,
    dialog: vaultSharedSetupDialog,
    currentDeviceRevoked: requestAutomaticVaultLock,
    trusted: (event) => authLocksInProgress === 0 && isTrustedVaultSender(event),
    parent: (event) => BrowserWindow.fromWebContents(event.sender),
  });
  registerSharedRecoveryInspectionIpc({
    ipc: ipcMain,
    host: vaultBackend,
    dialog: vaultSharedSetupDialog,
    trusted: (event) => authLocksInProgress === 0 && isTrustedVaultSender(event),
    parent: (event) => BrowserWindow.fromWebContents(event.sender),
  });
  registerSharedAuthenticationIpc({
    ipc: ipcMain,
    host: vaultBackend,
    dialog: vaultSharedDialog,
    trusted: isTrustedVaultSender,
    parent: (event) => BrowserWindow.fromWebContents(event.sender),
    activate: () => {
      rememberAuthState(vaultAuthState(), false);
      authSession.markUnlocked();
    },
  });
  registerSharedCatalogIpc({ ipc: ipcMain, host: vaultBackend, trusted: isTrustedVaultSender });
  registerSharedNodeEditIpc({
    ipc: ipcMain,
    host: vaultBackend,
    trusted: isTrustedVaultSender,
    dialog: vaultSharedDialog,
    parent: (event) => BrowserWindow.fromWebContents(event.sender),
  });
  registerSharedChangesIpc({ ipc: ipcMain, host: vaultBackend, trusted: isTrustedVaultSender });
  registerSharedCertificateRenewalIpc({
    ipc: ipcMain,
    host: vaultBackend,
    trusted: isTrustedVaultSender,
    lockAfterCARotation: () => lockApplication(),
    pickTLSExport: async (event) => {
      const window = BrowserWindow.fromWebContents(event.sender);
      if (!window || window.isDestroyed()) return null;
      const result = await showCoordinatedSaveDialog(window, {
        title: 'Export signed workspace trust bundle',
        defaultPath: 'wormhole-workspace.whtls',
        filters: [{ name: 'Wormhole trust bundle', extensions: ['whtls'] }],
      });
      return result.canceled ? null : (result.filePath ?? null);
    },
    confirmRecoveryKit: (event, startup, current, submit) => {
      const parent = BrowserWindow.fromWebContents(event.sender);
      if (!parent) throw Error('Recovery kit authentication unavailable.');
      return vaultSharedDialog.open(parent, current, 'refresh-recovery-kit', startup, submit);
    },
    pickRecoveryKit: async (event, intent) => {
      const window = BrowserWindow.fromWebContents(event.sender);
      if (!window || window.isDestroyed()) return null;
      const filters = [{ name: 'Wormhole organisation recovery kit', extensions: ['whrecovery'] }];
      if (intent === 'open') {
        const result = await showCoordinatedOpenDialog(window, {
          title: 'Open the existing organisation recovery kit',
          properties: ['openFile'],
          filters,
        });
        return result.canceled ? null : (result.filePaths[0] ?? null);
      }
      const result = await showCoordinatedSaveDialog(window, {
        title: 'Save the updated organisation recovery kit',
        defaultPath: 'wormhole-organisation-updated.whrecovery',
        filters,
      });
      return result.canceled ? null : (result.filePath ?? null);
    },
  });
  registerSharedConnectionContextIpc({
    ipc: ipcMain,
    host: vaultBackend,
    trusted: isTrustedVaultSender,
  });
  const activateVaultSession = () => {
    if (!vaultBackend.unlockedWorkspaceId) throw new Error('Vault is locked.');
    rememberAuthState(vaultAuthState(), false);
    authSession.markUnlocked();
  };
  registerVaultPresenceIpc({
    ipc: ipcMain,
    host: vaultBackend,
    trusted: (event) => authLocksInProgress === 0 && isTrustedVaultSender(event),
    owner: (event) => BrowserWindow.fromWebContents(event.sender),
    nativeHandle: nativeWindowHandle,
    confirm: (parent, current) => (operation, descriptor, submit) =>
      vaultReauthenticationDialog.open(
        parent,
        () => current() && vaultBackend.unlockedWorkspaceId === descriptor.vaultId,
        operation,
        descriptor,
        (input, dialog) =>
          operation === 'hello-enroll'
            ? runWithNativeAuthenticationWindow(dialog, () =>
                submit(input, nativeWindowHandle(dialog)),
              )
            : submit(input),
      ),
    unlocked: activateVaultSession,
  });
  registerVaultIpc(
    ipcMain,
    vaultBackend,
    isTrustedVaultSender,
    activateVaultSession,
    (event) => async (operation, descriptor, submit) => {
      const parent = BrowserWindow.fromWebContents(event.sender);
      if (!parent || !isTrustedVaultSender(event))
        throw Error('Authentication dialog unavailable.');
      return vaultReauthenticationDialog.open(
        parent,
        () =>
          isTrustedVaultSender(event) && vaultBackend.unlockedWorkspaceId === descriptor.vaultId,
        operation,
        descriptor,
        submit,
      );
    },
    (event, input) =>
      prepareVaultCredentialSelections(
        input,
        event.sender,
        sshPrivateKeySelections,
        sshCertificateSelections,
        requireAuthorizationEpoch,
      ),
    (path) => shell.openPath(path),
  );
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
  ipcMain.on('window:set-titlebar-theme', (event, value: unknown) => {
    const owner = BrowserWindow.fromWebContents(event.sender);
    if (!owner || owner.isDestroyed() || !windowCloseCoordinators.has(owner)) return;
    if (value !== 'light' && value !== 'dark') return;
    syncNativeTitlebarTheme(owner, value, process.platform);
    treeTooltips.setColorScheme(owner, value);
  });

  ipcMain.on('startup:ready', (event) => {
    const owner = BrowserWindow.fromWebContents(event.sender);
    if (!owner || owner.isDestroyed() || failedWorkspaceWindows.has(owner)) return;
    startupReadyWindows.add(owner);
    if (owner.isVisible()) owner.setOpacity(1);
    scheduleUnlockedBackgroundWork();
  });

  ipcMain.on('diagnostics:renderer-failure', (event, reason: unknown) => {
    if (
      reason !== 'uncaught-error' &&
      reason !== 'unhandled-rejection' &&
      reason !== 'workspace-mount'
    )
      return;
    const owner = BrowserWindow.fromWebContents(event.sender);
    const frame = event.senderFrame;
    if (
      !owner ||
      owner.isDestroyed() ||
      !windowCloseCoordinators.has(owner) ||
      !frame ||
      frame !== event.sender.mainFrame ||
      !isTrustedRendererNavigation(frame.url, productionRendererPath)
    )
      return;
    recordDiagnostic('ERR', 'Workspace renderer failure (' + reason + ')');
  });

  ipcMain.on('workspace:failed', (event) => {
    const owner = BrowserWindow.fromWebContents(event.sender);
    if (
      !owner ||
      owner.isDestroyed() ||
      !windowCloseCoordinators.has(owner) ||
      failedWorkspaceWindows.has(owner)
    )
      return;
    recordDiagnostic('ERR', 'Workspace React error boundary activated');
    failedWorkspaceWindows.add(owner);
    windowCloseCoordinators.get(owner)?.updateActiveCount(0);
    startupReadyWindows.delete(owner);
    owner.setOpacity(1);
    void serializeAuthOperation(async () => {
      authSession.lock();
      clearFortinetIPsecDrafts();
      await runWindowTeardown(
        () =>
          withBitwardenBrowserTimeout(
            webSurfaces.flushAndCloseForWindow(owner),
            30_000,
            'Workspace failure cleanup timed out.',
          ),
        async () => {
          try {
            // Flush can fail before disposing surfaces. Always remove their native views,
            // including pending opens, so they cannot cover the recovery screen.
            webSurfaces.closeForWindow(owner);
          } finally {
            await shutdownNativeResources();
          }
        },
      );
    }).catch(() => reportWarning('Workspace failure cleanup did not finish cleanly.'));
  });

  ipcMain.handle('startup:load', async (event, ...args: unknown[]) => {
    if (args.length > 1) throw new Error('Invalid startup request.');
    const request = parseThemeStartupRequest(args[0]);
    if (!isTrustedVaultSender(event)) throw new Error('Invalid startup request.');
    const metadata = await vaultBackend.startup();
    if (!isTrustedVaultSender(event)) throw new Error('Startup owner is no longer available.');
    // The pre-unlock request has no arguments. Full workspace loads always
    // carry the preload's settings request and use the owning authorization path.
    if (args.length === 0) return metadata;
    if (vaultBackend.isVaultWorkspace) {
      const startup = await runAuthorizedOperation(async () => {
        if (!vaultBackend.unlockedWorkspaceId) throw new Error('Vault is locked.');
        const settings = await vaultBackend.preferences();
        const workspace = await vaultBackend.workspace();
        return {
          auth: vaultAuthState(),
          settings,
          workspace,
          themeMigration: { handled: false, migrated: false },
          migration: { status: 'vault', migrated: 0, missing: 0 },
          migrationFailed: false,
        };
      });
      if (!isTrustedVaultSender(event)) throw new Error('Startup owner is no longer available.');
      confirmOnWindowClose = startup.settings.confirmOnWindowClose;
      return startup;
    }
    return serializeAuthOperation(async () => {
      if (!isTrustedVaultSender(event) || vaultBackend.isVaultWorkspace) {
        throw new Error('Startup owner is no longer available.');
      }
      const startup = await runBackend<StartupResponse>('startup', request);
      if (!isTrustedVaultSender(event) || vaultBackend.isVaultWorkspace) {
        throw new Error('Startup owner is no longer available.');
      }
      if (startup.auth.configured && startup.workspace) {
        throw new Error('Wormhole could not load the locked workspace.');
      }
      rememberAuthState(startup.auth, false);
      confirmOnWindowClose = normalizeWindowCloseConfirmation(
        startup.settings.confirmOnWindowClose,
      );
      startup.settings.confirmOnWindowClose = confirmOnWindowClose;
      scheduleStartupUpdateCheck(startup.settings);
      if (startup.migrationFailed) {
        recordDiagnostic(
          'ERR',
          'Credential Manager migration failed. It will be retried next launch.',
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
    const verificationEpoch = authSession.authorizationEpoch;
    return serializeAuthOperation(async () => {
      await ensureAuthSession();
      authSession.requireVerificationEpoch(verificationEpoch);
      const result = await runBackend<StartupUnlockResponse>('startup-unlock', request);
      if (result.succeeded) {
        if (!result.workspace) throw new Error('Wormhole returned no workspace.');
        authSession.markUnlocked(verificationEpoch);
      } else if (result.workspace) {
        throw new Error('Wormhole could not verify the workspace lock.');
      }
      return result;
    });
  });

  ipcMain.handle('workspace:load', async (event) => {
    return runAuthorizedOperation(async () => {
      if (vaultBackend.isVaultWorkspace) {
        if (!isTrustedVaultSender(event)) throw new Error('Invalid workspace request.');
        const workspace = await vaultBackend.workspace();
        if (!isTrustedVaultSender(event))
          throw new Error('Workspace owner is no longer available.');
        return workspace;
      }
      const workspace = await runBackend<WorkspaceResponse>('workspace');
      console.info(
        `[Wormhole] Workspace loaded: ${workspace.tree.length} roots, ${workspace.credentials.length} credentials, ${workspace.tunnels.length} tunnels.`,
      );
      return workspace;
    });
  });

  ipcMain.handle('workspace:node-notes', async (_event, value: unknown) => {
    const request = parseWorkspaceNodeRequest(value);
    return runAuthorizedOperation(() =>
      runBackend<{ notes: string }>('workspace-node-notes', request),
    );
  });

  ipcMain.handle('workspace:move-nodes', async (_event, value: unknown) => {
    const request = parseWorkspaceMoveNodesRequest(value);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<{ moved: boolean }>('workspace-move-nodes', request);
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
    const selection = await showCoordinatedOpenDialog(owner, options);
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
                reuseExisting: options.reuseExisting,
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
            reuseExisting: options.reuseExisting,
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
      selection.structureOnly !== options.structureOnly ||
      selection.reuseExisting !== options.reuseExisting
    ) {
      throw new Error('Analyze the mRemoteNG file with these options before importing it.');
    }
    const result = parseMRemoteImportResult(
      await runOwnedNativeOperation(event.sender, 'mremote-import', 'mremote.import.commit', {
        path: selection.path,
        password: options.password,
        structureOnly: options.structureOnly,
        reuseExisting: options.reuseExisting,
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
    const selection = await showCoordinatedSaveDialog(owner, options);
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
    const pickerEpoch = await serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return authSession.authorizationEpoch;
    });
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
    const selection = await showCoordinatedOpenDialog(owner, options);
    if (selection.canceled || selection.filePaths.length !== 1) return null;
    const selectedPath = selection.filePaths[0];
    return serializeAuthOperation(async () => {
      if (!isAuthorizationEpochCurrent(pickerEpoch)) return null;
      const inspected = parseBackupInspectResponse(
        await runBackend<BackupInspectBackendResponse>('backup-inspect', {
          path: selectedPath,
        }),
      );
      if (!isAuthorizationEpochCurrent(pickerEpoch)) return null;
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
          { name: 'All files', extensions: ['*'] },
          {
            name: 'SSH private keys (including extension-less id_* files)',
            extensions: ['key', 'pem', '*'],
          },
        ],
      };
      const selection = await showCoordinatedOpenDialog(owner, options);
      if (selection.canceled || selection.filePaths.length !== 1) return null;
      requireAuthorizationEpoch(authorizationEpoch);
      const selectedPath = selection.filePaths[0];
      const selected: SshPrivateKeySelection = {
        id: randomUUID(),
        path: selectedPath,
        fileName: sshPrivateKeyDisplayName(selectedPath),
        authorizationEpoch,
      };
      let suggestedCertificate: { selectionId: string; fileName: string } | undefined;
      const certificatePath = `${selectedPath}-cert.pub`;
      const info = await statFile(certificatePath).catch(() => null);
      requireAuthorizationEpoch(authorizationEpoch);
      if (info?.isFile() && info.size > 0 && info.size <= 16 * 1024) {
        const certificate = {
          id: randomUUID(),
          path: certificatePath,
          fileName: sshPrivateKeyDisplayName(certificatePath),
          authorizationEpoch,
        };
        sshCertificateSelections.set(event.sender, certificate);
        suggestedCertificate = { selectionId: certificate.id, fileName: certificate.fileName };
      }
      sshPrivateKeySelections.set(event.sender, selected);
      return { selectionId: selected.id, fileName: selected.fileName, suggestedCertificate };
    });
  });

  ipcMain.handle('credential:select-ssh-certificate', async (event) => {
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      const authorizationEpoch = authSession.authorizationEpoch;
      const owner = BrowserWindow.fromWebContents(event.sender);
      const options: Electron.OpenDialogOptions = {
        title: 'Select OpenSSH user certificate',
        properties: ['openFile'],
        filters: [
          { name: 'OpenSSH user certificates (*-cert.pub)', extensions: ['pub'] },
          { name: 'All files', extensions: ['*'] },
        ],
      };
      const selection = await showCoordinatedOpenDialog(owner, options);
      if (selection.canceled || selection.filePaths.length !== 1) return null;
      const selectedPath = selection.filePaths[0];
      const info = await statFile(selectedPath).catch(() => null);
      requireAuthorizationEpoch(authorizationEpoch);
      if (!info?.isFile() || info.size <= 0 || info.size > 16 * 1024) {
        throw new Error('Select a regular OpenSSH user certificate file up to 16 KiB.');
      }
      const selected = {
        id: randomUUID(),
        path: selectedPath,
        fileName: sshPrivateKeyDisplayName(selectedPath),
        authorizationEpoch,
      };
      sshCertificateSelections.set(event.sender, selected);
      return { selectionId: selected.id, fileName: selected.fileName };
    });
  });

  ipcMain.handle('credential:discard-ssh-certificate', (event, value: unknown) => {
    const selectionId = isRecord(value) ? value.selectionId : undefined;
    if (!isUuid(selectionId)) throw new Error('SSH certificate selection is invalid.');
    if (sshCertificateSelections.get(event.sender)?.id !== selectionId) return { discarded: false };
    sshCertificateSelections.delete(event.sender);
    return { discarded: true };
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
      if (selection) requireAuthorizationEpoch(selection.authorizationEpoch);
      const certificate = request.certificateSelectionId
        ? sshCertificateSelections.get(event.sender)
        : undefined;
      if (request.certificateSelectionId && certificate?.id !== request.certificateSelectionId) {
        throw new Error('Select the SSH certificate again.');
      }
      if (certificate) requireAuthorizationEpoch(certificate.authorizationEpoch);
      const {
        privateKeySelectionId: _selectionId,
        certificateSelectionId: _certificateSelectionId,
        ...backendRequest
      } = request;
      const credential = await runBackend<WorkspaceCredential>('credential-create', {
        ...backendRequest,
        ...(selection ? { privateKeyPath: selection.path } : {}),
        ...(certificate ? { certificatePath: certificate.path } : {}),
      });
      if (selection) sshPrivateKeySelections.delete(event.sender);
      if (certificate) sshCertificateSelections.delete(event.sender);
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
      if (selection) requireAuthorizationEpoch(selection.authorizationEpoch);
      const certificate = request.certificateSelectionId
        ? sshCertificateSelections.get(event.sender)
        : undefined;
      if (request.certificateSelectionId && certificate?.id !== request.certificateSelectionId) {
        throw new Error('Select the SSH certificate again.');
      }
      if (certificate) requireAuthorizationEpoch(certificate.authorizationEpoch);
      const {
        privateKeySelectionId: _selectionId,
        certificateSelectionId: _certificateSelectionId,
        ...backendRequest
      } = request;
      const credential = await runBackend<WorkspaceCredential>('credential-update', {
        ...backendRequest,
        ...(selection ? { privateKeyPath: selection.path } : {}),
        ...(certificate ? { certificatePath: certificate.path } : {}),
      });
      if (selection) sshPrivateKeySelections.delete(event.sender);
      if (certificate) sshCertificateSelections.delete(event.sender);
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

  ipcMain.handle('settings:set-ssh-terminal-theme', async (_event, value: unknown) => {
    if (!isSshTerminalTheme(value)) throw new Error('SSH terminal theme is invalid.');
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<{ updated: boolean }>('settings-set-ssh-terminal-theme', { theme: value });
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

  ipcMain.handle('settings:set-confirm-on-window-close', async (_event, value: unknown) => {
    if (typeof value !== 'boolean') throw new Error('Window close setting is invalid.');
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      const result = parseWindowCloseSettingUpdate(
        await runBackend<unknown>('settings-set-confirm-on-window-close', { enabled: value }),
      );
      confirmOnWindowClose = value;
      return result;
    });
  });

  ipcMain.handle('settings:set-sidebar-pinned', async (_event, value: unknown) => {
    if (typeof value !== 'boolean') throw new Error('Sidebar pin setting is invalid.');
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return runBackend<{ updated: boolean }>('settings-set-sidebar-pinned', { pinned: value });
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

  ipcMain.handle('settings:set-update-preferences', async (event, value: unknown) => {
    if (!isTrustedVaultSender(event) || !isRecord(value))
      throw new Error('Update preferences are invalid.');
    const request: VaultUpdatePreferences = {};
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
      if (!isTrustedVaultSender(event)) throw Error('Update preferences are invalid.');
      if (vaultBackend.isVaultWorkspace) {
        await vaultBackend.updatePreferences(request);
        if (request.autoCheckForUpdates)
          scheduleStartupUpdateCheck({ autoCheckForUpdates: true }, captureUpdateScope());
        else if (request.autoCheckForUpdates === false && startupUpdateTimer) {
          clearTimeout(startupUpdateTimer);
          startupUpdateTimer = undefined;
          startupUpdateScheduled = undefined;
        }
        return { updated: true };
      }
      return runBackend<{ updated: boolean }>('settings-set-update-preferences', request);
    });
  });

  ipcMain.handle('update:status', async (event) => {
    if (!isTrustedVaultSender(event)) throw Error('Invalid update request.');
    const scope = captureUpdateScope();
    const profile = await readVaultUpdateProfile(scope);
    if (!isTrustedVaultSender(event)) throw Error('Invalid update request.');
    const release = sameUpdateScope(scope, latestUpdateScope) ? latestUpdateCheck : undefined;
    return {
      currentVersion: app.getVersion(),
      result:
        release || profile === 'paranoid'
          ? applyUpdatePolicy(
              release ?? emptyUpdateResult(),
              profile,
              !!latestUpdateManifest,
              latestUpdatePublisherVerification,
            )
          : null,
    };
  });

  ipcMain.handle('visual-changelog:claim', async (event, hasChangelog: unknown) => {
    if (typeof hasChangelog !== 'boolean' || !isTrustedVaultSender(event))
      throw new Error('Visual changelog request is invalid.');
    await serializeAuthOperation(requireWorkspaceAuth);
    if (!isTrustedVaultSender(event)) throw new Error('Visual changelog request is invalid.');
    return runBackend<{ claimed: boolean }>('visual-changelog-claim', {
      appVersion: app.getVersion(),
      hasChangelog,
    });
  });

  ipcMain.handle('update:check', async (event) => {
    if (!isTrustedVaultSender(event)) throw Error('Invalid update request.');
    const result = await performUpdateCheck();
    if (!isTrustedVaultSender(event)) throw Error('Invalid update request.');
    return result;
  });

  ipcMain.handle('update:download', async (event, value: unknown) => {
    if (!isTrustedVaultSender(event) || !isRecord(value) || quitCleanupStarted || isQuitting)
      throw new Error('The update download request is invalid.');
    const scope = captureUpdateScope();
    await requireUpdateInstaller(scope);
    if (
      !isTrustedVaultSender(event) ||
      quitCleanupStarted ||
      !sameUpdateScope(scope, latestUpdateScope)
    )
      throw Error('The update download request is invalid.');
    const installerUrl = typeof value.installerUrl === 'string' ? value.installerUrl.trim() : '';
    const installerFileName =
      typeof value.installerFileName === 'string' ? value.installerFileName.trim() : '';
    const installerSha256 =
      typeof value.installerSha256 === 'string' ? value.installerSha256.trim().toLowerCase() : '';
    const installerSize =
      typeof value.installerSize === 'number' && Number.isInteger(value.installerSize)
        ? value.installerSize
        : null;
    if (
      !installerUrl ||
      !installerFileName ||
      path.basename(installerFileName) !== installerFileName ||
      (latestUpdateCheck?.updatePolicy === 'managed'
        ? installerUrl !== `managed-update:${installerFileName}`
        : !/^https:\/\//i.test(installerUrl)) ||
      !/^[0-9a-f]{64}$/.test(installerSha256) ||
      installerSize === null ||
      installerSize <= 0 ||
      !updateMatchesLatest({ installerUrl, installerFileName, installerSha256, installerSize })
    ) {
      throw new Error('The update download request is invalid.');
    }
    const target = event.sender;
    const request: NativeUpdateDownloadRequest = {
      installerUrl,
      installerFileName,
      installerSha256,
      installerSize,
      currentVersion: app.getVersion(),
      signedManifest: latestUpdateManifest,
    };
    const installerPath = await downloadUpdateInstaller(request, (downloaded, total) =>
      broadcastUpdateProgress(target, downloaded, total),
    );
    await requireUpdateInstaller(scope);
    requireUpdateScope(scope);
    if (
      !isTrustedVaultSender(event) ||
      !updateMatchesLatest(request) ||
      !isSafeInstallerPath(installerPath) ||
      path.resolve(installerPath) !== path.resolve(updateCacheRoot(), request.installerFileName)
    )
      throw Error('The installer download could not be confirmed.');
    downloadedUpdate = { path: path.resolve(installerPath), request, scope };
    return downloadedUpdate.path;
  });

  ipcMain.handle('update:install', async (event, value: unknown) => {
    if (
      !isTrustedVaultSender(event) ||
      !isRecord(value) ||
      typeof value.path !== 'string' ||
      !isSafeInstallerPath(value.path)
    ) {
      throw new Error('The installer path is invalid.');
    }
    const download = downloadedUpdate;
    if (
      !download ||
      path.resolve(value.path) !== download.path ||
      !updateMatchesLatest(download.request)
    )
      throw new Error('Download the selected update before installing it.');
    return handleDownloadedUpdate(download, () => isTrustedVaultSender(event));
  });

  ipcMain.handle('update:open-release', async (event, value: unknown) => {
    if (
      !isTrustedVaultSender(event) ||
      typeof value !== 'string' ||
      !/^https:\/\/github\.com\//i.test(value)
    ) {
      throw new Error('The release URL is invalid.');
    }
    const scope = captureUpdateScope();
    if (scope) {
      const profile = await readVaultUpdateProfile(scope);
      if (
        profile === 'paranoid' ||
        latestUpdateCheck?.updatePolicy === 'managed' ||
        !sameUpdateScope(scope, latestUpdateScope) ||
        !isTrustedVaultSender(event)
      )
        throw Error('The release URL is unavailable.');
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
    const selection = await showCoordinatedOpenDialog(owner, options);
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
    const selection = await showCoordinatedOpenDialog(owner, options);
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
    if (protocol !== 'ssh' && protocol !== 'rdp' && protocol !== 'vnc' && protocol !== 'smb') {
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

  ipcMain.handle('bitwarden:startup-state', async () => {
    return runAuthorizedOperation((authorizationEpoch) => {
      // This compatibility IPC name now serves on-demand authentication only.
      bitwardenVaultAccessed = true;
      return readBitwardenStartupState({
        readState: () => runBitwardenBackend<BitwardenCliState>('bitwarden.read'),
        ensureInstalled: () => runBitwardenBackend<BitwardenCliState>('bitwarden.ensure-installed'),
        readStatus: () => runBitwardenBackend<BitwardenCliStatusResponse>('bitwarden.status'),
        requireAuthorization: () => requireAuthorizationEpoch(authorizationEpoch),
      });
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
    if (protocol !== 'ssh' && protocol !== 'rdp' && protocol !== 'vnc' && protocol !== 'smb') {
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
    return runAuthorizedOperation(async () => {
      if (mcpApprovalWindowCoordinator.hasPendingApprovals) return { open: false };
      return webSurfaces.openBitwardenPopup(request);
    });
  });

  ipcMain.handle('web:bitwarden-popup-close', async (_event, sessionId: unknown) => {
    if (!isSshSessionId(sessionId)) throw new Error('Web session id is invalid.');
    return afterBitwardenPopupInputEvent(() => webSurfaces.closeBitwardenPopup(sessionId));
  });

  ipcMain.handle('tunnel:enter-ipsec-credential', async (event, draftId: unknown, key: unknown) => {
    if (!isTunnelIdentifier(draftId) || !isFortinetIPsecEditableSecret(key))
      throw new Error('Fortinet IPsec credential request is invalid.');
    await requireWorkspaceAuth();
    const owner = fortinetIPsecEditorOwner(event);
    const frame = event.senderFrame;
    const epoch = authSession.authorizationEpoch;
    return fortinetIPsecDrafts.enter(event.sender, draftId, epoch, key, (reference, isCurrent) => {
      const authorized = () =>
        isCurrent() &&
        !owner.isDestroyed() &&
        !authLockRequested &&
        isAuthorizationEpochCurrent(epoch) &&
        frame === event.sender.mainFrame;
      return queueFortinetIPsecSecret(key, owner, authorized).then((value) => {
        if (!authorized()) throw new FortinetIPsecEntryCancelled();
        const bytes = Buffer.from(value, 'utf8');
        try {
          return getNativeBackend()
            .send({
              action: 'tunnel.ipsec-stage',
              sessionId: reference,
              ipsecField: key,
              ipsecSecret: bytes.toString('base64'),
            })
            .then((response) => {
              if (!response.ok)
                throw new Error(response.error || 'Could not stage the Fortinet IPsec credential.');
            });
        } finally {
          bytes.fill(0);
        }
      });
    });
  });

  ipcMain.handle('tunnel:capabilities', async () => {
    return runAuthorizedOperation(async () =>
      parseTunnelCapabilities(await runBackend<unknown>('tunnel-capabilities')),
    );
  });

  ipcMain.handle('tunnel:discard-ipsec-credentials', (event, draftId: unknown) => {
    if (!isTunnelIdentifier(draftId))
      throw new Error('Fortinet IPsec credential draft is invalid.');
    fortinetIPsecEditorOwner(event);
    fortinetIPsecDrafts.discard(event.sender, draftId);
  });

  ipcMain.handle('tunnel:create', async (event, value: unknown, draftId: unknown) => {
    return saveTunnelWithNativeSecret('tunnel-create', event, value, draftId);
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

  ipcMain.handle('tunnel:update', async (event, value: unknown, draftId: unknown) => {
    return saveTunnelWithNativeSecret('tunnel-update', event, value, draftId);
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
        reportWarning('VPN tunnel test failed', error);
      }
      return { connected: false, error: message };
    } finally {
      if (!event.sender.isDestroyed()) {
        event.sender.removeListener('destroyed', cancelWhenRendererCloses);
      }
      await releaseTunnelTest(test).catch((error) => {
        reportWarning('Could not release the VPN tunnel test lease.', error);
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
      const selection = await showCoordinatedOpenDialog(owner, options);
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
      const selection = await showCoordinatedOpenDialog(owner, options);
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
      const selection = await showCoordinatedOpenDialog(owner, options);
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
      const selection = await showCoordinatedOpenDialog(owner, options);
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
      Buffer.byteLength(promptValue, 'utf8') > tunnelPromptValueMaxBytes ||
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
    const verificationEpoch = authSession.authorizationEpoch;
    return serializeAuthOperation(async () => {
      await ensureAuthSession();
      authSession.requireVerificationEpoch(verificationEpoch);
      const result = await runBackend<{ succeeded: boolean }>('auth-verify', request);
      if (result.succeeded) authSession.markUnlocked(verificationEpoch);
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

  ipcMain.handle('auth:lock', (event) => lockApplication(event.sender));

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
    const verificationEpoch = authSession.authorizationEpoch;
    if (process.platform !== 'win32') {
      return {
        succeeded: false,
        message: 'Windows Hello only works on Windows.',
      };
    }
    return serializeAuthOperation(async () => {
      await ensureAuthSession();
      authSession.requireVerificationEpoch(verificationEpoch);
      const state = currentAuthState;
      if (!state) throw new Error('Authentication state is not initialized.');
      if (state.mode !== 'windowsHello' || !state.configured) {
        return {
          succeeded: false,
          message: 'Choose Windows Hello in Settings first.',
        };
      }
      if (authLockRequested) {
        return { succeeded: false, message: 'Windows Hello was canceled.' };
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
      const ownerLifetime = new AbortController();
      activeHelloVerification = ownerLifetime;
      const cancelHello = () => ownerLifetime.abort();
      event.sender.once('destroyed', cancelHello);
      event.sender.once('did-start-loading', cancelHello);
      try {
        return await mcpApprovalWindowCoordinator.runPreemptibleOperation((approvalSignal) => {
          const signal = AbortSignal.any([approvalSignal, ownerLifetime.signal]);
          return runWithNativeAuthenticationWindow(ownerWindow, async () => {
            try {
              const result = await runBackend<{ succeeded: boolean }>(
                'auth-hello-verify',
                { ownerWindow: nativeWindowHandle(ownerWindow) },
                backendTimeoutMs,
                signal,
              );
              if (signal.aborted)
                return { succeeded: false, message: 'Windows Hello was canceled.' };
              if (result.succeeded) authSession.markUnlocked(verificationEpoch);
              return result;
            } catch (error) {
              if (signal.aborted) {
                return { succeeded: false, message: 'Windows Hello was canceled.' };
              }
              throw error;
            }
          });
        });
      } finally {
        activeHelloVerification = undefined;
        event.sender.removeListener('destroyed', cancelHello);
        event.sender.removeListener('did-start-loading', cancelHello);
      }
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
  ipcMain.handle('mcp:set-approval-mode', async (_event, mode: unknown) => {
    if (!isMcpApprovalMode(mode)) throw new Error('MCP approval mode is invalid.');
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return sshBackend.setMcpApprovalMode(mode);
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
        const authorizationEpoch = authSession.authorizationEpoch;
        await sshBackend.respondMcpApproval(approval.requestId, approval.approved);
        requireAuthorizationEpoch(authorizationEpoch);
      } finally {
        mcpApprovalWindowCoordinator.finishApproval(approval.requestId);
      }
    });
  });
  ipcMain.handle('mcp:revoke-session', async (_event, sessionId: unknown) => {
    if (!isSshSessionId(sessionId)) throw new Error('SSH session id is invalid.');
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      await sshBackend.revokeMcpSessionAccess(sessionId);
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
    if (quitCleanupStarted || isQuitting) return;
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
  ipcMain.handle('web:open', async (event, request: unknown, ...extra: unknown[]) => {
    if (vaultBackend.isVaultWorkspace && (extra.length !== 0 || !isTrustedVaultSender(event)))
      throw Error('Invalid vault web owner.');
    requireNativeResourcesRunning();
    if (!isWebOpenRequest(request)) throw new Error('Web connection request is invalid.');
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow || ownerWindow.isDestroyed())
      throw new Error('Web session owner window is unavailable.');
    if (vaultWebIpc.handles(request.sessionId)) {
      if (extra.length !== 0) throw Error('Invalid vault web owner.');
      return vaultWebIpc.open(event, request);
    }
    if (request.quickTarget) throw Error('Protected Quick Connect is unavailable.');
    return runAuthorizedOperation(
      () => {
        requireNativeResourcesRunning();
        return webSurfaces.open(ownerWindow, request, () => isTrustedVaultSender(event));
      },
      () => webSurfaces.closeForOwner(ownerWindow, request.sessionId),
    );
  });
  ipcMain.handle('web:set-bounds', async (event, request: unknown, ...extra: unknown[]) => {
    if (vaultBackend.isVaultWorkspace && (extra.length !== 0 || !isTrustedVaultSender(event)))
      throw Error('Invalid vault web owner.');
    if (!isWebBoundsRequest(request)) throw new Error('Web surface bounds are invalid.');
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow || ownerWindow.isDestroyed()) return;
    // Bounds updates are intentionally lightweight, but never make private page contents visible
    // after the native workspace was locked.
    if (!authSession.isAccessAllowed) {
      webSurfaces.hideAll();
      return;
    }
    return webSurfaces.setBounds(ownerWindow, request);
  });
  ipcMain.handle('web:command', async (event, request: unknown, ...extra: unknown[]) => {
    if (vaultBackend.isVaultWorkspace && (extra.length !== 0 || !isTrustedVaultSender(event)))
      throw Error('Invalid vault web owner.');
    if (!isWebCommandRequest(request)) throw new Error('Web browser command is invalid.');
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow || ownerWindow.isDestroyed()) return;
    if (request.operation === 'reconnect-vpn') {
      requireNativeResourcesRunning();
      return runAuthorizedOperation(async () => {
        requireNativeResourcesRunning();
        return webSurfaces.command(ownerWindow, request);
      });
    }
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      if (vaultBackend.isVaultWorkspace && !isTrustedVaultSender(event))
        throw Error('Invalid vault web owner.');
      await webSurfaces.command(ownerWindow, request);
    });
  });
  ipcMain.handle('web:close', async (event, sessionId: unknown, ...extra: unknown[]) => {
    if (vaultBackend.isVaultWorkspace && (extra.length !== 0 || !isTrustedVaultSender(event)))
      throw Error('Invalid vault web owner.');
    if (!isSshSessionId(sessionId)) throw new Error('Web session id is invalid.');
    if (vaultWebIpc.handles(sessionId)) {
      if (extra.length !== 0) throw Error('Invalid vault web owner.');
      return vaultWebIpc.close(event, sessionId);
    }
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow || ownerWindow.isDestroyed()) return;
    await webSurfaces.closeForOwner(ownerWindow, sessionId);
  });
  ipcMain.on('ssh:terminal-ack', (event, sessionId: unknown, sequence: unknown) => {
    if (
      !isSshSessionId(sessionId) ||
      typeof sequence !== 'number' ||
      !Number.isSafeInteger(sequence) ||
      sequence < 1
    )
      return;
    sshBackend.acknowledgeTerminal(event.sender, sessionId, sequence);
  });
  ipcMain.handle('ssh:open', async (event, request: unknown, ...extra: unknown[]) => {
    requireNativeResourcesRunning();
    if (
      vaultBackend.isVaultWorkspace ||
      (isRecord(request) &&
        typeof request.sessionId === 'string' &&
        vaultSshIpc.handles(request.sessionId))
    ) {
      if (extra.length !== 0 || !isTrustedVaultSender(event))
        throw Error('Invalid vault SSH owner.');
      return vaultSshIpc.open(event, request);
    }
    if (!isSshOpenRequest(request)) throw new Error('SSH open request is invalid.');
    if (vaultBackend.unlockedWorkspaceId && !isTrustedVaultSender(event))
      throw new Error('Invalid vault SSH owner.');
    return runAuthorizedOperation(
      (authorizationEpoch) => {
        requireNativeResourcesRunning();
        return sshBackend.open(request, authorizationEpoch, event.sender);
      },
      () => sshBackend.close(request.sessionId),
    );
  });
  ipcMain.handle('ssh:trust-host-key', async (_event, request: unknown) => {
    requireNativeResourcesRunning();
    if (!isSshHostKeyTrustRequest(request)) {
      throw new Error('SSH host-key trust request is invalid.');
    }
    if (vaultSshIpc.handles(request.sessionId)) throw Error('Use protected SSH host confirmation.');
    return runAuthorizedOperation(
      () => {
        requireNativeResourcesRunning();
        return sshBackend.trustHostKey(request);
      },
      () => sshBackend.close(request.sessionId),
    );
  });
  ipcMain.handle(
    'ssh:input',
    async (event, sessionId: unknown, data: unknown, paste: unknown = false) => {
      if (!isSshSessionId(sessionId) || typeof paste !== 'boolean' || !isSshInput(data, paste)) {
        throw new Error('SSH input request is invalid.');
      }
      const current = sshBackend.captureOwner(event, sessionId);
      return serializeAuthOperation(async () => {
        await requireWorkspaceAuth();
        current();
        sshBackend.sendInput(sessionId, data, paste);
      });
    },
  );
  ipcMain.handle('ssh:paste-clipboard', async (event, sessionId: unknown) => {
    if (!isSshSessionId(sessionId)) throw new Error('SSH paste request is invalid.');
    const current = sshBackend.captureOwner(event, sessionId);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      current();
      const epoch = authSession.authorizationEpoch;
      // Preserve input order while the native clipboard is read. Locking bypasses this queue.
      const text = await clipboard.readText();
      await requireWorkspaceAuth();
      current();
      requireAuthorizationEpoch(epoch);
      authSession.requireVerificationEpoch(epoch);
      const data = encodeTerminalClipboardText(text);
      if (!data) return { pasted: false };
      sshBackend.sendInput(sessionId, data, true);
      return { pasted: true };
    });
  });
  ipcMain.handle('ssh:open-link', async (_event, value: unknown) => {
    const url = parseTerminalLink(value);
    return runAuthorizedOperation(() => shell.openExternal(url));
  });
  ipcMain.handle(
    'ssh:resize',
    async (event, sessionId: unknown, columns: unknown, rows: unknown) => {
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
      const current = sshBackend.captureOwner(event, sessionId);
      return serializeAuthOperation(async () => {
        await requireWorkspaceAuth();
        current();
        sshBackend.resize(sessionId, columns, rows);
      });
    },
  );
  ipcMain.handle('settings:file-transfer-read', async (event) =>
    serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      if (vaultBackend.isVaultWorkspace) {
        if (!isTrustedVaultSender(event)) throw Error('Invalid vault file editor owner.');
        return vaultBackend.fileEditSettings();
      }
      return runBackend('settings-file-transfer-read');
    }),
  );
  ipcMain.handle('settings:file-transfer-write', async (event, request: unknown) => {
    if (!isRecord(request) || JSON.stringify(request).length > 64 * 1024)
      throw new Error('Invalid editor settings.');
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      if (vaultBackend.isVaultWorkspace) {
        if (!isTrustedVaultSender(event)) throw Error('Invalid vault file editor owner.');
        await vaultBackend.fileEditSettings(request);
        return;
      }
      return runBackend('settings-file-transfer-write', request);
    });
  });
  ipcMain.handle('ssh:sftp-edit', async (event, sessionId: unknown, request: unknown) => {
    if (!isSshSessionId(sessionId) || !isSftpEditRequest(request))
      throw new Error('Invalid file edit request.');
    const current = sshBackend.captureOwner(event, sessionId);
    return runAuthorizedOperation(() => {
      current();
      sshBackend.assertSftpOwner(event, sessionId);
      return sshBackend.edit(sessionId, request);
    });
  });
  ipcMain.handle('ssh:sftp-edit-close', async (event, sessionId: unknown) => {
    if (!isSshSessionId(sessionId)) throw new Error('Invalid file edit close request.');
    const current = sshBackend.captureOwner(event, sessionId, true);
    return runAuthorizedOperation(() => {
      current();
      sshBackend.assertSftpOwner(event, sessionId, true);
      return sshBackend.prepareEditClose(sessionId);
    });
  });
  ipcMain.handle(
    'ssh:sftp-share',
    async (event, sourceId: unknown, sessionId: unknown, ...extra: unknown[]) => {
      requireNativeResourcesRunning();
      if (!isSshSessionId(sourceId) || !isSshSessionId(sessionId) || sourceId === sessionId)
        throw new Error('Invalid SFTP session.');
      if (vaultSshIpc.handles(sourceId) || vaultSshIpc.handles(sessionId)) {
        if (extra.length !== 0) throw Error('Invalid vault SSH owner.');
        return vaultSshIpc.share(event, sourceId, sessionId);
      }
      return runAuthorizedOperation(
        () => {
          sshBackend.assertSftpOwner(event, sourceId);
          return sshBackend.shareSftp(sourceId, sessionId, event.sender);
        },
        () => sshBackend.close(sessionId),
      );
    },
  );
  ipcMain.handle(
    'ssh:sftp-tree-list',
    async (event, sessionId: unknown, pane: unknown, path: unknown, requestId: unknown) => {
      if (
        !isSshSessionId(sessionId) ||
        !isSftpRequestId(requestId) ||
        !isSftpPane(pane) ||
        !(pane === 'local' ? isLocalSftpPath(path) : isSftpPath(path))
      )
        throw new Error('Invalid SFTP tree request.');
      const current = sshBackend.captureOwner(event, sessionId);
      return serializeAuthOperation(async () => {
        await requireWorkspaceAuth();
        current();
        sshBackend.assertSftpOwner(event, sessionId);
        sshBackend.listSftpTree(sessionId, pane, path as string, requestId);
      });
    },
  );
  ipcMain.handle('ssh:sftp-open', async (event, sessionId: unknown, requestId: unknown) => {
    if (!isSshSessionId(sessionId) || (requestId !== undefined && !isSftpRequestId(requestId))) {
      throw new Error('SFTP open request is invalid.');
    }
    const current = sshBackend.captureOwner(event, sessionId);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      current();
      sshBackend.assertSftpOwner(event, sessionId);
      sshBackend.openSftp(sessionId, typeof requestId === 'string' ? requestId : '');
    });
  });
  ipcMain.handle(
    'ssh:sftp-list',
    async (event, sessionId: unknown, path: unknown, requestId: unknown) => {
      if (
        !isSshSessionId(sessionId) ||
        !isSftpPath(path) ||
        (requestId !== undefined && !isSftpRequestId(requestId))
      ) {
        throw new Error('SFTP list request is invalid.');
      }
      const current = sshBackend.captureOwner(event, sessionId);
      return serializeAuthOperation(async () => {
        await requireWorkspaceAuth();
        current();
        sshBackend.assertSftpOwner(event, sessionId);
        sshBackend.listSftp(sessionId, path, typeof requestId === 'string' ? requestId : '');
      });
    },
  );
  ipcMain.handle(
    'ssh:sftp-local-list',
    async (event, sessionId: unknown, path: unknown, requestId: unknown) => {
      if (
        !isSshSessionId(sessionId) ||
        !isLocalSftpPath(path, true) ||
        !isSftpRequestId(requestId)
      ) {
        throw new Error('Local SFTP list request is invalid.');
      }
      const current = sshBackend.captureOwner(event, sessionId);
      return serializeAuthOperation(async () => {
        await requireWorkspaceAuth();
        current();
        sshBackend.assertSftpOwner(event, sessionId);
        sshBackend.listLocalSftp(sessionId, path, requestId);
      });
    },
  );
  ipcMain.handle('ssh:sftp-operation', async (event, sessionId: unknown, request: unknown) => {
    if (!isSshSessionId(sessionId) || !isSftpOperationRequest(request)) {
      throw new Error('SFTP operation request is invalid.');
    }
    const current = sshBackend.captureOwner(event, sessionId);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      current();
      sshBackend.assertSftpOwner(event, sessionId);
      sshBackend.operateSftp(sessionId, request);
    });
  });
  ipcMain.handle('ssh:sftp-transfer', async (event, sessionId: unknown, request: unknown) => {
    if (!isSshSessionId(sessionId) || !isSftpTransferRequest(request)) {
      throw new Error('SFTP transfer request is invalid.');
    }
    const current = sshBackend.captureOwner(event, sessionId);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      current();
      sshBackend.assertSftpOwner(event, sessionId);
      sshBackend.startSftpTransfer(sessionId, request);
    });
  });
  ipcMain.handle(
    'ssh:sftp-transfer-decision',
    async (
      event,
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
      const current = sshBackend.captureOwner(event, sessionId);
      return serializeAuthOperation(async () => {
        await requireWorkspaceAuth();
        current();
        sshBackend.assertSftpOwner(event, sessionId);
        sshBackend.decideSftpConflict(sessionId, transferId, itemId, decision, applyToAll);
      });
    },
  );
  ipcMain.handle(
    'ssh:sftp-transfer-cancel',
    async (event, sessionId: unknown, transferId: unknown, itemId: unknown) => {
      if (
        !isSshSessionId(sessionId) ||
        !isSftpTransferId(transferId) ||
        (itemId !== undefined && !isSftpRequestId(itemId))
      ) {
        throw new Error('SFTP transfer cancellation is invalid.');
      }
      const current = sshBackend.captureOwner(event, sessionId);
      return serializeAuthOperation(async () => {
        await requireWorkspaceAuth();
        current();
        sshBackend.assertSftpOwner(event, sessionId);
        sshBackend.cancelSftpTransfer(
          sessionId,
          transferId,
          typeof itemId === 'string' ? itemId : undefined,
        );
      });
    },
  );
  ipcMain.handle('ssh:sftp-close', async (event, sessionId: unknown) => {
    if (!isSshSessionId(sessionId)) throw new Error('SFTP close request is invalid.');
    const current = sshBackend.captureOwner(event, sessionId);
    return serializeAuthOperation(async () => {
      current();
      sshBackend.assertSftpOwner(event, sessionId);
      sshBackend.closeSftp(sessionId);
    });
  });
  ipcMain.handle('ssh:close', async (event, sessionId: unknown, ...extra: unknown[]) => {
    if (!isSshSessionId(sessionId)) throw new Error('SSH close request is invalid.');
    if (vaultSshIpc.handles(sessionId)) {
      if (extra.length !== 0) throw Error('Invalid vault SSH owner.');
      return vaultSshIpc.close(event, sessionId);
    }
    sshBackend.assertSftpOwner(event, sessionId, true);
    await sshBackend.close(sessionId);
  });
  ipcMain.handle('serial:open', async (event, request: unknown) => {
    requireNativeResourcesRunning();
    if (!isSerialOpenRequest(request)) throw new Error('Serial open request is invalid.');
    if (vaultBackend.isVaultWorkspace || sealedSerial.handles(request.sessionId)) {
      if (!isTrustedVaultSender(event)) throw Error('Invalid serial owner.');
      return runAuthorizedOperation((epoch) =>
        sealedSerial.open(
          event.sender,
          request,
          epoch + 1,
          () => isAuthorizationEpochCurrent(epoch) && isTrustedVaultSender(event) && !isQuitting,
        ),
      );
    }
    let connection: Promise<SerialConnectedResponse> | undefined;
    await serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      connection = getSerialBackend().open(request as SerialOpenRequest);
    });
    return connection!;
  });
  ipcMain.handle('serial:input', async (event, sessionId: unknown, data: unknown) => {
    if (!isSerialSessionId(sessionId) || !isSerialInput(data)) {
      throw new Error('Serial input request is invalid.');
    }
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      if (vaultBackend.isVaultWorkspace || sealedSerial.handles(sessionId)) {
        if (!isTrustedVaultSender(event)) throw Error('Invalid serial owner.');
        return sealedSerial.command(event.sender, sessionId, { type: 'input', data });
      }
      getSerialBackend().sendInput(sessionId, data);
    });
  });
  ipcMain.handle(
    'serial:resize',
    async (event, sessionId: unknown, columns: unknown, rows: unknown) => {
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
        if (vaultBackend.isVaultWorkspace || sealedSerial.handles(sessionId)) {
          if (!isTrustedVaultSender(event)) throw Error('Invalid serial owner.');
          return sealedSerial.command(event.sender, sessionId, { type: 'resize', columns, rows });
        }
        getSerialBackend().resize(sessionId, columns, rows);
      });
    },
  );
  ipcMain.handle('serial:close', async (event, sessionId: unknown) => {
    if (!isSerialSessionId(sessionId)) throw new Error('Serial close request is invalid.');
    if (vaultBackend.isVaultWorkspace || sealedSerial.handles(sessionId)) {
      if (!isTrustedVaultSender(event)) throw Error('Invalid serial owner.');
      return sealedSerial.close(event.sender, sessionId);
    }
    getSerialBackend().close(sessionId);
  });
  ipcMain.handle('vnc:command', async (event, input: unknown, ...extra: unknown[]) => {
    if (vaultVncIpc.handles(input)) {
      if (extra.length !== 0 || !isTrustedVaultSender(event))
        return { id: '', ok: false, error: 'Invalid vault VNC request.' };
      try {
        await vaultVncIpc.command(event, input);
        return { id: '', ok: true };
      } catch {
        return { id: '', ok: false, error: 'VNC connection could not be completed.' };
      }
    }
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

  ipcMain.handle('vault:rdp-open', (event, value: unknown, ...extra: unknown[]) => {
    requireNativeResourcesRunning();
    if (extra.length) throw Error('Invalid vault RDP request.');
    return vaultRdpIpc.open(event, value);
  });

  ipcMain.handle('rdp:start', async (event, value: unknown) => {
    if (vaultRdpIpc.handles(value))
      throw Error('Open the saved connection through the protected RDP service.');
    requireNativeResourcesRunning();
    const request = parseRdpStartRequest(value);
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow) throw new Error('RDP owner window is unavailable.');
    assertRdpSurfaceOwner(ownerWindow, rdpSurfacePlacements.get(request.sessionId)?.owner);
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
              let configuredTunnelId: string | undefined;
              if (request.profile.nodeId || request.profile.tunnelConfigId) {
                const leaseId = randomUUID();
                rdpTunnelLeases.claim(lifecycleId, leaseId);
                rdpTunnelLeaseSessions.set(lifecycleId, request.sessionId);
                let route: { active: boolean; socksEndpoint: string; configuredTunnelId?: string };
                try {
                  route = await getNativeBackend().acquireTunnelRoute({
                    onExit: () => {
                      if (!rdpTunnelLeases.isActive(lifecycleId!, leaseId)) return;
                      rdpStartAttempts.cancel(request.sessionId);
                      client.cancelStart(request.sessionId, lifecycleId!);
                      if (!ownerWindow.isDestroyed())
                        ownerWindow.webContents.send('rdp:event', {
                          type: 'error',
                          sessionId: request.sessionId,
                          lifecycleId,
                          message: tunnelClosedMessage,
                        });
                      void settleTunnelCleanup(
                        client.command(
                          'disconnect',
                          request.sessionId,
                          ownerHandle,
                          bounds,
                          lifecycleId!,
                        ),
                        releaseRdpTunnel(lifecycleId!),
                      ).catch(() => undefined);
                    },
                    leaseId,
                    nodeId: request.profile.nodeId,
                    tunnelConfigId: request.profile.tunnelConfigId,
                    progressSessionId: request.sessionId,
                  });
                } catch (error) {
                  await releaseRdpTunnel(lifecycleId).catch(() => undefined);
                  const message =
                    error instanceof Error ? error.message : 'VPN tunnel establishment failed.';
                  throw new Error(`RDP VPN tunnel is unavailable: ${message}`);
                }
                if (!canProceedWithRdpTunnelRoute(request.profile, route)) {
                  await releaseRdpTunnel(lifecycleId);
                  throw new Error('RDP VPN tunnel returned an invalid route.');
                }
                socksEndpoint = route.socksEndpoint;
                configuredTunnelId = route.configuredTunnelId;
                assertRdpStartCurrent(request.sessionId, requestAttempt, generation);
                if (!rdpTunnelLeases.isActive(lifecycleId, leaseId)) {
                  throw new Error('RDP connection closed while opening its VPN tunnel.');
                }
                if (!socksEndpoint) await releaseRdpTunnel(lifecycleId);
              }
              requireAuthorizationEpoch(authorizationEpoch);
              // Resolving a saved profile can read the vault, including gateway credentials.
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
                    const credential = await resolveNativeRdpCredential(
                      request.profile.credentialId,
                    );
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
              if (!isAuthorizationEpochCurrent(authorizationEpoch)) {
                await releaseRdpTunnel(lifecycleId);
                throw new Error('Authentication is required before opening the RDP connection.');
              }
              if (!socksEndpoint) await releaseRdpTunnel(lifecycleId);
              assertRdpStartCurrent(request.sessionId, requestAttempt, generation);
              if (request.profile.nodeId) {
                assertTunnelRouteUnchanged(
                  configuredTunnelId,
                  resolvedProfile.tunnelEnabled === true ? resolvedProfile.tunnelConfigId : '',
                );
              }
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
    if (vaultBackend.isVaultWorkspace) return { supported: false };
    const request = parseRdpSystemClientCapabilityRequest(value);
    return serializeAuthOperation(async () => {
      await requireWorkspaceAuth();
      return resolveNativeRdpSystemClientCapability(request.nodeId);
    });
  });

  ipcMain.handle('rdp:open-system', async (event, value: unknown) => {
    if (vaultBackend.isVaultWorkspace)
      return {
        ok: false,
        lifecycleCommitted: false,
        error: 'The system client is unavailable for this protected connection.',
      };
    const request = parseRdpSystemClientOpenRequest(value);
    let ownsLifecycle = false;
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow) throw new Error('RDP owner window is unavailable.');
    assertRdpSurfaceOwner(ownerWindow, rdpSurfacePlacements.get(request.sessionId)?.owner);
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

  ipcMain.handle('rdp:input', async (event, value: unknown, ...extra: unknown[]) => {
    if (vaultRdpIpc.handles(value)) {
      if (extra.length) throw Error('Invalid vault RDP request.');
      return vaultRdpIpc.input(event, value);
    }
    const request = parseRdpCommandRequest(value);
    const lifecycleId = valueAsString(value, 'lifecycleId');
    const input = valueAsObject(value, 'input');
    if (!isRdpInput(input)) throw new Error('Invalid RDP input.');
    await ensureAuthSession();
    authSession.requireUnlocked();
    const owner = BrowserWindow.fromWebContents(event.sender);
    if (!owner || rdpSurfacePlacements.get(request.sessionId)?.owner !== owner) {
      throw new Error('RDP session belongs to another window.');
    }
    await getRdpClient().input(request.sessionId, lifecycleId, input);
  });

  ipcMain.handle('rdp:resize', async (event, value: unknown, ...extra: unknown[]) => {
    if (vaultRdpIpc.handles(value)) {
      if (extra.length) throw Error('Invalid vault RDP request.');
      return vaultRdpIpc.resize(event, value);
    }
    const request = parseRdpCommandRequest(value);
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow) throw new Error('RDP owner window is unavailable.');
    assertRdpSurfaceOwner(ownerWindow, rdpSurfacePlacements.get(request.sessionId)?.owner);
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

  ipcMain.handle('rdp:command', async (event, value: unknown, ...extra: unknown[]) => {
    if (vaultRdpIpc.handles(value)) {
      if (extra.length) throw Error('Invalid vault RDP request.');
      return vaultRdpIpc.command(event, value);
    }
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
    assertRdpSurfaceOwner(ownerWindow, rdpSurfacePlacements.get(request.sessionId)?.owner);
    if (request.bounds) rememberRdpSurfacePlacement(ownerWindow, request.sessionId, request.bounds);
    const placement = rdpSurfacePlacements.get(request.sessionId);
    const client = getRdpClient();
    if (operation === 'show') {
      const showRequest = Symbol();
      if (placement) placement.showRequest = showRequest;
      const lifecycleId = client.currentLifecycleId(request.sessionId);
      const authorizationEpoch = authSession.authorizationEpoch;
      return serializeAuthOperation(async () => {
        await requireWorkspaceAuth();
        // Hide bypasses the authorization queue. A delayed reveal must not undo it or show a
        // replacement lifecycle. Use any geometry reported while the reveal was queued.
        if (
          rdpSurfacePlacements.get(request.sessionId)?.showRequest !== showRequest ||
          !isAuthorizationEpochCurrent(authorizationEpoch) ||
          !lifecycleId ||
          client.currentLifecycleId(request.sessionId) !== lifecycleId ||
          ownerWindow.isDestroyed()
        ) {
          return;
        }
        return client.command(
          operation,
          request.sessionId,
          nativeWindowHandle(ownerWindow),
          currentRdpSurfaceScreenBounds(ownerWindow, request.sessionId),
          lifecycleId,
        );
      });
    }
    if (placement && operation !== 'focus') placement.showRequest = undefined;
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
        request.bounds && toScreenBounds(ownerWindow, request.bounds),
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

  rdpClient = new RdpBackendClient({
    executable: backendPath(),
    args,
    diagnostics: recordDiagnostic,
  });
  rdpClient.onEvent((event: RdpBackendEvent) => {
    if (
      event.sessionId &&
      event.lifecycleGeneration !== undefined &&
      !rdpSessionAttempts.isCurrent(event.sessionId, event.lifecycleGeneration)
    ) {
      return;
    }
    if (event.type === 'certificate') {
      const owner = event.sessionId ? rdpSurfacePlacements.get(event.sessionId)?.owner : undefined;
      void confirmRdpCertificate(event, {
        available: () => authSession.isAccessAllowed && Boolean(owner && !owner.isDestroyed()),
        prompt: async (certificate) => {
          const result = await showCoordinatedMessageBox(owner!, {
            type: 'warning',
            title: 'Remote Desktop certificate',
            message: 'The remote desktop certificate could not be verified.',
            detail: `Server: ${certificate.host}\nFingerprint: ${certificate.fingerprint}\n\nConnect only if you trust this server and have verified its fingerprint.`,
            buttons: ['Cancel', 'Connect once'],
            defaultId: 0,
            cancelId: 0,
          });
          return result.response === 1;
        },
        reply: async (sessionId, lifecycleId, accepted) => {
          await rdpClient?.certificateDecision(sessionId, lifecycleId, accepted);
        },
      });
      return;
    }
    if (event.type === 'frame' || event.type === 'frameEnd') {
      if (!authSession.isAccessAllowed || !event.sessionId) return;
      const owner = rdpSurfacePlacements.get(event.sessionId)?.owner;
      if (owner && !owner.isDestroyed()) owner.webContents.send('rdp:event', event);
      return;
    }
    // Native reveal/resize acknowledgements and reconnect events can raise the owned
    // RDP HWND above its siblings. Restore an open tooltip without showing a closed one.
    if (event.sessionId) {
      const owner = rdpSurfacePlacements.get(event.sessionId)?.owner;
      if (owner) treeTooltips.raiseForWindow(owner);
    }
    if (!isRdpLifecycleEvent(event)) return;
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
        reportWarning('Could not release the RDP VPN tunnel.', error);
      });
    }
    if (event.sessionId && terminalEvent) forgetRdpSurfacePlacement(event.sessionId);
    for (const window of BrowserWindow.getAllWindows()) {
      if (!window.isDestroyed() && windowCloseCoordinators.has(window)) {
        window.webContents.send('rdp:event', event);
      }
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
      reportWarning('Could not release a pending RDP VPN tunnel.', error);
    });
  }
}

async function releaseAllRdpTunnels(): Promise<void> {
  const results = await rdpTunnelLeases.releaseAll(releaseNativeTunnelLease);
  for (const lifecycleId of [...rdpTunnelLeaseSessions.keys()]) {
    if (!rdpTunnelLeases.has(lifecycleId)) rdpTunnelLeaseSessions.delete(lifecycleId);
  }
  if (results.some((result) => result.status === 'rejected')) {
    reportWarning('One or more RDP VPN tunnel leases could not be released cleanly.');
  }
}

function rememberRdpSurfacePlacement(
  owner: BrowserWindow,
  sessionId: string,
  rendererBounds: RdpSurfaceRect,
): void {
  const previous = rdpSurfacePlacements.get(sessionId);
  assertRdpSurfaceOwner(owner, previous?.owner);
  rdpSurfacePlacements.set(sessionId, {
    owner,
    rendererBounds: { ...rendererBounds },
    showRequest: previous?.showRequest,
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
    if (owner.isDestroyed()) return;
    const ownerWindow = nativeWindowHandle(owner);
    for (const [sessionId, placement] of rdpSurfacePlacements) {
      if (placement.owner !== owner) continue;
      const bounds = toScreenBounds(owner, placement.rendererBounds);
      if (!bounds) continue;
      const update = vaultRdpController.has(sessionId)
        ? vaultRdpController.control(owner.webContents, () => true, sessionId, {
            op: 'resize',
            bounds,
          })
        : rdpClient?.resize({ sessionId, bounds }, ownerWindow);
      void update?.catch(() => {
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
    diagnostics: recordDiagnostic,
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
      if (!window.isDestroyed() && windowCloseCoordinators.has(window)) {
        window.webContents.send('serial:event', event);
      }
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
  const window = createApplicationWindow({
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
          titleBarOverlay: nativeTitlebarOverlay('dark'),
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
  window.on('minimize', () => vaultLockMonitor.minimized());
  window.on('move', () => scheduleRdpSurfacePlacementSync(window));
  window.on('resize', () => scheduleRdpSurfacePlacementSync(window));
  window.once('closed', () => clearRdpSurfacePlacements(window));
  const credentialSelectionOwner = window.webContents;
  credentialSelectionOwner.once('destroyed', () => {
    fortinetIPsecDrafts.discard(credentialSelectionOwner);
    sshPrivateKeySelections.delete(credentialSelectionOwner);
    sshCertificateSelections.delete(credentialSelectionOwner);
  });

  // Keep the workspace renderer at its native CSS scale so a previously persisted Chromium zoom
  // level cannot make the whole workspace look oversized.
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
    if (startupReadyWindows.has(window) || failedWorkspaceWindows.has(window)) window.setOpacity(1);
  };
  window.once('ready-to-show', showWindow);
  showFallbackTimer = setTimeout(showWindow, 10_000);

  window.webContents.on('did-start-loading', () => {
    fortinetIPsecDrafts.discard(credentialSelectionOwner);
    failedWorkspaceWindows.delete(window);
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
      clearFortinetIPsecDrafts();
      backupImportSelections.delete(window.webContents);
      sshPrivateKeySelections.delete(window.webContents);
      sshCertificateSelections.delete(window.webContents);
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
      recordDiagnostic('ERR', 'Could not reset app authentication.', {
        code: diagnosticErrorCode(error),
      });
    });
  });

  window.webContents.on('preload-error', (_event, _preloadPath, error) => {
    recordDiagnostic('ERR', 'Workspace preload failed', { code: diagnosticErrorCode(error) });
  });

  const closeReason = new WindowCloseReasonTracker();
  window.on('query-session-end', () => {
    closeReason.beginSystemShutdown();
    // Windows can end the process without an ordinary window-close / before-quit sequence.
    // Start saving at the first shutdown notification, while the native backend is still alive.
    void webSurfaces.checkpointBitwardenStorage().catch(() => {
      reportWarning('Could not checkpoint Bitwarden storage before system shutdown.');
    });
  });
  window.on('session-end', () => {
    closeReason.confirmSystemShutdown();
    skipQuitConfirmation = true;
    isQuitting = true;
    void withBitwardenBrowserTimeout(
      webSurfaces.checkpointBitwardenStorage(),
      5_000,
      'Bitwarden system shutdown checkpoint timed out.',
    )
      .catch(() => {
        reportWarning('Bitwarden system shutdown checkpoint did not finish.');
      })
      .finally(() => shutdownNativeResources())
      .catch(() => {
        console.warn('[Wormhole] Native shutdown could not be confirmed.');
      });
  });
  window.webContents.on('render-process-gone', (_event, { reason, exitCode }) => {
    recordDiagnostic('ERR', 'Workspace renderer exited', { reason, exitCode });
    closeReason.rendererFailed();
    if (!window.isDestroyed()) window.close();
  });
  window.on('close', (event) => {
    if (isQuitting || closeCoordinator.isComplete) return;
    event.preventDefault();
    void closeCoordinator
      .request({
        reason: failedWorkspaceWindows.has(window) ? 'renderer-failure' : closeReason.reason,
        confirmationEnabled: confirmOnWindowClose,
        prepare: () => sshBackend.prepareEditClose('sftp-recovery', window.webContents),
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
                reportWarning('Browser window shutdown did not finish cleanly.', error);
              }
            },
            async () => {
              if (
                closeReason.reason !== 'renderer-failure' &&
                !failedWorkspaceWindows.has(window)
              ) {
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
        reportWarning('Window close cleanup failed.', error);
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

  void loadShellPage({
    load: () =>
      rendererUrl ? window.loadURL(rendererUrl) : window.loadFile(productionRendererPath),
    isDestroyed: () => window.isDestroyed(),
    reportFailure: () => {
      recordDiagnostic('ERR', 'Workspace page failed to load');
      dialog.showErrorBox(
        "Wormhole couldn't open",
        'The application page could not be loaded. Try reopening Wormhole. If the problem persists, reinstall the application.',
      );
    },
    close: () => {
      closeReason.rendererFailed();
      window.close();
    },
  });
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
const vaultSshIpc = new VaultSshIpc({
  workspace: () => vaultBackend.isVaultWorkspace,
  trusted: (event) => isTrustedVaultSender(event as Electron.IpcMainInvokeEvent),
  authorize: (run, cleanup) =>
    runAuthorizedOperation((epoch) => {
      requireNativeResourcesRunning();
      return run(epoch + 1);
    }, cleanup),
  quickTarget: (target, sessionId, epoch, current) => {
    const workspaceId = vaultBackend.unlockedWorkspaceId;
    if (!workspaceId) throw Error('Protected Quick Connect is locked.');
    return vaultBackend.beginQuickTarget({ workspaceId, sessionId, epoch, target }, current);
  },
  native: {
    hasReservation: (id) => sshBackend.hasProtectedReservation(id),
    owns: (owner, id) => sshBackend.ownsProtected(owner as Electron.WebContents, id),
    capture: (event, id) => sshBackend.captureOwner(event as Electron.IpcMainInvokeEvent, id),
    share: (owner, sourceId, id, current) =>
      sshBackend.shareSftp(sourceId, id, owner as Electron.WebContents, current),
    admit: (owner, q, epoch, current, retired) =>
      sshBackend.admitProtected(owner as Electron.WebContents, q, epoch, current, retired),
    close: (owner, id) => sshBackend.closeProtected(owner as Electron.WebContents, id),
    retire: (owner, id) => sshBackend.retireProtected(owner as Electron.WebContents, [id]),
    retireOwner: (owner, ids) =>
      sshBackend.retireProtected(owner as Electron.WebContents, ids, true),
    closeAll: () => sshBackend.stopSealedSessions(),
  },
});
const vaultRdpRoutes = new SealedRouteBroker({
  authentication: {
    prompt: (context, current, signal, request, fallback) => {
      const owner = vaultRdpController.ownerForSession(context.binding.sessionId);
      const parent = BrowserWindow.getAllWindows().find((window) => window.webContents === owner);
      if (!parent) return Promise.reject(Error('VPN authentication owner unavailable.'));
      return 'startURL' in context
        ? vaultTunnelBrowserDialog.open(parent, current, context, signal, request, fallback)
        : vaultTunnelAuthenticationDialog.open(parent, current, context, signal);
    },
    close: (context) =>
      'startURL' in context
        ? vaultTunnelBrowserDialog.cancelChallenge(context)
        : vaultTunnelAuthenticationDialog.cancelChallenge(context),
  },

  executable: backendPath,
  workspaceId: () => vaultBackend.unlockedWorkspaceId,
  authorized: (epoch) =>
    Boolean(vaultBackend.unlockedWorkspaceId) && isAuthorizationEpochCurrent(epoch - 1),
  plan: (q) => vaultBackend.tunnelPlan(q),
  bundle: (q) => vaultBackend.tunnelBundle(q),
  fallback: {
    plan: (q) => vaultBackend.tunnelFallbackPlan(q),
    bundle: (q) => vaultBackend.tunnelFallbackBundle(q),
  },
});
const vaultRdpController = new VaultRdpController(
  (onEvent) =>
    new SealedRdpBackend({
      executable: backendPath,
      workspaceId: () => vaultBackend.unlockedWorkspaceId,
      authorized: (epoch) =>
        Boolean(vaultBackend.unlockedWorkspaceId) && isAuthorizationEpochCurrent(epoch - 1),
      bundle: (q) => vaultBackend.rdpBundle(q),
      bitwarden: (request, signal, accepted) =>
        vaultBackend.isSharedWorkspace
          ? Promise.resolve(undefined)
          : resolveVaultRDPBitwarden({
              executable: backendPath(),
              databasePath: wormholeDatabasePath(),
              request,
              signal,
              prepare: (recipient) =>
                vaultBackend.prepareRDPBitwarden(request, recipient, accepted),
            }),
      manual: {
        plan: (q) => vaultBackend.rdpPlan(q),
        bundle: (q) => vaultBackend.rdpManualBundle(q),
        bitwarden: (q, signal, accepted) =>
          vaultBackend.isSharedWorkspace
            ? Promise.resolve(undefined)
            : resolveVaultRDPBitwarden({
                executable: backendPath(),
                databasePath: wormholeDatabasePath(),
                request: rdpManualTarget(q),
                signal,
                prepare: (recipient) =>
                  vaultBackend.prepareManualRDPBitwarden(q, recipient, accepted),
              }),
        prompt: (context, active, signal) => {
          const owner = vaultRdpController.ownerForSession(context.binding.sessionId);
          const parent = BrowserWindow.getAllWindows().find(
            (window) => window.webContents === owner,
          );
          if (!parent) return Promise.reject(Error('RDP credential owner unavailable.'));
          return vaultRdpCredentialsDialog.open(parent, active, context, signal);
        },
      },
      onEvent,
      route: {
        resolve: (q) => vaultBackend.connectionRoute(q),
        broker: vaultRdpRoutes,
        bundle: (q) => vaultBackend.routedRdpBundle(q),
      },
    }),
  (epoch) => Boolean(vaultBackend.unlockedWorkspaceId) && isAuthorizationEpochCurrent(epoch - 1),
  (event, owner) => {
    const parent = BrowserWindow.getAllWindows().find((window) => window.webContents === owner);
    const available = () =>
      Boolean(parent && !parent.isDestroyed()) &&
      authSession.isAccessAllowed &&
      vaultRdpController.ownerForSession(event.sessionId ?? '') === owner;
    void confirmRdpCertificate(event, {
      available,
      prompt: async (certificate) => {
        const result = await showCoordinatedMessageBox(parent!, {
          type: 'warning',
          title: 'Remote Desktop certificate',
          message: 'The remote desktop certificate could not be verified.',
          detail: `Server: ${certificate.host}\nFingerprint: ${certificate.fingerprint}\n\nConnect only if you trust this server and have verified its fingerprint.`,
          buttons: ['Cancel', 'Connect once'],
          defaultId: 0,
          cancelId: 0,
        });
        return result.response === 1;
      },
      reply: async (sessionId, lifecycle, accepted) => {
        await vaultRdpController.control(
          owner,
          available,
          sessionId,
          { op: 'certificate', certificateAccepted: accepted },
          lifecycle,
        );
      },
    });
  },
  (event, owner) => {
    if (event.type === 'frame' || event.type === 'frameEnd') return;
    const parent = BrowserWindow.getAllWindows().find((window) => window.webContents === owner);
    if (parent) treeTooltips.raiseForWindow(parent);
  },
);
const vaultRdpIpc = new VaultRdpIpc({
  controller: vaultRdpController,
  quickTarget: (target, sessionId, epoch, accepted) => {
    const workspaceId = vaultBackend.unlockedWorkspaceId;
    if (!workspaceId) throw Error('Protected Quick Connect is locked.');
    return vaultBackend.beginQuickTarget({ workspaceId, sessionId, epoch, target }, accepted);
  },
  workspace: () => vaultBackend.isVaultWorkspace,
  trusted: (event) => isTrustedVaultSender(event as Electron.IpcMainInvokeEvent),
  unlocked: async () => {
    await ensureAuthSession();
    authSession.requireUnlocked();
  },
  authorize: (run, cleanup) =>
    runAuthorizedOperation((epoch) => {
      requireNativeResourcesRunning();
      return run(epoch + 1);
    }, cleanup),
  surface: (event, id, bounds) => {
    const owner = BrowserWindow.fromWebContents(event.sender as Electron.WebContents);
    if (!owner || owner.isDestroyed()) throw Error('RDP owner window unavailable.');
    assertRdpSurfaceOwner(owner, rdpSurfacePlacements.get(id)?.owner);
    if (bounds) rememberRdpSurfacePlacement(owner, id, bounds);
    return {
      ownerWindow: nativeWindowHandle(owner),
      bounds: currentRdpSurfaceScreenBounds(owner, id),
      ...(process.platform === 'win32' && vaultWindowPolicy.requiresContentProtection
        ? { requireContentProtection: true as const }
        : {}),
    };
  },
  forget: forgetRdpSurfacePlacement,
});
async function stopVaultRdpSessions(): Promise<void> {
  const credentialsStopped = vaultRdpCredentialsDialog.cancel();
  const results = await Promise.allSettled([
    credentialsStopped,
    vaultRdpIpc.closeAll(),
    vaultRdpRoutes.closeAll(),
  ]);
  if (results.some((result) => result.status === 'rejected'))
    throw Error('RDP shutdown could not be confirmed.');
}
const vaultVncRoutes = new SealedRouteBroker({
  authentication: {
    prompt: (context, current, signal, request, fallback) => {
      const owner = vaultVncController.ownerForSession(context.binding.sessionId);
      const parent = BrowserWindow.getAllWindows().find((window) => window.webContents === owner);
      if (!parent) return Promise.reject(Error('VPN authentication owner unavailable.'));
      return 'startURL' in context
        ? vaultTunnelBrowserDialog.open(parent, current, context, signal, request, fallback)
        : vaultTunnelAuthenticationDialog.open(parent, current, context, signal);
    },
    close: (context) =>
      'startURL' in context
        ? vaultTunnelBrowserDialog.cancelChallenge(context)
        : vaultTunnelAuthenticationDialog.cancelChallenge(context),
  },

  executable: backendPath,
  workspaceId: () => vaultBackend.unlockedWorkspaceId,
  authorized: (epoch) =>
    Boolean(vaultBackend.unlockedWorkspaceId) && isAuthorizationEpochCurrent(epoch - 1),
  plan: (q) => vaultBackend.tunnelPlan(q),
  bundle: (q) => vaultBackend.tunnelBundle(q),
  fallback: {
    plan: (q) => vaultBackend.tunnelFallbackPlan(q),
    bundle: (q) => vaultBackend.tunnelFallbackBundle(q),
  },
});
const vaultVncController = new VaultVncController(
  (onEvent) =>
    new SealedVncBackend({
      executable: backendPath,
      workspaceId: () => vaultBackend.unlockedWorkspaceId,
      authorized: (epoch) =>
        Boolean(vaultBackend.unlockedWorkspaceId) && isAuthorizationEpochCurrent(epoch - 1),
      bundle: (q) => vaultBackend.vncBundle(q),
      bitwarden: (request, signal, accepted) =>
        vaultBackend.isSharedWorkspace
          ? Promise.resolve(undefined)
          : resolveVaultVNCBitwarden({
              executable: backendPath(),
              databasePath: wormholeDatabasePath(),
              request,
              signal,
              prepare: (recipient) =>
                vaultBackend.prepareVNCBitwarden(request, recipient, accepted),
            }),
      manual: {
        plan: (q) => vaultBackend.vncPlan(q),
        bundle: (q) => vaultBackend.vncManualBundle(q),
        prompt: (context, active, signal) => {
          const owner = vaultVncController.ownerForSession(context.binding.sessionId);
          const parent = BrowserWindow.getAllWindows().find(
            (window) => window.webContents === owner,
          );
          if (!parent) return Promise.reject(Error('VNC password owner unavailable.'));
          return vaultVncPasswordDialog.open(parent, active, context, signal);
        },
      },
      onEvent,
      route: {
        resolve: (q) => vaultBackend.connectionRoute(q),
        broker: vaultVncRoutes,
        bundle: (q) => vaultBackend.routedVncBundle(q),
      },
    }),
  (epoch) => Boolean(vaultBackend.unlockedWorkspaceId) && isAuthorizationEpochCurrent(epoch - 1),
);
const vaultVncIpc = new VaultVncIpc({
  controller: vaultVncController,
  workspace: () => vaultBackend.isVaultWorkspace,
  trusted: (event) => isTrustedVaultSender(event as Electron.IpcMainInvokeEvent),
  authorize: (run, cleanup) =>
    runAuthorizedOperation((epoch) => {
      requireNativeResourcesRunning();
      return run(epoch + 1);
    }, cleanup),
  quickTarget: (target, sessionId, epoch, accepted) => {
    const workspaceId = vaultBackend.unlockedWorkspaceId;
    if (!workspaceId) throw Error('Protected Quick Connect is locked.');
    return vaultBackend.beginQuickTarget({ workspaceId, sessionId, epoch, target }, accepted);
  },
});
async function stopVaultVncSessions(): Promise<void> {
  const passwordStopped = vaultVncPasswordDialog.cancel();
  const results = await Promise.allSettled([
    passwordStopped,
    vaultVncIpc.closeAll(),
    vaultVncRoutes.closeAll(),
  ]);
  if (results.some((result) => result.status === 'rejected'))
    throw Error('VNC shutdown could not be confirmed.');
}
async function stopVaultBitwardenCLIUnlock(): Promise<void> {
  const results = await Promise.allSettled([
    vaultBitwardenCLIUnlock.stop(),
    vaultBitwardenCLIUnlockDialog.cancel(),
  ]);
  if (results.some((result) => result.status === 'rejected'))
    throw Error('Bitwarden CLI shutdown could not be confirmed.');
}
let nativeResourceShutdownPromise: Promise<void> | undefined;
let nativeResourceShutdownRetainsVault = false;

function shutdownNativeResources(): Promise<void> {
  return shutdownNativeResourceOwner(false);
}

function shutdownNativeResourcesRetainingVault(): Promise<void> {
  return shutdownNativeResourceOwner(true);
}

function shutdownNativeResourceOwner(retainVaultOwner: boolean): Promise<void> {
  if (nativeResourceShutdownPromise) {
    if (retainVaultOwner || !nativeResourceShutdownRetainsVault)
      return nativeResourceShutdownPromise;
    // Upgrade one in-flight retained cleanup to a full retirement. Repeated
    // full shutdowns must join this same promise and never stop twice.
    nativeResourceShutdownRetainsVault = false;
    const escalated = nativeResourceShutdownPromise.finally(() => vaultBackend.stop());
    const tracked = escalated.finally(() => {
      if (nativeResourceShutdownPromise === tracked) nativeResourceShutdownPromise = undefined;
    });
    nativeResourceShutdownPromise = tracked;
    return tracked;
  }
  nativeResourceShutdownRetainsVault = retainVaultOwner;
  vaultLockMonitor.deactivate();
  const task = (async () => {
    vncSessionAttempts.cancelAll();
    cancelPreparingRdpStarts();
    serialBackend?.dispose();
    serialBackend = undefined;
    const vncStopped = stopVaultVncSessions();
    const sealedRdpStopped = stopVaultRdpSessions();
    const webStopped = vaultWebIpc.closeAll();
    const sealedSshStopped = vaultSshIpc.closeAll();
    const sealedSerialStopped = sealedSerial.closeAll();
    const bitwardenCLIStopped = stopVaultBitwardenCLIUnlock();
    const results = await Promise.allSettled([
      sshBackend.dispose(),
      rdpClient?.dispose(),
      retainVaultOwner ? Promise.resolve() : vaultBackend.stop(),
      vaultCreateDialog.cancel(),
      vaultMigrationSetupDialog.cancel(),
      vaultOSMigrationDialog.cancel(),
      vaultRootSetupDialog.cancel(),
      vaultUpgradeSetupDialog.cancel(),
      vaultReauthenticationDialog.cancel(),
      vaultSharedDialog.cancel(),
      vaultSharedSetupDialog.cancel(),
      Promise.resolve(vaultNotesDialog.cancel()),
      Promise.resolve(vaultCredentialsDialog.cancel()),
      vaultLinuxClipboard?.reset(),
      vaultTunnelDialog.cancel(),
      vncStopped,
      sealedRdpStopped,
      webStopped,
      sealedSshStopped,
      sealedSerialStopped,
      bitwardenCLIStopped,
    ]);
    if (results.some((result) => result.status === 'rejected')) {
      reportWarning('One or more connection services did not stop cleanly.');
    }
    await releaseAllRdpTunnels();
    const backend = nativeBackend;
    if (nativeBackend === backend) nativeBackend = undefined;
    await backend?.stop(true);
    webSurfaces.backendStopped();
    const relayBackend = browserRelayBackend;
    browserRelayBackend = undefined;
    await relayBackend?.stop(true);
    sshBackend.backendStopped();
    rdpTunnelLeases.clear();
    rdpTunnelLeaseSessions.clear();
    if (results[2].status === 'rejected') throw new Error('Vault shutdown could not be confirmed.');
    await vncStopped;
    await sealedRdpStopped;
    await webStopped;
    if (results.some((result) => result.status === 'rejected'))
      throw Error('Native shutdown could not be confirmed.');
  })();
  const tracked = task.finally(() => {
    if (nativeResourceShutdownPromise === tracked) nativeResourceShutdownPromise = undefined;
  });
  nativeResourceShutdownPromise = tracked;
  return tracked;
}

function scheduleUnlockedBackgroundWork(): void {
  if (vaultBackend.isVaultWorkspace || vaultBackend.requiresLegacyMigration) return;
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
    if (
      !stillHasReadyWindow ||
      !authSession.isAccessAllowed ||
      isQuitting ||
      vaultBackend.isVaultWorkspace ||
      vaultBackend.requiresLegacyMigration
    )
      return;
    const authorizationEpoch = authSession.authorizationEpoch;
    startBitwardenBackgroundMaintenance();
    void showBitwardenOnboardingNoticeIfNeeded();
    void sshBackend.syncMcpAfterUnlock(authorizationEpoch).catch((error) => {
      recordDiagnostic('ERR', 'Could not synchronize the MCP service after unlock.', {
        code: diagnosticErrorCode(error),
      });
    });
  }, startupBackgroundDelayMs);
}

authSession.onUnlocked(() => {
  sshBackend.requestSnapshots();
  serialBackend?.requestSnapshots();
  sealedSerial.requestSnapshots();
  scheduleUnlockedBackgroundWork();
  if (vaultBackend.isVaultWorkspace && !vaultBackend.requiresLegacyMigration) {
    void (async () => {
      const scope = captureUpdateScope();
      const settings = await vaultBackend.preferences();
      requireUpdateScope(scope);
      scheduleStartupUpdateCheck(settings, scope);
    })().catch(() => undefined);
  }
});

app.whenReady().then(() => {
  if (vaultMigrationBoot.unavailable) {
    dialog.showErrorBox(
      'Wormhole',
      vaultMigrationBoot.unsafeInstallation
        ? 'Wormhole could not verify this installation against the machine security policy. Contact your administrator.'
        : 'Wormhole could not verify the selected workspace.',
    );
    app.quit();
    return;
  }
  const disposeVaultPowerEvents = bindVaultPowerEvents(powerMonitor, requestAutomaticVaultLock);
  app.once('will-quit', disposeVaultPowerEvents);
  if (process.platform === 'linux' || process.platform === 'win32') {
    app.once(
      'will-quit',
      bindNativeVaultSession(process.platform, backendPath, requestAutomaticVaultLock, {
        beginSleep: beginLinuxVaultSleep,
      }),
    );
  }
  recordDiagnostic('INF', 'Application started', {
    version: app.getVersion(),
    platform: process.platform,
  });
  registerIpcHandlers(sshBackend, {
    handle: (channel, listener) =>
      ipcMain.handle(channel, withIpcDiagnostics(listener, channel, recordDiagnostic)),
    on: ipcMain.on.bind(ipcMain),
  });
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
  // Auxiliary tooltips have no renderer close-confirmation or teardown handlers.
  for (const window of BrowserWindow.getAllWindows()) treeTooltips.closeForWindow(window);
  void (async () => {
    if (!(await sshBackend.prepareEditClose())) {
      quitCleanupStarted = false;
      settleUpdateQuit(
        new Error('Update cancelled because Wormhole could not close pending file edits.'),
      );
      return;
    }
    if (!skipQuitConfirmation && confirmOnWindowClose) {
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

    await sshBackend.finishEditClose();
    await withBitwardenBrowserTimeout(
      webSurfaces.checkpointVaultCookies(),
      3000,
      'Vault web cookie checkpoint timed out.',
    ).catch(() => undefined);
    try {
      // Complete every cancellable step before opening a DMG or starting a detached installer.
      await pendingUpdateQuit?.launch();
    } catch (error) {
      // Native services are still running, so a failed handoff can safely return to the app.
      isQuitting = false;
      quitCleanupStarted = false;
      settleUpdateQuit(
        error instanceof Error ? error : new Error('The installer could not be opened.'),
      );
      return;
    }
    isQuitting = true;
    if (startupUpdateTimer) clearTimeout(startupUpdateTimer);
    startupUpdateTimer = undefined;
    if (startupBackgroundTimer) clearTimeout(startupBackgroundTimer);
    startupBackgroundTimer = undefined;
    if (updateDownloadChild) {
      expectBackendExit(updateDownloadChild);
      updateDownloadChild.kill();
    }
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
      reportWarning('Browser session shutdown did not finish cleanly.', error);
    } finally {
      await Promise.allSettled(
        BrowserWindow.getAllWindows().map((window) => requestRendererTeardown(window)),
      );
      try {
        await shutdownNativeResources();
      } catch {
        // File-edit journals are finalized and native services may already be partially
        // stopped. Finish exiting instead of leaving an unusable workspace.
        reportWarning('Native resource shutdown did not finish cleanly.');
      }
      quitCleanupComplete = true;
      app.quit();
      settleUpdateQuit();
    }
  })().catch(() => {
    quitCleanupStarted = false;
    settleUpdateQuit(
      new Error('Wormhole could not close for the update. File editing copies are retained.'),
    );
    reportWarning('Close did not finish; file editing copies are retained.');
  });
});

app.on('window-all-closed', () => {
  void shutdownNativeResources().catch(() => {
    console.warn('[Wormhole] Native shutdown could not be confirmed.');
  });
  if (process.platform !== 'darwin') app.quit();
});
