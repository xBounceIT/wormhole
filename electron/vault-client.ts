import { isAbsolute, join } from 'node:path';
import type { Socket } from 'node:net';
import {
  parseSlotDefaultRequest,
  parseSlotDefaultReply,
  type SlotDefaultRequest,
  type SlotDefaultReply,
} from './vault-shared-slot-default.ts';
import {
  parseVaultSerialBundle,
  parseVaultSerialRequest,
  parseSharedSerialUse,
  type VaultSerialBundle,
} from './vault-serial-contract.ts';
import {
  parseVaultBitwardenCLIUnlockBinding,
  parseVaultBitwardenCLISession,
  type VaultBitwardenCLIEnvelope,
  type VaultBitwardenCLIUnlockBinding,
} from './vault-bitwarden-cli-unlock.ts';
import {
  maxBitwardenFrame,
  parseVaultSSHBitwardenPreparation,
  validBitwardenRevision,
  type VaultSSHBitwardenPreparation,
  type VaultBitwardenRecipient,
  type VaultSSHBitwardenRequest,
} from './vault-ssh-bitwarden.ts';
import { parseVaultMigrationContext, type VaultMigrationContext } from './vault-migration-setup.ts';
import { parseVaultUpgradeContext, type VaultUpgradeContext } from './vault-upgrade-contract.ts';
import { consumeOSMigrationPrepare } from './vault-os-migration-contract.ts';
import {
  validAdminRecoveryPaths,
  wipeAdminRecoveryInput,
  type AdminRecoveryNativeInput,
} from './vault-admin-recovery.ts';
import { validSharedArtifactPath, validSharedVaultAppVersion } from './vault-shared-unlock.ts';
import { consumeSharedAccountResetInput } from './vault-shared-account-reset.ts';
import {
  parseSharedAccountResetIssue,
  type SharedAccountResetIssueInput,
  type SharedAccountResetIssueResult,
} from './vault-shared-account-reset-issue.ts';
import {
  parseAccountResetMark,
  parseAccountResetMarkResult,
  parseAccountResetTargetPage,
  type AccountResetMark,
} from './vault-shared-account-reset-queue.ts';
import {
  parseSharedCertificateRenewalRequest,
  parseSharedCertificateRenewalResult,
  parseSharedWorkspaceCARequest,
  parseSharedWorkspaceCAResult,
  type SharedCertificateRenewalRequest,
  type SharedCertificateRenewalResult,
  type SharedWorkspaceCAResult,
  parseSharedSetupReply,
  parseSharedWorkspaceSwitch,
  type SharedSetupNativeRequest,
  type SharedSetupTarget,
  type SharedSetupNetworkOperation,
  type SharedAdminSetupRequest,
  type SharedAdminSetupOperation,
} from './vault-shared-setup-contract.ts';
import {
  parseVaultProtection,
  parseVaultUnprotectedOpened,
  vaultFields,
  vaultRecord,
  type VaultUnprotectedOpened,
} from './vault-contract.ts';
import {
  parseVaultPresenceAvailability,
  parseVaultPresenceEnrollment,
  parseVaultPresenceRemoval,
  parseVaultPresenceSelection,
  parseVaultPresenceUnlock,
  vaultHelloWindow,
  type VaultPresenceAvailability,
  type VaultPresenceEnrollment,
  type VaultPresenceKind,
  type VaultPresenceOperation,
  type VaultPresenceRemoval,
  type VaultPresenceUnlockResult,
} from './vault-presence.ts';
import {
  consumeVaultRootEnrollmentBegin,
  parseVaultRootEnrollmentContext,
  type VaultRootEnrollmentContext,
} from './vault-root-enrollment.ts';
import {
  consumeVaultMigrationBegin,
  parseVaultMigrationPrepared,
  type VaultMigrationPrepared,
} from './vault-migration-setup.ts';
import {
  parseVaultQuickSshHostReceipt,
  parseVaultQuickTargetRequest,
  parseVaultQuickTargetRef,
  parseVaultQuickTargetReleased,
  vaultQuickTargetPayload,
  type VaultQuickTargetRef,
} from './vault-quick-target.ts';
import {
  parseVaultRdpPlan,
  parseVaultRdpManualRequest,
  parseVaultRdpManualBundle,
  rdpPlanPayload,
  rdpManualPayload,
  rdpManualTarget,
} from './vault-rdp-manual.ts';
import {
  parseSharedConnectionContextRequest,
  parseSharedConnectionContext,
  type SharedConnectionContext,
  type SharedConnectionContextRequest,
} from './vault-shared-connection.ts';
import { parseSharedVaultRuntime, type SharedVaultRuntime } from './vault-shared-runtime.ts';
import { parseGroupReply, type GroupRequest } from './vault-shared-admin-groups.ts';
import { parseNodeGrantReply, type NodeGrantRequest } from './vault-shared-node-grants.ts';
import { parseGroupKeyReply, type GroupKeyRequest } from './vault-shared-group-key.ts';
import {
  parseMemberRotationReply,
  type MemberRotationRequest,
} from './vault-shared-group-member-rotation.ts';
import {
  parseGroupBoundaryGrantReply,
  type GroupBoundaryGrantRequest,
} from './vault-shared-group-boundary-grant.ts';
import {
  parseAdminInventoryReply,
  parseCreateSlotReply,
  type CredentialSlot,
  type AdminInventoryRequest,
} from './vault-shared-admin-inventory.ts';
import { parseWorkspaceAccessReply, type WorkspaceAccessRequest } from './vault-shared-access.ts';
import {
  parseAccountBoundaryRotationReply,
  parsePersonalRootRecoveryReply,
  parseAccountSuspensionReply,
  type AccountBoundaryRotationRequest,
  type PersonalRootRecoveryRequest,
  type AccountSuspensionRequest,
} from './vault-account-suspension.ts';
import { consumeSharedInitialJoinInput } from './vault-shared-initial-join.ts';
import {
  maxSharedInvitationBytes,
  parseSharedInvitation,
  validSharedInvitationText,
  type SharedInvitation,
} from './vault-shared-invitation.ts';
import {
  parseSharedCatalogRequest,
  parseSharedCatalogPage,
  type SharedCatalogPage,
  type SharedCatalogRequest,
  parseSharedChangesRequest,
  parseSharedChanges,
  type SharedChangesRequest,
  type SharedChanges,
} from './vault-shared-catalog.ts';
import {
  parseSharedNodeEditRequest,
  parseSharedNodeEditReply,
  type SharedNodeEditRequest,
  type SharedNodeEditReply,
} from './vault-shared-node-edit.ts';
import {
  parseBitwardenCleanupRequest,
  parseBitwardenCleanupResult,
  type BitwardenCleanupRequest,
  parseBitwardenZipInstallRequest,
  parseBitwardenZipInstallResult,
  parseBitwardenFolderInstallRequest,
  parseBitwardenFolderInstallResult,
  type BitwardenFolderInstallResult,
  parseBitwardenInstallationRevision,
  type BitwardenInstallationRevision,
  parseBitwardenInstallationRequest,
  parseBitwardenInstallationPlan,
  type BitwardenInstallationPlan,
  type BitwardenInstallationRequest,
  type BitwardenFolderInstallRequest,
  type BitwardenZipInstallRequest,
} from './vault-bitwarden-installation.ts';
import { confirmNativeProcessExit } from './vault-process-exit.ts';
import {
  parseBrowserTransferRequest,
  parseBrowserTransferBegun,
  parseBrowserTransferAccepted,
  parseBrowserTransferCommitted,
  parseBrowserTransferCancelled,
  parseBrowserProfileClosed,
  type BrowserTransferRequest,
} from './vault-bitwarden-native.ts';
import {
  parseBrowserTransferContext,
  parseBrowserTransferPacket,
  type BrowserTransferContext,
  type BrowserTransferManifest,
  type BrowserTransferPacket,
} from './vault-bitwarden-transfer.ts';
import {
  parseVaultWebRequest,
  parseVaultWebPlan,
  parseVaultWebViews,
  parseVaultWebViewReply,
  type VaultWebPlan,
  type VaultWebView,
} from './vault-web.ts';
import {
  maxWebSessionArchiveBytes,
  maxWebSessionArchiveReply,
  parseWebSessionArchiveReply,
  parseWebSessionArchiveWrite,
  webSessionArchiveRecipient,
  webSessionArchiveWriteRevision,
  type WebSessionArchive,
  type WebSessionArchiveCoordinates,
} from './vault-web-session-archive.ts';
import { hasChildExited } from './child-process-exit.ts';
import {
  parseVaultSshManualPlanRequest,
  parseVaultSshManualPlan,
  parseVaultSshManualRequest,
  parseVaultSshManualBundle,
  sshManualPlanPayload,
  sshManualPayload,
  type VaultSshManualPlan,
} from './vault-ssh-manual.ts';
import {
  parseVaultVncPlan,
  parseVaultVncManualRequest,
  parseVaultVncManualBundle,
  vncPlanPayload,
  vncManualPayload,
} from './vault-vnc-manual.ts';
import {
  parseVaultVncBundle,
  parseVaultRoutedVncRequest,
  parseVaultRoutedVncBundle,
  type VaultVncBundle,
  type VaultRoutedVncBundle,
} from './vault-vnc.ts';
import {
  parseVaultVNCBitwardenPlan,
  type VaultVNCBitwardenPlan,
  type VaultVNCBitwardenRequest,
} from './vault-vnc-bitwarden.ts';
import {
  parseVaultRdpBundle,
  parseVaultRoutedRdpRequest,
  parseVaultRoutedRdpBundle,
  type VaultRdpBundle,
  type VaultRoutedRdpBundle,
} from './vault-rdp.ts';
import {
  maxRDPBitwardenPlanFrame,
  parseVaultRDPBitwardenPlan,
  type VaultRDPBitwardenPlan,
  type VaultRDPBitwardenRequest,
} from './vault-rdp-bitwarden.ts';
import {
  parseVaultRecoveryRequest,
  parseVaultRecoveryRecords,
  type VaultRecoveryRequest,
  type VaultRecoveryRecordsReply,
} from './vault-sftp-recovery.ts';
import { vaultID } from './vault-contract.ts';
import {
  parseVPNSSOBegin,
  parseVPNSSOContext,
  parseVPNSSOManifest,
  parseVPNSSOPacket,
  parseVPNSSOOffer,
  parseVPNSSOCheckpoint,
  vpnSSOChunkCount,
  type VPNSSOBegin,
  type VPNSSOContext,
  type VPNSSOManifest,
  type VPNSSOPacket,
  type VPNSSOOffer,
  type VPNSSOCheckpoint,
} from './vault-vpn-sso.ts';
import { parseVaultRecoveryScopes, type VaultRecoveryScopes } from './vault-sftp-recovery.ts';
import { parseVaultFileEditSettings, type VaultFileEditSettings } from './vault-sftp-edit.ts';
import {
  parseClipboardReleaseRequest,
  type VaultClipboardReleaseRequest,
} from './vault-clipboard-release.ts';
import {
  parseVaultClipboardRequest,
  parseVaultClipboardResult,
  type VaultClipboardResult,
  type VaultClipboardRequest,
} from './vault-clipboard.ts';
import {
  parseVaultNodeDuplicate,
  parseVaultNodeDuplicateResult,
  type VaultNodeDuplicateResult,
} from './vault-node-duplicate.ts';
import {
  parseVaultNodeMove,
  parseVaultNodeMoveResult,
  type VaultNodeMoveResult,
} from './vault-node-move.ts';
import {
  parseVaultSshHostRequest,
  parseVaultSshHostPlan,
  parseVaultSshHostTrust,
  vaultSshHostPayload,
  type VaultSshHostPlan,
} from './vault-ssh-host.ts';
import {
  parseVaultRoutedSshRequest,
  parseVaultRoutedSshBundle,
  type VaultRoutedSshBundle,
} from './vault-ssh-route.ts';
import {
  parseVaultConnectionRoute,
  parseVaultRoutePlanRequest,
  type VaultRoutePlanRequest,
  parseVaultRouteBinding,
  type VaultRouteBinding,
  parseVaultRouteRequest,
  parseVaultRouteBundle,
  type VaultRouteBundle,
} from './vault-route.ts';
import {
  parseVaultTunnelFallbackPlanRequest,
  parseVaultTunnelFallbackBinding,
  parseVaultTunnelFallbackRequest,
  parseVaultTunnelFallbackBundle,
  type VaultTunnelFallbackPlanRequest,
  type VaultTunnelFallbackRequest,
  type VaultTunnelFallbackBinding,
  type VaultTunnelFallbackBundle,
} from './vault-tunnel-fallback.ts';
import {
  parseTunnelImportRequest,
  parseTunnelImportDisplay,
  parseTunnelImportDiscard,
  parseTunnelImportDiscarded,
  type VaultTunnelImportRequest,
  type VaultTunnelImportDisplay,
  type VaultTunnelImportDiscard,
} from './vault-tunnel-import.ts';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import {
  parseVaultDescription,
  parseVaultDescriptor,
  parseVaultHeartbeat,
  parseVaultResponse,
  parseVaultCatalogEvent,
  parseVaultStatus,
  parseVaultCatalog,
  parseVaultUnlockResult,
  parseVaultStartup,
} from './vault-contract.ts';
import type {
  VaultCatalog,
  VaultDescriptor,
  VaultStatus,
  VaultUnlockResult,
  VaultStartupMetadata,
} from './vault-contract.js';
import {
  consumeVaultUnlockInput,
  encodeVaultUnlockFrame,
  encodeVaultBytesFrame,
  encodeVaultBytesObject,
} from './vault-unlock.ts';
import type { VaultUnlockInput } from './vault-unlock.js';
import {
  consumeVaultEnrollmentBegin,
  consumeVaultEnrollmentConfirm,
  parseVaultEnrollment,
  parseVaultEnrollmentCancel,
  type VaultEnrollment,
} from './vault-enrollment-contract.ts';
type FactorRequest = {
  bytes: Uint8Array[];
  encode: (id: number) => Buffer;
  action?: () => Buffer;
  timeoutMs?: number;
};
import {
  parseVaultPreferences,
  type VaultPreferences,
  type VaultUpdatePreferences,
} from './vault-preferences.ts';
import { parseVaultWorkspace } from './vault-workspace.ts';
import type { VaultWorkspace } from './vault-workspace.js';
import {
  parseVaultNodeDelete,
  parseVaultNodeDeleteResult,
  type VaultNodeDeleteResult,
  type VaultNodeDeleteRequest,
} from './vault-node-delete.ts';
import { parseVaultSecurity, type VaultSecurity } from './vault-security.ts';
import {
  parseVaultSshBundle,
  canonicalBase64,
  validVaultSshRequest,
  type VaultSshRequest,
  type VaultSshBundle,
} from './vault-ssh.ts';

import {
  parseVaultFolder,
  parseVaultFolderResult,
  type VaultFolderRequest,
  type VaultFolderResult,
} from './vault-folder.ts';

import { consumeVaultConnectionInput } from './vault-connection.ts';
import {
  consumeVaultCredentialInput,
  parseVaultCredentialSelection,
  parseVaultCredentialResult,
  parseVaultCredentialDeleteResult,
  type VaultCredentialSelection,
  type VaultCredentialResult,
  type VaultCredentialDeleteResult,
} from './vault-credential.ts';
import {
  parseVaultMigrationSelection,
  parseVaultMigrationDecision,
  parseVaultMigrationReport,
  type VaultMigrationSelection,
  type VaultMigrationDecision,
  type VaultMigrationReport,
} from './vault-migration.ts';
import {
  parseVaultNotesRequest,
  parseVaultNotesDisplay,
  type VaultNotesRequest,
  type VaultNotesDisplay,
} from './vault-notes.ts';

import {
  consumeVaultTunnelInput,
  parseVaultTunnelSelection,
  parseVaultTunnelResult,
  parseVaultTunnelDeleteResult,
  parseVaultTunnelEditorRequest,
  parseVaultTunnelEditorDisplay,
  type VaultTunnelSelection,
  type VaultTunnelResult,
  type VaultTunnelDeleteResult,
  type VaultTunnelEditorRequest,
  type VaultTunnelEditorDisplay,
} from './vault-tunnel.ts';

import {
  consumeSharedVaultUnlockInput,
  consumeSharedVaultContinuationInput,
  hasSharedVaultContinuation,
  SharedConnectionLimit,
  encodeSharedVaultUnlockFrame,
  parseSharedVaultAdmission,
  parseSharedEnrollmentResult,
  requireSharedEnrollmentAdmission,
  parseSharedVaultRecovery,
  parseSharedTLSBundleExport,
  parseSharedRecoveryKitNativeRefresh,
  validSharedTLSBundlePath,
  validSharedRecoveryKitPath,
  validSharedRecoveryBackupPath,
  type SharedRecoveryKitNativeRefresh,
  type SharedVaultUnlockInput,
  type SharedVaultAdmission,
  type SharedVaultRecovery,
} from './vault-shared-unlock.ts';
import {
  parseSharedRecoveryBackup,
  type SharedRecoveryBackupResult,
} from './vault-shared-recovery-backup.ts';
import {
  parseSharedRecoveryInspectionReceipt,
  parseSharedRecoveryRestoreStatus,
  validSharedRecoveryInspection,
  validSharedRecoveryRestore,
  wipeSharedRecoveryRestore,
  type SharedRecoveryInspectionNative,
  type SharedRecoveryRestoreNative,
} from './vault-shared-restore.ts';

export const vaultMetadataFrameLimit = 64 * 1024;
export const vaultCatalogFrameLimit = 8 * 1024 * 1024;
export type VaultStopReason = 'locked' | 'unavailable' | 'protocol' | 'timeout' | 'exited';
type Options = {
  executable: string;
  databasePath: string;
  userDataPath?: string;
  migrationSessionData?: string;
  openTouchIDBroker?: (executable: string) => Socket | undefined;
  onUnavailable?: (reason: VaultStopReason) => void;
  onSharedCatalogChanged?: () => void;
  heartbeatMs?: number;
  requestTimeoutMs?: number;
  stopGraceMs?: number;
  stopConfirmationMs?: number;
};
type SpawnVault = (
  executable: string,
  args: string[],
  touchID?: Socket,
) => ChildProcessWithoutNullStreams;
type Pending = {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  parse: (value: unknown) => unknown;
  timer: NodeJS.Timeout;
  frameLimit: number;
};
type PublicPayload =
  | VaultUpdatePreferences
  | { action: ReturnType<typeof vaultSshHostPayload> | SharedNodeEditRequest | SlotDefaultRequest }
  | { sequence: string }
  | { requestId: string; session?: VaultBitwardenCLIEnvelope }
  | { ownerWindow: string; vaultId?: string; slotId?: string }
  | { slotId: string }
  | { views: VaultWebView[] }
  | { nodeIds: string[] }
  | (WebSessionArchiveCoordinates['payload'] & ({ recipient: string } | { revision: string }))
  | (SharedSetupTarget & { caPem: string })
  | { source: string; destination: string }
  | SharedCertificateRenewalRequest
  | { workspaceId: string; path?: string }
  | { invitation: string }
  | { path: string; recipient?: string }
  | (Omit<VaultTunnelFallbackPlanRequest, 'workspaceId' | 'epoch'> & { epoch: string })
  | (Omit<VaultTunnelFallbackRequest, 'workspaceId' | 'epoch'> & { epoch: string })
  | (Omit<VPNSSOBegin, 'request'> & {
      request: Omit<VaultRoutePlanRequest, 'workspaceId' | 'epoch'> & { epoch: string };
    })
  | VPNSSOPacket
  | { context: VPNSSOContext; index?: number; manifest?: VPNSSOManifest }
  | ReturnType<typeof vaultQuickTargetPayload>
  | (Omit<VaultQuickTargetRef, 'epoch'> & { epoch: string })
  | SharedCatalogRequest
  | SharedConnectionContextRequest
  | SharedChangesRequest
  | AdminInventoryRequest
  | CredentialSlot
  | WorkspaceAccessRequest
  | AccountSuspensionRequest
  | AccountBoundaryRotationRequest
  | PersonalRootRecoveryRequest
  | GroupRequest
  | NodeGrantRequest
  | GroupKeyRequest
  | MemberRotationRequest
  | GroupBoundaryGrantRequest
  | BitwardenCleanupRequest
  | BitwardenZipInstallRequest
  | BitwardenFolderInstallRequest
  | BitwardenInstallationRequest
  | (Omit<BrowserTransferRequest, 'epoch'> & { epoch: string })
  | BrowserTransferPacket
  | { context: BrowserTransferContext; index?: number }
  | { profileId: string }
  | ReturnType<typeof vncManualPayload>
  | VaultRecoveryRequest
  | { after: string }
  | AccountResetMark
  | VaultFileEditSettings
  | Omit<VaultClipboardReleaseRequest, 'workspaceId'>
  | Omit<VaultClipboardRequest, 'workspaceId'>
  | Omit<VaultTunnelImportRequest, 'workspaceId'>
  | Omit<VaultTunnelImportDiscard, 'workspaceId'>
  | VaultTunnelSelection
  | Omit<VaultTunnelEditorRequest, 'workspaceId'>
  | VaultCredentialSelection
  | VaultMigrationSelection
  | VaultMigrationDecision
  | Omit<VaultNotesRequest, 'workspaceId'>
  | VaultFolderRequest
  | VaultNodeDeleteRequest
  | {
      nodeId: string;
      credentialOverride: string;
      sessionId: string;
      requestId: string;
      epoch: string;
      publicKey?: string;
      route?: VaultRouteBinding | null;
      expected?: VaultSshHostPlan;
      received?: string;
      endpoint?: string;
    };

/** One instance owns one process lifetime. It can never restart after lock or failure. */
export class VaultBackendClient {
  private readonly options: Required<
    Omit<Options, 'onUnavailable' | 'onSharedCatalogChanged' | 'openTouchIDBroker'>
  > &
    Pick<Options, 'onUnavailable' | 'onSharedCatalogChanged' | 'openTouchIDBroker'>;
  private readonly spawnVault: SpawnVault;
  private child: ChildProcessWithoutNullStreams | undefined;
  private starting: Promise<void> | undefined;
  private rejectStart: ((error: Error) => void) | undefined;
  private startTimer: NodeJS.Timeout | undefined;
  private spawned = false;
  private retired = false;
  private exitObserved = false;
  private stopping: Promise<void> | undefined;
  private resolveStop: (() => void) | undefined;
  private rejectStop: ((error: Error) => void) | undefined;
  private graceTimer: NodeJS.Timeout | undefined;
  private confirmationTimer: NodeJS.Timeout | undefined;
  private heartbeat: NodeJS.Timeout | undefined;
  private heartbeatPending = false;
  private sequence = 0;
  private readonly pending = new Map<number, Pending>();
  private queue: Promise<unknown> = Promise.resolve();
  private queued = 0;
  private chunks: Buffer[] = [];
  private frameBytes = 0;
  private readonly factors = new Set<Uint8Array>();
  private readonly writes = new Set<Buffer>();

  constructor(
    options: Options,
    spawnVault: SpawnVault = (executable, args, touchID) =>
      spawn(executable, args, {
        stdio: touchID ? ['pipe', 'pipe', 'pipe', touchID] : 'pipe',
        windowsHide: true,
      }) as ChildProcessWithoutNullStreams,
  ) {
    this.options = {
      userDataPath: '',
      migrationSessionData: '',
      heartbeatMs: 10_000,
      requestTimeoutMs: 5_000,
      stopGraceMs: 1_500,
      stopConfirmationMs: 1_500,
      ...options,
    };
    if (
      !options.executable ||
      !options.databasePath ||
      [
        this.options.heartbeatMs,
        this.options.requestTimeoutMs,
        this.options.stopGraceMs,
        this.options.stopConfirmationMs,
      ].some((value) => !Number.isSafeInteger(value) || value <= 0 || value > 120_000)
    )
      throw new Error('Invalid vault process options.');
    this.spawnVault = spawnVault;
  }

  status(): Promise<VaultStatus> {
    return this.metadata('status', parseVaultStatus);
  }
  describe(): Promise<VaultDescriptor | null> {
    return this.metadata('describe', parseVaultDescription);
  }
  catalog(): Promise<VaultCatalog> {
    return this.metadata('catalog', parseVaultCatalog);
  }

  sharedConnectionContext(value: unknown): Promise<SharedConnectionContext> {
    const request = parseSharedConnectionContextRequest(value);
    if (!request) return Promise.reject(Error('Invalid shared connection context request.'));
    return this.metadata(
      'shared-connection-context',
      (value) => parseSharedConnectionContext(value, request),
      undefined,
      request,
    );
  }
  sharedCatalog(value: unknown): Promise<SharedCatalogPage> {
    const request = parseSharedCatalogRequest(value);
    if (!request) return Promise.reject(Error('Invalid shared catalog request.'));
    return this.metadata(
      'shared-catalog',
      (value) => parseSharedCatalogPage(value, request),
      undefined,
      request,
    );
  }
  sharedChanges(value: unknown): Promise<SharedChanges> {
    const request = parseSharedChangesRequest(value);
    if (!request) return Promise.reject(Error('Invalid shared changes request.'));
    return this.metadata(
      'shared-changes',
      (value) => parseSharedChanges(value, request),
      undefined,
      request,
    );
  }
  renewSharedServerCertificate(value: unknown): Promise<SharedCertificateRenewalResult> {
    const request = parseSharedCertificateRenewalRequest(value);
    if (!request) return Promise.reject(Error('Invalid server CSR.'));
    return this.metadata(
      'shared-renew-server-certificate',
      parseSharedCertificateRenewalResult,
      undefined,
      request,
    );
  }
  sharedWorkspaceCA(value: unknown): Promise<SharedWorkspaceCAResult> {
    const request = parseSharedWorkspaceCARequest(value);
    if (!request) return Promise.reject(Error('Invalid workspace CA request.'));
    return this.metadata(
      `shared-ca-${request.action}`,
      (response) => parseSharedWorkspaceCAResult(response, request.action),
      undefined,
      request.action === 'rotate' ? { csr: request.csr } : undefined,
    );
  }
  workspace(): Promise<VaultWorkspace> {
    return this.metadata('workspace', parseVaultWorkspace);
  }
  migrationReport(value: unknown): Promise<VaultMigrationReport> {
    const request = parseVaultMigrationSelection(value);
    if (!request) return Promise.reject(Error('Invalid migration request.'));
    return this.metadata(
      'migration-report',
      (value) => parseVaultMigrationReport(value, request),
      undefined,
      request,
    );
  }
  decideMigration(value: unknown, authentication?: VaultUnlockInput): Promise<VaultFolderResult> {
    const request = parseVaultMigrationDecision(value);
    if (!request) return this.rejectAction(authentication, Error('Invalid migration request.'));
    return this.protectedRequest(
      'migration-decide',
      (value) => {
        const result = parseVaultFolderResult(value);
        return result &&
          result.nodeId === request.nodeId &&
          BigInt(result.rowVersion) === BigInt(request.rowVersion) + 1n
          ? result
          : undefined;
      },
      undefined,
      request,
      authentication,
    );
  }
  stageTunnelImport(value: unknown): Promise<VaultTunnelImportDisplay> {
    const request = parseTunnelImportRequest(value);
    if (!request) return Promise.reject(Error('Invalid tunnel import request.'));
    const { workspaceId: _workspace, ...payload } = request;
    return this.metadata(
      'tunnel-import-stage',
      (value) => parseTunnelImportDisplay(value, request),
      undefined,
      payload,
    );
  }
  discardTunnelImport(value: unknown): Promise<{ discarded: true }> {
    const request = parseTunnelImportDiscard(value);
    if (!request) return Promise.reject(Error('Invalid tunnel import discard.'));
    return this.metadata('tunnel-import-discard', parseTunnelImportDiscarded, undefined, {
      editorId: request.editorId,
      importId: request.importId,
    });
  }
  displayTunnelEditor(value: unknown): Promise<VaultTunnelEditorDisplay> {
    const request = parseVaultTunnelEditorRequest(value);
    if (!request) return Promise.reject(Error('Invalid vault tunnel editor request.'));
    return this.metadata(
      'tunnel-editor-display',
      (value) => parseVaultTunnelEditorDisplay(value, request),
      undefined,
      {
        tunnelId: request.tunnelId,
        rowVersion: request.rowVersion,
        requestId: request.requestId,
        publicKey: request.publicKey,
      },
    );
  }
  editTunnel(value: unknown, authentication?: VaultUnlockInput): Promise<VaultTunnelResult> {
    try {
      const input = consumeVaultTunnelInput(value);
      const metadata = {
        metadata: input.metadata,
        rowVersion: input.rowVersion,
        forgetHostKey: input.forgetHostKey,
        ...(input.editorId === undefined
          ? {}
          : { editorId: input.editorId, importId: input.importId }),
      };
      const values: [string, Uint8Array][] = [['patch', input.patch]];
      return this.protectedRequest(
        'tunnel-edit',
        (value) => {
          const result = parseVaultTunnelResult(value);
          return result &&
            (!input.metadata.id || result.id === input.metadata.id) &&
            BigInt(result.rowVersion) === BigInt(input.rowVersion) + 1n
            ? result
            : undefined;
        },
        {
          bytes: [input.patch],
          encode: (id) => encodeVaultBytesFrame(id, 'tunnel-edit', metadata, values),
          action: () => encodeVaultBytesObject(metadata, values),
        },
        undefined,
        authentication,
      );
    } catch {
      return this.rejectAction(authentication, Error('Invalid vault tunnel request.'));
    }
  }
  deleteTunnel(
    value: unknown,
    authentication?: VaultUnlockInput,
  ): Promise<VaultTunnelDeleteResult> {
    const request = parseVaultTunnelSelection(value);
    if (!request) return this.rejectAction(authentication, Error('Invalid vault tunnel deletion.'));
    return this.protectedRequest(
      'tunnel-delete',
      (value) => {
        const result = parseVaultTunnelDeleteResult(value);
        return result &&
          result.id === request.id &&
          BigInt(result.rowVersion) === BigInt(request.rowVersion) + 1n
          ? result
          : undefined;
      },
      undefined,
      request,
      authentication,
    );
  }
  displayNotes(value: unknown): Promise<VaultNotesDisplay> {
    const request = parseVaultNotesRequest(value);
    if (!request) return Promise.reject(new Error('Invalid vault notes request.'));
    return this.metadata(
      'notes-display',
      (value) => parseVaultNotesDisplay(value, request),
      undefined,
      {
        nodeId: request.nodeId,
        rowVersion: request.rowVersion,
        requestId: request.requestId,
        publicKey: request.publicKey,
      },
    );
  }
  releaseClipboard(value: unknown, authentication?: VaultUnlockInput): Promise<VaultNotesDisplay> {
    const request = parseClipboardReleaseRequest(value);
    if (!request)
      return this.rejectAction(authentication, Error('Invalid clipboard release request.'));
    return this.protectedRequest(
      'credential-clipboard-release',
      (value) => parseVaultNotesDisplay(value, request),
      undefined,
      {
        nodeId: request.nodeId,
        rowVersion: request.rowVersion,
        field: request.field,
        requestId: request.requestId,
        publicKey: request.publicKey,
      },
      authentication,
    );
  }
  copyCredential(value: unknown, authentication?: VaultUnlockInput): Promise<VaultClipboardResult> {
    const request = parseVaultClipboardRequest(value);
    if (!request) return this.rejectAction(authentication, Error('Invalid clipboard request.'));
    return this.protectedRequest(
      'credential-copy',
      parseVaultClipboardResult,
      undefined,
      { nodeId: request.nodeId, rowVersion: request.rowVersion, field: request.field },
      authentication,
    );
  }
  displayCredentials(
    value: unknown,
    authentication?: VaultUnlockInput,
  ): Promise<VaultNotesDisplay> {
    const request = parseVaultNotesRequest(value);
    if (!request)
      return this.rejectAction(authentication, new Error('Invalid credential display request.'));
    return this.protectedRequest(
      'credential-display',
      (value) => parseVaultNotesDisplay(value, request),
      undefined,
      {
        nodeId: request.nodeId,
        rowVersion: request.rowVersion,
        requestId: request.requestId,
        publicKey: request.publicKey,
      },
      authentication,
    );
  }
  editCredential(
    value: unknown,
    authentication?: VaultUnlockInput,
  ): Promise<VaultCredentialResult> {
    try {
      const input = consumeVaultCredentialInput(value);
      const metadata = { metadata: input.metadata, rowVersion: input.rowVersion };
      const values: [string, Uint8Array][] = [
        ['password', input.password],
        ['passphrase', input.passphrase],
      ];
      return this.protectedRequest(
        'credential-edit',
        (value) => {
          const result = parseVaultCredentialResult(value);
          return result &&
            (!input.metadata.id || result.id === input.metadata.id) &&
            BigInt(result.rowVersion) === BigInt(input.rowVersion) + 1n
            ? result
            : undefined;
        },
        {
          bytes: [input.password, input.passphrase],
          encode: (id) => encodeVaultBytesFrame(id, 'credential-edit', metadata, values),
          action: () => encodeVaultBytesObject(metadata, values),
        },
        undefined,
        authentication,
      );
    } catch {
      return this.rejectAction(authentication, Error('Invalid vault credential request.'));
    }
  }
  deleteCredential(
    value: unknown,
    authentication?: VaultUnlockInput,
  ): Promise<VaultCredentialDeleteResult> {
    const request = parseVaultCredentialSelection(value);
    if (!request)
      return this.rejectAction(authentication, Error('Invalid vault credential deletion.'));
    return this.protectedRequest(
      'credential-delete',
      (value) => {
        const result = parseVaultCredentialDeleteResult(value);
        return result &&
          result.id === request.id &&
          BigInt(result.rowVersion) === BigInt(request.rowVersion) + 1n
          ? result
          : undefined;
      },
      undefined,
      request,
      authentication,
    );
  }
  saveConnection(value: unknown, authentication?: VaultUnlockInput): Promise<VaultFolderResult> {
    try {
      const input = consumeVaultConnectionInput(value);
      const metadata = {
        metadata: input.metadata,
        rowVersion: input.rowVersion,
        notesAction: input.notesAction,
      };
      const values: [string, Uint8Array][] = [
        ['password', input.password],
        ['notes', input.notes],
      ];
      return this.protectedRequest(
        'connection-save',
        (value) => {
          const result = parseVaultFolderResult(value);
          if (
            !result ||
            (input.metadata.id && result.nodeId !== input.metadata.id) ||
            BigInt(result.rowVersion) !== BigInt(input.rowVersion) + 1n
          )
            return undefined;
          return result;
        },
        {
          bytes: [input.password, input.notes],
          encode: (id) => encodeVaultBytesFrame(id, 'connection-save', metadata, values),
          action: () => encodeVaultBytesObject(metadata, values),
        },
        undefined,
        authentication,
      );
    } catch {
      return this.rejectAction(authentication, new Error('Invalid vault connection request.'));
    }
  }
  saveFolder(value: unknown, authentication?: VaultUnlockInput): Promise<VaultFolderResult> {
    const request = parseVaultFolder(value);
    if (!request)
      return this.rejectAction(authentication, new Error('Invalid vault folder request.'));
    return this.protectedRequest(
      'folder-save',
      (value) => {
        const result = parseVaultFolderResult(value);
        if (
          !result ||
          (request.id && result.nodeId !== request.id) ||
          BigInt(result.rowVersion) !== BigInt(request.rowVersion) + 1n
        )
          return undefined;
        return result;
      },
      undefined,
      request,
      authentication,
    );
  }
  deleteNodes(value: unknown, authentication?: VaultUnlockInput): Promise<VaultNodeDeleteResult> {
    const request = parseVaultNodeDelete(value);
    if (!request)
      return this.rejectAction(authentication, new Error('Invalid vault deletion request.'));
    return this.protectedRequest(
      'node-delete-trees',
      parseVaultNodeDeleteResult,
      undefined,
      request,
      authentication,
    );
  }
  moveNodes(value: unknown, authentication?: VaultUnlockInput): Promise<VaultNodeMoveResult> {
    const request = parseVaultNodeMove(value);
    if (!request)
      return this.rejectAction(authentication, new Error('Invalid vault move request.'));
    return this.protectedRequest(
      'node-move',
      parseVaultNodeMoveResult,
      undefined,
      request,
      authentication,
    );
  }
  duplicateConnection(
    value: unknown,
    authentication?: VaultUnlockInput,
  ): Promise<VaultNodeDuplicateResult> {
    const request = parseVaultNodeDuplicate(value);
    if (!request)
      return this.rejectAction(authentication, new Error('Invalid vault duplicate request.'));
    return this.protectedRequest(
      'node-duplicate',
      (value) => {
        const result = parseVaultNodeDuplicateResult(value);
        return result && result.nodeId !== request.id ? result : undefined;
      },
      undefined,
      request,
      authentication,
    );
  }
  sftpRecoveryRecords(value: unknown, workspace?: string): Promise<VaultRecoveryRecordsReply> {
    const q = parseVaultRecoveryRequest(value);
    if (!q) return Promise.reject(Error('Invalid recovery request.'));
    let revealPath: string | undefined;
    if (q.operation === 'reveal') {
      const root = this.options.userDataPath;
      if (!vaultID(workspace) || !root || !isAbsolute(root))
        return Promise.reject(Error('Recovery folder is unavailable.'));
      revealPath = join(
        root,
        'vault-sftp-edit',
        workspace,
        q.nodeId,
        'sftp-edit',
        q.editId,
        'files',
      );
    }
    return this.metadata(
      'sftp-recovery-records',
      (value) => parseVaultRecoveryRecords(value, q, revealPath),
      undefined,
      q,
    );
  }
  sftpRecoveryScopes(after = ''): Promise<VaultRecoveryScopes> {
    if (after !== '' && !vaultID(after)) return Promise.reject(Error('Invalid recovery cursor.'));
    return this.metadata(
      'sftp-recovery-scopes',
      (value) => parseVaultRecoveryScopes(value, after),
      undefined,
      { after },
    );
  }
  fileEditSettings(value?: unknown): Promise<VaultFileEditSettings> {
    const request = value === undefined ? undefined : parseVaultFileEditSettings(value);
    if (value !== undefined && !request)
      return Promise.reject(Error('Invalid file editor settings.'));
    return this.metadata('file-edit-settings', parseVaultFileEditSettings, undefined, request);
  }
  preferences(): Promise<VaultPreferences> {
    return this.metadata('preferences', parseVaultPreferences);
  }
  updatePreferences(value: VaultUpdatePreferences): Promise<true> {
    return this.metadata(
      'update-preferences',
      (reply) => (reply === true ? true : undefined),
      undefined,
      value,
    );
  }
  exportLocalBackup(path: string, authentication?: VaultUnlockInput): Promise<true> {
    return this.protectedRequest(
      'local-backup-export',
      (value) => (value === 'exported' ? true : undefined),
      undefined,
      { path },
      authentication,
    );
  }
  tightenLocalProfile(sequence: string, authentication: VaultUnlockInput): Promise<true> {
    return this.protectedRequest(
      'tighten-local-profile',
      (value) => (value === true ? true : undefined),
      undefined,
      { sequence },
      authentication,
    );
  }
  inspectLocalBackup(path: string): Promise<{ slots: VaultDescriptor; fingerprint: string }> {
    return this.metadata(
      'local-backup-inspect',
      (value) => {
        if (!value || typeof value !== 'object' || Object.keys(value).length !== 2)
          return undefined;
        const { slots, fingerprint } = value as Record<string, unknown>;
        const descriptor = parseVaultDescriptor(slots);
        return descriptor?.encrypted &&
          descriptor.slots.length === 1 &&
          descriptor.slots[0].kind === 'recovery' &&
          typeof fingerprint === 'string' &&
          /^[a-f0-9]{64}$/.test(fingerprint)
          ? { slots: descriptor, fingerprint }
          : undefined;
      },
      undefined,
      { path },
    );
  }
  installLocalBackup(path: string, fingerprint: string, recoveryCode: Uint8Array): Promise<true> {
    return this.secretRequest(
      'local-backup-install',
      (value) => (value === 'restored' ? true : undefined),
      {
        bytes: [recoveryCode],
        encode: (id) =>
          encodeVaultBytesFrame(id, 'local-backup-install', { path, fingerprint }, [
            ['recoveryCode', recoveryCode],
          ]),
      },
    );
  }
  async startup(): Promise<VaultStartupMetadata> {
    const result = await this.metadata('startup', parseVaultStartup);
    if (this.options.migrationSessionData && result.unprotected) {
      const { unprotected, ...rest } = result;
      return { ...rest, upgrade: unprotected };
    }
    return result;
  }
  openUnprotected(create: boolean): Promise<VaultUnprotectedOpened> {
    return this.metadata(
      create ? 'unprotected-create' : 'unprotected-open',
      parseVaultUnprotectedOpened,
    );
  }
  protection(): Promise<{ protected: boolean }> {
    return this.metadata('protection', parseVaultProtection);
  }
  resumeOSMigration(): Promise<VaultUnprotectedOpened> {
    if (!this.options.migrationSessionData)
      return Promise.reject(Error('Vault maintenance restart required.'));
    return this.metadata('migration-os-resume', parseVaultUnprotectedOpened);
  }
  osMigrationContext(): Promise<VaultMigrationContext> {
    return this.metadata('migration-os-context', parseVaultMigrationContext);
  }
  prepareOSMigration(value: unknown): Promise<VaultMigrationPrepared> {
    try {
      const input = consumeOSMigrationPrepare(value);
      return this.secretRequest('migration-os-prepare', parseVaultMigrationPrepared, {
        bytes: [input.legacyFactor],
        encode: (id) =>
          encodeVaultBytesFrame(id, 'migration-os-prepare', { legacyMethod: input.legacyMethod }, [
            ['legacyFactor', input.legacyFactor],
          ]),
      });
    } catch {
      return Promise.reject(Error('Invalid migration preparation.'));
    }
  }
  security(): Promise<VaultSecurity> {
    return this.metadata('security', parseVaultSecurity);
  }
  sharedRuntime(): Promise<SharedVaultRuntime> {
    return this.metadata('shared-runtime', parseSharedVaultRuntime);
  }
  sshHostPlan(value: unknown): Promise<VaultSshHostPlan> {
    const q = parseVaultSshHostRequest(value);
    if (!q) return Promise.reject(Error('Invalid SSH host plan.'));
    return this.metadata(
      'ssh-host-plan',
      (value) => parseVaultSshHostPlan(value, q),
      undefined,
      vaultSshHostPayload(q),
    );
  }
  trustSshHost(value: unknown, authentication?: VaultUnlockInput): Promise<VaultFolderResult> {
    const q = parseVaultSshHostTrust(value);
    if (!q) return this.rejectAction(authentication, Error('Invalid SSH host confirmation.'));
    return this.protectedRequest(
      'ssh-host-trust',
      parseVaultFolderResult,
      undefined,
      vaultSshHostPayload(q),
      authentication,
    );
  }
  sharedNodeEdit(
    value: unknown,
    authentication?: SharedVaultUnlockInput,
  ): Promise<SharedNodeEditReply> {
    const request = parseSharedNodeEditRequest(value);
    if (!request || (authentication && !request.changes)) {
      authentication?.password.fill(0);
      authentication?.ask?.fill(0);
      return Promise.reject(Error('Invalid shared node edit.'));
    }
    return this.sharedCustodianRequest(
      'shared-node-edit',
      (value) => parseSharedNodeEditReply(value, request),
      { action: request },
      authentication,
    );
  }
  trustSharedSshHost(
    value: unknown,
    authentication?: SharedVaultUnlockInput,
  ): Promise<VaultFolderResult> {
    const request = parseVaultSshHostTrust(value);
    if (!request) {
      authentication?.password.fill(0);
      authentication?.ask?.fill(0);
      return Promise.reject(Error('Invalid shared SSH host confirmation.'));
    }
    return this.sharedCustodianRequest(
      'shared-ssh-host-trust',
      (value) => {
        const receipt = parseVaultFolderResult(value);
        return receipt?.nodeId === request.nodeId ? receipt : undefined;
      },
      { action: vaultSshHostPayload(request) },
      authentication,
    );
  }
  connectionRoute(value: unknown): Promise<VaultRouteBinding | null> {
    const q = parseVaultRoutePlanRequest(value);
    if (!q) return Promise.reject(Error('Invalid vault route request.'));
    return this.metadata(
      'connection-route',
      (value) => parseVaultConnectionRoute(value, q),
      undefined,
      {
        nodeId: q.nodeId,
        credentialOverride: q.credentialOverride,
        sessionId: q.sessionId,
        requestId: q.requestId,
        epoch: String(q.epoch),
      },
    );
  }
  cleanupBitwardenInstallations(
    value: unknown,
    authentication?: VaultUnlockInput,
  ): Promise<BitwardenInstallationRevision> {
    const q = parseBitwardenCleanupRequest(value);
    if (!q) return this.rejectAction(authentication, Error('Invalid Bitwarden cleanup request.'));
    return this.protectedRequest(
      'bitwarden-cleanup',
      (v) => parseBitwardenCleanupResult(v, q),
      undefined,
      q,
      authentication,
    );
  }
  installBitwardenZip(
    value: unknown,
    authentication?: VaultUnlockInput,
  ): Promise<BitwardenFolderInstallResult> {
    const q = parseBitwardenZipInstallRequest(value);
    if (!q)
      return this.rejectAction(authentication, Error('Invalid Bitwarden installation request.'));
    return this.protectedRequest(
      'bitwarden-install-zip',
      (v) => parseBitwardenZipInstallResult(v, q),
      undefined,
      q,
      authentication,
    );
  }
  installBitwardenFolder(
    value: unknown,
    authentication?: VaultUnlockInput,
  ): Promise<BitwardenFolderInstallResult> {
    const q = parseBitwardenFolderInstallRequest(value);
    if (!q)
      return this.rejectAction(authentication, Error('Invalid Bitwarden installation request.'));
    return this.protectedRequest(
      'bitwarden-install-folder',
      (v) => parseBitwardenFolderInstallResult(v, q),
      undefined,
      q,
      authentication,
    );
  }
  bitwardenInstallationRevision(value: unknown): Promise<BitwardenInstallationRevision> {
    const q = parseBitwardenInstallationRequest(value);
    if (!q) return Promise.reject(Error('Invalid Bitwarden installation request.'));
    return this.metadata(
      'bitwarden-installation-revision',
      (v) => parseBitwardenInstallationRevision(v, q),
      undefined,
      q,
    );
  }
  bitwardenInstallationPlan(value: unknown): Promise<BitwardenInstallationPlan> {
    const q = parseBitwardenInstallationRequest(value);
    if (!q) return Promise.reject(Error('Invalid Bitwarden installation request.'));
    return this.metadata(
      'bitwarden-installation-plan',
      (v) => parseBitwardenInstallationPlan(v, q),
      undefined,
      q,
    );
  }
  beginBitwardenTransfer(value: unknown): Promise<BrowserTransferContext> {
    const q = parseBrowserTransferRequest(value);
    if (!q) return Promise.reject(Error('Invalid browser transfer.'));
    return this.metadata(
      'bitwarden-transfer-begin',
      (v) => parseBrowserTransferBegun(v, q),
      undefined,
      { ...q, epoch: String(q.epoch) },
    );
  }
  pushBitwardenTransfer(value: unknown): Promise<{ accepted: true; index: number }> {
    const c =
      typeof value === 'object' && value !== null && 'context' in value ? value.context : undefined;
    const context = parseBrowserTransferContext(c);
    const p = context && parseBrowserTransferPacket(value, context, 'capture');
    if (!p) return Promise.reject(Error('Invalid browser transfer packet.'));
    return this.metadata(
      'bitwarden-transfer-push',
      (v) => parseBrowserTransferAccepted(v, p.index),
      undefined,
      p,
    );
  }
  commitBitwardenTransfer(value: unknown): Promise<BrowserTransferManifest> {
    const c = parseBrowserTransferContext(value);
    if (!c) return Promise.reject(Error('Invalid browser transfer.'));
    return this.metadata(
      'bitwarden-transfer-commit',
      (v) => parseBrowserTransferCommitted(v, c),
      undefined,
      { context: c },
    );
  }
  takeBitwardenTransfer(value: unknown, index: number): Promise<BrowserTransferPacket> {
    const c = parseBrowserTransferContext(value);
    if (!c || !Number.isInteger(index) || index < 0 || index > 4)
      return Promise.reject(Error('Invalid browser transfer chunk.'));
    return this.metadata(
      'bitwarden-transfer-take',
      (v) => {
        const p = parseBrowserTransferPacket(v, c, 'restore');
        return p?.index === index ? p : undefined;
      },
      undefined,
      { context: c, index },
    );
  }
  cancelBitwardenTransfer(value: unknown): Promise<{ cancelled: true }> {
    const c = parseBrowserTransferContext(value);
    if (!c) return Promise.reject(Error('Invalid browser transfer.'));
    return this.metadata('bitwarden-transfer-cancel', parseBrowserTransferCancelled, undefined, {
      context: c,
    });
  }
  closeBitwardenProfile(profileId: string): Promise<{ closed: true }> {
    if (!vaultID(profileId)) return Promise.reject(Error('Invalid browser profile.'));
    return this.metadata('bitwarden-profile-close', parseBrowserProfileClosed, undefined, {
      profileId,
    });
  }
  webPlan(value: unknown): Promise<VaultWebPlan> {
    const q = parseVaultWebRequest(value);
    if (!q) return Promise.reject(Error('Invalid vault web plan.'));
    return this.metadata('web-plan', (v) => parseVaultWebPlan(v, q), undefined, {
      nodeId: q.nodeId,
      credentialOverride: '',
      sessionId: q.sessionId,
      requestId: q.requestId,
      epoch: String(q.epoch),
    });
  }
  checkWebSessionViews(value: unknown): Promise<boolean[]> {
    const views = parseVaultWebViews(value);
    if (!views) return Promise.reject(Error('Invalid web session View check.'));
    return this.metadata(
      'web-session-verify-views',
      (reply) => parseVaultWebViewReply(reply, views.length),
      undefined,
      { views },
    );
  }
  async readWebSessionArchive(context: WebSessionArchiveCoordinates): Promise<WebSessionArchive> {
    const recipient = await webSessionArchiveRecipient(context);
    try {
      const response = await this.metadata(
        'web-session-read',
        parseWebSessionArchiveReply,
        undefined,
        {
          ...context.payload,
          recipient: recipient.publicKey,
        },
      );
      if (!('bundle' in response)) return { revision: response.revision };
      const bytes = await recipient.open(response.bundle, [response.revision]);
      if (this.retired) {
        bytes.fill(0);
        throw Error('Vault is unavailable.');
      }
      return { revision: response.revision, bytes };
    } finally {
      recipient.dispose();
    }
  }
  async saveWebSessionArchive(
    context: WebSessionArchiveCoordinates,
    revision: string,
    bytes: Uint8Array,
  ): Promise<string> {
    if (
      !webSessionArchiveWriteRevision(revision) ||
      bytes.length === 0 ||
      bytes.length > maxWebSessionArchiveBytes
    ) {
      bytes.fill(0);
      throw Error('Invalid web session archive.');
    }
    return this.secretRequest(
      'web-session-save',
      (value) => parseWebSessionArchiveWrite(value, revision),
      {
        bytes: [bytes],
        encode: (id) =>
          encodeVaultBytesFrame(id, 'web-session-save', { ...context.payload, revision }, [
            ['archive', bytes],
          ]),
      },
    );
  }
  async forgetWebSessionArchive(
    context: WebSessionArchiveCoordinates,
    revision: string,
  ): Promise<string> {
    if (!webSessionArchiveWriteRevision(revision))
      throw Error('Invalid web session archive revision.');
    return this.metadata(
      'web-session-forget',
      (value) => parseWebSessionArchiveWrite(value, revision),
      undefined,
      {
        ...context.payload,
        revision,
      },
    );
  }
  registerQuickTarget(value: unknown): Promise<VaultQuickTargetRef> {
    const q = parseVaultQuickTargetRequest(value);
    if (!q) return Promise.reject(Error('Invalid temporary target.'));
    return this.metadata(
      'quick-target-register',
      (result) => parseVaultQuickTargetRef(result, q),
      undefined,
      vaultQuickTargetPayload(q),
    );
  }
  releaseQuickTarget(value: unknown): Promise<true> {
    const q = parseVaultQuickTargetRef(value);
    if (!q) return Promise.reject(Error('Invalid temporary target release.'));
    return this.metadata('quick-target-release', parseVaultQuickTargetReleased, undefined, {
      ...q,
      epoch: String(q.epoch),
    });
  }
  trustQuickSshHost(value: unknown, authentication?: VaultUnlockInput): Promise<VaultSshHostPlan> {
    const q = parseVaultSshHostTrust(value);
    if (!q || q.credentialOverride !== '')
      return this.rejectAction(authentication, Error('Invalid temporary host confirmation.'));
    return this.protectedRequest(
      'ssh-quick-host-trust',
      (result) => parseVaultQuickSshHostReceipt(result, q),
      undefined,
      vaultSshHostPayload(q),
      authentication,
    );
  }
  rdpPlan(value: unknown): Promise<VaultRdpBundle['binding']> {
    const q = parseVaultRoutePlanRequest(value);
    if (!q) return Promise.reject(Error('Invalid RDP plan.'));
    return this.metadata('rdp-plan', (v) => parseVaultRdpPlan(v, q), undefined, rdpPlanPayload(q));
  }
  rdpManualBundle(value: unknown): Promise<VaultRdpBundle | VaultRoutedRdpBundle> {
    const q = parseVaultRdpManualRequest(value);
    if (!q) return Promise.reject(Error('Invalid temporary RDP request.'));
    return this.metadata(
      q.context.endpoint ? 'rdp-manual-route-bundle' : 'rdp-manual-bundle',
      (v) => parseVaultRdpManualBundle(v, q),
      undefined,
      rdpManualPayload(q),
    );
  }
  prepareManualRDPBitwarden(
    value: unknown,
    recipient?: VaultBitwardenRecipient,
  ): Promise<VaultRDPBitwardenPlan> {
    const q = parseVaultRdpManualRequest(value);
    const resolver = recipient && { ...recipient };
    if (
      !q ||
      q.context.endpoint ||
      (resolver &&
        (!validBitwardenRevision(resolver.revision) ||
          !canonicalBase64(resolver.publicKey, 32, 32)))
    )
      return Promise.reject(Error('Invalid temporary Bitwarden RDP request.'));
    const target = rdpManualTarget(q);
    return this.metadata(
      'rdp-manual-bitwarden-prepare',
      (value) => {
        const plan = parseVaultRDPBitwardenPlan(value, target, resolver);
        return plan?.required && plan.release && !parseVaultRdpManualBundle(plan.release.base, q)
          ? undefined
          : plan;
      },
      undefined,
      {
        ...rdpManualPayload(q),
        ...(resolver ? { resolverPublicKey: resolver.publicKey, revision: resolver.revision } : {}),
      },
    );
  }
  sshManualPlan(value: unknown): Promise<VaultSshManualPlan> {
    const q = parseVaultSshManualPlanRequest(value);
    if (!q) return Promise.reject(Error('Invalid SSH manual plan.'));
    return this.metadata(
      'ssh-manual-plan',
      (v) => parseVaultSshManualPlan(v, q),
      undefined,
      sshManualPlanPayload(q),
    );
  }
  sshManualBundle(value: unknown): Promise<VaultSshBundle | VaultRoutedSshBundle> {
    const q = parseVaultSshManualRequest(value);
    if (!q) return Promise.reject(Error('Invalid temporary SSH request.'));
    return this.metadata(
      'ssh-manual-bundle',
      (v) => parseVaultSshManualBundle(v, q),
      undefined,
      sshManualPayload(q),
    );
  }
  vncPlan(value: unknown): Promise<VaultVncBundle['binding']> {
    const q = parseVaultRoutePlanRequest(value);
    if (!q) return Promise.reject(Error('Invalid VNC plan.'));
    return this.metadata('vnc-plan', (v) => parseVaultVncPlan(v, q), undefined, vncPlanPayload(q));
  }
  vncManualBundle(value: unknown): Promise<VaultVncBundle | VaultRoutedVncBundle> {
    const q = parseVaultVncManualRequest(value);
    if (!q) return Promise.reject(Error('Invalid temporary VNC request.'));
    return this.metadata(
      q.context.endpoint ? 'vnc-manual-route-bundle' : 'vnc-manual-bundle',
      (v) => parseVaultVncManualBundle(v, q),
      undefined,
      vncManualPayload(q),
    );
  }
  vncBundle(value: unknown): Promise<VaultVncBundle> {
    const q = parseVaultRouteRequest(value);
    if (!q) return Promise.reject(Error('Invalid vault VNC request.'));
    return this.metadata('vnc-bundle', (value) => parseVaultVncBundle(value, q), undefined, {
      nodeId: q.nodeId,
      credentialOverride: q.credentialOverride,
      sessionId: q.sessionId,
      requestId: q.requestId,
      epoch: String(q.epoch),
      publicKey: q.publicKey,
    });
  }
  prepareVNCBitwarden(
    value: VaultVNCBitwardenRequest,
    recipient?: VaultBitwardenRecipient,
  ): Promise<VaultVNCBitwardenPlan> {
    const routed = 'route' in value ? parseVaultRoutedVncRequest(value) : undefined;
    const q = 'route' in value ? routed : parseVaultRouteRequest(value);
    const resolver = recipient && { ...recipient };
    if (
      !q ||
      (resolver &&
        (!validBitwardenRevision(resolver.revision) ||
          !canonicalBase64(resolver.publicKey, 32, 32)))
    )
      return Promise.reject(Error('Invalid Bitwarden VNC request.'));
    return this.metadata(
      'vnc-bitwarden-prepare',
      (reply) => parseVaultVNCBitwardenPlan(reply, q, resolver),
      undefined,
      {
        nodeId: q.nodeId,
        credentialOverride: q.credentialOverride,
        sessionId: q.sessionId,
        requestId: q.requestId,
        epoch: String(q.epoch),
        publicKey: q.publicKey,
        ...(routed ? { route: routed.route, endpoint: routed.endpoint } : {}),
        ...(resolver ? { resolverPublicKey: resolver.publicKey, revision: resolver.revision } : {}),
      },
    );
  }
  routedVncBundle(value: unknown): Promise<VaultRoutedVncBundle> {
    const q = parseVaultRoutedVncRequest(value);
    if (!q) return Promise.reject(Error('Invalid vault VNC route request.'));
    return this.metadata(
      'vnc-route-bundle',
      (value) => parseVaultRoutedVncBundle(value, q),
      undefined,
      {
        nodeId: q.nodeId,
        credentialOverride: q.credentialOverride,
        sessionId: q.sessionId,
        requestId: q.requestId,
        epoch: String(q.epoch),
        publicKey: q.publicKey,
        route: q.route,
        endpoint: q.endpoint,
      },
    );
  }
  rdpBundle(value: unknown): Promise<VaultRdpBundle> {
    const q = parseVaultRouteRequest(value);
    if (!q) return Promise.reject(Error('Invalid vault RDP request.'));
    return this.metadata('rdp-bundle', (value) => parseVaultRdpBundle(value, q), undefined, {
      nodeId: q.nodeId,
      credentialOverride: q.credentialOverride,
      sessionId: q.sessionId,
      requestId: q.requestId,
      epoch: String(q.epoch),
      publicKey: q.publicKey,
    });
  }
  serialBundle(value: unknown): Promise<VaultSerialBundle> {
    const q = parseVaultSerialRequest(value);
    if (!q) return Promise.reject(Error('Invalid protected serial request.'));
    return this.metadata('serial-bundle', (reply) => parseVaultSerialBundle(reply, q), undefined, {
      nodeId: q.nodeId,
      sessionId: q.sessionId,
      requestId: q.requestId,
      epoch: String(q.epoch),
      publicKey: q.publicKey,
      ...(q.quick ? { quick: q.quick } : {}),
    });
  }
  checkSharedSerialUse(nodeIds: readonly string[]): Promise<boolean[]> {
    const ids = [...nodeIds];
    if (
      ids.length === 0 ||
      ids.length > 32 ||
      !ids.every(vaultID) ||
      new Set(ids).size !== ids.length
    )
      return Promise.reject(Error('Invalid shared serial permission check.'));
    return this.metadata(
      'serial-use-check',
      (reply) => parseSharedSerialUse(reply, ids.length),
      undefined,
      { nodeIds: ids },
    );
  }
  prepareRDPBitwarden(
    value: VaultRDPBitwardenRequest,
    recipient?: VaultBitwardenRecipient,
  ): Promise<VaultRDPBitwardenPlan> {
    const routed = 'route' in value ? parseVaultRoutedRdpRequest(value) : undefined;
    const q = 'route' in value ? routed : parseVaultRouteRequest(value);
    const resolver = recipient && { ...recipient };
    if (
      !q ||
      (resolver &&
        (!validBitwardenRevision(resolver.revision) ||
          !canonicalBase64(resolver.publicKey, 32, 32)))
    )
      return Promise.reject(Error('Invalid Bitwarden RDP request.'));
    return this.metadata(
      'rdp-bitwarden-prepare',
      (reply) => parseVaultRDPBitwardenPlan(reply, q, resolver),
      undefined,
      {
        nodeId: q.nodeId,
        credentialOverride: q.credentialOverride,
        sessionId: q.sessionId,
        requestId: q.requestId,
        epoch: String(q.epoch),
        publicKey: q.publicKey,
        ...(routed ? { route: routed.route, endpoint: routed.endpoint } : {}),
        ...(resolver ? { resolverPublicKey: resolver.publicKey, revision: resolver.revision } : {}),
      },
    );
  }
  routedRdpBundle(value: unknown): Promise<VaultRoutedRdpBundle> {
    const q = parseVaultRoutedRdpRequest(value);
    if (!q) return Promise.reject(Error('Invalid vault RDP route request.'));
    return this.metadata(
      'rdp-route-bundle',
      (value) => parseVaultRoutedRdpBundle(value, q),
      undefined,
      {
        nodeId: q.nodeId,
        credentialOverride: q.credentialOverride,
        sessionId: q.sessionId,
        requestId: q.requestId,
        epoch: String(q.epoch),
        publicKey: q.publicKey,
        route: q.route,
        endpoint: q.endpoint,
      },
    );
  }
  routedSshBundle(value: unknown): Promise<VaultRoutedSshBundle> {
    const q = parseVaultRoutedSshRequest(value);
    if (!q) return Promise.reject(Error('Invalid vault SSH route request.'));
    return this.metadata(
      'ssh-route-bundle',
      (value) => parseVaultRoutedSshBundle(value, q),
      undefined,
      {
        nodeId: q.nodeId,
        credentialOverride: q.credentialOverride,
        sessionId: q.sessionId,
        requestId: q.requestId,
        epoch: String(q.epoch),
        publicKey: q.publicKey,
        route: q.route,
        endpoint: q.endpoint,
        ...(q.sftpOnly ? { sftpOnly: true } : {}),
      },
    );
  }
  tunnelPlan(value: unknown): Promise<VaultRouteBinding> {
    const q = parseVaultRoutePlanRequest(value);
    if (!q) return Promise.reject(Error('Invalid vault route request.'));
    return this.metadata('tunnel-plan', (value) => parseVaultRouteBinding(value, q), undefined, {
      nodeId: q.nodeId,
      credentialOverride: q.credentialOverride,
      sessionId: q.sessionId,
      requestId: q.requestId,
      epoch: String(q.epoch),
    });
  }
  tunnelBundle(value: unknown): Promise<VaultRouteBundle> {
    const request = parseVaultRouteRequest(value);
    if (!request) return Promise.reject(Error('Invalid vault route request.'));
    return this.metadata(
      'tunnel-bundle',
      (value) => parseVaultRouteBundle(value, request),
      undefined,
      {
        nodeId: request.nodeId,
        credentialOverride: request.credentialOverride,
        sessionId: request.sessionId,
        requestId: request.requestId,
        epoch: String(request.epoch),
        publicKey: request.publicKey,
      },
    );
  }
  tunnelFallbackPlan(value: unknown): Promise<VaultTunnelFallbackBinding> {
    const q = parseVaultTunnelFallbackPlanRequest(value);
    if (!q) return Promise.reject(Error('Invalid vault fallback request.'));
    const { workspaceId: _, epoch, ...payload } = q;
    return this.metadata(
      'tunnel-fallback-plan',
      (value) => parseVaultTunnelFallbackBinding(value, q),
      undefined,
      { ...payload, epoch: String(epoch) },
    );
  }
  tunnelFallbackBundle(value: unknown): Promise<VaultTunnelFallbackBundle> {
    const q = parseVaultTunnelFallbackRequest(value);
    if (!q) return Promise.reject(Error('Invalid vault fallback request.'));
    const { workspaceId: _, epoch, ...payload } = q;
    return this.metadata(
      'tunnel-fallback-bundle',
      (value) => parseVaultTunnelFallbackBundle(value, q),
      undefined,
      { ...payload, epoch: String(epoch) },
    );
  }
  beginVPNSSO(value: unknown): Promise<VPNSSOOffer> {
    const q = parseVPNSSOBegin(value);
    if (!q) return Promise.reject(Error('Invalid VPN SSO request.'));
    const { workspaceId: _, ...request } = q.request;
    return this.metadata('vpn-sso-begin', (v) => parseVPNSSOOffer(v, q), undefined, {
      ...q,
      request: { ...request, epoch: String(request.epoch) },
    });
  }
  takeVPNSSO(value: unknown, manifest: unknown, index: number): Promise<VPNSSOPacket> {
    const c = parseVPNSSOContext(value),
      m = c && parseVPNSSOManifest(manifest, c, 'restore');
    if (!c || !m || !Number.isInteger(index) || index < 0 || index >= vpnSSOChunkCount(m))
      return Promise.reject(Error('Invalid VPN SSO chunk.'));
    return this.metadata(
      'vpn-sso-take',
      (v) => {
        const p = parseVPNSSOPacket(v, c, 'restore');
        return p?.index === index && p.manifest.bytes === m.bytes && p.manifest.digest === m.digest
          ? p
          : undefined;
      },
      undefined,
      { context: c, index },
    );
  }
  acknowledgeVPNSSO(value: unknown, manifest: unknown): Promise<{ restored: true }> {
    const c = parseVPNSSOContext(value),
      m = c && parseVPNSSOManifest(manifest, c, 'restore');
    if (!c || !m) return Promise.reject(Error('Invalid VPN SSO restore.'));
    return this.metadata(
      'vpn-sso-restore-ack',
      (v) =>
        typeof v === 'object' &&
        v !== null &&
        Object.keys(v).length === 1 &&
        'restored' in v &&
        v.restored === true
          ? { restored: true }
          : undefined,
      undefined,
      { context: c, manifest: m },
    );
  }
  pushVPNSSO(value: unknown): Promise<{ accepted: true; index: number }> {
    const context =
      typeof value === 'object' && value !== null && 'context' in value ? value.context : undefined;
    const p = parseVPNSSOPacket(value, context, 'capture');
    if (!p) return Promise.reject(Error('Invalid VPN SSO capture.'));
    return this.metadata(
      'vpn-sso-push',
      (v) => parseBrowserTransferAccepted(v, p.index),
      undefined,
      p,
    );
  }
  commitVPNSSO(value: unknown): Promise<VPNSSOCheckpoint> {
    const c = parseVPNSSOContext(value);
    if (!c) return Promise.reject(Error('Invalid VPN SSO commit.'));
    return this.metadata(
      'vpn-sso-commit',
      (v) => {
        const p = parseVPNSSOCheckpoint(v);
        return p && !p.deleted && BigInt(p.revision) === BigInt(c.sourceRevision) + 1n
          ? p
          : undefined;
      },
      undefined,
      { context: c },
    );
  }
  cancelVPNSSO(value: unknown): Promise<{ cancelled: true }> {
    const c = parseVPNSSOContext(value);
    if (!c) return Promise.reject(Error('Invalid VPN SSO cancellation.'));
    return this.metadata('vpn-sso-cancel', parseBrowserTransferCancelled, undefined, {
      context: c,
    });
  }
  sshBundle(request: VaultSshRequest): Promise<VaultSshBundle> {
    const snapshot = { ...request };
    if (!validVaultSshRequest(snapshot))
      return Promise.reject(new Error('Invalid vault SSH request.'));
    return this.metadata('ssh-bundle', (value) => parseVaultSshBundle(value, snapshot), undefined, {
      nodeId: snapshot.nodeId,
      credentialOverride: snapshot.credentialOverride,
      sessionId: snapshot.sessionId,
      requestId: snapshot.requestId,
      epoch: String(snapshot.epoch),
      publicKey: snapshot.publicKey,
      ...(snapshot.sftpOnly ? { sftpOnly: true } : {}),
    });
  }
  beginBitwardenCLIUnlock(): Promise<VaultBitwardenCLIUnlockBinding> {
    return this.metadata('bitwarden-cli-unlock-begin', parseVaultBitwardenCLIUnlockBinding);
  }
  async commitBitwardenCLIUnlock(requestId: string, value: unknown): Promise<void> {
    const session = parseVaultBitwardenCLISession(value);
    if (!vaultID(requestId) || !session) throw Error('Invalid Bitwarden CLI session.');
    await this.metadata(
      'bitwarden-cli-unlock-commit',
      (reply) =>
        vaultRecord(reply) && vaultFields(reply, ['unlocked']) && reply.unlocked === true
          ? true
          : undefined,
      undefined,
      { requestId, session },
    );
  }
  async cancelBitwardenCLIUnlock(requestId: string): Promise<void> {
    if (!vaultID(requestId)) throw Error('Invalid Bitwarden CLI request.');
    await this.metadata(
      'bitwarden-cli-unlock-cancel',
      (reply) =>
        vaultRecord(reply) && vaultFields(reply, ['cancelled']) && reply.cancelled === true
          ? true
          : undefined,
      undefined,
      { requestId },
    );
  }
  prepareSSHBitwarden(
    request: VaultSSHBitwardenRequest,
    recipient?: VaultBitwardenRecipient,
  ): Promise<VaultSSHBitwardenPreparation> {
    const q = 'route' in request ? parseVaultRoutedSshRequest(request) : { ...request };
    const resolver = recipient && { ...recipient };
    if (
      !q ||
      !validVaultSshRequest(q) ||
      (resolver &&
        (!validBitwardenRevision(resolver.revision) ||
          !canonicalBase64(resolver.publicKey, 32, 32)))
    )
      return Promise.reject(Error('Invalid Bitwarden SSH request.'));
    return this.metadata(
      'ssh-bitwarden-prepare',
      (value) => parseVaultSSHBitwardenPreparation(value, q, resolver),
      undefined,
      {
        nodeId: q.nodeId,
        credentialOverride: q.credentialOverride,
        sessionId: q.sessionId,
        requestId: q.requestId,
        epoch: String(q.epoch),
        publicKey: q.publicKey,
        ...('route' in q ? { route: q.route, endpoint: q.endpoint } : {}),
        ...(q.sftpOnly ? { sftpOnly: true as const } : {}),
        ...(resolver ? { resolverPublicKey: resolver.publicKey, revision: resolver.revision } : {}),
      },
    );
  }
  unlock(value: unknown): Promise<VaultUnlockResult> {
    let input: VaultUnlockInput;
    try {
      input = consumeVaultUnlockInput(value);
    } catch (error) {
      return Promise.reject(error);
    }
    return this.secretRequest('unlock', parseVaultUnlockResult, {
      bytes: [input.factor],
      encode: (id) => encodeVaultUnlockFrame(id, input),
    });
  }
  presenceAvailability(kind: VaultPresenceKind): Promise<VaultPresenceAvailability> {
    return this.metadata(`${kind}-availability`, parseVaultPresenceAvailability);
  }
  unlockPresence(
    kind: VaultPresenceKind,
    value: unknown,
    ownerWindow?: string,
  ): Promise<VaultPresenceUnlockResult> {
    const selection = parseVaultPresenceSelection(value);
    if (
      !selection ||
      (kind === 'hello' ? !vaultHelloWindow(ownerWindow) : ownerWindow !== undefined)
    )
      return Promise.reject(Error('Invalid biometric unlock request.'));
    return this.metadata(
      `${kind}-unlock`,
      parseVaultPresenceUnlock,
      undefined,
      ownerWindow === undefined ? selection : { ...selection, ownerWindow },
    );
  }
  enrollPresence(
    kind: VaultPresenceKind,
    ownerWindow: string | undefined,
    authentication: VaultUnlockInput,
  ): Promise<VaultPresenceEnrollment> {
    if (kind === 'hello' ? !vaultHelloWindow(ownerWindow) : ownerWindow !== undefined) {
      authentication.factor.fill(0);
      return Promise.reject(Error('Invalid biometric owner window.'));
    }
    return this.protectedRequest(
      `${kind}-enroll`,
      parseVaultPresenceEnrollment,
      undefined,
      ownerWindow === undefined ? undefined : { ownerWindow },
      authentication,
      kind === 'hello' ? 210_000 : undefined,
    );
  }
  removePresence(
    kind: VaultPresenceKind,
    slotId: string,
    authentication: VaultUnlockInput,
  ): Promise<VaultPresenceRemoval> {
    if (!vaultID(slotId)) {
      authentication.factor.fill(0);
      return Promise.reject(Error('Invalid biometric slot.'));
    }
    return this.protectedRequest(
      `${kind}-remove`,
      parseVaultPresenceRemoval,
      undefined,
      { slotId },
      authentication,
    );
  }
  resumeMigration(value: unknown): Promise<VaultUnlockResult> {
    return this.resumeMaintenance(value, 'migration-resume');
  }
  resumeRootRotation(value: unknown): Promise<VaultUnlockResult> {
    return this.resumeMaintenance(value, 'rotation-resume');
  }
  private resumeMaintenance(
    value: unknown,
    operation: 'migration-resume' | 'rotation-resume',
  ): Promise<VaultUnlockResult> {
    let input: VaultUnlockInput;
    try {
      input = consumeVaultUnlockInput(value);
    } catch (error) {
      return Promise.reject(error);
    }
    if (!this.options.migrationSessionData) {
      input.factor.fill(0);
      return Promise.reject(Error('Vault maintenance restart required.'));
    }
    return this.secretRequest(operation, parseVaultUnlockResult, {
      bytes: [input.factor],
      encode: (id) => encodeVaultUnlockFrame(id, input, operation),
    });
  }
  sharedUnlock(
    value: unknown,
    appVersion: string,
    tlsUpdatePath?: string,
  ): Promise<SharedVaultAdmission> {
    return this.sharedAuthentication(
      'shared-unlock',
      value,
      appVersion,
      parseSharedVaultAdmission,
      tlsUpdatePath,
    );
  }
  exportSharedTLSBundle(path: string): Promise<boolean> {
    if (!validSharedTLSBundlePath(path))
      return Promise.reject(Error('Invalid trust bundle destination.'));
    return this.metadata('shared-tls-export', parseSharedTLSBundleExport, undefined, { path });
  }
  refreshSharedRecoveryKit(
    source: string,
    destination: string,
    auth?: SharedVaultUnlockInput,
  ): Promise<SharedRecoveryKitNativeRefresh> {
    if (!validSharedRecoveryKitPath(source) || !validSharedRecoveryKitPath(destination)) {
      auth?.password.fill(0);
      auth?.ask?.fill(0);
      return Promise.reject(Error('Invalid recovery kit path.'));
    }
    return this.sharedCustodianRequest(
      'shared-recovery-kit-refresh',
      parseSharedRecoveryKitNativeRefresh,
      { source, destination },
      auth,
    );
  }
  exportSharedRecoveryBackup(
    path: string,
    recipient: Uint8Array,
    auth?: Omit<SharedVaultUnlockInput, 'appVersion'>,
  ): Promise<SharedRecoveryBackupResult> {
    if (!validSharedRecoveryBackupPath(path) || recipient.length !== 32) {
      auth?.password.fill(0);
      auth?.ask?.fill(0);
      return Promise.reject(Error('Invalid workspace backup destination.'));
    }
    return this.sharedCustodianRequest(
      'shared-recovery-export',
      parseSharedRecoveryBackup,
      { path, recipient: Buffer.from(recipient).toString('base64') },
      auth,
    );
  }
  sharedAccountResetTargets(after: string | null) {
    if (after !== null && !vaultID(after)) return Promise.reject(Error('Invalid reset cursor.'));
    return this.metadata(
      'shared-account-reset-targets',
      (value) => parseAccountResetTargetPage(value, after),
      undefined,
      after === null ? undefined : { after },
    );
  }

  sharedCreateCredentialSlot(request: CredentialSlot) {
    return this.metadata('shared-create-credential-slot', parseCreateSlotReply, undefined, request);
  }
  sharedSlotDefault(
    value: unknown,
    authentication?: Omit<SharedVaultUnlockInput, 'appVersion'>,
  ): Promise<SlotDefaultReply> {
    return this.sharedSlotChange(value, authentication, false);
  }

  sharedPersonalSlot(value: unknown, authentication?: Omit<SharedVaultUnlockInput, 'appVersion'>) {
    return this.sharedSlotChange(value, authentication, true);
  }

  private sharedSlotChange(
    value: unknown,
    authentication: Omit<SharedVaultUnlockInput, 'appVersion'> | undefined,
    personal: boolean,
  ): Promise<SlotDefaultReply> {
    const request = parseSlotDefaultRequest(value, personal);
    if (!request || (authentication && !request.confirmation)) {
      authentication?.password.fill(0);
      authentication?.ask?.fill(0);
      return Promise.reject(Error('Invalid shared slot default.'));
    }
    return this.sharedCustodianRequest(
      personal ? 'shared-personal-slot' : 'shared-slot-default',
      (v) => parseSlotDefaultReply(v, request, personal),
      { action: request },
      authentication,
    );
  }

  sharedAdminInventory(request: AdminInventoryRequest) {
    return this.metadata(
      'shared-admin-inventory',
      (value) => parseAdminInventoryReply(value, request),
      undefined,
      request,
    );
  }

  sharedWorkspaceAccess(request: WorkspaceAccessRequest) {
    return this.metadata(
      'shared-workspace-access',
      (value) => parseWorkspaceAccessReply(value, request),
      undefined,
      request,
    );
  }

  sharedAccountSuspension(request: AccountSuspensionRequest) {
    return this.metadata(
      'shared-account-suspension',
      (value) => parseAccountSuspensionReply(value, request),
      undefined,
      request,
    );
  }

  sharedAccountBoundaryRotation(request: AccountBoundaryRotationRequest) {
    return this.metadata(
      'shared-account-boundary-rotation',
      (value) => parseAccountBoundaryRotationReply(value, request),
      undefined,
      request,
    );
  }

  sharedPersonalRootRecovery(
    request: PersonalRootRecoveryRequest,
    auth?: Omit<SharedVaultUnlockInput, 'appVersion'>,
  ) {
    if (!!request.review !== !!auth) {
      auth?.password.fill(0);
      auth?.ask?.fill(0);
      return Promise.reject(Error('Personal key recovery requires a reviewed confirmation.'));
    }
    return this.sharedCustodianRequest(
      'shared-personal-root-recovery',
      (value) => parsePersonalRootRecoveryReply(value, request),
      request,
      auth,
    );
  }

  sharedAdminGroups(request: GroupRequest) {
    return this.metadata(
      'shared-admin-groups',
      (value) => parseGroupReply(value, request),
      undefined,
      request,
    );
  }

  sharedAdminNodeGrant(request: NodeGrantRequest) {
    return this.metadata(
      'shared-admin-node-grant',
      (value) => parseNodeGrantReply(value, request),
      undefined,
      request,
    );
  }

  sharedAdminGroupKey(request: GroupKeyRequest) {
    return this.metadata(
      'shared-admin-group-key',
      (value) => parseGroupKeyReply(value, request),
      undefined,
      request,
    );
  }
  sharedAdminGroupBoundaryGrant(request: GroupBoundaryGrantRequest) {
    return this.metadata(
      'shared-admin-group-boundary-grant',
      (value) => parseGroupBoundaryGrantReply(value, request),
      undefined,
      request,
    );
  }
  sharedAdminGroupBoundaryRotation(request: GroupBoundaryGrantRequest) {
    return this.metadata(
      'shared-admin-group-boundary-rotation',
      (value) => parseGroupBoundaryGrantReply(value, request, true),
      undefined,
      request,
    );
  }
  sharedAdminGroupMemberRotation(request: MemberRotationRequest) {
    return this.metadata(
      'shared-admin-group-member-rotation',
      (value) => parseMemberRotationReply(value, request),
      undefined,
      request,
    );
  }
  markSharedAccountResetHandover(value: unknown) {
    const mark = parseAccountResetMark(value);
    if (!mark) return Promise.reject(Error('Invalid account reset handover.'));
    return this.metadata(
      'shared-account-reset-mark-handover',
      parseAccountResetMarkResult,
      undefined,
      mark,
    );
  }
  issueSharedAccountReset(
    path: string,
    input: SharedAccountResetIssueInput,
    factors: { vaultId: string; slotId: string },
  ): Promise<SharedAccountResetIssueResult> {
    if (!validSharedArtifactPath(path, '.whreset')) {
      input.password.fill(0);
      input.ask?.fill(0);
      return Promise.resolve({ status: 'save-failed' });
    }
    return this.sharedCustodianRequest(
      'shared-account-reset-issue',
      parseSharedAccountResetIssue,
      {
        path,
        targetLogin: input.targetLogin,
        ...(input.targetUserId ? { targetUserId: input.targetUserId } : {}),
        ...(input.suspension ? { suspension: input.suspension } : {}),
        requestId: input.requestId,
        recipient: Buffer.from(input.recipient).toString('base64'),
      },
      { ...factors, password: input.password, ask: input.ask },
    );
  }
  tightenSharedProfile(sequence: string, auth: SharedVaultUnlockInput): Promise<true> {
    if (!auth) return Promise.reject(Error('Shared authentication required.'));
    return this.sharedCustodianRequest(
      'shared-tighten-profile',
      (value) => (value === true ? true : undefined),
      { sequence },
      auth,
    );
  }
  private sharedCustodianRequest<T>(
    operation:
      | 'shared-tighten-profile'
      | 'shared-slot-default'
      | 'shared-personal-slot'
      | 'shared-node-edit'
      | 'shared-ssh-host-trust'
      | 'shared-recovery-kit-refresh'
      | 'shared-recovery-export'
      | 'shared-account-reset-issue'
      | 'shared-personal-root-recovery',
    parse: (value: unknown) => T | undefined,
    fields:
      | { sequence: string }
      | {
          action:
            | ReturnType<typeof vaultSshHostPayload>
            | SharedNodeEditRequest
            | SlotDefaultRequest;
        }
      | { source: string; destination: string }
      | PersonalRootRecoveryRequest
      | {
          path: string;
          recipient: string;
          targetLogin?: string;
          targetUserId?: string;
          suspension?: string;
          requestId?: string;
        },
    auth?: Omit<SharedVaultUnlockInput, 'appVersion'>,
  ): Promise<T> {
    if (!auth) return this.metadata(operation, parse, undefined, fields);
    const factors: [string, Uint8Array][] = [['password', auth.password]];
    if (auth.ask) factors.push(['ask', auth.ask]);
    return this.secretRequest(operation, parse, {
      bytes: factors.map(([, bytes]) => bytes),
      encode: (id) => {
        const authentication = encodeVaultBytesObject(
          { vaultId: auth.vaultId, slotId: auth.slotId },
          factors,
        );
        try {
          return encodeVaultBytesFrame(id, operation, fields, [['authentication', authentication]]);
        } finally {
          authentication.fill(0);
        }
      },
    });
  }
  sharedSetup(input: SharedSetupNativeRequest) {
    const action = input.action;
    const parse = (value: unknown) =>
      parseSharedSetupReply(value, action, 'workspaceId' in input ? input.workspaceId : undefined);
    if (input.action === 'prepare-tls' || input.action === 'prepare-generated-tls') {
      const { host, port, database, approvedHosts, accountPassword, ask } = input;
      const target = {
        host,
        port,
        database,
        approvedHosts,
        ...(input.action === 'prepare-tls' ? { csr: input.csr } : {}),
      };
      const factors: [string, Uint8Array][] = [['accountPassword', accountPassword]];
      if (ask) factors.push(['ask', ask]);
      if (input.action === 'prepare-generated-tls')
        factors.push(['keyPassphrase', input.keyPassphrase]);
      const operation = `shared-setup-${input.action}` as const;
      return this.secretRequest(operation, parse, {
        bytes: factors.map(([, bytes]) => bytes),
        encode: (id) => encodeVaultBytesFrame(id, operation, target, factors),
      });
    }
    if ('accountPassword' in input) return this.sharedAdministrator(input, parse);
    if ('password' in input) {
      const operation: SharedSetupNetworkOperation = `shared-setup-${input.action}`;
      return this.secretRequest(operation, parse, {
        bytes: [input.password],
        encode: (id) =>
          encodeVaultBytesFrame(
            id,
            operation,
            { workspaceId: input.workspaceId, role: input.role },
            [['password', input.password]],
          ),
      });
    }
    if (action === 'plan') return this.metadata('shared-setup-plan', parse);
    if (input.action === 'import-review') {
      const { action: _, ...review } = input;
      return this.metadata(
        'shared-setup-import-review',
        (value) => {
          const reply = parse(value);
          return reply?.importPreview?.reviewId === review.reviewId ? reply : undefined;
        },
        undefined,
        review,
      );
    }
    if (input.action === 'prepare') {
      const { action: _, caPem, ...target } = input;
      return this.metadata('shared-setup-prepare', parse, undefined, {
        ...target,
        caPem: Buffer.from(caPem, 'ascii').toString('base64'),
      });
    }
    return this.metadata(`shared-setup-${input.action}`, parse, undefined, {
      workspaceId: input.workspaceId,
      ...('path' in input ? { path: input.path } : {}),
      ...(input.action === 'export-hba' ? { networks: input.networks } : {}),
    });
  }
  sharedJoinAdministrator(
    input: Extract<SharedAdminSetupRequest, { action: 'admin-join' }>,
    appVersion: string,
  ) {
    return this.sharedAdministrator(input, parseSharedVaultAdmission, appVersion);
  }
  sharedRecoverAdministrator(input: AdminRecoveryNativeInput, appVersion: string) {
    if (
      !validAdminRecoveryPaths(input.kitPath, input.trustPath) ||
      !validSharedVaultAppVersion(appVersion)
    ) {
      wipeAdminRecoveryInput(input);
      return Promise.reject(Error('Invalid workspace recovery request.'));
    }
    const { recoveryCode, deployerPassword, accountPassword, ask, ...target } = input;
    const factors: [string, Uint8Array][] = [
      ['recoveryCode', recoveryCode],
      ['deployerPassword', deployerPassword],
      ['accountPassword', accountPassword],
    ];
    if (ask) factors.push(['ask', ask]);
    return this.secretRequest('shared-admin-recover', parseSharedVaultAdmission, {
      bytes: factors.map(([, bytes]) => bytes),
      encode: (id) =>
        encodeVaultBytesFrame(id, 'shared-admin-recover', { ...target, appVersion }, factors),
    });
  }
  inspectSharedRecoveryBackup(input: SharedRecoveryInspectionNative) {
    const { password, ...paths } = input;
    if (!validSharedRecoveryInspection(input)) {
      password.fill(0);
      return Promise.reject(Error('Invalid workspace restore request.'));
    }
    const operation = 'shared-recovery-inspect';
    return this.secretRequest(operation, parseSharedRecoveryInspectionReceipt, {
      bytes: [password],
      encode: (id) => encodeVaultBytesFrame(id, operation, paths, [['password', password]]),
    });
  }
  restoreSharedRecoveryBackup(input: SharedRecoveryRestoreNative) {
    if (!validSharedRecoveryRestore(input)) {
      wipeSharedRecoveryRestore(input);
      return Promise.reject(Error('Invalid workspace restore request.'));
    }
    const { password, deployerPassword, ...target } = input;
    const operation = 'shared-recovery-restore';
    return this.secretRequest(operation, parseSharedRecoveryRestoreStatus, {
      bytes: [password, deployerPassword],
      encode: (id) =>
        encodeVaultBytesFrame(id, operation, target, [
          ['password', password],
          ['deployerPassword', deployerPassword],
        ]),
    });
  }
  selectSharedWorkspace(
    input: Extract<SharedAdminSetupRequest, { action: 'admin-join' }>,
    appVersion: string,
  ) {
    return this.sharedAdministrator(input, parseSharedWorkspaceSwitch, appVersion);
  }
  private sharedAdministrator<T>(
    input:
      | SharedAdminSetupRequest
      | (Extract<SharedAdminSetupRequest, { action: 'admin-recovery' }> & { path: string }),
    parse: (value: unknown) => T | undefined,
    appVersion?: string,
  ) {
    const operation: SharedAdminSetupOperation = `shared-setup-${input.action}`;
    const metadata: Record<string, unknown> = { workspaceId: input.workspaceId };
    const values: [string, Uint8Array][] = [['accountPassword', input.accountPassword]];
    if (input.ask) values.push(['ask', input.ask]);
    switch (input.action) {
      case 'admin-prepare':
        Object.assign(metadata, { loginName: input.loginName, profile: input.profile });
        if (input.directConnectionDevices !== undefined)
          metadata.directConnectionDevices = input.directConnectionDevices;
      // fall through
      case 'admin-publish':
        metadata.role = input.role;
        values.push(['password', input.password]);
        break;
      case 'admin-recovery':
        if (!('path' in input))
          return Promise.reject(Error('Recovery kit destination is missing.'));
        metadata.path = input.path;
        values.push(['recipient', input.recipient]);
        break;
      case 'admin-confirm':
        metadata.enrollmentId = input.enrollmentId;
        values.push(['groups', input.groups]);
        break;
      case 'admin-join':
        Object.assign(metadata, {
          deviceName: input.deviceName,
          appVersion,
          ...(input.importConfirmation ? { importConfirmation: input.importConfirmation } : {}),
        });
        break;
    }
    return this.secretRequest(operation, parse, {
      bytes: values.map(([, bytes]) => bytes),
      encode: (id) => encodeVaultBytesFrame(id, operation, metadata, values),
    });
  }
  inspectSharedInvitation(invitation: string): Promise<SharedInvitation> {
    if (!validSharedInvitationText(invitation)) return Promise.reject(Error('Invalid invitation.'));
    return this.metadata('shared-invitation-inspect', parseSharedInvitation, undefined, {
      invitation,
    });
  }
  readSharedInvitationFile(path: string): Promise<SharedInvitation> {
    if (typeof path !== 'string' || !path.length || path.length > 4096 || path.includes('\0'))
      return Promise.reject(Error('Invalid invitation file.'));
    return this.metadata('shared-invitation-file', parseSharedInvitation, undefined, { path });
  }
  sharedJoinInitial(value: unknown, appVersion: string): Promise<SharedVaultAdmission> {
    try {
      const input = consumeSharedInitialJoinInput(value, appVersion);
      const bytes: [string, Uint8Array][] = [
        ['code', input.code],
        ['password', input.password],
      ];
      if (input.ask) bytes.push(['ask', input.ask]);
      return this.secretRequest('shared-join-initial', parseSharedVaultAdmission, {
        bytes: bytes.map(([, value]) => value),
        encode: (id) =>
          encodeVaultBytesFrame(
            id,
            'shared-join-initial',
            {
              invitation: input.invitation,
              deviceName: input.deviceName,
              acknowledgeTLSOff: input.acknowledgeTLSOff,
              appVersion,
            },
            bytes,
          ),
      });
    } catch {
      return Promise.reject(Error('Invalid shared workspace invitation request.'));
    }
  }
  sharedRecoverPassword(value: unknown, appVersion: string): Promise<SharedVaultRecovery> {
    return this.sharedAuthentication(
      'shared-recover-password',
      value,
      appVersion,
      parseSharedVaultRecovery,
    );
  }
  sharedRedeemAccountReset(
    offerPath: string,
    value: unknown,
    appVersion: string,
  ): Promise<SharedVaultAdmission> {
    try {
      const input = consumeSharedAccountResetInput(value, appVersion);
      const bytes: [string, Uint8Array][] = [
        ['code', input.code],
        ['password', input.password],
        ['ask', input.ask],
      ];
      if (!validSharedArtifactPath(offerPath, '.whreset')) {
        for (const [, factor] of bytes) factor.fill(0);
        throw Error('Invalid reset offer file.');
      }
      return this.secretRequest('shared-account-reset-redeem', parseSharedEnrollmentResult, {
        bytes: bytes.map(([, factor]) => factor),
        encode: (id) =>
          encodeVaultBytesFrame(
            id,
            'shared-account-reset-redeem',
            { offerPath, deviceName: input.deviceName, appVersion },
            bytes,
          ),
      }).then(requireSharedEnrollmentAdmission);
    } catch {
      return Promise.reject(Error('Invalid account reset request.'));
    }
  }
  sharedRecoverEnrollment(value: unknown, appVersion: string): Promise<SharedVaultAdmission> {
    return this.sharedAuthentication(
      'shared-recover-enrollment',
      value,
      appVersion,
      parseSharedEnrollmentResult,
    ).then(requireSharedEnrollmentAdmission);
  }
  sharedContinueEnrollment(value: unknown, appVersion: string): Promise<SharedVaultAdmission> {
    return this.sharedAuthentication(
      'shared-continue-enrollment',
      value,
      appVersion,
      parseSharedEnrollmentResult,
    ).then(requireSharedEnrollmentAdmission);
  }
  private sharedAuthentication<T>(
    operation:
      | 'shared-unlock'
      | 'shared-recover-password'
      | 'shared-recover-enrollment'
      | 'shared-continue-enrollment',
    value: unknown,
    appVersion: string,
    parse: (value: unknown) => T | undefined,
    tlsUpdatePath?: string,
  ): Promise<T> {
    try {
      const input =
        operation === 'shared-continue-enrollment'
          ? consumeSharedVaultContinuationInput(value, appVersion)
          : consumeSharedVaultUnlockInput(value, appVersion);
      return this.secretRequest(operation, parse, {
        bytes: [
          input.password,
          ...(input.ask ? [input.ask] : []),
          ...(hasSharedVaultContinuation(input) ? [input.code] : []),
        ],
        encode: (id) => encodeSharedVaultUnlockFrame(id, operation, input, tlsUpdatePath),
      });
    } catch {
      return Promise.reject(Error('Invalid shared vault authentication request.'));
    }
  }
  beginEnrollment(value: unknown): Promise<VaultEnrollment> {
    try {
      const input = consumeVaultEnrollmentBegin(value);
      return this.secretRequest('enrollment-begin', parseVaultEnrollment, {
        bytes: [input.password, input.publicKey],
        encode: (id) =>
          encodeVaultBytesFrame(id, 'enrollment-begin', {}, [
            ['password', input.password],
            ['publicKey', input.publicKey],
          ]),
      });
    } catch {
      return Promise.reject(new Error('Invalid vault enrollment request.'));
    }
  }
  confirmEnrollment(value: unknown): Promise<VaultUnlockResult> {
    try {
      const input = consumeVaultEnrollmentConfirm(value);
      return this.secretRequest('enrollment-confirm', parseVaultUnlockResult, {
        bytes: [input.groups],
        encode: (id) =>
          encodeVaultBytesFrame(id, 'enrollment-confirm', { enrollmentId: input.enrollmentId }, [
            ['groups', input.groups],
          ]),
      });
    } catch {
      return Promise.reject(new Error('Invalid vault enrollment confirmation.'));
    }
  }
  migrationSetupContext(): Promise<VaultMigrationContext> {
    return this.metadata('migration-setup-context', parseVaultMigrationContext);
  }
  beginMigrationSetup(value: unknown): Promise<VaultEnrollment> {
    try {
      const input = consumeVaultMigrationBegin(value);
      return this.secretRequest('migration-setup-begin', parseVaultEnrollment, {
        bytes: [input.password, input.publicKey, input.legacyFactor],
        encode: (id) =>
          encodeVaultBytesFrame(id, 'migration-setup-begin', { legacyMethod: input.legacyMethod }, [
            ['password', input.password],
            ['publicKey', input.publicKey],
            ['legacyFactor', input.legacyFactor],
          ]),
      });
    } catch {
      return Promise.reject(Error('Invalid migration preparation.'));
    }
  }
  confirmMigrationSetup(value: unknown): Promise<VaultMigrationPrepared> {
    try {
      const input = consumeVaultEnrollmentConfirm(value);
      return this.secretRequest('migration-setup-confirm', parseVaultMigrationPrepared, {
        bytes: [input.groups],
        encode: (id) =>
          encodeVaultBytesFrame(
            id,
            'migration-setup-confirm',
            { enrollmentId: input.enrollmentId },
            [['groups', input.groups]],
          ),
      });
    } catch {
      return Promise.reject(Error('Invalid migration confirmation.'));
    }
  }
  cancelEnrollment(): Promise<true> {
    return this.metadata('enrollment-cancel', parseVaultEnrollmentCancel);
  }
  rootRotationSetupContext(): Promise<VaultRootEnrollmentContext> {
    return this.metadata('rotation-setup-context', parseVaultRootEnrollmentContext);
  }
  upgradeSetupContext(): Promise<VaultUpgradeContext> {
    if (!this.options.migrationSessionData)
      return Promise.reject(Error('Vault maintenance restart required.'));
    return this.metadata('rotation-upgrade-context', parseVaultUpgradeContext);
  }
  beginUpgradeSetup(value: unknown): Promise<VaultEnrollment> {
    try {
      const input = consumeVaultEnrollmentBegin(value);
      if (!this.options.migrationSessionData) {
        input.password.fill(0);
        input.publicKey.fill(0);
        return Promise.reject(Error('Vault maintenance restart required.'));
      }
      return this.secretRequest('rotation-upgrade-begin', parseVaultEnrollment, {
        bytes: [input.password, input.publicKey],
        encode: (id) =>
          encodeVaultBytesFrame(id, 'rotation-upgrade-begin', {}, [
            ['password', input.password],
            ['publicKey', input.publicKey],
          ]),
      });
    } catch {
      return Promise.reject(Error('Invalid vault upgrade request.'));
    }
  }
  beginRootRotationSetup(value: unknown, encryptDatabase = false): Promise<VaultEnrollment> {
    try {
      const input = consumeVaultRootEnrollmentBegin(value);
      const operation = encryptDatabase ? 'rotation-encryption-begin' : 'rotation-setup-begin';
      return this.secretRequest(operation, parseVaultEnrollment, {
        bytes: [input.password, input.publicKey, input.authentication.factor],
        encode: (id) => {
          const auth = input.authentication;
          const field =
            auth.kind === 'password'
              ? 'password'
              : auth.kind === 'recovery'
                ? 'recoveryKey'
                : 'recoveryCode';
          const authentication = encodeVaultBytesObject(
            { vaultId: auth.vaultId, slotId: auth.slotId },
            [[field, auth.factor]],
          );
          try {
            return encodeVaultBytesFrame(id, operation, {}, [
              ['password', input.password],
              ['publicKey', input.publicKey],
              ['authentication', authentication],
            ]);
          } finally {
            authentication.fill(0);
          }
        },
      });
    } catch {
      return Promise.reject(Error('Invalid vault protection request.'));
    }
  }
  confirmRootRotationSetup(value: unknown): Promise<VaultMigrationPrepared> {
    try {
      const input = consumeVaultEnrollmentConfirm(value);
      return this.secretRequest('rotation-setup-confirm', parseVaultMigrationPrepared, {
        bytes: [input.groups],
        encode: (id) =>
          encodeVaultBytesFrame(
            id,
            'rotation-setup-confirm',
            { enrollmentId: input.enrollmentId },
            [['groups', input.groups]],
          ),
      });
    } catch {
      return Promise.reject(Error('Invalid vault protection confirmation.'));
    }
  }
  cancelRootRotationSetup(): Promise<true> {
    return this.metadata('rotation-setup-cancel', parseVaultEnrollmentCancel);
  }
  private rejectAction(authentication: VaultUnlockInput | undefined, error: Error): Promise<never> {
    if (authentication?.factor instanceof Uint8Array) authentication.factor.fill(0);
    return Promise.reject(error);
  }
  private protectedRequest<T>(
    operation:
      | 'tighten-local-profile'
      | 'ssh-host-trust'
      | 'ssh-quick-host-trust'
      | 'tunnel-edit'
      | 'tunnel-delete'
      | 'credential-edit'
      | 'credential-delete'
      | 'connection-save'
      | 'folder-save'
      | 'node-delete-trees'
      | 'node-move'
      | 'node-duplicate'
      | 'credential-clipboard-release'
      | 'credential-copy'
      | 'credential-display'
      | 'bitwarden-cleanup'
      | 'bitwarden-install-zip'
      | 'bitwarden-install-folder'
      | 'local-backup-export'
      | VaultPresenceOperation
      | 'migration-decide',
    parse: (value: unknown) => T | undefined,
    input?: FactorRequest,
    payload?: PublicPayload,
    authentication?: VaultUnlockInput,
    timeoutMs?: number,
  ): Promise<T> {
    if (!authentication) {
      if (operation === 'tighten-local-profile')
        return Promise.reject(Error('Fresh authentication is required.'));
      return input
        ? this.secretRequest(operation, parse, input)
        : this.metadata(operation, parse, undefined, payload);
    }
    let factor: VaultUnlockInput;
    try {
      factor = consumeVaultUnlockInput(authentication);
    } catch (error) {
      for (const bytes of input?.bytes ?? []) bytes.fill(0);
      return Promise.reject(error);
    }
    return this.secretRequest('fresh-action', parse, {
      timeoutMs,
      bytes: [...(input?.bytes ?? []), factor.factor],
      encode: (id) => {
        let action: Buffer | undefined, auth: Buffer | undefined;
        try {
          action = input ? input.action!() : Buffer.from(JSON.stringify(payload ?? {}));
          const field =
            factor.kind === 'password'
              ? 'password'
              : factor.kind === 'recovery'
                ? 'recoveryKey'
                : 'recoveryCode';
          auth = encodeVaultBytesObject({ vaultId: factor.vaultId, slotId: factor.slotId }, [
            [field, factor.factor],
          ]);
          return encodeVaultBytesFrame(id, 'fresh-action', { operation }, [
            ['authentication', auth],
            ['action', action],
          ]);
        } finally {
          action?.fill(0);
          auth?.fill(0);
        }
      },
    });
  }
  private secretRequest<T>(
    operation:
      | 'shared-admin-recover'
      | 'shared-recovery-inspect'
      | 'shared-recovery-restore'
      | 'shared-setup-prepare-tls'
      | 'shared-setup-prepare-generated-tls'
      | SharedSetupNetworkOperation
      | SharedAdminSetupOperation
      | 'shared-unlock'
      | 'shared-recover-password'
      | 'shared-recover-enrollment'
      | 'shared-continue-enrollment'
      | 'shared-join-initial'
      | 'shared-account-reset-redeem'
      | 'shared-tighten-profile'
      | 'shared-slot-default'
      | 'shared-personal-slot'
      | 'shared-node-edit'
      | 'shared-ssh-host-trust'
      | 'shared-recovery-kit-refresh'
      | 'shared-recovery-export'
      | 'shared-account-reset-issue'
      | 'shared-personal-root-recovery'
      | 'ssh-host-trust'
      | 'ssh-quick-host-trust'
      | 'tunnel-edit'
      | 'web-session-save'
      | 'tunnel-delete'
      | 'unlock'
      | VaultPresenceOperation
      | 'migration-resume'
      | 'rotation-resume'
      | 'migration-setup-begin'
      | 'migration-os-prepare'
      | 'migration-setup-confirm'
      | 'rotation-setup-begin'
      | 'rotation-encryption-begin'
      | 'rotation-upgrade-begin'
      | 'rotation-setup-confirm'
      | 'enrollment-begin'
      | 'enrollment-confirm'
      | 'credential-edit'
      | 'credential-delete'
      | 'connection-save'
      | 'fresh-action'
      | 'folder-save'
      | 'local-backup-export'
      | 'local-backup-install'
      | 'node-delete-trees'
      | 'node-move'
      | 'node-duplicate'
      | 'credential-clipboard-release'
      | 'credential-copy'
      | 'credential-display'
      | 'bitwarden-cleanup'
      | 'bitwarden-install-zip'
      | 'bitwarden-install-folder'
      | 'migration-decide',
    parse: (value: unknown) => T | undefined,
    input: FactorRequest,
  ): Promise<T> {
    for (const bytes of input.bytes) this.factors.add(bytes);
    return this.metadata(operation, parse, input).finally(() => {
      for (const bytes of input.bytes) {
        bytes.fill(0);
        this.factors.delete(bytes);
      }
    });
  }
  lock(): Promise<void> {
    return this.retired && this.exitObserved
      ? Promise.resolve()
      : this.stop('locked', new Error('Vault is locked.'));
  }

  private metadata<T>(
    operation:
      | 'shared-admin-recover'
      | 'shared-recovery-inspect'
      | 'shared-recovery-restore'
      | SharedSetupNetworkOperation
      | SharedAdminSetupOperation
      | 'shared-setup-plan'
      | 'shared-setup-import-review'
      | 'shared-setup-prepare'
      | 'shared-setup-prepare-tls'
      | 'shared-setup-prepare-generated-tls'
      | 'shared-setup-save-server-kit'
      | 'shared-setup-delete-server-key'
      | 'shared-setup-export'
      | 'shared-setup-export-hba'
      | 'shared-setup-discard'
      | 'shared-invitation-inspect'
      | 'shared-invitation-file'
      | 'shared-catalog'
      | 'shared-connection-context'
      | 'shared-changes'
      | 'shared-runtime'
      | 'shared-admin-inventory'
      | 'shared-create-credential-slot'
      | 'shared-workspace-access'
      | 'shared-account-suspension'
      | 'shared-account-boundary-rotation'
      | 'shared-personal-root-recovery'
      | 'shared-admin-groups'
      | 'shared-admin-node-grant'
      | 'shared-admin-group-key'
      | 'shared-admin-group-boundary-grant'
      | 'shared-admin-group-boundary-rotation'
      | 'shared-admin-group-member-rotation'
      | 'shared-renew-server-certificate'
      | 'shared-ca-status'
      | 'shared-ca-rotate'
      | 'shared-ca-retire'
      | 'shared-tls-export'
      | 'shared-tighten-profile'
      | 'shared-slot-default'
      | 'shared-personal-slot'
      | 'shared-node-edit'
      | 'shared-ssh-host-trust'
      | 'shared-recovery-kit-refresh'
      | 'shared-recovery-export'
      | 'shared-account-reset-issue'
      | 'shared-account-reset-targets'
      | 'shared-account-reset-mark-handover'
      | 'shared-unlock'
      | 'shared-recover-password'
      | 'shared-recover-enrollment'
      | 'shared-continue-enrollment'
      | 'shared-join-initial'
      | 'shared-account-reset-redeem'
      | 'ssh-host-trust'
      | 'ssh-quick-host-trust'
      | 'tunnel-edit'
      | 'tunnel-delete'
      | 'fresh-action'
      | 'local-backup-export'
      | 'local-backup-inspect'
      | 'local-backup-install'
      | 'status'
      | 'describe'
      | 'catalog'
      | 'unlock'
      | `${VaultPresenceKind}-${'availability' | 'unlock'}`
      | VaultPresenceOperation
      | 'migration-resume'
      | 'rotation-resume'
      | 'migration-setup-context'
      | 'migration-os-resume'
      | 'migration-os-context'
      | 'migration-os-prepare'
      | 'migration-setup-begin'
      | 'migration-setup-confirm'
      | 'rotation-setup-context'
      | 'rotation-upgrade-context'
      | 'rotation-setup-begin'
      | 'rotation-encryption-begin'
      | 'rotation-upgrade-begin'
      | 'rotation-setup-confirm'
      | 'rotation-setup-cancel'
      | 'enrollment-begin'
      | 'enrollment-confirm'
      | 'enrollment-cancel'
      | 'node-delete-trees'
      | 'node-move'
      | 'node-duplicate'
      | 'credential-clipboard-release'
      | 'credential-copy'
      | 'credential-display'
      | 'folder-save'
      | 'tunnel-editor-display'
      | 'tunnel-import-stage'
      | 'tunnel-import-discard'
      | 'notes-display'
      | 'migration-report'
      | 'migration-decide'
      | 'credential-edit'
      | 'credential-delete'
      | 'connection-save'
      | 'workspace'
      | 'startup'
      | 'security'
      | 'protection'
      | 'unprotected-create'
      | 'unprotected-open'
      | 'preferences'
      | 'update-preferences'
      | 'file-edit-settings'
      | 'sftp-recovery-scopes'
      | 'sftp-recovery-records'
      | 'ssh-host-plan'
      | 'connection-route'
      | 'ssh-route-bundle'
      | 'tunnel-plan'
      | 'tunnel-bundle'
      | 'tunnel-fallback-plan'
      | 'tunnel-fallback-bundle'
      | 'bitwarden-cleanup'
      | 'bitwarden-install-zip'
      | 'bitwarden-install-folder'
      | 'bitwarden-installation-revision'
      | 'bitwarden-installation-plan'
      | 'bitwarden-transfer-begin'
      | 'bitwarden-transfer-push'
      | 'bitwarden-transfer-commit'
      | 'bitwarden-transfer-take'
      | 'bitwarden-transfer-cancel'
      | 'vpn-sso-begin'
      | 'vpn-sso-take'
      | 'vpn-sso-restore-ack'
      | 'vpn-sso-push'
      | 'vpn-sso-commit'
      | 'vpn-sso-cancel'
      | 'bitwarden-profile-close'
      | 'web-plan'
      | 'web-session-read'
      | 'web-session-save'
      | 'web-session-forget'
      | 'web-session-verify-views'
      | 'ssh-manual-plan'
      | 'ssh-manual-bundle'
      | 'vnc-plan'
      | 'vnc-manual-bundle'
      | 'vnc-manual-route-bundle'
      | 'quick-target-register'
      | 'quick-target-release'
      | 'rdp-plan'
      | 'rdp-manual-bundle'
      | 'rdp-manual-route-bundle'
      | 'rdp-manual-bitwarden-prepare'
      | 'rdp-bundle'
      | 'serial-bundle'
      | 'serial-use-check'
      | 'rdp-route-bundle'
      | 'rdp-bitwarden-prepare'
      | 'vnc-bundle'
      | 'vnc-route-bundle'
      | 'vnc-bitwarden-prepare'
      | 'ssh-bundle'
      | 'bitwarden-cli-unlock-begin'
      | 'bitwarden-cli-unlock-commit'
      | 'bitwarden-cli-unlock-cancel'
      | 'ssh-bitwarden-prepare',
    parse: (value: unknown) => T | undefined,
    input?: FactorRequest,
    payload?: PublicPayload,
  ): Promise<T> {
    if (this.retired) return Promise.reject(new Error('Vault is unavailable.'));
    if (this.queued >= 16) return Promise.reject(new Error('Vault request queue is full.'));
    this.queued++;
    const result = this.queue.then(async () => {
      await this.start();
      return this.exchange(operation, parse, input, payload);
    });
    this.queue = result.catch(() => undefined);
    return result
      .then((value) => {
        if (this.retired) throw new Error('Vault is unavailable.');
        return value;
      })
      .finally(() => {
        this.queued--;
      });
  }

  private start(): Promise<void> {
    if (this.retired) return Promise.reject(new Error('Vault is unavailable.'));
    if (this.starting) return this.starting;
    this.starting = new Promise<void>((resolve, reject) => {
      this.rejectStart = reject;
      this.startTimer = setTimeout(() => this.fail('timeout'), this.options.requestTimeoutMs);
      this.startProcess(resolve);
    });
    return this.starting;
  }

  private startProcess(resolve: () => void): void {
    let channel: Socket | undefined;
    let child: ChildProcessWithoutNullStreams;
    try {
      channel = this.options.openTouchIDBroker?.(this.options.executable);
      const touchID = channel && !channel.destroyed ? channel : undefined;
      child = this.spawnVault(
        this.options.executable,
        [
          '--operation',
          this.options.migrationSessionData ? 'vault-migration' : 'vault',
          '--database',
          this.options.databasePath,
          ...(this.options.userDataPath ? ['--electron-user-data', this.options.userDataPath] : []),
          ...(this.options.migrationSessionData
            ? ['--migration-session-data', this.options.migrationSessionData]
            : []),
          ...(touchID ? ['--touch-id-channel'] : []),
        ],
        touchID,
      );
    } catch {
      this.exitObserved = true;
      this.fail('unavailable');
      return;
    } finally {
      channel?.destroy();
    }
    this.child = child;
    child.once('spawn', () => {
      this.spawned = true;
      clearTimeout(this.startTimer);
      if (this.retired) {
        try {
          child.kill('SIGKILL');
        } catch {
          // The stop deadline still requires an observed exit.
        }
        return;
      }
      this.rejectStart = undefined;
      this.heartbeat = setInterval(() => {
        if (this.heartbeatPending || this.retired) return;
        this.heartbeatPending = true;
        void this.exchange('heartbeat', parseVaultHeartbeat)
          .catch(() => this.fail('protocol'))
          .finally(() => {
            this.heartbeatPending = false;
          });
      }, this.options.heartbeatMs);
      this.heartbeat.unref();
      resolve();
    });
    child.on('error', () => {
      // A failed spawn has no process to wait for. A failed kill/write does.
      if (!this.spawned && child.pid === undefined) this.exitObserved = true;
      this.fail('unavailable');
      this.completeStop();
    });
    child.once('exit', () => {
      this.exitObserved = true;
      if (!this.retired) this.fail('exited');
      this.completeStop();
    });
    child.once('close', () => {
      // Node emits close after exit or after a failed spawn. Never infer exit
      // from child.killed: that only records that a signal was requested.
      if (!this.spawned && child.pid === undefined) this.exitObserved = true;
      if (!this.retired) this.fail('exited');
      this.completeStop();
    });
    child.stdin.on('error', () => this.fail('unavailable'));
    child.stdout.on('error', () => this.fail('protocol'));
    child.stderr.on('error', () => this.fail('unavailable'));
    child.stderr.resume(); // Discard diagnostics; never forward raw backend text.
    child.stdout.on('data', (chunk: Buffer) => this.receive(chunk));
    child.stdout.on('end', () => {
      if (!this.retired) this.fail('protocol');
    });
  }

  private exchange<T>(
    operation: string,
    parse: (value: unknown) => T | undefined,
    input?: FactorRequest,
    payload?: PublicPayload,
  ): Promise<T> {
    if (this.retired || !this.child || this.sequence >= Number.MAX_SAFE_INTEGER)
      return Promise.reject(new Error('Vault is unavailable.'));
    const id = ++this.sequence;
    return new Promise<T>((resolve, reject) => {
      const presenceTimeout =
        operation === 'hello-unlock' ||
        operation === 'hello-availability' ||
        operation === 'touch-id-unlock' ||
        operation === 'touch-id-availability'
          ? 120_000
          : undefined;
      const timer = setTimeout(
        () => this.fail('timeout'),
        input?.timeoutMs ??
          presenceTimeout ??
          (operation === 'migration-resume' ||
          operation === 'migration-os-resume' ||
          operation === 'rotation-resume' ||
          operation === 'rotation-setup-confirm' ||
          operation === 'local-backup-install'
            ? 30 * 60_000
            : operation === 'shared-admin-recover' ||
                operation === 'shared-recovery-inspect' ||
                operation === 'shared-join-initial' ||
                operation === 'shared-account-reset-redeem' ||
                operation === 'shared-setup-admin-join' ||
                operation === 'shared-continue-enrollment' ||
                operation === 'shared-setup-run'
              ? 360_000
              : operation === 'shared-recover-enrollment' || operation === 'shared-recovery-restore'
                ? 180_000
                : operation === 'unlock' ||
                    operation === 'unprotected-create' ||
                    operation === 'unprotected-open' ||
                    operation === 'shared-catalog' ||
                    operation === 'shared-changes' ||
                    operation === 'shared-renew-server-certificate' ||
                    operation.startsWith('shared-ca-') ||
                    operation === 'shared-tls-export' ||
                    operation === 'shared-tighten-profile' ||
                    operation === 'shared-ssh-host-trust' ||
                    operation === 'shared-node-edit' ||
                    operation === 'shared-recovery-kit-refresh' ||
                    operation === 'shared-recovery-export' ||
                    operation === 'shared-account-reset-issue' ||
                    operation === 'shared-account-reset-targets' ||
                    operation === 'shared-admin-inventory' ||
                    operation === 'shared-slot-default' ||
                    operation === 'shared-personal-slot' ||
                    operation === 'shared-create-credential-slot' ||
                    operation === 'shared-workspace-access' ||
                    operation === 'shared-account-suspension' ||
                    operation === 'shared-account-boundary-rotation' ||
                    operation === 'shared-personal-root-recovery' ||
                    operation === 'shared-admin-groups' ||
                    operation === 'shared-admin-node-grant' ||
                    operation === 'shared-admin-group-key' ||
                    operation === 'shared-admin-group-boundary-grant' ||
                    operation === 'shared-admin-group-boundary-rotation' ||
                    operation === 'shared-admin-group-member-rotation' ||
                    operation === 'shared-account-reset-mark-handover' ||
                    operation === 'shared-unlock' ||
                    operation === 'shared-recover-password' ||
                    operation === 'shared-setup-preflight' ||
                    operation === 'shared-setup-check' ||
                    operation.startsWith('shared-setup-admin-') ||
                    operation === 'enrollment-begin' ||
                    operation === 'rotation-setup-begin' ||
                    operation === 'rotation-encryption-begin' ||
                    operation === 'rotation-upgrade-begin' ||
                    operation === 'migration-os-prepare' ||
                    operation === 'local-backup-export' ||
                    operation === 'fresh-action' ||
                    operation === 'bitwarden-install-folder' ||
                    operation === 'bitwarden-cleanup' ||
                    operation === 'bitwarden-install-zip'
                  ? 120_000
                  : operation === 'migration-setup-begin' ||
                      operation === 'migration-setup-confirm' ||
                      operation === 'bitwarden-installation-plan' ||
                      operation === 'workspace' ||
                      operation === 'shared-connection-context' ||
                      operation === 'enrollment-confirm' ||
                      operation === 'node-delete-trees' ||
                      operation === 'node-move' ||
                      operation === 'node-duplicate' ||
                      operation === 'folder-save' ||
                      operation === 'connection-save' ||
                      operation === 'credential-edit' ||
                      operation === 'credential-delete' ||
                      operation === 'tunnel-edit' ||
                      operation === 'tunnel-delete' ||
                      operation === 'tunnel-import-stage'
                    ? 30_000
                    : this.options.requestTimeoutMs),
      );
      this.pending.set(id, {
        resolve: (value) => resolve(value as T),
        reject,
        parse,
        timer,
        frameLimit:
          operation === 'web-session-read'
            ? maxWebSessionArchiveReply
            : operation === 'rdp-bitwarden-prepare' || operation === 'rdp-manual-bitwarden-prepare'
              ? maxRDPBitwardenPlanFrame
              : operation === 'ssh-bitwarden-prepare' || operation === 'vnc-bitwarden-prepare'
                ? maxBitwardenFrame
                : operation === 'bitwarden-transfer-take' ||
                    operation === 'vpn-sso-take' ||
                    operation === 'catalog' ||
                    operation === 'shared-catalog' ||
                    operation === 'workspace' ||
                    operation === 'shared-node-edit' ||
                    operation === 'ssh-bundle' ||
                    operation === 'tunnel-bundle' ||
                    operation === 'tunnel-fallback-bundle' ||
                    operation === 'ssh-route-bundle' ||
                    operation === 'preferences'
                  ? vaultCatalogFrameLimit
                  : operation === 'shared-invitation-inspect' ||
                      operation === 'shared-invitation-file'
                    ? maxSharedInvitationBytes + vaultMetadataFrameLimit
                    : operation === 'sftp-recovery-records'
                      ? 512 * 1024
                      : operation === 'tunnel-editor-display' || operation === 'tunnel-import-stage'
                        ? 768 * 1024
                        : operation === 'notes-display' ||
                            operation === 'credential-display' ||
                            operation === 'fresh-action' ||
                            operation === 'file-edit-settings'
                          ? 96 * 1024
                          : vaultMetadataFrameLimit,
      });
      let frame: Buffer | undefined;
      try {
        if (input) {
          frame = input.encode(id);
          for (const bytes of input.bytes) {
            bytes.fill(0);
            this.factors.delete(bytes);
          }
          this.writes.add(frame);
        }
        this.child!.stdin.write(
          frame ??
            JSON.stringify({
              version: 1,
              id,
              operation,
              ...(payload ? { payload } : {}),
            }) + '\n',
          (error) => {
            if (frame) {
              frame.fill(0);
              this.writes.delete(frame);
            }
            if (error) this.fail('unavailable');
          },
        );
      } catch {
        if (frame) {
          frame.fill(0);
          this.writes.delete(frame);
        }
        this.fail('unavailable');
      }
    });
  }

  private receive(chunk: Buffer): void {
    if (this.retired) return;
    if (!Buffer.isBuffer(chunk)) {
      this.fail('protocol');
      return;
    }
    let offset = 0;
    while (offset < chunk.length && !this.retired) {
      const newline = chunk.indexOf(10, offset);
      const end = newline < 0 ? chunk.length : newline;
      const part = chunk.subarray(offset, end);
      const frameLimit = Math.max(
        vaultMetadataFrameLimit,
        ...[...this.pending.values()].map((request) => request.frameLimit),
      );
      if (this.frameBytes + part.length > frameLimit || this.chunks.length >= 4096) {
        this.fail('protocol');
        return;
      }
      this.chunks.push(part);
      this.frameBytes += part.length;
      if (newline < 0) return;
      const frame = Buffer.concat(this.chunks, this.frameBytes);
      this.chunks = [];
      this.frameBytes = 0;
      try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(
          frame.at(-1) === 13 ? frame.subarray(0, -1) : frame,
        );
        if (frame.length <= 128 && parseVaultCatalogEvent(text)) {
          this.options.onSharedCatalogChanged?.();
          offset = newline + 1;
          continue;
        }
        const response = parseVaultResponse(text);
        const pending = response && this.pending.get(response.id);
        if (!response || !pending || frame.length > pending.frameLimit) {
          this.fail('protocol');
          return;
        }
        if (response.error) {
          if (response.error === 'vault_invalid_response') {
            this.fail('protocol');
            return;
          }
          clearTimeout(pending.timer);
          this.pending.delete(response.id);
          pending.reject(
            response.error === 'vault_workspace_connection_limit'
              ? new SharedConnectionLimit()
              : new Error(
                  response.error === 'vault_cancelled'
                    ? 'Vault request cancelled.'
                    : 'Vault operation failed.',
                ),
          );
        } else {
          const value = pending.parse(response.result);
          if (value === undefined) {
            this.fail('protocol');
            return;
          }
          clearTimeout(pending.timer);
          this.pending.delete(response.id);
          pending.resolve(value);
        }
      } catch {
        this.fail('protocol');
        return;
      } finally {
        frame.fill(0);
      }
      offset = newline + 1;
    }
  }

  private fail(reason: VaultStopReason): void {
    void this.stop(
      reason,
      new Error(reason === 'timeout' ? 'Vault did not respond in time.' : 'Vault is unavailable.'),
    ).catch(() => undefined);
  }

  private stop(reason: VaultStopReason, error: Error): Promise<void> {
    if (this.stopping) return this.stopping;
    this.retired = true;
    for (const factor of this.factors) factor.fill(0);
    this.factors.clear();
    for (const frame of this.writes) frame.fill(0);
    this.writes.clear();
    clearInterval(this.heartbeat);
    clearTimeout(this.startTimer);
    this.rejectStart?.(error);
    this.rejectStart = undefined;
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
    this.chunks = [];
    this.frameBytes = 0;
    this.stopping = new Promise<void>((resolve, reject) => {
      this.resolveStop = resolve;
      this.rejectStop = reject;
    });
    try {
      this.options.onUnavailable?.(reason);
    } catch {
      /* Notification cannot prevent key retirement. */
    }
    const child = this.child;
    if (!child || this.exitObserved || hasChildExited(child)) {
      this.exitObserved = true;
      this.completeStop();
      return this.stopping;
    }
    try {
      if (this.spawned && this.sequence < Number.MAX_SAFE_INTEGER)
        child.stdin.write(
          JSON.stringify({ version: 1, id: ++this.sequence, operation: 'lock' }) + '\n',
        );
      child.stdin.end();
    } catch {
      /* Forced termination below still owns the process. */
    }
    if (!this.exitObserved)
      this.graceTimer = setTimeout(() => {
        if (hasChildExited(child) || confirmNativeProcessExit(this.options.executable, child)) {
          this.exitObserved = true;
          this.completeStop();
          return;
        }
        try {
          child.kill('SIGKILL');
        } catch {
          /* The native exit event or an OS absence proof still confirms lock. */
        }
        if (hasChildExited(child) || confirmNativeProcessExit(this.options.executable, child)) {
          this.exitObserved = true;
          this.completeStop();
        } else if (!this.exitObserved)
          this.confirmationTimer = setTimeout(() => {
            if (hasChildExited(child) || confirmNativeProcessExit(this.options.executable, child)) {
              this.exitObserved = true;
              this.completeStop();
            } else
              this.rejectStop?.(new Error('Vault process termination could not be confirmed.'));
          }, this.options.stopConfirmationMs);
      }, this.options.stopGraceMs);
    return this.stopping;
  }

  private completeStop(): void {
    if (!this.exitObserved) return;
    clearTimeout(this.graceTimer);
    clearTimeout(this.confirmationTimer);
    clearTimeout(this.startTimer);
    this.resolveStop?.();
  }
}
