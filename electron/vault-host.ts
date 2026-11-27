import { type VaultMigrationContext } from './vault-migration-setup.ts';
import type { VaultSerialBundle, VaultSerialRequest } from './vault-serial-contract.ts';
import { consumeOSMigrationPrepare } from './vault-os-migration-contract.ts';
import type { VaultUpgradeContext } from './vault-upgrade-contract.ts';
import type { VaultUnprotectedOpened } from './vault-contract.ts';
import { wipeAdminRecoveryInput, type AdminRecoveryNativeInput } from './vault-admin-recovery.ts';
import {
  parseSharedCertificateRenewalRequest,
  parseSharedWorkspaceCARequest,
  type SharedCertificateRenewalResult,
  type SharedWorkspaceCAResult,
  wipeSharedSetupRequest,
  type SharedSetupReply,
  type SharedSetupNativeRequest,
  type SharedAdminSetupRequest,
  type SharedSetupCompletion,
  type SharedWorkspaceSwitch,
} from './vault-shared-setup-contract.ts';
import {
  consumeVaultRootEnrollmentBegin,
  type VaultRootEnrollmentContext,
} from './vault-root-enrollment.ts';
import {
  consumeVaultMigrationBegin,
  type VaultMigrationBegin,
  type VaultMigrationPrepared,
} from './vault-migration-setup.ts';
import {
  parseVaultQuickSshHostReceipt,
  parseVaultQuickTargetRequest,
  parseVaultQuickTargetRef,
  type VaultQuickTargetRef,
  type VaultQuickTargetLease,
} from './vault-quick-target.ts';
import {
  parseVaultRdpPlan,
  parseVaultRdpManualRequest,
  parseVaultRdpManualBundle,
} from './vault-rdp-manual.ts';
import {
  parseSharedConnectionContextRequest,
  type SharedConnectionContext,
} from './vault-shared-connection.ts';
import { parseSharedVaultRuntime, type SharedVaultRuntime } from './vault-shared-runtime.ts';
import type {
  AdminInventoryReply,
  AdminInventoryRequest,
  CreateSlotPort,
} from './vault-shared-admin-inventory.ts';
import type { WorkspaceAccessPort } from './vault-shared-access.ts';
import type {
  AccountBoundaryRotationPort,
  AccountSuspensionPort,
  PersonalRootRecoveryFactors,
  PersonalRootRecoveryReply,
  PersonalRootRecoveryRequest,
} from './vault-account-suspension.ts';
import type { GroupReply, GroupRequest } from './vault-shared-admin-groups.ts';
import type { GroupKeyPort } from './vault-shared-group-key.ts';
import type { MemberRotationPort } from './vault-shared-group-member-rotation.ts';
import type { GroupBoundaryGrantPort } from './vault-shared-group-boundary-grant.ts';
import type {
  NodeGrantAdministration,
  NodeGrantRequest,
  NodeGrantReply,
} from './vault-shared-node-grants.ts';
import type {
  SharedRecoveryInspectionReceipt,
  SharedRecoveryInspectionNative,
  SharedRecoveryRestoreNative,
  SharedRecoveryRestoreStatus,
} from './vault-shared-restore.ts';
import type {
  SharedRecoveryBackupOperation,
  SharedRecoveryBackupResult,
} from './vault-shared-recovery-backup.ts';
import { consumeSharedInitialJoinInput } from './vault-shared-initial-join.ts';
import { consumeSharedAccountResetInput } from './vault-shared-account-reset.ts';
import type {
  SharedAccountResetIssueInput,
  SharedAccountResetIssueOperation,
  SharedAccountResetIssueResult,
} from './vault-shared-account-reset-issue.ts';
import type {
  AccountResetMark,
  AccountResetMarkResult,
  AccountResetTargetPage,
} from './vault-shared-account-reset-queue.ts';
import { validSharedInvitationText, type SharedInvitation } from './vault-shared-invitation.ts';
import {
  parseBitwardenCleanupRequest,
  parseBitwardenCleanupResult,
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
} from './vault-bitwarden-installation.ts';
import { VaultBitwardenSynchronizer } from './vault-bitwarden-sync.ts';
import {
  parseBitwardenBridgeOwner,
  type BitwardenExtensionBridge,
} from './vault-bitwarden-bridge-contract.ts';
import {
  beginNativeBrowserTransfer,
  parseBrowserTransferRequest,
  type BrowserTransferClient,
} from './vault-bitwarden-native.ts';
import {
  parseVaultWebRequest,
  parseVaultWebPlan,
  parseVaultWebViews,
  parseVaultWebViewReply,
  type VaultWebPlan,
  type VaultWebView,
} from './vault-web.ts';
import {
  webSessionArchiveCoordinates,
  type WebSessionArchive,
  type WebSessionArchiveCoordinates,
} from './vault-web-session-archive.ts';
import {
  beginNativeVPNSSO,
  parseVPNSSOBegin,
  type VPNSSOClient,
  type VPNSSOCapability,
} from './vault-vpn-sso.ts';
import {
  parseVaultSshManualPlanRequest,
  parseVaultSshManualPlan,
  parseVaultSshManualRequest,
  parseVaultSshManualBundle,
  type VaultSshManualPlan,
} from './vault-ssh-manual.ts';
import {
  parseVaultVncPlan,
  parseVaultVncManualRequest,
  parseVaultVncManualBundle,
} from './vault-vnc-manual.ts';
import {
  parseVaultRoutedVncRequest,
  type VaultVncBundle,
  type VaultRoutedVncBundle,
} from './vault-vnc.ts';
import type { VaultVNCBitwardenPlan, VaultVNCBitwardenRequest } from './vault-vnc-bitwarden.ts';
import {
  parseVaultRoutedRdpRequest,
  type VaultRdpBundle,
  type VaultRoutedRdpBundle,
} from './vault-rdp.ts';
import type { VaultRDPBitwardenPlan, VaultRDPBitwardenRequest } from './vault-rdp-bitwarden.ts';
import type { VaultRecoveryRecordsReply } from './vault-sftp-recovery.ts';
import type { VaultRecoveryScopes } from './vault-sftp-recovery.ts';
import type { VaultFileEditSettings } from './vault-sftp-edit.ts';
import { parseClipboardReleaseRequest } from './vault-clipboard-release.ts';
import { parseVaultClipboardRequest, type VaultClipboardResult } from './vault-clipboard.ts';
import { parseVaultNodeDuplicate, type VaultNodeDuplicateResult } from './vault-node-duplicate.ts';
import { parseVaultNodeMove, type VaultNodeMoveResult } from './vault-node-move.ts';
import {
  parseVaultSshHostRequest,
  parseVaultSshHostTrust,
  type VaultSshHostPlan,
} from './vault-ssh-host.ts';
import { parseVaultRoutedSshRequest, type VaultRoutedSshBundle } from './vault-ssh-route.ts';
import {
  parseVaultRoutePlanRequest,
  type VaultRouteBinding,
  parseVaultRouteRequest,
  type VaultRouteBundle,
} from './vault-route.ts';
import {
  parseVaultTunnelFallbackPlanRequest,
  parseVaultTunnelFallbackBinding,
  parseVaultTunnelFallbackRequest,
  parseVaultTunnelFallbackBundle,
  type VaultTunnelFallbackBinding,
  type VaultTunnelFallbackBundle,
} from './vault-tunnel-fallback.ts';
import {
  parseTunnelImportRequest,
  parseTunnelImportDiscard,
  type VaultTunnelImportDisplay,
} from './vault-tunnel-import.ts';
import type { IpcMain, IpcMainInvokeEvent } from 'electron';
import { parseSharedCatalogRequest, type SharedCatalogPage } from './vault-shared-catalog.ts';
import { parseSharedNodeEditRequest, type SharedNodeEditReply } from './vault-shared-node-edit.ts';
import { parseSharedChangesRequest, type SharedChanges } from './vault-shared-catalog.ts';
import type {
  VaultCatalog,
  VaultDescriptor,
  VaultStatus,
  VaultUnlockResult,
  VaultStartupMetadata,
} from './vault-contract.js';
import type { VaultUnlockInput } from './vault-unlock.js';
import { consumeVaultUnlockInput } from './vault-unlock.ts';
import {
  consumeSharedVaultUnlockInput,
  consumeSharedVaultContinuationInput,
  hasSharedVaultContinuation,
  SharedReenrollmentPending,
  SharedConnectionLimit,
  validSharedTLSBundlePath,
  validSharedRecoveryKitPath,
  validSharedRecoveryBackupPath,
  type SharedRecoveryKitRefresh,
  type SharedRecoveryKitNativeRefresh,
  type SharedVaultContinuationInput,
  type SharedVaultUnlockInput,
  type SharedVaultAdmission,
  type SharedVaultSessionAdmission,
  type SharedVaultRecovery,
} from './vault-shared-unlock.ts';
import type { VaultWorkspace } from './vault-workspace.js';
import { parseVaultNodeDelete, type VaultNodeDeleteResult } from './vault-node-delete.ts';
import { parseVaultFolder, type VaultFolderResult } from './vault-folder.ts';
import { consumeVaultConnectionInput } from './vault-connection.ts';
import {
  consumeVaultCredentialInput,
  consumeVaultCredentialRequest,
  parseVaultCredentialSelection,
  type VaultCredentialInput,
  type VaultCredentialRequest,
  type VaultCredentialResult,
  type VaultCredentialDeleteResult,
} from './vault-credential.ts';
import {
  parseVaultMigrationSelection,
  parseVaultMigrationDecision,
  type VaultMigrationReport,
} from './vault-migration.ts';
import type { VaultPreferences, VaultUpdatePreferences } from './vault-preferences.js';
import type { VaultSecurity } from './vault-security.js';
import {
  consumeVaultEnrollmentBegin,
  consumeVaultEnrollmentConfirm,
  type VaultEnrollment,
  type VaultEnrollmentBegin,
} from './vault-enrollment-contract.ts';
import type { VaultSshRequest, VaultSshBundle } from './vault-ssh.js';
import type {
  VaultSSHBitwardenPreparation,
  VaultBitwardenRecipient,
  VaultSSHBitwardenRequest,
} from './vault-ssh-bitwarden.ts';
import type {
  VaultBitwardenCLIEnvelope,
  VaultBitwardenCLIUnlockBinding,
} from './vault-bitwarden-cli-unlock.ts';
import { parseVaultNotesRequest, type VaultNotesDisplay } from './vault-notes.ts';

import {
  consumeVaultTunnelInput,
  parseVaultTunnelSelection,
  parseVaultTunnelEditorRequest,
  type VaultTunnelResult,
  type VaultTunnelDeleteResult,
  type VaultTunnelEditorDisplay,
} from './vault-tunnel.ts';
import type {
  VaultPresenceAction,
  VaultPresenceAvailability,
  VaultPresenceChange,
  VaultPresenceEnrollment,
  VaultPresenceKind,
  VaultPresenceOperation,
  VaultPresenceRemoval,
  VaultPresenceSelection,
  VaultPresenceStatus,
  VaultPresenceUnlockResult,
} from './vault-presence.ts';

export type VaultFreshOperation =
  | 'tighten-local-profile'
  | 'bitwarden-cleanup'
  | 'bitwarden-install-zip'
  | 'bitwarden-install-folder'
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
  | 'credential-copy'
  | 'credential-display'
  | 'local-backup-export'
  | 'local-backup-install'
  | VaultPresenceOperation
  | 'migration-decide';
export type VaultFreshAuthentication = <T>(
  operation: VaultFreshOperation,
  descriptor: VaultDescriptor,
  submit: (input: VaultUnlockInput) => Promise<T>,
) => Promise<T>;
export type VaultPresenceAuthentication = (
  operation: VaultPresenceOperation,
  descriptor: VaultDescriptor,
  submit: (input: VaultUnlockInput, ownerWindow?: string) => Promise<VaultPresenceChange>,
) => Promise<VaultPresenceChange>;

export type SharedAdministrationPorts = {
  read(request: AdminInventoryRequest): Promise<AdminInventoryReply>;
  createSlot?: CreateSlotPort;
  groups?: (request: GroupRequest) => Promise<GroupReply>;
  nodeGrants?: NodeGrantAdministration;
  groupKey?: GroupKeyPort;
  memberRotation?: MemberRotationPort;
  access?: WorkspaceAccessPort;
  suspension?: AccountSuspensionPort;
  accountRotation?: AccountBoundaryRotationPort;
  personalRecovery?: (
    request: PersonalRootRecoveryRequest,
    factors: PersonalRootRecoveryFactors | undefined,
    accepted: () => boolean,
  ) => Promise<PersonalRootRecoveryReply>;
  reenrollment?: Pick<SharedAccountResetIssueOperation, 'workspaceId' | 'submit'>;
  ownDevicesOnly?: boolean;
};

type Client = BrowserTransferClient &
  VPNSSOClient & {
    sharedAdminInventory(request: AdminInventoryRequest): Promise<AdminInventoryReply>;
    sharedCreateCredentialSlot: CreateSlotPort;
    sharedWorkspaceAccess: WorkspaceAccessPort;
    sharedAccountSuspension: AccountSuspensionPort;
    sharedAccountBoundaryRotation: AccountBoundaryRotationPort;
    sharedPersonalRootRecovery(
      request: PersonalRootRecoveryRequest,
      auth?: Omit<SharedVaultUnlockInput, 'appVersion'>,
    ): Promise<PersonalRootRecoveryReply>;
    sharedAdminGroups(request: GroupRequest): Promise<GroupReply>;
    sharedAdminGroupKey: GroupKeyPort;
    sharedAdminGroupBoundaryGrant: GroupBoundaryGrantPort;
    sharedAdminGroupBoundaryRotation: GroupBoundaryGrantPort;
    sharedAdminGroupMemberRotation: MemberRotationPort;
    sharedAdminNodeGrant(request: NodeGrantRequest): Promise<NodeGrantReply>;
    cleanupBitwardenInstallations(
      value: unknown,
      authentication?: VaultUnlockInput,
    ): Promise<BitwardenInstallationRevision>;
    installBitwardenZip(
      value: unknown,
      authentication?: VaultUnlockInput,
    ): Promise<BitwardenFolderInstallResult>;
    installBitwardenFolder(
      value: unknown,
      authentication?: VaultUnlockInput,
    ): Promise<BitwardenFolderInstallResult>;
    bitwardenInstallationRevision(value: unknown): Promise<BitwardenInstallationRevision>;
    bitwardenInstallationPlan(value: unknown): Promise<BitwardenInstallationPlan>;
    webPlan(value: unknown): Promise<VaultWebPlan>;
    checkWebSessionViews?(views: VaultWebView[]): Promise<boolean[]>;
    readWebSessionArchive?(context: WebSessionArchiveCoordinates): Promise<WebSessionArchive>;
    saveWebSessionArchive?(
      context: WebSessionArchiveCoordinates,
      revision: string,
      bytes: Uint8Array,
    ): Promise<string>;
    forgetWebSessionArchive?(
      context: WebSessionArchiveCoordinates,
      revision: string,
    ): Promise<string>;
    registerQuickTarget(value: unknown): Promise<VaultQuickTargetRef>;
    releaseQuickTarget(value: unknown): Promise<true>;
    trustQuickSshHost(value: unknown, authentication?: VaultUnlockInput): Promise<VaultSshHostPlan>;
    rdpPlan(value: unknown): Promise<VaultRdpBundle['binding']>;
    rdpManualBundle(value: unknown): Promise<VaultRdpBundle | VaultRoutedRdpBundle>;
    prepareManualRDPBitwarden(
      value: unknown,
      recipient?: VaultBitwardenRecipient,
    ): Promise<VaultRDPBitwardenPlan>;
    sshManualPlan(value: unknown): Promise<VaultSshManualPlan>;
    sshManualBundle(value: unknown): Promise<VaultSshBundle | VaultRoutedSshBundle>;
    vncPlan(value: unknown): Promise<VaultVncBundle['binding']>;
    vncManualBundle(value: unknown): Promise<VaultVncBundle | VaultRoutedVncBundle>;
    vncBundle(value: unknown): Promise<VaultVncBundle>;
    routedVncBundle(value: unknown): Promise<VaultRoutedVncBundle>;
    prepareVNCBitwarden(
      value: VaultVNCBitwardenRequest,
      recipient?: VaultBitwardenRecipient,
    ): Promise<VaultVNCBitwardenPlan>;
    rdpBundle(value: unknown): Promise<VaultRdpBundle>;
    serialBundle(value: unknown): Promise<VaultSerialBundle>;
    checkSharedSerialUse(nodeIds: readonly string[]): Promise<boolean[]>;
    routedRdpBundle(value: unknown): Promise<VaultRoutedRdpBundle>;
    prepareRDPBitwarden(
      value: VaultRDPBitwardenRequest,
      recipient?: VaultBitwardenRecipient,
    ): Promise<VaultRDPBitwardenPlan>;
    sshHostPlan(value: unknown): Promise<VaultSshHostPlan>;
    trustSshHost(value: unknown, authentication?: VaultUnlockInput): Promise<VaultFolderResult>;
    trustSharedSshHost(
      value: unknown,
      authentication?: SharedVaultUnlockInput,
    ): Promise<VaultFolderResult>;
    connectionRoute(value: unknown): Promise<VaultRouteBinding | null>;
    routedSshBundle(value: unknown): Promise<VaultRoutedSshBundle>;
    tunnelPlan(value: unknown): Promise<VaultRouteBinding>;
    tunnelBundle(value: unknown): Promise<VaultRouteBundle>;
    tunnelFallbackPlan(value: unknown): Promise<VaultTunnelFallbackBinding>;
    tunnelFallbackBundle(value: unknown): Promise<VaultTunnelFallbackBundle>;
    stageTunnelImport(value: unknown): Promise<VaultTunnelImportDisplay>;
    discardTunnelImport(value: unknown): Promise<{ discarded: true }>;
    editTunnel(value: unknown, authentication?: VaultUnlockInput): Promise<VaultTunnelResult>;
    deleteTunnel(
      value: unknown,
      authentication?: VaultUnlockInput,
    ): Promise<VaultTunnelDeleteResult>;
    displayTunnelEditor(value: unknown): Promise<VaultTunnelEditorDisplay>;
    editCredential(
      value: unknown,
      authentication?: VaultUnlockInput,
    ): Promise<VaultCredentialResult>;
    deleteCredential(
      value: unknown,
      authentication?: VaultUnlockInput,
    ): Promise<VaultCredentialDeleteResult>;
    migrationReport(value: unknown): Promise<VaultMigrationReport>;
    decideMigration(value: unknown, authentication?: VaultUnlockInput): Promise<VaultFolderResult>;
    displayNotes(value: unknown): Promise<VaultNotesDisplay>;
    releaseClipboard(value: unknown, authentication?: VaultUnlockInput): Promise<VaultNotesDisplay>;
    copyCredential(
      value: unknown,
      authentication?: VaultUnlockInput,
    ): Promise<VaultClipboardResult>;
    displayCredentials(
      value: unknown,
      authentication?: VaultUnlockInput,
    ): Promise<VaultNotesDisplay>;
    status(): Promise<VaultStatus>;
    describe(): Promise<VaultDescriptor | null>;
    tightenLocalProfile(sequence: string, authentication: VaultUnlockInput): Promise<true>;
    exportLocalBackup(path: string, authentication?: VaultUnlockInput): Promise<true>;
    inspectLocalBackup(path: string): Promise<{ slots: VaultDescriptor; fingerprint: string }>;
    installLocalBackup(path: string, fingerprint: string, recoveryCode: Uint8Array): Promise<true>;
    catalog(): Promise<VaultCatalog>;
    sharedConnectionContext(value: unknown): Promise<SharedConnectionContext>;
    sharedCatalog(value: unknown): Promise<SharedCatalogPage>;
    sharedNodeEdit(
      value: unknown,
      authentication?: SharedVaultUnlockInput,
    ): Promise<SharedNodeEditReply>;
    sharedChanges(value: unknown): Promise<SharedChanges>;
    renewSharedServerCertificate(value: unknown): Promise<SharedCertificateRenewalResult>;
    sharedWorkspaceCA(value: unknown): Promise<SharedWorkspaceCAResult>;
    exportSharedTLSBundle(path: string): Promise<boolean>;
    tightenSharedProfile(sequence: string, input: SharedVaultUnlockInput): Promise<true>;
    refreshSharedRecoveryKit(
      source: string,
      destination: string,
      auth?: SharedVaultUnlockInput,
    ): Promise<SharedRecoveryKitNativeRefresh>;
    issueSharedAccountReset(
      path: string,
      input: SharedAccountResetIssueInput,
      factors: { vaultId: string; slotId: string },
    ): Promise<SharedAccountResetIssueResult>;
    sharedAccountResetTargets(after: string | null): Promise<AccountResetTargetPage>;
    markSharedAccountResetHandover(mark: AccountResetMark): Promise<AccountResetMarkResult>;
    exportSharedRecoveryBackup(
      path: string,
      recipient: Uint8Array,
      authentication?: Omit<SharedVaultUnlockInput, 'appVersion'>,
    ): Promise<SharedRecoveryBackupResult>;
    workspace(): Promise<VaultWorkspace>;
    deleteNodes(value: unknown, authentication?: VaultUnlockInput): Promise<VaultNodeDeleteResult>;
    moveNodes(value: unknown, authentication?: VaultUnlockInput): Promise<VaultNodeMoveResult>;
    duplicateConnection(
      value: unknown,
      authentication?: VaultUnlockInput,
    ): Promise<VaultNodeDuplicateResult>;
    saveFolder(value: unknown, authentication?: VaultUnlockInput): Promise<VaultFolderResult>;
    saveConnection(value: unknown, authentication?: VaultUnlockInput): Promise<VaultFolderResult>;
    startup(): Promise<VaultStartupMetadata>;
    security(): Promise<VaultSecurity>;
    protection(): Promise<{ protected: boolean }>;
    openUnprotected(create: boolean): Promise<VaultUnprotectedOpened>;
    resumeOSMigration(): Promise<VaultUnprotectedOpened>;
    sharedRuntime(): Promise<SharedVaultRuntime>;
    preferences(): Promise<VaultPreferences>;
    updatePreferences(value: VaultUpdatePreferences): Promise<true>;
    fileEditSettings(value?: unknown): Promise<VaultFileEditSettings>;
    sftpRecoveryScopes(after?: string): Promise<VaultRecoveryScopes>;
    sftpRecoveryRecords(value: unknown, workspace?: string): Promise<VaultRecoveryRecordsReply>;
    sshBundle(request: VaultSshRequest): Promise<VaultSshBundle>;
    beginBitwardenCLIUnlock(): Promise<VaultBitwardenCLIUnlockBinding>;
    commitBitwardenCLIUnlock(requestId: string, session: VaultBitwardenCLIEnvelope): Promise<void>;
    cancelBitwardenCLIUnlock(requestId: string): Promise<void>;
    prepareSSHBitwarden(
      request: VaultSSHBitwardenRequest,
      recipient?: VaultBitwardenRecipient,
    ): Promise<VaultSSHBitwardenPreparation>;
    unlock(value: unknown): Promise<VaultUnlockResult>;
    presenceAvailability(kind: VaultPresenceKind): Promise<VaultPresenceAvailability>;
    unlockPresence(
      kind: VaultPresenceKind,
      selection: VaultPresenceSelection,
      ownerWindow?: string,
    ): Promise<VaultPresenceUnlockResult>;
    enrollPresence(
      kind: VaultPresenceKind,
      ownerWindow: string | undefined,
      authentication: VaultUnlockInput,
    ): Promise<VaultPresenceEnrollment>;
    removePresence(
      kind: VaultPresenceKind,
      slotId: string,
      authentication: VaultUnlockInput,
    ): Promise<VaultPresenceRemoval>;
    resumeMigration(value: unknown): Promise<VaultUnlockResult>;
    resumeRootRotation(value: unknown): Promise<VaultUnlockResult>;
    sharedUnlock(
      value: unknown,
      appVersion: string,
      tlsUpdatePath?: string,
    ): Promise<SharedVaultAdmission>;
    sharedRecoverPassword(value: unknown, appVersion: string): Promise<SharedVaultRecovery>;
    sharedRecoverEnrollment(value: unknown, appVersion: string): Promise<SharedVaultAdmission>;
    sharedContinueEnrollment(value: unknown, appVersion: string): Promise<SharedVaultAdmission>;
    sharedJoinInitial(value: unknown, appVersion: string): Promise<SharedVaultAdmission>;
    sharedRedeemAccountReset(
      offerPath: string,
      value: unknown,
      appVersion: string,
    ): Promise<SharedVaultAdmission>;
    sharedJoinAdministrator(
      input: Extract<SharedAdminSetupRequest, { action: 'admin-join' }>,
      appVersion: string,
    ): Promise<SharedVaultAdmission>;
    selectSharedWorkspace(
      input: Extract<SharedAdminSetupRequest, { action: 'admin-join' }>,
      appVersion: string,
    ): Promise<SharedWorkspaceSwitch>;
    sharedSetup(input: SharedSetupNativeRequest): Promise<SharedSetupReply>;
    sharedRecoverAdministrator(
      input: AdminRecoveryNativeInput,
      appVersion: string,
    ): Promise<SharedVaultAdmission>;
    inspectSharedRecoveryBackup(
      input: SharedRecoveryInspectionNative,
    ): Promise<SharedRecoveryInspectionReceipt>;
    restoreSharedRecoveryBackup(
      input: SharedRecoveryRestoreNative,
    ): Promise<SharedRecoveryRestoreStatus>;
    inspectSharedInvitation(invitation: string): Promise<SharedInvitation>;
    readSharedInvitationFile(path: string): Promise<SharedInvitation>;
    beginEnrollment(value: unknown): Promise<VaultEnrollment>;
    migrationSetupContext(): Promise<VaultMigrationContext>;
    osMigrationContext(): Promise<VaultMigrationContext>;
    prepareOSMigration(value: unknown): Promise<VaultMigrationPrepared>;
    beginMigrationSetup(value: unknown): Promise<VaultEnrollment>;
    confirmMigrationSetup(value: unknown): Promise<VaultMigrationPrepared>;
    confirmEnrollment(value: unknown): Promise<VaultUnlockResult>;
    rootRotationSetupContext(): Promise<VaultRootEnrollmentContext>;
    upgradeSetupContext(): Promise<VaultUpgradeContext>;
    beginUpgradeSetup(value: unknown): Promise<VaultEnrollment>;
    beginRootRotationSetup(value: unknown, encryptDatabase?: boolean): Promise<VaultEnrollment>;
    confirmRootRotationSetup(value: unknown): Promise<VaultMigrationPrepared>;
    cancelRootRotationSetup(): Promise<true>;
    lock(): Promise<void>;
  };

type SharedAuthenticationFactors =
  | Omit<SharedVaultUnlockInput, 'appVersion'>
  | Omit<SharedVaultContinuationInput, 'appVersion'>;
type SharedAuthenticationInvoke<T> = (
  client: Client,
  input: SharedAuthenticationFactors,
) => Promise<T>;
export type SharedActionConfirmation<T> = (
  startup: VaultStartupMetadata,
  current: () => boolean,
  submit: (input: SharedVaultUnlockInput, trusted: () => boolean) => Promise<T>,
) => Promise<T | null>;
export type SharedRecoveryKitConfirmation = SharedActionConfirmation<SharedRecoveryKitRefresh>;

/** Replacement is allowed only after the preceding process has confirmed exit. */
export class VaultBackendHost {
  private client: Client | undefined;
  private creating = false;
  private sharedAuthenticating = false;
  private unlocking = false;
  private configuringPresence = false;
  private sharedAdmitted = false;
  private selectingBitwardenPackage = false;
  private enrollment:
    | {
        client: Client;
        value: VaultEnrollment;
        migration: boolean;
        rotation?: boolean;
        upgrade?: boolean;
      }
    | undefined;
  private unlockedWorkspace: string | undefined;
  private selectedWorkspace: string | undefined;
  private selectedKind: 'local' | 'shared' | undefined;
  private stopping: Promise<void> | undefined;
  private readonly createClient: () => Client;
  private readonly canStart: () => boolean;
  private readonly selected: (() => void) | undefined;
  private readonly activate: ((security: VaultSecurity) => void) | undefined;
  private legacyMigrationRequired: boolean;
  constructor(
    createClient: () => Client,
    canStart: () => boolean,
    activate?: (security: VaultSecurity) => void,
    selected?: () => void,
    legacyMigrationRequired = false,
  ) {
    this.createClient = createClient;
    this.canStart = canStart;
    this.activate = activate;
    this.selected = selected;
    this.legacyMigrationRequired = legacyMigrationRequired;
  }

  get requiresLegacyMigration(): boolean {
    return this.legacyMigrationRequired;
  }

  get isVaultWorkspace(): boolean {
    return this.selectedWorkspace !== undefined;
  }
  get isSharedWorkspace(): boolean {
    return this.selectedKind === 'shared';
  }
  get hasOwner(): boolean {
    return this.client !== undefined;
  }
  get unlockedWorkspaceId(): string | undefined {
    return !this.stopping && this.canStart() ? this.unlockedWorkspace : undefined;
  }
  async sshHostPlan(
    value: unknown,
    accepted: () => boolean = () => true,
  ): Promise<VaultSshHostPlan> {
    const request = parseVaultSshHostRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid SSH host plan.');
    if (!client || !workspace || request.workspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const result = await client.sshHostPlan(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    return result;
  }
  async trustSshHost(
    value: unknown,
    confirm?: VaultFreshAuthentication,
    accepted: () => boolean = () => true,
  ): Promise<VaultFolderResult> {
    const request = parseVaultSshHostTrust(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid SSH host confirmation.');
    if (!client || !workspace || request.workspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const result = await this.freshAction(
      client,
      workspace,
      'ssh-host-trust',
      (authentication) => client.trustSshHost(request, authentication),
      confirm,
      accepted,
    );
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    return result;
  }
  async trustSharedSshHost(
    value: unknown,
    confirm: SharedActionConfirmation<true>,
    accepted: () => boolean,
  ): Promise<void> {
    const request = parseVaultSshHostTrust(value),
      client = this.client,
      device = this.selectedWorkspace;
    const current = () =>
      this.client === client &&
      this.sharedAdmitted &&
      !this.sharedAuthenticating &&
      this.selectedWorkspace === device &&
      this.unlockedWorkspaceId === request?.workspaceId &&
      accepted();
    if (!request || !client || !device || !current())
      throw Error('Shared SSH host confirmation unavailable.');
    const runtime = await client.sharedRuntime();
    if (!current() || runtime.vaultId !== device || runtime.workspaceId !== request.workspaceId)
      throw Error('Shared SSH session changed.');
    if (runtime.security.effective === 'default') {
      await client.trustSharedSshHost(request);
      if (!current()) throw Error('Shared SSH session changed.');
      return;
    }
    if (runtime.security.effective !== 'standard')
      throw Error('Shared SSH host confirmation unavailable.');
    const startup = await client.startup();
    if (!current() || !startup.shared || startup.slots?.vaultId !== device)
      throw Error('Shared SSH session changed.');
    const result = await confirm(startup, current, async (input, trusted) => {
      try {
        if (
          !current() ||
          !trusted() ||
          input.vaultId !== device ||
          !startup.slots?.slots.some((slot) => slot.kind === 'password' && slot.id === input.slotId)
        )
          throw Error('Shared SSH session changed.');
        await client.trustSharedSshHost(request, input);
        if (!current() || !trusted()) throw Error('Shared SSH session changed.');
        return true;
      } finally {
        input.password.fill(0);
        input.ask?.fill(0);
      }
    });
    if (!current() || result !== true) throw Error('Shared SSH host confirmation cancelled.');
  }
  async connectionRoute(
    value: unknown,
    accepted: () => boolean = () => true,
  ): Promise<VaultRouteBinding | null> {
    const request = parseVaultRoutePlanRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid vault route request.');
    if (!client || !workspace || request.workspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const result = await client.connectionRoute(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    return result;
  }
  async cleanupBitwardenInstallations(
    accepted: () => boolean,
    confirm?: VaultFreshAuthentication,
  ): Promise<BitwardenInstallationRevision> {
    const client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!client || !workspace || !accepted() || this.selectingBitwardenPackage)
      throw Error('Bitwarden cleanup is unavailable.');
    const current = () =>
      this.client === client && this.unlockedWorkspaceId === workspace && accepted();
    this.selectingBitwardenPackage = true;
    try {
      const query = { workspaceId: workspace, minimumRevision: '0' };
      const before = parseBitwardenInstallationRevision(
        await client.bitwardenInstallationRevision(query),
        query,
      );
      if (!before || !current()) throw Error('Bitwarden cleanup is unavailable.');
      const q = parseBitwardenCleanupRequest({
        workspaceId: workspace,
        expectedRevision: before.revision,
      });
      if (!q) throw Error('Bitwarden cleanup is unavailable.');
      const result = await this.freshAction(
        client,
        workspace,
        'bitwarden-cleanup',
        (authentication) => client.cleanupBitwardenInstallations(q, authentication),
        confirm,
        current,
      );
      const parsed = parseBitwardenCleanupResult(result, q);
      if (!parsed || !current()) throw Error('Bitwarden cleanup is unavailable.');
      return parsed;
    } finally {
      this.selectingBitwardenPackage = false;
    }
  }
  chooseBitwardenFolder(
    pick: () => Promise<string | null>,
    accepted: () => boolean,
    confirm?: VaultFreshAuthentication,
  ): Promise<BitwardenInstallationPlan | null> {
    return this.chooseBitwardenPackage(false, pick, accepted, confirm);
  }
  chooseBitwardenZip(
    pick: () => Promise<string | null>,
    accepted: () => boolean,
    confirm?: VaultFreshAuthentication,
  ): Promise<BitwardenInstallationPlan | null> {
    return this.chooseBitwardenPackage(true, pick, accepted, confirm);
  }
  private async chooseBitwardenPackage(
    archive: boolean,
    pick: () => Promise<string | null>,
    accepted: () => boolean,
    confirm?: VaultFreshAuthentication,
  ): Promise<BitwardenInstallationPlan | null> {
    const client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!client || !workspace || !accepted() || this.selectingBitwardenPackage)
      throw Error('Bitwarden installation is unavailable.');
    const current = () =>
      this.client === client && this.unlockedWorkspaceId === workspace && accepted();
    this.selectingBitwardenPackage = true;
    try {
      const query = { workspaceId: workspace, minimumRevision: '0' };
      const before = parseBitwardenInstallationRevision(
        await client.bitwardenInstallationRevision(query),
        query,
      );
      if (!before || !current()) throw Error('Bitwarden installation is unavailable.');
      const sourceDirectory = await pick();
      if (!current()) throw Error('Bitwarden installation is unavailable.');
      if (sourceDirectory === null) return null;
      const installed = archive
        ? await this.installBitwardenZip(
            {
              workspaceId: workspace,
              sourceFile: sourceDirectory,
              expectedRevision: before.revision,
            },
            current,
            confirm,
          )
        : await this.installBitwardenFolder(
            { workspaceId: workspace, sourceDirectory, expectedRevision: before.revision },
            current,
            confirm,
          );
      return await this.bitwardenInstallationPlan(
        { workspaceId: workspace, minimumRevision: installed.revision },
        current,
      );
    } finally {
      this.selectingBitwardenPackage = false;
    }
  }
  installBitwardenFolder(
    value: unknown,
    accepted: () => boolean,
    confirm?: VaultFreshAuthentication,
  ): Promise<BitwardenFolderInstallResult> {
    return this.installBitwardenPackage(value, false, accepted, confirm);
  }
  installBitwardenZip(
    value: unknown,
    accepted: () => boolean,
    confirm?: VaultFreshAuthentication,
  ): Promise<BitwardenFolderInstallResult> {
    return this.installBitwardenPackage(value, true, accepted, confirm);
  }
  private async installBitwardenPackage(
    value: unknown,
    archive: boolean,
    accepted: () => boolean,
    confirm?: VaultFreshAuthentication,
  ): Promise<BitwardenFolderInstallResult> {
    const q = archive
        ? parseBitwardenZipInstallRequest(value)
        : parseBitwardenFolderInstallRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!q || !client || !workspace || q.workspaceId !== workspace || !accepted())
      throw Error('Bitwarden installation is unavailable.');
    const result = await this.freshAction(
      client,
      workspace,
      archive ? 'bitwarden-install-zip' : 'bitwarden-install-folder',
      (authentication) =>
        archive
          ? client.installBitwardenZip(q, authentication)
          : client.installBitwardenFolder(q, authentication),
      confirm,
      accepted,
    );
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Bitwarden installation is unavailable.');
    const parsed =
      'sourceFile' in q
        ? parseBitwardenZipInstallResult(result, q)
        : parseBitwardenFolderInstallResult(result, q);
    if (!parsed) throw Error('Bitwarden installation is unavailable.');
    return parsed;
  }
  async bitwardenInstallationPlan(
    value: unknown,
    accepted: () => boolean,
  ): Promise<BitwardenInstallationPlan> {
    const q = parseBitwardenInstallationRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!q || !client || !workspace || q.workspaceId !== workspace || !accepted())
      throw Error('Bitwarden installation is unavailable.');
    const result = await client.bitwardenInstallationPlan(q);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Bitwarden installation is unavailable.');
    const plan = parseBitwardenInstallationPlan(result, q);
    if (!plan) throw Error('Bitwarden installation is unavailable.');
    return plan;
  }
  createBitwardenSynchronizer(
    owner: unknown,
    bridge: BitwardenExtensionBridge,
    accepted: () => boolean,
  ): VaultBitwardenSynchronizer {
    const parsed = parseBitwardenBridgeOwner(owner),
      client = this.client;
    if (!parsed || !client || this.unlockedWorkspaceId !== parsed.workspaceId || !accepted())
      throw Error('Invalid Bitwarden owner.');
    return new VaultBitwardenSynchronizer({
      owner: parsed,
      client,
      bridge,
      current: () =>
        this.client === client && this.unlockedWorkspaceId === parsed.workspaceId && accepted(),
    });
  }
  async beginBitwardenTransfer(value: unknown, accepted: () => boolean = () => true) {
    const q = parseBrowserTransferRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!q || !client || !workspace || q.workspaceId !== workspace)
      throw Error('Invalid browser transfer.');
    return beginNativeBrowserTransfer(
      client,
      q,
      () => this.client === client && this.unlockedWorkspaceId === workspace && accepted(),
    );
  }
  async beginVPNSSO(value: unknown, accepted: () => boolean) {
    const q = parseVPNSSOBegin(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!q || !client || !workspace || q.request.workspaceId !== workspace)
      throw Error('Invalid VPN SSO owner.');
    return beginNativeVPNSSO(
      client,
      q,
      () => this.client === client && this.unlockedWorkspaceId === workspace && accepted(),
    );
  }
  // Reserve the original root BEFORE native browser/helper initialization.
  // A replacement client must never acquire a pending browser continuation.
  vpnSSOAuthority(accepted: () => boolean) {
    const client = this.client,
      workspace = this.unlockedWorkspaceId,
      personal = this.isSharedWorkspace ? this.selectedWorkspace : undefined;
    const current = () =>
      this.client === client && this.unlockedWorkspaceId === workspace && accepted();
    if (!client || !workspace || !current()) throw Error('Invalid VPN SSO owner.');
    return {
      security: async () => {
        if (!current()) throw Error('Invalid VPN SSO owner.');
        const result = await client.security();
        if (!current()) throw Error('Invalid VPN SSO owner.');
        return result;
      },
      begin: (value: unknown, reserved?: (capability: VPNSSOCapability) => void) => {
        const q = parseVPNSSOBegin(value);
        if (!q || q.request.workspaceId !== workspace || !current())
          throw Error('Invalid VPN SSO owner.');
        return beginNativeVPNSSO(
          client,
          personal ? { ...q, custody: { workspaceId: personal, fileId: q.binding.fileId } } : q,
          current,
          reserved,
          async () => {
            // Retire the active owner synchronously before waiting for its process;
            // an old browser cleanup must never lock a replacement root.
            if (this.client === client) await this.stop();
            else await client.lock();
          },
        );
      },
    };
  }
  async webPlan(value: unknown, accepted: () => boolean = () => true): Promise<VaultWebPlan> {
    const request = parseVaultWebRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid vault web plan.');
    if (!client || !workspace || request.workspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const result = await client.webPlan(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const plan = parseVaultWebPlan(result, request);
    if (!plan) throw Error('Invalid vault web plan.');
    return plan;
  }
  webSessionArchive(plan: VaultWebPlan, accepted: () => boolean) {
    const client = this.client;
    const context = webSessionArchiveCoordinates(plan);
    if (
      !context ||
      !client?.readWebSessionArchive ||
      !client.saveWebSessionArchive ||
      !client.forgetWebSessionArchive
    )
      return undefined;
    const requireCurrent = () => {
      if (this.client !== client || this.unlockedWorkspaceId !== context.workspaceId || !accepted())
        throw Error('Vault web session is closed.');
    };
    requireCurrent();
    return {
      read: async (): Promise<WebSessionArchive> => {
        requireCurrent();
        const result = await client.readWebSessionArchive!(context);
        try {
          requireCurrent();
          return result;
        } catch (error) {
          result.bytes?.fill(0);
          throw error;
        }
      },
      save: async (revision: string, bytes: Uint8Array) => {
        try {
          requireCurrent();
          const next = await client.saveWebSessionArchive!(context, revision, bytes);
          requireCurrent();
          return next;
        } finally {
          bytes.fill(0);
        }
      },
      forget: async (revision: string) => {
        requireCurrent();
        const next = await client.forgetWebSessionArchive!(context, revision);
        requireCurrent();
        return next;
      },
    };
  }
  async checkWebSessionViews(workspaceId: string, value: unknown): Promise<boolean[]> {
    const client = this.client;
    const views = parseVaultWebViews(value);
    if (
      !views ||
      !client?.checkWebSessionViews ||
      !this.isSharedWorkspace ||
      !workspaceId ||
      workspaceId !== this.unlockedWorkspaceId
    )
      throw Error('Web session View is unavailable.');
    const current = await client.checkWebSessionViews(views);
    if (client !== this.client || workspaceId !== this.unlockedWorkspaceId)
      throw Error('Web session View is unavailable.');
    const verified = parseVaultWebViewReply({ current }, views.length);
    if (!verified) throw Error('Invalid web session View receipt.');
    return verified;
  }
  async beginQuickTarget(
    value: unknown,
    accepted: () => boolean = () => true,
  ): Promise<VaultQuickTargetLease> {
    const request = parseVaultQuickTargetRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid temporary target.');
    const current = () =>
      this.client === client && this.unlockedWorkspaceId === workspace && accepted();
    if (
      !client ||
      !workspace ||
      request.workspaceId !== workspace ||
      this.selectedKind === 'shared' ||
      !current()
    )
      throw Error('Vault is locked.');
    const result = await client.registerQuickTarget(request);
    const ref = parseVaultQuickTargetRef(result, request);
    if (!ref) {
      // Real clients retire on malformed replies; preserve that mutation-boundary
      // guarantee for custom adapters without stopping a replacement owner.
      if (this.client === client) await this.stop();
      else await client.lock();
      throw Error('Invalid temporary target receipt.');
    }
    let released = false,
      releasing: Promise<void> | undefined;
    const release = (): Promise<void> => {
      if (released) return Promise.resolve();
      if (releasing) return releasing;
      const task = Promise.resolve().then(async () => {
        try {
          if ((await client.releaseQuickTarget(ref)) !== true)
            throw Error('Invalid release receipt.');
        } catch {
          if (this.client === client) await this.stop();
          else await client.lock();
        }
        released = true;
      });
      releasing = task.catch((error) => {
        releasing = undefined;
        throw error;
      });
      return releasing;
    };
    const lease = { reference: Object.freeze({ ...ref }), release };
    if (!current()) {
      await release();
      throw Error('Vault is locked.');
    }
    return lease;
  }
  async trustQuickSshHost(
    value: unknown,
    confirm?: VaultFreshAuthentication,
    accepted: () => boolean = () => true,
  ): Promise<VaultSshHostPlan> {
    const request = parseVaultSshHostTrust(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request || request.credentialOverride !== '')
      throw Error('Invalid temporary host confirmation.');
    if (
      !client ||
      !workspace ||
      request.workspaceId !== workspace ||
      this.selectedKind === 'shared' ||
      !accepted()
    )
      throw Error('Vault is locked.');
    const result = await this.freshAction(
      client,
      workspace,
      'ssh-quick-host-trust',
      (authentication) => client.trustQuickSshHost(request, authentication),
      confirm,
      accepted,
    );
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const plan = parseVaultQuickSshHostReceipt(result, request);
    if (
      !plan ||
      plan.fingerprint !== request.received ||
      plan.revision === request.expected.revision
    )
      throw Error('Invalid temporary host receipt.');
    return plan;
  }
  async rdpPlan(
    value: unknown,
    accepted: () => boolean = () => true,
  ): Promise<VaultRdpBundle['binding']> {
    const request = parseVaultRoutePlanRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid RDP plan.');
    if (!client || !workspace || request.workspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const result = await client.rdpPlan(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const binding = parseVaultRdpPlan({ binding: result }, request);
    if (!binding) throw Error('Invalid RDP plan.');
    return binding;
  }
  async rdpManualBundle(
    value: unknown,
    accepted: () => boolean = () => true,
  ): Promise<VaultRdpBundle | VaultRoutedRdpBundle> {
    const request = parseVaultRdpManualRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid temporary RDP request.');
    if (!client || !workspace || request.context.binding.workspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const result = await client.rdpManualBundle(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const bundle = parseVaultRdpManualBundle(result, request);
    if (!bundle) throw Error('Invalid temporary RDP bundle.');
    return bundle;
  }
  async prepareManualRDPBitwarden(
    value: unknown,
    recipient: VaultBitwardenRecipient | undefined,
    accepted: () => boolean,
  ): Promise<VaultRDPBitwardenPlan> {
    const q = parseVaultRdpManualRequest(value),
      client = this.client;
    const workspace = this.unlockedWorkspaceId;
    if (
      !q ||
      q.context.endpoint ||
      !client ||
      !workspace ||
      this.isSharedWorkspace ||
      q.context.binding.workspaceId !== workspace ||
      !accepted()
    )
      throw Error('Temporary Bitwarden RDP is unavailable.');
    const result = await client.prepareManualRDPBitwarden(q, recipient);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    return result;
  }
  async sshManualPlan(
    value: unknown,
    accepted: () => boolean = () => true,
  ): Promise<VaultSshManualPlan> {
    const request = parseVaultSshManualPlanRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid SSH manual plan.');
    if (!client || !workspace || request.workspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const result = await client.sshManualPlan(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const plan = parseVaultSshManualPlan(result, request);
    if (!plan) throw Error('Invalid SSH manual plan.');
    return plan;
  }
  async sshManualBundle(
    value: unknown,
    accepted: () => boolean = () => true,
  ): Promise<VaultSshBundle | VaultRoutedSshBundle> {
    const request = parseVaultSshManualRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid temporary SSH request.');
    if (
      !client ||
      !workspace ||
      request.context.plan.host.binding.workspaceId !== workspace ||
      !accepted()
    )
      throw Error('Vault is locked.');
    const result = await client.sshManualBundle(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const bundle = parseVaultSshManualBundle(result, request);
    if (!bundle) throw Error('Invalid temporary SSH bundle.');
    return bundle;
  }
  async vncPlan(
    value: unknown,
    accepted: () => boolean = () => true,
  ): Promise<VaultVncBundle['binding']> {
    const request = parseVaultRoutePlanRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid VNC plan.');
    if (!client || !workspace || request.workspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const result = await client.vncPlan(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const binding = parseVaultVncPlan({ binding: result }, request);
    if (!binding) throw Error('Invalid VNC plan.');
    return binding;
  }
  async vncManualBundle(
    value: unknown,
    accepted: () => boolean = () => true,
  ): Promise<VaultVncBundle | VaultRoutedVncBundle> {
    const request = parseVaultVncManualRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid temporary VNC request.');
    if (!client || !workspace || request.context.binding.workspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const result = await client.vncManualBundle(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const bundle = parseVaultVncManualBundle(result, request);
    if (!bundle) throw Error('Invalid temporary VNC bundle.');
    return bundle;
  }
  async vncBundle(value: unknown, accepted: () => boolean = () => true): Promise<VaultVncBundle> {
    const request = parseVaultRouteRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid vault VNC request.');
    if (!client || !workspace || request.workspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const result = await client.vncBundle(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    return result;
  }
  async routedVncBundle(
    value: unknown,
    accepted: () => boolean = () => true,
  ): Promise<VaultRoutedVncBundle> {
    const request = parseVaultRoutedVncRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid vault VNC route request.');
    if (!client || !workspace || request.workspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const result = await client.routedVncBundle(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    return result;
  }
  async prepareVNCBitwarden(
    request: VaultVNCBitwardenRequest,
    recipient: VaultBitwardenRecipient | undefined,
    accepted: () => boolean,
  ): Promise<VaultVNCBitwardenPlan> {
    const client = this.client;
    const workspace = this.unlockedWorkspaceId;
    if (
      !client ||
      !workspace ||
      this.isSharedWorkspace ||
      workspace !== request.workspaceId ||
      !accepted()
    )
      throw Error('Vault is locked.');
    const result = await client.prepareVNCBitwarden(request, recipient);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    return result;
  }
  async rdpBundle(value: unknown, accepted: () => boolean = () => true): Promise<VaultRdpBundle> {
    const request = parseVaultRouteRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid vault RDP request.');
    if (!client || !workspace || request.workspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const result = await client.rdpBundle(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    return result;
  }
  async serialBundle(
    request: VaultSerialRequest,
    accepted: () => boolean,
  ): Promise<VaultSerialBundle> {
    const client = this.client;
    const workspace = this.unlockedWorkspaceId;
    if (
      !client ||
      !workspace ||
      request.workspaceId !== workspace ||
      !accepted() ||
      (request.quick && this.isSharedWorkspace)
    )
      throw Error('Protected serial connection is unavailable.');
    const result = await client.serialBundle(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    return result;
  }
  async checkSharedSerialUse(workspaceId: string, nodeIds: readonly string[]): Promise<boolean[]> {
    const client = this.client;
    if (!client || !this.isSharedWorkspace || this.unlockedWorkspaceId !== workspaceId)
      throw Error('Shared serial permission check is unavailable.');
    const result = await client.checkSharedSerialUse(nodeIds);
    if (this.client !== client || this.unlockedWorkspaceId !== workspaceId)
      throw Error('Vault is locked.');
    return result;
  }
  async prepareRDPBitwarden(
    request: VaultRDPBitwardenRequest,
    recipient: VaultBitwardenRecipient | undefined,
    accepted: () => boolean,
  ): Promise<VaultRDPBitwardenPlan> {
    const client = this.client;
    const workspace = this.unlockedWorkspaceId;
    if (
      !client ||
      !workspace ||
      this.isSharedWorkspace ||
      workspace !== request.workspaceId ||
      !accepted()
    )
      throw Error('Vault is locked.');
    const result = await client.prepareRDPBitwarden(request, recipient);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    return result;
  }
  async routedRdpBundle(
    value: unknown,
    accepted: () => boolean = () => true,
  ): Promise<VaultRoutedRdpBundle> {
    const request = parseVaultRoutedRdpRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid vault RDP route request.');
    if (!client || !workspace || request.workspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const result = await client.routedRdpBundle(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    return result;
  }
  async routedSshBundle(
    value: unknown,
    accepted: () => boolean = () => true,
  ): Promise<VaultRoutedSshBundle> {
    const request = parseVaultRoutedSshRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid vault SSH route request.');
    if (!client || !workspace || request.workspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const result = await client.routedSshBundle(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    return result;
  }
  async tunnelPlan(
    value: unknown,
    accepted: () => boolean = () => true,
  ): Promise<VaultRouteBinding> {
    const request = parseVaultRoutePlanRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid vault route request.');
    if (!client || !workspace || request.workspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const result = await client.tunnelPlan(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    return result;
  }
  async tunnelBundle(
    value: unknown,
    accepted: () => boolean = () => true,
  ): Promise<VaultRouteBundle> {
    const request = parseVaultRouteRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid vault route request.');
    if (!client || !workspace || request.workspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const result = await client.tunnelBundle(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    return result;
  }
  async tunnelFallbackPlan(
    value: unknown,
    accepted: () => boolean = () => true,
  ): Promise<VaultTunnelFallbackBinding> {
    const request = parseVaultTunnelFallbackPlanRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid vault fallback request.');
    if (!client || !workspace || request.workspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const result = await client.tunnelFallbackPlan(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const binding = parseVaultTunnelFallbackBinding(result, request);
    if (!binding) throw Error('Invalid vault fallback response.');
    return binding;
  }
  async tunnelFallbackBundle(
    value: unknown,
    accepted: () => boolean = () => true,
  ): Promise<VaultTunnelFallbackBundle> {
    const request = parseVaultTunnelFallbackRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid vault fallback request.');
    if (!client || !workspace || request.workspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const result = await client.tunnelFallbackBundle(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const bundle = parseVaultTunnelFallbackBundle(result, request);
    if (!bundle) throw Error('Invalid vault fallback response.');
    return bundle;
  }
  async beginBitwardenCLIUnlock(accepted: () => boolean) {
    const client = this.client;
    const workspace = this.unlockedWorkspaceId;
    if (!client || !workspace || this.isSharedWorkspace || !accepted())
      throw Error('Vault is locked.');
    const isCurrent = () => this.client === client && this.unlockedWorkspaceId === workspace;
    const binding = await client.beginBitwardenCLIUnlock();
    const cancel = async () => {
      if (isCurrent()) await client.cancelBitwardenCLIUnlock(binding.requestId);
    };
    if (binding.workspaceId !== workspace || !isCurrent() || !accepted()) {
      await cancel();
      throw Error('Vault is locked.');
    }
    return {
      binding,
      cancel,
      commit: async (session: VaultBitwardenCLIEnvelope) => {
        if (!isCurrent() || !accepted()) throw Error('Vault is locked.');
        await client.commitBitwardenCLIUnlock(binding.requestId, session);
        if (!isCurrent() || !accepted()) throw Error('Vault is locked.');
      },
    };
  }

  async prepareSSHBitwarden(
    request: VaultSSHBitwardenRequest,
    recipient: VaultBitwardenRecipient | undefined,
    accepted: () => boolean,
  ): Promise<VaultSSHBitwardenPreparation> {
    const client = this.client;
    const workspace = this.unlockedWorkspaceId;
    if (
      !client ||
      !workspace ||
      this.isSharedWorkspace ||
      workspace !== request.workspaceId ||
      !accepted()
    )
      throw Error('Vault is locked.');
    const result = await client.prepareSSHBitwarden(request, recipient);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    return result;
  }

  async sshBundle(request: VaultSshRequest): Promise<VaultSshBundle> {
    const client = this.client;
    const workspaceId = this.unlockedWorkspaceId;
    if (!client || !workspaceId || request.workspaceId !== workspaceId)
      throw new Error('Vault is locked.');
    const result = await client.sshBundle(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspaceId)
      throw new Error('Vault is locked.');
    return result;
  }

  async status(): Promise<VaultStatus> {
    return this.get().status();
  }
  async describe(): Promise<VaultDescriptor | null> {
    const client = this.get();
    const descriptor = await client.describe();
    this.select(client, descriptor, this.selectedKind);
    return descriptor;
  }
  async localBackupAvailable(): Promise<boolean> {
    const client = this.client;
    const workspace = this.unlockedWorkspaceId;
    if (!client || !workspace || this.isSharedWorkspace) return false;
    const descriptor = await client.describe();
    return (
      this.client === client &&
      this.unlockedWorkspaceId === workspace &&
      descriptor?.vaultId === workspace &&
      descriptor.encrypted
    );
  }
  async exportLocalBackup(
    pick: () => Promise<string | null>,
    confirm: VaultFreshAuthentication,
    accepted: () => boolean,
  ): Promise<boolean> {
    const client = this.client;
    const workspace = this.unlockedWorkspaceId;
    const current = () =>
      this.client === client && this.unlockedWorkspaceId === workspace && accepted();
    if (!client || !workspace || !current() || !(await this.localBackupAvailable()) || !current())
      throw Error('Encrypted vault backup is unavailable.');
    const destination = await pick();
    if (!current()) throw Error('Encrypted vault backup is unavailable.');
    if (!destination) return false;
    const result = await this.freshAction(
      client,
      workspace,
      'local-backup-export',
      (authentication) => client.exportLocalBackup(destination, authentication),
      confirm,
      current,
    );
    if (!current()) throw Error('Encrypted vault backup is unavailable.');
    return result;
  }
  async tightenLocalProfile(
    confirm: VaultFreshAuthentication,
    accepted: () => boolean,
    lock: () => Promise<void>,
  ): Promise<void> {
    const client = this.client;
    const workspace = this.unlockedWorkspaceId;
    if (!client || !workspace || this.isSharedWorkspace || this.enrollment || !accepted())
      throw Error('Local profile change unavailable.');
    let committed = false;
    try {
      await this.freshAction(
        client,
        workspace,
        'tighten-local-profile',
        async (authentication, security) => {
          if (!authentication) throw Error('Fresh authentication is required.');
          committed = await client.tightenLocalProfile(security.sequence, authentication);
        },
        confirm,
        accepted,
      );
    } finally {
      // Wait for the protected prompt to close before retiring the same owner.
      if (committed && this.client === client && this.unlockedWorkspaceId === workspace)
        await lock();
    }
  }
  async restoreLocalBackup(
    pick: () => Promise<string | null>,
    confirm: VaultFreshAuthentication,
    accepted: () => boolean,
  ): Promise<boolean> {
    const unavailable = () => Error('Encrypted vault restore is unavailable.');
    if (
      !accepted() ||
      this.selectedWorkspace ||
      this.creating ||
      this.enrollment ||
      this.sharedAuthenticating
    )
      throw unavailable();
    const client = this.get();
    const current = () =>
      this.client === client &&
      !this.stopping &&
      this.canStart() &&
      !this.selectedWorkspace &&
      accepted();
    this.creating = true;
    try {
      if (!(await this.startup()).newWorkspace || !current()) throw unavailable();
      const source = await pick();
      if (!current()) throw unavailable();
      if (!source) return false;
      const { slots, fingerprint } = await client.inspectLocalBackup(source);
      if (!current()) throw unavailable();
      const restored = await confirm('local-backup-install', slots, async (value) => {
        const input = consumeVaultUnlockInput(value);
        try {
          if (
            !current() ||
            input.kind !== 'recovery-code' ||
            input.vaultId !== slots.vaultId ||
            input.slotId !== slots.slots[0]?.id
          )
            throw unavailable();
          return await client.installLocalBackup(source, fingerprint, input.factor);
        } finally {
          input.factor.fill(0);
        }
      });
      if (!current()) throw unavailable();
      return restored;
    } finally {
      this.creating = false;
    }
  }
  async catalog(): Promise<VaultCatalog> {
    return this.get().catalog();
  }
  async workspace(): Promise<VaultWorkspace> {
    return this.get().workspace();
  }
  async editCredential(
    value: unknown,
    confirm?: VaultFreshAuthentication,
    accepted: () => boolean = () => true,
  ): Promise<VaultCredentialResult> {
    const input = consumeVaultCredentialInput(value);
    try {
      const client = this.client,
        workspace = this.unlockedWorkspaceId;
      if (!client || !workspace) throw Error('Vault is locked.');
      const result = await this.freshAction(
        client,
        workspace,
        'credential-edit',
        async (authentication) => {
          const attempt = {
            ...input,
            password: new Uint8Array(input.password),
            passphrase: new Uint8Array(input.passphrase),
          };
          try {
            return await client.editCredential(attempt, authentication);
          } finally {
            attempt.password.fill(0);
            attempt.passphrase.fill(0);
          }
        },
        confirm,
        accepted,
      );
      if (this.client !== client || this.unlockedWorkspaceId !== workspace)
        throw Error('Vault is locked.');
      return result;
    } finally {
      input.password.fill(0);
      input.passphrase.fill(0);
    }
  }
  async deleteCredential(
    value: unknown,
    confirm?: VaultFreshAuthentication,
    accepted: () => boolean = () => true,
  ): Promise<VaultCredentialDeleteResult> {
    const request = parseVaultCredentialSelection(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid vault credential deletion.');
    if (!client || !workspace) throw Error('Vault is locked.');
    const result = await this.freshAction(
      client,
      workspace,
      'credential-delete',
      (authentication) => client.deleteCredential(request, authentication),
      confirm,
      accepted,
    );
    if (this.client !== client || this.unlockedWorkspaceId !== workspace)
      throw Error('Vault is locked.');
    return result;
  }
  async saveConnection(
    value: unknown,
    confirm?: VaultFreshAuthentication,
    accepted: () => boolean = () => true,
  ): Promise<VaultFolderResult> {
    const input = consumeVaultConnectionInput(value);
    try {
      const client = this.client,
        workspace = this.unlockedWorkspaceId;
      if (!client || !workspace) throw new Error('Vault is locked.');
      const result = await this.freshAction(
        client,
        workspace,
        'connection-save',
        async (authentication) => {
          const attempt = {
            ...input,
            password: new Uint8Array(input.password),
            notes: new Uint8Array(input.notes),
          };
          try {
            return await client.saveConnection(attempt, authentication);
          } finally {
            attempt.password.fill(0);
            attempt.notes.fill(0);
          }
        },
        confirm,
        accepted,
      );
      if (this.client !== client || this.unlockedWorkspaceId !== workspace)
        throw new Error('Vault is locked.');
      return result;
    } finally {
      input.password.fill(0);
      input.notes.fill(0);
    }
  }
  async migrationReport(value: unknown): Promise<VaultMigrationReport> {
    const request = parseVaultMigrationSelection(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid migration request.');
    if (!client || !workspace) throw Error('Vault is locked.');
    const result = await client.migrationReport(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace)
      throw Error('Vault is locked.');
    return result;
  }
  async decideMigration(
    value: unknown,
    confirm?: VaultFreshAuthentication,
    accepted: () => boolean = () => true,
  ): Promise<VaultFolderResult> {
    const request = parseVaultMigrationDecision(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid migration request.');
    if (!client || !workspace) throw Error('Vault is locked.');
    const result = await this.freshAction(
      client,
      workspace,
      'migration-decide',
      (authentication) => client.decideMigration(request, authentication),
      confirm,
      accepted,
    );
    if (this.client !== client || this.unlockedWorkspaceId !== workspace)
      throw Error('Vault is locked.');
    return result;
  }
  // Main-owned tunnel editor only. No generic renderer IPC exposes these methods.
  async stageTunnelImport(
    value: unknown,
    accepted: () => boolean = () => true,
  ): Promise<VaultTunnelImportDisplay> {
    const request = parseTunnelImportRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid tunnel import request.');
    if (!client || !workspace || request.workspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    const result = await client.stageTunnelImport(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted()) {
      // A late stage must not survive the authority that requested it.
      if (this.client === client) await this.stop();
      throw Error('Vault is locked.');
    }
    return result;
  }
  async discardTunnelImport(value: unknown): Promise<{ discarded: true }> {
    const request = parseTunnelImportDiscard(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid tunnel import discard.');
    if (!client || !workspace || request.workspaceId !== workspace) throw Error('Vault is locked.');
    const result = await client.discardTunnelImport(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace)
      throw Error('Vault is locked.');
    return result;
  }
  async displayTunnelEditor(value: unknown): Promise<VaultTunnelEditorDisplay> {
    const request = parseVaultTunnelEditorRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid vault tunnel editor request.');
    if (!client || !workspace || request.workspaceId !== workspace) throw Error('Vault is locked.');
    const result = await client.displayTunnelEditor(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace)
      throw Error('Vault is locked.');
    return result;
  }
  async editTunnel(
    value: unknown,
    confirm?: VaultFreshAuthentication,
    accepted: () => boolean = () => true,
  ): Promise<VaultTunnelResult> {
    const input = consumeVaultTunnelInput(value);
    try {
      const client = this.client,
        workspace = this.unlockedWorkspaceId;
      if (!client || !workspace) throw Error('Vault is locked.');
      const result = await this.freshAction(
        client,
        workspace,
        'tunnel-edit',
        async (authentication) => {
          const attempt = { ...input, patch: new Uint8Array(input.patch) };
          try {
            return await client.editTunnel(attempt, authentication);
          } finally {
            attempt.patch.fill(0);
          }
        },
        confirm,
        accepted,
      );
      if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
        throw Error('Vault is locked.');
      return result;
    } finally {
      input.patch.fill(0);
    }
  }
  async deleteTunnel(
    value: unknown,
    confirm?: VaultFreshAuthentication,
    accepted: () => boolean = () => true,
  ): Promise<VaultTunnelDeleteResult> {
    const request = parseVaultTunnelSelection(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid vault tunnel deletion.');
    if (!client || !workspace) throw Error('Vault is locked.');
    const result = await this.freshAction(
      client,
      workspace,
      'tunnel-delete',
      (authentication) => client.deleteTunnel(request, authentication),
      confirm,
      accepted,
    );
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    return result;
  }
  async displayNotes(value: unknown): Promise<VaultNotesDisplay> {
    const request = parseVaultNotesRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw new Error('Invalid vault notes request.');
    if (!client || !workspace || request.workspaceId !== workspace)
      throw new Error('Vault is locked.');
    const result = await client.displayNotes(request);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace)
      throw new Error('Vault is locked.');
    return result;
  }
  // Main-only clipboard release; the application preload cannot choose a key.
  async releaseClipboard(
    value: unknown,
    confirm?: VaultFreshAuthentication,
    accepted: () => boolean = () => true,
  ): Promise<VaultNotesDisplay> {
    const request = parseClipboardReleaseRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid clipboard release request.');
    if (!client || !workspace || request.workspaceId !== workspace) throw Error('Vault is locked.');
    const result = await this.freshAction(
      client,
      workspace,
      'credential-copy',
      (authentication) => client.releaseClipboard(request, authentication),
      confirm,
      accepted,
    );
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    return result;
  }
  async copyCredential(
    value: unknown,
    confirm?: VaultFreshAuthentication,
    accepted: () => boolean = () => true,
  ): Promise<VaultClipboardResult> {
    const request = parseVaultClipboardRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid clipboard request.');
    if (!client || !workspace || request.workspaceId !== workspace) throw Error('Vault is locked.');
    const result = await this.freshAction(
      client,
      workspace,
      'credential-copy',
      (authentication) => client.copyCredential(request, authentication),
      confirm,
      accepted,
    );
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    return result;
  }
  async displayCredentials(
    value: unknown,
    confirm?: VaultFreshAuthentication,
    accepted: () => boolean = () => true,
  ): Promise<VaultNotesDisplay> {
    const request = parseVaultNotesRequest(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw Error('Invalid credential display request.');
    if (!client || !workspace || request.workspaceId !== workspace) throw Error('Vault is locked.');
    const result = await this.freshAction(
      client,
      workspace,
      'credential-display',
      (authentication) => client.displayCredentials(request, authentication),
      confirm,
      accepted,
    );
    if (this.client !== client || this.unlockedWorkspaceId !== workspace || !accepted())
      throw Error('Vault is locked.');
    return result;
  }

  async saveFolder(
    value: unknown,
    confirm?: VaultFreshAuthentication,
    accepted: () => boolean = () => true,
  ): Promise<VaultFolderResult> {
    const request = parseVaultFolder(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw new Error('Invalid vault folder request.');
    if (!client || !workspace) throw new Error('Vault is locked.');
    const result = await this.freshAction(
      client,
      workspace,
      'folder-save',
      (authentication) => client.saveFolder(request, authentication),
      confirm,
      accepted,
    );
    if (this.client !== client || this.unlockedWorkspaceId !== workspace)
      throw new Error('Vault is locked.');
    return result;
  }
  async deleteNodes(
    value: unknown,
    confirm?: VaultFreshAuthentication,
    accepted: () => boolean = () => true,
  ): Promise<VaultNodeDeleteResult> {
    const request = parseVaultNodeDelete(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw new Error('Invalid vault deletion request.');
    if (!client || !workspace) throw new Error('Vault is locked.');
    const result = await this.freshAction(
      client,
      workspace,
      'node-delete-trees',
      (authentication) => client.deleteNodes(request, authentication),
      confirm,
      accepted,
    );
    if (this.client !== client || this.unlockedWorkspaceId !== workspace)
      throw new Error('Vault is locked.');
    return result;
  }
  async moveNodes(
    value: unknown,
    confirm?: VaultFreshAuthentication,
    accepted: () => boolean = () => true,
  ): Promise<VaultNodeMoveResult> {
    const request = parseVaultNodeMove(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw new Error('Invalid vault move request.');
    if (!client || !workspace) throw new Error('Vault is locked.');
    const result = await this.freshAction(
      client,
      workspace,
      'node-move',
      (authentication) => client.moveNodes(request, authentication),
      confirm,
      accepted,
    );
    if (this.client !== client || this.unlockedWorkspaceId !== workspace)
      throw new Error('Vault is locked.');
    return result;
  }
  async duplicateConnection(
    value: unknown,
    confirm?: VaultFreshAuthentication,
    accepted: () => boolean = () => true,
  ): Promise<VaultNodeDuplicateResult> {
    const request = parseVaultNodeDuplicate(value),
      client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!request) throw new Error('Invalid vault duplicate request.');
    if (!client || !workspace) throw new Error('Vault is locked.');
    const result = await this.freshAction(
      client,
      workspace,
      'node-duplicate',
      (authentication) => client.duplicateConnection(request, authentication),
      confirm,
      accepted,
    );
    if (this.client !== client || this.unlockedWorkspaceId !== workspace)
      throw new Error('Vault is locked.');
    return result;
  }
  private async freshAction<T>(
    client: Client,
    workspace: string,
    operation: VaultFreshOperation,
    invoke: (authentication: VaultUnlockInput | undefined, security: VaultSecurity) => Promise<T>,
    confirm?: VaultFreshAuthentication,
    accepted: () => boolean = () => true,
  ): Promise<T> {
    const current = () =>
      this.client === client && this.unlockedWorkspaceId === workspace && accepted();
    const security = await client.security();
    if (!current()) throw Error('Vault is locked.');
    if (operation === 'tighten-local-profile') {
      if (!security.canTightenToStandard) throw Error('Standard protection is unavailable.');
    } else if (security.effective === 'default') return invoke(undefined, security);
    else if (security.effective !== 'standard') throw Error('Fresh authentication is required.');
    if (!confirm) throw Error('Fresh authentication is required.');
    const descriptor = await client.describe();
    if (!current() || !descriptor || descriptor.vaultId !== workspace)
      throw Error('Vault is locked.');
    return confirm(operation, descriptor, async (value) => {
      const input = consumeVaultUnlockInput(value);
      try {
        if (
          !current() ||
          input.vaultId !== workspace ||
          !descriptor.slots.some(
            (slot) =>
              slot.id === input.slotId &&
              slot.kind === (input.kind === 'password' ? 'password' : 'recovery'),
          )
        )
          throw Error('Vault is locked.');
        const result = await invoke(input, security);
        if (!current()) throw Error('Vault is locked.');
        return result;
      } finally {
        input.factor.fill(0);
      }
    });
  }
  async startup(): Promise<VaultStartupMetadata> {
    const client = this.get();
    const result = await client.startup();
    this.select(
      client,
      result.osMigration ?? result.upgrade ?? result.unprotected ?? result.slots,
      result.shared || result.sharedJoin ? 'shared' : 'local',
    );
    if (result.legacy && !this.legacyMigrationRequired) {
      this.legacyMigrationRequired = true;
      this.selected?.();
    }
    return result;
  }
  async openUnprotected(create: boolean): Promise<VaultUnlockResult> {
    let client: Client | undefined,
      reserved = false;
    try {
      if (
        this.creating ||
        this.enrollment ||
        this.sharedAuthenticating ||
        this.sharedAdmitted ||
        this.unlockedWorkspaceId ||
        this.isSharedWorkspace ||
        this.stopping ||
        !this.canStart() ||
        (create && this.selectedWorkspace)
      )
        throw Error('Vault opening unavailable.');
      this.creating = reserved = true;
      client = this.get();
      const before = await client.startup();
      if (
        this.client !== client ||
        this.stopping ||
        !this.canStart() ||
        (create
          ? !before.newWorkspace || before.slots || before.unprotected || before.upgrade
          : !before.unprotected)
      )
        throw Error('Vault opening unavailable.');
      const result = await client.openUnprotected(create);
      const startup = await client.startup();
      if (
        this.client !== client ||
        this.stopping ||
        !this.canStart() ||
        !startup.unprotected ||
        startup.unprotected.vaultId !== result.vaultId ||
        (!create && startup.unprotected.vaultId !== before.unprotected!.vaultId)
      )
        throw Error('Vault opening owner changed.');
      const protection = await client.protection();
      if (this.client !== client || this.stopping || !this.canStart() || protection.protected)
        throw Error('Vault opening owner changed.');
      await this.activateOwner(client, startup.unprotected.vaultId, result.lockedMemory);
      return result;
    } catch {
      if (client && this.client === client) await this.stop();
      throw Error('Vault opening unavailable.');
    } finally {
      if (reserved) this.creating = false;
    }
  }
  async resumeOSMigration(): Promise<VaultUnlockResult> {
    let client: Client | undefined,
      reserved = false;
    const workspace = this.selectedWorkspace;
    try {
      if (
        !workspace ||
        this.unlockedWorkspaceId ||
        this.isSharedWorkspace ||
        this.creating ||
        this.enrollment ||
        this.sharedAuthenticating ||
        this.sharedAdmitted ||
        this.stopping ||
        !this.canStart()
      )
        throw Error('Migration unavailable.');
      this.creating = reserved = true;
      client = this.get();
      const startup = await client.startup();
      if (
        this.client !== client ||
        this.stopping ||
        !this.canStart() ||
        startup.osMigration?.vaultId !== workspace
      )
        throw Error('Migration owner changed.');
      const result = await client.resumeOSMigration();
      if (
        this.client !== client ||
        this.stopping ||
        !this.canStart() ||
        this.selectedWorkspace !== workspace ||
        result.vaultId !== workspace
      )
        throw Error('Migration owner changed.');
      await this.activateOwner(client, workspace, result.lockedMemory);
      return result;
    } catch {
      if (client && this.client === client) await this.stop();
      throw Error('Migration unavailable.');
    } finally {
      if (reserved) this.creating = false;
    }
  }
  async protection(): Promise<{ protected: boolean }> {
    const client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!client || !workspace || this.isSharedWorkspace) throw Error('Vault is locked.');
    try {
      const result = await client.protection();
      if (this.client !== client || this.unlockedWorkspaceId !== workspace)
        throw Error('Vault owner changed.');
      return result;
    } catch {
      if (this.client === client) await this.stop();
      throw Error('Vault protection unavailable.');
    }
  }
  private select(
    client: Client,
    descriptor: Pick<VaultDescriptor, 'vaultId'> | null,
    kind: 'local' | 'shared' = 'local',
  ): void {
    if (this.client !== client || this.stopping || !this.canStart())
      throw new Error('Vault is stopping.');
    if (
      this.selectedWorkspace &&
      (this.selectedWorkspace !== descriptor?.vaultId || this.selectedKind !== kind)
    )
      throw new Error('Vault workspace identity changed.');
    if (descriptor) this.rememberWorkspace(descriptor.vaultId, kind);
    if (this.client !== client || this.stopping || !this.canStart())
      throw new Error('Vault is stopping.');
  }
  private rememberWorkspace(id: string, kind: 'local' | 'shared' = 'local'): void {
    if (this.selectedWorkspace) {
      if (this.selectedWorkspace !== id || this.selectedKind !== kind)
        throw Error('Vault workspace identity changed.');
      return;
    }
    this.selectedWorkspace = id;
    this.selectedKind = kind;
    this.selected?.();
  }
  async sftpRecoveryRecords(value: unknown): Promise<VaultRecoveryRecordsReply> {
    const client = this.client;
    const workspace = this.unlockedWorkspaceId;
    if (!client || !workspace) throw new Error('Vault is locked.');
    const result = await client.sftpRecoveryRecords(value, workspace);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace)
      throw new Error('Vault is locked.');
    return result;
  }
  async sftpRecoveryScopes(after = ''): Promise<VaultRecoveryScopes> {
    const client = this.client;
    const workspace = this.unlockedWorkspaceId;
    if (!client || !workspace) throw new Error('Vault is locked.');
    const result = await client.sftpRecoveryScopes(after);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace)
      throw new Error('Vault is locked.');
    return result;
  }
  async fileEditSettings(value?: unknown): Promise<VaultFileEditSettings> {
    const client = this.client;
    const workspace = this.unlockedWorkspaceId;
    if (!client || !workspace) throw new Error('Vault is locked.');
    const result = await client.fileEditSettings(value);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace)
      throw new Error('Vault is locked.');
    return result;
  }
  async preferences(): Promise<VaultPreferences> {
    const client = this.client;
    const workspace = this.unlockedWorkspaceId;
    if (!client || !workspace) throw new Error('Vault is locked.');
    const result = await client.preferences();
    if (this.client !== client || this.unlockedWorkspaceId !== workspace)
      throw new Error('Vault is locked.');
    return result;
  }
  async updatePreferences(value: VaultUpdatePreferences): Promise<void> {
    const client = this.client;
    const workspace = this.unlockedWorkspaceId;
    if (!client || !workspace) throw new Error('Vault is locked.');
    await client.updatePreferences(value);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace)
      throw new Error('Vault is locked.');
  }
  // Main-only authority; no renderer IPC endpoint is registered for this method.
  async security(): Promise<VaultSecurity> {
    const client = this.get();
    const result = await client.security();
    if (this.client !== client || this.stopping || !this.canStart())
      throw Error('Vault is stopping.');
    return result;
  }
  async unlock(value: unknown): Promise<VaultUnlockResult> {
    const input = consumeVaultUnlockInput(value);
    try {
      return await this.withLocalUnlock(input.vaultId, async (client) => {
        const result = await client.unlock(input);
        await this.activateOwner(client, input.vaultId, result.lockedMemory);
        return result;
      });
    } finally {
      input.factor.fill(0);
    }
  }

  private async withLocalUnlock<T>(
    workspace: string,
    unlock: (client: Client) => Promise<T>,
  ): Promise<T> {
    if (
      this.creating ||
      this.enrollment ||
      this.sharedAuthenticating ||
      this.sharedAdmitted ||
      this.isSharedWorkspace
    )
      throw Error('Vault enrollment is pending.');
    if (this.unlocking) throw Error('Vault unlock is already in progress.');
    if (this.selectedWorkspace && this.selectedWorkspace !== workspace)
      throw Error('Vault workspace identity changed.');
    const client = this.get();
    this.unlocking = true;
    try {
      return await unlock(client);
    } finally {
      this.unlocking = false;
    }
  }

  unlockPresence(
    kind: VaultPresenceKind,
    selection: VaultPresenceSelection,
    ownerWindow: string | undefined,
    accepted: () => boolean,
    signal: AbortSignal,
  ): Promise<VaultPresenceUnlockResult> {
    return this.withLocalUnlock(selection.vaultId, async (client) => {
      const current = () =>
        this.client === client &&
        !this.stopping &&
        this.canStart() &&
        this.selectedWorkspace === selection.vaultId &&
        !this.isSharedWorkspace &&
        !signal.aborted &&
        accepted();
      if (this.unlockedWorkspace || !current()) throw Error('Biometric unlock unavailable.');
      const descriptor = await client.describe();
      if (
        !current() ||
        descriptor?.vaultId !== selection.vaultId ||
        !descriptor.slots.some((slot) => slot.kind === kind && slot.id === selection.slotId)
      )
        throw Error('Biometric slot unavailable.');
      const cancel = () => {
        if (this.client === client) void this.stop().catch(() => undefined);
      };
      signal.addEventListener('abort', cancel, { once: true });
      try {
        const result = await client.unlockPresence(kind, selection, ownerWindow);
        if (!current()) throw Error('Vault request owner is no longer available.');
        if ('unlocked' in result)
          await this.activateOwner(client, selection.vaultId, result.lockedMemory, current);
        return result;
      } catch (error) {
        if (!current() && this.client === client) await this.stop();
        throw error;
      } finally {
        signal.removeEventListener('abort', cancel);
      }
    });
  }

  async presenceStatus(kind: VaultPresenceKind): Promise<VaultPresenceStatus | null> {
    const client = this.client;
    const workspace = this.unlockedWorkspaceId;
    if (!client || !workspace || this.isSharedWorkspace) return null;
    const protection = await client.protection();
    if (!protection.protected || this.client !== client || this.unlockedWorkspaceId !== workspace)
      return null;
    const descriptor = await client.describe();
    if (
      descriptor?.vaultId !== workspace ||
      this.client !== client ||
      this.unlockedWorkspaceId !== workspace
    )
      return null;
    const enrolled = descriptor.slots.some((slot) => slot.kind === kind);
    const availability = await client.presenceAvailability(kind);
    if (this.client !== client || this.unlockedWorkspaceId !== workspace) return null;
    return { enrolled, availability };
  }

  async configurePresence(
    kind: VaultPresenceKind,
    action: VaultPresenceAction,
    confirm: VaultPresenceAuthentication,
    accepted: () => boolean,
  ): Promise<VaultPresenceChange> {
    const client = this.client;
    const workspace = this.unlockedWorkspaceId;
    if (!client || !workspace || this.isSharedWorkspace || this.configuringPresence || !accepted())
      throw Error('Biometric settings unavailable.');
    const current = () =>
      this.client === client && this.unlockedWorkspaceId === workspace && accepted();
    this.configuringPresence = true;
    try {
      const protection = await client.protection();
      if (!current() || !protection.protected) throw Error('Protected local vault required.');
      const descriptor = await client.describe();
      if (!current() || descriptor?.vaultId !== workspace) throw Error('Vault is locked.');
      const slot = descriptor.slots.find((slot) => slot.kind === kind);
      if (action === 'enroll' && slot) throw Error('Biometric factor is already enrolled.');
      if (action === 'remove' && !slot) throw Error('Biometric slot unavailable.');
      return await confirm(`${kind}-${action}`, descriptor, async (value, ownerWindow) => {
        const input = consumeVaultUnlockInput(value);
        try {
          if (
            !current() ||
            input.vaultId !== workspace ||
            !descriptor.slots.some(
              ({ id, kind }) =>
                id === input.slotId &&
                kind === (input.kind === 'password' ? 'password' : 'recovery'),
            )
          )
            throw Error('Vault is locked.');
          const result = slot
            ? await client.removePresence(kind, slot.id, input)
            : await client.enrollPresence(kind, ownerWindow, input);
          if (!current()) throw Error('Vault is locked.');
          return result;
        } finally {
          input.factor.fill(0);
        }
      });
    } finally {
      this.configuringPresence = false;
    }
  }

  // Main-owned protected migration prompt only; no generic renderer endpoint.
  async resumeMigration(value: unknown): Promise<VaultUnlockResult> {
    return this.resumeMaintenance(value, 'migration');
  }
  async resumeRootRotation(value: unknown): Promise<VaultUnlockResult> {
    return this.resumeMaintenance(value, 'rotation');
  }
  private async resumeMaintenance(
    value: unknown,
    kind: 'migration' | 'rotation',
  ): Promise<VaultUnlockResult> {
    const input = consumeVaultUnlockInput(value);
    try {
      if (
        this.creating ||
        this.enrollment ||
        this.sharedAuthenticating ||
        this.sharedAdmitted ||
        this.isSharedWorkspace ||
        this.unlockedWorkspace
      )
        throw Error('Migration unavailable.');
      const client = this.get();
      const startup = await client.startup();
      if (
        this.client !== client ||
        this.stopping ||
        !this.canStart() ||
        !(kind === 'migration' ? startup.migration?.pending : startup.rotation?.pending) ||
        startup.slots?.vaultId !== input.vaultId
      )
        throw Error('Migration unavailable.');
      this.select(client, startup.slots);
      const result = await (kind === 'migration'
        ? client.resumeMigration(input)
        : client.resumeRootRotation(input));
      await this.activateOwner(client, input.vaultId, result.lockedMemory);
      return result;
    } finally {
      input.factor.fill(0);
    }
  }

  // Main-owned protected input only. Activate native verified policy before
  // publishing the shared workspace identity; parent IPC activates auth last.
  sharedUnlock(
    value: unknown,
    appVersion: string,
    accepted: () => boolean,
    tlsUpdatePath?: string,
  ): Promise<SharedVaultSessionAdmission> {
    return this.sharedAuthentication(value, appVersion, accepted, true, (client, input) =>
      client.sharedUnlock(input, appVersion, tlsUpdatePath),
    );
  }
  sharedRecoverPassword(
    value: unknown,
    appVersion: string,
    accepted: () => boolean,
  ): Promise<SharedVaultRecovery> {
    return this.sharedAuthentication(value, appVersion, accepted, false, (client, input) =>
      client.sharedRecoverPassword(input, appVersion),
    );
  }
  sharedRecoverEnrollment(
    value: unknown,
    appVersion: string,
    accepted: () => boolean,
  ): Promise<SharedVaultSessionAdmission> {
    return this.sharedAuthentication(
      value,
      appVersion,
      accepted,
      true,
      (client, input) => client.sharedRecoverEnrollment(input, appVersion),
      true,
    );
  }
  sharedContinueEnrollment(
    value: unknown,
    appVersion: string,
    accepted: () => boolean,
  ): Promise<SharedVaultSessionAdmission> {
    return this.sharedAuthentication(
      value,
      appVersion,
      accepted,
      true,
      (client, input) => client.sharedContinueEnrollment(input, appVersion),
      true,
      true,
    );
  }
  inspectSharedInvitation(invitation: string, accepted: () => boolean): Promise<SharedInvitation> {
    if (!validSharedInvitationText(invitation)) return Promise.reject(Error('Invalid invitation.'));
    return this.sharedInitialRead(accepted, (client) => client.inspectSharedInvitation(invitation));
  }
  async sharedSetup(input: SharedSetupNativeRequest, accepted: () => boolean) {
    try {
      if (
        !accepted() ||
        this.stopping ||
        !this.canStart() ||
        this.creating ||
        this.enrollment ||
        this.sharedAuthenticating ||
        this.sharedAdmitted
      )
        throw Error('Shared workspace setup is unavailable.');
      const client = this.get();
      const reply = await client.sharedSetup(input);
      if (this.client !== client || this.stopping || !this.canStart() || !accepted())
        throw Error('Shared workspace setup was interrupted.');
      return reply;
    } finally {
      wipeSharedSetupRequest(input);
    }
  }
  readSharedInvitationFile(path: string, accepted: () => boolean): Promise<SharedInvitation> {
    return this.sharedInitialRead(accepted, (client) => client.readSharedInvitationFile(path));
  }
  async inspectSharedRecoveryBackup(
    input: SharedRecoveryInspectionNative,
    accepted: () => boolean,
  ) {
    try {
      return await this.sharedInitialRead(
        accepted,
        (client) => client.inspectSharedRecoveryBackup(input),
        'Workspace restore is unavailable.',
      );
    } finally {
      input.password.fill(0);
    }
  }
  async restoreSharedRecoveryBackup(input: SharedRecoveryRestoreNative, accepted: () => boolean) {
    try {
      return await this.sharedInitialRead(
        accepted,
        (client) => client.restoreSharedRecoveryBackup(input),
        'Workspace restore is unavailable.',
      );
    } finally {
      input.password.fill(0);
      input.deployerPassword.fill(0);
    }
  }
  private async sharedInitialRead<T>(
    accepted: () => boolean,
    read: (client: Client) => Promise<T>,
    message = 'Invitation unavailable.',
  ): Promise<T> {
    if (
      this.creating ||
      this.enrollment ||
      this.sharedAuthenticating ||
      this.sharedAdmitted ||
      this.selectedWorkspace ||
      this.unlockedWorkspace ||
      !accepted()
    )
      throw Error(message);
    const client = this.get();
    const current = () => this.client === client && !this.stopping && this.canStart() && accepted();
    try {
      const startup = await client.startup();
      if (
        !current() ||
        !startup.newWorkspace ||
        startup.slots ||
        startup.shared ||
        startup.sharedJoin
      )
        throw Error(message);
      const result = await read(client);
      if (!current()) throw Error('Invitation owner changed.');
      return result;
    } catch {
      throw Error(message);
    }
  }
  async sharedJoinInitial(
    value: unknown,
    appVersion: string,
    accepted: () => boolean,
  ): Promise<SharedVaultSessionAdmission> {
    const input = consumeSharedInitialJoinInput(value, appVersion);
    try {
      return await this.admitSharedInitial(accepted, (client) =>
        client.sharedJoinInitial(input, appVersion),
      );
    } finally {
      input.code.fill(0);
      input.password.fill(0);
      input.ask?.fill(0);
    }
  }
  async sharedRedeemAccountReset(
    offerPath: string,
    value: unknown,
    appVersion: string,
    accepted: () => boolean,
  ): Promise<SharedVaultSessionAdmission> {
    const input = consumeSharedAccountResetInput(value, appVersion);
    try {
      return await this.admitSharedInitial(accepted, (client) =>
        client.sharedRedeemAccountReset(offerPath, input, appVersion),
      );
    } finally {
      for (const factor of [input.code, input.password, input.ask]) factor.fill(0);
    }
  }
  async sharedJoinAdministrator(
    input: Extract<SharedAdminSetupRequest, { action: 'admin-join' }>,
    appVersion: string,
    accepted: () => boolean,
  ): Promise<SharedSetupCompletion> {
    try {
      const local = this.unlockedWorkspace;
      if (local && !this.isSharedWorkspace) {
        if (
          !accepted() ||
          this.stopping ||
          !this.canStart() ||
          this.creating ||
          this.enrollment ||
          this.sharedAuthenticating ||
          this.sharedAdmitted ||
          this.selectedWorkspace !== local
        )
          throw Error('Shared workspace setup is unavailable.');
        this.sharedAuthenticating = true;
        try {
          const client = this.get();
          const result = await client.selectSharedWorkspace(input, appVersion);
          if (
            this.client !== client ||
            this.stopping ||
            !this.canStart() ||
            !accepted() ||
            this.unlockedWorkspace !== local
          )
            throw Error('Shared workspace setup was interrupted.');
          return result;
        } finally {
          this.sharedAuthenticating = false;
        }
      }
      return await this.admitSharedInitial(accepted, (client) =>
        client.sharedJoinAdministrator(input, appVersion),
      );
    } finally {
      wipeSharedSetupRequest(input);
    }
  }
  async sharedRecoverAdministrator(
    input: AdminRecoveryNativeInput,
    appVersion: string,
    accepted: () => boolean,
  ) {
    try {
      return await this.admitSharedInitial(
        accepted,
        (client) => client.sharedRecoverAdministrator(input, appVersion),
        true,
      );
    } finally {
      wipeAdminRecoveryInput(input);
    }
  }
  private async admitSharedInitial(
    accepted: () => boolean,
    join: (client: Client) => Promise<SharedVaultAdmission>,
    recovery = false,
  ): Promise<SharedVaultSessionAdmission> {
    let client: Client | undefined;
    let reserved = false;
    try {
      if (
        this.creating ||
        this.enrollment ||
        this.sharedAuthenticating ||
        this.sharedAdmitted ||
        (this.selectedWorkspace && !(recovery && this.selectedKind === 'shared')) ||
        this.unlockedWorkspace ||
        !accepted()
      )
        throw Error('Shared workspace invitation unavailable.');
      this.sharedAuthenticating = reserved = true;
      client = this.get();
      const current = () =>
        this.client === client && !this.stopping && this.canStart() && accepted();
      const before = await client.startup();
      const resuming =
        recovery &&
        before.sharedJoin?.adminRecovery === true &&
        (!this.selectedWorkspace || this.selectedWorkspace === before.slots?.vaultId);
      if (
        !current() ||
        (this.selectedWorkspace && !resuming) ||
        (!resuming && (!before.newWorkspace || before.slots || before.sharedJoin)) ||
        before.shared ||
        before.legacy ||
        before.osMigration ||
        before.migration ||
        before.rotation ||
        before.upgrade ||
        before.unprotected
      )
        throw Error('Shared workspace invitation unavailable.');
      const result = await join(client);
      if (!current()) throw Error('Shared workspace invitation owner changed.');
      const completed = await client.startup();
      if (
        !current() ||
        !completed.shared ||
        completed.sharedJoin ||
        !completed.slots ||
        completed.newWorkspace
      )
        throw Error('Shared workspace invitation was not confirmed.');
      this.select(client, completed.slots, 'shared');
      const runtime = parseSharedVaultRuntime(await client.sharedRuntime());
      if (
        !current() ||
        !runtime ||
        runtime.vaultId !== completed.slots.vaultId ||
        this.selectedWorkspace !== runtime.vaultId ||
        !this.isSharedWorkspace
      )
        throw Error('Shared workspace invitation owner changed.');
      this.activateNativePolicy(runtime.security, result.lockedMemory);
      if (!current()) throw Error('Shared workspace invitation owner changed.');
      this.unlockedWorkspace = runtime.workspaceId;
      this.sharedAdmitted = true;
      return {
        ...result,
        tls: runtime.tls,
        ...(runtime.recoveryBackup ? { recoveryBackup: true } : {}),
        ...(runtime.administrator ? { administrator: true } : {}),
      };
    } catch (error) {
      return await this.failSharedAuthentication(
        error,
        client,
        accepted,
        true,
        'Shared workspace invitation unavailable.',
      );
    } finally {
      if (reserved) this.sharedAuthenticating = false;
    }
  }
  async sharedConnectionContext(
    value: unknown,
    accepted: () => boolean,
  ): Promise<SharedConnectionContext> {
    const request = parseSharedConnectionContextRequest(value);
    if (!request) throw Error('Invalid shared connection context request.');
    return this.sharedRead(accepted, (client) => client.sharedConnectionContext(request));
  }
  async sharedCatalog(value: unknown, accepted: () => boolean): Promise<SharedCatalogPage> {
    const request = parseSharedCatalogRequest(value);
    if (!request) throw Error('Invalid shared catalog request.');
    return this.sharedRead(accepted, (client) => client.sharedCatalog(request));
  }
  async sharedNodeEdit(
    value: unknown,
    accepted: () => boolean,
    confirm: SharedActionConfirmation<true>,
  ): Promise<SharedNodeEditReply> {
    const request = parseSharedNodeEditRequest(value);
    const device = this.selectedWorkspace,
      workspace = this.unlockedWorkspaceId;
    if (
      !request ||
      !device ||
      !workspace ||
      ('workspaceId' in request && request.workspaceId !== workspace)
    )
      throw Error('Invalid shared node edit.');
    const owner = () =>
      accepted() && this.selectedWorkspace === device && this.unlockedWorkspaceId === workspace;
    return this.sharedRead<SharedNodeEditReply>(owner, async (client, current) => {
      const reply = await client.sharedNodeEdit(request);
      if (!current() || (reply.status === 'ready' && reply.workspaceId !== workspace))
        throw Error('Shared workspace changed.');
      if (reply.status !== 'authentication-required') return reply;
      const startup = await client.startup();
      if (!request.changes || !current() || !startup.shared || startup.slots?.vaultId !== device)
        throw Error('Shared node edit unavailable.');
      let result: SharedNodeEditReply = { status: 'unavailable' };
      const confirmed = await confirm(startup, current, async (input, trusted) => {
        try {
          if (
            !current() ||
            !trusted() ||
            input.vaultId !== device ||
            !startup.slots?.slots.some(
              (slot) => slot.kind === 'password' && slot.id === input.slotId,
            )
          )
            throw Error('Shared workspace changed.');
          result = await client.sharedNodeEdit(request, input);
          if (!current() || !trusted() || result.status !== 'saved')
            throw Error('Could not confirm the edit.');
          return true;
        } finally {
          input.password.fill(0);
          input.ask?.fill(0);
        }
      });
      return confirmed === true ? result : { status: 'unavailable' };
    });
  }
  async sharedChanges(value: unknown, accepted: () => boolean): Promise<SharedChanges> {
    const request = parseSharedChangesRequest(value);
    if (!request) throw Error('Invalid shared changes request.');
    return this.sharedRead(accepted, (client) => client.sharedChanges(request));
  }
  async renewSharedServerCertificate(
    value: unknown,
    accepted: () => boolean,
  ): Promise<SharedCertificateRenewalResult> {
    const request = parseSharedCertificateRenewalRequest(value);
    if (!request) throw Error('Invalid server CSR.');
    return this.sharedRead(accepted, (client) => client.renewSharedServerCertificate(request));
  }
  async sharedWorkspaceCA(
    value: unknown,
    accepted: () => boolean,
    lock: () => Promise<void> = () => this.stop(),
  ): Promise<SharedWorkspaceCAResult> {
    const request = parseSharedWorkspaceCARequest(value);
    if (!request) throw Error('Invalid workspace CA request.');
    return this.sharedRead(
      accepted,
      (client) => client.sharedWorkspaceCA(request),
      (result) => ('reconnect' in result && result.reconnect ? lock() : undefined),
    );
  }
  exportSharedTLSBundle(
    choose: () => Promise<string | null>,
    accepted: () => boolean,
  ): Promise<boolean | null> {
    return this.sharedRead(accepted, async (client, current) => {
      const path = await choose();
      if (!current()) throw Error('Shared workspace owner changed.');
      if (path === null) return null;
      if (!validSharedTLSBundlePath(path)) return false;
      return client.exportSharedTLSBundle(path);
    });
  }
  refreshSharedRecoveryKit(
    choose: (intent: 'open' | 'save') => Promise<string | null>,
    accepted: () => boolean,
    confirm?: SharedRecoveryKitConfirmation,
  ): Promise<SharedRecoveryKitRefresh | null> {
    return this.sharedRead(accepted, async (client, current) => {
      const source = await choose('open');
      if (!current()) throw Error('Shared workspace owner changed.');
      if (source === null) return null;
      if (!validSharedRecoveryKitPath(source)) return 'invalid-kit';
      const destination = await choose('save');
      if (!current()) throw Error('Shared workspace owner changed.');
      if (destination === null) return null;
      if (!validSharedRecoveryKitPath(destination) || destination === source) return 'save-failed';
      const result = await client.refreshSharedRecoveryKit(source, destination);
      if (result === 'invalid-authentication') throw Error('Unexpected recovery kit reply.');
      if (result !== 'authentication-required') return result;
      if (!confirm) return 'unavailable';
      const startup = await client.startup();
      if (!current() || !startup.shared || !startup.slots)
        throw Error('Shared workspace owner changed.');
      return confirm(startup, current, async (input, trusted) => {
        try {
          if (!current() || !trusted()) throw Error('Shared workspace owner changed.');
          const updated = await client.refreshSharedRecoveryKit(source, destination, input);
          if (
            !current() ||
            !trusted() ||
            updated === 'invalid-authentication' ||
            updated === 'authentication-required'
          )
            throw Error('Recovery kit authentication unavailable.');
          return updated;
        } finally {
          input.password.fill(0);
          input.ask?.fill(0);
        }
      });
    });
  }
  async tightenSharedProfile(
    confirm: SharedActionConfirmation<true>,
    accepted: () => boolean,
    lock: () => Promise<void>,
  ): Promise<void> {
    const client = this.client;
    const workspace = this.unlockedWorkspaceId;
    const device = this.selectedWorkspace;
    const current = () =>
      !!client &&
      this.client === client &&
      this.sharedAdmitted &&
      !this.sharedAuthenticating &&
      this.unlockedWorkspaceId === workspace &&
      this.selectedWorkspace === device &&
      !this.stopping &&
      this.canStart() &&
      accepted();
    if (!client || !workspace || !device || !current())
      throw Error('Shared profile change unavailable.');
    const runtime = await client.sharedRuntime();
    if (
      !current() ||
      runtime.vaultId !== device ||
      runtime.workspaceId !== workspace ||
      !runtime.security.canTightenToStandard ||
      runtime.tls !== 'verified'
    )
      throw Error('Standard protection unavailable.');
    const startup = await client.startup();
    if (!current() || !startup.shared || startup.slots?.vaultId !== device)
      throw Error('Shared profile change unavailable.');
    let committed = false;
    try {
      await confirm(startup, current, async (input, trusted) => {
        try {
          if (
            !current() ||
            !trusted() ||
            input.vaultId !== device ||
            !startup.slots?.slots.some(
              (slot) => slot.kind === 'password' && slot.id === input.slotId,
            )
          )
            throw Error('Shared profile change unavailable.');
          committed = await client.tightenSharedProfile(runtime.security.sequence, input);
          return true;
        } finally {
          input.password.fill(0);
          input.ask?.fill(0);
        }
      });
    } finally {
      if (
        committed &&
        this.client === client &&
        this.unlockedWorkspaceId === workspace &&
        this.selectedWorkspace === device
      )
        await lock();
    }
  }
  async openSharedAccountReset(
    accepted: () => boolean,
    open: (current: () => boolean, operation: SharedAccountResetIssueOperation) => Promise<void>,
  ): Promise<void> {
    const owner = await this.sharedRead(accepted, async (client, current) => {
      const runtime = await client.sharedRuntime();
      if (
        !runtime.recoveryBackup ||
        runtime.tls !== 'verified' ||
        runtime.vaultId !== this.selectedWorkspace ||
        runtime.workspaceId !== this.unlockedWorkspace
      )
        return;
      const startup = await client.startup();
      const slot = startup.slots?.slots.find(({ kind }) => kind === 'password');
      if (!startup.shared || startup.slots?.vaultId !== runtime.vaultId || !slot) return;
      const operation: SharedAccountResetIssueOperation = {
        workspaceId: runtime.workspaceId,
        targets: (after, trusted) =>
          this.sharedRead(
            () => current() && trusted(),
            (native) => native.sharedAccountResetTargets(after),
          ),
        mark: (handover, trusted) =>
          this.sharedRead(
            () => current() && trusted(),
            (native) => native.markSharedAccountResetHandover(handover),
          ),
        submit: (path, input, trusted) =>
          this.sharedRead(
            () => current() && trusted(),
            (native) =>
              this.issueAccountReset(native, path, input, runtime.workspaceId, {
                vaultId: runtime.vaultId,
                slotId: slot.id,
              }),
          ),
      };
      return { current, operation };
    });
    if (!owner?.current()) throw Error('Account reset is unavailable.');
    await open(owner.current, owner.operation);
  }

  private async issueAccountReset(
    client: Client,
    path: string,
    input: SharedAccountResetIssueInput,
    workspaceId: string,
    factors: { vaultId: string; slotId: string },
  ): Promise<SharedAccountResetIssueResult> {
    const result = await client.issueSharedAccountReset(path, input, factors);
    if (
      result.status === 'issued' &&
      (result.handover.workspaceId !== workspaceId || result.handover.requestId !== input.requestId)
    )
      throw Error('Account reset receipt does not match the request.');
    return result;
  }

  async openSharedAdministration(
    accepted: () => boolean,
    open: (current: () => boolean, ports: SharedAdministrationPorts) => Promise<void>,
  ): Promise<void> {
    const owner = await this.sharedRead(accepted, async (client, current) => {
      const runtime = await client.sharedRuntime();
      if (
        runtime.tls !== 'verified' ||
        runtime.vaultId !== this.selectedWorkspace ||
        runtime.workspaceId !== this.unlockedWorkspace
      )
        return;
      return {
        client,
        current,
        administrator: runtime.administrator === true,
        recoveryBackup: runtime.recoveryBackup === true,
        vaultId: runtime.vaultId,
        workspaceId: runtime.workspaceId,
      };
    });
    if (!owner?.current()) throw Error('Workspace administration is unavailable.');
    const current = () => this.client === owner.client;
    const read = <T>(operation: (client: Client) => Promise<T>) =>
      this.sharedRead(current, operation);
    const { administrator } = owner;
    await open(owner.current, {
      read: (request) =>
        administrator || request.kind === 'my-devices'
          ? read((client) => client.sharedAdminInventory(request))
          : Promise.resolve({ status: 'unavailable' }),
      createSlot: administrator
        ? (request) => read((client) => client.sharedCreateCredentialSlot(request))
        : undefined,
      groups: administrator
        ? (request) => read((client) => client.sharedAdminGroups(request))
        : undefined,
      nodeGrants: administrator
        ? {
            catalog: (request) => read((client) => client.sharedCatalog(request)),
            grant: (request) => read((client) => client.sharedAdminNodeGrant(request)),
            boundary: (request) => read((client) => client.sharedAdminGroupBoundaryGrant(request)),
            rotation: (request) =>
              read((client) => client.sharedAdminGroupBoundaryRotation(request)),
          }
        : undefined,
      groupKey: administrator
        ? (request) => read((client) => client.sharedAdminGroupKey(request))
        : undefined,
      memberRotation: administrator
        ? (request) => read((client) => client.sharedAdminGroupMemberRotation(request))
        : undefined,
      access: (request) =>
        administrator || request.action === 'revoke-device'
          ? read((client) => client.sharedWorkspaceAccess(request))
          : Promise.resolve({ status: 'unavailable' }),
      suspension: administrator
        ? (request) => read((client) => client.sharedAccountSuspension(request))
        : undefined,
      accountRotation: administrator
        ? (request) => read((client) => client.sharedAccountBoundaryRotation(request))
        : undefined,
      personalRecovery: administrator
        ? (request, factors, accepted) =>
            this.sharedRead(
              () => owner.current() && accepted(),
              async (client, current) => {
                if (!factors) return client.sharedPersonalRootRecovery(request);
                const startup = await client.startup();
                const descriptor = startup.slots;
                const slot = descriptor?.slots.find(({ kind }) => kind === 'password');
                if (
                  !current() ||
                  !startup.shared ||
                  !descriptor ||
                  descriptor.vaultId !== this.selectedWorkspace ||
                  !slot
                )
                  throw Error('Personal key recovery authentication is unavailable.');
                return client.sharedPersonalRootRecovery(request, {
                  vaultId: descriptor.vaultId,
                  slotId: slot.id,
                  ...factors,
                });
              },
            )
        : undefined,
      reenrollment:
        administrator && owner.recoveryBackup
          ? {
              workspaceId: owner.workspaceId,
              submit: (path, input, accepted) =>
                this.sharedRead(
                  () => owner.current() && accepted(),
                  async (client, current) => {
                    const startup = await client.startup();
                    const slot = startup.slots?.slots.find(({ kind }) => kind === 'password');
                    if (
                      !input.suspension ||
                      !input.targetUserId ||
                      !current() ||
                      !startup.shared ||
                      startup.slots?.vaultId !== owner.vaultId ||
                      !slot
                    )
                      throw Error('Account re-enrollment authentication is unavailable.');
                    return this.issueAccountReset(client, path, input, owner.workspaceId, {
                      vaultId: owner.vaultId,
                      slotId: slot.id,
                    });
                  },
                ),
            }
          : undefined,
      ownDevicesOnly: !administrator,
    });
  }
  async openSharedRecoveryBackup(
    accepted: () => boolean,
    open: (current: () => boolean, operation: SharedRecoveryBackupOperation) => Promise<void>,
  ): Promise<void> {
    const owner = await this.sharedRead(accepted, async (client, current) => {
      const runtime = await client.sharedRuntime();
      if (
        !runtime.recoveryBackup ||
        runtime.vaultId !== this.selectedWorkspace ||
        runtime.workspaceId !== this.unlockedWorkspace
      )
        return;
      const authenticationRequired = runtime.security.effective === 'standard';
      const startup = authenticationRequired ? await client.startup() : undefined;
      const slot = startup?.slots?.slots.find(({ kind }) => kind === 'password');
      if (
        authenticationRequired &&
        (!startup?.shared || startup.slots?.vaultId !== runtime.vaultId || !slot)
      )
        return;
      const operation: SharedRecoveryBackupOperation = {
        authenticationRequired,
        submit: (path, input, trusted) => {
          if (!validSharedRecoveryBackupPath(path))
            return Promise.resolve({ status: 'save-failed' });
          return this.sharedRead(
            () => current() && trusted(),
            async (native) => {
              const authentication =
                slot && input.password
                  ? {
                      vaultId: runtime.vaultId,
                      slotId: slot.id,
                      password: input.password,
                      ask: input.ask,
                    }
                  : undefined;
              const result = await native.exportSharedRecoveryBackup(
                path,
                input.recipient,
                authentication,
              );
              if (result.status === 'exported' && result.receipt.vaultId !== runtime.workspaceId)
                throw Error('Workspace backup receipt does not match the admitted workspace.');
              return result;
            },
          );
        },
      };
      return { current, operation };
    });
    if (!owner?.current()) throw Error('Workspace backup is unavailable.');
    await open(owner.current, owner.operation);
  }
  private async sharedRead<T>(
    accepted: () => boolean,
    read: (client: Client, current: () => boolean) => Promise<T>,
    retire?: (result: T) => Promise<void> | undefined,
  ): Promise<T> {
    const client = this.client;
    const current = () =>
      !!client &&
      this.client === client &&
      this.sharedAdmitted &&
      !this.sharedAuthenticating &&
      !this.stopping &&
      this.canStart() &&
      accepted();
    if (!current()) throw Error('Shared catalog unavailable.');
    try {
      const result = await read(client!, current);
      const deliver = current();
      // A committed trust change retires its owner even if the caller navigated.
      const retiring = this.client === client ? retire?.(result) : undefined;
      if (retiring) await retiring;
      if (!deliver || (retiring && !accepted())) throw Error('Shared catalog owner changed.');
      return result;
    } catch {
      if (client && this.client === client) await this.stop();
      throw Error('Shared catalog unavailable.');
    }
  }

  private sharedAuthentication(
    value: unknown,
    appVersion: string,
    accepted: () => boolean,
    admission: true,
    invoke: SharedAuthenticationInvoke<SharedVaultAdmission>,
    joining?: boolean,
    continuing?: boolean,
  ): Promise<SharedVaultSessionAdmission>;
  private sharedAuthentication(
    value: unknown,
    appVersion: string,
    accepted: () => boolean,
    admission: false,
    invoke: SharedAuthenticationInvoke<SharedVaultRecovery>,
    joining?: boolean,
    continuing?: boolean,
  ): Promise<SharedVaultRecovery>;
  private async sharedAuthentication(
    value: unknown,
    appVersion: string,
    accepted: () => boolean,
    admission: boolean,
    invoke: SharedAuthenticationInvoke<SharedVaultAdmission | SharedVaultRecovery>,
    joining = false,
    continuing = false,
  ): Promise<SharedVaultSessionAdmission | SharedVaultRecovery> {
    const input = continuing
      ? consumeSharedVaultContinuationInput(value, appVersion)
      : consumeSharedVaultUnlockInput(value, appVersion);
    let client: Client | undefined;
    let reserved = false;
    try {
      if (
        this.creating ||
        this.enrollment ||
        this.sharedAuthenticating ||
        this.sharedAdmitted ||
        this.unlockedWorkspace ||
        !accepted()
      )
        throw Error('Shared vault authentication unavailable.');
      this.sharedAuthenticating = reserved = true;
      client = this.get();
      const current = () =>
        this.client === client && !this.stopping && this.canStart() && accepted();
      const startup = await client.startup();
      if (
        !current() ||
        !(joining ? startup.sharedJoin : startup.shared) ||
        (continuing && startup.sharedJoin?.canContinue !== true) ||
        !startup.slots ||
        startup.slots.vaultId !== input.vaultId ||
        !startup.slots.slots.some((slot) => slot.id === input.slotId && slot.kind === 'password')
      )
        throw Error('Shared vault selection changed.');
      this.select(client, startup.slots, 'shared');
      if (!current()) throw Error('Shared vault authentication unavailable.');
      const result = await invoke(client, {
        vaultId: input.vaultId,
        slotId: input.slotId,
        password: input.password,
        ...(input.ask ? { ask: input.ask } : {}),
        ...(hasSharedVaultContinuation(input)
          ? { code: input.code, acknowledgeTLSOff: input.acknowledgeTLSOff }
          : {}),
      });
      if (!current()) throw Error('Shared vault authentication owner changed.');
      if (admission) {
        if (!('admitted' in result) || result.admitted !== true)
          throw Error('Invalid admission receipt.');
        const runtime = parseSharedVaultRuntime(await client.sharedRuntime());
        if (
          !current() ||
          !runtime ||
          runtime.vaultId !== input.vaultId ||
          this.selectedWorkspace !== runtime.vaultId ||
          !this.isSharedWorkspace
        )
          throw Error('Shared vault selection changed.');
        this.activateNativePolicy(runtime.security, result.lockedMemory);
        if (!current()) throw Error('Shared vault authentication owner changed.');
        this.unlockedWorkspace = runtime.workspaceId;
        this.sharedAdmitted = true;
        return {
          ...result,
          tls: runtime.tls,
          ...(runtime.recoveryBackup ? { recoveryBackup: true } : {}),
          ...(runtime.administrator ? { administrator: true } : {}),
        };
      }
      if (!('recovered' in result) || result.recovered !== true)
        throw Error('Invalid recovery receipt.');
      this.sharedAdmitted = false;
      return result;
    } catch (error) {
      return await this.failSharedAuthentication(
        error,
        client,
        accepted,
        joining,
        'Shared vault authentication unavailable.',
      );
    } finally {
      if (reserved) this.sharedAuthenticating = false;
      input.password.fill(0);
      input.ask?.fill(0);
      if (hasSharedVaultContinuation(input)) input.code.fill(0);
    }
  }

  private async failSharedAuthentication(
    error: unknown,
    client: Client | undefined,
    accepted: () => boolean,
    joining: boolean,
    message: string,
  ): Promise<never> {
    if (client && this.client === client) {
      const pending = joining && error instanceof SharedReenrollmentPending;
      const capacity = error instanceof SharedConnectionLimit;
      const current = (pending || capacity) && !this.stopping && this.canStart() && accepted();
      if (current && pending) throw error;
      await this.stop();
      if (current && capacity && accepted()) throw error;
    }
    throw Error(message);
  }

  // Only the main-owned recovery dialog can call these methods. No generic
  // renderer endpoints are registered by registerVaultIpc.
  async beginEnrollment(value: unknown): Promise<VaultEnrollment> {
    return this.beginEnrollmentRequest(consumeVaultEnrollmentBegin(value), false);
  }
  async migrationSetupContext(): Promise<VaultMigrationContext> {
    if (
      this.creating ||
      this.enrollment ||
      this.sharedAuthenticating ||
      this.sharedAdmitted ||
      this.selectedWorkspace
    )
      throw Error('Migration preparation unavailable.');
    const client = this.get();
    const result = await client.migrationSetupContext();
    if (this.client !== client || this.stopping || !this.canStart())
      throw Error('Migration preparation unavailable.');
    return result;
  }
  async beginMigrationSetup(value: unknown): Promise<VaultEnrollment> {
    return this.beginEnrollmentRequest(consumeVaultMigrationBegin(value), true);
  }
  async osMigrationContext(): Promise<VaultMigrationContext> {
    if (
      this.creating ||
      this.enrollment ||
      this.sharedAuthenticating ||
      this.sharedAdmitted ||
      this.selectedWorkspace
    )
      throw Error('Migration preparation unavailable.');
    const client = this.get();
    const result = await client.osMigrationContext();
    if (this.client !== client || this.stopping || !this.canStart() || this.selectedWorkspace)
      throw Error('Migration preparation unavailable.');
    return result;
  }
  async prepareOSMigration(value: unknown): Promise<VaultMigrationPrepared> {
    const input = consumeOSMigrationPrepare(value);
    let client: Client | undefined,
      reserved = false;
    try {
      if (
        this.creating ||
        this.enrollment ||
        this.sharedAuthenticating ||
        this.sharedAdmitted ||
        this.selectedWorkspace
      )
        throw Error('Migration preparation unavailable.');
      this.creating = reserved = true;
      client = this.get();
      const result = await client.prepareOSMigration(input);
      if (this.client !== client || this.stopping || !this.canStart() || this.selectedWorkspace)
        throw Error('Migration preparation unavailable.');
      this.rememberWorkspace(result.vaultId);
      return result;
    } catch {
      if (client && this.client === client) await this.stop();
      throw Error('Migration preparation unavailable.');
    } finally {
      if (reserved) this.creating = false;
      input.legacyFactor.fill(0);
    }
  }
  private async beginEnrollmentRequest(
    input: VaultEnrollmentBegin | VaultMigrationBegin,
    migration: boolean,
  ): Promise<VaultEnrollment> {
    let client: Client | undefined;
    let reserved = false;
    try {
      if (
        this.creating ||
        this.enrollment ||
        this.sharedAuthenticating ||
        this.sharedAdmitted ||
        this.selectedWorkspace
      )
        throw new Error('Vault enrollment unavailable.');
      this.creating = reserved = true;
      client = this.get();
      const result =
        'legacyFactor' in input
          ? await client.beginMigrationSetup(input)
          : await client.beginEnrollment(input);
      if (this.client !== client || this.stopping || !this.canStart())
        throw new Error('Vault is stopping.');
      this.enrollment = { client, value: result, migration };
      return result;
    } catch {
      if (client && this.client === client) await this.stop();
      throw new Error('Vault enrollment unavailable.');
    } finally {
      if (reserved) this.creating = false;
      input.password.fill(0);
      input.publicKey.fill(0);
      if ('legacyFactor' in input) input.legacyFactor.fill(0);
    }
  }
  async confirmEnrollment(value: unknown): Promise<VaultUnlockResult> {
    const input = consumeVaultEnrollmentConfirm(value);
    try {
      const pending = this.enrollment;
      if (
        !pending ||
        pending.migration ||
        pending.rotation ||
        pending.upgrade ||
        pending.client !== this.client ||
        input.enrollmentId !== pending.value.enrollmentId ||
        this.stopping ||
        !this.canStart()
      )
        throw new Error('Vault enrollment unavailable.');
      const result = await pending.client.confirmEnrollment(input);
      await this.activateOwner(pending.client, pending.value.vaultId, result.lockedMemory);
      this.enrollment = undefined;
      return result;
    } finally {
      input.groups.fill(0);
    }
  }
  async confirmMigrationSetup(value: unknown): Promise<VaultMigrationPrepared> {
    const input = consumeVaultEnrollmentConfirm(value);
    const pending = this.enrollment;
    let confirmed = false;
    try {
      if (
        !pending?.migration ||
        pending.client !== this.client ||
        input.enrollmentId !== pending.value.enrollmentId ||
        this.stopping ||
        !this.canStart()
      )
        throw Error('Migration preparation unavailable.');
      const result = await pending.client.confirmMigrationSetup(input);
      confirmed = true;
      if (
        this.client !== pending.client ||
        this.stopping ||
        !this.canStart() ||
        result.vaultId !== pending.value.vaultId
      )
        throw Error('Migration preparation unavailable.');
      this.enrollment = undefined;
      this.rememberWorkspace(result.vaultId);
      return result;
    } catch {
      // A rejected recovery group may be retried within the native attempt
      // budget. A committed response with changed ownership must retire.
      if (confirmed && pending && this.client === pending.client) await this.stop();
      throw Error('Migration preparation unavailable.');
    } finally {
      input.groups.fill(0);
    }
  }
  async rootRotationSetupContext(): Promise<VaultRootEnrollmentContext> {
    const client = this.client,
      workspace = this.unlockedWorkspaceId;
    if (!client || !workspace || this.isSharedWorkspace || this.creating || this.enrollment)
      throw Error('Vault protection unavailable.');
    const result = await client.rootRotationSetupContext();
    if (
      this.client !== client ||
      this.unlockedWorkspaceId !== workspace ||
      result.slots.vaultId !== workspace
    )
      throw Error('Vault protection owner changed.');
    return result;
  }
  async upgradeSetupContext(): Promise<VaultUpgradeContext> {
    if (
      !this.selectedWorkspace ||
      this.unlockedWorkspaceId ||
      this.isSharedWorkspace ||
      this.enrollment ||
      this.creating
    )
      throw Error('Vault upgrade unavailable.');
    const client = this.get(),
      workspace = this.selectedWorkspace;
    const context = await client.upgradeSetupContext();
    if (
      this.client !== client ||
      this.stopping ||
      !this.canStart() ||
      this.selectedWorkspace !== workspace ||
      this.unlockedWorkspaceId ||
      context.vaultId !== workspace
    )
      throw Error('Vault upgrade owner changed.');
    return context;
  }
  async beginUpgradeSetup(value: unknown): Promise<VaultEnrollment> {
    const input = consumeVaultEnrollmentBegin(value),
      client = this.client,
      workspace = this.selectedWorkspace;
    let reserved = false;
    try {
      if (
        !client ||
        !workspace ||
        this.unlockedWorkspaceId ||
        this.isSharedWorkspace ||
        this.creating ||
        this.enrollment ||
        this.sharedAuthenticating ||
        this.sharedAdmitted ||
        this.stopping ||
        !this.canStart()
      )
        throw Error('Vault upgrade unavailable.');
      this.creating = reserved = true;
      const result = await client.beginUpgradeSetup(input);
      if (
        this.client !== client ||
        this.stopping ||
        !this.canStart() ||
        this.selectedWorkspace !== workspace ||
        this.unlockedWorkspaceId ||
        result.vaultId !== workspace
      )
        throw Error('Vault upgrade owner changed.');
      this.enrollment = { client, value: result, migration: false, upgrade: true };
      return result;
    } catch {
      if (reserved && client && this.client === client) await this.stop();
      throw Error('Vault upgrade unavailable.');
    } finally {
      if (reserved) this.creating = false;
      input.password.fill(0);
      input.publicKey.fill(0);
    }
  }
  async beginRootRotationSetup(value: unknown, encryptDatabase = false): Promise<VaultEnrollment> {
    const input = consumeVaultRootEnrollmentBegin(value);
    const client = this.client,
      workspace = this.unlockedWorkspaceId;
    let reserved = false,
      began = false;
    try {
      if (
        !client ||
        !workspace ||
        this.isSharedWorkspace ||
        this.creating ||
        this.enrollment ||
        this.sharedAuthenticating ||
        this.sharedAdmitted ||
        input.authentication.vaultId !== workspace
      )
        throw Error('Vault protection unavailable.');
      this.creating = reserved = true;
      const result = await client.beginRootRotationSetup(input, encryptDatabase);
      began = true;
      if (
        this.client !== client ||
        this.unlockedWorkspaceId !== workspace ||
        result.vaultId !== workspace
      )
        throw Error('Vault protection owner changed.');
      this.enrollment = { client, value: result, migration: false, rotation: true };
      return result;
    } catch {
      if (reserved && client && workspace && this.client === client) {
        if (began) await this.stop();
        else await this.retainRotationSourceAfterRejection(client, workspace);
      }
      throw Error('Vault protection unavailable.');
    } finally {
      if (reserved) this.creating = false;
      input.password.fill(0);
      input.publicKey.fill(0);
      input.authentication.factor.fill(0);
    }
  }
  async confirmRootRotationSetup(value: unknown): Promise<VaultMigrationPrepared> {
    return this.confirmRootSetup(value, false);
  }
  async confirmUpgradeSetup(value: unknown): Promise<VaultMigrationPrepared> {
    return this.confirmRootSetup(value, true);
  }
  private async confirmRootSetup(
    value: unknown,
    upgrade: boolean,
  ): Promise<VaultMigrationPrepared> {
    const input = consumeVaultEnrollmentConfirm(value),
      pending = this.enrollment,
      workspace = upgrade ? this.selectedWorkspace : this.unlockedWorkspaceId;
    let attempted = false,
      confirmed = false,
      reserved = false;
    try {
      if (
        !pending ||
        !(upgrade ? pending.upgrade : pending.rotation) ||
        !workspace ||
        pending.client !== this.client ||
        input.enrollmentId !== pending.value.enrollmentId ||
        this.creating ||
        this.stopping ||
        !this.canStart()
      )
        throw Error('Vault protection unavailable.');
      this.creating = reserved = true;
      attempted = true;
      const result = await pending.client.confirmRootRotationSetup(input);
      confirmed = true;
      if (this.client === pending.client) this.unlockedWorkspace = undefined;
      if (
        this.client !== pending.client ||
        this.stopping ||
        !this.canStart() ||
        result.vaultId !== pending.value.vaultId
      )
        throw Error('Vault protection owner changed.');
      this.enrollment = undefined;
      return result;
    } catch {
      if (attempted && pending && workspace && this.client === pending.client) {
        if (confirmed) await this.stop();
        else await this.retainRotationSourceAfterRejection(pending.client, workspace, upgrade);
      }
      throw Error('Vault protection unavailable.');
    } finally {
      if (reserved) this.creating = false;
      input.groups.fill(0);
    }
  }
  async cancelRootRotationSetup(): Promise<true> {
    const pending = this.enrollment;
    if (!pending) return true;
    if (
      (!pending.rotation && !pending.upgrade) ||
      pending.client !== this.client ||
      this.stopping ||
      this.creating
    )
      throw Error('Vault protection unavailable.');
    this.creating = true;
    try {
      await pending.client.cancelRootRotationSetup();
      if (this.client !== pending.client || this.stopping)
        throw Error('Vault protection owner changed.');
      this.enrollment = undefined;
      return true;
    } catch {
      if (this.client === pending.client) await this.stop();
      throw Error('Vault protection owner changed.');
    } finally {
      this.creating = false;
    }
  }
  // Only a fresh native status can prove that a rejected group/factor left the
  // original owner alive. Uncertain commit/transport failures retire the process.
  private async retainRotationSourceAfterRejection(
    client: Client,
    workspace: string,
    upgrade = false,
  ): Promise<void> {
    try {
      const status = await client.status();
      if (
        this.client === client &&
        (upgrade
          ? this.selectedWorkspace === workspace &&
            !this.unlockedWorkspaceId &&
            !status.unlocked &&
            !this.stopping &&
            this.canStart()
          : this.unlockedWorkspaceId === workspace && status.unlocked)
      )
        return;
    } catch {
      /* Native process may already be retired. */
    }
    if (this.client === client) await this.stop();
  }
  private activateNativePolicy(security: VaultSecurity, lockedMemory: boolean): void {
    if (!lockedMemory && (security.effective === 'hardened' || security.effective === 'paranoid')) {
      throw new Error('The vault requires locked memory.');
    }
    this.activate?.(security);
  }

  private async activateOwner(
    client: Client,
    workspace: string,
    lockedMemory: boolean,
    accepted: () => boolean = () => true,
  ): Promise<void> {
    const current = () => this.client === client && !this.stopping && this.canStart() && accepted();
    try {
      const security = await client.security();
      if (!current()) throw new Error('Vault is stopping.');
      this.activateNativePolicy(security, lockedMemory);
      if (!current()) throw new Error('Vault is stopping.');
      this.rememberWorkspace(workspace);
      if (!current()) throw new Error('Vault is stopping.');
      this.unlockedWorkspace = workspace;
    } catch {
      if (this.client === client) await this.stop();
      throw new Error('Vault policy could not be activated.');
    }
  }

  private get(): Client {
    if (this.stopping || !this.canStart()) throw new Error('Vault is stopping.');
    this.client ??= this.createClient();
    return this.client;
  }

  stop(): Promise<void> {
    this.enrollment = undefined;
    this.unlockedWorkspace = undefined;
    this.sharedAdmitted = false;
    if (this.stopping) return this.stopping;
    const client = this.client;
    if (!client) return Promise.resolve();
    const stopping = client.lock().then(() => {
      if (this.client === client) this.client = undefined;
    });
    const tracked = stopping.finally(() => {
      if (this.stopping === tracked) this.stopping = undefined;
    });
    this.stopping = tracked;
    return tracked;
  }
}

export function isTrustedVaultDocument(
  documentURL: string,
  productionURL: string,
  developmentURL: string | undefined,
  packaged: boolean,
): boolean {
  try {
    const actual = new URL(documentURL);
    if (!packaged && developmentURL) {
      const development = new URL(developmentURL);
      return (
        ['http:', 'https:'].includes(development.protocol) &&
        ['localhost', '127.0.0.1', '[::1]'].includes(development.hostname) &&
        actual.origin === development.origin
      );
    }
    const production = new URL(productionURL);
    return (
      actual.protocol === 'file:' &&
      production.protocol === 'file:' &&
      actual.hostname === production.hostname &&
      actual.pathname === production.pathname
    );
  } catch {
    return false;
  }
}

// Recheck the sender after the asynchronous response: a window may navigate or
// close while Go is working. No generic request/payload forwarding is registered.
export function registerVaultIpc(
  ipc: Pick<IpcMain, 'handle'>,
  host: VaultBackendHost,
  trusted: (event: IpcMainInvokeEvent) => boolean,
  unlocked?: () => void,
  freshAuthentication?: (event: IpcMainInvokeEvent) => VaultFreshAuthentication,
  prepareCredential?: (
    event: IpcMainInvokeEvent,
    input: VaultCredentialRequest,
  ) => VaultCredentialInput,
  openRecoveryFolder?: (path: string) => Promise<string>,
): void {
  const accepts = (event: IpcMainInvokeEvent): boolean => {
    try {
      return trusted(event);
    } catch {
      // Native frame/window getters may throw after their owner is destroyed.
      return false;
    }
  };
  const register = (
    channel: string,
    read: () => Promise<
      VaultStatus | VaultDescriptor | VaultCatalog | VaultWorkspace | VaultStartupMetadata | null
    >,
  ) => {
    ipc.handle(channel, async (event, ...args: unknown[]) => {
      if (!accepts(event) || args.length !== 0) throw new Error('Invalid vault request.');
      const result = await read();
      if (!accepts(event)) throw new Error('Vault request owner is no longer available.');
      return result;
    });
  };
  register('vault:status', () => host.status());
  register('vault:describe', () => host.describe());
  register('vault:catalog', () => host.catalog());
  register('vault:workspace', () => host.workspace());
  register('vault:startup', () => host.startup());
  ipc.handle('vault:sftp-recovery-scopes', async (event, ...args: unknown[]) => {
    if (!accepts(event) || args.length !== 1 || typeof args[0] !== 'string')
      throw Error('Invalid vault request.');
    const result = await host.sftpRecoveryScopes(args[0]);
    if (!accepts(event)) throw Error('Vault request owner is no longer available.');
    return result;
  });
  ipc.handle('vault:sftp-recovery-records', async (event, ...args: unknown[]) => {
    if (!accepts(event) || args.length !== 1) throw Error('Invalid vault request.');
    const workspace = host.unlockedWorkspaceId;
    const { revealPath, edits, after, busy } = await host.sftpRecoveryRecords(args[0]);
    if (!accepts(event)) throw Error('Vault request owner is no longer available.');
    if (revealPath) {
      if (!workspace || workspace !== host.unlockedWorkspaceId || !openRecoveryFolder)
        throw Error('Recovery folder is unavailable.');
      try {
        if (await openRecoveryFolder(revealPath)) throw Error();
      } catch {
        throw Error('Recovery folder could not be opened.');
      }
      if (!accepts(event) || workspace !== host.unlockedWorkspaceId)
        throw Error('Vault request owner is no longer available.');
    }
    return { edits, after, busy };
  });
  ipc.handle('vault:edit-credential', async (event, ...args: unknown[]) => {
    const input = consumeVaultCredentialRequest(args[0]);
    try {
      if (!accepts(event) || args.length !== 1 || !prepareCredential)
        throw Error('Invalid vault request.');
      const result = await host.editCredential(
        prepareCredential(event, input),
        freshAuthentication?.(event),
        () => accepts(event),
      );
      if (!accepts(event)) throw Error('Vault request owner is no longer available.');
      return result;
    } finally {
      input.password.fill(0);
      input.passphrase.fill(0);
    }
  });
  ipc.handle('vault:delete-tunnel', async (event, ...args: unknown[]) => {
    if (!accepts(event) || args.length !== 1) throw Error('Invalid vault request.');
    const result = await host.deleteTunnel(args[0], freshAuthentication?.(event), () =>
      accepts(event),
    );
    if (!accepts(event)) throw Error('Vault request owner is no longer available.');
    return result;
  });
  ipc.handle('vault:delete-credential', async (event, ...args: unknown[]) => {
    if (!accepts(event) || args.length !== 1) throw Error('Invalid vault request.');
    const result = await host.deleteCredential(args[0], freshAuthentication?.(event), () =>
      accepts(event),
    );
    if (!accepts(event)) throw Error('Vault request owner is no longer available.');
    return result;
  });
  ipc.handle('vault:migration-report', async (event, ...args: unknown[]) => {
    if (!accepts(event) || args.length !== 1) throw Error('Invalid vault request.');
    const result = await host.migrationReport(args[0]);
    if (!accepts(event)) throw Error('Vault request owner is no longer available.');
    return result;
  });
  ipc.handle('vault:migration-decide', async (event, ...args: unknown[]) => {
    if (!accepts(event) || args.length !== 1) throw Error('Invalid vault request.');
    const result = await host.decideMigration(args[0], freshAuthentication?.(event), () =>
      accepts(event),
    );
    if (!accepts(event)) throw Error('Vault request owner is no longer available.');
    return result;
  });
  ipc.handle('vault:save-connection', async (event, ...args: unknown[]) => {
    const input = consumeVaultConnectionInput(args[0]);
    try {
      if (!accepts(event) || args.length !== 1) throw new Error('Invalid vault request.');
      const result = await host.saveConnection(input, freshAuthentication?.(event), () =>
        accepts(event),
      );
      if (!accepts(event)) throw new Error('Vault request owner is no longer available.');
      return result;
    } finally {
      input.password.fill(0);
      input.notes.fill(0);
    }
  });
  ipc.handle('vault:save-folder', async (event, ...args: unknown[]) => {
    if (!accepts(event) || args.length !== 1) throw new Error('Invalid vault request.');
    const result = await host.saveFolder(args[0], freshAuthentication?.(event), () =>
      accepts(event),
    );
    if (!accepts(event)) throw new Error('Vault request owner is no longer available.');
    return result;
  });
  ipc.handle('vault:delete-nodes', async (event, ...args: unknown[]) => {
    if (!accepts(event) || args.length !== 1) throw new Error('Invalid vault request.');
    const result = await host.deleteNodes(args[0], freshAuthentication?.(event), () =>
      accepts(event),
    );
    if (!accepts(event)) throw new Error('Vault request owner is no longer available.');
    return result;
  });
  ipc.handle('vault:move-nodes', async (event, ...args: unknown[]) => {
    if (!accepts(event) || args.length !== 1) throw new Error('Invalid vault request.');
    const result = await host.moveNodes(args[0], freshAuthentication?.(event), () =>
      accepts(event),
    );
    if (!accepts(event)) throw new Error('Vault request owner is no longer available.');
    return result;
  });
  ipc.handle('vault:duplicate-connection', async (event, ...args: unknown[]) => {
    if (!accepts(event) || args.length !== 1) throw new Error('Invalid vault request.');
    const result = await host.duplicateConnection(args[0], freshAuthentication?.(event), () =>
      accepts(event),
    );
    if (!accepts(event)) throw new Error('Vault request owner is no longer available.');
    return result;
  });
  ipc.handle('vault:unlock', async (event, ...args: unknown[]) => {
    const input = consumeVaultUnlockInput(args[0]);
    try {
      if (!accepts(event) || args.length !== 1) throw new Error('Invalid vault request.');
      const outcome = await host.unlock(input).then(
        (value) => ({ value }),
        (error) => ({ error }),
      );
      // A factor submitted by a destroyed/navigated window must not leave an
      // unlocked owner behind, including when the response races navigation.
      if (!accepts(event)) {
        await host.stop();
        throw new Error('Vault request owner is no longer available.');
      }
      if ('error' in outcome) throw outcome.error;
      try {
        if (host.unlockedWorkspaceId !== input.vaultId) throw new Error('Vault is locked.');
        unlocked?.();
      } catch {
        await host.stop();
        throw new Error('Vault session could not be activated.');
      }
      return outcome.value;
    } finally {
      input.factor.fill(0);
    }
  });
}
