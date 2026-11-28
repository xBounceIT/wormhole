package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/secretclipboard"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// The transport serves metadata before authentication and typed-factor unlock
// for app startup. Native initialization UX and legacy cutover remain incomplete.
// Reporting protection here would incorrectly describe legacy DPAPI/keychain
// workspaces as password-encrypted vaults.
type vaultFoundationHandler struct {
	databasePath              string
	sharedSelection           *sharedWorkspaceSelection // immutable native launch selection
	sharedDestination         *sharedSetupDestination   // separate owner until cutover cleanup is confirmed
	setupImport               *sharedSetupImportReview
	userDataPath              string
	owner                     *localvault.Owner
	helloOperation            platformHelloOperation             // native test seam
	helloRemove               func(context.Context, string) bool // native test seam
	touchID                   touchIDProvider                    // native test seam
	bitwardenCLIUnlock        *vaultBitwardenCLIUnlock
	enrollment                *vaultEnrollment
	rotationMaterial          io.Closer // native cleanup obligation; never wire authority
	migrationQuiesced         bool      // native launch authority; never a wire field
	closed                    bool
	reauthenticationFailures  int
	releaseWorkspace          func()
	clipboard                 *secretclipboard.Manager
	memberClipboard           *invitationClipboard // encrypted, scoped to this vault process
	shared                    *vaultSharedSession
	sharedFactory             func() *sharedAdmissionController       // native test seam
	sharedInvitationFactory   func() sharedInitialInvitationSession   // native test seam
	sharedContinuationFactory func() sharedInitialContinuationSession // native test seam
	sharedProtection          *sharedStartupProtection                // native test seam
	catalogEvents             chan struct{}                           // immutable, bounded; configured before Serve
	stopService               context.CancelFunc                      // configured before Serve
}

func (h *vaultFoundationHandler) SharedCatalogEvents() <-chan struct{} { return h.catalogEvents }

func (h *vaultFoundationHandler) notifySharedCatalog() {
	select {
	case h.catalogEvents <- struct{}{}:
	default:
	}
}

func (h *vaultFoundationHandler) Handle(ctx context.Context, operation string, payload json.RawMessage) (json.RawMessage, error) {
	result, err := h.handle(ctx, operation, payload, false)
	if errors.Is(err, sharedpg.ErrConnectionLimit) {
		// Preserve cancellation and native retirement if cleanup also failed.
		err = errors.Join(err, vaultwire.ErrWorkspaceConnectionLimit)
	}
	return result, err
}

func (h *vaultFoundationHandler) handle(ctx context.Context, operation string, payload json.RawMessage, fresh bool) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if h.closed {
		return nil, vaultwire.ErrProtocol
	}
	if h.enrollment != nil && h.enrollment.rotationSource != nil && operation != "rotation-setup-confirm" && operation != "rotation-setup-cancel" && operation != "status" && operation != "security" {
		return nil, vault.ErrPolicy
	}
	if operation == "shared-unlock" || operation == "shared-recover-password" || operation == "shared-recover-enrollment" || operation == "shared-continue-enrollment" {
		return h.openShared(ctx, operation, payload)
	}
	if operation == "shared-join-initial" {
		return h.joinSharedInitial(ctx, payload)
	}
	if operation == "shared-account-reset-redeem" {
		return h.redeemSharedAccountReset(ctx, payload)
	}
	if operation == "shared-admin-recover" {
		return h.recoverSharedAdministrator(ctx, payload)
	}
	if operation == "shared-recovery-inspect" {
		return h.inspectSharedRecoveryBackup(ctx, payload)
	}
	if operation == "shared-recovery-restore" {
		return h.restoreSharedRecoveryBackup(ctx, payload)
	}
	if operation == "shared-invitation-inspect" || operation == "shared-invitation-file" {
		return h.inspectSharedInvitation(ctx, operation == "shared-invitation-file", payload)
	}
	switch operation {
	case "shared-setup-plan", "shared-setup-prepare", "shared-setup-prepare-tls", "shared-setup-prepare-generated-tls", "shared-setup-save-server-kit", "shared-setup-delete-server-key", "shared-setup-discard", "shared-setup-export", "shared-setup-export-hba", "shared-setup-preflight", "shared-setup-check", "shared-setup-run":
		return h.sharedSetup(ctx, operation, payload)
	case "shared-setup-admin-prepare", "shared-setup-admin-open", "shared-setup-admin-recovery", "shared-setup-admin-confirm", "shared-setup-admin-publish", "shared-setup-admin-join",
		"shared-setup-admin-import-start", "shared-setup-import-review":
		return h.sharedSetup(ctx, operation, payload)
	}
	if operation == "shared-catalog" {
		return h.sharedCatalog(ctx, payload)
	}
	if operation == "shared-changes" {
		return h.sharedChanges(ctx, payload)
	}
	if h.shared != nil {
		switch operation {
		case "tunnel-fallback-plan", "tunnel-fallback-bundle":
			return h.tunnelFallback(ctx, operation, payload)
		case "vpn-sso-begin", "vpn-sso-take", "vpn-sso-restore-ack", "vpn-sso-push", "vpn-sso-commit", "vpn-sso-cancel":
			return h.vpnSSO(ctx, operation, payload)
		case "shared-connection-context":
			return h.sharedConnectionContext(ctx, payload)
		case "shared-runtime":
			return h.sharedRuntime(ctx, payload)
		case "shared-admin-inventory":
			return h.sharedAdminInventory(ctx, payload)
		case "shared-create-credential-slot":
			return h.sharedCreateCredentialSlot(ctx, payload)
		case "shared-slot-default", "shared-personal-slot":
			return h.sharedSlotChange(ctx, payload, operation == "shared-personal-slot")
		case "shared-node-credential":
			return h.sharedNodeCredential(ctx, payload)
		case "shared-workspace-access":
			return h.sharedWorkspaceAccess(ctx, payload)
		case "shared-account-suspension":
			return h.sharedAccountSuspension(ctx, payload)
		case "shared-account-boundary-rotation":
			return h.sharedAccountBoundaryRotation(ctx, payload)
		case "shared-personal-root-recovery":
			return h.sharedPersonalRootRecovery(ctx, payload)
		case "shared-admin-groups":
			return h.sharedAdminGroups(ctx, payload)
		case "shared-admin-node-grant":
			return h.sharedAdminNodeGrant(ctx, payload)
		case "shared-node-edit":
			return h.sharedNodeEdit(ctx, payload)
		case "shared-admin-group-key":
			return h.sharedGroupKey(ctx, payload)
		case "shared-admin-group-boundary-grant":
			return h.sharedGroupBoundaryChange(ctx, payload, false)
		case "shared-admin-group-boundary-rotation":
			return h.sharedGroupBoundaryChange(ctx, payload, true)
		case "shared-admin-group-member-rotation":
			return h.sharedGroupMemberRotation(ctx, payload)
		case "notes-display":
			return h.displayNotes(ctx, payload)
		case "shared-renew-server-certificate":
			return h.sharedRenewServerCertificate(ctx, payload)
		case "shared-ca-status", "shared-ca-rotate", "shared-ca-retire":
			return h.sharedWorkspaceCA(ctx, operation, payload)
		case "shared-tls-export":
			return h.exportSharedTLSBundle(ctx, payload)
		case "shared-recovery-kit-refresh":
			return h.refreshSharedRecoveryKit(ctx, payload)
		case "shared-recovery-export":
			return h.exportSharedRecoveryBackup(ctx, payload)
		case "shared-account-reset-issue":
			return h.issueSharedAccountReset(ctx, payload)
		case "shared-member-invitation":
			return h.issueMemberInvitation(ctx, payload)
		case "shared-member-code-copy":
			return h.copyMemberInvitationCode(ctx, payload)
		case "shared-member-invitation-dismiss":
			return h.dismissMemberInvitation(payload)
		case "shared-account-reset-targets", "shared-account-reset-mark-handover":
			return h.sharedAccountResetQueue(ctx, operation, payload)
		case "security":
			return h.security(ctx, payload)
		case "shared-tighten-profile":
			return h.tightenSharedProfile(ctx, payload)
		case "preferences":
			return h.preferences(ctx, payload)
		case "update-preferences":
			return h.updatePreferences(ctx, payload)
		case "file-edit-settings":
			return h.fileEditSettings(ctx, payload)
		case "web-plan":
			return h.webPlan(ctx, payload, true)
		case "web-session-read", "web-session-save", "web-session-forget":
			return h.webSessionState(ctx, operation, payload)
		case "web-session-verify-views":
			return h.verifyWebSessionViews(ctx, payload)
		case "connection-route":
			return h.connectionRoute(ctx, payload)
		case "tunnel-plan":
			return h.tunnelPlan(ctx, payload)
		case "tunnel-bundle":
			return h.tunnelBundle(ctx, payload)
		case "ssh-route-bundle":
			return h.sshRouteBundle(ctx, payload)
		case "ssh-host-plan":
			return h.sshHost(ctx, operation, payload)
		case "shared-ssh-host-trust":
			return h.sharedSSHHostTrust(ctx, payload)
		case "vnc-plan", "vnc-manual-bundle", "vnc-manual-route-bundle":
			return h.vncManual(ctx, operation, payload)
		case "rdp-plan", "rdp-manual-bundle", "rdp-manual-route-bundle":
			return h.rdpManual(ctx, operation, payload)
		case "rdp-bundle", "rdp-route-bundle":
			return h.rdpBundle(ctx, operation, payload)
		case "vnc-bundle", "vnc-route-bundle":
			return h.vncBundle(ctx, operation, payload)
		case "ssh-bundle":
			return h.sshBundle(ctx, payload)
		case "serial-bundle":
			return h.serialBundle(ctx, payload)
		case "serial-use-check":
			return h.checkSerialUse(ctx, payload)
		}
	}
	if h.shared != nil && operation != "status" && operation != "startup" && operation != "describe" {
		return nil, vaultwire.ErrProtocol
	}
	if operation == "fresh-action" {
		return h.freshAction(ctx, payload)
	}
	if operation == "initialize" || operation == "unlock" {
		return h.open(ctx, operation, payload)
	}
	switch operation {
	case "hello-availability":
		if len(payload) == 0 && h.owner != nil {
			policy, err := h.owner.ReadLocalPolicy(ctx)
			if err != nil {
				return nil, err
			}
			if policy.Policy.ASKRequired {
				return helloReply(nil, errVaultHelloUnavailable)
			}
		}
		return vaultHelloAvailability(ctx, payload)
	case "hello-unlock":
		return helloReply(h.openWithHello(ctx, payload))
	case "hello-enroll":
		return helloReply(h.enrollVaultHello(ctx, payload, fresh))
	case "hello-remove":
		return h.removeVaultHello(ctx, payload, fresh)
	case "touch-id-availability":
		return touchIDReply(h.vaultTouchIDAvailability(ctx, payload))
	case "touch-id-unlock":
		return touchIDReply(h.openWithTouchID(ctx, payload))
	case "touch-id-enroll":
		return touchIDReply(h.enrollVaultTouchID(ctx, payload, fresh))
	case "touch-id-remove":
		return h.removeVaultPlatformSlot(ctx, payload, fresh, vault.SlotTouchID, h.deleteVaultTouchID)
	case "unprotected-create", "unprotected-open":
		return h.openUnprotected(ctx, operation == "unprotected-create", payload)
	case "protection":
		return h.protection(ctx, payload)
	case "vpn-sso-begin", "vpn-sso-take", "vpn-sso-restore-ack", "vpn-sso-push", "vpn-sso-commit", "vpn-sso-cancel":
		return h.vpnSSO(ctx, operation, payload)
	case "tunnel-fallback-plan", "tunnel-fallback-bundle":
		return h.tunnelFallback(ctx, operation, payload)
	case "migration-setup-context":
		return h.migrationSetupContext(ctx, payload)
	case "migration-os-context":
		if err := h.requireOSMigration(ctx); err != nil {
			return nil, err
		}
		return h.migrationSetupContext(ctx, payload)
	case "migration-os-prepare":
		return h.prepareOSMigration(ctx, payload)
	case "migration-os-resume":
		return h.resumeOSMigration(ctx, payload)
	case "migration-setup-begin":
		return h.beginMigrationEnrollment(ctx, payload)
	case "migration-setup-confirm":
		return h.confirmMigrationEnrollment(ctx, payload)
	case "migration-resume":
		return h.resumeMigration(ctx, payload)
	case "rotation-resume":
		return h.resumeRootRotation(ctx, payload)
	case "rotation-setup-context":
		return h.rootRotationSetupContext(ctx, payload)
	case "rotation-upgrade-context":
		return h.unprotectedUpgradeSetupContext(ctx, payload)
	case "rotation-upgrade-begin":
		return h.beginUnprotectedUpgradeEnrollment(ctx, payload)
	case "rotation-setup-begin":
		return h.beginRootRotationEnrollment(ctx, payload)
	case "rotation-encryption-begin":
		return h.beginRootRotationEnrollmentMode(ctx, payload, true)
	case "rotation-setup-confirm":
		return h.confirmRootRotationEnrollment(ctx, payload)
	case "rotation-setup-cancel":
		return h.cancelRootRotationEnrollment(payload)
	case "enrollment-begin":
		return h.beginEnrollment(ctx, payload)
	case "enrollment-confirm":
		return h.confirmEnrollment(ctx, payload)
	case "enrollment-cancel":
		return h.cancelEnrollment(payload)
	}
	if h.owner != nil && operation != "startup" && operation != "describe" && operation != "status" && operation != "security" {
		profile, err := h.owner.ReadSecurityProfile(ctx)
		if err != nil {
			return h.rejectLocalPolicy(ctx, err)
		}
		if profile.Effective != vault.Default && vaultFreshAction(operation) && !fresh {
			return nil, vault.ErrPolicy
		}
		switch operation {
		case "web-plan":
			return h.webPlan(ctx, payload, webSessionPersistenceAllowed(profile.Effective))
		case "web-session-read", "web-session-save", "web-session-forget":
			if !webSessionPersistenceAllowed(profile.Effective) {
				return nil, vault.ErrPolicy
			}
		}
	}
	switch operation {
	case "local-backup-export":
		return h.exportLocalBackup(ctx, payload)
	case "local-backup-inspect":
		return h.inspectLocalBackup(payload)
	case "local-backup-restore":
		return h.restoreLocalBackup(ctx, payload, false)
	case "local-backup-install":
		return h.restoreLocalBackup(ctx, payload, true)
	case "migration-report", "migration-decide":
		return h.migrationChoices(ctx, operation, payload)
	case "credential-clipboard-release":
		return h.releaseClipboard(ctx, payload)
	case "credential-copy":
		return h.copyCredential(ctx, payload)
	case "credential-display":
		return h.displayCredentials(ctx, payload)
	case "notes-display":
		return h.displayNotes(ctx, payload)
	case "tunnel-editor-display":
		return h.displayTunnelEditor(ctx, payload)
	case "tunnel-import-stage":
		return h.stageTunnelImport(ctx, payload)
	case "tunnel-import-discard":
		return h.discardTunnelImport(payload)
	case "tunnel-edit":
		return h.editTunnel(ctx, payload)
	case "credential-edit":
		return h.editCredential(ctx, payload)
	case "connection-save":
		return h.saveConnection(ctx, payload)
	case "folder-save":
		return h.saveFolder(ctx, payload)
	case "node-duplicate":
		return h.duplicateConnection(ctx, payload)
	case "node-move":
		return h.moveNodes(ctx, payload)
	case "node-delete-trees":
		return h.deleteNodeTrees(ctx, payload)
	case "quick-target-register", "quick-target-release":
		return h.quickTarget(ctx, operation, payload)
	case "ssh-host-plan", "ssh-host-trust", "ssh-quick-host-trust":
		return h.sshHost(ctx, operation, payload)
	case "bitwarden-transfer-begin", "bitwarden-transfer-push", "bitwarden-transfer-commit", "bitwarden-transfer-take", "bitwarden-transfer-cancel", "bitwarden-profile-close":
		return h.bitwardenTransfer(ctx, operation, payload)
	case "bitwarden-cleanup":
		return h.cleanupBitwardenInstallations(ctx, payload)
	case "bitwarden-install-zip":
		return h.installBitwardenZip(ctx, payload)
	case "bitwarden-install-folder":
		return h.installBitwardenFolder(ctx, payload)
	case "bitwarden-installation-revision":
		return h.bitwardenInstallationRevision(ctx, payload)
	case "bitwarden-installation-plan":
		return h.bitwardenInstallationPlan(ctx, payload)
	case "web-plan":
		return nil, vaultwire.ErrProtocol
	case "web-session-read", "web-session-save", "web-session-forget":
		return h.webSessionState(ctx, operation, payload)
	case "connection-route":
		return h.connectionRoute(ctx, payload)
	case "ssh-route-bundle":
		return h.sshRouteBundle(ctx, payload)
	case "ssh-bitwarden-prepare":
		return h.prepareConnectionBitwarden(ctx, "ssh", payload)
	case "vnc-bitwarden-prepare":
		return h.prepareConnectionBitwarden(ctx, "vnc", payload)
	case "rdp-bitwarden-prepare":
		return h.prepareConnectionBitwarden(ctx, "rdp", payload)
	case "bitwarden-cli-unlock-begin", "bitwarden-cli-unlock-commit", "bitwarden-cli-unlock-cancel":
		return h.bitwardenCLIUnlockOperation(ctx, operation, payload)
	case "ssh-manual-plan", "ssh-manual-bundle":
		return h.sshManual(ctx, operation, payload)
	case "tunnel-plan":
		return h.tunnelPlan(ctx, payload)
	case "tunnel-bundle":
		return h.tunnelBundle(ctx, payload)
	case "vnc-plan", "vnc-manual-bundle", "vnc-manual-route-bundle":
		return h.vncManual(ctx, operation, payload)
	case "rdp-plan", "rdp-manual-bundle", "rdp-manual-route-bundle", "rdp-manual-bitwarden-prepare":
		return h.rdpManual(ctx, operation, payload)
	case "rdp-bundle", "rdp-route-bundle":
		return h.rdpBundle(ctx, operation, payload)
	case "vnc-bundle", "vnc-route-bundle":
		return h.vncBundle(ctx, operation, payload)
	case "ssh-bundle":
		return h.sshBundle(ctx, payload)
	case "serial-bundle":
		return h.serialBundle(ctx, payload)
	case "sftp-recovery-records":
		return h.recoveryRecords(ctx, payload)
	case "sftp-recovery-scopes":
		return h.recoveryScopes(ctx, payload)
	case "file-edit-settings":
		return h.fileEditSettings(ctx, payload)
	case "preferences":
		return h.preferences(ctx, payload)
	case "update-preferences":
		return h.updatePreferences(ctx, payload)
	case "security":
		return h.security(ctx, payload)
	case "startup":
		return h.startup(ctx, payload)
	case "workspace":
		return h.workspace(ctx, payload)
	case "catalog":
		return h.catalog(ctx, payload)
	case "credential-list", "credential-read", "credential-save", "credential-delete":
		return h.credential(ctx, operation, payload)
	case "tunnel-list", "tunnel-read", "tunnel-save", "tunnel-delete":
		return h.tunnel(ctx, operation, payload)
	case "node-list", "node-read", "node-save", "node-delete", "node-delete-tree":
		return h.node(ctx, operation, payload)
	}
	if len(payload) != 0 {
		return nil, vaultwire.ErrProtocol
	}
	if operation == "describe" {
		if h.databasePath == "" {
			return nil, vaultwire.ErrProtocol
		}
		descriptor, shared, err := h.describeSharedStartup(ctx)
		if err != nil {
			return nil, err
		}
		if shared == nil {
			descriptor, err = describeVaultSlots(h.databasePath)
			if err != nil {
				return nil, err
			}
		}
		return json.Marshal(struct {
			Slots *vault.SlotFileDescriptor `json:"slots"`
		}{descriptor})
	}
	if operation != "status" {
		return nil, vaultwire.ErrProtocol
	}
	return json.Marshal(struct {
		FormatVersion            int    `json:"formatVersion"`
		Stage                    string `json:"stage"`
		ProtectionAvailable      bool   `json:"protectionAvailable"`
		SharedWorkspaceAvailable bool   `json:"sharedWorkspaceAvailable"`
		Unlocked                 bool   `json:"unlocked"`
		LockedMemory             bool   `json:"lockedMemory"`
	}{FormatVersion: 1, Stage: "foundation", Unlocked: h.owner != nil, LockedMemory: h.owner != nil && h.owner.LockedMemory()})
}

func (h *vaultFoundationHandler) Close() error {
	h.setupImport = nil
	h.closed = true
	var err error
	if h.sharedDestination != nil {
		if err = h.sharedDestination.close(); err == nil {
			h.sharedDestination = nil
		}
	}
	if h.shared != nil {
		err = errors.Join(err, h.shared.close())
	}
	if h.enrollment != nil {
		err = errors.Join(err, h.enrollment.close())
	}
	err = errors.Join(err, h.closeBitwardenCLIUnlock())
	if h.rotationMaterial != nil {
		closeErr := h.rotationMaterial.Close()
		if closeErr == nil {
			h.rotationMaterial = nil
		}
		err = errors.Join(err, closeErr)
	}
	if h.owner != nil {
		err = errors.Join(err, h.owner.Close())
	}
	if h.clipboard != nil {
		ctx, cancel := context.WithTimeout(context.Background(), vaultwire.ShutdownTimeout/2)
		defer cancel()
		err = errors.Join(err, h.clipboard.Close(ctx))
	}
	// Retain workspace exclusion while any native owner still has an uncertain
	// cleanup obligation. Close retires operations; a later Close may retry.
	if err == nil && h.releaseWorkspace != nil {
		h.releaseWorkspace()
		h.releaseWorkspace = nil
	}
	return err
}

func (*vaultFoundationHandler) ExitOnCancel(operation string) bool {
	if operation == "touch-id-unlock" {
		return true
	}
	if operation == "local-backup-install" || operation == "local-backup-restore" || operation == "local-backup-export" {
		return true
	}
	if operation == "shared-admin-recover" || operation == "shared-tighten-profile" || operation == "shared-member-invitation" {
		return true
	}
	if operation == "shared-recovery-export" || operation == "shared-recovery-inspect" || operation == "shared-recovery-restore" ||
		operation == "shared-account-reset-issue" || operation == "shared-account-reset-redeem" || operation == "shared-account-reset-mark-handover" {
		return true
	}
	if operation == "shared-setup-admin-prepare" || operation == "shared-setup-admin-publish" || operation == "shared-setup-admin-join" || operation == "shared-setup-admin-recovery" {
		return true
	}
	if operation == "shared-setup-run" || operation == "shared-setup-preflight" || operation == "shared-setup-check" || operation == "shared-setup-prepare-tls" || operation == "shared-setup-prepare-generated-tls" || operation == "shared-setup-save-server-kit" || operation == "shared-setup-delete-server-key" {
		return true
	}
	if operation == "shared-invitation-inspect" || operation == "shared-invitation-file" {
		return true
	}
	if operation == "rotation-upgrade-begin" || operation == "rotation-encryption-begin" || operation == "unprotected-create" || operation == "unprotected-open" || operation == "migration-os-prepare" || operation == "migration-os-resume" || operation == "shared-recover-enrollment" || operation == "shared-join-initial" || operation == "shared-continue-enrollment" {
		return true
	}
	return operation == "quick-target-register" || operation == "quick-target-release" || operation == "ssh-quick-host-trust" || operation == "shared-unlock" || operation == "shared-recover-password" || operation == "bitwarden-cleanup" || operation == "bitwarden-install-zip" || operation == "bitwarden-install-folder" || operation == "initialize" || operation == "unlock" || operation == "hello-unlock" || operation == "migration-setup-begin" || operation == "migration-setup-confirm" || operation == "migration-resume" || operation == "rotation-resume" || operation == "rotation-setup-begin" || operation == "rotation-setup-confirm" || operation == "enrollment-begin" || operation == "enrollment-confirm" || operation == "fresh-action"
}

type vaultWriteCloser struct{ io.Writer }

func (vaultWriteCloser) Close() error { return nil }

func serveVaultFoundation(databasePath string, input io.ReadCloser, output io.WriteCloser, timeout time.Duration, userDataPath ...string) error {
	root := ""
	if len(userDataPath) > 0 {
		root = userDataPath[0]
	}
	return serveVaultFoundationLaunch(databasePath, input, output, timeout, vaultLaunchOptions{userDataPath: root})
}

func serveVaultFoundationLaunch(databasePath string, input io.ReadCloser, output io.WriteCloser, timeout time.Duration, launch vaultLaunchOptions) error {
	if err := launch.validate(); err != nil {
		return err
	}
	// Metadata requests coexist with legacy services. Native unlock acquires
	// the separate directory-wide ownership guard before touching vault data.
	if err := os.MkdirAll(filepath.Dir(databasePath), 0o700); err != nil {
		return errors.New("vault_storage_unavailable")
	}
	release, err := tryAcquireExclusiveFileLock(databasePath + ".vault.lock")
	if err != nil {
		return errors.New("vault_owner_unavailable")
	}
	defer release()
	effective, selection, err := resolveVaultWorkspace(databasePath, nativeSharedStartupProtection())
	if err != nil || (selection != nil && launch.migrationSessionData != "") {
		return errSharedTrustStorage
	}
	if selection != nil {
		releaseTarget, err := tryAcquireExclusiveFileLock(effective + ".vault.lock")
		if err != nil {
			return errWorkspaceInUse
		}
		defer releaseTarget()
	}
	root := context.Background()
	if launch.touchIDBroker != nil {
		root = context.WithValue(root, touchIDBrokerContextKey{}, launch.touchIDBroker)
	}
	ctx, cancel := context.WithCancel(root)
	defer cancel()
	handler := &vaultFoundationHandler{
		databasePath: effective, sharedSelection: selection, userDataPath: launch.userDataPath,
		migrationQuiesced: launch.migrationSessionData != "", catalogEvents: make(chan struct{}, 1), stopService: cancel,
	}
	return vaultwire.Serve(ctx, input, output, handler, timeout)
}

func runVaultLaunchCLI(databasePath string, input io.Reader, output, errorOutput io.Writer, launch vaultLaunchOptions) int {
	if !enforceVaultChildProcessPolicy() {
		writeErrorTo(errorOutput, "vault_child_process_policy_unavailable")
		return 1
	}
	if err := securemem.DisableProcessDumps(); err != nil {
		writeErrorTo(errorOutput, "vault_memory_unavailable")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err := checkVaultInstallationFloor(ctx)
	cancel()
	if err != nil {
		writeErrorTo(errorOutput, err.Error())
		return 1
	}
	if launch.touchIDChannel {
		channel, err := openTouchIDChannel()
		if err != nil {
			writeErrorTo(errorOutput, "vault_touch_id_channel_unavailable")
			return 1
		}
		defer channel.Close()
		launch.touchIDBroker = &touchIDBrokerClient{conn: channel}
	}
	return runVaultLaunchStream(databasePath, input, output, errorOutput, launch)
}

func runVaultLaunchStream(databasePath string, input io.Reader, output, errorOutput io.Writer, launch vaultLaunchOptions) int {
	readCloser, ok := input.(io.ReadCloser)
	if !ok {
		readCloser = io.NopCloser(input)
	}
	writeCloser, ok := output.(io.WriteCloser)
	if !ok {
		writeCloser = vaultWriteCloser{output}
	}
	if err := serveVaultFoundationLaunch(databasePath, readCloser, writeCloser, 0, launch); err != nil {
		// No raw errors, paths, SQL, payloads or key material cross this boundary.
		writeErrorTo(errorOutput, "vault_service_stopped")
		return 1
	}
	return 0
}
