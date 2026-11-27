package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// One selected workspace per native database path. Neither path is a wire input.
func sharedWorkspaceDirectory(databasePath string) string { return databasePath + ".shared" }
func sharedWorkspaceTrustPath(databasePath string) string {
	return filepath.Join(sharedWorkspaceDirectory(databasePath), "device.trust")
}

func requireNoSharedWorkspace(databasePath string) error {
	if _, err := os.Lstat(sharedWorkspaceSelectionPath(databasePath)); !errors.Is(err, os.ErrNotExist) {
		return errVaultOwnerRequired
	}
	_, err := os.Lstat(sharedWorkspaceDirectory(databasePath))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return errVaultOwnerRequired
}

type vaultSharedSession struct {
	selected   *sharedSelectedDevice
	controller *sharedAdmissionController
	initial    *vaultSharedInitialJoin
	joining    *sharedInvitationJoin // explicit continuation, never a staging-discard owner
	release    func()
	vaultID    string // public device slot identity, distinct from its remote workspace
	fileID     string // public device-file identity from the authenticated startup anchor
}

// Keep the workspace lease until every native/network owner confirms cleanup.
// Failed owners remain attached for Close retry; Close never grants operations.
func (s *vaultSharedSession) close() error {
	var err error
	if s.joining != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = s.joining.Close(ctx)
		cancel()
	}
	if s.controller != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = errors.Join(err, s.controller.Close(ctx))
		cancel()
	}
	if s.selected != nil {
		err = errors.Join(err, s.selected.Close())
	}
	if s.initial != nil {
		err = errors.Join(err, s.initial.close())
	}
	if err == nil && s.release != nil {
		s.release()
		s.release = nil
	}
	return err
}

func (h *vaultFoundationHandler) startupProtection() sharedStartupProtection {
	if h.sharedProtection != nil {
		return *h.sharedProtection
	}
	return nativeSharedStartupProtection()
}

// Stdin-only typed factors for the native protected input flow. This
// admits account keys but does not yet grant catalog/protocol/UI capabilities.
func (h *vaultFoundationHandler) openShared(ctx context.Context, operation string, payload []byte) (result json.RawMessage, err error) {
	if ctx == nil || h.closed || h.shared != nil || h.owner != nil || h.enrollment != nil || !filepath.IsAbs(h.databasePath) || len(payload) > 12288 || (operation != "shared-unlock" && operation != "shared-recover-password" && operation != "shared-recover-enrollment" && operation != "shared-continue-enrollment") {
		return nil, vaultwire.ErrProtocol
	}
	var factors json.RawMessage
	var appVersion string
	continuing := operation == "shared-continue-enrollment"
	var codeRaw json.RawMessage
	var code []byte
	var acknowledgeTLSOff bool
	var tlsUpdatePath string
	defer func() { vault.Wipe(factors); vault.Wipe(codeRaw); vault.Wipe(code) }()
	fields := map[string]any{"factors": &factors, "appVersion": &appVersion}
	required := []string{"factors", "appVersion"}
	if operation == "shared-unlock" {
		fields["tlsUpdatePath"] = &tlsUpdatePath
	}
	if continuing {
		fields["code"], fields["acknowledgeTLSOff"] = &codeRaw, &acknowledgeTLSOff
		required = append(required, "code", "acknowledgeTLSOff")
	}
	if decodeVaultObject(payload, fields, required...) != nil {
		return nil, vaultwire.ErrProtocol
	}
	if continuing && (len(codeRaw) == 0 || codeRaw[0] != '"' || json.Unmarshal(codeRaw, &code) != nil || len(code) != vault.InviteCodeBytes) {
		return nil, vaultwire.ErrProtocol
	}
	input, err := decodeVaultUnlock(factors)
	defer input.wipe()
	if err != nil {
		return nil, vaultwire.ErrProtocol
	}
	if tlsUpdatePath != "" && !sharedTLSBundlePathValid(tlsUpdatePath) {
		return nil, vaultwire.ErrProtocol
	}
	return sharedEnrollmentReply(h.openSharedInput(ctx, operation, input, appVersion, code, acknowledgeTLSOff, tlsUpdatePath))
}

func sharedEnrollmentReply(result json.RawMessage, err error) (json.RawMessage, error) {
	// Only return the receipt after the native owner has closed successfully.
	// Cleanup failures and retired owners must remain errors.
	if err == errSharedReenrollmentPending {
		return json.RawMessage(`{"awaitingActivation":true}`), nil
	}
	return result, err
}

func (h *vaultFoundationHandler) openSharedInput(ctx context.Context, operation string, input vaultUnlockInput, appVersion string, code []byte, acknowledgeTLSOff bool, tlsUpdatePath string) (result json.RawMessage, err error) {
	if ctx == nil || h.closed || h.shared != nil || h.owner != nil || h.enrollment != nil || !filepath.IsAbs(h.databasePath) ||
		input.VaultID == "" || input.SlotID == "" || len(input.Password) == 0 || len(input.RecoveryKey) != 0 || len(input.RecoveryCode) != 0 {
		return nil, vaultwire.ErrProtocol
	}
	continuing := operation == "shared-continue-enrollment"
	if h.sharedSelection != nil && (continuing || operation == "shared-recover-enrollment") {
		return nil, sharedpg.ErrTrustState
	}
	if continuing {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	floor, err := ospolicy.ReadFloor(ctx)
	if err != nil {
		return nil, err
	}
	release, err := acquireWorkspaceOwnership(h.databasePath, true)
	if err != nil {
		return nil, err
	}
	s := &vaultSharedSession{release: release}
	h.shared = s
	defer func() {
		if err != nil || operation == "shared-recover-password" {
			if cleanup := s.close(); cleanup != nil {
				result, err = nil, h.retire(errors.Join(err, cleanup))
			} else {
				h.shared = nil
			}
		}
	}()
	if err := requireNoLegacyMigrationSetup(h.databasePath); err != nil {
		return nil, err
	}
	// Do not activate shared access over a local encrypted workspace. A separate
	// migration must own that conversion; no implicit deletion or fallback.
	if _, e := os.Lstat(vaultSlotPath(h.databasePath)); !errors.Is(e, os.ErrNotExist) {
		return nil, errVaultOwnerRequired
	}
	if _, e := os.Lstat(h.databasePath); !errors.Is(e, os.ErrNotExist) {
		return nil, errVaultOwnerRequired
	}
	info, err := os.Lstat(sharedWorkspaceDirectory(h.databasePath))
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errSharedTrustStorage
	}
	mode := sharedDeviceOrdinary
	if operation == "shared-recover-password" {
		mode = sharedDevicePasswordRecovery
	}
	o := sharedAdmissionOptions{TrustPath: sharedWorkspaceTrustPath(h.databasePath), OSFloor: floor, UserFloor: vault.Default, Request: sharedpg.AdmissionRequest{API: 1, AppVersion: appVersion, Source: "ui"}}
	joining := operation == "shared-recover-enrollment" || continuing
	if joining {
		s.selected, err = unlockSharedJoiningDevice(ctx, o, input.SlotID, input.Password, input.ASK, h.startupProtection())
		if err != nil {
			return nil, fmt.Errorf("unlock pending device: %w", err)
		}
	} else {
		s.selected, err = unlockSharedSelectedDevice(ctx, o, input.SlotID, input.Password, input.ASK, mode, h.startupProtection())
	}
	if err != nil {
		return nil, err
	}
	if s.selected.vaultID != input.VaultID {
		return nil, vault.ErrAuthentication
	}
	if selection := h.sharedSelection; selection != nil && (selection.VaultID != s.selected.vaultID ||
		selection.WorkspaceID != s.selected.options.Binding.WorkspaceID || selection.DeviceID != s.selected.options.Binding.DeviceID) {
		return nil, sharedpg.ErrTrustState
	}
	if tlsUpdatePath != "" {
		if operation != "shared-unlock" {
			return nil, vaultwire.ErrProtocol
		}
		if err := s.selected.applyTLSUpdate(ctx, tlsUpdatePath, h.startupProtection()); err != nil {
			return nil, err
		}
	}
	factory := h.sharedFactory
	if factory == nil {
		factory = newSharedAdmissionController
	}
	if continuing {
		if s.selected.initial == nil || (s.selected.initial.FormatVersion != 3 && s.selected.initial.FormatVersion != 4) {
			return nil, sharedpg.ErrTrustState
		}
	}
	reset := joining && s.selected.initial != nil && s.selected.initial.FormatVersion == 4
	if reset {
		if err := s.selected.reconcileAccountReset(ctx, code, input.ASK); err != nil {
			if err == errSharedReenrollmentPending {
				return nil, err
			}
			return nil, fmt.Errorf("reconcile account reset: %w", err)
		}
	} else if continuing {
		create := h.sharedContinuationFactory
		if create == nil {
			create = func() sharedInitialContinuationSession { return sharedpg.NewSession() }
		}
		session := create()
		if session == nil {
			return nil, sharedpg.ErrConfiguration
		}
		s.joining = newSharedInvitationJoinWithSession(session, func() sharedJoinRecovery { return factory() })
		if err := s.selected.continueInitialEnrollment(ctx, s.joining, session, code, acknowledgeTLSOff); err != nil {
			return nil, err
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		closeErr := s.joining.Close(cleanup)
		cancel()
		if closeErr != nil {
			return nil, closeErr
		}
		s.joining = nil
	}
	s.controller = factory()
	if s.controller == nil {
		return nil, sharedpg.ErrConfiguration
	}
	s.controller.catalogChanged = h.notifySharedCatalog
	if joining && !continuing && !reset {
		if err := s.selected.reconcileInitialEnrollment(ctx, s.controller); err != nil {
			return nil, err
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		closeErr := s.controller.Close(cleanup)
		cancel()
		if closeErr != nil {
			return nil, closeErr
		}
		s.controller = nil
		s.controller = factory()
		if s.controller == nil {
			return nil, sharedpg.ErrConfiguration
		}
		s.controller.catalogChanged = h.notifySharedCatalog
	}
	if mode == sharedDevicePasswordRecovery {
		outcome, e := s.selected.RecoverNewPassword(ctx, s.controller)
		if e != nil {
			return nil, e
		}
		if outcome == nil || !outcome.Changed {
			return nil, sharedpg.ErrTrustState
		}
		return json.RawMessage(`{"recovered":true}`), nil
	}
	if err := s.selected.Open(ctx, s.controller); err != nil {
		if reset {
			return nil, fmt.Errorf("admit confirmed reset device: %w", err)
		}
		return nil, err
	}
	anchor, err := readSharedStartupAnchor(o.TrustPath, h.startupProtection())
	if errors.Is(err, errSharedTrustMissing) && joining {
		anchor = sharedStartupAnchor{DisplayName: s.selected.initial.Binding.WorkspaceID.String()}
	} else if err != nil {
		return nil, err
	}
	result, err = h.publishSharedAdmission(ctx, s, anchor.DisplayName, anchor.Revision)
	if reset && err != nil {
		err = fmt.Errorf("publish reset device admission: %w", err)
	}
	return result, err
}

// Both a new invitation and a subsequent unlock publish from admitted native
// owners. Neither an invitation receipt nor a renderer acknowledgement suffices.
func (h *vaultFoundationHandler) publishSharedAdmission(ctx context.Context, s *vaultSharedSession, displayName string, revision uint64) (json.RawMessage, error) {
	anchor, err := writeSharedStartupAnchor(ctx, s.selected.options, s.selected.account, displayName, revision, h.startupProtection())
	if err != nil {
		return nil, err
	}
	if h.sharedSelection != nil && !h.sharedSelection.matches(anchor) {
		return nil, sharedpg.ErrTrustState
	}
	s.fileID = anchor.FileID
	s.vaultID = anchor.VaultID
	locked := s.selected.account.Locked()
	if err := s.controller.adoptVPNSSOStorage(ctx, s.selected.account, h.startupProtection()); err != nil {
		return nil, err
	}
	// Admission owns protocol keys and the separate personal browser-state root.
	// Account derivation roots do not survive; all retained keys share revocation.
	if err := s.selected.Close(); err != nil {
		return nil, err
	}
	if !s.controller.Unlocked() {
		return nil, sharedpg.ErrSessionClosed
	}
	result, err := marshalSharedAdmission(locked && !s.controller.MemoryLockWarning(), anchor.Trust)
	if err == nil && h.stopService != nil {
		// A published owner losing admission ends this process even if the
		// renderer is idle. Electron already treats owner exit as a vault lock.
		s.controller.stopOwnerExit = context.AfterFunc(s.controller.lifetime, h.stopService)
	}
	// The admission and the worker both checkpoint device trust. Start the
	// worker only after the startup anchor has been published.
	if session, ok := s.controller.session.(suspensionInventorySession); err == nil && ok {
		go s.controller.monitorSuspensionRotations(session)
		s.controller.wakeSuspensionRotation()
	}
	return result, err
}

// The checkpoint supplies an authenticated policy, never invitation hints or a
// renderer preference. Keep the false case for a future Paranoid runtime.
func marshalSharedAdmission(lockedMemory bool, trust sharedpg.TrustState) (json.RawMessage, error) {
	policy, err := trust.Policy()
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Admitted     bool `json:"admitted"`
		LockedMemory bool `json:"lockedMemory"`
		OrgEscrow    bool `json:"orgEscrow"`
	}{true, lockedMemory, policy.OrgEscrow})
}
