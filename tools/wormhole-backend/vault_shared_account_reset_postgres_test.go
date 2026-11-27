package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// The parent PostgreSQL fixture owns the live reset role. Codes and ASK travel
// only through stdin. The child uses ordinary native startup and admission.
func TestVaultSharedAccountResetPostgresFixture(t *testing.T) {
	mode := os.Getenv("WORMHOLE_TEST_RESET_APP_MODE")
	if mode == "" {
		t.Skip("synthetic offer from the PostgreSQL reset fixture")
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 2*sharedpg.MaxResetDeviceCheckpointBytes))
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(raw)
	var handover struct{ Offer, Code, ASK []byte }
	if json.Unmarshal(raw, &handover) != nil {
		t.Fatal("invalid synthetic handover")
	}
	defer vault.Wipe(handover.Code)
	defer vault.Wipe(handover.ASK)
	password := []byte("synthetic application reset password")
	defer vault.Wipe(password)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	database := filepath.Join(t.TempDir(), "workspace.db")
	h := &vaultFoundationHandler{databasePath: database}
	retire := func(h *vaultFoundationHandler) {
		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
	}
	const appVersion = "2.4.3"
	var reply json.RawMessage
	switch mode {
	case "direct":
		offerPath := filepath.Join(t.TempDir(), "account.whreset")
		if err := os.WriteFile(offerPath, handover.Offer, 0600); err != nil {
			t.Fatal(err)
		}
		payload := vaultInput(t, map[string]any{"offerPath": offerPath, "code": handover.Code, "ask": handover.ASK,
			"password": password, "deviceName": "Reset fixture", "appVersion": appVersion})
		defer vault.Wipe(payload)
		reply, err = h.Handle(ctx, "shared-account-reset-redeem", payload)
	case "before-submit", "after-submit":
		plan, prepareErr := sharedpg.PrepareAccountResetRedemption(ctx, handover.Offer, handover.Code, handover.ASK, password,
			"Reset fixture", vault.Default, vault.Default)
		if plan != nil {
			defer plan.Close()
		}
		if prepareErr != nil {
			t.Fatal(prepareErr)
		}
		checkpoint, checkpointErr := plan.DeviceCheckpoint()
		if checkpointErr != nil {
			t.Fatal(checkpointErr)
		}
		path := sharedWorkspaceTrustPath(database)
		stage := func() error { return publishSharedResetCheckpoint(ctx, path, checkpoint, h.startupProtection()) }
		if mode == "after-submit" {
			if _, err := plan.Commit(ctx, func(sharedpg.PendingAccountReset) error { return stage() }); err != nil {
				t.Fatal(err)
			}
		} else if err := stage(); err != nil {
			t.Fatal(err)
		}
		if err := plan.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("staging published active trust before ordinary admission")
		}
		// Reconstruct the exact transport piece from the independently protected
		// checkpoint. It cannot be replaced with caller-supplied settings.
		if err := os.Remove(sharedTransportSetupPath(path)); err != nil {
			t.Fatal(err)
		}
		retire(h)
		h = &vaultFoundationHandler{databasePath: database}
		startup, describeErr := h.Handle(ctx, "startup", nil)
		var metadata vaultStartupMetadata
		if describeErr != nil || json.Unmarshal(startup, &metadata) != nil || metadata.SharedJoin == nil ||
			!metadata.SharedJoin.CanContinue || !metadata.SharedJoin.AccountReset || metadata.Slots == nil || len(metadata.Slots.Slots) != 1 {
			t.Fatal("pending reset was not selected on restart", describeErr)
		}
		slots := metadata.Slots
		factors := vaultUnlockInput{VaultID: slots.VaultID, SlotID: slots.Slots[0].ID, Password: password, ASK: handover.ASK}
		if mode == "before-submit" {
			protection := h.startupProtection()
			selected, selectErr := unlockSharedJoiningDevice(ctx, sharedAdmissionOptions{TrustPath: path, OSFloor: vault.Default,
				UserFloor: vault.Default, Request: sharedpg.AdmissionRequest{API: 1, AppVersion: appVersion, Source: "ui"}},
				factors.SlotID, password, handover.ASK, protection)
			if selectErr != nil {
				t.Fatal(selectErr)
			}
			release, lockErr := tryAcquireExclusiveFileLock(path + ".lock")
			if lockErr != nil {
				t.Fatal(lockErr)
			}
			reconcileErr := selected.reconcileAccountReset(ctx, handover.Code, handover.ASK)
			release()
			if !errors.Is(reconcileErr, errSharedTrustConflict) {
				t.Fatal("reset continued while another owner held the trust lock", reconcileErr)
			}
			original := selected.initial
			changed := *original
			changed.Pending = bytes.Clone(changed.Pending)
			changed.Pending[len(changed.Pending)/2] ^= 1
			if err := persistSharedJoinStartupValue(ctx, path, changed, protection); err != nil {
				t.Fatal(err)
			}
			if err := selected.reconcileAccountReset(ctx, handover.Code, handover.ASK); !errors.Is(err, errSharedTrustConflict) {
				t.Fatal("recovery accepted a replaced startup selection", err)
			}
			selected.initial = &changed
			if err := selected.reconcileAccountReset(ctx, handover.Code, handover.ASK); err == nil {
				t.Fatal("recovery accepted a tampered reset envelope")
			}
			if err := persistSharedJoinStartupValue(ctx, path, *original, protection); err != nil {
				t.Fatal(err)
			}
			selected.initial = original
			if err := os.WriteFile(path, []byte("invalid active trust"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := selected.reconcileAccountReset(ctx, handover.Code, handover.ASK); err == nil {
				t.Fatal("recovery ignored a corrupt active trust file")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := selected.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := h.openSharedInput(ctx, "shared-recover-enrollment", factors, appVersion, nil, false, ""); !errors.Is(err, sharedpg.ErrAuthentication) {
				t.Fatal("ordinary recovery submitted an uncommitted reset", err)
			}
			wrongCode := bytes.Repeat([]byte{37}, vault.InviteCodeBytes)
			if _, err := h.openSharedInput(ctx, "shared-continue-enrollment", factors, appVersion, wrongCode, false, ""); !errors.Is(err, sharedpg.ErrAuthentication) {
				t.Fatal("continuation accepted the wrong reset code", err)
			}
			reply, err = h.openSharedInput(ctx, "shared-continue-enrollment", factors, appVersion, handover.Code, false, "")
		} else {
			h.sharedFactory = func() *sharedAdmissionController { return nil }
			if _, err := h.openSharedInput(ctx, "shared-recover-enrollment", factors, appVersion, nil, false, ""); !errors.Is(err, sharedpg.ErrConfiguration) {
				t.Fatal("did not interrupt after trust publication", err)
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatal("confirmed trust was lost after interruption", err)
			}
			retire(h)
			h = &vaultFoundationHandler{databasePath: database}
			reply, err = h.openSharedInput(ctx, "shared-recover-enrollment", factors, appVersion, nil, false, "")
		}
	default:
		t.Fatal("unknown reset fixture mode")
	}
	if err != nil || len(reply) == 0 || h.shared == nil || !h.shared.controller.Unlocked() {
		t.Fatal("application reset did not establish ordinary admission", err)
	}
	retire(h)
	h = &vaultFoundationHandler{databasePath: database}
	defer retire(h)
	path := sharedWorkspaceTrustPath(database)
	if err := requireNoSharedJoinStartup(path); err != nil {
		t.Fatal("active reset retained its startup marker", err)
	}
	startup, err := h.Handle(ctx, "startup", nil)
	var metadata vaultStartupMetadata
	if err != nil || json.Unmarshal(startup, &metadata) != nil || metadata.Shared == nil || metadata.SharedJoin != nil {
		t.Fatal("confirmed reset was not selected for ordinary startup", err)
	}
	anchor, err := readSharedStartupAnchor(path, h.startupProtection())
	if err != nil {
		t.Fatal(err)
	}
	data, err := readSharedTrustBytes(sharedDeviceEnrollmentPath(path), sharedpg.MaxDeviceEnrollmentFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	slots, _, err := sharedpg.DecodeDeviceEnrollmentFile(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.openSharedInput(ctx, "shared-unlock", vaultUnlockInput{VaultID: anchor.VaultID, SlotID: slots.Slots[0].ID,
		Password: password, ASK: handover.ASK}, appVersion, nil, false, ""); err != nil {
		t.Fatal("confirmed device did not reopen using the new factors", err)
	}
}
