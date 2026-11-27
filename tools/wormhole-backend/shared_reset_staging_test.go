package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestResetStagingRefusesCompetingPiecesBeforeWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.trust")
	p := sharedJoinStartup{DeviceFile: []byte("prepared device"), Transport: []byte("prepared transport"), Pending: []byte("prepared intent")}
	if err := os.WriteFile(sharedPendingEnrollmentPath(path), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := restoreAccountResetPieces(context.Background(), path, p, true); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("accepted a competing reset intent", err)
	}
	if _, err := os.Stat(sharedDeviceEnrollmentPath(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published device files before confirming the entire selection", err)
	}
	if err := os.Remove(sharedPendingEnrollmentPath(path)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sharedStartupAnchorPath(path), []byte("ordinary selection"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := restoreAccountResetPieces(context.Background(), path, p, true); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("recreated reset files behind a normal startup anchor", err)
	}
	if err := os.Remove(sharedStartupAnchorPath(path)); err != nil {
		t.Fatal(err)
	}
	if _, err := restoreAccountResetPieces(context.Background(), path, p, false); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("recreated missing ciphertext over active trust", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := restoreAccountResetPieces(ctx, path, p, true); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled recovery published missing device pieces", err)
	}
	if _, err := restoreAccountResetPieces(context.Background(), path, p, true); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(sharedDeviceEnrollmentPath(path))
	if err != nil || !bytes.Equal(raw, p.DeviceFile) {
		t.Fatal("device did not come from the checkpoint", err)
	}
	if err := os.Remove(sharedPendingEnrollmentPath(path)); err != nil {
		t.Fatal(err)
	}
	if missing, err := restoreAccountResetPieces(context.Background(), path, p, false); !missing || err != nil {
		t.Fatal("active trust could not reopen after intent cleanup", err)
	}
}

func TestResetOperationRejectsInvalidWireAndWorkspace(t *testing.T) {
	handler := &vaultFoundationHandler{databasePath: "workspace.db"}
	ctx := context.Background()
	if reply, err := handler.Handle(ctx, "shared-account-reset-redeem", []byte("{}")); reply != nil || !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("incomplete recipient request was accepted", err)
	}
	offerPath := filepath.Join(t.TempDir(), "account.whreset")
	if err := os.WriteFile(offerPath, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	payload := vaultInput(t, map[string]any{"offerPath": offerPath, "code": make([]byte, 16), "ask": make([]byte, 32),
		"password": []byte("fixture"), "deviceName": "Fixture device", "appVersion": "2.4.3"})
	if reply, err := handler.Handle(ctx, "shared-account-reset-redeem", payload); reply != nil || !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("reset reached a relative storage destination", err)
	}
	handler.databasePath = filepath.Join(t.TempDir(), "workspace.db")
	local := []byte("existing local database")
	if err := os.WriteFile(handler.databasePath, local, 0600); err != nil {
		t.Fatal(err)
	}
	if reply, err := handler.Handle(ctx, "shared-account-reset-redeem", payload); reply != nil || err == nil {
		t.Fatal("reset accepted an existing local destination", err)
	}
	if raw, err := os.ReadFile(handler.databasePath); err != nil || !bytes.Equal(raw, local) {
		t.Fatal("reset modified the existing local destination", err)
	}
	if err := os.Remove(handler.databasePath); err != nil {
		t.Fatal(err)
	}
	rejected := vaultInput(t, map[string]any{"offerPath": "relative.whreset", "code": make([]byte, 16), "ask": make([]byte, 32),
		"password": []byte("fixture"), "deviceName": "Fixture device", "appVersion": "2.4.3"})
	if reply, err := handler.Handle(ctx, "shared-account-reset-redeem", rejected); reply != nil || !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("relative offer file accepted", err)
	}
	if reply, err := handler.Handle(ctx, "shared-account-reset-redeem", payload); reply != nil || err == nil {
		t.Fatal("reset accepted malformed offer in fresh workspace", err)
	}
	if err := requireNoSharedWorkspace(handler.databasePath); err != nil {
		t.Fatal("malformed offer created a shared selection", err)
	}
	// The native reader owns the public offer file and rejects missing or
	// oversized contents without staging an enrollment.
	if err := os.Remove(offerPath); err != nil {
		t.Fatal(err)
	}
	for _, oversized := range []bool{false, true} {
		if oversized {
			if err := os.WriteFile(offerPath, make([]byte, sharedpg.MaxAccountResetOfferBytes+1), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if reply, err := handler.Handle(ctx, "shared-account-reset-redeem", payload); reply != nil || !errors.Is(err, sharedpg.ErrAccountRecovery) {
			t.Fatal("invalid offer file reached redemption", err)
		}
	}
}
