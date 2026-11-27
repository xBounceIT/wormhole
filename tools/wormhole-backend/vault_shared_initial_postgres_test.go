package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Simulate process loss at the dispatch boundary without invoking remote SQL.
type interruptedInitialInvitation struct{ nativeSharedInitialInvitation }

func (s interruptedInitialInvitation) CommitInvitation(context.Context, *sharedpg.PreparedInvitationCommit) error {
	return sharedpg.ErrInvitationCommitUncertain
}

func TestVaultSharedInitialPostgresFixture(t *testing.T) {
	token := os.Getenv("WORMHOLE_TEST_INITIAL_INVITATION")
	if token == "" {
		t.Skip("public invitation from the disposable PostgreSQL fixture")
	}
	h := &vaultFoundationHandler{databasePath: filepath.Join(t.TempDir(), "workspace.db")}
	if database := os.Getenv("WORMHOLE_TEST_INITIAL_STAGE_DATABASE"); database != "" {
		if !filepath.IsAbs(database) {
			t.Fatal("absolute fixture database required")
		}
		h.databasePath = database
	}
	recovery := os.Getenv("WORMHOLE_TEST_INITIAL_RECOVERY_PREFIX")
	if recovery != "" {
		// Fail only after the real invitation transaction, before confirmation.
		h.sharedFactory = func() *sharedAdmissionController { return nil }
		if recovery == "before-submit" || recovery == "stage-only" {
			h.sharedInvitationFactory = func() sharedInitialInvitationSession {
				return interruptedInitialInvitation{nativeSharedInitialInvitation{sharedpg.NewSession()}}
			}
		}
	}
	defer func() {
		if err := h.Close(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	invitation, err := sharedpg.DecodeInvitation(token, time.Now())
	if err != nil {
		t.Fatal("fixture invitation", err)
	}
	acknowledgeTLSOff := invitation.TLS == sharedpg.TLSOff
	var ask []byte
	if os.Getenv("WORMHOLE_TEST_INITIAL_ASK") == "1" {
		ask = bytes.Repeat([]byte{47}, 32)
	}
	defer vault.Wipe(ask)
	rejectTLS := os.Getenv("WORMHOLE_TEST_INITIAL_REJECT_TLS")
	if rejectTLS != "" {
		if invitation.TLS != sharedpg.TLSVerified {
			t.Fatal("rejection fixture must use verified TLS")
		}
		switch rejectTLS {
		case "ca":
			invitation.CAPEM = sharedControllerCA(t)
		case "host":
			for n := range invitation.Endpoints {
				invitation.Endpoints[n].Host = "localhost"
			}
		default:
			t.Fatal("invalid TLS rejection fixture")
		}
		token, err = sharedpg.EncodeInvitation(invitation, time.Now())
		if err != nil {
			t.Fatal("invalid TLS fixture invitation", err)
		}
	}
	joinInput := map[string]any{
		"invitation": token, "code": bytes.Repeat([]byte{31}, 16),
		"password": []byte("real join password"), "deviceName": "Native PostgreSQL device",
		"appVersion": "1.2.3", "acknowledgeTLSOff": acknowledgeTLSOff,
	}
	if len(ask) != 0 {
		joinInput["ask"] = ask
	}
	raw, err := h.Handle(ctx, "shared-join-initial", vaultInput(t, joinInput))
	if rejectTLS != "" {
		if !errors.Is(err, sharedpg.ErrConnection) || len(raw) != 0 || h.shared != nil || requireNoSharedWorkspace(h.databasePath) != nil {
			t.Fatal("untrusted TLS was not refused before staging", err)
		}
		return
	}
	if recovery != "" {
		if err == nil || len(raw) != 0 {
			t.Fatal("interrupted enrollment published admission")
		}
		database := h.databasePath
		path := sharedWorkspaceTrustPath(database)
		p, e := readSharedJoinStartup(path, h.startupProtection())
		if e != nil || p.FormatVersion != 3 || len(p.Continuation) == 0 {
			t.Fatal("missing recoverable initial selection", e)
		}
		if e := h.Close(); e != nil {
			t.Fatal(e)
		}
		slotsForCheckpoint, _, e := sharedpg.DecodeDeviceEnrollmentFile(p.DeviceFile)
		if e != nil {
			t.Fatal(e)
		}
		selected, e := unlockSharedJoiningDevice(ctx, sharedAdmissionOptions{TrustPath: path, OSFloor: vault.Default, UserFloor: vault.Default, Request: sharedpg.AdmissionRequest{API: 1, AppVersion: "1.2.3", Source: "ui"}}, slotsForCheckpoint.Slots[0].ID, []byte("real join password"), ask, h.startupProtection())
		if e != nil {
			t.Fatal("published checkpoint could not unlock", e)
		}
		e = selected.account.Borrow(func(master *sharedpg.AccountMaster, root *sharedpg.DeviceTrustRoot) error {
			return root.Use(func(key []byte) error {
				continuation, err := sharedpg.OpenInvitationContinuation(key, p.Binding, master, p.Continuation)
				if err != nil {
					return err
				}
				defer continuation.Wipe()
				invitation, err := continuation.Invitation()
				if err != nil {
					return err
				}
				if invitation.WorkspaceID != p.Binding.WorkspaceID || invitation.LoginName != p.LoginName {
					return sharedpg.ErrTrustState
				}
				return nil
			})
		})
		closeErr := selected.Close()
		if e != nil || closeErr != nil {
			t.Fatal("published continuation did not authenticate after restart", e, closeErr)
		}
		pieces := []string{sharedDeviceEnrollmentPath(path), sharedTransportSetupPath(path), sharedPendingEnrollmentPath(path)}
		var keep int
		switch recovery {
		case "snapshot", "before-submit", "stage-only":
			keep = 0
		case "device":
			keep = 1
		case "transport":
			keep = 2
		case "complete":
			keep = 3
		default:
			t.Fatal("invalid recovery fixture prefix")
		}
		for _, piece := range pieces[keep:] {
			if e := os.Remove(piece); e != nil {
				t.Fatal(e)
			}
		}
		if recovery == "stage-only" {
			return
		}
		h = &vaultFoundationHandler{databasePath: database, sharedInvitationFactory: func() sharedInitialInvitationSession {
			t.Fatal("recovery attempted invitation authentication or replay")
			return nil
		}}
		if _, e := h.Handle(ctx, "startup", nil); e != nil {
			t.Fatal("partial startup could not advertise recovery", e)
		}
		slots, _, e := sharedpg.DecodeDeviceEnrollmentFile(p.DeviceFile)
		if e != nil {
			t.Fatal(e)
		}
		operation := "shared-recover-enrollment"
		input := map[string]any{
			"appVersion": "1.2.3", "factors": map[string]any{
				"vaultId": slots.VaultID, "slotId": slots.Slots[0].ID, "password": []byte("real join password"),
			},
		}
		if len(ask) != 0 {
			input["factors"].(map[string]any)["ask"] = ask
		}
		if recovery == "before-submit" {
			operation = "shared-continue-enrollment"
			input["code"] = bytes.Repeat([]byte{31}, 16)
			input["acknowledgeTLSOff"] = acknowledgeTLSOff
		}
		raw, err = h.Handle(ctx, operation, vaultInput(t, input))
	}
	if err != nil {
		t.Fatal("native PostgreSQL initial enrollment", err)
	}
	var result map[string]bool
	if json.Unmarshal(raw, &result) != nil || len(result) != 3 || !result["admitted"] || !result["orgEscrow"] || h.shared == nil || !h.shared.controller.Unlocked() {
		t.Fatal("native PostgreSQL initial admission was not published")
	}
	startupRaw, err := h.Handle(ctx, "startup", nil)
	var startup map[string]json.RawMessage
	if err != nil || json.Unmarshal(startupRaw, &startup) != nil || startup["shared"] == nil || startup["sharedJoin"] != nil {
		t.Fatal("native PostgreSQL selection was not promoted", err)
	}
	if runtime, err := h.readSharedRuntime(ctx); err != nil || runtime.VaultID != h.shared.vaultID {
		t.Fatal("native PostgreSQL runtime was not activated", err)
	}
}
