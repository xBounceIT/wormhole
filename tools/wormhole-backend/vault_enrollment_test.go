package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type enrollmentResponse struct {
	EnrollmentID string             `json:"enrollmentId"`
	VaultID      string             `json:"vaultId"`
	Groups       [2]int             `json:"groups"`
	Bundle       vault.SealedBundle `json:"bundle"`
}

func beginEnrollmentFixture(t *testing.T) (*vaultFoundationHandler, enrollmentResponse, []byte) {
	t.Helper()
	h := &vaultFoundationHandler{databasePath: filepath.Join(t.TempDir(), "workspace.db")}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Error(err)
		}
	})
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	input := vaultInput(t, map[string]any{"password": []byte("enrollment-password-fixture"), "publicKey": private.PublicKey().Bytes()})
	raw, err := h.Handle(context.Background(), "enrollment-begin", input)
	if err != nil {
		t.Fatal(err)
	}
	var response enrollmentResponse
	if err := json.Unmarshal(raw, &response); err != nil || response.EnrollmentID == "" || response.VaultID == "" || response.Groups[0] == response.Groups[1] {
		t.Fatal("invalid enrollment", err)
	}
	for _, group := range response.Groups {
		if group < 1 || group > 11 {
			t.Fatal("group outside complete code groups")
		}
	}
	info := []byte("wormhole/v1/recovery-display")
	for _, field := range []string{response.VaultID, response.EnrollmentID} {
		info = binary.BigEndian.AppendUint32(info, uint32(len(field)))
		info = append(info, field...)
	}
	key, err := hpke.NewDHKEMPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := hpke.NewRecipient(response.Bundle.Enc, key, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		t.Fatal(err)
	}
	code, err := recipient.Open(nil, response.Bundle.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, code) || bytes.Contains(raw, []byte("enrollment-password-fixture")) {
		t.Fatal("plaintext escaped native enrollment")
	}
	if h.owner != nil || h.enrollment == nil || !h.enrollment.material.Locked() {
		t.Fatal("incorrect pending state")
	}
	assertEnrollmentUnpublished(t, h)
	return h, response, code
}

func assertEnrollmentUnpublished(t *testing.T, h *vaultFoundationHandler) {
	t.Helper()
	for _, path := range []string{h.databasePath, vaultSlotPath(h.databasePath)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("unconfirmed enrollment wrote workspace", err)
		}
	}
}

func enrollmentConfirmation(t *testing.T, response enrollmentResponse, code []byte) []byte {
	t.Helper()
	groups := make([]byte, 0, 10)
	for _, number := range response.Groups {
		start := 7 + (number-1)*6
		groups = append(groups, code[start:start+5]...)
	}
	return vaultInput(t, map[string]any{"enrollmentId": response.EnrollmentID, "groups": groups})
}

func TestVaultEnrollmentConfirmsThenUnlocksWithEitherFactor(t *testing.T) {
	h, response, code := beginEnrollmentFixture(t)
	ctx := context.Background()
	pending := h.enrollment
	if release, err := acquireWorkspaceOwnership(h.databasePath, false); err == nil {
		release()
		t.Fatal("legacy startup entered pending enrollment")
	}
	for _, operation := range []string{"initialize", "unlock", "enrollment-begin"} {
		if _, err := h.Handle(ctx, operation, []byte(`{}`)); err != vaultwire.ErrProtocol {
			t.Fatal("parallel initialization accepted", operation, err)
		}
	}
	if _, err := h.Handle(ctx, "enrollment-confirm", enrollmentConfirmation(t, response, code)); err != nil {
		t.Fatal(err)
	}
	if h.owner == nil || h.enrollment != nil || !pending.closed || pending.material.With(func([]byte) error { return nil }) != securemem.ErrClosed {
		t.Fatal("pending recovery key retained")
	}
	if release, err := acquireWorkspaceOwnership(h.databasePath, false); err == nil {
		release()
		t.Fatal("lease lost during publication")
	}
	if _, err := h.Handle(ctx, "enrollment-confirm", enrollmentConfirmation(t, response, code)); err != vaultwire.ErrProtocol {
		t.Fatal("confirmation replay accepted", err)
	}
	if _, err := h.Handle(ctx, "enrollment-cancel", nil); err != vaultwire.ErrProtocol {
		t.Fatal("cancel hid active owner", err)
	}
	doc, err := readVaultSlotFile(h.databasePath)
	if err != nil || doc.Initializing || doc.VaultID != response.VaultID {
		t.Fatal("invalid publication", err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []vault.SlotKind{vault.SlotPassword, vault.SlotRecovery} {
		other := &vaultFoundationHandler{databasePath: h.databasePath}
		fields := map[string]any{"vaultId": doc.VaultID}
		for _, slot := range doc.Slots {
			if slot.Kind == kind {
				fields["slotId"] = slot.ID
			}
		}
		if kind == vault.SlotPassword {
			fields["password"] = []byte("enrollment-password-fixture")
		} else {
			fields["recoveryCode"] = code
		}
		if _, err := other.Handle(ctx, "unlock", vaultInput(t, fields)); err != nil {
			t.Fatal("confirmed factor cannot unlock", kind, err)
		}
		if err := other.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVaultEnrollmentRejectsMalformedAndExistingSources(t *testing.T) {
	h := &vaultFoundationHandler{databasePath: filepath.Join(t.TempDir(), "workspace.db")}
	defer h.Close()
	ctx := context.Background()
	private, _ := ecdh.X25519().GenerateKey(rand.Reader)
	valid := vaultInput(t, map[string]any{"password": []byte("fixture"), "publicKey": private.PublicKey().Bytes()})
	for _, raw := range [][]byte{nil, []byte(`{}`), bytes.Repeat([]byte{' '}, 4097), []byte(`{"password":null,"publicKey":"AA=="}`), []byte(`{"password":[65],"publicKey":"AA=="}`), []byte(`{"password":"QQ==","publicKey":"AA==","extra":1}`), []byte(`{"password":"QQ==","password":"QQ==","publicKey":"AA=="}`), vaultInput(t, map[string]any{"password": []byte{}, "publicKey": private.PublicKey().Bytes()}), vaultInput(t, map[string]any{"password": bytes.Repeat([]byte{1}, 1025), "publicKey": private.PublicKey().Bytes()})} {
		if _, err := h.Handle(ctx, "enrollment-begin", raw); err == nil {
			t.Fatal("malformed begin accepted")
		}
		assertEnrollmentUnpublished(t, h)
	}
	if _, err := h.Handle(ctx, "enrollment-begin", vaultInput(t, map[string]any{"password": []byte("fixture"), "publicKey": make([]byte, 32)})); err == nil {
		t.Fatal("low-order recipient accepted")
	}
	if release, err := acquireWorkspaceOwnership(h.databasePath, true); err != nil {
		t.Fatal("failed begin leaked lease", err)
	} else {
		release()
	}
	release, err := acquireWorkspaceOwnership(h.databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "enrollment-begin", valid); err == nil {
		t.Fatal("legacy owner displaced")
	}
	release()
	for _, path := range []string{h.databasePath, vaultSlotPath(h.databasePath)} {
		if err := os.WriteFile(path, []byte("legacy-fixture"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := h.Handle(ctx, "enrollment-begin", valid); err == nil {
			t.Fatal("existing source overwritten")
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != "legacy-fixture" {
			t.Fatal("source changed", err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := h.Handle(cancelled, "enrollment-begin", valid); err != context.Canceled {
		t.Fatal(err)
	}
	if _, err := (&vaultFoundationHandler{}).Handle(ctx, "enrollment-begin", valid); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "enrollment-confirm", nil); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "enrollment-cancel", []byte(`{}`)); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "enrollment-cancel", nil); err != nil {
		t.Fatal(err)
	}
}

func TestVaultEnrollmentMistakesCancelAndExpiry(t *testing.T) {
	h, response, code := beginEnrollmentFixture(t)
	ctx := context.Background()
	for _, raw := range [][]byte{nil, bytes.Repeat([]byte{' '}, 1025), vaultInput(t, map[string]any{"enrollmentId": uuid.NewString(), "groups": []byte("AAAAAAAAAA")}), vaultInput(t, map[string]any{"enrollmentId": response.EnrollmentID, "groups": []byte("short")}), []byte(`{"enrollmentId":"` + response.EnrollmentID + `","groups":[65]}`)} {
		if _, err := h.Handle(ctx, "enrollment-confirm", raw); err != vaultwire.ErrProtocol {
			t.Fatal("malformed confirmation accepted", err)
		}
	}
	pending := h.enrollment
	wrong := vaultInput(t, map[string]any{"enrollmentId": response.EnrollmentID, "groups": []byte("0000000000")})
	for i := 0; i < 3; i++ {
		if _, err := h.Handle(ctx, "enrollment-confirm", wrong); !errors.Is(err, vault.ErrAuthentication) {
			t.Fatal(err)
		}
	}
	if _, err := h.Handle(ctx, "enrollment-confirm", enrollmentConfirmation(t, response, code)); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("attempt limit bypassed", err)
	}
	if !pending.closed || pending.material.With(func([]byte) error { return nil }) != securemem.ErrClosed {
		t.Fatal("failed enrollment retained key")
	}
	assertEnrollmentUnpublished(t, h)
	if _, err := h.Handle(ctx, "enrollment-cancel", nil); err != nil || h.enrollment != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "enrollment-cancel", nil); err != nil {
		t.Fatal("cancel not idempotent", err)
	}

	h2, response2, code2 := beginEnrollmentFixture(t)
	p := h2.enrollment
	p.mu.Lock()
	p.expires = time.Now().Add(-time.Second)
	p.mu.Unlock()
	if _, err := h2.Handle(ctx, "enrollment-confirm", enrollmentConfirmation(t, response2, code2)); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("expired confirmation accepted", err)
	}
	if !p.closed {
		t.Fatal("expired key retained")
	}
	assertEnrollmentUnpublished(t, h2)
	if release, err := acquireWorkspaceOwnership(h2.databasePath, false); err != nil {
		t.Fatal("expiry retained lease", err)
	} else {
		release()
	}
}

func TestVaultEnrollmentCleanupRacesAndPublicationConflict(t *testing.T) {
	h, response, code := beginEnrollmentFixture(t)
	if err := os.WriteFile(h.databasePath, []byte("late-independent-file"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(context.Background(), "enrollment-confirm", enrollmentConfirmation(t, response, code)); !errors.Is(err, vaultwire.ErrRetired) {
		t.Fatal("publication failure did not retire", err)
	}
	got, err := os.ReadFile(h.databasePath)
	if err != nil || string(got) != "late-independent-file" {
		t.Fatal("late file overwritten", err)
	}
	if h.enrollment != nil || h.owner != nil {
		t.Fatal("failed publication retained state")
	}

	h2, _, _ := beginEnrollmentFixture(t)
	p := h2.enrollment
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			if err := p.close(); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if err := h2.Close(); err != nil {
		t.Fatal(err)
	}
	if release, err := acquireWorkspaceOwnership(h2.databasePath, true); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
	assertEnrollmentUnpublished(t, h2)
	for _, op := range []string{"enrollment-begin", "enrollment-confirm"} {
		if !h2.ExitOnCancel(op) {
			t.Fatal("cancelled authentication could retain key")
		}
	}
	if h2.ExitOnCancel("enrollment-cancel") {
		t.Fatal("ordinary cancel classified as key installation")
	}
}

func TestVaultEnrollmentPendingCleanup(t *testing.T) {
	for _, mode := range []string{"cancel", "close", "timer"} {
		t.Run(mode, func(t *testing.T) {
			h, response, code := beginEnrollmentFixture(t)
			p := h.enrollment
			switch mode {
			case "cancel":
				if _, err := h.Handle(context.Background(), "enrollment-cancel", nil); err != nil {
					t.Fatal(err)
				}
			case "close":
				if err := h.Close(); err != nil {
					t.Fatal(err)
				}
			case "timer":
				// Exercise the actual autonomous expiry callback without waiting five minutes.
				p.mu.Lock()
				p.timer.Reset(time.Millisecond)
				p.mu.Unlock()
				deadline := time.Now().Add(5 * time.Second)
				for p.material.Locked() && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
			}
			p.mu.Lock()
			closed := p.closed
			p.mu.Unlock()
			if !closed || p.material.With(func([]byte) error { return nil }) != securemem.ErrClosed {
				t.Fatal("pending material survived cleanup")
			}
			if _, err := h.Handle(context.Background(), "enrollment-confirm", enrollmentConfirmation(t, response, code)); err == nil {
				t.Fatal("closed enrollment published")
			}
			if release, err := acquireWorkspaceOwnership(h.databasePath, false); err != nil {
				t.Fatal("cleanup retained lease", err)
			} else {
				release()
			}
			assertEnrollmentUnpublished(t, h)
		})
	}
}

func TestVaultEnrollmentProcessExitCleansPending(t *testing.T) {
	for _, mode := range []string{"eof", "lock"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			path := filepath.Join(t.TempDir(), "workspace.db")
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVaultCLIProcess$")
			cmd.Env = append(os.Environ(), "WORMHOLE_TEST_VAULT_CHILD=1", "WORMHOLE_TEST_VAULT_DATABASE="+path)
			var diagnostics bytes.Buffer
			cmd.Stderr = &diagnostics
			input, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			output, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				cancel()
				if !waited {
					_ = cmd.Wait()
				}
			}()
			private, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			payload := vaultInput(t, map[string]any{"password": []byte("process-enrollment-fixture"), "publicKey": private.PublicKey().Bytes()})
			encoder := json.NewEncoder(input)
			if err := encoder.Encode(vaultwire.Request{Version: 1, ID: 1, Operation: "enrollment-begin", Payload: payload}); err != nil {
				t.Fatal(err)
			}
			var response vaultwire.Response
			if err := json.NewDecoder(output).Decode(&response); err != nil || response.Error != "" || response.ID != 1 {
				t.Fatal("native enrollment failed", err, response.Error)
			}
			var enrollment enrollmentResponse
			if err := json.Unmarshal(response.Result, &enrollment); err != nil || len(enrollment.Bundle.Ciphertext) != 92 {
				t.Fatal("invalid sealed native response", err)
			}
			if mode == "lock" {
				if err := encoder.Encode(vaultwire.Request{Version: 1, ID: 2, Operation: "lock"}); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := input.Close(); err != nil {
					t.Fatal(err)
				}
			}
			err = cmd.Wait()
			waited = true
			if err != nil || diagnostics.Len() != 0 {
				t.Fatal("native cleanup failed", err)
			}
			assertEnrollmentUnpublished(t, &vaultFoundationHandler{databasePath: path})
			if release, err := acquireWorkspaceOwnership(path, true); err != nil {
				t.Fatal("process left lease", err)
			} else {
				release()
			}
		})
	}
}
