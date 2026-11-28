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
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestSharedRecoveryBackupSealsSnapshotAndDisplaysGeneratedCode(t *testing.T) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "workspace-recovery.json")
	snapshot := &sharedpg.WorkspaceRecoverySnapshot{FormatVersion: 1, WorkspaceID: uuid.New(), Records: []sharedpg.WorkspaceRecoveryRecord{
		{Relation: "nodes", Body: json.RawMessage(`{"name":"synthetic project name"}`)},
		{Relation: "secret_values", Body: json.RawMessage(`{"envelope":"already-encrypted-contents"}`)},
	}}
	ctx := context.Background()
	reply, err := saveSharedRecoveryBackup(ctx, path, private.PublicKey().Bytes(), snapshot)
	if err != nil || reply.Status != "exported" || reply.VaultID != snapshot.WorkspaceID.String() || reply.Bundle == nil {
		t.Fatal("recovery backup was not published with a sealed display", err)
	}
	key, err := hpke.NewDHKEMPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	info := []byte("wormhole/v1/recovery-display")
	for _, field := range []string{reply.VaultID, reply.ExportID} {
		info = binary.BigEndian.AppendUint32(info, uint32(len(field)))
		info = append(info, field...)
	}
	receiver, err := hpke.NewRecipient(reply.Bundle.Enc, key, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		t.Fatal(err)
	}
	code, err := receiver.Open(nil, reply.Bundle.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(code)
	recoveryKey, err := vault.ParseRecoveryKey(code)
	if err != nil || len(recoveryKey) != 32 {
		t.Fatal("expected a generated recovery code", err)
	}
	vault.Wipe(recoveryKey)
	raw, err := os.ReadFile(path)
	if err != nil || bytes.Contains(raw, code) || bytes.Contains(raw, []byte("synthetic project name")) {
		t.Fatal("backup disclosed the generated code or workspace data", err)
	}
	var document backupDocument
	if json.Unmarshal(raw, &document) != nil || document.SchemaVersion != 3 || document.Payload != nil ||
		document.Encryption != backupEncryptionAESGCM || document.EncryptedPayload == nil {
		t.Fatal("wrong encrypted backup document")
	}
	if got, err := unsealBackupPayload(*document.EncryptedPayload, "unrelated"); got != nil || !errors.Is(err, errBackupBadPassword) {
		t.Fatal("unrelated password opened the export", err)
	}
	plain, err := unsealBackupPayload(*document.EncryptedPayload, string(code))
	if err != nil {
		t.Fatal("generated code could not open the backup", err)
	}
	defer vault.Wipe(plain)
	want, err := json.Marshal(snapshot)
	if err != nil || !bytes.Equal(plain, want) {
		t.Fatal("encrypted export changed the snapshot", err)
	}
	if repeated, err := saveSharedRecoveryBackup(ctx, path, private.PublicKey().Bytes(), snapshot); err != nil || repeated.Status != "save-failed" || repeated.Bundle != nil {
		t.Fatal("export overwrote a previously published file", err)
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, raw) {
		t.Fatal("the existing backup changed", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := saveSharedRecoveryBackup(cancelled, path, private.PublicKey().Bytes(), snapshot); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled export attempted publication", err)
	}
}

type sharedRecoveryExportProbe struct {
	*credentialReleaseProbe
	t *testing.T
}

func (p sharedRecoveryExportProbe) ReadWorkspaceRecoverySnapshot(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, []byte, []byte) (*sharedpg.WorkspaceRecoverySnapshot, error) {
	p.t.Fatal("unverified transport released an export snapshot")
	return nil, sharedpg.ErrConfiguration
}

func TestVaultRecoveryExportRefusesUnverifiedTransportAndInvalidInputs(t *testing.T) {
	const op = "shared-recovery-export"
	ctx := context.Background()
	controller, probe, _, _, _, _, _, _ := credentialControllerFixture(t)
	controller.session = sharedRecoveryExportProbe{probe, t}
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: controller}}
	target := filepath.Join(t.TempDir(), "export.json")
	for _, fields := range []map[string]any{
		{"path": "relative.json", "recipient": make([]byte, 32)},
		{"path": target, "recipient": make([]byte, 16)},
		{"path": target, "recipient": make([]byte, 32), "authentication": "invalid"},
		{"path": target, "recipient": make([]byte, 32), "password": "renderer chose password"},
	} {
		if _, err := h.Handle(ctx, op, vaultInput(t, fields)); !errors.Is(err, vaultwire.ErrProtocol) {
			t.Fatal("malformed export reached the live workspace", err)
		}
	}
	input := vaultInput(t, map[string]any{"path": target, "recipient": make([]byte, 32)})
	raw, err := h.Handle(ctx, op, input)
	if err != nil || string(raw) != `{"status":"unavailable"}` {
		t.Fatal("unverified workspace export did not fail closed", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused export wrote a backup file", err)
	}
}
