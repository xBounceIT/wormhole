package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestVaultLocalBackupRoundTripPublishesBothFilesWithoutReplacing(t *testing.T) {
	ctx := context.Background()
	f := nativeRootRotationMode(t, true)
	h := &vaultFoundationHandler{databasePath: f.source, owner: f.owner}
	out := t.TempDir()
	archive := filepath.Join(out, "backup.whvault")
	exportRequest := vaultInput(t, map[string]any{"path": archive})
	if reply, err := h.Handle(ctx, "local-backup-export", exportRequest); err != nil || string(reply) != `"exported"` {
		t.Fatalf("export failed: %s %v", reply, err)
	}
	slots, err := readVaultSlotBytes(f.source)
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "local-backup-export", exportRequest); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatalf("existing backup accepted: %v", err)
	}
	if current, err := os.ReadFile(archive); err != nil || !bytes.Equal(current, source) {
		t.Fatalf("existing backup changed: %v", err)
	}
	code, err := vault.FormatRecoveryKey(bytes.Repeat([]byte{0x32}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(code)
	target := filepath.Join(out, "Restored vault")
	restore := func(selected string, factor []byte) []byte {
		return vaultInput(t, map[string]any{"path": selected, "target": target, "recoveryCode": factor})
	}
	if _, err := h.Handle(ctx, "local-backup-restore", restore(archive, code)); !errors.Is(err, vault.ErrPolicy) {
		t.Fatalf("restore accepted with an active vault: %v", err)
	}
	recovery := &vaultFoundationHandler{databasePath: f.source}
	badArchive := filepath.Join(t.TempDir(), "bad.whvault")
	if err := os.WriteFile(badArchive, source[:len(source)-1], 0o600); err != nil {
		t.Fatal(err)
	}
	wrongCode, err := vault.FormatRecoveryKey(bytes.Repeat([]byte{0x1f}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(wrongCode)
	for _, failure := range []struct {
		path string
		code []byte
		want error
	}{
		{archive, []byte("invalid"), vault.ErrAuthentication},
		{archive, wrongCode, vault.ErrAuthentication},
		{badArchive, code, vault.ErrFormat},
		{filepath.Join(out, "no-archive.whvault"), code, vaultstore.ErrStorage},
		{filepath.Join(out, "not-whole-file.json"), code, vaultwire.ErrProtocol},
	} {
		req := restore(failure.path, failure.code)
		if _, err := recovery.Handle(ctx, "local-backup-restore", req); !errors.Is(err, failure.want) {
			t.Fatalf("restore error: %v, want %v", err, failure.want)
		}
		if !bytes.Equal(req, make([]byte, len(req))) {
			t.Fatal("restore request retained the recovery code")
		}
	}
	if entries, err := os.ReadDir(out); err != nil || len(entries) != 1 {
		t.Fatalf("failed restore retained files: %v, %v", entries, err)
	}
	if reply, err := recovery.Handle(ctx, "local-backup-restore", restore(archive, code)); err != nil || string(reply) != `"restored"` {
		t.Fatalf("restore failed: %s %v", reply, err)
	}
	if _, err := recovery.Handle(ctx, "local-backup-restore", restore(archive, code)); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatalf("existing workspace accepted: %v", err)
	}
	restored := filepath.Join(target, "wormhole.db")
	if current, err := readVaultSlotBytes(restored); err != nil || !bytes.Equal(current, slots) {
		t.Fatalf("restored slot bytes changed: %v", err)
	}
	doc, err := readVaultSlotFile(restored)
	if err != nil {
		t.Fatal(err)
	}
	admitted := &vaultFoundationHandler{databasePath: restored}
	defer admitted.Close()
	input := vaultInput(t, map[string]any{"vaultId": doc.VaultID, "slotId": doc.Slots[0].ID, "recoveryCode": code})
	if _, err := admitted.Handle(ctx, "unlock", input); err != nil {
		t.Fatal(err)
	}
	if err := admitted.owner.WithSecret(ctx, f.ref, 1, func(value []byte) error {
		if string(value) != "native root transition private value" {
			t.Fatal("restored secret differs")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestVaultLocalBackupExportRejectsUnavailableOrUnsafeTargets(t *testing.T) {
	ctx := context.Background()
	f := nativeRootRotationMode(t, true)
	h := &vaultFoundationHandler{databasePath: f.source, owner: f.owner}
	out := t.TempDir()
	for _, tc := range []struct {
		path string
		want error
	}{
		{"relative.whvault", vaultwire.ErrProtocol},
		{filepath.Join(out, "archive.json"), vaultwire.ErrProtocol},
		{filepath.Join(filepath.Dir(f.source), "keys", "backup.whvault"), vaultwire.ErrProtocol},
		{filepath.Join(out, "missing", "archive.whvault"), vaultstore.ErrStorage},
	} {
		if _, err := h.Handle(ctx, "local-backup-export", vaultInput(t, map[string]any{"path": tc.path})); !errors.Is(err, tc.want) {
			t.Fatalf("export error: %v, want %v", err, tc.want)
		}
	}
	locked := &vaultFoundationHandler{databasePath: f.source}
	if _, err := locked.Handle(ctx, "local-backup-export", vaultInput(t, map[string]any{"path": filepath.Join(out, "archive.whvault")})); !errors.Is(err, vault.ErrPolicy) {
		t.Fatalf("locked export accepted: %v", err)
	}
	plain := nativeRootRotationMode(t, false)
	plainHandler := &vaultFoundationHandler{databasePath: plain.source, owner: plain.owner}
	if _, err := plainHandler.Handle(ctx, "local-backup-export", vaultInput(t, map[string]any{"path": filepath.Join(out, "archive.whvault")})); !errors.Is(err, vault.ErrPolicy) {
		t.Fatalf("field-encrypted export accepted: %v", err)
	}
	if entries, err := os.ReadDir(out); err != nil || len(entries) != 0 {
		t.Fatalf("denied exports retained files: %v %v", entries, err)
	}
}

func TestVaultLocalBackupStandardRequiresFreshFactor(t *testing.T) {
	ctx := context.Background()
	doc, root := localSlotFixture(t)
	defer vault.Wipe(root)
	doc.Initializing, doc.Encrypted = true, true
	doc.Nodes = nil
	password, err := vault.CreatePasswordSlot(ctx, doc.VaultID, uuid.NewString(), doc.RootKeyVersion, root, []byte("synthetic backup factor"), nil, vault.KDFV1)
	if err != nil {
		t.Fatal(err)
	}
	doc.Slots = append(doc.Slots, password)
	path := filepath.Join(t.TempDir(), "vault.db")
	o, err := initializeVaultFiles(ctx, path, doc, root)
	if err != nil {
		t.Fatal(err)
	}
	h := &vaultFoundationHandler{databasePath: path, owner: o}
	defer h.Close()
	policy, err := o.ReadLocalPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	policy.Policy.Profile = vault.Standard
	policy.Policy.Sequence++
	if _, err := o.PutLocalPolicy(ctx, policy.Policy, vault.Default, policy.Policy.Sequence-1); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	action := vaultInput(t, map[string]any{"path": filepath.Join(out, "standard.whvault")})
	if _, err := h.Handle(ctx, "local-backup-export", action); err != vault.ErrPolicy {
		t.Fatalf("Standard export was not gated: %v", err)
	}
	wrong := freshActionInput(t, "local-backup-export", action, bytes.Repeat([]byte{0x2a}, 32))
	if _, err := h.Handle(ctx, "fresh-action", wrong); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatalf("wrong fresh factor: %v", err)
	}
	if entries, err := os.ReadDir(out); err != nil || len(entries) != 0 {
		t.Fatalf("denied export wrote files: %v %v", entries, err)
	}
	right := freshActionInput(t, "local-backup-export", action, bytes.Repeat([]byte{0x32}, 32))
	if reply, err := h.Handle(ctx, "fresh-action", right); err != nil || string(reply) != `"exported"` {
		t.Fatalf("fresh export failed: %s %v", reply, err)
	}
}

func TestVaultLocalBackupPublicationRejectsConflictAndCancellation(t *testing.T) {
	parent := t.TempDir()
	source := filepath.Join(parent, "source")
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(target, "marker")
	if err := os.WriteFile(marker, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := publishLocalBackup(ctx, source, target); err != context.Canceled {
		t.Fatalf("canceled publish error: %v", err)
	}
	if err := publishLocalBackup(context.Background(), source, target); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatalf("existing target replaced: %v", err)
	}
	if contents, err := os.ReadFile(marker); err != nil || string(contents) != "existing" {
		t.Fatalf("existing workspace changed: %v", err)
	}
}

func TestVaultLocalBackupInstallBindsReviewedArchiveAndReservesStartup(t *testing.T) {
	ctx := context.Background()
	f := nativeRootRotationMode(t, true)
	exporter := &vaultFoundationHandler{databasePath: f.source, owner: f.owner, migrationQuiesced: true}
	parent := t.TempDir()
	archive := filepath.Join(parent, "original.whvault")
	if _, err := exporter.Handle(ctx, "local-backup-export", vaultInput(t, map[string]any{"path": archive})); err != nil {
		t.Fatal(err)
	}
	newDB := filepath.Join(parent, "unused.db")
	restorer := &vaultFoundationHandler{databasePath: newDB}
	selection := vaultInput(t, map[string]any{"path": archive})
	contextJSON, err := restorer.Handle(ctx, "local-backup-inspect", selection)
	if err != nil {
		t.Fatal(err)
	}
	var reviewed struct {
		Slots       vault.SlotFileDescriptor `json:"slots"`
		Fingerprint string                   `json:"fingerprint"`
	}
	if json.Unmarshal(contextJSON, &reviewed) != nil || !reviewed.Slots.Encrypted ||
		len(reviewed.Slots.Slots) != 1 || reviewed.Slots.Slots[0].Kind != vault.SlotRecovery || len(reviewed.Fingerprint) != 64 {
		t.Fatal("missing recovery context")
	}
	code, err := vault.FormatRecoveryKey(bytes.Repeat([]byte{0x32}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(code)
	install := func(path string) (json.RawMessage, error) {
		return restorer.Handle(ctx, "local-backup-install", vaultInput(t, map[string]any{"path": path, "fingerprint": reviewed.Fingerprint, "recoveryCode": code}))
	}
	swapped := filepath.Join(parent, "different.whvault")
	raw, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if err := os.WriteFile(swapped, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := install(swapped); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatalf("unreviewed archive accepted: %v", err)
	}
	if err := os.WriteFile(newDB+"-wal", []byte("preserve fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := install(archive); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatalf("restore ignored existing journal: %v", err)
	}
	if err := os.Remove(newDB + "-wal"); err != nil {
		t.Fatal(err)
	}
	if result, err := install(archive); err != nil || string(result) != `"restored"` {
		t.Fatalf("install: %s %v", result, err)
	}
	if _, err := restorer.Handle(ctx, "startup", nil); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatalf("previous startup path offered another workspace: %v", err)
	}
	if err := requireLegacySlotAbsent(newDB); !errors.Is(err, errVaultOwnerRequired) {
		t.Fatalf("legacy startup accepted superseded path: %v", err)
	}
	if _, err := install(archive); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatalf("restore accepted overwrite: %v", err)
	}
	recovered := &vaultFoundationHandler{databasePath: filepath.Join(newDB+localBackupInstallSuffix, "wormhole.db")}
	raw, err = recovered.Handle(ctx, "startup", nil)
	var startup vaultStartupMetadata
	if err != nil || json.Unmarshal(raw, &startup) != nil || startup.Slots == nil || !startup.Slots.Encrypted || startup.Slots.VaultID != reviewed.Slots.VaultID {
		t.Fatalf("recovered workspace unavailable for startup: %v", err)
	}
}
