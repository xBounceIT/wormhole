package localvault

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestRootRotationClosedDatabasesRetainLeaseAndRecoveryUntilClose(t *testing.T) {
	f := rotationOwner(t)
	ctx := context.Background()
	stage, err := f.owner.StageRootRotation(ctx, filepath.Join(filepath.Dir(f.path), "journal-target.db"), f.options.Slots, f.slots, bytes.Clone(f.key))
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	if err := stage.CloseDatabases(); err != nil {
		t.Fatal(err)
	}
	if err := stage.CloseDatabases(); err != nil {
		t.Fatal("close replay", err)
	}
	if f.owner.mu.TryLock() {
		f.owner.mu.Unlock()
		t.Fatal("closed database released source lease")
	}
	if _, err := stage.Document(); err != nil {
		t.Fatal(err)
	}
	binding, envelope, err := stage.SealSourceRecovery(f.key)
	if err != nil {
		t.Fatal("closing SQLite destroyed resident recovery authority", err)
	}
	old, err := vault.Open(f.key, binding, envelope)
	defer vault.Wipe(old)
	if err != nil || !bytes.Equal(old, f.oldKey) {
		t.Fatal("recovery changed", err)
	}
	// Abort after the irreversible database close still retires the resident
	// owner. The unchanged source files can be reopened by the original factors.
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if !f.owner.closed {
		t.Fatal("aborted closed database left live source owner")
	}
	if err := stage.CloseDatabases(); !errors.Is(err, vaultstore.ErrClosed) {
		t.Fatal(err)
	}
	options := f.options
	options.Create = false
	reopened, err := Open(ctx, f.path, options, bytes.Clone(f.oldKey))
	if err != nil {
		t.Fatal("abort changed source files", err)
	}
	defer reopened.Close()
	if err := reopened.VerifyRootRotation(ctx); err != nil {
		t.Fatal("native all-record audit", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reopened.VerifyRootRotation(ctx); !errors.Is(err, vaultstore.ErrClosed) {
		t.Fatal(err)
	}
}

func TestRootRotationBarrierCannotOpenReauthenticateOrPersistCheckpoint(t *testing.T) {
	o, _, options, key := owner(t)
	ctx := context.Background()
	doc := options.Slots
	doc.FormatVersion = 3
	doc.Rotation = &vault.LocalRootRotation{ID: doc.FileID, Phase: vault.RotationPrepared, TargetRootVersion: doc.RootKeyVersion + 1, TargetSlotDigest: strings.Repeat("a", 64)}
	raw, err := vault.EncodeSlotFile(key, doc)
	if err != nil {
		t.Fatal(err)
	}
	doc, err = vault.DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.VerifyReauthentication(ctx, doc, doc.Slots[0].ID, nil, bytes.Repeat([]byte{3}, 32), nil); err == nil || errors.Is(err, ErrReauthentication) {
		t.Fatal("barrier treated as factor failure", err)
	}
	if err := o.PersistVPNSSOCheckpoints(ctx, doc, func(vault.SlotFile, []byte) error { t.Fatal("barrier checkpoint callback"); return nil }); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	options.Slots = doc
	missing := filepath.Join(t.TempDir(), "must-not-open.db")
	if opened, err := Open(ctx, missing, options, bytes.Clone(key)); opened != nil || err != vault.ErrPolicy {
		t.Fatal("barrier reached SQLite", err)
	}
	// A normal v3 checkpoint keeps its version; SSO never downgrades it to v2.
	doc.Rotation = nil
	raw, err = vault.EncodeSlotFile(key, doc)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ = vault.DecodeSlotFile(raw)
	o.profileFloor = doc.ProfileSequence + 1
	if err := o.PersistVPNSSOCheckpoints(ctx, doc, func(next vault.SlotFile, _ []byte) error {
		if next.FormatVersion != 3 {
			t.Fatal("v3 checkpoint downgraded")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
