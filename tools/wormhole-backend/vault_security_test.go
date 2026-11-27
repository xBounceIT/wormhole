package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func profileTestVault(t *testing.T, preset vault.KDFPreset) (*vaultFoundationHandler, vault.SlotFile, []byte) {
	t.Helper()
	ctx := context.Background()
	doc, key := localSlotFixture(t)
	t.Cleanup(func() { vault.Wipe(key) })
	password, err := vault.CreatePasswordSlot(ctx, doc.VaultID, uuid.NewString(), 1, key, []byte("local profile fixture"), nil, preset)
	if err != nil {
		t.Fatal(err)
	}
	doc.Initializing = true
	doc.Slots = append(doc.Slots, password)
	path := filepath.Join(t.TempDir(), "vault.db")
	owner, err := initializeVaultFiles(ctx, path, doc, key)
	if err != nil {
		t.Fatal(err)
	}
	h := &vaultFoundationHandler{databasePath: path, owner: owner}
	t.Cleanup(func() { h.Close() })
	slots, err := readVaultSlotFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return h, slots, key
}

func TestVaultProfileRelaxationRequiresNewUnlock(t *testing.T) {
	ctx := context.Background()
	h, doc, _ := profileTestVault(t, vault.KDFV1)
	owner, path := h.owner, h.databasePath
	setUser := func(floor vault.Profile) {
		p, err := owner.ReadLocalPolicy(ctx)
		if err != nil {
			t.Fatal(err)
		}
		p.Policy.Sequence++
		if _, err = owner.PutLocalPolicy(ctx, p.Policy, floor, p.Policy.Sequence-1); err != nil {
			t.Fatal(err)
		}
	}
	setUser(vault.Standard)
	if ttl, err := h.clipboardTTL(ctx); err != nil || ttl != 20*time.Second {
		t.Fatal(ttl, err)
	}
	setUser(vault.Default)
	raw, err := h.Handle(ctx, "security", nil)
	var status vaultSecurityProjection
	if err != nil || json.Unmarshal(raw, &status) != nil || status.User != "default" || status.Effective != "standard" || status.Source != "user" || !status.RetainedUntilLock {
		t.Fatal(status, err)
	}
	if _, err := h.Handle(ctx, "credential-display", nil); err != vault.ErrPolicy {
		t.Fatal("fresh authentication lost", err)
	}
	if ttl, err := h.clipboardTTL(ctx); err != nil || ttl != 20*time.Second {
		t.Fatal(ttl, err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := &vaultFoundationHandler{databasePath: path}
	defer reopened.Close()
	if _, err := reopened.Handle(ctx, "unlock", vaultInput(t, map[string]any{"vaultId": doc.VaultID, "slotId": doc.Slots[0].ID, "recoveryKey": bytes.Repeat([]byte{0x32}, 32)})); err != nil {
		t.Fatal(err)
	}
	if ttl, err := reopened.clipboardTTL(ctx); err != nil || ttl != 30*time.Second {
		t.Fatal(ttl, err)
	}
}

func TestVaultProfileTighteningRequiresFreshFactorAndPersists(t *testing.T) {
	ctx := context.Background()
	h, slots, _ := profileTestVault(t, vault.KDFV1)
	status := func(handler *vaultFoundationHandler) vaultSecurityProjection {
		t.Helper()
		raw, err := handler.Handle(ctx, "security", nil)
		var p vaultSecurityProjection
		if err != nil || json.Unmarshal(raw, &p) != nil {
			t.Fatal("read security profile", err)
		}
		return p
	}
	before := status(h)
	if !before.CanTightenToStandard || before.Effective != "default" {
		t.Fatal(before)
	}
	call := func(action []byte, factor byte) (json.RawMessage, error) {
		return h.Handle(ctx, "fresh-action", freshActionInput(t, "tighten-local-profile", action, bytes.Repeat([]byte{factor}, 32)))
	}
	action := vaultInput(t, map[string]any{"sequence": before.Sequence})
	if _, err := h.Handle(ctx, "tighten-local-profile", action); err == nil {
		t.Fatal("direct call changed the profile")
	}
	if _, err := call(action, 0x31); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"sequence":"0"}`, `{"sequence":"03"}`, `{"sequence":"3","user":"standard"}`} {
		if _, err := call([]byte(raw), 0x32); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	if _, err := call([]byte(`{"sequence":"1"}`), 0x32); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatal("stale sequence", err)
	}
	if status(h) != before {
		t.Fatal("rejected actions changed the profile")
	}
	if result, err := call(action, 0x32); err != nil || string(result) != "true" {
		t.Fatal("fresh choice", err)
	}
	after := status(h)
	if after.Effective != "standard" || after.User != "standard" || after.Source != "user" || after.Workspace != before.Workspace || after.OS != before.OS || after.CanTightenToStandard {
		t.Fatal(after)
	}
	checkpoint, err := readVaultSlotFile(h.databasePath)
	if err != nil || checkpoint.Sequence <= slots.Sequence || checkpoint.ProfileSequence != slots.ProfileSequence+1 || after.Sequence != strconv.FormatUint(checkpoint.ProfileSequence, 10) {
		t.Fatal("profile checkpoint", err)
	}
	if _, err := call(action, 0x32); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatal("replayed profile choice", err)
	}
	if _, err := call(vaultInput(t, map[string]any{"sequence": after.Sequence}), 0x32); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("redundant profile change", err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := &vaultFoundationHandler{databasePath: h.databasePath}
	defer reopened.Close()
	if _, err := reopened.Handle(ctx, "unlock", vaultInput(t, map[string]any{"vaultId": slots.VaultID, "slotId": slots.Slots[0].ID, "recoveryKey": bytes.Repeat([]byte{0x32}, 32)})); err != nil {
		t.Fatal(err)
	}
	if got := status(reopened); got != after {
		t.Fatal(got)
	}
}

func TestVaultProfileTighteningRechecksSlotsAndCheckpoint(t *testing.T) {
	ctx := context.Background()
	run := func(h *vaultFoundationHandler) error {
		_, err := h.Handle(ctx, "fresh-action", freshActionInput(t, "tighten-local-profile", []byte(`{"sequence":"3"}`), bytes.Repeat([]byte{0x32}, 32)))
		return err
	}
	t.Run("latest authenticated slots", func(t *testing.T) {
		h, slots, key := profileTestVault(t, vault.KDFV1)
		slots.Slots = slots.Slots[:1] // The recovery slot remains valid for fresh authentication.
		slots.Sequence++
		if err := writeVaultSlotFile(h.databasePath, key, slots, slots.Sequence-1); err != nil {
			t.Fatal(err)
		}
		if err := run(h); !errors.Is(err, vault.ErrPolicy) {
			t.Fatal(err)
		}
		p, err := h.owner.ReadSecurityProfile(ctx)
		if err != nil || p.CanTightenToStandard || p.User != vault.Default {
			t.Fatal(p, err)
		}
	})
	t.Run("low KDF", func(t *testing.T) {
		h, _, _ := profileTestVault(t, vault.KDFLow)
		if err := run(h); !errors.Is(err, vault.ErrPolicy) {
			t.Fatal(err)
		}
	})
	t.Run("checkpoint writer busy", func(t *testing.T) {
		h, _, _ := profileTestVault(t, vault.KDFV1)
		release, err := tryAcquireExclusiveFileLock(vaultSlotPath(h.databasePath) + ".lock")
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		if err := run(h); !errors.Is(err, vaultwire.ErrRetired) || !h.closed {
			t.Fatal("uncertain policy checkpoint left owner available", err)
		}
	})
}

func TestVaultSecurityOnlyAuthenticatedProfilesAndNoFreshAuthBypass(t *testing.T) {
	ctx := context.Background()
	locked := &vaultFoundationHandler{}
	if _, err := locked.Handle(ctx, "security", nil); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	h := vaultCredentialFixture(t)
	raw, err := h.Handle(ctx, "security", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 6 || result["sequence"] != "3" || result["workspace"] != "default" || result["user"] != "default" || result["os"] != "default" || result["effective"] != "default" || result["source"] != "workspace" {
		t.Fatal("unexpected authority projection")
	}
	if _, err := h.Handle(ctx, "security", []byte(`{}`)); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := h.Handle(canceled, "security", nil); err != context.Canceled {
		t.Fatal(err)
	}
	p, err := h.owner.ReadLocalPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p.Policy.Sequence++
	p.Policy.MinAPI = 2
	p.Policy.MaxAPI = 2
	if _, err := h.owner.PutLocalPolicy(ctx, p.Policy, vault.Default, p.Policy.Sequence-1); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "workspace", nil); !errors.Is(err, vaultwire.ErrRetired) || !errors.Is(err, vault.ErrNewerFormat) {
		t.Fatal("future policy remained accessible", err)
	}
	if !h.closed {
		t.Fatal("owner not retired")
	}

	// Standard can read metadata, but cannot use the initial unlock as the fresh
	// authentication required for writes. Real password/recovery slots satisfy it.
	doc, key := localSlotFixture(t)
	defer vault.Wipe(key)
	password, err := vault.CreatePasswordSlot(ctx, doc.VaultID, uuid.NewString(), 1, key, []byte("synthetic-password"), nil, vault.KDFV1)
	if err != nil {
		t.Fatal(err)
	}
	doc.Slots = append(doc.Slots, password)
	doc.Initializing = true
	path := filepath.Join(t.TempDir(), "vault.db")
	o, err := initializeVaultFiles(ctx, path, doc, key)
	if err != nil {
		t.Fatal(err)
	}
	standard := &vaultFoundationHandler{databasePath: path, owner: o}
	defer standard.Close()
	p, err = o.ReadLocalPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p.Policy.Sequence++
	_, standardNode, _ := vaultMigrationChoicesFixture(t, standard)
	p.Policy.Profile = vault.Standard
	if _, err = o.PutLocalPolicy(ctx, p.Policy, vault.Default, p.Policy.Sequence-1); err != nil {
		t.Fatal(err)
	}
	if _, err = standard.Handle(ctx, "workspace", nil); err != nil {
		t.Fatal(err)
	}
	raw, err = standard.Handle(ctx, "migration-report", vaultInput(t, map[string]any{"nodeId": standardNode.ID, "rowVersion": "2"}))
	if err != nil {
		t.Fatal(err)
	}
	var migration struct {
		CanDecide bool  `json:"canDecide"`
		Entries   []any `json:"entries"`
	}
	if json.Unmarshal(raw, &migration) != nil || !migration.CanDecide || len(migration.Entries) != 3 {
		t.Fatal("standard migration capabilities")
	}
	for _, op := range []string{"ssh-host-trust", "tunnel-edit", "credential-save", "credential-edit", "credential-delete", "tunnel-save", "tunnel-delete", "node-save", "node-delete", "node-delete-tree", "node-delete-trees", "node-move", "credential-clipboard-release", "credential-copy", "credential-display", "node-duplicate", "folder-save", "connection-save", "migration-decide"} {
		if _, err = standard.Handle(ctx, op, nil); err != vault.ErrPolicy {
			t.Fatal(op, err)
		}
	}
	// Fresh authority must reach the typed move and must not persist afterward.
	moveSource, moveTarget := uuid.NewString(), uuid.NewString()
	for _, id := range []string{moveSource, moveTarget} {
		if _, err := standard.owner.PutNode(ctx, vaultstore.NodeMetadata{ID: id, Kind: 0, Name: "Move folder"}, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	moveAction := vaultInput(t, map[string]any{"nodes": []map[string]any{{"id": moveSource, "rowVersion": "1"}}, "target": map[string]any{"id": moveTarget, "rowVersion": "1"}, "placement": "inside"})
	if _, err := standard.Handle(ctx, "fresh-action", freshActionInput(t, "node-move", moveAction, bytes.Repeat([]byte{0x32}, 32))); err != nil {
		t.Fatal("fresh move rejected", err)
	}
	moved, err := standard.owner.ReadNode(ctx, moveSource, 2)
	if err != nil || moved.ParentID == nil || *moved.ParentID != moveTarget {
		t.Fatal("move not committed", err)
	}
	if _, err := standard.Handle(ctx, "node-move", moveAction); err != vault.ErrPolicy {
		t.Fatal("move authority leaked", err)
	}
	duplicateAction := vaultInput(t, map[string]any{"id": standardNode.ID, "rowVersion": "2"})
	if _, err := standard.Handle(ctx, "fresh-action", freshActionInput(t, "node-duplicate", duplicateAction, bytes.Repeat([]byte{0x32}, 32))); err != nil {
		t.Fatal("fresh duplicate rejected", err)
	}
	if _, err := standard.Handle(ctx, "node-duplicate", duplicateAction); err != vault.ErrPolicy {
		t.Fatal("duplication authority leaked", err)
	}

	revealKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	revealAction := vaultInput(t, map[string]any{"nodeId": standardNode.ID, "rowVersion": "2", "requestId": uuid.NewString(), "publicKey": revealKey.PublicKey().Bytes()})
	if _, err := standard.Handle(ctx, "fresh-action", freshActionInput(t, "credential-display", revealAction, bytes.Repeat([]byte{0x32}, 32))); err != nil {
		t.Fatal("fresh reveal rejected", err)
	}
	if _, err := standard.Handle(ctx, "credential-display", revealAction); err != vault.ErrPolicy {
		t.Fatal("reveal authority leaked", err)
	}
	assertFreshClipboard(t, standard, standardNode.ID)
	assertFreshClipboardRelease(t, standard, standardNode.ID)
	freshID := uuid.NewString()
	freshSave := vaultCredentialSave(t, freshID, "0", []map[string]any{{"field": "password", "remove": false, "value": []byte("confirmed secret")}})
	if _, err := standard.Handle(ctx, "fresh-action", freshActionInput(t, "credential-save", freshSave, bytes.Repeat([]byte{0x32}, 32))); err != nil {
		t.Fatal("fresh Standard action rejected", err)
	}
	if _, err := standard.Handle(ctx, "fresh-action", freshActionInput(t, "credential-edit", vaultInput(t, credentialEditorInput()), bytes.Repeat([]byte{0x32}, 32))); err != nil {
		t.Fatal("fresh Standard credential editor rejected", err)
	}
	if _, err := standard.Handle(ctx, "fresh-action", freshActionInput(t, "tunnel-edit", vaultInput(t, tunnelEditorInput(1, `{"ProfileOvpn":"Standard profile"}`)), bytes.Repeat([]byte{0x32}, 32))); err != nil {
		t.Fatal("fresh Standard tunnel editor rejected", err)
	}
	if _, err := standard.Handle(ctx, "credential-delete", nil); err != vault.ErrPolicy {
		t.Fatal("fresh authentication leaked into a subsequent request", err)
	}
	if _, err = standard.Handle(ctx, "security", nil); err != nil {
		t.Fatal(err)
	}
	p.Policy.Sequence++
	p.Policy.Profile = vault.Hardened
	p.Policy.KDF = vault.KDFV2
	if _, err = o.PutLocalPolicy(ctx, p.Policy, vault.Default, p.Policy.Sequence-1); err != nil {
		t.Fatal(err)
	}
	if _, err = standard.Handle(ctx, "security", nil); !errors.Is(err, vaultwire.ErrRetired) {
		t.Fatal(err)
	}
}
