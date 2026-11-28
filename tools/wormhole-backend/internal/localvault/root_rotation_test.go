package localvault

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
)

type rotationOwnerFixture struct {
	owner        *Owner
	path         string
	options      OpenOptions
	oldKey, key  []byte
	slots        []vault.Slot
	credential   vaultstore.Credential
	node         vaultstore.Node
	tunnel       vaultstore.Tunnel
	state        vaultstore.LocalState
	standalone   vaultstore.SecretRef
	statePayload []byte
	password     []byte
}

func rotationOwner(t *testing.T) rotationOwnerFixture {
	t.Helper()
	ctx := context.Background()
	o, path, opts, oldKey := owner(t)
	key := vault.NewRecoveryKey()
	t.Cleanup(func() { vault.Wipe(key) })
	password := []byte("native test rotation password")
	p, err := vault.CreatePasswordSlot(ctx, opts.Identity.WorkspaceID, uuid.NewString(), 2, key, password, nil, vault.KDFV1)
	if err != nil {
		t.Fatal(err)
	}
	r, err := vault.CreateRecoverySlot(opts.Identity.WorkspaceID, uuid.NewString(), 2, key, bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	f := rotationOwnerFixture{owner: o, path: path, options: opts, oldKey: oldKey, key: key, slots: []vault.Slot{p, r}, password: password}
	f.statePayload = bytes.Repeat([]byte("native-root-rotation-private-state"), vault.MaxSecretBytes/33+1)
	for _, deleted := range []bool{false, true} {
		c, err := o.ImportCredential(ctx, draft(), "2020-01-02T03:04:05Z", []SecretChange{{Field: "password", Value: []byte("root-rotation-private-password")}})
		if err != nil {
			t.Fatal(err)
		}
		n, err := o.PutNode(ctx, nodeDraft(), []SecretChange{{Field: "notes", Value: []byte("root-rotation-private-notes")}}, 0)
		if err != nil {
			t.Fatal(err)
		}
		v, err := o.PutTunnel(ctx, tunnelDraft(), []byte(`{"ProfileOvpn":"root-rotation-private-configuration"}`), 0)
		if err != nil {
			t.Fatal(err)
		}
		state, err := o.PutLocalState(ctx, "azure-refresh", uuid.NewString(), f.statePayload, 0)
		if err != nil {
			t.Fatal(err)
		}
		if deleted {
			if err := o.DeleteCredential(ctx, c.ID, c.RowVersion); err != nil {
				t.Fatal(err)
			}
			if err := o.DeleteNode(ctx, n.ID, n.RowVersion); err != nil {
				t.Fatal(err)
			}
			if err := o.DeleteTunnel(ctx, v.ID, v.RowVersion); err != nil {
				t.Fatal(err)
			}
			if _, err := o.DeleteLocalState(ctx, state.Kind, state.ScopeID, state.RowVersion); err != nil {
				t.Fatal(err)
			}
		} else {
			f.credential, f.node, f.tunnel, f.state = c, n, v, state
		}
	}
	f.standalone = vaultstore.SecretRef{OwnerKind: "slot-value", OwnerID: uuid.NewString(), Field: "password"}
	if _, err := o.Put(ctx, f.standalone, []byte("root-rotation-native-standalone"), 0); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestEncryptedRootRotationRetriesAfterStageConflict(t *testing.T) {
	ctx := context.Background()
	f := rotationOwner(t)
	stagePath := filepath.Join(filepath.Dir(f.path), "encrypted-stage.db")
	const existing = "unrelated stage destination"
	if err := os.WriteFile(stagePath, []byte(existing), 0600); err != nil {
		t.Fatal(err)
	}
	borrowed := bytes.Clone(f.key)
	if _, err := f.owner.StageEncryptedRootRotation(ctx, stagePath, f.options.Slots, f.slots, borrowed); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatalf("existing stage was not refused: %v", err)
	}
	if !bytes.Equal(borrowed, make([]byte, 32)) {
		t.Fatal("failed staging retained the new root copy")
	}
	if raw, err := os.ReadFile(stagePath); err != nil || string(raw) != existing {
		t.Fatal("failed staging modified the existing file", err)
	}
	stagePath = filepath.Join(filepath.Dir(f.path), "retry-stage.db")
	stage, err := f.owner.StageEncryptedRootRotation(ctx, stagePath, f.options.Slots, f.slots, bytes.Clone(f.key))
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	doc, err := stage.Document()
	if err != nil || !doc.Encrypted {
		t.Fatal("new storage mode missing from authenticated document", err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.ReadNode(ctx, f.node.ID, 1); err != nil {
		t.Fatal("unpublished stage changed the source owner", err)
	}
}

func TestRootRotationOwnerReencryptsAndResealsCompleteNativeGraph(t *testing.T) {
	f := rotationOwner(t)
	ctx := context.Background()
	ref := vaultstore.SecretRef{OwnerKind: "credential", OwnerID: f.credential.ID, Field: "password"}
	old, err := f.owner.store.ReadSecret(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(f.path), "rotation.db")
	input := bytes.Clone(f.key)
	stage, err := f.owner.StageRootRotation(ctx, path, f.options.Slots, f.slots, input)
	if err != nil {
		t.Fatal("native graph rotation", err)
	}
	defer stage.Close()
	if !bytes.Equal(input, make([]byte, len(input))) {
		t.Fatal("new root input retained")
	}
	if f.owner.mu.TryLock() {
		f.owner.mu.Unlock()
		t.Fatal("source writes not frozen")
	}
	if _, err := json.Marshal(stage); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("native stage serialized", err)
	}
	counts, err := stage.Inventory()
	if err != nil || counts != (vaultstore.RootRotationCounts{Credentials: 2, Tunnels: 2, Nodes: 2, LocalStates: 2, Secrets: 11}) {
		t.Fatal("rotation omitted live/deleted records", counts, err)
	}
	doc, err := stage.Document()
	if err != nil || doc.RootKeyVersion != 2 || doc.Sequence != f.options.Slots.Sequence+vault.RootRotationSequenceSpan || doc.FileEpoch != 2 || doc.ProfileSequence != 1 {
		t.Fatal("target slot epoch", err)
	}
	if err := vault.VerifySlotFile(f.key, doc, doc.VaultID, doc.FileID, doc.Sequence); err != nil {
		t.Fatal(err)
	}
	opened, err := vault.OpenPasswordSlot(ctx, doc.VaultID, doc.Slots[0], f.password, nil)
	defer vault.Wipe(opened)
	if err != nil || !bytes.Equal(opened, f.key) {
		t.Fatal("new factors do not recover new root", err)
	}
	binding, envelope, err := stage.SealSourceRecovery(f.key)
	if err != nil {
		t.Fatal(err)
	}
	source, err := vault.Open(f.key, binding, envelope)
	defer vault.Wipe(source)
	if err != nil || !bytes.Equal(source, f.oldKey) {
		t.Fatal("source recovery escrow", err)
	}
	if _, _, err := stage.SealSourceRecovery(bytes.Repeat([]byte{0x72}, 32)); err == nil {
		t.Fatal("wrong new key accepted for recovery escrow")
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if !f.owner.mu.TryLock() {
		t.Fatal("cancelled stage did not unfreeze original")
	}
	f.owner.mu.Unlock()
	// The original remains usable until the native journal commits retirement.
	if err := f.owner.WithCredentialSecret(ctx, f.credential.ID, "password", 1, func(value []byte) error { return nil }); err != nil {
		t.Fatal("unpublished rotation changed original", err)
	}
	opts := f.options
	opts.Create = false
	opts.Identity.Root.Version = 2
	opts.Slots = doc
	rotated, err := Open(ctx, path, opts, bytes.Clone(f.key))
	if err != nil {
		t.Fatal("new root cannot reopen persisted target", err)
	}
	defer rotated.Close()
	current, err := rotated.store.ReadSecret(ctx, ref)
	if err != nil || current.RowVersion != old.RowVersion || current.DEK.ID != old.DEK.ID || current.DEK.Version != old.DEK.Version+1 || bytes.Equal(current.Envelope.Ciphertext, old.Envelope.Ciphertext) {
		t.Fatal("current field not rotated independently", err)
	}
	if _, err := vault.Open(f.oldKey, copyBinding(opts.Identity, current), current.Copy.Envelope); err != vault.ErrAuthentication {
		t.Fatal("old root can open new DEK", err)
	}
	if err := rotated.WithCredentialSecret(ctx, f.credential.ID, "password", 1, func(raw []byte) error {
		if string(raw) != "root-rotation-private-password" {
			t.Fatal("password changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := rotated.WithNodeField(ctx, f.node.ID, "notes", 1, func(raw []byte) error {
		if string(raw) != "root-rotation-private-notes" {
			t.Fatal("notes changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := rotated.WithLocalState(ctx, f.state.Kind, f.state.ScopeID, 1, func(raw []byte) error {
		if !bytes.Equal(raw, f.statePayload) {
			t.Fatal("multi-chunk native state changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if c, err := rotated.ReadCredential(ctx, f.credential.ID, 1); err != nil || c.CreatedAt != f.credential.CreatedAt {
		t.Fatal("migration provenance changed", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || bytes.Contains(raw, []byte("root-rotation-private-password")) || bytes.Contains(raw, []byte("root-rotation-native-standalone")) || bytes.Contains(raw, f.key) || bytes.Contains(raw, f.oldKey) {
		t.Fatal("target file contains plaintext or root material", err)
	}
}

func TestRootRotationOwnerRetainsNewAuthenticatedFloorsOnRejection(t *testing.T) {
	f := rotationOwner(t)
	doc := f.options.Slots
	doc.Sequence++
	doc.Nodes = []vault.NodeHighWater{{NodeID: f.node.ID, Revision: f.node.RowVersion + 1}}
	raw, err := vault.EncodeSlotFile(f.oldKey, doc)
	if err != nil {
		t.Fatal(err)
	}
	doc, err = vault.DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := f.owner.StageRootRotation(context.Background(), filepath.Join(filepath.Dir(f.path), "refused.db"), doc, f.slots, bytes.Clone(f.key))
	if stage != nil {
		_ = stage.Close()
	}
	if stage != nil || !errors.Is(err, vault.ErrRollback) {
		t.Fatal("newer authenticated floor did not deny old source", err)
	}
	if _, err := f.owner.ReadCatalog(context.Background(), 8*1024*1024); err != vault.ErrRollback {
		t.Fatal("authenticated observation forgotten after failed rotation", err)
	}
}

func TestRootRotationOwnerRefusesInvalidRequestsBeforeCreatingAStage(t *testing.T) {
	f := rotationOwner(t)
	for _, mode := range []string{"cancel", "key-size", "reused-key", "bad-auth", "future", "initializing", "epoch-overflow", "root-overflow", "wrong-root", "missing-recovery", "unsupported-slot", "wrong-slot-version", "weak-slot", "bad-slot-id", "bad-slot-salt", "busy", "sso-quarantine", "bitwarden-quarantine"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			doc := f.options.Slots
			slots := append([]vault.Slot(nil), f.slots...)
			input := bytes.Clone(f.key)
			switch mode {
			case "cancel":
				cancel()
			case "key-size":
				input = make([]byte, 31)
			case "reused-key":
				input = bytes.Clone(f.oldKey)
			case "bad-auth":
				doc.Authentication = bytes.Repeat([]byte{0x55}, 32)
			case "future":
				doc.FormatVersion = vault.SlotFileFormatVersion + 1
			case "initializing":
				doc.Initializing = true
			case "epoch-overflow":
				doc.FileEpoch = ^uint64(0)
			case "root-overflow":
				doc.RootKeyVersion = ^uint32(0)
			case "wrong-root":
				doc.RootKeyID = uuid.NewString()
			case "missing-recovery":
				slots = slots[:1]
			case "unsupported-slot":
				slots[0].Kind = vault.SlotUnprotected
			case "wrong-slot-version":
				slots[0].WrappedKey.KeyVersion = 1
			case "weak-slot":
				slots[0].Preset = vault.KDFLow
			case "bad-slot-id":
				slots[0].ID = "invalid"
			case "bad-slot-salt":
				slots[0].Salt = nil
			case "busy":
				f.owner.quickTargets = map[string]*quickTargetStage{"busy": nil}
				defer func() { f.owner.quickTargets = nil }()
			case "sso-quarantine":
				f.owner.vpnSSOTransferFailure = true
				defer func() { f.owner.vpnSSOTransferFailure = false }()
			case "bitwarden-quarantine":
				f.owner.bitwardenTransferFailure = true
				defer func() { f.owner.bitwardenTransferFailure = false }()
			}
			path := filepath.Join(filepath.Dir(f.path), mode+".db")
			stage, err := f.owner.StageRootRotation(ctx, path, doc, slots, input)
			if stage != nil {
				_ = stage.Close()
			}
			if err == nil || stage != nil || !bytes.Equal(input, make([]byte, len(input))) {
				t.Fatal("invalid request returned a stage or retained key", err)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid request created stage data", err)
			}
			if !f.owner.mu.TryLock() {
				t.Fatal("invalid request retained source lease")
			}
			f.owner.mu.Unlock()
		})
	}
}

func TestRootRotationOwnerCancellationAndExplicitSourceRetirement(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "retire", true: "cancel"}[cancelled], func(t *testing.T) {
			f := rotationOwner(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stage, err := f.owner.StageRootRotation(ctx, filepath.Join(filepath.Dir(f.path), "stage.db"), f.options.Slots, f.slots, bytes.Clone(f.key))
			if err != nil {
				t.Fatal(err)
			}
			defer stage.Close()
			first, err := stage.Document()
			if err != nil {
				t.Fatal(err)
			}
			first.Slots[0].WrappedKey.Ciphertext[0] ^= 1
			second, err := stage.Document()
			if err != nil || bytes.Equal(first.Slots[0].WrappedKey.Ciphertext, second.Slots[0].WrappedKey.Ciphertext) {
				t.Fatal("caller mutated native slot authority", err)
			}
			if cancelled {
				cancel()
				if _, _, err := stage.SealSourceRecovery(f.key); err != context.Canceled {
					t.Fatal("cancelled stage loaned source key", err)
				}
				if err := stage.RetireSource(); err != context.Canceled || f.owner.closed {
					t.Fatal("cancelled stage retired original", err)
				}
			} else {
				if err := stage.RetireSource(); err != nil || !f.owner.closed {
					t.Fatal("explicit native retirement failed", err)
				}
				if _, _, err := stage.SealSourceRecovery(f.key); err == nil {
					t.Fatal("retired root still available")
				}
			}
			if err := stage.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := stage.Document(); err != vaultstore.ErrClosed {
				t.Fatal("closed stage returned slot document", err)
			}
			if _, err := stage.Inventory(); err != vaultstore.ErrClosed {
				t.Fatal("closed stage returned inventory", err)
			}
			if _, _, err := stage.SealSourceRecovery(f.key); err != vaultstore.ErrClosed {
				t.Fatal("closed stage returned key escrow", err)
			}
			if err := stage.RetireSource(); err != vaultstore.ErrClosed {
				t.Fatal("closed stage retired source", err)
			}
		})
	}
	o, path, opts, _ := owner(t)
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	key := vault.NewRecoveryKey()
	if _, err := o.StageRootRotation(context.Background(), path+".stage", opts.Slots, nil, key); err != vaultstore.ErrClosed || !bytes.Equal(key, make([]byte, 32)) {
		t.Fatal("closed owner admitted rotation or retained input", err)
	}
}

func TestRootRotationOwnerRetainsLiveAndDeletedSSOArchives(t *testing.T) {
	for _, deleted := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "deleted"}[deleted], func(t *testing.T) {
			f := rotationOwner(t)
			ctx, binding := context.Background(), vpnSSOFixture()
			id, _ := openVPNSSO(t, f.owner, binding, VPNSSOCheckpoint{})
			archive := []byte("native root rotation retained SSO archive")
			checkpoint := saveVPNSSO(t, f.owner, binding, id, archive)
			if err := f.owner.CloseVPNSSO(id); err != nil {
				t.Fatal(err)
			}
			if deleted {
				var err error
				checkpoint, err = f.owner.DeleteVPNSSO(ctx, binding, checkpoint)
				if err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(filepath.Dir(f.path), "sso-rotation.db")
			stage, err := f.owner.StageRootRotation(ctx, path, f.options.Slots, f.slots, bytes.Clone(f.key))
			if err != nil {
				t.Fatal("SSO source refused", err)
			}
			defer stage.Close()
			doc, err := stage.Document()
			if err != nil || len(doc.VPNSSO) != 1 || doc.VPNSSO[0].Revision != checkpoint.Revision || doc.VPNSSO[0].Deleted != deleted {
				t.Fatal("SSO checkpoint lost", err)
			}
			if err := stage.Close(); err != nil {
				t.Fatal(err)
			}
			opts := f.options
			opts.Create = false
			opts.Identity.Root.Version++
			opts.Slots = doc
			target, err := Open(ctx, path, opts, bytes.Clone(f.key))
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			var borrowed []byte
			if err := target.OpenVPNSSO(ctx, binding, uuid.NewString(), checkpoint, func(got VPNSSOSnapshot) error {
				if got.Checkpoint != checkpoint || (!deleted && !bytes.Equal(got.Archive, archive)) || (deleted && len(got.Archive) != 0) {
					t.Fatal("SSO content or tombstone changed")
				}
				borrowed = got.Archive
				return nil
			}); err != nil {
				t.Fatal("SSO cannot reopen after rotation", err)
			}
			if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("restored archive not wiped")
			}
		})
	}
}

func TestRootRotationOwnerRejectsCorruptKnownSSOAndRetainsItsManifestFloor(t *testing.T) {
	f := rotationOwner(t)
	ctx, binding := context.Background(), vpnSSOFixture()
	id, _ := openVPNSSO(t, f.owner, binding, VPNSSOCheckpoint{})
	checkpoint := saveVPNSSO(t, f.owner, binding, id, []byte("original archive"))
	if err := f.owner.CloseVPNSSO(id); err != nil {
		t.Fatal(err)
	}
	digest, _ := binding.digest()
	scope := vpnSSOScope(digest)
	if _, err := f.owner.PutLocalState(ctx, "vpn-sso", scope, []byte("invalid native archive header"), 1); err != nil {
		t.Fatal(err)
	}
	stage, err := f.owner.StageRootRotation(ctx, filepath.Join(filepath.Dir(f.path), "bad-sso.db"), f.options.Slots, f.slots, bytes.Clone(f.key))
	if stage != nil {
		_ = stage.Close()
	}
	if stage != nil || !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("corrupt archive became protected state", err)
	}
	if floor := f.owner.vpnSSOFloors[scope]; floor.RowVersion != 2 || floor.Checkpoint != checkpoint {
		t.Fatal("new manifest fact lost after corrupt-payload refusal")
	}
}

func TestRootRotationOwnerCryptographicCallbacksRejectIndependentCorruption(t *testing.T) {
	f := rotationOwner(t)
	ctx := context.Background()
	i, next := f.options.Identity, f.options.Identity
	next.Root.Version++
	ref := vaultstore.SecretRef{OwnerKind: "credential", OwnerID: f.credential.ID, Field: "password"}
	value, err := f.owner.store.ReadSecret(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"record-mac", "key-envelope", "value-envelope", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			changed := value
			cctx, cancel := context.WithCancel(ctx)
			defer cancel()
			switch mode {
			case "record-mac":
				changed.Copy.Signature = bytes.Repeat([]byte{0x61}, 32)
			case "key-envelope":
				changed.Copy.Envelope.Ciphertext = bytes.Clone(value.Copy.Envelope.Ciphertext)
				changed.Copy.Envelope.Ciphertext[0] ^= 1
				changed.Copy.Signature, err = recordMAC(f.oldKey, i, changed)
			case "value-envelope":
				changed.Envelope.Ciphertext = bytes.Clone(value.Envelope.Ciphertext)
				changed.Envelope.Ciphertext[0] ^= 1
				changed.Copy.Signature, err = recordMAC(f.oldKey, i, changed)
			case "cancel":
				cancel()
			}
			if err != nil {
				t.Fatal(err)
			}
			transforms := f.owner.rootRotationTransforms(cctx, i, next, f.oldKey, f.key, true)
			if _, err := transforms.Secret(changed); err == nil {
				t.Fatal("corrupt record reencrypted as valid")
			}
		})
	}
	transforms := f.owner.rootRotationTransforms(ctx, i, next, f.oldKey, f.key, true)
	c := f.credential
	c.Seal = bytes.Repeat([]byte{0x62}, 32)
	if _, err := transforms.Credential(c); err != vault.ErrAuthentication {
		t.Fatal("bad credential seal accepted", err)
	}
	n := f.node
	n.SealSignerKeyVersion++
	if _, err := transforms.Node(n); err != vault.ErrAuthentication {
		t.Fatal("foreign node signer accepted", err)
	}
	f.owner.nodeFloors[n.ID] = n.RowVersion + 1
	if _, err := transforms.Node(n); err != vault.ErrRollback {
		t.Fatal("newer node floor ignored", err)
	}
	f.owner.tunnelFloors[f.tunnel.ID] = f.tunnel.RowVersion + 1
	if _, err := transforms.Tunnel(f.tunnel); err != vault.ErrRollback {
		t.Fatal("newer tunnel floor ignored", err)
	}
	if _, err := transforms.Profile([]byte(`{`)); err == nil {
		t.Fatal("malformed profile accepted")
	}
	policy, err := f.owner.ReadLocalPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	policy.RootKeyVersion++
	raw, err := vault.EncodeLocalPolicy(f.oldKey, policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transforms.Profile(raw); err == nil {
		t.Fatal("foreign profile root accepted")
	}
}
