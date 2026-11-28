package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestSharedCatalogTrustRevocationDurability(t *testing.T) {
	root, b, base, _ := sharedTrustFileFixture(t)
	org := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{55}, 32))
	defer vault.Wipe(org)
	signer := vault.KeyRef{ID: uuid.New(), Version: 1}
	policy, _ := vault.DecodeSignedPolicy(base.SignedProfile)
	policy, err := vault.SignPolicy(policy.Policy, signer.ID.String(), 1, org)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := vault.EncodeSignedPolicy(policy)
	request := sharedpg.AdmissionRequest{API: 1, AppVersion: "1.2.3", Source: "ui", WorkspaceID: b.WorkspaceID, UserID: b.UserID, DeviceID: b.DeviceID}
	admission := &sharedpg.UnverifiedAdmission{WorkspaceID: b.WorkspaceID, UserID: b.UserID, DeviceID: b.DeviceID, MinAPI: 1, MaxAPI: 1, SignedProfile: raw}
	current, err := sharedpg.NewTrustState(admission, request, sharedpg.PolicyTrust{WorkspaceID: b.WorkspaceID, SignerKeyID: signer.ID.String(), SignerKeyVersion: 1, PublicKey: org.Public().(ed25519.PublicKey), MinimumSequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	o := sharedAdmissionOptions{TrustPath: filepath.Join(t.TempDir(), "device.trust"), Binding: b}
	if err := writeSharedTrustFile(o.TrustPath, root, b, current, 0); err != nil {
		t.Fatal(err)
	}
	state := vault.UserKeyState{FormatVersion: 1, WorkspaceID: b.WorkspaceID, UserID: uuid.New(), Sequence: 3, Active: false, Encryption: vault.KeyRef{ID: uuid.New(), Version: 1}, Signing: vault.KeyRef{ID: uuid.New(), Version: 1}, MinimumEncryptionCertificate: 1, MinimumSigningCertificate: 1, Signer: signer}
	state, err = vault.SignUserKeyState(state, org)
	if err != nil {
		t.Fatal(err)
	}
	node := sharedpg.UnverifiedTreeNode{Metadata: vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Node", Kind: 1}, Boundary: uuid.New()}
	author := sharedpg.UnverifiedNodeAuthor{State: &state}
	next, err := acceptSharedCatalogObservation(o, root, current, node, author)
	if err != vault.ErrPolicy || next.Revision != current.Revision+1 {
		t.Fatal("revocation not persisted", err)
	}
	loaded, err := readSharedTrustFile(o.TrustPath, root, b, next.Revision)
	if err != nil || loaded.Catalog["author/"+state.UserID.String()].Revision != 3 {
		t.Fatal("restart lost revocation", err)
	}
	if _, err := acceptSharedCatalogObservation(o, root, loaded, node, author); err != vault.ErrPolicy {
		t.Fatal("repeat revocation", err)
	}
	if _, err := acceptSharedCatalogObservation(o, root, current, node, author); err != errSharedTrustConflict {
		t.Fatal("stale writer", err)
	}
	if _, err := acceptSharedCatalogObservation(o, root, sharedpg.TrustState{}, node, author); err != sharedpg.ErrTrustState {
		t.Fatal(err)
	}
	oldSync := privateFileDirectorySync
	t.Cleanup(func() { privateFileDirectorySync = oldSync })
	privateFileDirectorySync = func(string) error { return errors.New("test sync failure") }
	if value, err := acceptSharedCatalogObservation(o, root, loaded, node, author); err != errSharedTrustCommitUncertain || value.Revision != 0 {
		t.Fatal("uncertain persistence accepted", err)
	}
	privateFileDirectorySync = oldSync
	if _, err := acceptSharedCatalogObservation(o, root, loaded, node, author); err != vault.ErrPolicy {
		t.Fatal("durability confirmation", err)
	}
}
