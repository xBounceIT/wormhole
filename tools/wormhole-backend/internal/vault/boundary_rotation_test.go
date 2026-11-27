package vault

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"slices"
	"testing"

	"github.com/google/uuid"
)

func TestPrepareBoundaryRotationRewrapsOnlyDEKsAndRetainedRecipients(t *testing.T) {
	ctx := context.Background()
	keyRef := func() KeyRef { return KeyRef{ID: uuid.New(), Version: 1} }
	public := func(seed []byte) []byte {
		t.Helper()
		key, err := ecdh.X25519().NewPrivateKey(seed)
		if err != nil {
			t.Fatal(err)
		}
		return key.PublicKey().Bytes()
	}
	org := &UserKeys{EncryptionPrivate: bytes.Repeat([]byte{12}, 32), SigningSeed: bytes.Repeat([]byte{13}, 32)}
	defer org.Wipe()
	signer := ed25519.NewKeyFromSeed(org.SigningSeed)
	defer Wipe(signer)
	orgPublic, err := org.Public()
	if err != nil {
		t.Fatal(err)
	}
	workspace, boundary, signerRef := uuid.New(), uuid.New(), keyRef()
	trust := BoundaryTrust{WorkspaceID: workspace, BoundaryID: boundary, Signer: signerRef, Organisation: orgPublic.Signing, MinimumRevision: 7}
	recovery := OrganisationRecoveryRecipient{WorkspaceID: workspace, Encryption: keyRef(), Signer: signerRef, PublicKey: orgPublic.Encryption}
	recoveryProof, err := SignOrganisationRecoveryRecipient(recovery, org.SigningSeed)
	if err != nil {
		t.Fatal(err)
	}
	viewSeed, secretSeed := bytes.Repeat([]byte{14}, 32), bytes.Repeat([]byte{15}, 32)
	defer Wipe(viewSeed)
	defer Wipe(secretSeed)
	before, err := SignBoundaryManifest(BoundaryManifest{FormatVersion: 1, WorkspaceID: workspace, BoundaryID: boundary,
		Signer: signerRef, Revision: 7, Active: true, OrgEscrow: true,
		View: BoundaryKey{keyRef(), public(viewSeed)}, Secret: BoundaryKey{keyRef(), public(secretSeed)}}, signer)
	if err != nil {
		t.Fatal(err)
	}
	retainedSeed, revokedSeed := bytes.Repeat([]byte{16}, 32), bytes.Repeat([]byte{17}, 32)
	defer Wipe(retainedSeed)
	defer Wipe(revokedSeed)
	retained, revoked := BoundaryKey{keyRef(), public(retainedSeed)}, BoundaryKey{keyRef(), public(revokedSeed)}
	otherAuthor := UserKeys{SigningSeed: bytes.Repeat([]byte{18}, 32), EncryptionPrivate: bytes.Repeat([]byte{19}, 32)}
	defer otherAuthor.Wipe()
	otherPublic, err := otherAuthor.Public()
	if err != nil {
		t.Fatal(err)
	}
	writer := KeyCopyTrust{Issuer: keyRef(), Public: otherPublic.Signing}
	dekSeed := bytes.Repeat([]byte{20}, 32)
	defer Wipe(dekSeed)
	sealCopy := func(key, holder KeyRef, recipient, seed, signing []byte, issuer KeyRef) RewrappedKeyCopy {
		t.Helper()
		binding := KeyCopyBinding{WorkspaceID: workspace, Key: key, Holder: holder, Issuer: issuer}
		copy, err := SealKeyCopy(seed, binding, recipient, signing)
		if err != nil {
			t.Fatal(err)
		}
		return RewrappedKeyCopy{Binding: binding, Copy: copy}
	}
	makeRoot := func(purpose BoundaryPurpose, key BoundaryKey, seed []byte, recipients ...BoundaryKey) BoundaryRootRotation {
		t.Helper()
		escrow := sealCopy(key.Key, recovery.Encryption, recovery.PublicKey, seed, org.SigningSeed, signerRef)
		dek := sealCopy(keyRef(), key.Key, key.Public, dekSeed, otherAuthor.SigningSeed, writer.Issuer)
		return BoundaryRootRotation{Purpose: purpose, Escrow: escrow.Copy,
			Recipients: append([]BoundaryKey{{recovery.Encryption, recovery.PublicKey}}, recipients...),
			DEKs:       []BoundaryRotationDEK{{Binding: dek.Binding, Copy: dek.Copy, Issuer: writer}}}
	}
	view := makeRoot(BoundaryView, before.View, viewSeed, retained, revoked)
	secret := makeRoot(BoundarySecret, before.Secret, secretSeed, retained)
	binding := SharedValueBinding{WorkspaceID: workspace, OwnerKind: "credential", OwnerID: uuid.New(), Field: "password", Version: 1, DEK: secret.DEKs[0].Binding.Key}
	value, err := SealSharedValue(dekSeed, binding, []byte("existing synthetic credential"))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := PrepareBoundaryRotation(ctx, before, trust, recovery, recoveryProof, org, []BoundaryRootRotation{secret})
	if err != nil || rotated == nil || len(rotated.Copies) != 3 {
		t.Fatal("could not rotate the Secret root in isolation", err)
	}
	next := rotated.Manifest
	if next.Revision != 8 || next.View.Key != before.View.Key || !bytes.Equal(next.View.Public, before.View.Public) ||
		next.Secret.Key.ID != before.Secret.Key.ID || next.Secret.Key.Version != 2 ||
		bytes.Equal(next.Secret.Public, before.Secret.Public) || next.PreviousSecret != nil {
		t.Fatal("rotation changed the unaffected view key or retained the previous secret root")
	}
	for _, copy := range rotated.Copies {
		if copy.Binding.Holder == revoked.Key || copy.Binding.Holder == before.Secret.Key || copy.Binding.Issuer != signerRef {
			t.Fatal("rotation retained access for an excluded holder or emitted an uncertified copy")
		}
	}
	issuer := KeyCopyTrust{Issuer: signerRef, Public: orgPublic.Signing}
	retainedCopy := rotated.Copies[1]
	if seed, err := OpenBoundaryKeyCopy(revokedSeed, retainedCopy.Binding, retainedCopy.Copy, issuer, next, trust, BoundarySecret); err == nil || seed != nil {
		t.Fatal("the removed recipient opened the newly published root")
	}
	rootSeed, err := OpenBoundaryKeyCopy(retainedSeed, retainedCopy.Binding, retainedCopy.Copy, issuer, next, trust, BoundarySecret)
	if err != nil {
		t.Fatal(err)
	}
	defer Wipe(rootSeed)
	dekCopy := rotated.Copies[2]
	plain, err := OpenSharedValue(rootSeed, next.Secret.Key, binding, dekCopy.Copy, issuer, value, next, trust)
	defer Wipe(plain)
	if err != nil || !bytes.Equal(plain, []byte("existing synthetic credential")) {
		t.Fatal("the encrypted value changed during rewrap", err)
	}
	if raw, err := OpenSharedValue(secretSeed, next.Secret.Key, binding, dekCopy.Copy, issuer, value, next, trust); err == nil || raw != nil {
		t.Fatal("the old boundary seed opened a replacement DEK copy")
	}
	both, err := PrepareBoundaryRotation(ctx, before, trust, recovery, recoveryProof, org, []BoundaryRootRotation{view, secret})
	if err != nil || both.Manifest.View.Key.Version != 2 || both.Manifest.Secret.Key.Version != 2 || len(both.Copies) != 7 {
		t.Fatal("simultaneous View and Secret rotation could not replace the full copy set", err)
	}
	t.Run("PersonalOrganisationCustody", func(t *testing.T) {
		owner := uuid.New()
		personal := before
		personal.OwnerUserID = owner
		personal, err := SignBoundaryManifest(personal, signer)
		if err != nil {
			t.Fatal(err)
		}
		root := makeRoot(BoundarySecret, personal.Secret, secretSeed)
		approved := []BoundaryRootRotation{root}
		next, err := PreparePersonalBoundaryRotation(ctx, personal, trust, owner, recovery, recoveryProof, org, approved)
		if err != nil || next.Manifest.OwnerUserID != owner || next.Manifest.Secret.Key.Version != 2 ||
			len(next.Copies) != 2 || next.Copies[0].Binding.Holder != recovery.Encryption {
			t.Fatal("a personal root did not advance under exclusive organisation custody", err)
		}
		for _, invalidOwner := range []uuid.UUID{uuid.Nil, uuid.New()} {
			if result, err := PreparePersonalBoundaryRotation(ctx, personal, trust, invalidOwner, recovery, recoveryProof, org, approved); result != nil || err != ErrPolicy {
				t.Fatal("rotation accepted a different owner", err)
			}
		}
		if result, err := PrepareBoundaryRotation(ctx, personal, trust, recovery, recoveryProof, org, approved); result != nil || err != ErrPolicy {
			t.Fatal("shared rotation accepted a personal root", err)
		}
		for _, recipients := range [][]BoundaryKey{nil, {retained}, {root.Recipients[0], retained}} {
			root.Recipients = recipients
			if result, err := PreparePersonalBoundaryRotation(ctx, personal, trust, owner, recovery, recoveryProof, org, []BoundaryRootRotation{root}); result != nil || err != ErrPolicy {
				t.Fatal("personal rotation accepted a different recipient set", err)
			}
		}
	})
	for _, tc := range []struct {
		name string
		edit func(*BoundaryRootRotation)
		want error
	}{
		{"missing recovery recipient", func(root *BoundaryRootRotation) { root.Recipients = root.Recipients[1:] }, ErrPolicy},
		{"unrecognised root purpose", func(root *BoundaryRootRotation) { root.Purpose = "other" }, ErrFormat},
		{"duplicate recipient", func(root *BoundaryRootRotation) {
			root.Recipients = append(slices.Clone(root.Recipients), root.Recipients[0])
		}, ErrFormat},
		{"different DEK scope", func(root *BoundaryRootRotation) { root.DEKs[0].Binding.Holder = before.View.Key }, ErrAuthentication},
		{"tampered copy signature", func(root *BoundaryRootRotation) {
			root.DEKs[0].Copy.Signature = bytes.Clone(root.DEKs[0].Copy.Signature)
			root.DEKs[0].Copy.Signature[0] ^= 1
		}, ErrAuthentication},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := secret
			bad.DEKs = append([]BoundaryRotationDEK(nil), secret.DEKs...)
			tc.edit(&bad)
			if p, err := PrepareBoundaryRotation(ctx, before, trust, recovery, recoveryProof, org, []BoundaryRootRotation{bad}); err != tc.want || p != nil {
				t.Fatal("invalid rotation produced publishable copies", err)
			}
		})
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if p, err := PrepareBoundaryRotation(canceled, before, trust, recovery, recoveryProof, org, []BoundaryRootRotation{secret}); err != context.Canceled || p != nil {
		t.Fatal("canceled rotation produced publishable copies", err)
	}
}
