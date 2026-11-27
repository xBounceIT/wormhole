package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/workspaceimport"
)

func TestPersonalImportScopeBindsOwnerAndRetainsRevocation(t *testing.T) {
	_, _, trust, m, org := boundaryTrustFixture(t)
	encode := func(m vault.BoundaryManifest) [][][]byte {
		t.Helper()
		signed, err := vault.SignBoundaryManifest(m, org)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := vault.EncodeBoundaryManifest(signed)
		if err != nil {
			t.Fatal(err)
		}
		return [][][]byte{{hex.AppendEncode(nil, raw)}}
	}
	m.OwnerUserID = trust.UserID
	m.BoundaryID = personalImportBoundaryID(m.WorkspaceID, m.OwnerUserID)
	raw := encode(m)
	next, verified, err := decodeImportBoundary(raw, trust, true, true)
	if err != nil || verified == nil || next.Catalog["boundary/"+m.BoundaryID.String()].Revision != m.Revision {
		t.Fatal("personal manifest did not bind its owner", err)
	}
	null := [][][]byte{{nil}}
	if _, empty, err := decodeImportBoundary(null, trust, true, true); empty != nil || err != nil {
		t.Fatal("missing first-time destination was treated as malformed", err)
	}
	if _, empty, err := decodeImportBoundary(null, next, true, true); empty != nil || !errors.Is(err, vault.ErrRollback) {
		t.Fatal("missing established scope authorised recreation", err)
	}
	if _, result, err := decodeImportBoundary(raw, next, false, false); result != nil || !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("private manifest was treated as the shared scope", err)
	}
	mismatch := m
	mismatch.BoundaryID = uuid.New()
	if _, result, err := decodeImportBoundary(encode(mismatch), next, true, true); result != nil || !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("a different scope was accepted even though the owner was unchanged", err)
	}
	inactive := m
	inactive.Revision++
	inactive.Active = false
	observed, result, err := decodeImportBoundary(encode(inactive), next, true, true)
	if !errors.Is(err, vault.ErrPolicy) || result != nil || observed.Catalog["boundary/"+m.BoundaryID.String()].Revision != inactive.Revision {
		t.Fatal("authentic revocation was lost or remained usable", err)
	}
	if _, result, err := decodeImportBoundary(raw, observed, true, true); result != nil || !errors.Is(err, vault.ErrRollback) {
		t.Fatal("historical root selection was accepted after revocation", err)
	}
	for _, invalid := range [][][][]byte{nil, {nil}, {{[]byte("zz")}}, {{[]byte("00")}}, {{bytes.Repeat([]byte{'a'}, 2*vault.MaxBoundaryManifestBytes+1)}}} {
		if _, result, err := decodeImportBoundary(invalid, trust, true, true); result != nil || err == nil {
			t.Fatal("unexpected database manifest was accepted")
		}
	}
}

func TestPersonalImportRootsAreIndependentlyWrappedForBothRecipients(t *testing.T) {
	owner := vault.UserKeys{EncryptionPrivate: bytes.Repeat([]byte{13}, 32), SigningSeed: bytes.Repeat([]byte{23}, 32)}
	org := vault.UserKeys{EncryptionPrivate: bytes.Repeat([]byte{39}, 32), SigningSeed: bytes.Repeat([]byte{42}, 32)}
	defer owner.Wipe()
	defer org.Wipe()
	ownerPublic, err := owner.Public()
	if err != nil {
		t.Fatal(err)
	}
	orgPublic, err := org.Public()
	if err != nil {
		t.Fatal(err)
	}
	trust := TrustState{WorkspaceID: uuid.New(), UserID: uuid.New(), Enrollment: &EnrollmentPin{Encryption: vault.KeyRef{ID: uuid.New(), Version: 1}}}
	recipient := vault.OrganisationRecoveryRecipient{WorkspaceID: trust.WorkspaceID, Encryption: vault.KeyRef{ID: uuid.New(), Version: 1},
		Signer: vault.KeyRef{ID: uuid.New(), Version: 1}, PublicKey: orgPublic.Encryption}
	orgSigning := ed25519.NewKeyFromSeed(org.SigningSeed)
	defer vault.Wipe(orgSigning)
	raw, wrapped, err := preparePersonalImportBoundary(trust, recipient, ownerPublic.Encryption, orgSigning)
	if err != nil {
		t.Fatal(err)
	}
	m, err := vault.DecodeBoundaryManifest(raw)
	var copies []personalImportCopy
	if err != nil || json.Unmarshal(wrapped, &copies) != nil || len(copies) != 4 {
		t.Fatal("expected two roots and two recipients", err)
	}
	boundaryTrust := vault.BoundaryTrust{WorkspaceID: m.WorkspaceID, BoundaryID: m.BoundaryID, Signer: recipient.Signer, Organisation: orgPublic.Signing, MinimumRevision: 1}
	signer := vault.KeyCopyTrust{Issuer: recipient.Signer, Public: orgPublic.Signing}
	for i, root := range []struct {
		key     vault.KeyRef
		purpose vault.BoundaryPurpose
	}{{m.View.Key, vault.BoundaryView}, {m.Secret.Key, vault.BoundarySecret}} {
		binding := vault.KeyCopyBinding{WorkspaceID: trust.WorkspaceID, Key: root.key, Holder: trust.Enrollment.Encryption, Issuer: recipient.Signer}
		if copies[2*i].Binding != binding {
			t.Fatal("the account copy described a different wrapping context")
		}
		self, err := vault.OpenBoundaryKeyCopy(owner.EncryptionPrivate, binding, copies[2*i].SignedKeyCopy, signer, m, boundaryTrust, root.purpose)
		defer vault.Wipe(self)
		if err != nil {
			t.Fatal("account could not unwrap its own root", err)
		}
		binding.Holder = recipient.Encryption
		if copies[2*i+1].Binding != binding {
			t.Fatal("the escrow copy described a different wrapping context")
		}
		escrow, err := vault.OpenBoundaryKeyCopy(org.EncryptionPrivate, binding, copies[2*i+1].SignedKeyCopy, signer, m, boundaryTrust, root.purpose)
		defer vault.Wipe(escrow)
		if err != nil || !bytes.Equal(self, escrow) {
			t.Fatal("organisation escrow did not preserve the original root", err)
		}
		if value, err := vault.OpenBoundaryKeyCopy(org.EncryptionPrivate, binding, copies[2*i].SignedKeyCopy, signer, m, boundaryTrust, root.purpose); err == nil || value != nil {
			vault.Wipe(value)
			t.Fatal("organisation accepted the account-only copy")
		}
	}
	if body, copies, err := preparePersonalImportBoundary(trust, recipient, []byte{1}, orgSigning); body != nil || copies != nil || err == nil {
		t.Fatal("invalid account recipient produced persistent material", err)
	}
}

func TestPersonalImportSignerResponseIsBounded(t *testing.T) {
	contextID := uuid.New()
	key := []byte(uuid.NewString())
	version := []byte("1")
	proof := bytes.Repeat([]byte{'a'}, 128)
	row := [][]byte{key, version, bytes.Repeat([]byte{'a'}, 64), bytes.Repeat([]byte{'a'}, 96), proof,
		[]byte(uuid.NewString()), version, bytes.Repeat([]byte{'a'}, 64), proof}
	m, err := parsePersonalImportSigner([][][]byte{row}, contextID)
	if err != nil || m.recipient.WorkspaceID != contextID || m.recipient.Signer.ID.String() != string(key) {
		t.Fatal("signed material projection lost its context", err)
	}
	for _, raw := range [][][][]byte{nil, {row[:8]}, {append(row[:8:8], []byte("bb"))}, {append(row[:8:8], bytes.Repeat([]byte{'z'}, 128))}} {
		if _, err := parsePersonalImportSigner(raw, contextID); err == nil {
			t.Fatal("invalid signing material passed the codec")
		}
	}
	s := NewSession()
	defer s.Close(context.Background())
	if _, m, err := s.EnsurePersonalImportBoundary(nil, TrustState{}, nil, nil); m != nil || !errors.Is(err, ErrConfiguration) {
		t.Fatal("missing native authority accepted for provisioning", err)
	}
	if _, m, err := s.WorkspaceImportBoundary(context.Background(), TrustState{}, nil, workspaceimport.Destination("other")); m != nil || !errors.Is(err, ErrConfiguration) {
		t.Fatal("unknown destination kind accepted", err)
	}
}
