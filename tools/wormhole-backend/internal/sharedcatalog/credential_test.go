package sharedcatalog

import (
	"bytes"
	"crypto/ed25519"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func credentialFixture(t *testing.T) (CredentialRecord, vault.RecordSeal, vault.UserKeyCertificate, vault.UserKeyState, CredentialTrust, ed25519.PrivateKey) {
	t.Helper()
	_, _, cert, pin, key := fixture(t)
	org := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32))
	defer vault.Wipe(org)
	state, err := vault.SignUserKeyState(vault.UserKeyState{FormatVersion: vault.FormatVersion, WorkspaceID: pin.Workspace, UserID: pin.Author, Sequence: 9, Active: true, Encryption: vault.KeyRef{ID: uuid.New(), Version: 1}, Signing: pin.AuthorKey, MinimumEncryptionCertificate: 1, MinimumSigningCertificate: 3, Signer: pin.OrganisationKey}, org)
	if err != nil {
		t.Fatal(err)
	}
	record := CredentialRecord{Metadata: vaultstore.CredentialMetadata{ID: pin.Node.String(), Name: "Account", Protocol: "ssh", Kind: "password", Provider: "local"}, Fields: []vaultstore.CredentialField{{Field: "password", Version: 5, Present: true}}}
	seal, err := SignCredential(pin.Workspace, pin.Boundary, record, 7, pin.AuthorKey, key)
	if err != nil {
		t.Fatal(err)
	}
	trust := CredentialTrust{Workspace: pin.Workspace, Credential: pin.Node, Boundary: pin.Boundary, Author: pin.Author, OrganisationKey: pin.OrganisationKey, Organisation: pin.Organisation, MinimumStateSequence: 9, MinimumCertificateRevision: 3, MinimumCredentialRevision: 7}
	return record, seal, cert, state, trust, key
}

func TestCredentialFullMetadataAndManifest(t *testing.T) {
	record, seal, cert, state, trust, key := credentialFixture(t)
	if got, err := VerifyCurrentCredential(record, trust.Boundary, seal, cert, state, trust); err != nil || got != (CredentialObservation{9, 3, 7}) {
		t.Fatal(got, err)
	}
	// Every profile field is either cryptographically bound or rejected by content
	// validation. Alternate valid provider/kind records test their extra fields.
	types := reflect.TypeOf(record.Metadata)
	for i := 0; i < types.NumField(); i++ {
		t.Run(types.Field(i).Name, func(t *testing.T) {
			base := record
			base.Fields = nil
			name := types.Field(i).Name
			if strings.HasPrefix(name, "Bitwarden") {
				base.Metadata.Provider = "bitwarden"
				base.Metadata.BitwardenItemID = "item"
			}
			if name == "PrivateKeyName" || name == "CertificateName" {
				base.Metadata.Kind = "sshKey"
			}
			signed, err := SignCredential(trust.Workspace, trust.Boundary, base, 7, state.Signing, key)
			if err != nil {
				t.Fatal(err)
			}
			changed := base
			value := "changed"
			if strings.HasSuffix(name, "ID") && !strings.HasPrefix(name, "Bitwarden") {
				value = uuid.NewString()
			}
			switch name {
			case "Protocol":
				value = "rdp"
			case "Kind":
				value = "sshKey"
			case "Provider":
				value = "bitwarden"
			}
			reflect.ValueOf(&changed.Metadata).Elem().Field(i).SetString(value)
			got, err := VerifyCurrentCredential(changed, trust.Boundary, signed, cert, state, trust)
			if err == nil || got.CredentialRevision != 0 {
				t.Fatal("unsigned credential field", name, got, err)
			}
		})
	}
	for _, fields := range [][]vaultstore.CredentialField{
		nil, {}, {{Field: "password", Version: 6, Present: true}}, {{Field: "password", Version: 5, Present: false}}, {{Field: "privateKey", Version: 5, Present: true}},
	} {
		changed := record
		changed.Fields = fields
		if got, err := VerifyCurrentCredential(changed, trust.Boundary, seal, cert, state, trust); err == nil || got.CredentialRevision != 0 {
			t.Fatal("unsigned manifest", got, err)
		}
	}
	empty := record
	empty.Fields = nil
	emptySeal, err := SignCredential(trust.Workspace, trust.Boundary, empty, 7, state.Signing, key)
	if err != nil {
		t.Fatal(err)
	}
	empty.Fields = []vaultstore.CredentialField{}
	if _, err = VerifyCurrentCredential(empty, trust.Boundary, emptySeal, cert, state, trust); err != nil {
		t.Fatal("nil/empty canonicalization", err)
	}
	// Domain separation blocks a node signature even with all identity pins equal.
	node := vaultstore.NodeMetadata{ID: record.Metadata.ID, Name: "Account", Kind: 1}
	nodeSeal, err := SignNode(trust.Workspace, trust.Boundary, node, 7, state.Signing, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyCurrentCredential(record, trust.Boundary, nodeSeal, cert, state, trust); err != vault.ErrAuthentication {
		t.Fatal("cross-record seal", err)
	}
}

func TestCredentialRevocationFloorsAndTombstone(t *testing.T) {
	record, seal, cert, state, trust, key := credentialFixture(t)
	org := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32))
	defer vault.Wipe(org)
	signState := func(s vault.UserKeyState) vault.UserKeyState {
		t.Helper()
		out, err := vault.SignUserKeyState(s, org)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	check := func(s vault.UserKeyState, c vault.UserKeyCertificate, tr CredentialTrust, want CredentialObservation, wantErr error) {
		t.Helper()
		got, err := VerifyCurrentCredential(record, trust.Boundary, seal, c, s, tr)
		if got != want || err != wantErr {
			t.Fatal(got, err, want, wantErr)
		}
	}
	bad := state
	bad.Sequence++
	check(bad, cert, trust, CredentialObservation{}, vault.ErrAuthentication)
	revoked := state
	revoked.Sequence++
	revoked.Active = false
	revoked = signState(revoked)
	check(revoked, vault.UserKeyCertificate{}, trust, CredentialObservation{StateSequence: 10}, vault.ErrPolicy)
	tr := trust
	tr.MinimumStateSequence++
	check(state, cert, tr, CredentialObservation{}, vault.ErrRollback)
	tr = trust
	tr.MinimumCertificateRevision++
	check(state, cert, tr, CredentialObservation{StateSequence: 9}, vault.ErrRollback)
	tr = trust
	tr.MinimumCredentialRevision++
	check(state, cert, tr, CredentialObservation{9, 3, 0}, vault.ErrRollback)
	high := state
	high.MinimumSigningCertificate++
	high = signState(high)
	check(high, cert, trust, CredentialObservation{StateSequence: 9}, vault.ErrRollback)
	rotated := state
	rotated.Signing.Version++
	rotated.Sequence++
	rotated = signState(rotated)
	check(rotated, cert, trust, CredentialObservation{StateSequence: 10}, vault.ErrAuthentication)
	nextKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{13}, 32))
	defer vault.Wipe(nextKey)
	nextCert := cert
	nextCert.Key = rotated.Signing
	nextCert.PublicKey = nextKey.Public().(ed25519.PublicKey)
	nextCert, e := vault.SignUserKeyCertificate(nextCert, org)
	if e != nil {
		t.Fatal(e)
	}
	check(rotated, nextCert, trust, CredentialObservation{10, 3, 0}, vault.ErrAuthentication)
	nextSeal, e := SignCredential(trust.Workspace, trust.Boundary, record, 8, rotated.Signing, nextKey)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := VerifyCurrentCredential(record, trust.Boundary, nextSeal, nextCert, rotated, trust); e != nil || got != (CredentialObservation{10, 3, 8}) {
		t.Fatal("rotated credential signer", got, e)
	}
	badCert := cert
	badCert.Signature = nil
	check(state, badCert, trust, CredentialObservation{StateSequence: 9}, vault.ErrAuthentication)
	tombstone := record
	tombstone.Deleted = true
	tombstone.Fields = []vaultstore.CredentialField{{Field: "password", Version: 6, Present: false}}
	signed, err := SignCredential(trust.Workspace, trust.Boundary, tombstone, 8, state.Signing, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyCurrentCredential(tombstone, trust.Boundary, signed, cert, state, trust)
	if got != (CredentialObservation{9, 3, 8}) || err != vaultstore.ErrMissing {
		t.Fatal("tombstone floor", got, err)
	}
	// Unsigned deletion must never advance the record's floor.
	tombstone = record
	tombstone.Deleted = true
	tombstone.Fields = nil
	got, err = VerifyCurrentCredential(tombstone, trust.Boundary, seal, cert, state, trust)
	if got.CredentialRevision != 0 || err != vault.ErrAuthentication {
		t.Fatal("unsigned deletion", got, err)
	}
}

func TestCredentialSealBindingsAndInvalidInputs(t *testing.T) {
	record, seal, cert, state, trust, key := credentialFixture(t)
	for _, mutate := range []func(*CredentialTrust){
		func(v *CredentialTrust) { v.Workspace = uuid.New() }, func(v *CredentialTrust) { v.Credential = uuid.New() }, func(v *CredentialTrust) { v.Credential = uuid.Nil }, func(v *CredentialTrust) { v.Boundary = uuid.New() }, func(v *CredentialTrust) { v.Boundary = uuid.Nil }, func(v *CredentialTrust) { v.Author = uuid.New() }, func(v *CredentialTrust) { v.OrganisationKey.Version++ }, func(v *CredentialTrust) { v.Organisation = nil },
	} {
		bad := trust
		mutate(&bad)
		if _, err := VerifyCurrentCredential(record, trust.Boundary, seal, cert, state, bad); err == nil {
			t.Fatal("trust substitution")
		}
	}
	if _, err := VerifyCurrentCredential(record, uuid.New(), seal, cert, state, trust); err != vault.ErrAuthentication {
		t.Fatal("boundary substitution", err)
	}
	for _, mutate := range []func(*vault.RecordSeal){
		func(v *vault.RecordSeal) { v.FormatVersion++ }, func(v *vault.RecordSeal) { v.FormatVersion = 0 }, func(v *vault.RecordSeal) { v.Revision = 0 }, func(v *vault.RecordSeal) { v.Revision = 1 << 63 }, func(v *vault.RecordSeal) { v.Revision++ }, func(v *vault.RecordSeal) { v.Signature = nil }, func(v *vault.RecordSeal) { v.SignerKeyID = uuid.NewString() }, func(v *vault.RecordSeal) { v.SignerKeyVersion++ }, func(v *vault.RecordSeal) { s := uuid.NewString(); v.CapabilityID = &s },
	} {
		bad := seal
		mutate(&bad)
		if _, err := VerifyCurrentCredential(record, trust.Boundary, bad, cert, state, trust); err == nil {
			t.Fatal("seal substitution")
		}
	}
	if _, err := SignCredential(trust.Workspace, trust.Boundary, record, 7, state.Signing, nil); err != vault.ErrFormat {
		t.Fatal(err)
	}
	bad := record
	bad.Metadata.ID = "bad"
	if _, err := SignCredential(trust.Workspace, trust.Boundary, bad, 7, state.Signing, key); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if _, err := SignCredential(uuid.Nil, trust.Boundary, record, 7, state.Signing, key); err != vault.ErrFormat {
		t.Fatal(err)
	}
}
