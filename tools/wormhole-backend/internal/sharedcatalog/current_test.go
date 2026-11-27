package sharedcatalog

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestCurrentNodeState(t *testing.T) {
	node, seal, certificate, pin, _ := fixture(t)
	org := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32))
	defer vault.Wipe(org)
	state := vault.UserKeyState{FormatVersion: vault.FormatVersion, WorkspaceID: pin.Workspace, UserID: pin.Author, Sequence: 9, Active: true, Encryption: vault.KeyRef{ID: uuid.New(), Version: 1}, Signing: pin.AuthorKey, MinimumEncryptionCertificate: 1, MinimumSigningCertificate: 3, Signer: pin.OrganisationKey}
	sign := func(s vault.UserKeyState) vault.UserKeyState {
		t.Helper()
		out, err := vault.SignUserKeyState(s, org)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	state = sign(state)
	trust := CurrentNodeTrust{Workspace: pin.Workspace, Node: pin.Node, Boundary: pin.Boundary, Author: pin.Author, OrganisationKey: pin.OrganisationKey, Organisation: pin.Organisation, MinimumStateSequence: 9, MinimumCertificateRevision: 3, MinimumNodeRevision: 7}
	check := func(s vault.UserKeyState, c vault.UserKeyCertificate, tr CurrentNodeTrust, want Observation, wantErr error) {
		t.Helper()
		got, err := VerifyCurrentNode(node, pin.Boundary, seal, c, s, tr)
		if got != want || err != wantErr {
			t.Fatalf("got %+v/%v want %+v/%v", got, err, want, wantErr)
		}
	}
	check(state, certificate, trust, Observation{9, 3, 7}, nil)
	for _, mutate := range []func(*vault.UserKeyState){func(s *vault.UserKeyState) { s.Active = false }, func(s *vault.UserKeyState) { s.Sequence++ }, func(s *vault.UserKeyState) { s.Signing.Version++ }} {
		bad := state
		mutate(&bad)
		check(bad, certificate, trust, Observation{}, vault.ErrAuthentication)
	}
	revoked := state
	revoked.Active = false
	revoked.Sequence++
	revoked = sign(revoked)
	check(revoked, vault.UserKeyCertificate{}, trust, Observation{StateSequence: 10}, vault.ErrPolicy)
	newer := trust
	newer.MinimumStateSequence = 10
	check(state, certificate, newer, Observation{}, vault.ErrRollback)
	rotated := state
	rotated.Signing.Version++
	rotated.Sequence++
	rotated = sign(rotated)
	check(rotated, certificate, trust, Observation{StateSequence: 10}, vault.ErrAuthentication)
	// A real newly certified key selection can sign the next node revision.
	newKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{13}, 32))
	defer vault.Wipe(newKey)
	newCert := certificate
	newCert.Key = rotated.Signing
	newCert.PublicKey = newKey.Public().(ed25519.PublicKey)
	newCert, err := vault.SignUserKeyCertificate(newCert, org)
	if err != nil {
		t.Fatal(err)
	}
	check(rotated, newCert, trust, Observation{10, 3, 0}, vault.ErrAuthentication)
	newSeal, err := SignNode(pin.Workspace, pin.Boundary, node, 8, rotated.Signing, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := VerifyCurrentNode(node, pin.Boundary, newSeal, newCert, rotated, trust); err != nil || got != (Observation{10, 3, 8}) {
		t.Fatal(got, err)
	}
	higher := state
	higher.MinimumSigningCertificate = 4
	higher = sign(higher)
	check(higher, certificate, trust, Observation{StateSequence: 9}, vault.ErrRollback)
	newer = trust
	newer.MinimumCertificateRevision = 4
	check(state, certificate, newer, Observation{StateSequence: 9}, vault.ErrRollback)
	newer = trust
	newer.MinimumNodeRevision = 8
	check(state, certificate, newer, Observation{9, 3, 0}, vault.ErrRollback)
	badCert := certificate
	badCert.Signature = nil
	check(state, badCert, trust, Observation{StateSequence: 9}, vault.ErrAuthentication)
}
