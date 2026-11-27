package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestCertifiedGroupKeyCopyIsScopedAndMatchesItsPublicKey(t *testing.T) {
	seed := bytes.Repeat([]byte{62}, 32)
	member := bytes.Repeat([]byte{77}, 32)
	signerSeed := bytes.Repeat([]byte{19}, 32)
	signer := ed25519.NewKeyFromSeed(signerSeed)
	public := signer.Public().(ed25519.PublicKey)
	groupKey, _ := ecdh.X25519().NewPrivateKey(seed)
	memberKey, _ := ecdh.X25519().NewPrivateKey(member)
	digest := sha256.Sum256([]byte("review snapshot"))
	m := GroupKeyManifest{FormatVersion: 1, WorkspaceID: uuid.New(), GroupID: uuid.New(), GroupRevision: 3, RosterDigest: digest[:],
		Key:    BoundaryKey{Key: KeyRef{ID: uuid.New(), Version: 2}, Public: groupKey.PublicKey().Bytes()},
		Signer: KeyRef{ID: uuid.New(), Version: 1}, Recovery: KeyRef{ID: uuid.New(), Version: 1}}
	signed, err := SignGroupKeyManifest(m, signer)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeGroupKeyManifest(signed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeGroupKeyManifest(raw)
	if err != nil || VerifyGroupKeyManifest(decoded, m.WorkspaceID, m.GroupID, m.Signer, public, 2) != nil {
		t.Fatal("valid manifest failed verification", err)
	}
	holder := KeyRef{ID: uuid.New(), Version: 2}
	binding := KeyCopyBinding{WorkspaceID: m.WorkspaceID, Key: m.Key.Key, Holder: holder, Issuer: m.Signer}
	copy, err := SealKeyCopy(seed, binding, memberKey.PublicKey().Bytes(), signerSeed)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenGroupKeyCopy(decoded, m.WorkspaceID, m.GroupID, m.Signer, public, 2, holder, member, copy)
	defer Wipe(opened)
	if err != nil || !bytes.Equal(opened, seed) {
		t.Fatal("certified holder could not open group key", err)
	}
	if _, err := OpenGroupKeyCopy(decoded, m.WorkspaceID, uuid.New(), m.Signer, public, 2, holder, member, copy); !errors.Is(err, ErrAuthentication) {
		t.Fatal("another group reused the manifest", err)
	}
	if _, err := OpenGroupKeyCopy(decoded, m.WorkspaceID, m.GroupID, m.Signer, public, 3, holder, member, copy); !errors.Is(err, ErrRollback) {
		t.Fatal("an older generation was accepted", err)
	}
	if _, err := OpenGroupKeyCopy(decoded, m.WorkspaceID, m.GroupID, m.Signer, public, 2, KeyRef{ID: uuid.New(), Version: 2}, member, copy); err == nil {
		t.Fatal("existing copy was moved to another holder")
	}
	wrong, err := SealKeyCopy(bytes.Repeat([]byte{45}, 32), binding, memberKey.PublicKey().Bytes(), signerSeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenGroupKeyCopy(decoded, m.WorkspaceID, m.GroupID, m.Signer, public, 2, holder, member, wrong); !errors.Is(err, ErrAuthentication) {
		t.Fatal("copy carrying a different private key was accepted", err)
	}
	decoded.RosterDigest[0] ^= 1
	if err := VerifyGroupKeyManifest(decoded, m.WorkspaceID, m.GroupID, m.Signer, public, 1); !errors.Is(err, ErrAuthentication) {
		t.Fatal("roster digest was not covered by the organisation signature", err)
	}
	for _, change := range []func(*GroupKeyManifest){
		func(m *GroupKeyManifest) { m.FormatVersion++ },
		func(m *GroupKeyManifest) { m.GroupRevision = 0 },
		func(m *GroupKeyManifest) { m.Recovery = m.Signer },
		func(m *GroupKeyManifest) { m.Key.Key.Version = 0 },
		func(m *GroupKeyManifest) { m.Key.Public = make([]byte, 32) },
	} {
		bad := m
		change(&bad)
		if _, err := SignGroupKeyManifest(bad, signer); err == nil {
			t.Fatal("malformed group manifest was signed")
		}
	}
	if _, err := SignGroupKeyManifest(m, nil); !errors.Is(err, ErrFormat) {
		t.Fatal("malformed signer was accepted", err)
	}
	if _, err := EncodeGroupKeyManifest(m); !errors.Is(err, ErrFormat) {
		t.Fatal("unsigned group manifest encoded", err)
	}
	for _, bad := range [][]byte{nil, []byte(`{bad}`), []byte(`{}`), append([]byte(" "), raw...)} {
		if _, err := DecodeGroupKeyManifest(bad); err == nil {
			t.Fatal("noncanonical encoding accepted")
		}
	}
}
