package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"math"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func boundaryKeyFixture(t *testing.T, seed byte, version uint32) BoundaryKey {
	t.Helper()
	private, e := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{seed}, 32))
	if e != nil {
		t.Fatal(e)
	}
	return BoundaryKey{Key: KeyRef{ID: uuid.New(), Version: version}, Public: private.PublicKey().Bytes()}
}
func boundaryManifestFixture(t *testing.T) (BoundaryManifest, BoundaryTrust, ed25519.PrivateKey) {
	t.Helper()
	org := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	m := BoundaryManifest{FormatVersion: 1, WorkspaceID: uuid.New(), BoundaryID: uuid.New(), Revision: 7, OrgEscrow: true, Active: true, View: boundaryKeyFixture(t, 1, 2), Secret: boundaryKeyFixture(t, 2, 3), Signer: KeyRef{ID: uuid.New(), Version: 1}}
	v, s := boundaryKeyFixture(t, 3, 1), boundaryKeyFixture(t, 4, 2)
	v.Key.ID = m.View.Key.ID
	s.Key.ID = m.Secret.Key.ID
	m.PreviousView = &v
	m.PreviousSecret = &s
	var e error
	m, e = SignBoundaryManifest(m, org)
	if e != nil {
		t.Fatal(e)
	}
	return m, BoundaryTrust{WorkspaceID: m.WorkspaceID, BoundaryID: m.BoundaryID, Signer: m.Signer, Organisation: org.Public().(ed25519.PublicKey), MinimumRevision: 7}, org
}
func cloneBoundaryFixture(t *testing.T, m BoundaryManifest) BoundaryManifest {
	t.Helper()
	raw, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	var c BoundaryManifest
	if json.Unmarshal(raw, &c) != nil {
		t.Fatal("clone")
	}
	return c
}

func TestBoundaryManifestAuthentication(t *testing.T) {
	m, pin, org := boundaryManifestFixture(t)
	if e := VerifyBoundaryManifest(m, pin); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*BoundaryManifest){
		func(m *BoundaryManifest) { m.WorkspaceID = uuid.New() }, func(m *BoundaryManifest) { m.BoundaryID = uuid.New() }, func(m *BoundaryManifest) { m.Revision++ }, func(m *BoundaryManifest) { m.OwnerUserID = uuid.New() }, func(m *BoundaryManifest) { m.Active = false }, func(m *BoundaryManifest) { m.OwnerUserID = uuid.New(); m.OrgEscrow = false }, func(m *BoundaryManifest) { m.Signer.ID = uuid.New() }, func(m *BoundaryManifest) { m.Signer.Version++ }, func(m *BoundaryManifest) { m.View.Key.ID = uuid.New(); m.PreviousView = nil }, func(m *BoundaryManifest) { m.View.Key.Version++ }, func(m *BoundaryManifest) { m.Secret.Key.Version++ }, func(m *BoundaryManifest) { m.View.Public = boundaryKeyFixture(t, 5, 1).Public }, func(m *BoundaryManifest) { m.Secret.Public = boundaryKeyFixture(t, 6, 1).Public }, func(m *BoundaryManifest) { m.PreviousView = nil }, func(m *BoundaryManifest) { m.PreviousSecret = nil }, func(m *BoundaryManifest) { m.PreviousView.Public = boundaryKeyFixture(t, 7, 1).Public }, func(m *BoundaryManifest) { m.PreviousSecret.Key.Version-- }, func(m *BoundaryManifest) { m.Signature[0] ^= 1 },
	} {
		c := cloneBoundaryFixture(t, m)
		change(&c)
		if e := VerifyBoundaryManifest(c, pin); e == nil {
			t.Fatal("unsigned field accepted")
		}
	}
	for _, change := range []func(*BoundaryTrust){func(p *BoundaryTrust) { p.WorkspaceID = uuid.New() }, func(p *BoundaryTrust) { p.BoundaryID = uuid.New() }, func(p *BoundaryTrust) { p.Signer.ID = uuid.New() }, func(p *BoundaryTrust) { p.Signer.Version++ }, func(p *BoundaryTrust) { p.Organisation = nil }} {
		p := pin
		change(&p)
		if e := VerifyBoundaryManifest(m, p); e != ErrAuthentication {
			t.Fatal("pin", e)
		}
	}
	p := pin
	p.MinimumRevision++
	if e := VerifyBoundaryManifest(m, p); e != ErrRollback {
		t.Fatal(e)
	}
	p = pin
	p.MinimumRevision = math.MaxUint64
	if e := VerifyBoundaryManifest(m, p); e != ErrFormat {
		t.Fatal(e)
	}
	m.Active = false
	m.OwnerUserID = uuid.New()
	m.OrgEscrow = false
	m, e := SignBoundaryManifest(m, org)
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyBoundaryManifest(m, pin); e != nil {
		t.Fatal("inactive/private manifests must authenticate", e)
	}
	raw, e := m.signingBytes()
	if e != nil {
		t.Fatal(e)
	}
	m.Signature = ed25519.Sign(org, canonical("wormhole/v1/other", raw))
	if e = VerifyBoundaryManifest(m, pin); e != ErrAuthentication {
		t.Fatal("domain", e)
	}
}

func TestBoundaryManifestValidationAndCodec(t *testing.T) {
	m, _, org := boundaryManifestFixture(t)
	for _, change := range []func(*BoundaryManifest){
		func(m *BoundaryManifest) { m.FormatVersion = 0 }, func(m *BoundaryManifest) { m.WorkspaceID = uuid.Nil }, func(m *BoundaryManifest) { m.BoundaryID = uuid.Nil }, func(m *BoundaryManifest) { m.Revision = 0 }, func(m *BoundaryManifest) { m.Revision = math.MaxUint64 }, func(m *BoundaryManifest) { m.OrgEscrow = false }, func(m *BoundaryManifest) { m.Signer.ID = uuid.Nil }, func(m *BoundaryManifest) { m.Signer.Version = 0 }, func(m *BoundaryManifest) { m.Signer.Version = math.MaxUint32 }, func(m *BoundaryManifest) { m.View.Key.ID = uuid.Nil }, func(m *BoundaryManifest) { m.View.Key.ID = m.Signer.ID; m.PreviousView = nil }, func(m *BoundaryManifest) { m.Secret.Key.ID = m.View.Key.ID; m.PreviousSecret = nil }, func(m *BoundaryManifest) { m.View.Key.Version = 0; m.PreviousView = nil }, func(m *BoundaryManifest) { m.Secret.Key.Version = math.MaxUint32 }, func(m *BoundaryManifest) { m.Secret.Public = nil }, func(m *BoundaryManifest) { m.View.Public = make([]byte, 32) }, func(m *BoundaryManifest) { m.Secret.Public = m.View.Public }, func(m *BoundaryManifest) { m.PreviousView.Key.ID = uuid.New() }, func(m *BoundaryManifest) { m.PreviousView.Key.Version = m.View.Key.Version }, func(m *BoundaryManifest) { m.PreviousSecret.Key.Version = 0 }, func(m *BoundaryManifest) { m.PreviousSecret.Public = m.Secret.Public },
	} {
		c := cloneBoundaryFixture(t, m)
		change(&c)
		if _, e := SignBoundaryManifest(c, org); e != ErrFormat {
			t.Fatal("malformed signed", e)
		}
		if _, e := EncodeBoundaryManifest(c); e != ErrFormat {
			t.Fatal("malformed encoded", e)
		}
	}
	newer := m
	newer.FormatVersion++
	if _, e := SignBoundaryManifest(newer, org); e != ErrNewerFormat {
		t.Fatal(e)
	}
	if _, e := SignBoundaryManifest(m, nil); e != ErrFormat {
		t.Fatal(e)
	}
	unsigned := m
	unsigned.Signature = nil
	if _, e := EncodeBoundaryManifest(unsigned); e != ErrFormat {
		t.Fatal(e)
	}
	raw, e := EncodeBoundaryManifest(m)
	if e != nil {
		t.Fatal(e)
	}
	restored, e := DecodeBoundaryManifest(raw)
	if e != nil || !reflect.DeepEqual(restored, m) {
		t.Fatal("roundtrip", e)
	}
	before := bytes.Clone(raw)
	raw[0] ^= 1
	if e := VerifyBoundaryManifest(restored, BoundaryTrust{WorkspaceID: m.WorkspaceID, BoundaryID: m.BoundaryID, Signer: m.Signer, Organisation: org.Public().(ed25519.PublicKey)}); e != nil {
		t.Fatal("wire alias", e)
	}
	raw = before
	for _, bad := range [][]byte{nil, bytes.Repeat([]byte(" "), MaxBoundaryManifestBytes+1), []byte("{"), []byte("null"), append([]byte(" "), raw...), append(append([]byte{}, raw...), []byte(" {}")...), append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"active":true}`)...), bytes.Replace(raw, []byte(`"view"`), []byte(`"View"`), 1), append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"unknown":0}`)...), []byte(`{"formatVersion":2}`)} {
		if _, e := DecodeBoundaryManifest(bad); e == nil {
			t.Fatal("noncanonical JSON", string(bad))
		}
	}
	m.PreviousView = nil
	m.PreviousSecret = nil
	m.Revision = math.MaxInt64
	m.View.Key.Version = math.MaxInt32
	if _, e := SignBoundaryManifest(m, org); e != nil {
		t.Fatal("maximum bounds", e)
	}
}
