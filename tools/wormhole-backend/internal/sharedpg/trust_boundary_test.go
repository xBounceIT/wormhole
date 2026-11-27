package sharedpg

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"math"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func boundaryTrustFixture(t *testing.T) ([]byte, TrustBinding, TrustState, vault.BoundaryManifest, ed25519.PrivateKey) {
	t.Helper()
	root, b, s, _, _, org, _ := credentialTrustFixture(t)
	key := func(seed byte, v uint32) vault.BoundaryKey {
		p, e := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{seed}, 32))
		if e != nil {
			t.Fatal(e)
		}
		return vault.BoundaryKey{Key: vault.KeyRef{ID: uuid.New(), Version: v}, Public: p.PublicKey().Bytes()}
	}
	m := vault.BoundaryManifest{FormatVersion: 1, WorkspaceID: s.WorkspaceID, BoundaryID: uuid.New(), Revision: 1, Active: true, OrgEscrow: true, View: key(3, 2), Secret: key(4, 3), Signer: vault.KeyRef{ID: uuid.MustParse(s.SignerKeyID), Version: s.SignerKeyVersion}}
	var e error
	m, e = vault.SignBoundaryManifest(m, org)
	if e != nil {
		t.Fatal(e)
	}
	return root, b, s, m, org
}
func TestBoundaryTrustPersistenceAndForks(t *testing.T) {
	root, b, s, m, org := boundaryTrustFixture(t)
	sign := func(m vault.BoundaryManifest) vault.BoundaryManifest {
		t.Helper()
		r, e := vault.SignBoundaryManifest(m, org)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	restore := func(s TrustState) TrustState {
		t.Helper()
		raw, e := SealTrustState(root, b, s)
		if e != nil {
			t.Fatal(e)
		}
		got, e := OpenTrustState(root, b, raw, s.Revision)
		if e != nil || !reflect.DeepEqual(got, s) {
			t.Fatal("roundtrip", e)
		}
		return got
	}
	next, e := s.AdvanceBoundary(m.BoundaryID, m)
	if e != nil || len(next.Catalog) != 3 || s.Catalog != nil || s.ValidateAdvance(next) != nil {
		t.Fatal("boundary advance", e)
	}
	next = restore(next)
	same, e := next.AdvanceBoundary(m.BoundaryID, m)
	if e != nil || !reflect.DeepEqual(same, next) {
		t.Fatal("idempotence", e)
	}
	for _, v := range same.Catalog {
		v.Digest[0] ^= 1
		break
	}
	if _, e = next.AdvanceBoundary(m.BoundaryID, m); e != nil {
		t.Fatal("alias", e)
	}
	fork := m
	fork.OwnerUserID = s.UserID
	if _, e = next.AdvanceBoundary(m.BoundaryID, sign(fork)); e != ErrCatalogEquivocation {
		t.Fatal("manifest fork", e)
	}
	fork.Revision = 2
	fork.View.Key.Version = 1
	newer, e := next.AdvanceBoundary(m.BoundaryID, sign(fork))
	if e != vault.ErrRollback || next.ValidateAdvance(newer) != nil || newer.Catalog["boundary/"+m.BoundaryID.String()].Revision != 2 || newer.Catalog["boundary-view/"+m.BoundaryID.String()].Revision != 2 {
		t.Fatal("root rollback in newer manifest", e)
	}
	newer = restore(newer)
	if _, e = newer.AdvanceBoundary(m.BoundaryID, m); e != vault.ErrRollback {
		t.Fatal("older manifest", e)
	}
	// A same-version different public recipient is a fork even under a newer manifest.
	fork = m
	fork.Revision = 3
	fork.View.Public = bytes.Clone(m.Secret.Public)
	fork.Secret.Public = bytes.Clone(m.View.Public)
	seen, e := newer.AdvanceBoundary(m.BoundaryID, sign(fork))
	if e != ErrCatalogEquivocation || newer.ValidateAdvance(seen) != nil {
		t.Fatal("root public fork", e)
	}
	seen = restore(seen)
	repaired := m
	repaired.Revision = 4
	repaired.Active = false
	dead, e := seen.AdvanceBoundary(m.BoundaryID, sign(repaired))
	if e != vault.ErrPolicy || seen.ValidateAdvance(dead) != nil {
		t.Fatal("inactive floor", e)
	}
	dead = restore(dead)
	if _, e = dead.AdvanceBoundary(m.BoundaryID, m); e != vault.ErrRollback {
		t.Fatal("inactive rollback", e)
	}
}

func TestBoundaryTrustEscrowPolicyAndLimits(t *testing.T) {
	_, _, s, m, org := boundaryTrustFixture(t)
	m.OwnerUserID = s.UserID
	m.OrgEscrow = false
	m, e := vault.SignBoundaryManifest(m, org)
	if e != nil {
		t.Fatal(e)
	}
	denied, e := s.AdvanceBoundary(m.BoundaryID, m)
	if e != vault.ErrPolicy || len(denied.Catalog) != 3 || s.ValidateAdvance(denied) != nil {
		t.Fatal("escrow policy floor", e)
	}
	policy, _ := vault.DecodeSignedPolicy(s.SignedProfile)
	policy.Policy.Profile = vault.Paranoid
	policy.Policy.KDF = vault.KDFV3
	policy.Policy.ASKRequired = true
	policy.Policy.OrgEscrow = false
	policy.Policy.Sequence++
	policy, e = vault.SignPolicy(policy.Policy, s.SignerKeyID, s.SignerKeyVersion, org)
	if e != nil {
		t.Fatal(e)
	}
	s.SignedProfile, e = vault.EncodeSignedPolicy(policy)
	if e != nil {
		t.Fatal(e)
	}
	digest := sha256.Sum256(s.SignedProfile)
	s.PolicyDigest = digest[:]
	s.PolicySequence = policy.Policy.Sequence
	if _, e = s.AdvanceBoundary(m.BoundaryID, m); e != nil {
		t.Fatal("Paranoid personal no-escrow", e)
	}
	s.Revision = math.MaxUint64 - 1
	last, e := s.AdvanceBoundary(m.BoundaryID, m)
	if e != nil || last.Revision != math.MaxUint64 {
		t.Fatal("last revision", e)
	}
	same, e := last.AdvanceBoundary(m.BoundaryID, m)
	if e != nil || !reflect.DeepEqual(same, last) {
		t.Fatal("max idempotence", e)
	}
	s.Revision = math.MaxUint64
	if _, e = s.AdvanceBoundary(m.BoundaryID, m); e != ErrTrustState {
		t.Fatal("overflow", e)
	}
	invalid := s
	invalid.Revision = 0
	if _, e = invalid.AdvanceBoundary(m.BoundaryID, m); e != ErrTrustState {
		t.Fatal(e)
	}
	if _, e = s.AdvanceBoundary(uuid.Nil, m); e != ErrTrustState {
		t.Fatal(e)
	}
	if _, e = s.AdvanceBoundary(uuid.New(), m); e != vault.ErrAuthentication {
		t.Fatal("boundary pin", e)
	}
	m.Signature = make([]byte, 64)
	if _, e = s.AdvanceBoundary(m.BoundaryID, m); e != vault.ErrAuthentication {
		t.Fatal("signature", e)
	}
	floor := CatalogFloor{Revision: math.MaxInt32 + 1, Digest: make([]byte, 32)}
	if validCatalogFloors(map[string]CatalogFloor{"boundary-view/" + m.BoundaryID.String(): floor}) {
		t.Fatal("unrepresentable root floor")
	}
}

func TestBoundaryTrustCapacityKeepsPartialManifest(t *testing.T) {
	_, _, s, m, _ := boundaryTrustFixture(t)
	s.Catalog = make(map[string]CatalogFloor, MaxCatalogFloors)
	for i := 0; i < MaxCatalogFloors-1; i++ {
		s.Catalog["node/"+uuid.NewString()] = CatalogFloor{Revision: 1, Digest: make([]byte, 32)}
	}
	next, e := s.AdvanceBoundary(m.BoundaryID, m)
	if e != ErrTrustState || len(next.Catalog) != MaxCatalogFloors || next.Catalog["boundary/"+m.BoundaryID.String()].Revision != 1 || s.ValidateAdvance(next) != nil {
		t.Fatal("bounded partial observation", e)
	}
}

func TestBoundaryTrustResumableRotation(t *testing.T) {
	_, _, s, m, org := boundaryTrustFixture(t)
	next, e := s.AdvanceBoundary(m.BoundaryID, m)
	if e != nil {
		t.Fatal(e)
	}
	oldView, oldSecret := m.View, m.Secret
	m.Revision++
	m.PreviousView = &oldView
	m.PreviousSecret = &oldSecret
	m.View.Key.Version++
	m.Secret.Key.Version++
	for i, dest := range []*vault.BoundaryKey{&m.View, &m.Secret} {
		key, e := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{byte(7 + i)}, 32))
		if e != nil {
			t.Fatal(e)
		}
		dest.Public = key.PublicKey().Bytes()
	}
	m, e = vault.SignBoundaryManifest(m, org)
	if e != nil {
		t.Fatal(e)
	}
	rotated, e := next.AdvanceBoundary(m.BoundaryID, m)
	if e != nil || next.ValidateAdvance(rotated) != nil || rotated.Catalog["boundary-view/"+m.BoundaryID.String()].Revision != 3 || rotated.Catalog["boundary-secret/"+m.BoundaryID.String()].Revision != 4 {
		t.Fatal("rotation", e)
	}
	m.Revision++
	m.PreviousView = nil
	m.PreviousSecret = nil
	m, e = vault.SignBoundaryManifest(m, org)
	if e != nil {
		t.Fatal(e)
	}
	finished, e := rotated.AdvanceBoundary(m.BoundaryID, m)
	if e != nil || rotated.ValidateAdvance(finished) != nil {
		t.Fatal("rotation completion", e)
	}
}
