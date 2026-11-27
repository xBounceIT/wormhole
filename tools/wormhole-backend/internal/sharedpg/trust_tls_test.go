package sharedpg

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func trustedTLSFixture(t *testing.T, s TrustState, org ed25519.PrivateKey, seq uint64) *VerifiedTLSBundle {
	t.Helper()
	b, _, _ := tlsTrustFixture(t)
	b.WorkspaceID = s.WorkspaceID
	b.Signer = vault.KeyRef{ID: uuid.MustParse(s.SignerKeyID), Version: s.SignerKeyVersion}
	b.Sequence = seq
	b, err := SignTLSTrustBundle(b, org)
	if err != nil {
		t.Fatal(err)
	}
	v, err := VerifyTLSTrustBundle(b, TLSTrustPin{WorkspaceID: s.WorkspaceID, Signer: b.Signer, Organisation: s.PublicKey, MinimumSequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestTrustTLSProtectedFloorAndOtherUpdates(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	root, b, base, account, org, a, r := accountTrustFixture(t)
	v := trustedTLSFixture(t, base, org, 3)
	s, err := base.AdvanceTLS(v)
	if err != nil {
		t.Fatal(err)
	}
	if s.FormatVersion != 4 || s.Account != nil || s.Revision != base.Revision+1 || base.TLSSequence != 0 {
		t.Fatal("upgrade")
	}
	if err := base.ValidateAdvance(s); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AccountTrust(); err == nil {
		t.Fatal("TLS implied account trust")
	}
	raw, err := SealTrustState(root, b, s)
	if err != nil {
		t.Fatal(err)
	}
	s, err = OpenTrustState(root, b, raw, s.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyTLS(v.Encode()); err != nil {
		t.Fatal(err)
	}
	unchanged, err := s.AdvanceTLS(v)
	if err != nil || !reflect.DeepEqual(s, unchanged) {
		t.Fatal("idempotence", err)
	}
	unchanged.TLSDigest[0] ^= 1
	if bytes.Equal(unchanged.TLSDigest, s.TLSDigest) {
		t.Fatal("alias")
	}
	withAccount, err := s.AdvanceAccount(account, 2)
	if err != nil {
		t.Fatal(err)
	}
	if withAccount.FormatVersion != 4 || !bytes.Equal(withAccount.TLSDigest, s.TLSDigest) {
		t.Fatal("account erased TLS")
	}
	if _, err := withAccount.AccountTrust(); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateAdvance(withAccount); err != nil {
		t.Fatal(err)
	}
	resignTrustPolicy(t, a, org, 8, vault.Standard)
	updated, err := withAccount.Advance(a, r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(updated.TLSDigest, s.TLSDigest) || updated.FormatVersion != 4 {
		t.Fatal("profile erased TLS")
	}
	if err := withAccount.ValidateAdvance(updated); err != nil {
		t.Fatal(err)
	}
	settings := settings()
	settings.TLS = TLSVerified
	settings.TLSBundle = v
	if _, err := s.PrepareTransport(settings, vault.Default, vault.Default, 1); err != nil {
		t.Fatal(err)
	}
	settings.TLSBundle = nil
	settings.CAPEM = testCA(t)
	if _, err := s.PrepareTransport(settings, vault.Default, vault.Default, 1); err != ErrConfiguration {
		t.Fatal("raw CA bypass", err)
	}
	newer := trustedTLSFixture(t, base, org, 4)
	settings.TLSBundle = newer
	settings.CAPEM = nil
	if _, err := s.PrepareTransport(settings, vault.Default, vault.Default, 1); err != ErrTrustRollback {
		t.Fatal("unpersisted bundle used", err)
	}
	next, err := s.AdvanceTLS(newer)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateAdvance(next); err != nil {
		t.Fatal(err)
	}
	if _, err := next.AdvanceTLS(v); err != ErrTrustRollback {
		t.Fatal("rollback", err)
	}
	if _, err := next.VerifyTLS(v.Encode()); !errors.Is(err, vault.ErrRollback) {
		t.Fatal("cached rollback", err)
	}
	equivocal := trustedTLSFixture(t, base, org, 4)
	if _, err := next.AdvanceTLS(equivocal); err != ErrTrustRollback {
		t.Fatal("equivocation", err)
	}
	if _, err := next.VerifyTLS(equivocal.Encode()); !errors.Is(err, vault.ErrRollback) {
		t.Fatal("cached equivocation", err)
	}
	for _, mutate := range []func(*TrustState){func(s *TrustState) { s.TLSSequence = 0 }, func(s *TrustState) { s.TLSDigest = nil }, func(s *TrustState) { s.TLSSequence = math.MaxUint64 }, func(s *TrustState) { s.FormatVersion = 3 }} {
		bad := next
		mutate(&bad)
		if _, err := SealTrustState(root, b, bad); err == nil {
			t.Fatal("invalid TLS state sealed")
		}
	}
	if _, err := base.AdvanceTLS(nil); err == nil {
		t.Fatal("nil")
	}
	if _, err := base.AdvanceTLS(&VerifiedTLSBundle{}); err == nil {
		t.Fatal("zero owner")
	}
	invalid := base
	invalid.Revision = 0
	if _, err := invalid.AdvanceTLS(v); err == nil {
		t.Fatal("invalid state")
	}
	full := base
	full.Revision = math.MaxUint64
	if _, err := full.AdvanceTLS(v); err == nil {
		t.Fatal("overflow")
	}
	foreign, foreignPin, _ := tlsTrustFixture(t)
	foreignV, _ := VerifyTLSTrustBundle(foreign, foreignPin)
	if _, err := base.AdvanceTLS(foreignV); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("foreign bundle", err)
	}
	if _, err := base.VerifyTLS(v.Encode()); err == nil {
		t.Fatal("no floor")
	}
	if _, err := next.VerifyTLS([]byte("bad")); err == nil {
		t.Fatal("invalid bundle")
	}
	downgrade := withAccount
	downgrade.FormatVersion = 3
	downgrade.TLSSequence = 0
	downgrade.TLSDigest = nil
	downgrade.Revision = withAccount.Revision + 1
	if err := withAccount.ValidateAdvance(downgrade); err != ErrTrustRollback {
		t.Fatal("floor erased", err)
	}
}

func TestTrustTLSRootTransitionKeepsObservations(t *testing.T) {
	root, b, base, account, org, _, _ := accountTrustFixture(t)
	base, err := base.AdvanceAccount(account, 2)
	if err != nil {
		t.Fatal(err)
	}
	first := trustedTLSFixture(t, base, org, 1)
	next := trustedTLSFixture(t, base, org, 2)
	newRoot := bytes.Repeat([]byte{99}, 32)
	for _, upgrade := range []bool{false, true} {
		current := base
		if upgrade {
			current, err = current.AdvanceTLS(first)
			if err != nil {
				t.Fatal(err)
			}
		}
		raw, err := SealTrustState(root, b, current)
		if err != nil {
			t.Fatal(err)
		}
		pending, _, err := PrepareTrustRootTransition(root, newRoot, b, raw, current.Revision)
		if err != nil {
			t.Fatal(err)
		}
		observed, err := pending.ObserveTLS(b, next)
		if err != nil {
			t.Fatal(err)
		}
		if err := pending.ValidateObservationAdvance(b, observed); err != nil {
			t.Fatal(err)
		}
		repeat, err := observed.ObserveTLS(b, next)
		if err != nil || !reflect.DeepEqual(repeat, observed) {
			t.Fatal("same observation", err)
		}
		sealed, err := SealTrustRootTransition(newRoot, b, observed)
		if err != nil {
			t.Fatal(err)
		}
		loaded, err := OpenTrustRootTransition(newRoot, b, sealed)
		if err != nil {
			t.Fatal(err)
		}
		promoted, err := loaded.PromotionState(b)
		if err != nil {
			t.Fatal(err)
		}
		aborted, err := loaded.AbortState(b)
		if err != nil {
			t.Fatal(err)
		}
		if promoted.TLSSequence != 2 || aborted.TLSSequence != 2 || promoted.FormatVersion != 4 || aborted.FormatVersion != 4 {
			t.Fatal("TLS observation lost")
		}
		clone := loaded.ObservedTrust()
		clone.TLSDigest[0] ^= 1
		if bytes.Equal(clone.TLSDigest, loaded.Observed.TLSDigest) {
			t.Fatal("observation alias")
		}
		if _, err := loaded.ObserveTLS(b, first); err != ErrTrustRollback {
			t.Fatal("observation rollback", err)
		}
	}
	if _, err := (TrustRootTransition{}).ObserveTLS(b, next); err == nil {
		t.Fatal("invalid transition")
	}
}
