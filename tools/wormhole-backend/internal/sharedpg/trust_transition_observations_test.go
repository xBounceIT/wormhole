package sharedpg

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestTrustTransitionObservationsPreserveRevocation(t *testing.T) {
	root, b, base, account, priv, a, r := accountTrustFixture(t)
	previous, err := base.AdvanceAccount(account, 2)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := SealTrustState(root, b, previous)
	if err != nil {
		t.Fatal(err)
	}
	nextRoot := bytes.Repeat([]byte{99}, 32)
	prepared, _, err := PrepareTrustRootTransition(root, nextRoot, b, raw, previous.Revision)
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := prepared.ObserveAccount(b, account, 2)
	if err != nil || !reflect.DeepEqual(unchanged, prepared) {
		t.Fatal("unchanged account wrote observation")
	}
	unchanged, err = prepared.ObserveProfile(b, a, r)
	if err != nil || !reflect.DeepEqual(unchanged, prepared) {
		t.Fatal("unchanged policy wrote observation")
	}
	signed, err := vault.DecodeSignedPolicy(a.SignedProfile)
	if err != nil {
		t.Fatal(err)
	}
	signed.Policy.Sequence++
	signed, err = vault.SignPolicy(signed.Policy, previous.SignerKeyID, 1, priv)
	if err != nil {
		t.Fatal(err)
	}
	a.SignedProfile, err = vault.EncodeSignedPolicy(signed)
	if err != nil {
		t.Fatal(err)
	}
	profiled, err := prepared.ObserveProfile(b, a, r)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepared.ValidateObservationAdvance(b, profiled); err != nil {
		t.Fatal(err)
	}
	revoked := account
	revoked.Sequence++
	revoked.Active = false
	revoked, err = vault.SignUserKeyState(revoked, priv)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := profiled.ObserveAccount(b, revoked, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := profiled.ValidateObservationAdvance(b, observed); err != nil {
		t.Fatal(err)
	}
	if err := observed.ValidateObservationAdvance(b, observed); err != nil {
		t.Fatal(err)
	}
	if err := observed.ValidateObservationAdvance(b, profiled); err == nil {
		t.Fatal("revocation removed")
	}
	if _, err := observed.ObserveAccount(b, account, 2); err == nil {
		t.Fatal("active replay accepted")
	}
	encoded, err := SealTrustRootTransition(nextRoot, b, observed)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := OpenTrustRootTransition(nextRoot, b, encoded)
	if err != nil || !reflect.DeepEqual(restored, observed) {
		t.Fatal("observations lost", err)
	}
	promoted, err := restored.PromotionState(b)
	if err != nil || promoted.Account.Active || promoted.WrappingRevision != 3 || promoted.PolicySequence != signed.Policy.Sequence || promoted.Revision != observed.Observed.Revision+1 {
		t.Fatal("promotion erased observation", err)
	}
	aborted, err := restored.AbortState(b)
	if err != nil || aborted.Account.Active || aborted.WrappingRevision != 2 {
		t.Fatal("abort erased observation", err)
	}
	interim, err := profiled.PromotionState(b)
	if err != nil {
		t.Fatal(err)
	}
	if !restored.AcceptsDestination(b, interim, true) || !restored.AcceptsDestination(b, promoted, true) || restored.AcceptsDestination(b, promoted, false) {
		t.Fatal("interrupted destination classification")
	}
	if !restored.AcceptsDestination(b, profiled.ObservedTrust(), false) || !restored.AcceptsDestination(b, aborted, false) {
		t.Fatal("interrupted abort classification")
	}
	if restored.AcceptsDestination(b, previous, true) {
		t.Fatal("old floor treated as promoted")
	}
	future := promoted
	future.Revision++
	future.WrappingRevision++
	if restored.AcceptsDestination(b, future, true) {
		t.Fatal("future destination overwritten")
	}
	wrong := promoted
	wrong.PublicKey = bytes.Repeat([]byte{1}, 32)
	if restored.AcceptsDestination(b, wrong, true) {
		t.Fatal("foreign pin accepted")
	}
	clone := restored.ObservedTrust()
	clone.Account.Signature[0] ^= 1
	clone.PublicKey[0] ^= 1
	if !restored.valid(b) {
		t.Fatal("observed snapshot aliases journal")
	}
	proved, err := prepared.ObserveAccount(b, account, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proved.AbortState(b); err != ErrTrustRollback {
		t.Fatal("verified committed floor discarded")
	}
	target, err := proved.PromotionState(b)
	if err != nil || target.Revision != proved.Observed.Revision {
		t.Fatal("redundant promotion increment")
	}
}

func TestTrustTransitionObservationValidation(t *testing.T) {
	root, b, base, account, _, a, r := accountTrustFixture(t)
	previous, err := base.AdvanceAccount(account, 2)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := SealTrustState(root, b, previous)
	if err != nil {
		t.Fatal(err)
	}
	nextRoot := bytes.Repeat([]byte{99}, 32)
	record, _, err := PrepareTrustRootTransition(root, nextRoot, b, raw, previous.Revision)
	if err != nil {
		t.Fatal(err)
	}
	invalid := record
	invalid.ID = uuid.Nil
	if _, err := invalid.ObserveAccount(b, account, 2); err == nil {
		t.Fatal("invalid record")
	}
	if _, err := invalid.ObserveProfile(b, a, r); err == nil {
		t.Fatal("invalid record")
	}
	if _, err := invalid.PromotionState(b); err == nil {
		t.Fatal("invalid promotion")
	}
	if _, err := invalid.AbortState(b); err == nil {
		t.Fatal("invalid abort")
	}
	if err := record.ValidateObservationAdvance(b, invalid); err == nil {
		t.Fatal("invalid advance")
	}
	changed := record
	changed.ID = uuid.New()
	if err := record.ValidateObservationAdvance(b, changed); err == nil {
		t.Fatal("preparation replaced")
	}
	if _, err := record.ObserveProfile(b, nil, r); err == nil {
		t.Fatal("missing admission accepted")
	}
	observed := previous
	observed.Revision--
	bad := record
	bad.Observed = &observed
	if _, err := SealTrustRootTransition(nextRoot, b, bad); err == nil {
		t.Fatal("older observation")
	}
	observed = previous
	observed.Revision++
	observed.PublicKey = bytes.Repeat([]byte{1}, 32)
	if _, err := SealTrustRootTransition(nextRoot, b, bad); err == nil {
		t.Fatal("forged observation")
	}
	wrong := b
	wrong.KeyID = uuid.Nil
	if _, err := SealTrustRootTransition(nextRoot, wrong, record); err == nil {
		t.Fatal("invalid binding")
	}
	if _, err := SealTrustRootTransition(nil, b, record); err == nil {
		t.Fatal("invalid root")
	}
}
