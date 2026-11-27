package sharedpg

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestTrustRootTransitionRoundtripAndIsolation(t *testing.T) {
	old, b, base, account, _, _, _ := accountTrustFixture(t)
	current, err := base.AdvanceAccount(account, 2)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := SealTrustState(old, b, current)
	if err != nil {
		t.Fatal(err)
	}
	nextRoot := bytes.Repeat([]byte{91}, 32)
	record, raw, err := PrepareTrustRootTransition(old, nextRoot, b, previous, current.Revision)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := OpenTrustRootTransition(nextRoot, b, raw)
	if err != nil || !reflect.DeepEqual(record, restored) {
		t.Fatalf("roundtrip: %v", err)
	}
	if record.Next.WrappingRevision != 3 || record.Next.Revision != current.Revision+1 || !reflect.DeepEqual(record.Previous, current) {
		t.Fatal("wrong predicted transition")
	}
	if _, err := OpenTrustRootTransition(old, b, raw); err == nil {
		t.Fatal("old root opened transition")
	}
	if _, err := OpenTrustState(nextRoot, b, raw, 1); err == nil {
		t.Fatal("transition accepted as trust")
	}
	if _, err := OpenTrustRootTransition(old, b, previous); err == nil {
		t.Fatal("trust accepted as transition")
	}
	for _, mutate := range []func(*TrustBinding){func(b *TrustBinding) { b.WorkspaceID = uuid.New() }, func(b *TrustBinding) { b.UserID = uuid.New() }, func(b *TrustBinding) { b.DeviceID = uuid.New() }, func(b *TrustBinding) { b.KeyID = uuid.New() }, func(b *TrustBinding) { b.KeyVersion++ }} {
		wrong := b
		mutate(&wrong)
		if _, err := OpenTrustRootTransition(nextRoot, wrong, raw); err == nil {
			t.Fatal("cross-binding replay")
		}
	}
	for _, bad := range [][]byte{nil, []byte("{"), append(bytes.Clone(raw), ' '), bytes.Repeat([]byte{0}, MaxTrustRootTransitionBytes+1)} {
		if _, err := OpenTrustRootTransition(nextRoot, b, bad); err == nil {
			t.Fatal("malformed envelope accepted")
		}
	}
	if _, err := OpenTrustRootTransition(nil, b, raw); err == nil {
		t.Fatal("invalid root")
	}
	if _, err := OpenTrustRootTransition(nextRoot, TrustBinding{}, raw); err == nil {
		t.Fatal("invalid binding")
	}
	var envelope vault.Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	// A valid outer envelope must not bypass canonical or semantic validation.
	key, err := vault.DeriveKey(nextRoot, b.WorkspaceID[:], vault.PurposeSharedTrust)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(key)
	aad, err := transitionBinding(b)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{[]byte("{"), []byte("{}"), append(bytes.Clone(plain), ' ')} {
		sealed, e := vault.Seal(key, aad, invalid)
		if e != nil {
			t.Fatal(e)
		}
		encoded, e := json.Marshal(sealed)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = OpenTrustRootTransition(nextRoot, b, encoded); e == nil {
			t.Fatal("invalid authenticated plaintext")
		}
	}
	for _, rev := range []uint64{0, current.Revision - 1, current.Revision + 1} {
		if _, _, err := PrepareTrustRootTransition(old, nextRoot, b, previous, rev); err == nil {
			t.Fatal("stale revision")
		}
	}
	if _, _, err := PrepareTrustRootTransition(old, nil, b, previous, current.Revision); err == nil {
		t.Fatal("invalid new root")
	}
	if _, err := transitionBinding(TrustBinding{}); err == nil {
		t.Fatal("invalid transition binding")
	}
}

func TestTrustRootTransitionRejectsInvalidState(t *testing.T) {
	old, b, base, account, priv, _, _ := accountTrustFixture(t)
	nextRoot := bytes.Repeat([]byte{91}, 32)
	for _, kind := range []string{"legacy", "revoked", "wrap-exhausted", "revision-exhausted"} {
		t.Run(kind, func(t *testing.T) {
			state := base
			signed := account
			if kind == "revoked" {
				signed.Active = false
				var err error
				signed, err = vault.SignUserKeyState(signed, priv)
				if err != nil {
					t.Fatal(err)
				}
			}
			if kind != "legacy" {
				var err error
				state, err = base.AdvanceAccount(signed, 2)
				if err != nil {
					t.Fatal(err)
				}
			}
			if kind == "wrap-exhausted" {
				state.WrappingRevision = math.MaxInt64
			}
			if kind == "revision-exhausted" {
				state.Revision = math.MaxUint64
			}
			raw, err := SealTrustState(old, b, state)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := PrepareTrustRootTransition(old, nextRoot, b, raw, state.Revision); err == nil {
				t.Fatal("invalid source state")
			}
		})
	}
	state, err := base.AdvanceAccount(account, 2)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := SealTrustState(old, b, state)
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := PrepareTrustRootTransition(old, nextRoot, b, raw, state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*TrustRootTransition){func(r *TrustRootTransition) { r.ID = uuid.Nil }, func(r *TrustRootTransition) { r.FormatVersion++ }, func(r *TrustRootTransition) { r.PreviousDigest = nil }, func(r *TrustRootTransition) { r.Next.WrappingRevision++ }, func(r *TrustRootTransition) { r.Next.PolicySequence++ }} {
		bad := record
		mutate(&bad)
		if bad.valid(b) {
			t.Fatal("invalid transition state")
		}
	}
}
