package sharedpg

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"math"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func accountTrustFixture(t *testing.T) ([]byte, TrustBinding, TrustState, vault.UserKeyState, ed25519.PrivateKey, *UnverifiedAdmission, AdmissionRequest) {
	t.Helper()
	root, b, _, a, r, priv := trustFixture(t)
	signed, _ := vault.DecodeSignedPolicy(a.SignedProfile)
	signer := uuid.New()
	signed, err := vault.SignPolicy(signed.Policy, signer.String(), 1, priv)
	if err != nil {
		t.Fatal(err)
	}
	a.SignedProfile, err = vault.EncodeSignedPolicy(signed)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewTrustState(a, r, PolicyTrust{WorkspaceID: b.WorkspaceID, SignerKeyID: signer.String(), SignerKeyVersion: 1, PublicKey: priv.Public().(ed25519.PublicKey), MinimumSequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	account := vault.UserKeyState{FormatVersion: 1, WorkspaceID: b.WorkspaceID, UserID: b.UserID, Sequence: 4, Active: true, Encryption: vault.KeyRef{ID: uuid.New(), Version: 2}, Signing: vault.KeyRef{ID: uuid.New(), Version: 2}, MinimumEncryptionCertificate: 3, MinimumSigningCertificate: 3, Signer: vault.KeyRef{ID: signer, Version: 1}}
	account, err = vault.SignUserKeyState(account, priv)
	if err != nil {
		t.Fatal(err)
	}
	return root, b, s, account, priv, a, r
}

func TestEnrolledPersonalProfileSurvivesRewrapAndRejectsRollback(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	root, binding, initial, account, signer, admission, _ := accountTrustFixture(t)
	resignTrustPolicy(t, admission, signer, initial.PolicySequence+1, vault.Default)
	initial, err := initial.AdvancePolicy(admission.SignedProfile)
	if err != nil {
		t.Fatal(err)
	}
	old, err := initial.AdvanceAccount(account, 2)
	if err != nil || old.PersonalProfile() != vault.Default {
		t.Fatal(err)
	}
	next := old
	next.FormatVersion, next.UserMinimum = 7, vault.Standard
	next.Revision++
	if err := old.ValidateAdvance(next); err != nil {
		t.Fatal(err)
	}
	raw, err := SealTrustState(root, binding, next)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := OpenTrustState(root, binding, raw, next.Revision)
	if err != nil || restored.PersonalProfile() != vault.Standard {
		t.Fatal(err)
	}
	rewrapped, err := restored.AdvanceAccount(account, 3)
	if err != nil || rewrapped.PersonalProfile() != vault.Standard || restored.ValidateAdvance(rewrapped) != nil {
		t.Fatal(err)
	}
	clearMinimum := old
	clearMinimum.Revision = next.Revision + 1
	if err := next.ValidateAdvance(clearMinimum); err != ErrTrustRollback {
		t.Fatal("lost personal minimum", err)
	}
	for _, mutate := range []func(*TrustState){
		func(s *TrustState) { s.UserMinimum = "" },
		func(s *TrustState) { s.UserMinimum = vault.Default },
		func(s *TrustState) { s.UserMinimum = "future" },
		func(s *TrustState) { s.FormatVersion = 6 },
		func(s *TrustState) { s.Account = nil },
	} {
		bad := next
		mutate(&bad)
		if _, err := SealTrustState(root, binding, bad); err != ErrTrustState {
			t.Fatal("invalid personal minimum", err)
		}
	}
	insecure := settings()
	if _, err := old.PrepareTransport(insecure, vault.Default, vault.Default, 1); err != nil {
		t.Fatal("workspace Default should permit the original transport", err)
	}
	if _, err := restored.PrepareTransport(insecure, vault.Default, vault.Default, 1); err != ErrConfiguration {
		t.Fatal("personal Standard allowed insecure transport")
	}
}

func TestTrustAccountUpgradePersistenceAndRevocation(t *testing.T) {
	root, b, original, account, priv, a, r := accountTrustFixture(t)
	if _, err := original.AccountTrust(); err != ErrTrustState {
		t.Fatal("policy-only state granted account trust")
	}
	current, err := original.AdvanceAccount(account, 2)
	if err != nil {
		t.Fatal(err)
	}
	if current.FormatVersion != 3 || current.Revision != original.Revision+1 || current.PolicySequence != original.PolicySequence || original.Account != nil {
		t.Fatal("incorrect upgrade")
	}
	if err := original.ValidateAdvance(current); err != nil {
		t.Fatal(err)
	}
	raw, err := SealTrustState(root, b, current)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := OpenTrustState(root, b, raw, current.Revision)
	if err != nil || !reflect.DeepEqual(current, restored) {
		t.Fatal("format3 roundtrip failed")
	}
	trust, err := restored.AccountTrust()
	if err != nil || trust.MinimumSequence != 4 || trust.MinimumWrappingRevision != 2 {
		t.Fatal("floors missing after restart")
	}
	unchanged, err := current.AdvanceAccount(account, 2)
	if err != nil || unchanged.Revision != current.Revision {
		t.Fatal("unchanged account forced write")
	}
	unchanged.Account.Signature[0] ^= 1
	if !bytes.Equal(current.Account.Signature, account.Signature) {
		t.Fatal("account state aliases output")
	}
	revoked := account
	revoked.Active = false
	revoked.Sequence++
	revoked, err = vault.SignUserKeyState(revoked, priv)
	if err != nil {
		t.Fatal(err)
	}
	next, err := current.AdvanceAccount(revoked, 2)
	if err != nil || next.Account.Active {
		t.Fatal("revocation not retained")
	}
	if err := current.ValidateAdvance(next); err != nil {
		t.Fatal(err)
	}
	if _, err := next.AdvanceAccount(account, 2); err != vault.ErrRollback {
		t.Fatal("old active state replayed")
	}
	equivocal := account
	equivocal.Active = false
	equivocal, _ = vault.SignUserKeyState(equivocal, priv)
	if _, err := current.AdvanceAccount(equivocal, 2); err != ErrAccountEquivocation {
		t.Fatal("same-sequence equivocation accepted")
	}
	// A policy advance retains account state, even when that state revokes access.
	policy, _ := vault.DecodeSignedPolicy(a.SignedProfile)
	policy.Policy.Sequence++
	policy, _ = vault.SignPolicy(policy.Policy, current.SignerKeyID, 1, priv)
	a.SignedProfile, _ = vault.EncodeSignedPolicy(policy)
	advanced, err := next.Advance(a, r)
	if err != nil || advanced.Account.Active || advanced.Account.Sequence != revoked.Sequence {
		t.Fatal("policy update erased revocation")
	}
	if err := next.ValidateAdvance(advanced); err != nil {
		t.Fatal(err)
	}
	advanced.Account.Signature[0] ^= 1
	if !bytes.Equal(next.Account.Signature, revoked.Signature) {
		t.Fatal("policy advance aliases account")
	}
}

func TestTrustAccountRejectsDowngrades(t *testing.T) {
	_, _, initial, account, priv, _, _ := accountTrustFixture(t)
	current, err := initial.AdvanceAccount(account, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*vault.UserKeyState){func(a *vault.UserKeyState) { a.Encryption.Version-- }, func(a *vault.UserKeyState) { a.Signing.Version-- }, func(a *vault.UserKeyState) { a.MinimumEncryptionCertificate-- }, func(a *vault.UserKeyState) { a.MinimumSigningCertificate-- }} {
		changed := account
		changed.Sequence++
		mutate(&changed)
		changed, _ = vault.SignUserKeyState(changed, priv)
		if _, err := current.AdvanceAccount(changed, 2); err != ErrTrustRollback {
			t.Fatal("signed lower key floor accepted")
		}
		forged := current
		forged.Revision++
		forged.Account = &changed
		if err := current.ValidateAdvance(forged); err != ErrTrustRollback {
			t.Fatal("persistence bypassed floor check")
		}
	}
	if _, err := current.AdvanceAccount(account, 1); err != ErrTrustRollback {
		t.Fatal("wrapper rollback accepted")
	}
	for _, revision := range []uint64{0, math.MaxInt64 + 1} {
		if _, err := current.AdvanceAccount(account, revision); err != ErrTrustState {
			t.Fatal("bad wrapper floor accepted")
		}
	}
	for _, mutate := range []func(*TrustState){func(s *TrustState) { s.FormatVersion = 2 }, func(s *TrustState) { s.Account = nil }, func(s *TrustState) { s.WrappingRevision = 0 }, func(s *TrustState) { s.WrappingRevision = math.MaxInt64 + 1 }, func(s *TrustState) { s.SignerKeyID = "bad" }, func(s *TrustState) { a := *s.Account; a.Signature = nil; s.Account = &a }} {
		changed := current
		mutate(&changed)
		if _, err := changed.AccountTrust(); err != ErrTrustState {
			t.Fatal("invalid cached account trusted")
		}
		if _, err := changed.AdvanceAccount(account, 2); err != ErrTrustState {
			t.Fatal("invalid state advanced")
		}
	}
	exhausted := current
	exhausted.Revision = math.MaxUint64
	if _, err := exhausted.AdvanceAccount(account, 3); err != ErrTrustState {
		t.Fatal("revision overflow accepted")
	}
	downgrade := initial
	downgrade.Revision = current.Revision + 1
	if err := current.ValidateAdvance(downgrade); err != ErrTrustRollback {
		t.Fatal("format downgrade lost account floor")
	}
	noChange := current
	noChange.Revision++
	if err := current.ValidateAdvance(noChange); err != ErrProfileRollback {
		t.Fatal("empty advance accepted")
	}
	other := account
	other.Active = false
	other, _ = vault.SignUserKeyState(other, priv)
	noChange.Account = &other
	if err := current.ValidateAdvance(noChange); err != ErrAccountEquivocation {
		t.Fatal("writer accepted equivocation")
	}
	raised, err := current.AdvanceAccount(account, 3)
	if err != nil || current.ValidateAdvance(raised) != nil {
		t.Fatal("wrapper-only advance rejected")
	}
	if accountFloorsAdvance(current.Account, nil) {
		t.Fatal("missing state accepted")
	}
	if err := current.ValidateAdvance(TrustState{}); err != ErrTrustState {
		t.Fatal("invalid state persisted")
	}
	policy, _ := vault.DecodeSignedPolicy(current.SignedProfile)
	policy.Policy.Profile = vault.Default
	policy, _ = vault.SignPolicy(policy.Policy, current.SignerKeyID, 1, priv)
	equivocalPolicy := current
	equivocalPolicy.Revision++
	equivocalPolicy.SignedProfile, _ = vault.EncodeSignedPolicy(policy)
	digest := sha256.Sum256(equivocalPolicy.SignedProfile)
	equivocalPolicy.PolicyDigest = bytes.Clone(digest[:])
	if err := current.ValidateAdvance(equivocalPolicy); err != ErrProfileEquivocation {
		t.Fatal("same-sequence policy change persisted")
	}
	policy.Policy.Sequence++
	policy, _ = vault.SignPolicy(policy.Policy, current.SignerKeyID, 1, priv)
	high := current
	high.PolicySequence = policy.Policy.Sequence
	high.SignedProfile, _ = vault.EncodeSignedPolicy(policy)
	digest = sha256.Sum256(high.SignedProfile)
	high.PolicyDigest = bytes.Clone(digest[:])
	lower := current
	lower.Revision = high.Revision + 1
	if err := high.ValidateAdvance(lower); err != ErrProfileRollback {
		t.Fatal("policy rollback persisted during account update")
	}
	_, _, legacy, _, _, _ := trustFixture(t)
	if _, err := legacy.AdvanceAccount(account, 1); err != ErrTrustState {
		t.Fatal("non-UUID signer silently upgraded")
	}
}
