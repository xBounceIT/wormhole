package sharedpg

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func trustFixture(t *testing.T) ([]byte, TrustBinding, TrustState, *UnverifiedAdmission, AdmissionRequest, ed25519.PrivateKey) {
	t.Helper()
	a, r, p, priv := signedAdmissionFixture(t)
	s, err := NewTrustState(a, r, p)
	if err != nil {
		t.Fatal(err)
	}
	b := TrustBinding{WorkspaceID: r.WorkspaceID, UserID: r.UserID, DeviceID: r.DeviceID, KeyID: uuid.MustParse("22345678-1234-4234-8234-123456789abc"), KeyVersion: 1}
	return bytes.Repeat([]byte{0x72}, 32), b, s, a, r, priv
}

func TestCachedTrustPolicyAuthenticatesDocument(t *testing.T) {
	for _, change := range []func(*TrustState){
		func(s *TrustState) { s.SignedProfile = nil }, func(s *TrustState) { s.SignedProfile = []byte("bad") },
		func(s *TrustState) { s.PolicySequence++ }, func(s *TrustState) { s.PolicySequence-- },
		func(s *TrustState) { s.PublicKey = bytes.Repeat([]byte{0}, 32) }, func(s *TrustState) { s.PolicyDigest = bytes.Repeat([]byte{0}, 32) },
	} {
		_, _, s, _, _, _ := trustFixture(t)
		change(&s)
		if _, err := s.Policy(); err != ErrTrustState {
			t.Fatal("invalid cached policy authenticated")
		}
	}
	_, _, s, a, _, _ := trustFixture(t)
	a.SignedProfile[0] ^= 1
	if p, err := s.Policy(); err != nil || p.Profile != vault.Standard {
		t.Fatal("enrolled document aliases caller")
	}
	signed, err := vault.DecodeSignedPolicy(s.SignedProfile)
	if err != nil {
		t.Fatal(err)
	}
	signed.Policy.Profile = vault.Default
	s.SignedProfile, err = vault.EncodeSignedPolicy(signed)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(s.SignedProfile)
	s.PolicyDigest = bytes.Clone(digest[:])
	if _, err := s.Policy(); err != ErrTrustState {
		t.Fatal("matching digest bypassed signature verification")
	}
}

func TestTrustStateFitsMaximumCanonicalSigner(t *testing.T) {
	root, b, _, a, r, priv := trustFixture(t)
	signed, err := vault.DecodeSignedPolicy(a.SignedProfile)
	if err != nil {
		t.Fatal(err)
	}
	signer := strings.Repeat("\x01", vault.MaxContextBytes)
	signed, err = vault.SignPolicy(signed.Policy, signer, 1, priv)
	if err != nil {
		t.Fatal(err)
	}
	a.SignedProfile, err = vault.EncodeSignedPolicy(signed)
	if err != nil {
		t.Fatal(err)
	}
	pinned := PolicyTrust{WorkspaceID: b.WorkspaceID, SignerKeyID: signer, SignerKeyVersion: 1, PublicKey: priv.Public().(ed25519.PublicKey), MinimumSequence: 1}
	s, err := NewTrustState(a, r, pinned)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := SealTrustState(root, b, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenTrustState(root, b, raw, 1); err != nil {
		t.Fatal(err)
	}
}

func resignTrustPolicy(t *testing.T, a *UnverifiedAdmission, priv ed25519.PrivateKey, sequence uint64, profile vault.Profile) {
	t.Helper()
	p, err := vault.DecodeSignedPolicy(a.SignedProfile)
	if err != nil {
		t.Fatal(err)
	}
	p.Policy.Sequence = sequence
	p.Policy.Profile = profile
	p, err = vault.SignPolicy(p.Policy, p.SignerKeyID, p.SignerKeyVersion, priv)
	if err != nil {
		t.Fatal(err)
	}
	a.SignedProfile, err = vault.EncodeSignedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTrustStateEncryptedRoundTripAndBinding(t *testing.T) {
	root, b, s, _, _, _ := trustFixture(t)
	raw, err := SealTrustState(root, b, s)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, root) || bytes.Contains(raw, []byte(s.SignerKeyID)) || bytes.Contains(raw, s.PublicKey) {
		t.Fatal("trust state exposed plaintext")
	}
	duplicate, err := SealTrustState(root, b, s)
	if err != nil || bytes.Equal(raw, duplicate) {
		t.Fatal("nonce was reused")
	}
	opened, err := OpenTrustState(root, b, raw, 1)
	if err != nil || !reflect.DeepEqual(opened, s) {
		t.Fatalf("trust state roundtrip failed: %v", err)
	}
	if _, err := OpenTrustState(root, b, raw, 2); err != ErrTrustRollback {
		t.Fatal("revision rollback accepted")
	}
	for _, change := range []func(*TrustBinding){
		func(b *TrustBinding) { b.WorkspaceID = b.KeyID }, func(b *TrustBinding) { b.UserID = b.KeyID }, func(b *TrustBinding) { b.DeviceID = b.KeyID },
		func(b *TrustBinding) { b.KeyID = b.DeviceID }, func(b *TrustBinding) { b.KeyVersion++ },
		func(b *TrustBinding) { b.WorkspaceID = uuid.Nil }, func(b *TrustBinding) { b.UserID = uuid.Nil }, func(b *TrustBinding) { b.DeviceID = uuid.Nil }, func(b *TrustBinding) { b.KeyID = uuid.Nil }, func(b *TrustBinding) { b.KeyVersion = 0 },
	} {
		bad := b
		change(&bad)
		if _, err := OpenTrustState(root, bad, raw, 1); err != ErrTrustState {
			t.Fatal("binding substitution accepted")
		}
	}
	for _, key := range [][]byte{nil, bytes.Repeat([]byte{1}, 32)} {
		if _, err := OpenTrustState(key, b, raw, 1); err != ErrTrustState {
			t.Fatal("wrong key accepted")
		}
	}
	var envelope vault.Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Ciphertext[0] ^= 1
	altered, _ := json.Marshal(envelope)
	for _, bad := range [][]byte{nil, []byte("null"), []byte("{"), []byte(strings.Repeat(" ", MaxTrustStateBytes+1)), append(bytes.Clone(raw), ' '), altered} {
		if _, err := OpenTrustState(root, b, bad, 1); err != ErrTrustState {
			t.Fatal("corrupt state accepted")
		}
	}
	if _, err := OpenTrustState(root, b, raw, 0); err != ErrTrustState {
		t.Fatal("missing revision floor accepted")
	}
	if _, err := SealTrustState(nil, b, s); err != ErrTrustState {
		t.Fatal("invalid root accepted")
	}
	badBinding := b
	badBinding.UserID = b.KeyID
	if _, err := SealTrustState(root, badBinding, s); err != ErrTrustState {
		t.Fatal("state identity rebound")
	}
	if _, err := SealTrustState(root, TrustBinding{}, s); err != ErrTrustState {
		t.Fatal("invalid binding accepted")
	}
}

func TestTrustStateAdvanceAndEquivocation(t *testing.T) {
	_, _, s, a, r, priv := trustFixture(t)
	unchanged, err := s.Advance(a, r)
	if err != nil || !reflect.DeepEqual(unchanged, s) {
		t.Fatal("unchanged profile changed revision")
	}
	unchanged.PublicKey[0] ^= 1
	if bytes.Equal(unchanged.PublicKey, s.PublicKey) {
		t.Fatal("advanced state aliases old key")
	}
	pinned := s.PolicyTrust()
	pinned.PublicKey[0] ^= 1
	if bytes.Equal(pinned.PublicKey, s.PublicKey) {
		t.Fatal("trust view aliases state")
	}
	resignTrustPolicy(t, a, priv, 8, vault.Standard)
	next, err := s.Advance(a, r)
	if err != nil || next.Revision != 2 || next.PolicySequence != 8 || bytes.Equal(next.PolicyDigest, s.PolicyDigest) {
		t.Fatalf("advance failed: %v", err)
	}
	overflow := s
	overflow.Revision = math.MaxUint64
	if _, err := overflow.Advance(a, r); err != ErrTrustState {
		t.Fatal("revision overflow accepted")
	}
	resignTrustPolicy(t, a, priv, 6, vault.Standard)
	if _, err := s.Advance(a, r); err != ErrProfileRollback {
		t.Fatal("old profile accepted")
	}
	resignTrustPolicy(t, a, priv, 7, vault.Default)
	if _, err := s.Advance(a, r); err != ErrProfileEquivocation {
		t.Fatal("same-sequence alteration accepted")
	}
	bad := r
	bad.UserID = uuid.Nil
	if _, err := s.Advance(a, bad); err != ErrTrustState {
		t.Fatal("identity changed during advance")
	}
	if _, err := (TrustState{}).Advance(a, r); err != ErrTrustState {
		t.Fatal("empty trust initialized during advance")
	}
	if _, err := NewTrustState(nil, r, s.PolicyTrust()); err != ErrProfileAuthentication {
		t.Fatal("unverified enrollment accepted")
	}
}

func TestTrustStateRejectsAuthenticatedMalformedPayload(t *testing.T) {
	root, b, s, _, _, _ := trustFixture(t)
	key, err := vault.DeriveKey(root, b.WorkspaceID[:], vault.PurposeSharedTrust)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(key)
	binding, _ := b.binding()
	encode := func(plain []byte) []byte {
		t.Helper()
		e, err := vault.Seal(key, binding, plain)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for _, change := range []func(*TrustState){
		func(s *TrustState) { s.FormatVersion = 1 }, func(s *TrustState) { s.Revision = 0 }, func(s *TrustState) { s.WorkspaceID = uuid.Nil }, func(s *TrustState) { s.UserID = uuid.Nil }, func(s *TrustState) { s.DeviceID = uuid.Nil },
		func(s *TrustState) { s.SignerKeyID = "" }, func(s *TrustState) { s.SignerKeyID = strings.Repeat("x", 1025) }, func(s *TrustState) { s.SignerKeyID = "a\x00b" },
		func(s *TrustState) { s.SignerKeyVersion = 0 }, func(s *TrustState) { s.PublicKey = nil }, func(s *TrustState) { s.PolicySequence = 0 }, func(s *TrustState) { s.PolicyDigest = nil },
		func(s *TrustState) { s.UserID = b.KeyID },
	} {
		bad := s
		change(&bad)
		plain, _ := json.Marshal(bad)
		if _, err := OpenTrustState(root, b, encode(plain), 1); err != ErrTrustState {
			t.Fatal("invalid authenticated payload accepted")
		}
		if _, err := SealTrustState(root, b, bad); err != ErrTrustState {
			t.Fatal("invalid state sealed")
		}
	}
	plain, _ := json.Marshal(s)
	for _, bad := range [][]byte{[]byte("{"), append(bytes.Clone(plain), ' '), []byte(strings.Replace(string(plain), `"revision":1`, `"revision":1,"revision":1`, 1))} {
		if _, err := OpenTrustState(root, b, encode(bad), 1); err != ErrTrustState {
			t.Fatal("noncanonical payload accepted")
		}
	}
}
