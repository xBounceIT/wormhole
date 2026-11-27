package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func reconciliationFixture(t *testing.T) (*Session, TrustBinding, PendingEnrollment, *AccountMaster, *UnverifiedAccountKeys) {
	t.Helper()
	f := invitationCommitFixture(t, 0)
	request, err := f.prepare()
	if err != nil {
		t.Fatal(err)
	}
	defer request.Wipe()
	b := TrustBinding{WorkspaceID: f.i.WorkspaceID, UserID: f.i.Enrollment.Context.UserID, DeviceID: f.device, KeyID: uuid.New(), KeyVersion: 1}
	p, err := request.PendingEnrollment(b)
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := hex.DecodeString(string(request.params[8]))
	ciphertext, _ := hex.DecodeString(string(request.params[9]))
	binding := vault.UserKeyBinding{WorkspaceID: b.WorkspaceID, UserID: b.UserID, Encryption: vault.KeyRef{ID: f.plan.Proof.EncryptionKeyID, Version: 1}, Signing: vault.KeyRef{ID: f.plan.Proof.SigningKeyID, Version: 1}, Revision: 1}
	material := &UnverifiedAccountKeys{Binding: binding, Envelope: vault.Envelope{FormatVersion: 1, SuiteID: vault.SuiteAES256GCM, KeyID: binding.Encryption.ID.String(), KeyVersion: 1, Nonce: nonce, Ciphertext: ciphertext}, KDF: p.KDF, ASKRequired: p.ASKRequired, State: cloneAccountState(p.Trust.Account), EnrollmentCertificate: &p.Certificate}
	s, _ := readySession(t, false)
	seedPasswordSession(t, s)
	s.admission.WorkspaceID = b.WorkspaceID
	s.admission.UserID = b.UserID
	s.admission.DeviceID = b.DeviceID
	return s, b, p, f.master, material
}

func TestEnrollmentReconciliation(t *testing.T) {
	s, b, p, master, material := reconciliationFixture(t)
	proof, err := s.VerifyPendingEnrollment(context.Background(), b, p, master, material)
	if err != nil {
		t.Fatal(err)
	}
	state, err := proof.Activation(b, p)
	if err != nil || state.Enrollment == nil || state.Enrollment.Encryption != material.Binding.Encryption {
		t.Fatal("activation", err)
	}
	state.PublicKey[0] ^= 1
	original, err := proof.Activation(b, p)
	if err != nil || bytes.Equal(state.PublicKey, original.PublicKey) {
		t.Fatal("activation aliases proof")
	}
	raw, _ := json.Marshal(proof)
	if string(raw) != "{}" {
		t.Fatal("proof serialized")
	}
	digest := proof.CertificateDigest()
	digest[0] ^= 1
	if bytes.Equal(digest, proof.CertificateDigest()) {
		t.Fatal("digest alias")
	}
	var absent *VerifiedEnrollment
	if absent.CertificateDigest() != nil {
		t.Fatal("nil proof")
	}
	if _, err := absent.Activation(b, p); err != ErrTrustState {
		t.Fatal(err)
	}
	wrong := b
	wrong.DeviceID = uuid.New()
	if _, err := proof.Activation(wrong, p); err != ErrTrustState {
		t.Fatal(err)
	}
	changed := p
	changed.CapsuleDigest = bytes.Repeat([]byte{12}, 32)
	if _, err := proof.Activation(b, changed); err != ErrTrustState {
		t.Fatal("proof transferred to other intent", err)
	}
	for _, mode := range []string{"ctx", "binding", "master", "login", "closed", "unready", "capability", "epoch", "device", "nil-material", "state", "certificate", "mixed", "kdf", "ask", "capsule", "shape", "different-cert", "wrapper", "master-preset", "master-ask", "wrong-password", "closed-master", "cancel", "cancel-after-open"} {
		t.Run(mode, func(t *testing.T) {
			s, b, p, m, a := reconciliationFixture(t)
			ctx := context.Background()
			switch mode {
			case "ctx":
				ctx = nil
			case "binding":
				b.KeyID = uuid.Nil
			case "master":
				m = nil
			case "login":
				m.loginName = "another"
			case "closed":
				s.cancel()
			case "unready":
				s.ready.Store(false)
			case "capability":
				s.capability.Close()
				s.capability = nil
			case "epoch":
				s.authEpoch++
			case "device":
				s.admission.DeviceID = uuid.New()
			case "nil-material":
				a = nil
			case "state":
				a.State = nil
			case "certificate":
				a.EnrollmentCertificate = nil
			case "mixed":
				a.SigningCertificate = &vault.UserKeyCertificate{}
			case "kdf":
				a.KDF = vault.KDFV2
			case "ask":
				a.ASKRequired = !a.ASKRequired
			case "capsule":
				a.Envelope.Ciphertext[0] ^= 1
			case "shape":
				changed := *a.EnrollmentCertificate
				changed.FormatVersion = 0
				a.EnrollmentCertificate = &changed
			case "different-cert":
				changed := *a.EnrollmentCertificate
				changed.Rekey.Signature = bytes.Clone(changed.Rekey.Signature)
				changed.Rekey.Signature[0] ^= 1
				a.EnrollmentCertificate = &changed
			case "wrapper":
				a.Binding.Revision++
			case "master-preset":
				m.preset = vault.KDFV2
			case "master-ask":
				m.askUsed = false
			case "wrong-password":
				m.memory.(*masterMemoryProbe).data[0] ^= 1
			case "closed-master":
				m.Close()
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "cancel-after-open":
				m.memory.(*masterMemoryProbe).afterUse = s.cancel
			}
			if result, err := s.VerifyPendingEnrollment(ctx, b, p, m, a); err == nil || result != nil {
				t.Fatal("invalid evidence accepted")
			}
		})
	}
}

func TestPendingEnrollmentObservations(t *testing.T) {
	root, b, p := pendingEnrollmentFixture(t, 0)
	org := ed25519.NewKeyFromSeed(make([]byte, 32))
	defer vault.Wipe(org)
	r := admissionRequest()
	r.WorkspaceID = b.WorkspaceID
	r.UserID = b.UserID
	r.DeviceID = b.DeviceID
	a := &UnverifiedAdmission{WorkspaceID: b.WorkspaceID, UserID: b.UserID, DeviceID: b.DeviceID, MinAPI: 1, MaxAPI: 1, SignedProfile: bytes.Clone(p.Trust.SignedProfile)}
	same, err := p.ObserveProfile(b, a, r)
	if err != nil || !reflect.DeepEqual(same, p) {
		t.Fatal(err)
	}
	same, err = p.ObserveAccount(b, *p.Trust.Account, 1)
	if err != nil || !reflect.DeepEqual(same, p) {
		t.Fatal(err)
	}
	policy, err := vault.DecodeSignedPolicy(a.SignedProfile)
	if err != nil {
		t.Fatal(err)
	}
	policy.Policy.Sequence++
	policy, err = vault.SignPolicy(policy.Policy, policy.SignerKeyID, policy.SignerKeyVersion, org)
	if err != nil {
		t.Fatal(err)
	}
	a.SignedProfile, err = vault.EncodeSignedPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	profiled, err := p.ObserveProfile(b, a, r)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ValidateObservationAdvance(b, profiled); err != nil {
		t.Fatal(err)
	}
	state := *p.Trust.Account
	state.Sequence++
	state.Active = false
	state, err = vault.SignUserKeyState(state, org)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := profiled.ObserveAccount(b, state, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := profiled.ValidateObservationAdvance(b, revoked); err != nil {
		t.Fatal(err)
	}
	if err := revoked.ValidateObservationAdvance(b, revoked); err != nil {
		t.Fatal(err)
	}
	if err := revoked.ValidateObservationAdvance(b, profiled); err == nil {
		t.Fatal("revocation dropped")
	}
	if _, err := revoked.ObserveAccount(b, *p.Trust.Account, 1); err == nil {
		t.Fatal("state rollback")
	}
	raw, err := SealPendingEnrollment(root, b, revoked)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := OpenPendingEnrollment(root, b, raw)
	if err != nil || !reflect.DeepEqual(restored, revoked) {
		t.Fatal(err)
	}
	clone := restored.ObservedTrust()
	clone.Account.Signature[0] ^= 1
	if reflect.DeepEqual(clone, restored.ObservedTrust()) {
		t.Fatal("observation aliases journal")
	}
	tls := trustedTLSFixture(t, revoked.ObservedTrust(), org, 1)
	secured, err := revoked.ObserveTLS(b, tls)
	if err != nil {
		t.Fatal(err)
	}
	if err := revoked.ValidateObservationAdvance(b, secured); err != nil {
		t.Fatal(err)
	}
	if err := p.ValidateObservationSnapshot(b, secured); err != nil {
		t.Fatal("multiple signed observations could not be reconciled", err)
	}
	if err := p.ValidateObservationAdvance(b, secured); err == nil {
		t.Fatal("ordinary observation writes lost their adjacent-revision guard")
	}
	if err := secured.ValidateObservationSnapshot(b, p); err == nil {
		t.Fatal("snapshot comparison discarded revocation, policy and TLS floors")
	}
	if err := secured.ValidateObservationSnapshot(b, secured); err != nil {
		t.Fatal("identical snapshot was not idempotent", err)
	}
	accountOnly, err := p.ObserveAccount(b, state, 1)
	if err != nil {
		t.Fatal(err)
	}
	if accountOnly.ValidateObservationSnapshot(b, profiled) == nil || profiled.ValidateObservationSnapshot(b, accountOnly) == nil {
		t.Fatal("divergent signed observations could be combined by losing a floor")
	}
	same, err = secured.ObserveTLS(b, tls)
	if err != nil || !reflect.DeepEqual(same, secured) {
		t.Fatal(err)
	}
	if _, err := p.ObserveTLS(b, nil); err == nil {
		t.Fatal("invalid TLS")
	}
	bad := p
	bad.FormatVersion = 0
	if _, err := bad.ObserveTLS(b, tls); err != ErrTrustState {
		t.Fatal(err)
	}
	if _, err := bad.ObserveProfile(b, a, r); err != ErrTrustState {
		t.Fatal(err)
	}
	if _, err := bad.ObserveAccount(b, state, 1); err != ErrTrustState {
		t.Fatal(err)
	}
	if err := bad.ValidateObservationAdvance(b, p); err != ErrTrustState {
		t.Fatal(err)
	}
	if err := bad.ValidateObservationSnapshot(b, p); err != ErrTrustState {
		t.Fatal("invalid snapshot accepted", err)
	}
	changed := p
	changed.RoleTag = "otheraaa"
	if err := p.ValidateObservationAdvance(b, changed); err != ErrTrustState {
		t.Fatal("changed preparation", err)
	}
	if err := p.ValidateObservationSnapshot(b, changed); err != ErrTrustState {
		t.Fatal("snapshot changed prepared identities", err)
	}
	a.SignedProfile[0] ^= 1
	if _, err := p.ObserveProfile(b, a, r); err == nil {
		t.Fatal("forged profile")
	}
}

func TestReconciliationPreservesRevocation(t *testing.T) {
	s, b, p, m, a := reconciliationFixture(t)
	org := ed25519.NewKeyFromSeed(make([]byte, 32))
	defer vault.Wipe(org)
	state := *a.State
	state.Sequence++
	state.Active = false
	var err error
	state, err = vault.SignUserKeyState(state, org)
	if err != nil {
		t.Fatal(err)
	}
	p, err = p.ObserveAccount(b, state, 1)
	if err != nil {
		t.Fatal(err)
	}
	a.State = &state
	if result, err := s.VerifyPendingEnrollment(context.Background(), b, p, m, a); err == nil || result != nil {
		t.Fatal("revoked enrollment activated")
	}
}

func TestReconciliationCurrentPolicy(t *testing.T) {
	for _, mode := range []string{"stronger-kdf", "paranoid", "admin", "unlocked-master"} {
		t.Run(mode, func(t *testing.T) {
			s, b, p, m, a := reconciliationFixture(t)
			org := ed25519.NewKeyFromSeed(make([]byte, 32))
			defer vault.Wipe(org)
			if mode == "admin" || mode == "unlocked-master" {
				// A non-admin may have enrolled without ASK, then become an administrator.
				original, e := vault.DecodeSignedPolicy(p.Trust.SignedProfile)
				if e != nil {
					t.Fatal(e)
				}
				original.Policy.KDF = vault.KDFV2
				original.Policy.ASKRequired = false
				original, e = vault.SignPolicy(original.Policy, original.SignerKeyID, original.SignerKeyVersion, org)
				if e != nil {
					t.Fatal(e)
				}
				p.Trust.SignedProfile, e = vault.EncodeSignedPolicy(original)
				if e != nil {
					t.Fatal(e)
				}
				d := sha256.Sum256(p.Trust.SignedProfile)
				p.Trust.PolicyDigest = d[:]
				p.KDF, m.preset, a.KDF = vault.KDFV2, vault.KDFV2, vault.KDFV2
				p.ASKRequired, m.askUsed, a.ASKRequired = false, false, false
				s.administrator = mode == "admin"
			}
			signed, e := vault.DecodeSignedPolicy(p.Trust.SignedProfile)
			if e != nil {
				t.Fatal(e)
			}
			signed.Policy.Sequence++
			switch mode {
			case "stronger-kdf":
				signed.Policy.KDF = vault.KDFV2
			case "paranoid":
				signed.Policy.Profile = vault.Paranoid
				signed.Policy.KDF = vault.KDFV3
			case "admin", "unlocked-master":
				signed.Policy.Profile = vault.Hardened
			}
			signed, e = vault.SignPolicy(signed.Policy, signed.SignerKeyID, signed.SignerKeyVersion, org)
			if e != nil {
				t.Fatal(e)
			}
			raw, e := vault.EncodeSignedPolicy(signed)
			if e != nil {
				t.Fatal(e)
			}
			admission := &UnverifiedAdmission{WorkspaceID: b.WorkspaceID, UserID: b.UserID, DeviceID: b.DeviceID, MinAPI: 1, MaxAPI: 1, SignedProfile: raw}
			p, e = p.ObserveProfile(b, admission, s.admission)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "unlocked-master" {
				m.memory = &unlockedReconciliationMemory{m.memory}
			}
			result, e := s.VerifyPendingEnrollment(context.Background(), b, p, m, a)
			if e == nil || result != nil {
				t.Fatal("current requirements ignored")
			}
			if mode == "unlocked-master" && e != securemem.ErrUnavailable {
				t.Fatal("unlocked memory accepted", e)
			}
			if mode == "admin" && s.capability.Locked() && e != vault.ErrPolicy {
				t.Fatal("administrator ASK ignored", e)
			}
		})
	}
}

type unlockedReconciliationMemory struct{ accountMasterMemory }

func (*unlockedReconciliationMemory) Locked() bool { return false }

func TestVerifiedEnrollmentConfirmationGuards(t *testing.T) {
	s, b, p, master, material := reconciliationFixture(t)
	proof, err := s.VerifyPendingEnrollment(context.Background(), b, p, master, material)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := s.ConfirmVerifiedEnrollment(context.Background(), b, p, nil); err != ErrAuthentication || result != nil {
		t.Fatal(err)
	}
	other := NewSession()
	defer other.Close(context.Background())
	if result, err := other.ConfirmVerifiedEnrollment(context.Background(), b, p, proof); err != ErrAuthentication || result != nil {
		t.Fatal(err)
	}
	wrong := p
	wrong.CapsuleDigest = bytes.Repeat([]byte{82}, 32)
	if result, err := s.ConfirmVerifiedEnrollment(context.Background(), b, wrong, proof); err != ErrTrustState || result != nil {
		t.Fatal(err)
	}
	if result, err := s.ConfirmVerifiedEnrollment(nil, b, p, proof); err != ErrConfiguration || result != nil {
		t.Fatal(err)
	}
	if result, err := s.ConfirmVerifiedEnrollment(context.Background(), b, p, proof); err != ErrQuery || result != nil {
		t.Fatal("fake transport confirmed", err)
	}
	var absent *ConfirmedEnrollment
	if _, err := absent.ConfirmedActivation(b, p); err != ErrTrustState {
		t.Fatal(err)
	}
	if _, err := (&ConfirmedEnrollment{}).ConfirmedActivation(b, p); err != ErrTrustState {
		t.Fatal(err)
	}
}
