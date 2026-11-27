package sharedpg

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func signedAdmissionFixture(t *testing.T) (*UnverifiedAdmission, AdmissionRequest, PolicyTrust, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	expected := admissionRequest()
	policy := vault.Policy{FormatVersion: vault.FormatVersion, WorkspaceID: expected.WorkspaceID.String(), Sequence: 7, Profile: vault.Standard, KDF: vault.KDFV1, OrgEscrow: true, MinAPI: 1, MaxAPI: 2}
	signed, err := vault.SignPolicy(policy, "org-key", 1, priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := vault.EncodeSignedPolicy(signed)
	if err != nil {
		t.Fatal(err)
	}
	admission := &UnverifiedAdmission{WorkspaceID: expected.WorkspaceID, UserID: expected.UserID, DeviceID: expected.DeviceID, MinAPI: 1, MaxAPI: 2, SignedProfile: raw}
	trust := PolicyTrust{WorkspaceID: expected.WorkspaceID, SignerKeyID: "org-key", SignerKeyVersion: 1, PublicKey: pub, MinimumSequence: 7}
	return admission, expected, trust, priv
}

func TestVerifyAdmissionPolicy(t *testing.T) {
	a, r, trust, _ := signedAdmissionFixture(t)
	policy, err := VerifyAdmissionPolicy(a, r, trust)
	if err != nil || policy.Sequence != 7 || policy.Profile != vault.Standard {
		t.Fatalf("valid profile rejected: %v", err)
	}
	trust.MinimumSequence = 6
	if _, err := VerifyAdmissionPolicy(a, r, trust); err != nil {
		t.Fatal("newer signed policy rejected")
	}
	trust.MinimumSequence = 8
	if _, err := VerifyAdmissionPolicy(a, r, trust); err != ErrProfileRollback {
		t.Fatal("rollback accepted")
	}
	// An old but altered policy must fail authentication before rollback handling.
	signed, err := vault.DecodeSignedPolicy(a.SignedProfile)
	if err != nil {
		t.Fatal(err)
	}
	signed.Policy.Sequence = 6
	a.SignedProfile, err = vault.EncodeSignedPolicy(signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAdmissionPolicy(a, r, trust); err != ErrProfileAuthentication {
		t.Fatal("unauthenticated document reached rollback handling")
	}
}

func TestAdmissionPolicyRejectsUntrustedMetadata(t *testing.T) {
	for _, mutate := range []func(*UnverifiedAdmission, *AdmissionRequest, *PolicyTrust){
		func(a *UnverifiedAdmission, r *AdmissionRequest, p *PolicyTrust) { a.WorkspaceID = uuid.Nil },
		func(a *UnverifiedAdmission, r *AdmissionRequest, p *PolicyTrust) { a.UserID = uuid.Nil },
		func(a *UnverifiedAdmission, r *AdmissionRequest, p *PolicyTrust) { a.DeviceID = uuid.Nil },
		func(a *UnverifiedAdmission, r *AdmissionRequest, p *PolicyTrust) { a.SignedProfile = nil },
		func(a *UnverifiedAdmission, r *AdmissionRequest, p *PolicyTrust) {
			a.SignedProfile = append(a.SignedProfile, ' ')
		},
		func(a *UnverifiedAdmission, r *AdmissionRequest, p *PolicyTrust) {
			p.PublicKey = make([]byte, ed25519.PublicKeySize)
		},
		func(a *UnverifiedAdmission, r *AdmissionRequest, p *PolicyTrust) { p.SignerKeyID = "other" },
		func(a *UnverifiedAdmission, r *AdmissionRequest, p *PolicyTrust) { p.SignerKeyVersion = 2 },
		func(a *UnverifiedAdmission, r *AdmissionRequest, p *PolicyTrust) { a.MinAPI = 0 },
		func(a *UnverifiedAdmission, r *AdmissionRequest, p *PolicyTrust) { a.MinAPI = 2 },
		func(a *UnverifiedAdmission, r *AdmissionRequest, p *PolicyTrust) { a.MaxAPI = 0 },
		func(a *UnverifiedAdmission, r *AdmissionRequest, p *PolicyTrust) { a.MaxAPI = 3 },
		func(a *UnverifiedAdmission, r *AdmissionRequest, p *PolicyTrust) { r.API = 3 },
	} {
		a, r, p, _ := signedAdmissionFixture(t)
		mutate(a, &r, &p)
		if got, err := VerifyAdmissionPolicy(a, r, p); err != ErrProfileAuthentication || got != (vault.Policy{}) {
			t.Fatalf("accepted untrusted metadata: %v", err)
		}
	}
	a, r, p, priv := signedAdmissionFixture(t)
	if _, err := VerifyAdmissionPolicy(nil, r, p); err != ErrProfileAuthentication {
		t.Fatal("nil admission accepted")
	}
	signed, err := vault.DecodeSignedPolicy(a.SignedProfile)
	if err != nil {
		t.Fatal(err)
	}
	signed.Policy.WorkspaceID = "22345678-1234-4234-8234-123456789abc"
	signed, err = vault.SignPolicy(signed.Policy, p.SignerKeyID, p.SignerKeyVersion, priv)
	if err != nil {
		t.Fatal(err)
	}
	a.SignedProfile, err = vault.EncodeSignedPolicy(signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAdmissionPolicy(a, r, p); err != ErrProfileAuthentication {
		t.Fatal("cross-workspace signed policy accepted")
	}
}

func TestAdmissionPolicyTrustConfiguration(t *testing.T) {
	for _, mutate := range []func(*AdmissionRequest, *PolicyTrust){
		func(r *AdmissionRequest, p *PolicyTrust) { r.API = 0 }, func(r *AdmissionRequest, p *PolicyTrust) { r.WorkspaceID = uuid.Nil },
		func(r *AdmissionRequest, p *PolicyTrust) { r.UserID = uuid.Nil }, func(r *AdmissionRequest, p *PolicyTrust) { r.DeviceID = uuid.Nil },
		func(r *AdmissionRequest, p *PolicyTrust) { p.WorkspaceID = uuid.Nil }, func(r *AdmissionRequest, p *PolicyTrust) { p.SignerKeyID = "" },
		func(r *AdmissionRequest, p *PolicyTrust) { p.SignerKeyVersion = 0 }, func(r *AdmissionRequest, p *PolicyTrust) { p.PublicKey = nil },
		func(r *AdmissionRequest, p *PolicyTrust) { p.MinimumSequence = 0 },
	} {
		a, r, p, _ := signedAdmissionFixture(t)
		mutate(&r, &p)
		if _, err := VerifyAdmissionPolicy(a, r, p); err != ErrConfiguration {
			t.Fatal("invalid trust configuration accepted")
		}
	}
}
