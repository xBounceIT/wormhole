package vault

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func testPolicy() Policy {
	return Policy{FormatVersion: 1, WorkspaceID: "workspace", Sequence: 1, Profile: Standard, KDF: KDFV1, OrgEscrow: true, MinAPI: 1, MaxAPI: 1}
}

func TestDirectRoutePolicyAllowsOnlyDefaultAndStandard(t *testing.T) {
	for profile, allowed := range map[Profile]bool{
		Default: true, Standard: true, Hardened: false, Paranoid: false, "": false, "future": false,
	} {
		if profile.AllowsDirectRoute() != allowed {
			t.Errorf("profile %q, want Direct allowed = %t", profile, allowed)
		}
	}
}

func TestEffectiveProfileFailsClosed(t *testing.T) {
	for _, a := range []Profile{Default, Standard, Hardened, Paranoid} {
		for _, b := range []Profile{Default, Standard, Hardened, Paranoid} {
			for _, c := range []Profile{Default, Standard, Hardened, Paranoid} {
				got := EffectiveProfile(a, b, c)
				if profileRank(got) < profileRank(a) || profileRank(got) < profileRank(b) || profileRank(got) < profileRank(c) {
					t.Fatal("weakened floor")
				}
			}
		}
	}
	for _, p := range []Profile{"", "future"} {
		if EffectiveProfile(Default, p, Default) != Paranoid {
			t.Fatal("invalid policy failed open")
		}
	}
}

func TestSignedPolicyTamperAndRollback(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signed, err := SignPolicy(testPolicy(), "org", 1, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPolicy(signed, "workspace", "org", 1, pub, 1); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPolicy(signed, "workspace", "org", 1, pub, 2); err != ErrRollback {
		t.Fatal("rollback accepted")
	}
	if err := VerifyPolicy(signed, "other", "org", 1, pub, 1); err != ErrAuthentication {
		t.Fatal("wrong workspace")
	}
	if err := VerifyPolicy(signed, "workspace", "other", 1, pub, 1); err != ErrAuthentication {
		t.Fatal("wrong signer")
	}
	if err := VerifyPolicy(signed, "workspace", "org", 2, pub, 1); err != ErrAuthentication {
		t.Fatal("wrong signer version")
	}
	for name, mutate := range map[string]func(*SignedPolicy){
		"profile": func(s *SignedPolicy) { s.Policy.Profile = Default }, "sequence": func(s *SignedPolicy) { s.Policy.Sequence++ },
		"kdf": func(s *SignedPolicy) { s.Policy.KDF = KDFV2 }, "ask": func(s *SignedPolicy) { s.Policy.ASKRequired = true },
		"api": func(s *SignedPolicy) { s.Policy.MaxAPI++ }, "signature": func(s *SignedPolicy) { s.Signature = nil },
	} {
		t.Run(name, func(t *testing.T) {
			s := signed
			mutate(&s)
			if err := VerifyPolicy(s, "workspace", "org", 1, pub, 1); err == nil {
				t.Fatal("policy alteration accepted")
			}
		})
	}
}

func TestPolicyValidation(t *testing.T) {
	for _, mutate := range []func(*Policy){
		func(p *Policy) { p.FormatVersion = 0 }, func(p *Policy) { p.FormatVersion = 2 }, func(p *Policy) { p.Sequence = 0 }, func(p *Policy) { p.WorkspaceID = "" }, func(p *Policy) { p.MinAPI = 2 }, func(p *Policy) { p.Profile = "future" },
		func(p *Policy) { p.KDF = "custom" }, func(p *Policy) { p.KDF = KDFLow }, func(p *Policy) { p.Profile = Hardened }, func(p *Policy) { p.Profile = Paranoid; p.KDF = KDFV3 }, func(p *Policy) { p.OrgEscrow = false },
	} {
		p := testPolicy()
		mutate(&p)
		if p.Validate() == nil {
			t.Fatal("invalid policy accepted")
		}
	}
	p := testPolicy()
	p.Profile = Default
	p.KDF = KDFLow
	p.LowKDFApproved = true
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.Profile = Hardened
	p.KDF = KDFV2
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.Profile = Paranoid
	p.KDF = KDFV3
	p.ASKRequired = true
	p.OrgEscrow = false
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := SignPolicy(testPolicy(), "org", 1, nil); err != ErrFormat {
		t.Fatal("bad key")
	}
	if _, err := SignPolicy(testPolicy(), "", 1, priv); err != ErrFormat {
		t.Fatal("bad signer")
	}
	p.Sequence = 0
	if _, err := SignPolicy(p, "org", 1, priv); err != ErrFormat {
		t.Fatal("bad policy")
	}
}
