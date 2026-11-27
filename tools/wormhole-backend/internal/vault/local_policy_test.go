package vault

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func localPolicyFixture() LocalPolicy {
	p := testPolicy()
	p.WorkspaceID = "11111111-1111-4111-8111-111111111111"
	return LocalPolicy{Policy: p, FileID: "22222222-2222-4222-8222-222222222222", RootKeyID: "33333333-3333-4333-8333-333333333333", RootKeyVersion: 1, UserProfile: Default}
}

func TestLocalPolicyAuthenticatesIdentityFloorAndAllFields(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	p := localPolicyFixture()
	raw, err := EncodeLocalPolicy(key, p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeLocalPolicy(raw)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(p LocalPolicy, key []byte, floor uint64) error {
		return VerifyLocalPolicy(key, p, got.Policy.WorkspaceID, got.FileID, got.RootKeyID, got.RootKeyVersion, floor)
	}
	if err := verify(got, key, 1); err != nil {
		t.Fatal(err)
	}
	if err := verify(got, key, 2); err != ErrRollback {
		t.Fatal(err)
	}
	if err := verify(got, bytes.Repeat([]byte{8}, 32), 1); err != ErrAuthentication {
		t.Fatal(err)
	}
	if err := verify(got, nil, 1); err != ErrFormat {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*LocalPolicy){
		"workspace": func(p *LocalPolicy) { p.Policy.WorkspaceID = p.FileID }, "file": func(p *LocalPolicy) { p.FileID = p.RootKeyID },
		"root": func(p *LocalPolicy) { p.RootKeyID = p.FileID }, "root-version": func(p *LocalPolicy) { p.RootKeyVersion++ },
		"profile": func(p *LocalPolicy) { p.Policy.Profile = Default }, "user-floor": func(p *LocalPolicy) { p.UserProfile = Paranoid },
		"sequence": func(p *LocalPolicy) { p.Policy.Sequence++ }, "kdf": func(p *LocalPolicy) { p.Policy.KDF = KDFV2 },
		"ask": func(p *LocalPolicy) { p.Policy.ASKRequired = true }, "api": func(p *LocalPolicy) { p.Policy.MaxAPI++ },
		"mac": func(p *LocalPolicy) { p.Authentication = make([]byte, 32) },
	} {
		t.Run(name, func(t *testing.T) {
			modified := got
			change(&modified)
			if err := verify(modified, key, 1); err == nil {
				t.Fatal("modified policy accepted")
			}
		})
	}
	if bytes.Contains(raw, key) {
		t.Fatal("root key serialized")
	}
}

func TestLocalPolicyRejectsAmbiguousFormatsAndInvalidFields(t *testing.T) {
	key := make([]byte, 32)
	p := localPolicyFixture()
	raw, err := EncodeLocalPolicy(key, p)
	if err != nil {
		t.Fatal(err)
	}
	sharedOnly := bytes.Replace(raw, []byte(`"maxApi":1`), []byte(`"maxApi":1,"directConnectionDevices":50`), 1)
	if _, err := DecodeLocalPolicy(sharedOnly); err != ErrFormat {
		t.Fatal("shared deployment metadata accepted in local policy", err)
	}
	for _, bad := range [][]byte{nil, []byte(`null`), []byte(`{`), bytes.Repeat([]byte{'a'}, MaxLocalPolicyBytes+1), append(bytes.Clone(raw), ' '), bytes.Replace(raw, []byte(`"userProfile":"default"`), []byte(`"userProfile":"default","userProfile":"default"`), 1), bytes.Replace(raw, []byte(`"userProfile"`), []byte(`"UserProfile"`), 1), bytes.Replace(raw, []byte(`"userProfile":"default",`), nil, 1), bytes.Replace(raw, []byte(`"fileId"`), []byte(`"unknown"`), 1)} {
		if _, err := DecodeLocalPolicy(bad); err == nil {
			t.Fatal("ambiguous format accepted")
		}
	}
	for _, change := range []func(*LocalPolicy){func(p *LocalPolicy) { p.Policy.Sequence = 0 }, func(p *LocalPolicy) { p.Policy.Sequence = math.MaxUint64 }, func(p *LocalPolicy) { p.Policy.WorkspaceID = "workspace" }, func(p *LocalPolicy) { p.FileID = strings.ToUpper(p.FileID[:8]) + "-BAD" }, func(p *LocalPolicy) { p.RootKeyID = "00000000-0000-0000-0000-000000000000" }, func(p *LocalPolicy) { p.RootKeyVersion = 0 }, func(p *LocalPolicy) { p.UserProfile = "future" }, func(p *LocalPolicy) { p.Policy.FormatVersion = 2 }} {
		changed := p
		change(&changed)
		if _, err := EncodeLocalPolicy(key, changed); err == nil {
			t.Fatal("invalid encode")
		}
		encoded, _ := json.Marshal(changed)
		if _, err := DecodeLocalPolicy(encoded); err == nil {
			t.Fatal("invalid decode")
		}
		if err := VerifyLocalPolicy(key, changed, p.Policy.WorkspaceID, p.FileID, p.RootKeyID, p.RootKeyVersion, 0); err == nil {
			t.Fatal("invalid verify")
		}
	}
	if _, err := EncodeLocalPolicy(nil, p); err != ErrFormat {
		t.Fatal(err)
	}
	unsigned, _ := json.Marshal(p)
	if _, err := DecodeLocalPolicy(unsigned); err != ErrFormat {
		t.Fatal("unsigned policy accepted", err)
	}
}

func TestLocalPolicyPersonalFloorCannotWeakenCryptographicRequirements(t *testing.T) {
	for _, test := range []struct {
		workspace, user Profile
		preset          KDFPreset
		ask, allowed    bool
	}{
		{Default, Default, KDFLow, false, true},
		{Default, Standard, KDFLow, false, false},
		{Default, Standard, KDFV1, false, true},
		{Standard, Hardened, KDFV1, false, false},
		{Standard, Hardened, KDFV2, false, true},
		{Default, Paranoid, KDFV2, true, false},
		{Default, Paranoid, KDFV3, false, false},
		{Default, Paranoid, KDFV3, true, true},
		{Hardened, Default, KDFV1, false, false},
		{Paranoid, Default, KDFV3, true, true},
	} {
		p := localPolicyFixture()
		p.Policy.Profile, p.UserProfile = test.workspace, test.user
		p.Policy.KDF, p.Policy.ASKRequired = test.preset, test.ask
		p.Policy.LowKDFApproved = test.preset == KDFLow
		_, err := EncodeLocalPolicy(make([]byte, 32), p)
		if test.allowed && err != nil || !test.allowed && err != ErrPolicy {
			t.Fatalf("workspace %s user %s kdf %s ask %t: %v", test.workspace, test.user, test.preset, test.ask, err)
		}
	}
}
