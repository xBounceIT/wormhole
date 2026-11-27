package sharedpg

import (
	"bytes"
	"context"
	"math"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestReleasePolicyObservation(t *testing.T) {
	for _, mode := range []string{"same-profile", "hardened", "future-api"} {
		f, g, _, _ := openReleaseFixture(t, "saved", true, false)
		policy, e := vault.DecodeSignedPolicy(f.s.SignedProfile)
		if e != nil {
			t.Fatal(e)
		}
		policy.Policy.Sequence++
		switch mode {
		case "hardened":
			policy.Policy.Profile = vault.Hardened
			policy.Policy.KDF = vault.KDFV2
			policy.Policy.ASKRequired = true
		case "future-api":
			policy.Policy.MinAPI = 2
			policy.Policy.MaxAPI = 3
		}
		policy, e = vault.SignPolicy(policy.Policy, f.s.SignerKeyID, f.s.SignerKeyVersion, f.org)
		if e != nil {
			t.Fatal(e)
		}
		raw, e := vault.EncodeSignedPolicy(policy)
		if e != nil {
			t.Fatal(e)
		}
		g.profile = raw
		next, v, e := f.s.VerifyCredentialRelease(context.Background(), f.node(), g)
		if e != ErrProfileChanged || v != nil || next.PolicySequence != policy.Policy.Sequence || next.Revision != f.s.Revision+1 || f.s.ValidateAdvance(next) != nil {
			t.Fatal("new policy not persisted before denying", mode, e)
		}
		if len(next.Catalog) != len(f.s.Catalog) {
			t.Fatal("continued verification after changed policy")
		}
		root := bytes.Repeat([]byte{55}, 32)
		binding := TrustBinding{WorkspaceID: f.s.WorkspaceID, UserID: f.s.UserID, DeviceID: f.s.DeviceID, KeyID: uuid.New(), KeyVersion: 1}
		sealed, e := SealTrustState(root, binding, next)
		if e != nil {
			t.Fatal(e)
		}
		stored, e := OpenTrustState(root, binding, sealed, next.Revision)
		if e != nil || !reflect.DeepEqual(stored, next) {
			t.Fatal("policy floor lost", e)
		}
		if observed, e := stored.advanceReleasePolicy(f.s.SignedProfile); e != ErrProfileRollback || !reflect.DeepEqual(observed, stored) {
			t.Fatal("old policy replay", e)
		}
		if same, e := stored.advanceReleasePolicy(raw); e != nil || !reflect.DeepEqual(same, stored) {
			t.Fatal("unchanged policy", e)
		}
		vault.Wipe(raw)
		if _, e := next.Policy(); e != nil {
			t.Fatal("policy bytes aliased", e)
		}
	}
}

func TestReleasePolicyFailures(t *testing.T) {
	for _, mode := range []string{"invalid-state", "malformed", "signature", "workspace", "signer", "fork", "counter"} {
		t.Run(mode, func(t *testing.T) {
			f, _, _, _ := openReleaseFixture(t, "saved", true, false)
			policy, e := vault.DecodeSignedPolicy(f.s.SignedProfile)
			if e != nil {
				t.Fatal(e)
			}
			want := error(ErrProfileAuthentication)
			switch mode {
			case "invalid-state":
				f.s = TrustState{}
				want = ErrTrustState
			case "workspace":
				policy.Policy.WorkspaceID = uuid.NewString()
			case "signer":
				policy.SignerKeyID = uuid.NewString()
			case "fork":
				policy.Policy.ASKRequired = !policy.Policy.ASKRequired
				want = ErrProfileEquivocation
			case "counter":
				f.s.Revision = math.MaxUint64
				policy.Policy.Sequence++
				want = ErrTrustState
			}
			policy, e = vault.SignPolicy(policy.Policy, policy.SignerKeyID, policy.SignerKeyVersion, f.org)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "signature" {
				policy.Signature[0] ^= 1
			}
			raw, e := vault.EncodeSignedPolicy(policy)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "malformed" {
				raw = []byte("{}")
			}
			if _, e := f.s.advanceReleasePolicy(raw); e != want {
				t.Fatal("policy rejection", mode, e, want)
			}
		})
	}
	for _, mode := range []string{"absent", "null", "hex", "large", "old-format"} {
		f, w := releaseGraphFixture(t, "none", false, false)
		switch mode {
		case "absent":
			delete(w, "profile")
		case "null":
			w["profile"] = nil
		case "hex":
			w["profile"] = "zz"
		case "large":
			w["profile"] = string(bytes.Repeat([]byte("a"), 2*65536+2))
		case "old-format":
			w["formatVersion"] = 1
		}
		if g, e := releaseParseFixture(t, f, w); g != nil || e == nil {
			t.Fatal("policy wire", mode, e)
		}
	}
}
