package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func admissionNoticeTrust(t *testing.T, profile vault.Profile, escrow bool) sharedpg.TrustState {
	t.Helper()
	org := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{72}, ed25519.SeedSize))
	defer vault.Wipe(org)
	workspace, signer := uuid.New(), uuid.NewString()
	policy := vault.Policy{FormatVersion: 1, WorkspaceID: workspace.String(), Sequence: 3,
		Profile: profile, KDF: vault.KDFV1, OrgEscrow: escrow, MinAPI: 1, MaxAPI: 1}
	if profile == vault.Paranoid {
		policy.KDF, policy.ASKRequired = vault.KDFV3, true
	}
	signed, err := vault.SignPolicy(policy, signer, 1, org)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := vault.EncodeSignedPolicy(signed)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	return sharedpg.TrustState{FormatVersion: 2, Revision: 1, WorkspaceID: workspace,
		UserID: uuid.New(), DeviceID: uuid.New(), SignerKeyID: signer, SignerKeyVersion: 1,
		PublicKey: bytes.Clone(org.Public().(ed25519.PublicKey)), PolicySequence: policy.Sequence,
		PolicyDigest: digest[:], SignedProfile: raw}
}

func TestSharedAdmissionNoticeUsesAuthenticatedPolicy(t *testing.T) {
	for _, example := range []struct {
		profile vault.Profile
		escrow  bool
	}{{vault.Default, true}, {vault.Standard, true}, {vault.Paranoid, true}, {vault.Paranoid, false}} {
		for _, locked := range []bool{false, true} {
			trust := admissionNoticeTrust(t, example.profile, example.escrow)
			raw, err := marshalSharedAdmission(locked, trust)
			var response map[string]bool
			if err != nil || json.Unmarshal(raw, &response) != nil || len(response) != 3 || !response["admitted"] || response["lockedMemory"] != locked || response["orgEscrow"] != example.escrow {
				t.Fatal("notice changed authenticated policy or exposed extra data", err)
			}
		}
	}
}

func TestSharedAdmissionNoticeRejectsUnverifiedOrReplacedPolicy(t *testing.T) {
	for _, mode := range []string{"missing", "unsigned-change", "key", "sequence", "workspace", "digest"} {
		t.Run(mode, func(t *testing.T) {
			trust := admissionNoticeTrust(t, vault.Paranoid, true)
			switch mode {
			case "missing":
				trust = sharedpg.TrustState{}
			case "unsigned-change":
				trust.SignedProfile = bytes.Replace(trust.SignedProfile, []byte(`"orgEscrow":true`), []byte(`"orgEscrow":false`), 1)
				digest := sha256.Sum256(trust.SignedProfile)
				trust.PolicyDigest = digest[:] // reject the forged signature, not only its digest
			case "key":
				trust.PublicKey[0] ^= 1
			case "sequence":
				trust.PolicySequence++
			case "workspace":
				trust.WorkspaceID = uuid.New()
			case "digest":
				trust.PolicyDigest[0] ^= 1
			}
			raw, err := marshalSharedAdmission(true, trust)
			if err == nil || len(raw) != 0 {
				t.Fatal("unverified policy produced an admission notice")
			}
		})
	}
}
