package sharedpg

import (
	"crypto/ed25519"
	"errors"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var (
	ErrProfileAuthentication = errors.New("workspace security profile cannot be authenticated")
	ErrProfileRollback       = errors.New("workspace security profile is older than the trusted version")
)

// PolicyTrust comes from authenticated device enrollment and protected local
// high-water state, never from the server response or its accompanying document.
// The initial minimum sequence must be pinned at enrollment (at least one).
type PolicyTrust struct {
	WorkspaceID      uuid.UUID
	SignerKeyID      string
	SignerKeyVersion uint32
	PublicKey        ed25519.PublicKey
	MinimumSequence  uint64
}

// VerifyAdmissionPolicy authenticates only the signed workspace policy. It does
// not authenticate IsAdmin, Epoch, ChangeSeq or other unsigned server metadata,
// persist a new sequence floor, enforce transport/OS/user policy, or activate a
// workspace. The controller must finish those steps before permitting access.
func VerifyAdmissionPolicy(admission *UnverifiedAdmission, expected AdmissionRequest, trust PolicyTrust) (vault.Policy, error) {
	if expected.API < 1 || expected.WorkspaceID == uuid.Nil || expected.UserID == uuid.Nil || expected.DeviceID == uuid.Nil || trust.WorkspaceID != expected.WorkspaceID ||
		trust.SignerKeyID == "" || trust.SignerKeyVersion == 0 || len(trust.PublicKey) != ed25519.PublicKeySize || trust.MinimumSequence == 0 {
		return vault.Policy{}, ErrConfiguration
	}
	if admission == nil || admission.WorkspaceID != expected.WorkspaceID || admission.UserID != expected.UserID || admission.DeviceID != expected.DeviceID {
		return vault.Policy{}, ErrProfileAuthentication
	}
	policy, err := verifySignedWorkspacePolicy(admission.SignedProfile, trust)
	if err != nil {
		return vault.Policy{}, err
	}
	if admission.MinAPI < 1 || admission.MaxAPI < admission.MinAPI || uint32(admission.MinAPI) != policy.MinAPI || uint32(admission.MaxAPI) != policy.MaxAPI ||
		uint32(expected.API) < policy.MinAPI || uint32(expected.API) > policy.MaxAPI {
		return vault.Policy{}, ErrProfileAuthentication
	}
	return policy, nil
}

func verifySignedWorkspacePolicy(raw []byte, trust PolicyTrust) (vault.Policy, error) {
	signed, err := vault.DecodeSignedPolicy(raw)
	if err != nil {
		return vault.Policy{}, ErrProfileAuthentication
	}
	err = vault.VerifyPolicy(signed, trust.WorkspaceID.String(), trust.SignerKeyID, trust.SignerKeyVersion, trust.PublicKey, trust.MinimumSequence)
	if errors.Is(err, vault.ErrRollback) {
		return vault.Policy{}, ErrProfileRollback
	}
	if err != nil {
		return vault.Policy{}, ErrProfileAuthentication
	}
	return signed.Policy, nil
}
