package sharedpg

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var ErrProfileChanged = errors.New("workspace security profile changed; fresh admission required")

// Unlike admission, this observes a higher authentic policy even if its API or
// factor requirements cannot run on the current client. Persist the floor, then
// retire the old owner; it must not decrypt under its previous runtime policy.
func (s TrustState) advanceReleasePolicy(raw []byte) (TrustState, error) {
	if !s.valid() {
		return TrustState{}, ErrTrustState
	}
	signed, e := vault.DecodeSignedPolicy(raw)
	if e != nil {
		return cloneTrustState(s), ErrProfileAuthentication
	}
	e = vault.VerifyPolicy(signed, s.WorkspaceID.String(), s.SignerKeyID, s.SignerKeyVersion, s.PublicKey, s.PolicySequence)
	if errors.Is(e, vault.ErrRollback) {
		return cloneTrustState(s), ErrProfileRollback
	}
	if e != nil {
		return cloneTrustState(s), ErrProfileAuthentication
	}
	digest := sha256.Sum256(raw)
	if signed.Policy.Sequence == s.PolicySequence {
		if !bytes.Equal(digest[:], s.PolicyDigest) {
			return cloneTrustState(s), ErrProfileEquivocation
		}
		return cloneTrustState(s), nil
	}
	if s.Revision == math.MaxUint64 {
		return TrustState{}, ErrTrustState
	}
	next := cloneTrustState(s)
	next.Revision++
	next.PolicySequence = signed.Policy.Sequence
	next.PolicyDigest = bytes.Clone(digest[:])
	next.SignedProfile = bytes.Clone(raw)
	return next, ErrProfileChanged
}
