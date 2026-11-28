package sharedpg

import (
	"bytes"
	"crypto/sha256"
	"math"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func (s TrustState) validTLS() bool {
	if s.FormatVersion < 4 || (s.FormatVersion >= 5 && s.TLSSequence == 0) {
		return s.TLSSequence == 0 && len(s.TLSDigest) == 0
	}
	_, err := s.accountTrust()
	return err == nil && s.TLSSequence > 0 && s.TLSSequence <= math.MaxInt64 && len(s.TLSDigest) == sha256.Size
}

// AdvanceTLS accepts only an already verified bundle under this state's pinned
// organisation identity. Persist the returned state before using the bundle.
// Only compact sequence/digest metadata enters the protected trust file.
func (s TrustState) AdvanceTLS(bundle *VerifiedTLSBundle) (TrustState, error) {
	if !s.valid() || bundle == nil || len(bundle.raw) == 0 {
		return TrustState{}, ErrTrustState
	}
	pin := bundle.Pin()
	if pin.WorkspaceID != s.WorkspaceID || pin.Signer.ID.String() != s.SignerKeyID || pin.Signer.Version != s.SignerKeyVersion || !bytes.Equal(pin.Organisation, s.PublicKey) {
		return TrustState{}, vault.ErrAuthentication
	}
	if pin.MinimumSequence < s.TLSSequence || (pin.MinimumSequence == s.TLSSequence && !bytes.Equal(pin.Digest, s.TLSDigest)) {
		return TrustState{}, ErrTrustRollback
	}
	if pin.MinimumSequence != s.TLSSequence {
		if s.Revision == math.MaxUint64 {
			return TrustState{}, ErrTrustState
		}
		s.Revision++
	}
	if s.FormatVersion < 4 {
		s.FormatVersion = 4
	}
	s.TLSSequence = pin.MinimumSequence
	s.TLSDigest = bytes.Clone(pin.Digest)
	s.PublicKey = bytes.Clone(s.PublicKey)
	s.PolicyDigest = bytes.Clone(s.PolicyDigest)
	s.SignedProfile = bytes.Clone(s.SignedProfile)
	s.Account = cloneAccountState(s.Account)
	s.Enrollment = cloneEnrollmentPin(s.Enrollment)
	s.Catalog = cloneCatalogFloors(s.Catalog)
	return s, nil
}

// VerifyTLS authenticates a separately stored public bundle against the protected
// floor. A newer result still needs AdvanceTLS and durable publication before use.
func (s TrustState) VerifyTLS(raw []byte) (*VerifiedTLSBundle, error) {
	if !s.valid() || s.TLSSequence == 0 {
		return nil, ErrTrustState
	}
	trust, err := s.accountTrust()
	if err != nil {
		return nil, err
	}
	bundle, err := DecodeTLSTrustBundle(raw)
	if err != nil {
		return nil, err
	}
	return VerifyTLSTrustBundle(bundle, TLSTrustPin{WorkspaceID: s.WorkspaceID, Signer: trust.Signer, Organisation: trust.Organisation, MinimumSequence: s.TLSSequence, Digest: bytes.Clone(s.TLSDigest)})
}
