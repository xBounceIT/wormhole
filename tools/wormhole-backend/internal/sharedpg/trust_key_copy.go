package sharedpg

import (
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// AdvanceKeyCopy verifies an org-issued copy against the independent org pin, or
// a member-issued copy against its current state/certificate. Persist any nonzero
// returned state even on error. Copy bytes have no revision: root/field/key version
// authority comes separately from signed manifests/selection, never from this copy.
// Success permits further validation, not secret release or policy bypass.
func (s TrustState) AdvanceKeyCopy(binding vault.KeyCopyBinding, copy vault.SignedKeyCopy, author *UnverifiedNodeAuthor) (TrustState, error) {
	if !s.valid() {
		return TrustState{}, ErrTrustState
	}
	pin, err := s.accountTrust()
	if err != nil {
		return TrustState{}, err
	}
	if binding.Issuer == pin.Signer {
		if author != nil || binding.WorkspaceID != s.WorkspaceID {
			return cloneTrustState(s), vault.ErrAuthentication
		}
		return cloneTrustState(s), vault.VerifyKeyCopy(binding, copy, pin.Organisation)
	}
	if author == nil || author.State == nil {
		return TrustState{}, ErrTrustState
	}
	m := s.catalogAuthorMaterial(*author)
	floor := s.catalogAuthorFloor(author.State.UserID)
	observed, verifyErr := sharedcatalog.VerifyCurrentKeyCopy(binding, copy, m.certificate, *author.State, vault.UserKeyTrust{WorkspaceID: s.WorkspaceID, UserID: author.State.UserID, Signer: pin.Signer, Organisation: pin.Organisation, MinimumSequence: floor.Revision}, m.minimum, m.enrollment...)
	return s.mergeCatalogAuthor(*author, m, floor, observed.StateSequence, observed.CertificateRevision, verifyErr)
}
