package sharedpg

import (
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// UnverifiedSelection is a signed slot, assignment, override tunnel profile or node field manifest, not a release capability.
// Its fields remain untrusted until AdvanceSelection succeeds and the returned
// trust state has been durably committed. Secret envelopes are separate.
type UnverifiedSelection struct {
	Record   sharedcatalog.SelectionRecord
	Boundary uuid.UUID
	Seal     vault.RecordSeal
}

// AdvanceSelection retains independently authenticated observations even when
// verification later fails, including revocation and tombstones. Persist any
// nonzero returned state before handling the error. Only nil error permits use
// of the selection, subject to separate node/boundary permissions and credential verification.
func (s TrustState) AdvanceSelection(selection UnverifiedSelection, author UnverifiedNodeAuthor) (TrustState, error) {
	if !s.valid() || author.State == nil {
		return TrustState{}, ErrTrustState
	}
	pin, err := s.accountTrust()
	if err != nil {
		return TrustState{}, err
	}
	scope, _, err := sharedcatalog.SelectionIdentity(selection.Record)
	if err != nil {
		return TrustState{}, ErrAdmissionResponse
	}
	m := s.catalogAuthorMaterial(author)
	selectionKey := scope.Kind + "/" + scope.Subject.String()
	if scope.User != uuid.Nil {
		selectionKey += "/" + scope.User.String()
	}
	authorFloor := s.catalogAuthorFloor(author.State.UserID)
	observed, verifyErr := sharedcatalog.VerifyCurrentSelection(selection.Record, selection.Boundary, selection.Seal, m.certificate, *author.State, sharedcatalog.SelectionTrust{
		Workspace: s.WorkspaceID, Scope: scope, Boundary: selection.Boundary, Author: author.State.UserID,
		OrganisationKey: pin.Signer, Organisation: pin.Organisation, MinimumStateSequence: authorFloor.Revision,
		MinimumCertificateRevision: m.minimum, MinimumSelectionRevision: s.Catalog[selectionKey].Revision,
	}, m.enrollment...)
	return s.mergeCatalogAuthor(author, m, authorFloor, observed.StateSequence, observed.CertificateRevision, verifyErr,
		catalogFloorObservation{selectionKey, observed.SelectionRevision, selection.Seal})
}
