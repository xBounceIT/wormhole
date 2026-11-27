package sharedpg

import (
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// UnverifiedCredential is a signed profile projection, not a release capability.
// Its fields remain untrusted until AdvanceCredential succeeds and the returned
// trust state has been durably committed. Secret envelopes are separate.
type UnverifiedCredential struct {
	Record   sharedcatalog.CredentialRecord
	Boundary uuid.UUID
	Seal     vault.RecordSeal
}

// AdvanceCredential retains independently authenticated observations even when
// verification later fails, including revocation and tombstones. Persist any
// nonzero returned state before handling the error. Only nil error permits use
// of the profile, subject to separate node/boundary permissions and envelope checks.
func (s TrustState) AdvanceCredential(credential UnverifiedCredential, author UnverifiedNodeAuthor) (TrustState, error) {
	if !s.valid() || author.State == nil {
		return TrustState{}, ErrTrustState
	}
	pin, err := s.accountTrust()
	if err != nil {
		return TrustState{}, err
	}
	id, err := uuid.Parse(credential.Record.Metadata.ID)
	if err != nil || id == uuid.Nil {
		return TrustState{}, ErrAdmissionResponse
	}
	m := s.catalogAuthorMaterial(author)
	credentialKey := "credential/" + id.String()
	authorFloor := s.catalogAuthorFloor(author.State.UserID)
	observed, verifyErr := sharedcatalog.VerifyCurrentCredential(credential.Record, credential.Boundary, credential.Seal, m.certificate, *author.State, sharedcatalog.CredentialTrust{
		Workspace: s.WorkspaceID, Credential: id, Boundary: credential.Boundary, Author: author.State.UserID,
		OrganisationKey: pin.Signer, Organisation: pin.Organisation, MinimumStateSequence: authorFloor.Revision,
		MinimumCertificateRevision: m.minimum, MinimumCredentialRevision: s.Catalog[credentialKey].Revision,
	}, m.enrollment...)
	return s.mergeCatalogAuthor(author, m, authorFloor, observed.StateSequence, observed.CertificateRevision, verifyErr,
		catalogFloorObservation{credentialKey, observed.CredentialRevision, credential.Seal})
}
