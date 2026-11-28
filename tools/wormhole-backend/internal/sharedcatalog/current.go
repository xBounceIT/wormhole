package sharedcatalog

import (
	"crypto/ed25519"
	"reflect"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// Certificate floors are scoped to the selected key reference, state sequence
// to the author and node revision to the node. Never merge these namespaces.
type CurrentNodeTrust struct {
	Workspace, Node, Boundary, Author                                     uuid.UUID
	OrganisationKey                                                       vault.KeyRef
	Organisation                                                          ed25519.PublicKey
	MinimumStateSequence, MinimumCertificateRevision, MinimumNodeRevision uint64
}

// Observation contains only authenticated revisions. The owner must durably
// merge nonzero values even when verification fails (especially revocation),
// and must not publish metadata until that persistence succeeds. Zero means no
// authenticated observation, never an instruction to lower an existing floor.
type Observation struct {
	StateSequence, CertificateRevision, NodeRevision uint64
}

// verifyCurrentAuthor is shared by signed catalog record kinds so revocation and
// certificate floors cannot diverge between nodes and credential profiles.
type currentAuthor struct {
	Key                                vault.KeyRef
	Public                             ed25519.PublicKey
	StateSequence, CertificateRevision uint64
}

func verifyCurrentAuthor(certificate vault.UserKeyCertificate, state vault.UserKeyState, trust vault.UserKeyTrust, minimumCertificate uint64, enrollment ...vault.UserEnrollmentCertificate) (result currentAuthor, err error) {
	if err := vault.VerifyUserKeyState(state, trust); err != nil {
		return result, err
	}
	result.StateSequence = state.Sequence
	if !state.Active {
		return result, vault.ErrPolicy
	}
	if len(enrollment) != 0 {
		// A delegated final key is certified by the signed bootstrap -> manifest
		// -> rekey chain. It must never masquerade as an organisation certificate,
		// or replace the current signed bootstrap state used for revocation.
		if len(enrollment) != 1 || !reflect.DeepEqual(certificate, vault.UserKeyCertificate{}) {
			return result, vault.ErrFormat
		}
		c := enrollment[0]
		if err := vault.VerifyUserEnrollmentCertificate(c, state, trust, max(1, minimumCertificate)); err != nil {
			return result, err
		}
		result.Key = vault.KeyRef{ID: c.Rekey.SigningKeyID, Version: c.Rekey.KeyVersion}
		result.Public = c.Rekey.Public.Signing
		result.CertificateRevision = c.Manifest.Revision
		return result, nil
	}
	minimumCertificate = max(minimumCertificate, state.MinimumSigningCertificate)
	if err := vault.VerifyUserKeyCertificate(certificate, trust.WorkspaceID, trust.UserID, state.Signing, "user-sign", trust.Signer, trust.Organisation, minimumCertificate); err != nil {
		return result, err
	}
	result.Key, result.Public, result.CertificateRevision = state.Signing, certificate.PublicKey, certificate.Revision
	return result, nil
}

// VerifyCurrentNode adds organisation-signed current key selection/revocation to
// VerifyNode. It does not make an unseen server state fresh: only independently
// stored sequence floors detect replay of previously superseded states.
func VerifyCurrentNode(metadata vaultstore.NodeMetadata, boundary uuid.UUID, seal vault.RecordSeal, certificate vault.UserKeyCertificate, state vault.UserKeyState, trust CurrentNodeTrust, enrollment ...vault.UserEnrollmentCertificate) (Observation, error) {
	author, err := verifyCurrentAuthor(certificate, state, vault.UserKeyTrust{WorkspaceID: trust.Workspace, UserID: trust.Author, Signer: trust.OrganisationKey, Organisation: trust.Organisation, MinimumSequence: trust.MinimumStateSequence}, trust.MinimumCertificateRevision, enrollment...)
	observed := Observation{StateSequence: author.StateSequence, CertificateRevision: author.CertificateRevision}
	if err != nil {
		return observed, err
	}
	if err := verifyNodeSignature(metadata, boundary, seal, author.Public, NodeTrust{Workspace: trust.Workspace, Node: trust.Node, Boundary: trust.Boundary, Author: trust.Author, AuthorKey: author.Key, OrganisationKey: trust.OrganisationKey, Organisation: trust.Organisation, MinimumCertificateRevision: author.CertificateRevision, MinimumNodeRevision: trust.MinimumNodeRevision}); err != nil {
		return observed, err
	}
	observed.NodeRevision = seal.Revision
	return observed, nil
}
