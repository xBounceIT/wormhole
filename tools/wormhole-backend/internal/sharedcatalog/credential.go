package sharedcatalog

import (
	"crypto/ed25519"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// CredentialRecord authenticates the full profile and field manifest, including
// absence/tombstones. Secret envelopes are separate and must match these IDs,
// field versions and the selected boundary before use.
type CredentialRecord struct {
	Metadata vaultstore.CredentialMetadata `json:"metadata"`
	Deleted  bool                          `json:"deleted"`
	Fields   []vaultstore.CredentialField  `json:"fields"`
}

type CredentialTrust struct {
	Workspace, Credential, Boundary, Author                                     uuid.UUID
	OrganisationKey                                                             vault.KeyRef
	Organisation                                                                ed25519.PublicKey
	MinimumStateSequence, MinimumCertificateRevision, MinimumCredentialRevision uint64
}

// CredentialObservation is authenticated even on later failure. Persist nonzero
// floors before publishing a credential or returning a revocation response.
// The owning trust store must also retain canonical digests to reject conflicting
// records at an equal revision; minimum revisions alone cannot detect such forks.
type CredentialObservation struct {
	StateSequence, CertificateRevision, CredentialRevision uint64
}

func credentialSigningBytes(workspace, boundary uuid.UUID, record CredentialRecord, seal vault.RecordSeal) ([]byte, error) {
	if err := validateRecordSeal(workspace, boundary, seal); err != nil {
		return nil, err
	}
	content := vaultstore.Credential{CredentialMetadata: record.Metadata, RowVersion: seal.Revision, Deleted: record.Deleted, Fields: record.Fields}
	if content.ValidateContent() != nil {
		return nil, vault.ErrFormat
	}
	// Empty manifests have one canonical representation across Go and PostgreSQL.
	if record.Fields == nil {
		record.Fields = []vaultstore.CredentialField{}
	}
	seal.Signature = nil
	body, err := json.Marshal(struct {
		Workspace uuid.UUID        `json:"workspaceId"`
		Boundary  uuid.UUID        `json:"boundaryId"`
		Suite     uint16           `json:"suite"`
		Record    CredentialRecord `json:"record"`
		Seal      vault.RecordSeal `json:"seal"`
	}{workspace, boundary, NodeSealEd25519, record, seal})
	if err != nil {
		return nil, vault.ErrFormat
	}
	return append([]byte("wormhole/v1/shared-credential-metadata\x00"), body...), nil
}

func SignCredential(workspace, boundary uuid.UUID, record CredentialRecord, revision uint64, signer vault.KeyRef, private ed25519.PrivateKey) (vault.RecordSeal, error) {
	if len(private) != ed25519.PrivateKeySize {
		return vault.RecordSeal{}, vault.ErrFormat
	}
	seal := vault.RecordSeal{FormatVersion: vault.FormatVersion, SignerKeyID: signer.ID.String(), SignerKeyVersion: signer.Version, Revision: revision}
	body, err := credentialSigningBytes(workspace, boundary, record, seal)
	if err != nil {
		return vault.RecordSeal{}, err
	}
	seal.Signature = ed25519.Sign(private, body)
	return seal, nil
}

// VerifyCurrentCredential verifies organisation-signed current membership, the
// selected signing certificate and the complete credential record. A signature
// proves authorship, not Use/Write permission. A valid tombstone advances the
// revision floor and returns ErrMissing; it never becomes a usable credential.
func VerifyCurrentCredential(record CredentialRecord, boundary uuid.UUID, seal vault.RecordSeal, certificate vault.UserKeyCertificate, state vault.UserKeyState, trust CredentialTrust, enrollment ...vault.UserEnrollmentCertificate) (CredentialObservation, error) {
	author, err := verifyCurrentAuthor(certificate, state, vault.UserKeyTrust{WorkspaceID: trust.Workspace, UserID: trust.Author, Signer: trust.OrganisationKey, Organisation: trust.Organisation, MinimumSequence: trust.MinimumStateSequence}, trust.MinimumCertificateRevision, enrollment...)
	observed := CredentialObservation{StateSequence: author.StateSequence, CertificateRevision: author.CertificateRevision}
	if err != nil {
		return observed, err
	}
	if trust.Credential == uuid.Nil || trust.Boundary == uuid.Nil || record.Metadata.ID != trust.Credential.String() || boundary != trust.Boundary || seal.SignerKeyID != author.Key.ID.String() || seal.SignerKeyVersion != author.Key.Version {
		return observed, vault.ErrAuthentication
	}
	body, err := credentialSigningBytes(trust.Workspace, boundary, record, seal)
	if err != nil {
		return observed, err
	}
	if !ed25519.Verify(author.Public, body, seal.Signature) {
		return observed, vault.ErrAuthentication
	}
	if seal.Revision < trust.MinimumCredentialRevision {
		return observed, vault.ErrRollback
	}
	observed.CredentialRevision = seal.Revision
	if record.Deleted {
		return observed, vaultstore.ErrMissing
	}
	return observed, nil
}
