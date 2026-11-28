// Package sharedcatalog authenticates shared catalog records independently of
// PostgreSQL policy. It does not authorize secret release or accept trust roots
// from the database response being verified.
package sharedcatalog

import (
	"crypto/ed25519"
	"encoding/json"
	"math"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const NodeSealEd25519 = 2

// NodeTrust comes from the authenticated key graph and persistent revision
// floors. A certificate proves membership, not current Write permission. The
// database enforces Write below Paranoid; capabilities require a separate flow.
type NodeTrust struct {
	Workspace, Node, Boundary, Author               uuid.UUID
	AuthorKey, OrganisationKey                      vault.KeyRef
	Organisation                                    ed25519.PublicKey
	MinimumCertificateRevision, MinimumNodeRevision uint64
}

func validateRecordSeal(workspace, boundary uuid.UUID, seal vault.RecordSeal) error {
	if seal.FormatVersion > vault.FormatVersion {
		return vault.ErrNewerFormat
	}
	signer, err := uuid.Parse(seal.SignerKeyID)
	if workspace == uuid.Nil || boundary == uuid.Nil ||
		seal.FormatVersion != vault.FormatVersion || seal.Revision == 0 || seal.Revision > math.MaxInt64 ||
		err != nil || signer == uuid.Nil || signer.String() != seal.SignerKeyID ||
		seal.SignerKeyVersion == 0 || seal.SignerKeyVersion > math.MaxInt32 || seal.CapabilityID != nil {
		return vault.ErrFormat
	}
	return nil
}

func signingBytes(workspace, boundary uuid.UUID, metadata vaultstore.NodeMetadata, seal vault.RecordSeal) ([]byte, error) {
	if err := validateRecordSeal(workspace, boundary, seal); err != nil {
		return nil, err
	}
	if metadata.Validate() != nil {
		return nil, vault.ErrFormat
	}
	seal.Signature = nil
	// A typed full projection preserves explicit NULL/false/empty inheritance and
	// int64 values. The separate domain prevents reuse of resolution-only seals.
	body, err := json.Marshal(struct {
		Workspace uuid.UUID               `json:"workspaceId"`
		Boundary  uuid.UUID               `json:"boundaryId"`
		Suite     uint16                  `json:"suite"`
		Metadata  vaultstore.NodeMetadata `json:"metadata"`
		Seal      vault.RecordSeal        `json:"seal"`
	}{workspace, boundary, NodeSealEd25519, metadata, seal})
	if err != nil {
		return nil, vault.ErrFormat
	}
	return append([]byte("wormhole/v1/shared-node-metadata\x00"), body...), nil
}

func SignNode(workspace, boundary uuid.UUID, metadata vaultstore.NodeMetadata, revision uint64, signer vault.KeyRef, private ed25519.PrivateKey) (vault.RecordSeal, error) {
	if len(private) != ed25519.PrivateKeySize {
		return vault.RecordSeal{}, vault.ErrFormat
	}
	seal := vault.RecordSeal{FormatVersion: vault.FormatVersion, SignerKeyID: signer.ID.String(), SignerKeyVersion: signer.Version, Revision: revision}
	body, err := signingBytes(workspace, boundary, metadata, seal)
	if err != nil {
		return vault.RecordSeal{}, err
	}
	seal.Signature = ed25519.Sign(private, body)
	return seal, nil
}

// VerifyNode authenticates all metadata, its boundary and revision against an
// independently trusted member key. It does not authenticate the server's
// permission mask, prove snapshot completeness, or authorize a protocol session.
func VerifyNode(metadata vaultstore.NodeMetadata, boundary uuid.UUID, seal vault.RecordSeal, certificate vault.UserKeyCertificate, trust NodeTrust) error {
	if err := vault.VerifyUserKeyCertificate(certificate, trust.Workspace, trust.Author, trust.AuthorKey, "user-sign", trust.OrganisationKey, trust.Organisation, trust.MinimumCertificateRevision); err != nil {
		return err
	}
	return verifyNodeSignature(metadata, boundary, seal, certificate.PublicKey, trust)
}

// The caller has authenticated this public key and its binding to trust.AuthorKey.
func verifyNodeSignature(metadata vaultstore.NodeMetadata, boundary uuid.UUID, seal vault.RecordSeal, public ed25519.PublicKey, trust NodeTrust) error {
	if trust.Node == uuid.Nil || trust.Boundary == uuid.Nil || metadata.ID != trust.Node.String() || boundary != trust.Boundary ||
		seal.SignerKeyID != trust.AuthorKey.ID.String() || seal.SignerKeyVersion != trust.AuthorKey.Version {
		return vault.ErrAuthentication
	}
	body, err := signingBytes(trust.Workspace, boundary, metadata, seal)
	if err != nil {
		return err
	}
	if !ed25519.Verify(public, body, seal.Signature) {
		return vault.ErrAuthentication
	}
	if seal.Revision < trust.MinimumNodeRevision {
		return vault.ErrRollback
	}
	return nil
}
