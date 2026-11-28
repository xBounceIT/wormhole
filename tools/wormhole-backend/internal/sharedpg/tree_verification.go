package sharedpg

import (
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// VerifyMetadata checks the signed full projection against independently trusted
// key graph state. Permissions and page completeness remain unverified; this is
// not a capability to release secrets or start a protocol connection.
func (node UnverifiedTreeNode) VerifyMetadata(certificate vault.UserKeyCertificate, trust sharedcatalog.NodeTrust) error {
	return sharedcatalog.VerifyNode(node.Metadata, node.Boundary, node.Seal, certificate, trust)
}

// VerifyCurrentMetadata also authenticates the author's current key selection.
// The owner must persist returned observations before publishing this metadata,
// including state observations returned alongside revocation/errors.
func (node UnverifiedTreeNode) VerifyCurrentMetadata(certificate vault.UserKeyCertificate, state vault.UserKeyState, trust sharedcatalog.CurrentNodeTrust, enrollment ...vault.UserEnrollmentCertificate) (sharedcatalog.Observation, error) {
	return sharedcatalog.VerifyCurrentNode(node.Metadata, node.Boundary, node.Seal, certificate, state, trust, enrollment...)
}
