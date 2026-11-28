package sharedcatalog

import "github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"

type KeyCopyObservation struct {
	StateSequence, CertificateRevision uint64
}

// VerifyCurrentKeyCopy checks current membership, selected certificate and the
// copy signature before any HPKE open. This proves authorship, not Write/Use or
// that the copied plaintext is the expected root/DEK. Persist observations even
// on later errors, then verify the independently bound manifest/value context.
func VerifyCurrentKeyCopy(binding vault.KeyCopyBinding, copy vault.SignedKeyCopy, certificate vault.UserKeyCertificate, state vault.UserKeyState, trust vault.UserKeyTrust, minimumCertificate uint64, enrollment ...vault.UserEnrollmentCertificate) (KeyCopyObservation, error) {
	author, err := verifyCurrentAuthor(certificate, state, trust, minimumCertificate, enrollment...)
	observed := KeyCopyObservation{author.StateSequence, author.CertificateRevision}
	if err != nil {
		return observed, err
	}
	if binding.WorkspaceID != trust.WorkspaceID || binding.Issuer != author.Key {
		return observed, vault.ErrAuthentication
	}
	return observed, vault.VerifyKeyCopy(binding, copy, author.Public)
}
