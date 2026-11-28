package sharedpg

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const MaxPendingEnrollmentBytes = 2 * 1024 * 1024

// PendingEnrollment records an intended first join, NOT proof of a committed
// enrollment. Store only with SealPendingEnrollment, before SQL dispatch. It
// contains no password, ASK, verifier, master or private keys. Recovery must prove
// the exact device login and verify its capsule/certificate before creating trust.
// Never turn this record alone into an active TrustState or a retry permission.
type PendingEnrollment struct {
	FormatVersion uint16                          `json:"formatVersion"`
	Trust         TrustState                      `json:"trust"`
	Certificate   vault.UserEnrollmentCertificate `json:"certificate"`
	CapsuleDigest []byte                          `json:"capsuleDigest"`
	RoleTag       string                          `json:"roleTag"`
	KDF           vault.KDFPreset                 `json:"kdf"`
	ASKRequired   bool                            `json:"askRequired"`
	Observed      *TrustState                     `json:"observed,omitempty"`
}

func (p PendingEnrollment) valid(b TrustBinding) bool {
	if _, err := b.binding(); err != nil {
		return false
	}
	if p.FormatVersion != 1 || !p.Trust.matches(b) || p.Trust.FormatVersion != 3 || p.Trust.Revision != 1 || p.Trust.Account == nil || !p.Trust.Account.Active || p.Trust.WrappingRevision != 1 || len(p.CapsuleDigest) != sha256.Size {
		return false
	}
	policy, err := p.Trust.Policy()
	if err != nil {
		return false
	}
	trust, err := p.Trust.AccountTrust()
	if err != nil || vault.VerifyUserEnrollmentCertificate(p.Certificate, *p.Trust.Account, trust, 1) != nil {
		return false
	}
	actual := policy
	actual.KDF, actual.ASKRequired = p.KDF, p.ASKRequired
	if actual.Validate() != nil {
		return false
	}
	floor, _ := vault.Parameters(policy.KDF)
	selected, _ := vault.Parameters(p.KDF)
	if selected.MemoryKiB < floor.MemoryKiB || selected.Iterations < floor.Iterations || (policy.ASKRequired && !p.ASKRequired) {
		return false
	}
	if len(p.RoleTag) < 8 || len(p.RoleTag) > 16 {
		return false
	}
	for _, c := range p.RoleTag {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return p.Observed == nil || (p.Observed.Enrollment == nil && trustProgress(p.Trust, *p.Observed))
}

func pendingEnrollmentBinding(b TrustBinding) (vault.Binding, error) {
	result, err := b.binding()
	result.Table = "SharedPendingEnrollment"
	result.Field += "/initial-invite"
	return result, err
}

func SealPendingEnrollment(root []byte, b TrustBinding, p PendingEnrollment) ([]byte, error) {
	binding, err := pendingEnrollmentBinding(b)
	if err != nil || !p.valid(b) {
		return nil, ErrTrustState
	}
	key, err := vault.DeriveKey(root, b.WorkspaceID[:], vault.PurposeSharedTrust)
	if err != nil {
		return nil, ErrTrustState
	}
	defer vault.Wipe(key)
	plain, err := json.Marshal(p)
	if err != nil {
		return nil, ErrTrustState
	}
	defer vault.Wipe(plain)
	envelope, err := vault.Seal(key, binding, plain)
	if err != nil {
		return nil, ErrTrustState
	}
	raw, err := json.Marshal(envelope)
	if err != nil || len(raw) > MaxPendingEnrollmentBytes {
		return nil, ErrTrustState
	}
	return raw, nil
}

func OpenPendingEnrollment(root []byte, b TrustBinding, raw []byte) (PendingEnrollment, error) {
	binding, err := pendingEnrollmentBinding(b)
	if err != nil || len(raw) == 0 || len(raw) > MaxPendingEnrollmentBytes {
		return PendingEnrollment{}, ErrTrustState
	}
	var envelope vault.Envelope
	if json.Unmarshal(raw, &envelope) != nil {
		return PendingEnrollment{}, ErrTrustState
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, raw) {
		return PendingEnrollment{}, ErrTrustState
	}
	key, err := vault.DeriveKey(root, b.WorkspaceID[:], vault.PurposeSharedTrust)
	if err != nil {
		return PendingEnrollment{}, ErrTrustState
	}
	defer vault.Wipe(key)
	plain, err := vault.Open(key, binding, envelope)
	if err != nil {
		return PendingEnrollment{}, ErrTrustState
	}
	defer vault.Wipe(plain)
	var p PendingEnrollment
	if json.Unmarshal(plain, &p) != nil || !p.valid(b) {
		return PendingEnrollment{}, ErrTrustState
	}
	canonical, err = json.Marshal(p)
	if err != nil || !bytes.Equal(canonical, plain) {
		return PendingEnrollment{}, ErrTrustState
	}
	return p, nil
}

// PendingEnrollment returns an independent authenticated snapshot for encrypted
// staging. It survives wiping the request, but cannot recreate its SQL mutation.
func (p *PreparedInvitationCommit) PendingEnrollment(b TrustBinding) (PendingEnrollment, error) {
	if p == nil || len(p.pending) == 0 {
		return PendingEnrollment{}, ErrTrustState
	}
	var record PendingEnrollment
	if json.Unmarshal(p.pending, &record) != nil || !record.valid(b) {
		return PendingEnrollment{}, ErrTrustState
	}
	return record, nil
}

func enrollmentCapsuleDigest(envelope vault.Envelope) []byte {
	h := sha256.New()
	h.Write([]byte("wormhole/v1/pending-enrollment-capsule"))
	h.Write(envelope.Nonce)
	h.Write(envelope.Ciphertext)
	return h.Sum(nil)
}
