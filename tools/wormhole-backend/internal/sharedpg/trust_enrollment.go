package sharedpg

import (
	"bytes"
	"crypto/sha256"
	"math"
	"reflect"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// EnrollmentPin binds one final pair to the current signed bootstrap anchor.
// It is protected device-local metadata, never an assertion accepted from SQL.
type EnrollmentPin struct {
	Encryption       vault.KeyRef `json:"encryption"`
	Signing          vault.KeyRef `json:"signing"`
	PublicDigest     []byte       `json:"publicDigest"`
	ManifestRevision uint64       `json:"manifestRevision"`
}

func cloneEnrollmentPin(p *EnrollmentPin) *EnrollmentPin {
	if p == nil {
		return nil
	}
	next := *p
	next.PublicDigest = bytes.Clone(p.PublicDigest)
	return &next
}

func (s TrustState) validEnrollment() bool {
	if s.FormatVersion < 5 {
		return s.Enrollment == nil
	}
	if s.Account == nil {
		return s.FormatVersion >= 6 && s.Enrollment == nil
	}
	p := s.Enrollment
	if p == nil {
		return true
	} // A signed reset may retire the previous anchor.
	if p.Encryption.ID == p.Signing.ID || p.ManifestRevision == 0 || p.ManifestRevision > math.MaxInt64 || len(p.PublicDigest) != sha256.Size {
		return false
	}
	for _, ref := range []vault.KeyRef{p.Encryption, p.Signing} {
		if ref.ID == uuid.Nil || ref.Version != 1 || ref.ID == s.Account.Encryption.ID || ref.ID == s.Account.Signing.ID || ref.ID == s.Account.Signer.ID {
			return false
		}
	}
	return true
}

func enrollmentAdvances(previous, next TrustState) bool {
	if previous.Enrollment == nil {
		return true
	}
	if next.Account == nil {
		return false
	}
	if previous.Account.Encryption != next.Account.Encryption || previous.Account.Signing != next.Account.Signing {
		return next.Account.Sequence > previous.Account.Sequence
	}
	p, n := previous.Enrollment, next.Enrollment
	return n != nil && p.Encryption == n.Encryption && p.Signing == n.Signing && bytes.Equal(p.PublicDigest, n.PublicDigest) && n.ManifestRevision >= p.ManifestRevision
}

// AdvanceEnrollment verifies the chain under the current authenticated account
// state and pins its final pair. The caller must establish successful redemption
// (or independently authenticated device enrollment) and open the capsule first,
// then persist this result before publishing unlocked state. This method alone
// does not prove server commit or authorize first-use trust from arbitrary SQL.
// Persist a nonzero returned state even on error: independently authenticated
// bootstrap certificates remain observations when a later delegation is refused.
func (s TrustState) AdvanceEnrollment(c vault.UserEnrollmentCertificate, wrapping uint64) (result TrustState, resultErr error) {
	initialRevision := s.Revision
	defer func() {
		if result.Revision > initialRevision {
			result.Revision = initialRevision + 1
		}
	}()
	trust, err := s.AccountTrust()
	if err != nil || wrapping == 0 || wrapping > math.MaxInt64 {
		return TrustState{}, ErrTrustState
	}
	bootstrap, bootstrapErr := s.enrollmentBootstrapObservations(c, *s.Account)
	observed, err := s.mergeCatalogObservations(*s.Account, s.catalogAuthorFloor(s.UserID), 0, bootstrapErr, bootstrap...)
	if err != nil {
		return observed, err
	}
	s = observed
	minimum := uint64(1)
	if s.Enrollment != nil {
		minimum = s.Enrollment.ManifestRevision
	}
	minimum = max(minimum, s.Catalog[catalogEnrollmentName(*s.Account)].Revision)
	if err := vault.VerifyUserEnrollmentCertificate(c, *s.Account, trust, minimum); err != nil {
		return observed, err
	}
	author := UnverifiedNodeAuthor{State: s.Account, EnrollmentCertificate: &c}
	material := s.catalogAuthorMaterial(author)
	if err := s.checkCatalogAuthorSelection(author, material); err != nil {
		return observed, err
	}
	if wrapping < s.WrappingRevision {
		return observed, ErrTrustRollback
	}
	next := s
	next.Enrollment = &EnrollmentPin{
		Encryption:   material.selection.Encryption,
		Signing:      material.selection.Signing,
		PublicDigest: bytes.Clone(material.selection.PublicDigest[:]), ManifestRevision: c.Manifest.Revision,
	}
	if !enrollmentAdvances(s, next) {
		return observed, ErrAccountEquivocation
	}
	if !reflect.DeepEqual(next.Enrollment, s.Enrollment) || wrapping != s.WrappingRevision {
		if next.Revision == math.MaxUint64 {
			return TrustState{}, ErrTrustState
		}
		next.Revision++
	}
	next.FormatVersion, next.WrappingRevision = max(next.FormatVersion, 5), wrapping
	next.Account = cloneAccountState(s.Account)
	next.PublicKey = bytes.Clone(s.PublicKey)
	next.PolicyDigest = bytes.Clone(s.PolicyDigest)
	next.SignedProfile = bytes.Clone(s.SignedProfile)
	next.TLSDigest = bytes.Clone(s.TLSDigest)
	next.Catalog = cloneCatalogFloors(s.Catalog)
	return next, nil
}
