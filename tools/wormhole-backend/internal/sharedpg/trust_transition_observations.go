package sharedpg

import (
	"bytes"
	"maps"
	"reflect"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// ObservedTrust never includes the predicted next wrapping floor. Only verified
// remote material may advance that floor during reconciliation.
func (t TrustRootTransition) ObservedTrust() TrustState {
	s := t.Previous
	if t.Observed != nil {
		s = *t.Observed
	}
	return cloneTrustState(s)
}

func cloneTrustState(s TrustState) TrustState {
	s.PublicKey = bytes.Clone(s.PublicKey)
	s.PolicyDigest = bytes.Clone(s.PolicyDigest)
	s.SignedProfile = bytes.Clone(s.SignedProfile)
	s.Account = cloneAccountState(s.Account)
	s.TLSDigest = bytes.Clone(s.TLSDigest)
	s.Enrollment = cloneEnrollmentPin(s.Enrollment)
	s.Catalog = cloneCatalogFloors(s.Catalog)
	s.SuspensionRotations = maps.Clone(s.SuspensionRotations)
	return s
}

func (t TrustRootTransition) ObserveProfile(b TrustBinding, a *UnverifiedAdmission, r AdmissionRequest) (TrustRootTransition, error) {
	if !t.valid(b) {
		return TrustRootTransition{}, ErrTrustState
	}
	current := t.ObservedTrust()
	next, err := current.Advance(a, r)
	if err != nil {
		return TrustRootTransition{}, err
	}
	if next.Revision != current.Revision {
		t.Observed = &next
	}
	return t, nil
}

func (t TrustRootTransition) ObserveTLS(b TrustBinding, bundle *VerifiedTLSBundle) (TrustRootTransition, error) {
	if !t.valid(b) {
		return TrustRootTransition{}, ErrTrustState
	}
	current := t.ObservedTrust()
	next, err := current.AdvanceTLS(bundle)
	if err != nil {
		return TrustRootTransition{}, err
	}
	if next.Revision != current.Revision {
		t.Observed = &next
	}
	return t, nil
}

func (t TrustRootTransition) ObserveAccount(b TrustBinding, state vault.UserKeyState, wrapping uint64) (TrustRootTransition, error) {
	if !t.valid(b) {
		return TrustRootTransition{}, ErrTrustState
	}
	current := t.ObservedTrust()
	next, err := current.AdvanceAccount(state, wrapping)
	if err != nil {
		return TrustRootTransition{}, err
	}
	if next.Revision != current.Revision {
		t.Observed = &next
	}
	return t, nil
}

// ObserveEnrollment preserves the verified final selection and manifest floor
// when reconciling a password change. It cannot establish a new enrollment pin.
func (t TrustRootTransition) ObserveEnrollment(b TrustBinding, certificate vault.UserEnrollmentCertificate, wrapping uint64) (TrustRootTransition, error) {
	if !t.valid(b) {
		return TrustRootTransition{}, ErrTrustState
	}
	current := t.ObservedTrust()
	if current.Enrollment == nil {
		return TrustRootTransition{}, ErrTrustState
	}
	next, err := current.AdvanceEnrollment(certificate, wrapping)
	if next.Revision != 0 && next.Revision != current.Revision {
		t.Observed = &next
	}
	return t, err
}

// ValidateObservationAdvance is the journal CAS boundary. Immutable preparation
// fields cannot change; each persisted observation advances the local counter by
// exactly one, or confirms the exact unchanged state after uncertain durability.
func (t TrustRootTransition) ValidateObservationAdvance(b TrustBinding, next TrustRootTransition) error {
	if !t.valid(b) || !next.valid(b) {
		return ErrTrustState
	}
	oldCore, newCore := t, next
	oldCore.Observed = nil
	newCore.Observed = nil
	if !reflect.DeepEqual(oldCore, newCore) {
		return ErrTrustState
	}
	current, updated := t.ObservedTrust(), next.ObservedTrust()
	if reflect.DeepEqual(current, updated) {
		return nil
	}
	return current.ValidateAdvance(updated)
}

// PromotionState merges every authenticated observation into the committed
// destination. Deleting a journal must never discard a revocation/profile floor.
func (t TrustRootTransition) PromotionState(b TrustBinding) (TrustState, error) {
	if !t.valid(b) {
		return TrustState{}, ErrTrustState
	}
	current := t.ObservedTrust()
	wrapping := max(current.WrappingRevision, t.Next.WrappingRevision)
	return current.AdvanceAccount(*current.Account, wrapping)
}

// AbortState is usable only after independent proof of noncommit. A verified
// higher wrapping floor contradicts noncommit and cannot be discarded.
func (t TrustRootTransition) AbortState(b TrustBinding) (TrustState, error) {
	if !t.valid(b) {
		return TrustState{}, ErrTrustState
	}
	current := t.ObservedTrust()
	if current.WrappingRevision != t.Previous.WrappingRevision {
		return TrustState{}, ErrTrustRollback
	}
	return current, nil
}

// AcceptsDestination recognizes a durable intermediate result left by a prior
// finalization attempt. It cannot accept arbitrary self-signed pins, a state
// ahead of the journal, or a committed destination as an aborted one.
func (t TrustRootTransition) AcceptsDestination(b TrustBinding, current TrustState, committed bool) bool {
	var target TrustState
	var err error
	if committed {
		target, err = t.PromotionState(b)
		if current.WrappingRevision < t.Next.WrappingRevision {
			return false
		}
	} else {
		target, err = t.AbortState(b)
		if current.WrappingRevision != t.Previous.WrappingRevision {
			return false
		}
	}
	return err == nil && trustProgress(t.Previous, current) && trustProgress(current, target)
}

func trustProgress(from, to TrustState) bool {
	if reflect.DeepEqual(from, to) {
		return true
	}
	if to.Revision <= from.Revision {
		return false
	}
	normalized := to
	normalized.Revision = from.Revision + 1
	return from.ValidateAdvance(normalized) == nil
}
