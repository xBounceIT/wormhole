package sharedpg

import (
	"reflect"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func (p PendingEnrollment) ObservedTrust() TrustState {
	if p.Observed != nil {
		return cloneTrustState(*p.Observed)
	}
	return cloneTrustState(p.Trust)
}

// Observations must be durably saved before acting on them, including a signed
// revocation or reset that prevents completion. They never select final keys.
func (p PendingEnrollment) ObserveProfile(b TrustBinding, a *UnverifiedAdmission, r AdmissionRequest) (PendingEnrollment, error) {
	if !p.valid(b) {
		return PendingEnrollment{}, ErrTrustState
	}
	current := p.ObservedTrust()
	next, err := current.Advance(a, r)
	if err != nil {
		return PendingEnrollment{}, err
	}
	if next.Revision != current.Revision {
		p.Observed = &next
	}
	return p, nil
}

// ObservePolicy retains a signed floor independently of API compatibility. It
// cannot authorize admission; callers persist it before rejecting a newer API.
func (p PendingEnrollment) ObservePolicy(b TrustBinding, raw []byte) (PendingEnrollment, error) {
	if !p.valid(b) {
		return PendingEnrollment{}, ErrTrustState
	}
	current := p.ObservedTrust()
	next, err := current.AdvancePolicy(raw)
	if err != nil {
		return PendingEnrollment{}, err
	}
	if next.Revision != current.Revision {
		p.Observed = &next
	}
	return p, nil
}

func (p PendingEnrollment) ObserveAccount(b TrustBinding, state vault.UserKeyState, wrapping uint64) (PendingEnrollment, error) {
	if !p.valid(b) {
		return PendingEnrollment{}, ErrTrustState
	}
	current := p.ObservedTrust()
	next, err := current.AdvanceAccount(state, wrapping)
	if err != nil {
		return PendingEnrollment{}, err
	}
	if next.Revision != current.Revision {
		p.Observed = &next
	}
	return p, nil
}

func (p PendingEnrollment) ObserveTLS(b TrustBinding, bundle *VerifiedTLSBundle) (PendingEnrollment, error) {
	if !p.valid(b) {
		return PendingEnrollment{}, ErrTrustState
	}
	current := p.ObservedTrust()
	next, err := current.AdvanceTLS(bundle)
	if err != nil {
		return PendingEnrollment{}, err
	}
	if next.Revision != current.Revision {
		p.Observed = &next
	}
	return p, nil
}

func (p PendingEnrollment) ValidateObservationAdvance(b TrustBinding, next PendingEnrollment) error {
	if err := p.validateObservationCore(b, next); err != nil {
		return err
	}
	current, updated := p.ObservedTrust(), next.ObservedTrust()
	if reflect.DeepEqual(current, updated) {
		return nil
	}
	return current.ValidateAdvance(updated)
}

// ValidateObservationSnapshot compares independently persisted observations that
// can be several revisions apart. The prepared identity/capsule must be exact;
// every signed trust floor must advance together. Ordinary writes still require
// the adjacent revision checked by ValidateObservationAdvance.
func (p PendingEnrollment) ValidateObservationSnapshot(b TrustBinding, next PendingEnrollment) error {
	if err := p.validateObservationCore(b, next); err != nil {
		return err
	}
	if !trustProgress(p.ObservedTrust(), next.ObservedTrust()) {
		return ErrTrustRollback
	}
	return nil
}

func (p PendingEnrollment) validateObservationCore(b TrustBinding, next PendingEnrollment) error {
	if !p.valid(b) || !next.valid(b) {
		return ErrTrustState
	}
	oldCore, newCore := p, next
	oldCore.Observed, newCore.Observed = nil, nil
	if !reflect.DeepEqual(oldCore, newCore) {
		return ErrTrustState
	}
	return nil
}
