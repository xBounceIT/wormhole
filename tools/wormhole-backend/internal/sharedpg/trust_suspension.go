package sharedpg

import (
	"maps"
	"math"
)

// Each entry is a locally confirmed request to disable this account at the
// preceding row version. The resulting suspension has the recorded revision.
// The encrypted device trust file authenticates this authority across restarts.
func (s TrustState) validSuspensionRotations() bool {
	if s.SuspensionRotations == nil {
		return true
	}
	if s.FormatVersion != 8 || s.Account == nil || len(s.SuspensionRotations) == 0 {
		return false
	}
	for account, revision := range s.SuspensionRotations {
		id, ok := treeID([]byte(account))
		if !ok || id == s.UserID || revision < 2 || revision > math.MaxInt64 {
			return false
		}
	}
	return true
}

// TrackSuspension never replaces a newer confirmation with a stale one.
// Forgetting an intent is conditional on finishing that same suspension.
func (s TrustState) TrackSuspension(account string, revision uint64, finished bool) (TrustState, error) {
	id, ok := treeID([]byte(account))
	if !ok || id == s.UserID || revision < 2 || revision > math.MaxInt64 || !s.valid() || s.Account == nil || !s.Account.Active {
		return TrustState{}, ErrTrustState
	}
	prior := s.SuspensionRotations[account]
	if (finished && prior != revision) || (!finished && prior >= revision) {
		return s, nil
	}
	if s.Revision == math.MaxUint64 {
		return TrustState{}, ErrTrustState
	}
	s.SuspensionRotations = maps.Clone(s.SuspensionRotations)
	if finished {
		delete(s.SuspensionRotations, account)
		if len(s.SuspensionRotations) == 0 {
			s.SuspensionRotations = nil
		}
	} else {
		if s.SuspensionRotations == nil {
			s.SuspensionRotations = make(map[string]uint64)
		}
		s.SuspensionRotations[account] = revision
	}
	s.FormatVersion = 8
	s.Revision++
	if !s.validSuspensionRotations() {
		return TrustState{}, ErrTrustState
	}
	return s, nil
}
