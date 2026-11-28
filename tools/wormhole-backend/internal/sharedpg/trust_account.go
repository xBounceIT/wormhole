package sharedpg

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"reflect"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var ErrAccountEquivocation = errors.New("account key state changed without a sequence advance")

func cloneAccountState(state *vault.UserKeyState) *vault.UserKeyState {
	if state == nil {
		return nil
	}
	copy := *state
	copy.Signature = bytes.Clone(state.Signature)
	return &copy
}

func accountFloorsAdvance(previous, next *vault.UserKeyState) bool {
	if previous == nil {
		return true
	}
	if next == nil {
		return false
	}
	for _, pair := range []struct {
		old, new           vault.KeyRef
		oldFloor, newFloor uint64
	}{
		{previous.Encryption, next.Encryption, previous.MinimumEncryptionCertificate, next.MinimumEncryptionCertificate},
		{previous.Signing, next.Signing, previous.MinimumSigningCertificate, next.MinimumSigningCertificate},
	} {
		if pair.old.ID == pair.new.ID && (pair.new.Version < pair.old.Version || (pair.new == pair.old && pair.newFloor < pair.oldFloor)) {
			return false
		}
	}
	return true
}

func (s TrustState) accountTrust() (vault.UserKeyTrust, error) {
	signer, err := uuid.Parse(s.SignerKeyID)
	if err != nil || signer == uuid.Nil || signer.String() != s.SignerKeyID {
		return vault.UserKeyTrust{}, ErrTrustState
	}
	trust := vault.UserKeyTrust{WorkspaceID: s.WorkspaceID, UserID: s.UserID, Signer: vault.KeyRef{ID: signer, Version: s.SignerKeyVersion}, Organisation: bytes.Clone(s.PublicKey), MinimumWrappingRevision: s.WrappingRevision}
	if s.Account != nil {
		trust.MinimumSequence = s.Account.Sequence
	}
	return trust, nil
}

// Catalog verification may observe the user's signed state before the first
// account anchor is installed. Those authenticated floors constrain login too.
func (s TrustState) checkAccountCatalog(state vault.UserKeyState) error {
	floor := s.Catalog["author/"+s.UserID.String()]
	if state.Sequence < floor.Revision {
		return vault.ErrRollback
	}
	if floor.Revision > 0 && state.Sequence == floor.Revision {
		raw, _ := json.Marshal(state)
		digest := sha256.Sum256(raw)
		if !bytes.Equal(floor.Digest, digest[:]) {
			return ErrAccountEquivocation
		}
	}
	return nil
}

func (s TrustState) validAccount() bool {
	if s.FormatVersion == 2 || ((s.FormatVersion == 4 || s.FormatVersion >= 6) && s.Account == nil) {
		return s.Account == nil && s.WrappingRevision == 0
	}
	if s.Account == nil || s.WrappingRevision == 0 || s.WrappingRevision > math.MaxInt64 {
		return false
	}
	trust, err := s.accountTrust()
	return err == nil && vault.VerifyUserKeyState(*s.Account, trust) == nil && s.checkAccountCatalog(*s.Account) == nil
}

// AccountTrust exposes authenticated floors only after an explicit account-state
// upgrade (formats 3–6). Policy/TLS enrollment alone is not an account anchor.
func (s TrustState) AccountTrust() (vault.UserKeyTrust, error) {
	if !s.valid() || s.Account == nil {
		return vault.UserKeyTrust{}, ErrTrustState
	}
	return s.accountTrust()
}

// AdvanceAccount authenticates even revoked states. Persist its result before
// acting on the account state; never discard a revocation merely because unlock
// will be denied. The observed wrapping revision must come from verified material.
func (s TrustState) AdvanceAccount(state vault.UserKeyState, wrappingRevision uint64) (TrustState, error) {
	if !s.valid() || wrappingRevision == 0 || wrappingRevision > math.MaxInt64 {
		return TrustState{}, ErrTrustState
	}
	trust, err := s.accountTrust()
	if err != nil {
		return TrustState{}, err
	}
	if err := vault.VerifyUserKeyState(state, trust); err != nil {
		return TrustState{}, err
	}
	if err := s.checkAccountCatalog(state); err != nil {
		return TrustState{}, err
	}
	if wrappingRevision < s.WrappingRevision {
		return TrustState{}, ErrTrustRollback
	}
	if !accountFloorsAdvance(s.Account, &state) {
		return TrustState{}, ErrTrustRollback
	}
	if s.Account != nil && state.Sequence == s.Account.Sequence && !reflect.DeepEqual(state, *s.Account) {
		return TrustState{}, ErrAccountEquivocation
	}
	changed := s.Account == nil || state.Sequence > s.Account.Sequence || wrappingRevision > s.WrappingRevision
	if changed {
		if s.Revision == math.MaxUint64 {
			return TrustState{}, ErrTrustState
		}
		s.Revision++
	}
	if s.FormatVersion < 4 {
		s.FormatVersion = 3
	}
	if s.Account != nil && (s.Account.Encryption != state.Encryption || s.Account.Signing != state.Signing) {
		s.Enrollment = nil
	}
	s.Enrollment = cloneEnrollmentPin(s.Enrollment)
	s.Account = cloneAccountState(&state)
	s.WrappingRevision = wrappingRevision
	s.PublicKey = bytes.Clone(s.PublicKey)
	s.PolicyDigest = bytes.Clone(s.PolicyDigest)
	s.SignedProfile = bytes.Clone(s.SignedProfile)
	s.TLSDigest = bytes.Clone(s.TLSDigest)
	s.Catalog = cloneCatalogFloors(s.Catalog)
	return s, nil
}

// ValidateAdvance is the persistence boundary: neither a policy-only writer nor
// an account-state writer may erase the other's authenticated high-water marks.
func (s TrustState) ValidateAdvance(next TrustState) error {
	if !s.valid() || !next.valid() || s.Revision == math.MaxUint64 || next.Revision != s.Revision+1 || s.WorkspaceID != next.WorkspaceID || s.UserID != next.UserID || s.DeviceID != next.DeviceID || s.SignerKeyID != next.SignerKeyID || s.SignerKeyVersion != next.SignerKeyVersion || !bytes.Equal(s.PublicKey, next.PublicKey) {
		return ErrTrustState
	}
	if next.FormatVersion < s.FormatVersion || (s.UserMinimum != "" && next.UserMinimum != s.UserMinimum) {
		return ErrTrustRollback
	}
	if next.PolicySequence < s.PolicySequence {
		return ErrProfileRollback
	}
	if next.PolicySequence == s.PolicySequence && !bytes.Equal(s.PolicyDigest, next.PolicyDigest) {
		return ErrProfileEquivocation
	}
	if s.Account != nil {
		if next.Account == nil || next.Account.Sequence < s.Account.Sequence || next.WrappingRevision < s.WrappingRevision || !accountFloorsAdvance(s.Account, next.Account) {
			return ErrTrustRollback
		}
		if next.Account.Sequence == s.Account.Sequence && !reflect.DeepEqual(next.Account, s.Account) {
			return ErrAccountEquivocation
		}
	}
	if next.TLSSequence < s.TLSSequence || (next.TLSSequence == s.TLSSequence && !bytes.Equal(next.TLSDigest, s.TLSDigest)) {
		return ErrTrustRollback
	}
	if !enrollmentAdvances(s, next) {
		return ErrTrustRollback
	}
	if !catalogFloorsAdvance(s.Catalog, next.Catalog) {
		return ErrTrustRollback
	}
	if reflect.DeepEqual(next.SuspensionRotations, s.SuspensionRotations) && next.UserMinimum == s.UserMinimum && next.PolicySequence == s.PolicySequence && reflect.DeepEqual(next.Account, s.Account) && next.WrappingRevision == s.WrappingRevision && next.TLSSequence == s.TLSSequence && reflect.DeepEqual(next.Enrollment, s.Enrollment) && reflect.DeepEqual(next.Catalog, s.Catalog) {
		return ErrProfileRollback
	}
	return nil
}
