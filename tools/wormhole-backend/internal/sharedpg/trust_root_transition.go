package sharedpg

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"math"
	"reflect"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Format 3 also carries the bounded device candidate needed before root unlock.
const MaxTrustRootTransitionBytes = 16 * 1024 * 1024

// TrustRootTransition is a prepared local password-root transition, not evidence
// of a PostgreSQL commit. Promotion requires independent remote reconciliation.
// The record contains no old/new root, master, login material or private keys.
type TrustRootTransition struct {
	FormatVersion  uint16                   `json:"formatVersion"`
	ID             uuid.UUID                `json:"id"`
	PreviousDigest []byte                   `json:"previousDigest"`
	Previous       TrustState               `json:"previous"`
	Next           TrustState               `json:"next"`
	Observed       *TrustState              `json:"observed,omitempty"`
	Transport      *TransportRootTransition `json:"transport,omitempty"`
	Device         *DeviceRootTransition    `json:"device,omitempty"`
}

func (t TrustRootTransition) valid(b TrustBinding) bool {
	formatValid := (t.FormatVersion == 1 && t.Transport == nil && t.Device == nil) ||
		(t.FormatVersion == 2 && t.Transport.valid() && t.Device == nil) ||
		(t.FormatVersion == 3 && t.Device.valid() && (t.Transport == nil || t.Transport.valid()))
	if !formatValid || t.ID == uuid.Nil || len(t.PreviousDigest) != sha256.Size || !t.Previous.valid() || !t.Previous.matches(b) || t.Previous.Account == nil || !t.Previous.Account.Active || t.Previous.WrappingRevision >= math.MaxInt64 {
		return false
	}
	expected, err := t.Previous.AdvanceAccount(*t.Previous.Account, t.Previous.WrappingRevision+1)
	if err != nil || !reflect.DeepEqual(expected, t.Next) {
		return false
	}
	if t.Observed == nil {
		return true
	}
	if t.Observed.Revision <= t.Previous.Revision {
		return false
	}
	// Observations may span multiple authenticated updates. Normalize only the
	// local counter for the existing monotonic identity/pin/policy/account check.
	observed := *t.Observed
	observed.Revision = t.Previous.Revision + 1
	return t.Previous.ValidateAdvance(observed) == nil
}

func transitionBinding(b TrustBinding) (vault.Binding, error) {
	binding, err := b.binding()
	if err != nil {
		return vault.Binding{}, err
	}
	binding.Table = "SharedTrustTransition"
	binding.Field += "/password-root"
	return binding, nil
}

// PrepareTrustRootTransition authenticates the exact old snapshot and seals the
// predicted next wrapping floor under the new root, with a separate AEAD domain.
// Persist this record durably before sending the remote password mutation.
func PrepareTrustRootTransition(oldRoot, newRoot []byte, b TrustBinding, previousRaw []byte, expectedRevision uint64) (TrustRootTransition, []byte, error) {
	previous, err := OpenTrustState(oldRoot, b, previousRaw, expectedRevision)
	if err != nil {
		return TrustRootTransition{}, nil, err
	}
	if previous.Revision != expectedRevision || previous.Account == nil || !previous.Account.Active || previous.WrappingRevision >= math.MaxInt64 {
		return TrustRootTransition{}, nil, ErrTrustState
	}
	next, err := previous.AdvanceAccount(*previous.Account, previous.WrappingRevision+1)
	if err != nil {
		return TrustRootTransition{}, nil, err
	}
	digest := sha256.Sum256(previousRaw)
	result := TrustRootTransition{FormatVersion: 1, ID: uuid.New(), PreviousDigest: bytes.Clone(digest[:]), Previous: previous, Next: next}
	raw, err := SealTrustRootTransition(newRoot, b, result)
	if err != nil {
		return TrustRootTransition{}, nil, err
	}
	return result, raw, nil
}

// Seal also validates observations; callers may not replace pins or erase a
// previously observed revocation while recovering an uncertain password change.
func SealTrustRootTransition(newRoot []byte, b TrustBinding, result TrustRootTransition) ([]byte, error) {
	if !result.valid(b) || !result.transportAuthenticates(newRoot, b) {
		return nil, ErrTrustState
	}
	binding, err := transitionBinding(b)
	if err != nil {
		return nil, err
	}
	key, err := vault.DeriveKey(newRoot, b.WorkspaceID[:], vault.PurposeSharedTrust)
	if err != nil {
		return nil, ErrTrustState
	}
	defer vault.Wipe(key)
	plain, err := json.Marshal(result)
	if err != nil {
		return nil, ErrTrustState
	}
	defer vault.Wipe(plain)
	envelope, err := vault.Seal(key, binding, plain)
	if err != nil {
		return nil, ErrTrustState
	}
	raw, err := json.Marshal(envelope)
	if err == nil && result.Device != nil {
		raw, err = json.Marshal(deviceTransitionFile{FormatVersion: 3, Device: result.Device.Next, Transition: raw})
	}
	if err != nil || len(raw) > MaxTrustRootTransitionBytes {
		return nil, ErrTrustState
	}
	return raw, nil
}

// OpenTrustRootTransition permits recovery using only the new root and the
// independently enrolled binding. It never authorizes adopting the predicted floor.
func OpenTrustRootTransition(newRoot []byte, b TrustBinding, raw []byte) (TrustRootTransition, error) {
	binding, err := transitionBinding(b)
	if err != nil || len(raw) == 0 || len(raw) > MaxTrustRootTransitionBytes {
		return TrustRootTransition{}, ErrTrustState
	}
	raw, candidate, err := decodeDeviceTransitionFile(raw)
	if err != nil {
		return TrustRootTransition{}, err
	}
	var envelope vault.Envelope
	if json.Unmarshal(raw, &envelope) != nil {
		return TrustRootTransition{}, ErrTrustState
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, raw) {
		return TrustRootTransition{}, ErrTrustState
	}
	key, err := vault.DeriveKey(newRoot, b.WorkspaceID[:], vault.PurposeSharedTrust)
	if err != nil {
		return TrustRootTransition{}, ErrTrustState
	}
	defer vault.Wipe(key)
	plain, err := vault.Open(key, binding, envelope)
	if err != nil {
		return TrustRootTransition{}, ErrTrustState
	}
	defer vault.Wipe(plain)
	var result TrustRootTransition
	if json.Unmarshal(plain, &result) != nil || !result.valid(b) || !result.transportAuthenticates(newRoot, b) {
		return TrustRootTransition{}, ErrTrustState
	}
	if (result.Device == nil) != (candidate == nil) || (result.Device != nil && !bytes.Equal(result.Device.Next, candidate)) {
		return TrustRootTransition{}, ErrTrustState
	}
	canonical, err = json.Marshal(result)
	if err != nil || !bytes.Equal(canonical, plain) {
		return TrustRootTransition{}, ErrTrustState
	}
	return result, nil
}
