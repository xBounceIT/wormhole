package sharedpg

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const MaxTrustStateBytes = 2 * 1024 * 1024

var (
	ErrTrustState          = errors.New("shared workspace trust state is invalid")
	ErrTrustRollback       = errors.New("shared workspace trust state is older than the trusted revision")
	ErrProfileEquivocation = errors.New("workspace profile changed without a sequence advance")
)

// TrustBinding and the root key must come from the unlocked device enrollment,
// never from the file being opened. This file is not an offline workspace cache.
type TrustBinding struct {
	WorkspaceID uuid.UUID
	UserID      uuid.UUID
	DeviceID    uuid.UUID
	KeyID       uuid.UUID
	KeyVersion  uint32
}

type TrustState struct {
	FormatVersion       uint16                  `json:"formatVersion"`
	Revision            uint64                  `json:"revision"`
	WorkspaceID         uuid.UUID               `json:"workspaceId"`
	UserID              uuid.UUID               `json:"userId"`
	DeviceID            uuid.UUID               `json:"deviceId"`
	SignerKeyID         string                  `json:"signerKeyId"`
	SignerKeyVersion    uint32                  `json:"signerKeyVersion"`
	PublicKey           []byte                  `json:"publicKey"`
	PolicySequence      uint64                  `json:"policySequence"`
	PolicyDigest        []byte                  `json:"policyDigest"`
	SignedProfile       []byte                  `json:"signedProfile"`
	Account             *vault.UserKeyState     `json:"account,omitempty"`
	WrappingRevision    uint64                  `json:"wrappingRevision,omitempty"`
	TLSSequence         uint64                  `json:"tlsSequence,omitempty"`
	TLSDigest           []byte                  `json:"tlsDigest,omitempty"`
	Enrollment          *EnrollmentPin          `json:"enrollment,omitempty"`
	Catalog             map[string]CatalogFloor `json:"catalog,omitempty"`
	UserMinimum         vault.Profile           `json:"userMinimum,omitempty"`
	SuspensionRotations map[string]uint64       `json:"suspensionRotations,omitempty"`
}

// PersonalProfile is the user's minimum for this device enrollment.
// Existing trust documents predate personal choices and omit the field.
func (s TrustState) PersonalProfile() vault.Profile {
	if s.UserMinimum == "" {
		return vault.Default
	}
	return s.UserMinimum
}

func (s TrustState) valid() bool {
	_, err := s.Policy()
	return err == nil
}

// Policy authenticates the cached document before it can influence a connection
// policy. Formats 2–7 require the document. Formats 3–7 authenticate account
// state when present. Format 4 requires TLS floors. Format 5 adds enrollment
// selection and permits TLS floors when transport is managed. Format 6 retains
// public enrolled-author selections independently of an unlocked account. Format 7
// adds the personal Standard minimum to an authenticated device account.
func (s TrustState) Policy() (vault.Policy, error) {
	if !((s.FormatVersion >= 2 && s.FormatVersion <= 8) && s.Revision > 0 && s.WorkspaceID != uuid.Nil && s.UserID != uuid.Nil && s.DeviceID != uuid.Nil &&
		len(s.SignerKeyID) > 0 && len(s.SignerKeyID) <= vault.MaxContextBytes && utf8.ValidString(s.SignerKeyID) && !strings.ContainsRune(s.SignerKeyID, 0) &&
		s.SignerKeyVersion > 0 && len(s.PublicKey) == ed25519.PublicKeySize && s.PolicySequence > 0 && len(s.PolicyDigest) == sha256.Size) {
		return vault.Policy{}, ErrTrustState
	}
	if (s.FormatVersion == 7 && s.UserMinimum != vault.Standard) ||
		(s.UserMinimum != "" && (s.FormatVersion < 7 || s.UserMinimum != vault.Standard || s.Account == nil)) || !s.validSuspensionRotations() {
		return vault.Policy{}, ErrTrustState
	}
	signed, err := vault.DecodeSignedPolicy(s.SignedProfile)
	if err != nil {
		return vault.Policy{}, ErrTrustState
	}
	if err := vault.VerifyPolicy(signed, s.WorkspaceID.String(), s.SignerKeyID, s.SignerKeyVersion, s.PublicKey, s.PolicySequence); err != nil || signed.Policy.Sequence != s.PolicySequence {
		return vault.Policy{}, ErrTrustState
	}
	digest := sha256.Sum256(s.SignedProfile)
	if !bytes.Equal(digest[:], s.PolicyDigest) {
		return vault.Policy{}, ErrTrustState
	}
	if !s.validAccount() || !s.validTLS() || !s.validEnrollment() || !validCatalogFloors(s.Catalog) {
		return vault.Policy{}, ErrTrustState
	}
	if s.FormatVersion < 6 {
		for key := range s.Catalog {
			if strings.HasPrefix(key, "enrollment/") {
				return vault.Policy{}, ErrTrustState
			}
		}
	}
	return signed.Policy, nil
}

func (b TrustBinding) binding() (vault.Binding, error) {
	if b.WorkspaceID == uuid.Nil || b.UserID == uuid.Nil || b.DeviceID == uuid.Nil || b.KeyID == uuid.Nil || b.KeyVersion == 0 {
		return vault.Binding{}, ErrTrustState
	}
	return vault.Binding{WorkspaceID: b.WorkspaceID.String(), Table: "SharedTrust", OwnerID: b.DeviceID.String(), Field: b.UserID.String(), KeyID: b.KeyID.String(), KeyVersion: b.KeyVersion}, nil
}

func (s TrustState) matches(b TrustBinding) bool {
	return s.WorkspaceID == b.WorkspaceID && s.UserID == b.UserID && s.DeviceID == b.DeviceID
}

func (s TrustState) PolicyTrust() PolicyTrust {
	return PolicyTrust{WorkspaceID: s.WorkspaceID, SignerKeyID: s.SignerKeyID, SignerKeyVersion: s.SignerKeyVersion, PublicKey: bytes.Clone(s.PublicKey), MinimumSequence: s.PolicySequence}
}

// NewTrustState is enrollment-only: it authenticates the first profile using the
// independently confirmed organisation key. Ordinary reads never create a state.
func NewTrustState(a *UnverifiedAdmission, r AdmissionRequest, pinned PolicyTrust) (TrustState, error) {
	policy, err := VerifyAdmissionPolicy(a, r, pinned)
	if err != nil {
		return TrustState{}, err
	}
	digest := sha256.Sum256(a.SignedProfile)
	result := TrustState{FormatVersion: 2, Revision: 1, WorkspaceID: r.WorkspaceID, UserID: r.UserID, DeviceID: r.DeviceID,
		SignerKeyID: pinned.SignerKeyID, SignerKeyVersion: pinned.SignerKeyVersion, PublicKey: bytes.Clone(pinned.PublicKey), PolicySequence: policy.Sequence, PolicyDigest: bytes.Clone(digest[:]), SignedProfile: bytes.Clone(a.SignedProfile)}
	if !result.valid() {
		return TrustState{}, ErrTrustState
	}
	return result, nil
}

// Advance verifies against the existing pin and never changes signer identity.
// An unchanged profile needs no disk write. A higher revision must be durably
// persisted before the caller uses the newly authenticated profile.
func (s TrustState) Advance(a *UnverifiedAdmission, r AdmissionRequest) (TrustState, error) {
	if !s.valid() || s.WorkspaceID != r.WorkspaceID || s.UserID != r.UserID || s.DeviceID != r.DeviceID {
		return TrustState{}, ErrTrustState
	}
	policy, err := VerifyAdmissionPolicy(a, r, s.PolicyTrust())
	if err != nil {
		return TrustState{}, err
	}
	return s.advanceProfile(a.SignedProfile, policy)
}

// AdvancePolicy authenticates a policy observation even when its API window
// prevents this client from proceeding. It grants no admission or compatibility.
// Persist the resulting floor before reporting denial or using the policy.
func (s TrustState) AdvancePolicy(raw []byte) (TrustState, error) {
	if !s.valid() {
		return TrustState{}, ErrTrustState
	}
	policy, err := verifySignedWorkspacePolicy(raw, s.PolicyTrust())
	if err != nil {
		return TrustState{}, err
	}
	return s.advanceProfile(raw, policy)
}

func (s TrustState) advanceProfile(raw []byte, policy vault.Policy) (TrustState, error) {
	digest := sha256.Sum256(raw)
	if policy.Sequence == s.PolicySequence {
		if !bytes.Equal(digest[:], s.PolicyDigest) {
			return TrustState{}, ErrProfileEquivocation
		}
	} else {
		if s.Revision == math.MaxUint64 {
			return TrustState{}, ErrTrustState
		}
		s.Revision++
		s.PolicySequence = policy.Sequence
	}
	s.PublicKey = bytes.Clone(s.PublicKey)
	s.PolicyDigest = bytes.Clone(digest[:])
	s.SignedProfile = bytes.Clone(raw)
	s.Account = cloneAccountState(s.Account)
	s.TLSDigest = bytes.Clone(s.TLSDigest)
	s.Enrollment = cloneEnrollmentPin(s.Enrollment)
	s.Catalog = cloneCatalogFloors(s.Catalog)
	return s, nil
}

func SealTrustState(root []byte, b TrustBinding, s TrustState) ([]byte, error) {
	binding, err := b.binding()
	if err != nil || !s.valid() || !s.matches(b) {
		return nil, ErrTrustState
	}
	key, err := vault.DeriveKey(root, b.WorkspaceID[:], vault.PurposeSharedTrust)
	if err != nil {
		return nil, ErrTrustState
	}
	defer vault.Wipe(key)
	plain, err := json.Marshal(s)
	if err != nil {
		return nil, ErrTrustState
	}
	defer vault.Wipe(plain)
	envelope, err := vault.Seal(key, binding, plain)
	if err != nil {
		return nil, ErrTrustState
	}
	raw, err := json.Marshal(envelope)
	if err != nil || len(raw) > MaxTrustStateBytes {
		return nil, ErrTrustState
	}
	return raw, nil
}

// Open authenticates both the envelope and its identity binding, then enforces
// the caller's revision floor. Restoring all valid old state and its external
// floor is not detectable by encryption alone; no monotonic-hardware claim.
func OpenTrustState(root []byte, b TrustBinding, raw []byte, minimumRevision uint64) (TrustState, error) {
	binding, err := b.binding()
	if err != nil || minimumRevision == 0 || len(raw) == 0 || len(raw) > MaxTrustStateBytes {
		return TrustState{}, ErrTrustState
	}
	var envelope vault.Envelope
	if json.Unmarshal(raw, &envelope) != nil {
		return TrustState{}, ErrTrustState
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(raw, canonical) {
		return TrustState{}, ErrTrustState
	}
	key, err := vault.DeriveKey(root, b.WorkspaceID[:], vault.PurposeSharedTrust)
	if err != nil {
		return TrustState{}, ErrTrustState
	}
	defer vault.Wipe(key)
	plain, err := vault.Open(key, binding, envelope)
	if err != nil {
		return TrustState{}, ErrTrustState
	}
	defer vault.Wipe(plain)
	var s TrustState
	if json.Unmarshal(plain, &s) != nil || !s.valid() || !s.matches(b) {
		return TrustState{}, ErrTrustState
	}
	canonical, err = json.Marshal(s)
	if err != nil || !bytes.Equal(plain, canonical) {
		return TrustState{}, ErrTrustState
	}
	if s.Revision < minimumRevision {
		return TrustState{}, ErrTrustRollback
	}
	return s, nil
}
