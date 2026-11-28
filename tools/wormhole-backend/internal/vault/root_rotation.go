package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
)

// The recovery envelope is inseparable from both complete authenticated slot
// documents. Callers authenticate those documents after recovering the old root.
func RootRotationRecoveryBinding(source, target SlotFile) Binding {
	a, _ := json.Marshal(source)
	b, _ := json.Marshal(target)
	x, y := sha256.Sum256(a), sha256.Sum256(b)
	return Binding{WorkspaceID: target.VaultID, Table: "LocalRootRotation/source", OwnerID: target.FileID, Field: hex.EncodeToString(x[:]) + ":" + hex.EncodeToString(y[:]), KeyID: target.RootKeyID, KeyVersion: target.RootKeyVersion}
}

type RootRotationPhase string

const (
	RotationStaging    RootRotationPhase = "staging"
	RotationPrepared   RootRotationPhase = "prepared"
	RotationRetiring   RootRotationPhase = "retiring"
	RotationPublishing RootRotationPhase = "publishing"
	// Three source barriers precede the final document. Reserve all four
	// sequences before binding the recovery envelope to the final document.
	RootRotationSequenceSpan uint64 = 4
)

// LocalRootRotation is a denial barrier, never permission to open a database.
// Only the native journal controller can replace it with the new-root document.
type LocalRootRotation struct {
	ID                string              `json:"id"`
	Phase             RootRotationPhase   `json:"phase"`
	TargetRootVersion uint32              `json:"targetRootVersion"`
	TargetSlotDigest  string              `json:"targetSlotDigest"`
	Pending           *PendingRotationKey `json:"pending,omitempty"`
}

// PendingRotationKey is the wrapped next root and the KCV authenticated by the
// current slot file before an encrypted workspace copy can be opened.
type PendingRotationKey struct {
	Slots    []Slot `json:"slots"`
	KeyCheck []byte `json:"keyCheck"`
}

func (p RootRotationPhase) Step() uint64 {
	switch p {
	case RotationPrepared:
		return 1
	case RotationRetiring:
		return 2
	case RotationPublishing:
		return 3
	default:
		return 0
	}
}

func (r LocalRootRotation) valid(sourceVersion uint32) bool {
	digest, err := hex.DecodeString(r.TargetSlotDigest)
	validPhase := r.Phase == RotationStaging && r.Pending != nil || r.Phase.Step() != 0 && r.Pending == nil
	return canonicalID(r.ID) && validPhase && sourceVersion < math.MaxUint32 && r.TargetRootVersion == sourceVersion+1 && err == nil && len(digest) == 32 && hex.EncodeToString(digest) == r.TargetSlotDigest
}
