package sharedpg

import (
	"bytes"
	"crypto/sha256"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// TransportRootTransition carries only ciphertext and a source commitment.
// The target is authenticated under the new root and the same device binding.
// It is not proof of remote password-change commit.
type TransportRootTransition struct {
	PreviousDigest []byte `json:"previousDigest"`
	Next           []byte `json:"next"`
}

func (t *TransportRootTransition) valid() bool {
	return t != nil && len(t.PreviousDigest) == sha256.Size && len(t.Next) > 0 && len(t.Next) <= MaxTransportSnapshotBytes*2
}

// Payload validation is deliberately independent of ambient PostgreSQL settings,
// API availability and current TLS policy: rewrapping preserves authenticated
// historical metadata. Opening it for use still applies all current trust floors.
func transportPayloadCanonical(raw []byte) bool {
	_, err := decodeTransportSnapshotRecord(raw)
	return err == nil
}

func prepareTransportRootTransition(oldRoot, newRoot []byte, b TrustBinding, source []byte) (*TransportRootTransition, error) {
	plain, err := openTransportSetupPayload(oldRoot, b, source)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(plain)
	if !transportPayloadCanonical(plain) {
		return nil, ErrTrustState
	}
	next, err := sealTransportSetupPayload(newRoot, b, plain)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(source)
	return &TransportRootTransition{PreviousDigest: bytes.Clone(digest[:]), Next: next}, nil
}

func (t TrustRootTransition) transportAuthenticates(root []byte, b TrustBinding) bool {
	if t.Transport == nil {
		return true
	}
	plain, err := openTransportSetupPayload(root, b, t.Transport.Next)
	if err != nil {
		return false
	}
	defer vault.Wipe(plain)
	return transportPayloadCanonical(plain)
}

// PrepareTrustRootTransitionWithSetup authenticates and rewraps exact setup bytes
// without connecting, changing hosts or accepting new TLS state. The complete
// transition must be durably staged before a remote password change is sent.
func PrepareTrustRootTransitionWithSetup(oldRoot, newRoot []byte, b TrustBinding, previousRaw, setupRaw []byte, expectedRevision uint64) (TrustRootTransition, []byte, error) {
	record, _, err := PrepareTrustRootTransition(oldRoot, newRoot, b, previousRaw, expectedRevision)
	if err != nil {
		return TrustRootTransition{}, nil, err
	}
	record.Transport, err = prepareTransportRootTransition(oldRoot, newRoot, b, setupRaw)
	if err != nil {
		return TrustRootTransition{}, nil, err
	}
	record.FormatVersion = 2
	raw, err := SealTrustRootTransition(newRoot, b, record)
	if err != nil {
		return TrustRootTransition{}, nil, err
	}
	return record, raw, nil
}

// TransportCiphertext returns a separately authenticated snapshot for publication
// or new-root-only recovery. The caller still needs remote outcome proof before
// replacing the old setup. Mutating this result cannot mutate the journal.
func (t TrustRootTransition) TransportCiphertext(root []byte, b TrustBinding) ([]byte, error) {
	if !t.valid(b) || !t.transportAuthenticates(root, b) {
		return nil, ErrTrustState
	}
	if t.Transport == nil {
		return nil, nil
	}
	return bytes.Clone(t.Transport.Next), nil
}
