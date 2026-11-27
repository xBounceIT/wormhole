package vault

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
)

const MaxSignedPolicyBytes = 64 * 1024

// EncodeSignedPolicy produces the canonical stored document. It validates shape,
// not signature trust; callers authenticate with VerifyPolicy and a pinned key.
func EncodeSignedPolicy(p SignedPolicy) ([]byte, error) {
	if _, err := p.signingBytes(); err != nil {
		return nil, err
	}
	if len(p.Signature) != ed25519.SignatureSize {
		return nil, ErrFormat
	}
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > MaxSignedPolicyBytes {
		return nil, ErrFormat
	}
	return raw, nil
}

// DecodeSignedPolicy rejects unknown, missing, duplicate, case-folded and
// noncanonical fields before signature verification. No key is taken from JSON.
func DecodeSignedPolicy(raw []byte) (SignedPolicy, error) {
	if len(raw) == 0 || len(raw) > MaxSignedPolicyBytes {
		return SignedPolicy{}, ErrFormat
	}
	var p SignedPolicy
	if json.Unmarshal(raw, &p) != nil {
		return SignedPolicy{}, ErrFormat
	}
	canonical, err := EncodeSignedPolicy(p)
	if err != nil {
		return SignedPolicy{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return SignedPolicy{}, ErrFormat
	}
	return p, nil
}
