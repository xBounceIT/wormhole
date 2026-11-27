package vault

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
)

const MaxUserKeyStateBytes = 4096

// Encoding/decoding validates structure only, never the organisation signature.
func EncodeUserKeyState(state UserKeyState) ([]byte, error) {
	if _, err := state.signingBytes(); err != nil {
		return nil, err
	}
	if len(state.Signature) != ed25519.SignatureSize {
		return nil, ErrFormat
	}
	raw, err := json.Marshal(state)
	if err != nil || len(raw) > MaxUserKeyStateBytes {
		return nil, ErrFormat
	}
	return raw, nil
}

func DecodeUserKeyState(raw []byte) (UserKeyState, error) {
	if len(raw) == 0 || len(raw) > MaxUserKeyStateBytes {
		return UserKeyState{}, ErrFormat
	}
	var state UserKeyState
	if json.Unmarshal(raw, &state) != nil {
		return UserKeyState{}, ErrFormat
	}
	canonical, err := EncodeUserKeyState(state)
	if err != nil {
		return UserKeyState{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return UserKeyState{}, ErrFormat
	}
	return state, nil
}
