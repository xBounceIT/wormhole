package vault

import (
	"bytes"
	"encoding/json"
	"math"

	"github.com/google/uuid"
)

// The largest 4 MiB AES value is <6 MiB in canonical JSON/base64 form. The codec
// handles ciphertext only; plaintext never enters a JSON string here.
const MaxSharedEnvelopeBytes = 6 * 1024 * 1024

func validateSharedEnvelope(e Envelope) error {
	if e.FormatVersion > FormatVersion {
		return ErrNewerFormat
	}
	id, err := uuid.Parse(e.KeyID)
	if err != nil || id == uuid.Nil || id.String() != e.KeyID || e.KeyVersion == 0 || e.KeyVersion > math.MaxInt32 {
		return ErrFormat
	}
	return validateEnvelope(Binding{KeyID: e.KeyID, KeyVersion: e.KeyVersion}, e)
}
func EncodeSharedEnvelope(e Envelope) ([]byte, error) {
	if err := validateSharedEnvelope(e); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(e)
	if err != nil || len(raw) > MaxSharedEnvelopeBytes {
		return nil, ErrFormat
	}
	return raw, nil
}

// DecodeSharedEnvelope checks bounded canonical ciphertext encoding, not AEAD
// authentication or permission. The expected binding is supplied at OpenSharedValue.
func DecodeSharedEnvelope(raw []byte) (Envelope, error) {
	if len(raw) == 0 || len(raw) > MaxSharedEnvelopeBytes {
		return Envelope{}, ErrFormat
	}
	var e Envelope
	if json.Unmarshal(raw, &e) != nil {
		return Envelope{}, ErrFormat
	}
	canonical, err := EncodeSharedEnvelope(e)
	if err != nil {
		return Envelope{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return Envelope{}, ErrFormat
	}
	return e, nil
}
