package vault

import (
	"encoding/binary"
)

const MaxVNCManualCiphertext = 6 + MaxVNCPasswordBytes + 16

// The isolated password document seals only to the native protocol recipient.
// Its independent purpose binds both the destination and the exact route; the
// vault subsequently wraps this opaque envelope as a manual authorization.
func manualVNCInfo(b BundleBinding, route *TunnelBundleBinding, endpoint string) ([]byte, error) {
	return manualCredentialInfo(b, route, endpoint, "vnc", "wormhole/v1/vnc-manual-password")
}

func SealManualVNCPassword(public []byte, b BundleBinding, route *TunnelBundleBinding, endpoint string, password []byte) (SealedBundle, error) {
	info, err := manualVNCInfo(b, route, endpoint)
	if err != nil {
		return SealedBundle{}, err
	}
	raw, err := EncodeVNCBundle(VNCBundlePayload{Password: password, PasswordProvided: true})
	if err != nil {
		return SealedBundle{}, err
	}
	defer Wipe(raw)
	return sealBundlePayload(public, info, raw)
}
func OpenManualVNCPassword(private []byte, b BundleBinding, route *TunnelBundleBinding, endpoint string, sealed SealedBundle) ([]byte, error) {
	if err := validVNCManualEnvelope(sealed); err != nil {
		return nil, err
	}
	info, err := manualVNCInfo(b, route, endpoint)
	if err != nil {
		return nil, err
	}
	raw, err := openBundlePayload(private, info, sealed)
	if err != nil {
		return nil, err
	}
	payload, err := DecodeVNCBundle(raw)
	if err != nil || !payload.PasswordProvided {
		Wipe(raw)
		return nil, ErrFormat
	}
	return raw, nil
}
func validVNCManualEnvelope(sealed SealedBundle) error {
	if err := validateSealedBundle(sealed); err != nil {
		return err
	}
	if len(sealed.Ciphertext) < 22 || len(sealed.Ciphertext) > MaxVNCManualCiphertext {
		return ErrFormat
	}
	return nil
}

// Version 2 is deliberately distinct from the saved-password frame (version 1).
// It contains ciphertext only: version, X25519 encapsulation, uint32 length,
// ciphertext. Native manual-only recipients reject saved-password frames.
func EncodeVNCManualAuthorization(inner SealedBundle) ([]byte, error) {
	if err := validVNCManualEnvelope(inner); err != nil {
		return nil, err
	}
	raw := make([]byte, 37+len(inner.Ciphertext))
	raw[0] = 2
	copy(raw[1:33], inner.Enc)
	binary.BigEndian.PutUint32(raw[33:37], uint32(len(inner.Ciphertext)))
	copy(raw[37:], inner.Ciphertext)
	return raw, nil
}

// The decoded envelope borrows raw. The owner must wipe it after the open attempt.
func DecodeVNCManualAuthorization(raw []byte) (SealedBundle, error) {
	if len(raw) < 59 || len(raw) > 37+MaxVNCManualCiphertext || raw[0] != 2 || uint64(binary.BigEndian.Uint32(raw[33:37])) != uint64(len(raw)-37) {
		return SealedBundle{}, ErrFormat
	}
	return SealedBundle{FormatVersion: FormatVersion, SuiteID: SuiteX25519HKDFSHA256AES256GCM, Enc: raw[1:33], Ciphertext: raw[37:]}, nil
}
