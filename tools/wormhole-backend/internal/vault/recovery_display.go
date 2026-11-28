package vault

import (
	"crypto/ecdh"
	"crypto/hpke"

	"github.com/google/uuid"
)

// Recovery display is a separate HPKE domain from protocol credentials. Only
// the dedicated, content-protected dialog owns the one-use recipient key.
// Main relays ciphertext; neither a protocol child nor another enrollment can
// open it. The caller wipes the formatted code after handing off the result.
func recoveryDisplayInfo(workspace, enrollment string) ([]byte, error) {
	for _, id := range []string{workspace, enrollment} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id {
			return nil, ErrFormat
		}
	}
	return canonical("wormhole/v1/recovery-display", []byte(workspace), []byte(enrollment)), nil
}

func SealRecoveryDisplay(publicKey []byte, workspace, enrollment string, code []byte) (SealedBundle, error) {
	info, err := recoveryDisplayInfo(workspace, enrollment)
	if err != nil {
		return SealedBundle{}, err
	}
	key, err := ParseRecoveryKey(code)
	Wipe(key)
	if err != nil {
		return SealedBundle{}, err
	}
	pub, err := ecdh.X25519().NewPublicKey(publicKey)
	if err != nil {
		return SealedBundle{}, ErrFormat
	}
	recipient, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return SealedBundle{}, ErrFormat
	}
	enc, sender, err := hpke.NewSender(recipient, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		return SealedBundle{}, ErrAuthentication
	}
	ciphertext, err := sender.Seal(nil, code)
	if err != nil {
		return SealedBundle{}, ErrAuthentication
	}
	return SealedBundle{FormatVersion, SuiteX25519HKDFSHA256AES256GCM, enc, ciphertext}, nil
}
