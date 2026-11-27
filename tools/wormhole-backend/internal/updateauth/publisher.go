package updateauth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"runtime"
)

var (
	ErrPublisherUnavailable = errors.New("installer publisher verification is unavailable")
	ErrPublisherUntrusted   = errors.New("installer publisher signature could not be verified")
)

// PublisherPin is the SHA-256 digest of the end-entity signer's DER SPKI.
type PublisherPin [sha256.Size]byte

func ParsePublisherPin(value string) (PublisherPin, error) {
	var pin PublisherPin
	if !validHex(value, len(pin)) {
		return pin, ErrPublisherUnavailable
	}
	_, _ = hex.Decode(pin[:], []byte(value))
	if pin == (PublisherPin{}) {
		return pin, ErrPublisherUnavailable
	}
	return pin, nil
}

// ValidatePublisherIdentity validates the public identity for the current OS.
func ValidatePublisherIdentity(identity string) error {
	switch runtime.GOOS {
	case "windows":
		_, err := ParsePublisherPin(identity)
		return err
	case "darwin":
		return validateDarwinTeamID(identity)
	default:
		return ErrPublisherUnavailable
	}
}

// VerifyPublisher uses the platform trust service. The file must remain open
// until verification returns. Windows callers also hold a sharing lock.
func VerifyPublisher(file *os.File, identity string) error {
	switch runtime.GOOS {
	case "windows":
		pin, err := ParsePublisherPin(identity)
		if err != nil {
			return err
		}
		return VerifyWindowsPublisher(file, pin)
	case "darwin":
		return verifyDarwinPublisher(file, identity, runDarwinPublisherTool)
	default:
		return ErrPublisherUnavailable
	}
}
