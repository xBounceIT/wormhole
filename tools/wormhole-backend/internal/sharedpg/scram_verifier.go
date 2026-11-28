package sharedpg

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"golang.org/x/crypto/pbkdf2"
)

const SCRAMIterations = 4096
const MaxSCRAMVerifierBytes = 256

var ErrSCRAMVerifier = errors.New("invalid shared PostgreSQL SCRAM verifier")

// EncodeLoginSecret converts 256-bit HKDF login material to PostgreSQL's ASCII
// password input. It accepts neither a Wormhole password nor an arbitrary string.
// The caller owns and must wipe the result; the input is borrowed.
func EncodeLoginSecret(derived []byte) ([]byte, error) {
	if len(derived) != 32 {
		return nil, ErrSCRAMVerifier
	}
	return base64.RawURLEncoding.AppendEncode(nil, derived), nil
}

// NewSCRAMVerifier prepares a PostgreSQL SCRAM-SHA-256 verifier locally from the
// derived login material, with a fresh 32-byte salt. It never sends a password.
// Treat the returned verifier as a credential: do not log it, and wipe after use.
func NewSCRAMVerifier(derived []byte) ([]byte, error) {
	login, err := EncodeLoginSecret(derived)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(login)
	salt := make([]byte, 32)
	rand.Read(salt)
	return buildSCRAMVerifier(login, salt), nil
}

func buildSCRAMVerifier(login, salt []byte) []byte {
	salted := pbkdf2.Key(login, salt, SCRAMIterations, 32, sha256.New)
	defer vault.Wipe(salted)
	h := hmac.New(sha256.New, salted)
	_, _ = h.Write([]byte("Client Key"))
	client := h.Sum(nil)
	defer vault.Wipe(client)
	stored := sha256.Sum256(client)
	defer vault.Wipe(stored[:])
	h.Reset()
	_, _ = h.Write([]byte("Server Key"))
	server := h.Sum(nil)
	defer vault.Wipe(server)
	out := make([]byte, 0, 160)
	out = append(out, "SCRAM-SHA-256$4096:"...)
	out = base64.StdEncoding.AppendEncode(out, salt)
	out = append(out, '$')
	out = base64.StdEncoding.AppendEncode(out, stored[:])
	out = append(out, ':')
	out = base64.StdEncoding.AppendEncode(out, server)
	return out
}

// ValidateSCRAMVerifier accepts a bounded canonical PostgreSQL verifier, with
// 4096..1000000 iterations, 16..64 salt bytes and two 32-byte keys. It validates
// syntax/cost only, not knowledge of the credential or authorization to change it.
func ValidateSCRAMVerifier(verifier []byte) error {
	const prefix = "SCRAM-SHA-256$"
	if len(verifier) > MaxSCRAMVerifierBytes || !bytes.HasPrefix(verifier, []byte(prefix)) {
		return ErrSCRAMVerifier
	}
	parameters, keys, ok := bytes.Cut(verifier[len(prefix):], []byte("$"))
	if !ok {
		return ErrSCRAMVerifier
	}
	iterations, salt, ok := bytes.Cut(parameters, []byte(":"))
	if !ok || len(iterations) == 0 || len(iterations) > 7 || iterations[0] == '0' {
		return ErrSCRAMVerifier
	}
	cost := 0
	for _, digit := range iterations {
		if digit < '0' || digit > '9' {
			return ErrSCRAMVerifier
		}
		cost = cost*10 + int(digit-'0')
	}
	if cost < SCRAMIterations || cost > 1000000 {
		return ErrSCRAMVerifier
	}
	stored, server, ok := bytes.Cut(keys, []byte(":"))
	if !ok {
		return ErrSCRAMVerifier
	}
	if !canonicalSCRAMBase64(salt, 16, 64) || !canonicalSCRAMBase64(stored, 32, 32) || !canonicalSCRAMBase64(server, 32, 32) {
		return ErrSCRAMVerifier
	}
	return nil
}

func canonicalSCRAMBase64(raw []byte, min, max int) bool {
	if len(raw) > base64.StdEncoding.EncodedLen(max) {
		return false
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(raw)))
	defer vault.Wipe(decoded)
	n, err := base64.StdEncoding.Strict().Decode(decoded, raw)
	if err != nil || n < min || n > max {
		return false
	}
	canonical := base64.StdEncoding.AppendEncode(nil, decoded[:n])
	defer vault.Wipe(canonical)
	return bytes.Equal(raw, canonical)
}
