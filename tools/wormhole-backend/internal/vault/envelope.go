// Package vault defines the versioned cryptographic boundary for Wormhole.
// It does not read legacy secrets or enable protection of existing workspaces.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf8"
)

const (
	FormatVersion                  = 1
	SuiteAES256GCM                 = 1
	SuiteX25519HKDFSHA256AES256GCM = 2
	MaxSecretBytes                 = 4 * 1024 * 1024
	MaxContextBytes                = 1024
)

var (
	ErrFormat         = errors.New("vault_invalid_format")
	ErrNewerFormat    = errors.New("vault_newer_format")
	ErrAuthentication = errors.New("vault_authentication_failed")
	ErrPolicy         = errors.New("vault_policy_rejected")
	ErrRollback       = errors.New("vault_rollback_detected")
)

// Binding must come from the trusted resolver, never from the envelope being
// opened. Length-prefixing prevents ambiguities between adjacent AAD fields.
type Binding struct {
	WorkspaceID string `json:"workspaceId"`
	Table       string `json:"table"`
	OwnerID     string `json:"ownerId"`
	Field       string `json:"field"`
	KeyID       string `json:"keyId"`
	KeyVersion  uint32 `json:"keyVersion"`
}

type Envelope struct {
	FormatVersion uint16 `json:"formatVersion"`
	SuiteID       uint16 `json:"suiteId"`
	KeyID         string `json:"keyId"`
	KeyVersion    uint32 `json:"keyVersion"`
	Nonce         []byte `json:"nonce"`
	Ciphertext    []byte `json:"ciphertext"`
}

func canonical(domain string, fields ...[]byte) []byte {
	result := []byte(domain)
	for _, field := range fields {
		result = binary.BigEndian.AppendUint32(result, uint32(len(field)))
		result = append(result, field...)
	}
	return result
}

func validText(value string, maxBytes int, allowEmpty bool) bool {
	return (allowEmpty || len(value) > 0) && len(value) <= maxBytes && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

func (b Binding) aad() ([]byte, error) {
	fields := []string{b.WorkspaceID, b.Table, b.OwnerID, b.Field, b.KeyID}
	if b.KeyVersion == 0 {
		return nil, ErrFormat
	}
	var values [][]byte
	values = append(values, binary.BigEndian.AppendUint16(nil, FormatVersion), binary.BigEndian.AppendUint16(nil, SuiteAES256GCM))
	for _, field := range fields {
		if !validText(field, MaxContextBytes, false) {
			return nil, ErrFormat
		}
		values = append(values, []byte(field))
	}
	values = append(values, binary.BigEndian.AppendUint32(nil, b.KeyVersion))
	return canonical("wormhole/v1/envelope", values...), nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrFormat
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrFormat
	}
	return cipher.NewGCM(block)
}

func Seal(key []byte, binding Binding, plaintext []byte) (Envelope, error) {
	if len(plaintext) > MaxSecretBytes {
		return Envelope{}, ErrFormat
	}
	aad, err := binding.aad()
	if err != nil {
		return Envelope{}, err
	}
	aead, err := gcm(key)
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	return Envelope{FormatVersion, SuiteAES256GCM, binding.KeyID, binding.KeyVersion, nonce, aead.Seal(nil, nonce, plaintext, aad)}, nil
}

func validateEnvelope(binding Binding, envelope Envelope) error {
	if envelope.FormatVersion > FormatVersion {
		return ErrNewerFormat
	}
	if envelope.FormatVersion != FormatVersion || envelope.SuiteID != SuiteAES256GCM ||
		envelope.KeyID != binding.KeyID || envelope.KeyVersion != binding.KeyVersion ||
		len(envelope.Nonce) != 12 || len(envelope.Ciphertext) < 16 || len(envelope.Ciphertext) > MaxSecretBytes+16 {
		return ErrFormat
	}
	return nil
}

func Open(key []byte, binding Binding, envelope Envelope) ([]byte, error) {
	if err := validateEnvelope(binding, envelope); err != nil {
		return nil, err
	}
	aad, err := binding.aad()
	if err != nil {
		return nil, err
	}
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}
