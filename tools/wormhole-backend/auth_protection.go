package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

const (
	authProtectionKeyLength   = 32
	authProtectionNonceLength = 12
)

var authProtectionEnvelope = []byte("WormholeAuth\x01")

// encryptAuthDocument encrypts a verifier document using a key that is kept in the
// operating system's credential store. The document contains no secret itself, but
// treating it as protected data keeps its shape consistent with the DPAPI version.
func encryptAuthDocument(plaintext, key []byte) ([]byte, error) {
	if len(key) != authProtectionKeyLength {
		return nil, errors.New("authentication protection key has an invalid length")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("authentication cipher is unavailable")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || gcm.NonceSize() != authProtectionNonceLength {
		return nil, errors.New("authentication cipher is unavailable")
	}

	nonce := make([]byte, authProtectionNonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("cannot generate an authentication nonce")
	}
	defer clearBytes(nonce)

	protected := append([]byte(nil), authProtectionEnvelope...)
	protected = append(protected, nonce...)
	return gcm.Seal(protected, nonce, plaintext, authProtectionEnvelope), nil
}

func decryptAuthDocument(protected, key []byte) ([]byte, error) {
	if len(key) != authProtectionKeyLength {
		return nil, errors.New("authentication protection key has an invalid length")
	}
	minimumLength := len(authProtectionEnvelope) + authProtectionNonceLength
	if len(protected) < minimumLength ||
		string(protected[:len(authProtectionEnvelope)]) != string(authProtectionEnvelope) {
		return nil, errors.New("authentication store has an invalid envelope")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("authentication cipher is unavailable")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || gcm.NonceSize() != authProtectionNonceLength {
		return nil, errors.New("authentication cipher is unavailable")
	}
	nonce := protected[len(authProtectionEnvelope):minimumLength]
	ciphertext := protected[minimumLength:]
	if len(ciphertext) < gcm.Overhead() {
		return nil, errors.New("authentication store has an invalid payload")
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, authProtectionEnvelope)
	if err != nil {
		return nil, errors.New("authentication store could not be decrypted")
	}
	return plaintext, nil
}
