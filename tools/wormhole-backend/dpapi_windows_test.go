//go:build windows

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDecryptElectronSafeStoragePayload(t *testing.T) {
	const expected = "legacy-safe-storage-secret"
	key := []byte("01234567890123456789012345678901")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("123456789012")
	envelope := append([]byte(electronSafeStoragePrefix), nonce...)
	envelope = append(envelope, gcm.Seal(nil, nonce, []byte(expected), nil)...)
	encoded := base64.StdEncoding.EncodeToString(envelope)

	actual, err := decryptElectronSafeStoragePayload(encoded, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != expected {
		t.Fatalf("unexpected decrypted secret: %q", actual)
	}
}

func TestUnprotectStoredSecretReadsElectronSafeStorageKey(t *testing.T) {
	const expected = "legacy-safe-storage-secret"
	key := []byte("01234567890123456789012345678901")
	protectedKey, err := protectDpapi(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	encodedKey := base64.StdEncoding.EncodeToString(append([]byte(electronSafeStorageKeyHeader), protectedKey...))
	state, err := json.Marshal(map[string]any{
		"os_crypt": map[string]string{"encrypted_key": encodedKey},
	})
	if err != nil {
		t.Fatal(err)
	}
	userDataPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(userDataPath, "Local State"), state, 0o600); err != nil {
		t.Fatal(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("123456789012")
	envelope := append([]byte(electronSafeStoragePrefix), nonce...)
	envelope = append(envelope, gcm.Seal(nil, nonce, []byte(expected), nil)...)
	encoded := base64.StdEncoding.EncodeToString(envelope)

	actual, err := unprotectStoredSecret("credential-id", encoded, electronSafeStorageSecretEncoding, userDataPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != expected {
		t.Fatalf("unexpected decrypted secret: %q", actual)
	}
}
