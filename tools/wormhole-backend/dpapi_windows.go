//go:build windows

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

const protectedSecretEncoding = "windows-dpapi-v1"

const (
	electronSafeStorageKeyHeader = "DPAPI"
	electronSafeStorageKeyLength = 32
	electronSafeStorageNonceSize = 12
	electronLocalStateMaxBytes   = 4 * 1024 * 1024
)

var appAuthenticationEntropy = []byte("Wormhole.AppAuthentication.v1")

type dataBlob struct {
	cbData uint32
	pbData *byte
}

var (
	crypt32            = syscall.NewLazyDLL("crypt32.dll")
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	cryptProtectData   = crypt32.NewProc("CryptProtectData")
	cryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	localFree          = kernel32.NewProc("LocalFree")
)

func protectSecret(value string) (string, error) {
	protected, err := protectDpapi([]byte(value), nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(protected), nil
}

func protectAuthDocument(plaintext []byte) ([]byte, error) {
	return protectDpapi(plaintext, appAuthenticationEntropy)
}

func unprotectAuthDocument(protected []byte) ([]byte, error) {
	if len(protected) == 0 {
		return nil, errors.New("Windows DPAPI returned an invalid protected value")
	}
	return unprotectDpapi(protected, appAuthenticationEntropy)
}

func protectDpapi(value, entropy []byte) ([]byte, error) {
	inputBytes := value
	if len(inputBytes) == 0 {
		// CryptProtectData rejects a nil pointer even when cbData is zero. Keep a stable one-byte
		// backing store while still reporting an empty payload to DPAPI.
		inputBytes = []byte{0}
	}
	input := dataBlob{cbData: uint32(len(value)), pbData: &inputBytes[0]}
	var entropyBlob *dataBlob
	if len(entropy) > 0 {
		entropyBlob = &dataBlob{cbData: uint32(len(entropy)), pbData: &entropy[0]}
	}
	var output dataBlob
	result, _, callErr := cryptProtectData.Call(
		uintptr(unsafe.Pointer(&input)),
		uintptr(unsafe.Pointer(entropyBlob)),
		0,
		0,
		0,
		0x1, // CRYPTPROTECT_UI_FORBIDDEN
		uintptr(unsafe.Pointer(&output)),
	)
	if result == 0 {
		if callErr != syscall.Errno(0) {
			return nil, fmt.Errorf("Windows DPAPI failed: %w", callErr)
		}
		return nil, errors.New("Windows DPAPI failed")
	}
	if output.pbData == nil || output.cbData == 0 {
		return nil, errors.New("Windows DPAPI returned an empty value")
	}
	defer localFree.Call(uintptr(unsafe.Pointer(output.pbData)))
	protected := unsafe.Slice(output.pbData, output.cbData)
	return append([]byte(nil), protected...), nil
}

func unprotectDpapi(protected, entropy []byte) ([]byte, error) {
	if len(protected) == 0 {
		return nil, errors.New("Windows DPAPI returned an invalid protected value")
	}

	input := dataBlob{cbData: uint32(len(protected)), pbData: &protected[0]}
	var entropyBlob *dataBlob
	if len(entropy) > 0 {
		entropyBlob = &dataBlob{cbData: uint32(len(entropy)), pbData: &entropy[0]}
	}
	var output dataBlob
	result, _, callErr := cryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&input)),
		uintptr(unsafe.Pointer(entropyBlob)),
		0,
		0,
		0,
		0x1, // CRYPTPROTECT_UI_FORBIDDEN
		uintptr(unsafe.Pointer(&output)),
	)
	if result == 0 {
		if callErr != syscall.Errno(0) {
			return nil, fmt.Errorf("Windows DPAPI failed: %w", callErr)
		}
		return nil, errors.New("Windows DPAPI failed")
	}
	if output.pbData == nil {
		return nil, errors.New("Windows DPAPI returned an empty value")
	}
	defer localFree.Call(uintptr(unsafe.Pointer(output.pbData)))
	return append([]byte(nil), unsafe.Slice(output.pbData, output.cbData)...), nil
}

func unprotectSecret(encoded string) ([]byte, error) {
	protected, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("stored secret is not valid base64")
	}
	if len(protected) == 0 {
		return nil, errors.New("stored secret is empty")
	}

	input := dataBlob{cbData: uint32(len(protected)), pbData: &protected[0]}
	var output dataBlob
	result, _, callErr := cryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&input)),
		0,
		0,
		0,
		0,
		0x1, // CRYPTPROTECT_UI_FORBIDDEN
		uintptr(unsafe.Pointer(&output)),
	)
	if result == 0 {
		if callErr != syscall.Errno(0) {
			return nil, fmt.Errorf("Windows DPAPI failed: %w", callErr)
		}
		return nil, errors.New("Windows DPAPI failed")
	}
	if output.pbData == nil {
		return nil, errors.New("Windows DPAPI returned an empty value")
	}
	defer localFree.Call(uintptr(unsafe.Pointer(output.pbData)))
	return append([]byte(nil), unsafe.Slice(output.pbData, output.cbData)...), nil
}

func unprotectElectronSafeStorageSecret(encoded, userDataPath string) ([]byte, error) {
	key, err := readElectronSafeStorageKey(userDataPath)
	if err != nil {
		return nil, err
	}
	return decryptElectronSafeStoragePayload(encoded, key)
}

func readElectronSafeStorageKey(userDataPath string) ([]byte, error) {
	if userDataPath == "" {
		return nil, errors.New("Electron safe-storage user data path is missing")
	}
	localState, err := os.ReadFile(filepath.Join(userDataPath, "Local State"))
	if err != nil {
		return nil, errors.New("Electron safe-storage key is unavailable")
	}
	if len(localState) > electronLocalStateMaxBytes {
		return nil, errors.New("Electron safe-storage state is too large")
	}

	var document struct {
		OsCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(localState, &document); err != nil {
		return nil, errors.New("Electron safe-storage state is invalid")
	}
	encodedKey := document.OsCrypt.EncryptedKey
	keyEnvelope, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil || len(keyEnvelope) <= len(electronSafeStorageKeyHeader) ||
		string(keyEnvelope[:len(electronSafeStorageKeyHeader)]) != electronSafeStorageKeyHeader {
		return nil, errors.New("Electron safe-storage key has an invalid envelope")
	}

	key, err := unprotectDpapi(keyEnvelope[len(electronSafeStorageKeyHeader):], nil)
	if err != nil || len(key) != electronSafeStorageKeyLength {
		return nil, errors.New("Electron safe-storage key could not be decrypted")
	}
	return key, nil
}

func decryptElectronSafeStoragePayload(encoded string, key []byte) ([]byte, error) {
	protected, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("stored Electron safe-storage secret is not valid base64")
	}
	if len(key) != electronSafeStorageKeyLength {
		return nil, errors.New("Electron safe-storage key has an invalid length")
	}
	if len(protected) < len(electronSafeStoragePrefix)+electronSafeStorageNonceSize ||
		string(protected[:len(electronSafeStoragePrefix)]) != electronSafeStoragePrefix {
		return nil, errors.New("stored Electron safe-storage secret has an invalid envelope")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("Electron safe-storage cipher is unavailable")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || gcm.NonceSize() != electronSafeStorageNonceSize {
		return nil, errors.New("Electron safe-storage cipher is unavailable")
	}
	start := len(electronSafeStoragePrefix)
	nonce := protected[start : start+electronSafeStorageNonceSize]
	ciphertext := protected[start+electronSafeStorageNonceSize:]
	if len(ciphertext) < gcm.Overhead() {
		return nil, errors.New("stored Electron safe-storage secret has an invalid payload")
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("stored Electron safe-storage secret could not be decrypted")
	}
	return plaintext, nil
}

func unprotectFile(path string) ([]byte, error) {
	protected, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(protected) == 0 {
		return nil, errors.New("protected file is empty")
	}

	input := dataBlob{cbData: uint32(len(protected)), pbData: &protected[0]}
	var output dataBlob
	result, _, callErr := cryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&input)),
		0,
		0,
		0,
		0,
		0x1, // CRYPTPROTECT_UI_FORBIDDEN
		uintptr(unsafe.Pointer(&output)),
	)
	if result == 0 {
		if callErr != syscall.Errno(0) {
			return nil, fmt.Errorf("Windows DPAPI failed: %w", callErr)
		}
		return nil, errors.New("Windows DPAPI failed")
	}
	if output.pbData == nil {
		return nil, errors.New("Windows DPAPI returned an empty value")
	}
	defer localFree.Call(uintptr(unsafe.Pointer(output.pbData)))
	return append([]byte(nil), unsafe.Slice(output.pbData, output.cbData)...), nil
}
