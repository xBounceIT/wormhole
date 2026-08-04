//go:build windows

package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const protectedSecretEncoding = "windows-dpapi-v1"

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
