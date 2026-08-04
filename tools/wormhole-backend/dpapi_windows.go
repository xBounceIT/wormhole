//go:build windows

package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

const protectedSecretEncoding = "windows-dpapi-v1"

type dataBlob struct {
	cbData uint32
	pbData *byte
}

var (
	crypt32          = syscall.NewLazyDLL("crypt32.dll")
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	cryptProtectData = crypt32.NewProc("CryptProtectData")
	localFree        = kernel32.NewProc("LocalFree")
)

func protectSecret(value string) (string, error) {
	inputBytes := []byte(value)
	if len(inputBytes) == 0 {
		// CryptProtectData rejects a nil pointer even when cbData is zero. Keep a stable one-byte
		// backing store while still reporting an empty payload to DPAPI.
		inputBytes = []byte{0}
	}
	input := dataBlob{cbData: uint32(len(value)), pbData: &inputBytes[0]}
	var output dataBlob
	result, _, callErr := cryptProtectData.Call(
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
			return "", fmt.Errorf("Windows DPAPI failed: %w", callErr)
		}
		return "", errors.New("Windows DPAPI failed")
	}
	if output.pbData == nil || output.cbData == 0 {
		return "", errors.New("Windows DPAPI returned an empty value")
	}
	defer localFree.Call(uintptr(unsafe.Pointer(output.pbData)))
	protected := unsafe.Slice(output.pbData, output.cbData)
	return base64.StdEncoding.EncodeToString(protected), nil
}
