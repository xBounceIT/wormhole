//go:build !windows

package main

import (
	"strings"
)

func protectBitwardenBrowserStorage(path string, plaintext []byte) error {
	return protectFile(path, plaintext)
}

func unprotectBitwardenBrowserStorage(path string) ([]byte, error) {
	protected, err := readBoundedRegularFile(path, bitwardenBrowserStorageMaxProtected)
	if err != nil {
		return nil, err
	}
	defer clearBytes(protected)
	return unprotectBitwardenBrowserStorageContents(path, protected)
}

func unprotectBitwardenBrowserStorageContents(path string, protected []byte) ([]byte, error) {
	// The recovery copy contains the primary ciphertext and uses the primary's keyring key.
	return unprotectFileContents(strings.TrimSuffix(path, ".bak"), protected)
}
