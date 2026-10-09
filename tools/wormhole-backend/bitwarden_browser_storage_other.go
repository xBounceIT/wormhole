//go:build !windows

package main

import (
	"os"
	"strings"
)

func protectBitwardenBrowserStorage(path string, plaintext []byte) error {
	return protectFile(path, plaintext)
}

func unprotectBitwardenBrowserStorage(path string) ([]byte, error) {
	protected, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clearBytes(protected)
	// The recovery copy contains the primary ciphertext and uses the primary's keyring key.
	return unprotectFileContents(strings.TrimSuffix(path, ".bak"), protected)
}
