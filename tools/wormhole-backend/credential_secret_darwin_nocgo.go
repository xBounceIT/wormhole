//go:build darwin && !cgo

package main

import "errors"

func storeCredentialSecret(string, string) (string, string, error) {
	return "", "", errors.New("the macOS Keychain requires a cgo-enabled Wormhole backend")
}

func unprotectPlatformCredentialSecret(string, string, string) ([]byte, error) {
	return nil, errUnsupportedSecretEncoding
}

func deleteStoredCredentialSecret(string, string, string) error {
	return nil
}
