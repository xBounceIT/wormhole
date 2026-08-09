//go:build darwin && !cgo

package main

import "errors"

func storeCredentialSecret(string, string) (string, string, error) {
	return "", "", errors.New("the macOS Keychain requires a compatible Wormhole build")
}

func unprotectPlatformCredentialSecret(string, string, string) ([]byte, error) {
	return nil, errUnsupportedSecretEncoding
}

func deleteStoredCredentialSecret(string, string, string) error {
	return nil
}
