//go:build !windows && !darwin && !linux

package main

import "errors"

func storeCredentialSecret(string, string) (string, string, error) {
	return "", "", errors.New("a protected system credential store is unavailable on this platform")
}

func unprotectPlatformCredentialSecret(string, string, string) ([]byte, error) {
	return nil, errUnsupportedSecretEncoding
}

func deleteStoredCredentialSecret(string, string, string) error {
	return nil
}
