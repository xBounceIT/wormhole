//go:build !windows

package main

import (
	"errors"
)

const protectedSecretEncoding = "windows-dpapi-v1"

func protectSecret(string) (string, error) {
	return "", errors.New("Windows DPAPI is unavailable on this platform")
}

func unprotectSecret(string) ([]byte, error) {
	return nil, errors.New("Windows DPAPI is unavailable on this platform")
}

func unprotectElectronSafeStorageSecret(string, string) ([]byte, error) {
	return nil, errors.New("Windows DPAPI is unavailable on this platform")
}

func unprotectFile(string) ([]byte, error) {
	return nil, errors.New("Windows DPAPI is unavailable on this platform")
}

func protectAuthDocument([]byte) ([]byte, error) {
	return nil, errors.New("Windows DPAPI is unavailable on this platform")
}

func unprotectAuthDocument([]byte) ([]byte, error) {
	return nil, errors.New("Windows DPAPI is unavailable on this platform")
}
