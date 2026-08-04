//go:build !windows

package main

import "errors"

const protectedSecretEncoding = "windows-dpapi-v1"

func protectSecret(string) (string, error) {
	return "", errors.New("Windows DPAPI is unavailable on this platform")
}
