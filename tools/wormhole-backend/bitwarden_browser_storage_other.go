//go:build !windows

package main

func protectBitwardenBrowserStorage(path string, plaintext []byte) error {
	return protectFile(path, plaintext)
}

func unprotectBitwardenBrowserStorage(path string) ([]byte, error) {
	return unprotectFile(path)
}
