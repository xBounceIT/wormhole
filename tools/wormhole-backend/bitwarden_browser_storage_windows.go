//go:build windows

package main

import "os"

var bitwardenBrowserStorageEntropy = []byte("Wormhole.BitwardenBrowser.SharedStorage.v1")

func protectBitwardenBrowserStorage(path string, plaintext []byte) error {
	protected, err := protectDpapi(plaintext, bitwardenBrowserStorageEntropy)
	if err != nil {
		return err
	}
	return writePrivateFileAtomic(path, protected)
}

func unprotectBitwardenBrowserStorage(path string) ([]byte, error) {
	protected, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return unprotectDpapi(protected, bitwardenBrowserStorageEntropy)
}
