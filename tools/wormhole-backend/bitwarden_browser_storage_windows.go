//go:build windows

package main

var bitwardenBrowserStorageEntropy = []byte("Wormhole.BitwardenBrowser.SharedStorage.v1")

func protectBitwardenBrowserStorage(path string, plaintext []byte) error {
	protected, err := protectDpapi(plaintext, bitwardenBrowserStorageEntropy)
	if err != nil {
		return err
	}
	return writePrivateFileAtomic(path, protected)
}

func unprotectBitwardenBrowserStorage(path string) ([]byte, error) {
	protected, err := readBoundedRegularFile(path, bitwardenBrowserStorageMaxProtected)
	if err != nil {
		return nil, err
	}
	defer clearBytes(protected)
	return unprotectBitwardenBrowserStorageContents(path, protected)
}

func unprotectBitwardenBrowserStorageContents(_ string, protected []byte) ([]byte, error) {
	return unprotectDpapiWithLegacyEntropy(protected, bitwardenBrowserStorageEntropy)
}
