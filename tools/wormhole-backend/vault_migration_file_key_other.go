//go:build !windows

package main

func retireLegacyFileProtectionKey(path string, protected []byte) error {
	account := protectedFileKeyringAccount(path)
	load := func() ([]byte, error) {
		encoded, err := desktopProtectedKeys.load(fileKeyringService, account)
		defer clearBytes(encoded)
		if err != nil {
			return nil, err
		}
		return decodeAuthProtectionKey(encoded)
	}
	return retireLegacyFileKeyChecked(protected, load, func() error {
		return desktopProtectedKeys.remove(fileKeyringService, account)
	}, errProtectedKeyringNotFound)
}
