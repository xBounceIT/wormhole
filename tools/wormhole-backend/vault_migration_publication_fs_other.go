//go:build !windows

package main

import "os"

func renameLegacyPublicationRootFile(root *os.Root, from, to string, replace bool) error {
	if !legacyPublicationFilename(from) || !legacyPublicationFilename(to) {
		return errVaultSlotStorage
	}
	if replace {
		return root.Rename(from, to)
	}
	if err := root.Link(from, to); err != nil {
		return err
	}
	return root.Remove(from)
}

func syncLegacyPublicationRoot(root *os.Root) error {
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
