//go:build !windows

package main

import "os"

func publishVaultFile(source, target string) error {
	// Linking within one directory atomically fails if target already exists.
	// If unlinking fails, startup authenticates the target before removing stage.
	if err := os.Link(source, target); err != nil {
		return err
	}
	return os.Remove(source)
}
