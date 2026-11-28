//go:build windows

package main

// The existing MoveFileEx adapter omits REPLACE_EXISTING and requests
// WRITE_THROUGH. Both names are newly owned children of the same install root.
func publishVaultExtensionDirectory(source, target string) error {
	return publishVaultFile(source, target)
}
