//go:build windows

package main

// DPAPI's OS master key is not a Wormhole-owned per-file key and must not be
// deleted. The coordinator removes the exact inventoried protected file.
func retireLegacyFileProtectionKey(string, []byte) error { return nil }
