//go:build !windows && !linux && !darwin

package main

// These platforms still have vault operations that require dedicated native
// helpers before a no-child policy can be installed.
func enforceVaultChildProcessPolicy() bool { return true }
