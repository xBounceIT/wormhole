//go:build !windows && !linux && !darwin

package main

func publishVaultExtensionDirectory(string, string) error { return errVaultExtensionFiles }
