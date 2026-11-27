//go:build !windows && (!darwin || !cgo)

package main

func platformProtectedKeyring() protectedKeyringAdapter { return legacyProtectedKeyring() }
