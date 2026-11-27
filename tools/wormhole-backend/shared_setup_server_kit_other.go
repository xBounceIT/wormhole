//go:build !windows && !linux && !darwin

package main

func isLocalServerKitCache(string) bool { return false }
