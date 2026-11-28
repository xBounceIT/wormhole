//go:build !windows

package main

import (
	"os"
	"testing"
)

func assertServerKitPrivateFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("server key is not restricted to its owner", err)
	}
}
