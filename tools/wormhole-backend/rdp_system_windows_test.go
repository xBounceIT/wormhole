package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestSystemRdpClientUsesWindowsSystemDirectory(t *testing.T) {
	pathDirectory := t.TempDir()
	if err := os.WriteFile(filepath.Join(pathDirectory, "mstsc.exe"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", pathDirectory)
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(systemDirectory, "mstsc.exe")
	info, statErr := os.Stat(want)
	got, err := systemRdpClientExecutable()
	switch {
	case errors.Is(statErr, os.ErrNotExist) || (statErr == nil && info.IsDir()):
		if err == nil || got != "" {
			t.Fatalf("missing system client resolved to %q, %v", got, err)
		}
	case statErr != nil:
		t.Fatal(statErr)
	case err != nil || got != want:
		t.Fatalf("resolved client = %q, %v; want %q", got, err, want)
	}
}
