//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsDurableMoveRetriesOnlyAccessAndSharingErrors(t *testing.T) {
	for _, tt := range []struct {
		name     string
		outcomes []error
		want     error
		calls    int
	}{
		{"transient", []error{windows.ERROR_ACCESS_DENIED, windows.ERROR_SHARING_VIOLATION, nil}, nil, 3},
		{"permanent", []error{windows.ERROR_ACCESS_DENIED}, windows.ERROR_ACCESS_DENIED, 6},
		{"target exists", []error{windows.ERROR_ALREADY_EXISTS}, windows.ERROR_ALREADY_EXISTS, 1},
		{"source lost", []error{windows.ERROR_SHARING_VIOLATION, windows.ERROR_FILE_NOT_FOUND}, windows.ERROR_FILE_NOT_FOUND, 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			err := retryWindowsFileMove(func() error {
				result := tt.outcomes[min(calls, len(tt.outcomes)-1)]
				calls++
				return result
			})
			if calls != tt.calls || !errors.Is(err, tt.want) {
				t.Fatalf("rename attempts = %d, result = %v", calls, err)
			}
		})
	}
}

func TestWindowsDurableMoveRespectsDestinationOwnership(t *testing.T) {
	directory := t.TempDir()
	source, target := filepath.Join(directory, "prepared"), filepath.Join(directory, "selected")
	if err := os.WriteFile(source, []byte("prepared"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := publishVaultFile(source, target); err == nil {
		t.Fatal("exclusive publication accepted a competing destination")
	}
	if raw, err := os.ReadFile(target); err != nil || string(raw) != "existing" {
		t.Fatal("exclusive publication replaced a competing destination", err)
	}
	for _, paths := range [][2]string{{source + "\x00", target}, {source, target + "\x00"}} {
		if err := replaceFileWithWriteThrough(paths[0], paths[1]); err == nil {
			t.Fatal("invalid path reached the durable writer")
		}
	}
	if err := replaceFileWithWriteThrough(source, target); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(target); err != nil || string(raw) != "prepared" {
		t.Fatal("durable replacement did not publish the prepared file", err)
	}
	if _, err := os.Stat(source); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("durable replacement left the original staging path", err)
	}
}
