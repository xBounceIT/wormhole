package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/updateauth"
)

func TestVerifyReleasePublisher(t *testing.T) {
	dir := t.TempDir()
	if err := verify(nil); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("missing command arguments: %v", err)
	}
	var pin, ext string
	switch runtime.GOOS {
	case "windows":
		pin, ext = strings.Repeat("ab", 32), ".exe"
	case "darwin":
		pin, ext = "AB7CDEFGH9", ".dmg"
	default:
		if err := verify([]string{strings.Repeat("ab", 32), filepath.Join(dir, "setup.exe")}); err != updateauth.ErrPublisherUnavailable {
			t.Fatalf("unsupported publisher backend: %v", err)
		}
		return
	}
	unsigned := filepath.Join(dir, "unsigned"+ext)
	if err := os.WriteFile(unsigned, []byte("installer lacking a native signature"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verify([]string{pin, filepath.Join(dir, "text.txt")}); err == nil || !strings.Contains(err.Error(), "extension") {
		t.Fatalf("accepted a non-installer extension: %v", err)
	}
	if err := verify([]string{"invalid", unsigned}); err != updateauth.ErrPublisherUnavailable {
		t.Fatalf("invalid key: %v", err)
	}
	if err := verify([]string{pin, filepath.Join(dir, "missing", "file"+ext)}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing directory: %v", err)
	}
	if err := verify([]string{pin, filepath.Join(dir, "missing"+ext)}); err != updateauth.ErrArtifact {
		t.Fatalf("missing installer: %v", err)
	}
	if err := verify([]string{pin, unsigned}); err != updateauth.ErrPublisherUntrusted {
		t.Fatalf("unsigned installer: %v", err)
	}
}
