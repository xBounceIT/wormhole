package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/updateauth"
)

func TestSignRelease(t *testing.T) {
	const tag = "v4.5.6"
	dir := t.TempDir()
	m, err := updateauth.NewManifest(tag)
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{17}, ed25519.SeedSize)
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	seedHex, pin := hex.EncodeToString(seed), hex.EncodeToString(public)
	otherPin := hex.EncodeToString(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{19}, ed25519.SeedSize)).Public().(ed25519.PublicKey))
	path := filepath.Join(dir, updateauth.ManifestName)

	for _, c := range []struct{ tag, dir, pin, seed, message string }{
		{"main", dir, pin, seedHex, "manifest is invalid"},
		{tag, dir, "not a pin", seedHex, "invalid update manifest public key"},
		{tag, dir, pin, "", "signature is invalid"},
		{tag, dir, pin, strings.Repeat("z", 64), "signature is invalid"},
		{tag, dir, pin, seedHex + "   trailing", "signature is invalid"},
		{tag, dir, otherPin, seedHex, "does not match the build pin"},
		{tag, filepath.Join(dir, "missing"), pin, seedHex, "missing"},
		{tag, dir, pin, seedHex, "installer is invalid"},
	} {
		err := signRelease(c.tag, c.dir, c.pin, strings.NewReader(c.seed))
		if err == nil || !strings.Contains(err.Error(), c.message) || strings.Contains(err.Error(), seedHex) {
			t.Fatalf("unexpected signer error: %v, want %q", err, c.message)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("manifest exists after a failure: %v", err)
		}
	}
	if err := signRelease(tag, dir, pin, iotest.ErrReader(errors.New("stdin unavailable"))); !errors.Is(err, updateauth.ErrSignature) {
		t.Fatalf("unexpected stdin failure: %v", err)
	}

	for _, artifact := range m.Artifacts {
		if err := os.WriteFile(filepath.Join(dir, artifact.Name), []byte(artifact.Name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := signRelease(tag, dir, pin, strings.NewReader(seedHex+"\r\n")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(seedHex)) {
		t.Fatal("manifest contains the signing seed")
	}
	got, err := updateauth.Verify(raw, public)
	if err != nil || got.ReleaseTag != tag {
		t.Fatalf("unexpected manifest: %+v, %v", got, err)
	}
	for _, artifact := range got.Artifacts {
		sha := sha256.Sum256([]byte(artifact.Name))
		if artifact.Size != int64(len(artifact.Name)) || artifact.SHA256 != hex.EncodeToString(sha[:]) {
			t.Errorf("incorrect digest for %s", artifact.Name)
		}
	}
	if err := signRelease(tag, dir, pin, strings.NewReader(seedHex)); !errors.Is(err, os.ErrExist) {
		t.Fatalf("unexpected result overwriting the manifest: %v", err)
	}
}
