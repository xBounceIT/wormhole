package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/updateauth"
)

func TestInstallationCommandsMeasureSignAndVerify(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	root := filepath.Join(base, "Wormhole.app")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "runner"), []byte("packaged application"), 0600); err != nil {
		t.Fatal(err)
	}
	const release, target = "v2.4.3", "darwin/universal"
	var output bytes.Buffer
	if err := runManifestCommand(ctx, []string{"inventory-installation", release, target, root}, strings.NewReader(""), &output); err != nil {
		t.Fatal(err)
	}
	inventory := filepath.Join(base, "inventory.json")
	if err := os.WriteFile(inventory, output.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	seed := bytes.Repeat([]byte{11}, ed25519.SeedSize)
	key := ed25519.NewKeyFromSeed(seed)
	pin := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	encoded := hex.EncodeToString(seed)
	for _, mismatch := range [][]string{
		{"sign-installation", "v2.4.4", target, inventory, pin},
		{"sign-installation", release, "windows/x64", inventory, pin},
	} {
		if err := runManifestCommand(ctx, mismatch, strings.NewReader(encoded), &output); !errors.Is(err, updateauth.ErrManifest) || output.Len() != 0 {
			t.Fatal("signed an unexpected build identity", err)
		}
	}
	args := []string{"sign-installation", release, target, inventory, pin}
	if err := runManifestCommand(ctx, args, strings.NewReader(encoded+"\n"), &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), encoded) {
		t.Fatal("signing seed leaked")
	}
	if err := os.WriteFile(root+updateauth.InstallationProofSuffix, output.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runManifestCommand(ctx, []string{"verify-installation", target, root, pin}, strings.NewReader(""), io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, tooShort := range [][]string{{}, {"inventory-installation"}, {"sign-installation"}, {"verify-installation"}, {"unknown"}} {
		if err := runManifestCommand(ctx, tooShort, strings.NewReader(""), io.Discard); !errors.Is(err, errManifestUsage) {
			t.Fatal("invalid invocation accepted", err)
		}
	}
}

func TestSignSystemManifestRequiresAllPackagedFormats(t *testing.T) {
	dir := t.TempDir()
	seed := bytes.Repeat([]byte{22}, ed25519.SeedSize)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	args := []string{"sign-system-manifest", "v1.2.3", dir, hex.EncodeToString(pub)}
	run := func() error {
		return runManifestCommand(context.Background(), args, strings.NewReader(hex.EncodeToString(seed)), io.Discard)
	}
	m, err := updateauth.NewSystemManifest(args[1])
	if err != nil {
		t.Fatal(err)
	}
	for i, asset := range m.Artifacts {
		if i == len(m.Artifacts)-1 {
			if err := run(); !errors.Is(err, updateauth.ErrArtifact) {
				t.Fatal("missing RPM accepted", err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, asset.Name), []byte(asset.Name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, updateauth.SystemManifestName))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := updateauth.Verify(raw, pub)
	if err != nil || signed.FormatVersion != 2 {
		t.Fatal(signed, err)
	}
	if _, err := os.Stat(filepath.Join(dir, updateauth.ManifestName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("system signing replaced public manifest", err)
	}
}
