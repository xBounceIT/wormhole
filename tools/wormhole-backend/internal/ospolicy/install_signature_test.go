package ospolicy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/updateauth"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestParanoidInstallationRequiresProofOfTrustedNativeRoot(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	root := filepath.Join(base, "Wormhole")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	app := filepath.Join(root, "application")
	if err := os.WriteFile(app, []byte("first payload"), 0600); err != nil {
		t.Fatal(err)
	}
	native := func(context.Context) (string, error) { return root, nil }
	untrusted := func(context.Context) (string, error) { return "", ErrInstallationLocation }
	if err := checkInstallationFloor(ctx, vault.Default, "", untrusted); err != nil {
		t.Fatal("Default inspected installation", err)
	}
	if err := checkInstallationFloor(ctx, vault.Hardened, "", native); err != nil {
		t.Fatal("Hardened required a signature for an acceptable location", err)
	}
	if err := checkInstallationFloor(ctx, vault.Paranoid, "", untrusted); !errors.Is(err, ErrInstallationLocation) {
		t.Fatal("untrusted location did not take precedence", err)
	}
	if err := checkInstallationFloor(ctx, vault.Paranoid, "", native); !errors.Is(err, ErrInstallationSignature) {
		t.Fatal("missing pin did not block the installation", err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	pin := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	if err := checkInstallationFloor(ctx, vault.Paranoid, pin, native); !errors.Is(err, ErrInstallationSignature) {
		t.Fatal("missing proof did not block the installation", err)
	}
	manifest, err := updateauth.InventoryInstallation(ctx, root, "v2.4.3", updateauth.InstallationTarget(runtime.GOOS, runtime.GOARCH))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := updateauth.SignInstallation(manifest, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root+updateauth.InstallationProofSuffix, proof, 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkInstallationFloor(ctx, vault.Paranoid, pin, native); err != nil {
		t.Fatal("trusted installed release rejected", err)
	}
	if err := os.WriteFile(app, []byte("other payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkInstallationFloor(ctx, vault.Paranoid, pin, native); !errors.Is(err, ErrInstallationSignature) {
		t.Fatal("modified installed release admitted", err)
	}
}
