package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestVaultMigrationFactorBytesMatchLegacyAndCancel(t *testing.T) {
	salt := bytes.Repeat([]byte{7}, authSaltLength)
	for _, iterations := range []int{1, 2, 4096} {
		derived, err := deriveLegacyMigrationFactor(context.Background(), []byte("legacy-α-factor"), salt, iterations)
		if err != nil || !bytes.Equal(derived, deriveAuthSecret("legacy-α-factor", salt, iterations)) {
			t.Fatal("native factor changed legacy PBKDF2", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if derived, err := deriveLegacyMigrationFactor(ctx, []byte("fixture"), salt, authMaxPbkdf2Iterations); !errors.Is(err, context.Canceled) || derived != nil {
		t.Fatal("cancelled factor material retained", err)
	}
	if _, err := deriveLegacyMigrationFactor(context.Background(), nil, salt, 1); !errors.Is(err, vault.ErrFormat) {
		t.Fatal(err)
	}
}

func TestVaultMigrationFactorRequiresProtectedVerifierRegardlessOfSettings(t *testing.T) {
	source := filepath.Join(t.TempDir(), "legacy.db")
	store, settings := authPaths(source)
	ctx := context.Background()
	if err := verifyLegacyMigrationFactor(ctx, source, "none", nil); err != nil {
		t.Fatal("unconfigured native owner rejected", err)
	}
	salt := bytes.Repeat([]byte{3}, authSaltLength)
	verifier := &authVerifier{Salt: salt, Hash: deriveAuthSecret("2468", salt, 4096), Iterations: 4096}
	if err := writeAuthDocument(store, authDocument{Version: authStoreVersion, Pin: verifier}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(`{"AppAuthenticationMode":0}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyLegacyMigrationFactor(ctx, source, "none", nil); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("mutable settings bypassed native verifier", err)
	}
	if err := verifyLegacyMigrationFactor(ctx, source, "pin", []byte("2468")); err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct{ method, factor string }{{"pin", "0000"}, {"password", "2468"}, {"other", "2468"}, {"pin", ""}} {
		if err := verifyLegacyMigrationFactor(ctx, source, request.method, []byte(request.factor)); !errors.Is(err, vault.ErrAuthentication) {
			t.Fatal("invalid legacy proof accepted", err)
		}
	}
	password := &authVerifier{Salt: salt, Hash: deriveAuthSecret("legacy native password", salt, 4096), Iterations: 4096}
	if err := writeAuthDocument(store, authDocument{Version: authStoreVersion, Pin: verifier, Password: password}); err != nil {
		t.Fatal(err)
	}
	if err := verifyLegacyMigrationFactor(ctx, source, "password", []byte("legacy native password")); err != nil {
		t.Fatal("existing native password rejected", err)
	}
	if err := verifyLegacyMigrationFactor(ctx, source, "password", []byte("2468")); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("PIN substituted for password proof", err)
	}
	if err := os.WriteFile(store, []byte("corrupted protected auth store"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyLegacyMigrationFactor(ctx, source, "none", nil); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("corrupted verifier became unconfigured", err)
	}
}
