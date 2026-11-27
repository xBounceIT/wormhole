package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestVaultMigrationContextUsesOnlyProtectedVerifiers(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.db")
	if err := os.WriteFile(source, []byte("not SQLite, private fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	h := &vaultFoundationHandler{databasePath: source}
	ctx := context.Background()
	store, settings := authPaths(source)
	for _, mode := range []string{"none", "pin", "password", "both", "corrupt"} {
		doc := authDocument{Version: authStoreVersion}
		v := &authVerifier{Salt: bytes.Repeat([]byte{7}, authSaltLength), Hash: deriveAuthSecret("native context fixture", bytes.Repeat([]byte{7}, authSaltLength), 4096), Iterations: 4096}
		if mode == "pin" || mode == "both" {
			doc.Pin = v
		}
		if mode == "password" || mode == "both" {
			doc.Password = v
		}
		if mode != "none" {
			if err := writeAuthDocument(store, doc); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(settings, []byte(`{"AppAuthenticationMode":0}`), 0600); err != nil {
			t.Fatal(err)
		}
		if mode == "corrupt" {
			if err := os.WriteFile(store, []byte("corrupt native verifier"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		raw, err := h.Handle(ctx, "migration-setup-context", nil)
		if mode == "corrupt" {
			if !errors.Is(err, vault.ErrAuthentication) {
				t.Fatal("corrupt proof became none", err)
			}
			continue
		}
		want := map[string]string{"none": `{"methods":["none"]}`, "pin": `{"methods":["pin"]}`, "password": `{"methods":["password"]}`, "both": `{"methods":["password","pin"]}`}[mode]
		if err != nil || string(raw) != want {
			t.Fatal("incorrect method hints", string(raw), err)
		}
		for _, private := range []string{source, "Salt", "Hash", "fixture", "Iterations"} {
			if bytes.Contains(raw, []byte(private)) {
				t.Fatal("private context escaped")
			}
		}
	}
	if _, err := h.Handle(ctx, "migration-setup-context", []byte(`{}`)); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := readLegacyMigrationAuth(canceled, source); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultSlotPath(source), []byte("quarantined"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "migration-setup-context", nil); err != errVaultOwnerRequired {
		t.Fatal("protected source admitted", err)
	}
	if _, err := (&vaultFoundationHandler{databasePath: filepath.Join(root, "absent.db")}).Handle(ctx, "migration-setup-context", nil); err != vault.ErrPolicy {
		t.Fatal(err)
	}
}
