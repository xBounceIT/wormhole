package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// The real service owns the database. This process owns only the ephemeral
// recipient and checks the client relay without exporting a private key.
func TestVaultQuickTargetInteropFixture(t *testing.T) {
	path := os.Getenv("WORMHOLE_TEST_QUICK_INTEROP_DATABASE")
	if path == "" {
		t.Skip("native Quick Connect owner/recipient fixture")
	}
	ctx := context.Background()
	doc, root := localSlotFixture(t)
	defer vault.Wipe(root)
	doc.Initializing = true
	owner, err := initializeVaultFiles(ctx, path, doc, root)
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private := key.Bytes()
	defer vault.Wipe(private)
	session := uuid.NewString()
	if json.NewEncoder(os.Stdout).Encode(map[string]any{"workspaceId": doc.VaultID, "sessionId": session, "publicKey": key.PublicKey().Bytes()}) != nil {
		t.Fatal("fixture metadata")
	}
	var result localvault.RDPConnectionBundle
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 128*1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil {
		t.Fatal("invalid target bundle")
	}
	b := result.Binding
	if b.WorkspaceID != doc.VaultID || b.SessionID != session || b.Protocol != "rdp" || b.Host != "quick.example" || b.Port != 3389 || b.TunnelConfigID != "" || b.UseExternalClient || b.Epoch != 1 {
		t.Fatal("unadmitted target")
	}
	raw, err := vault.OpenBundle(private, b, result.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(raw)
	base, inner, err := vault.DecodeRDPManualAuthorization(raw)
	if err != nil || base.PasswordProvided || base.Username != "" || base.Settings.Domain != "" {
		t.Fatal("saved fallback", err)
	}
	plaintext, err := vault.OpenManualRDPCredentials(private, b, nil, "", inner)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(plaintext)
	account, err := vault.DecodeRDPManualCredentials(plaintext)
	if err != nil || account.Username != "quick-browser-user" || account.Domain != "QUICK" || !bytes.Equal(account.Password, []byte("one-use-quick")) {
		t.Fatal("wrong manual account", err)
	}
	if json.NewEncoder(os.Stdout).Encode(map[string]bool{"ok": true}) != nil {
		t.Fatal("fixture receipt")
	}
}
