package main

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestUnprotectedPlatformKeyWindowsDPAPICustody(t *testing.T) {
	db, vaultID, slotID, _, _ := unprotectedKeyFixture(t)
	ctx := context.Background()
	key, err := createVaultUnprotectedKey(ctx, db, vaultID, slotID)
	defer vault.Wipe(key)
	if err != nil {
		t.Fatal(err)
	}
	path, _, _ := vaultUnprotectedKeyLocation(ctx, db, vaultID, slotID)
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || bytes.Contains(raw, key) || bytes.Contains(raw, []byte(vaultUnprotectedKeyDomain)) {
		t.Fatal("DPAPI factor exposed plaintext", err)
	}
	opened, err := openVaultUnprotectedKey(ctx, db, vaultID, slotID)
	defer vault.Wipe(opened)
	if err != nil || !bytes.Equal(opened, key) {
		t.Fatal("real DPAPI custody cannot reopen its factor", err)
	}
}
