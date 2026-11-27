package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func unprotectedKeyFixture(t *testing.T) (string, string, string, vaultPlatformKeyTransform, vaultPlatformKeyTransform) {
	t.Helper()
	if floor, err := ospolicy.ReadFloor(context.Background()); err != nil || floor != vault.Default {
		t.Skip("OS-only custody is unavailable under the actual managed floor")
	}
	key := bytes.Repeat([]byte{0x71}, 32)
	return filepath.Join(t.TempDir(), "wormhole.db"), uuid.NewString(), uuid.NewString(),
		func(_ string, raw []byte) ([]byte, error) { return encryptAuthDocument(raw, key) },
		func(_ string, raw []byte) ([]byte, error) { return decryptAuthDocument(raw, key) }
}

func TestUnprotectedPlatformKeyCustodyAndBorrowedBufferWiping(t *testing.T) {
	db, vaultID, slotID, protect, unprotect := unprotectedKeyFixture(t)
	ctx := context.Background()
	path, _, err := vaultUnprotectedKeyLocation(ctx, db, vaultID, slotID)
	if err != nil {
		t.Fatal(err)
	}
	var borrowedPlain, borrowedCipher []byte
	key, err := createVaultUnprotectedKeyWith(ctx, db, vaultID, slotID, func(got string, raw []byte) ([]byte, error) {
		if got != path {
			t.Fatal("wrong platform protection scope")
		}
		borrowedPlain = raw
		sealed, err := protect(got, raw)
		borrowedCipher = sealed
		return sealed, err
	})
	defer vault.Wipe(key)
	if err != nil || len(key) != 32 || bytes.Equal(key, make([]byte, 32)) {
		t.Fatal("native key creation", err)
	}
	if !bytes.Equal(borrowedPlain, make([]byte, len(borrowedPlain))) || !bytes.Equal(borrowedCipher, make([]byte, len(borrowedCipher))) {
		t.Fatal("native creation retained borrowed material")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || bytes.Contains(raw, key) || bytes.Contains(raw, []byte(vaultUnprotectedKeyDomain)) {
		t.Fatal("platform factor persisted as plaintext", err)
	}
	opened, err := openVaultUnprotectedKeyWith(ctx, db, vaultID, slotID, func(got string, raw []byte) ([]byte, error) {
		if got != path {
			t.Fatal("wrong platform unprotection scope")
		}
		borrowedCipher = raw
		plain, err := unprotect(got, raw)
		borrowedPlain = plain
		return plain, err
	})
	defer vault.Wipe(opened)
	if err != nil || !bytes.Equal(opened, key) {
		t.Fatal("native key reopening", err)
	}
	if !bytes.Equal(borrowedPlain, make([]byte, len(borrowedPlain))) || !bytes.Equal(borrowedCipher, make([]byte, len(borrowedCipher))) {
		t.Fatal("native reopening retained borrowed material")
	}
	if value, err := createVaultUnprotectedKeyWith(ctx, db, vaultID, slotID, func(string, []byte) ([]byte, error) {
		t.Error("existing factor reached the platform writer")
		return nil, nil
	}); value != nil || !errors.Is(err, errVaultUnprotectedKeyStorage) {
		t.Fatal("existing factor replaced", err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, raw) {
		t.Fatal("existing ciphertext altered")
	}
	// The root wrapper is independently authenticated against the slot kind.
	slot, err := vault.CreateUnprotectedSlot(vaultID, slotID, 1, bytes.Repeat([]byte{0x72}, 32), opened)
	if err != nil {
		t.Fatal(err)
	}
	root, err := vault.OpenUnprotectedSlot(vaultID, slot, key)
	defer vault.Wipe(root)
	if err != nil || !bytes.Equal(root, bytes.Repeat([]byte{0x72}, 32)) {
		t.Fatal("OS custody cannot open its native root wrapper", err)
	}
}

func TestUnprotectedPlatformKeyRefusesInvalidScopesAndMissingStorage(t *testing.T) {
	db, vaultID, slotID, protect, unprotect := unprotectedKeyFixture(t)
	ctx := context.Background()
	for _, args := range [][3]string{
		{"", vaultID, slotID}, {"relative.db", vaultID, slotID},
		{filepath.Dir(db) + string(os.PathSeparator) + "." + string(os.PathSeparator) + "wormhole.db", vaultID, slotID},
		{db, "../outside", slotID}, {db, vaultID, "../outside"},
		{db, uuid.Nil.String(), slotID}, {db, vaultID, "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"},
	} {
		if key, err := createVaultUnprotectedKeyWith(ctx, args[0], args[1], args[2], protect); err != vault.ErrFormat || key != nil {
			t.Fatal("invalid create scope", args, err)
		}
		if key, err := openVaultUnprotectedKeyWith(ctx, args[0], args[1], args[2], unprotect); err != vault.ErrFormat || key != nil {
			t.Fatal("invalid open scope", args, err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	for _, operation := range []func(context.Context, string, string, string) ([]byte, error){createVaultUnprotectedKey, openVaultUnprotectedKey} {
		if key, err := operation(cancelled, db, vaultID, slotID); err != context.Canceled || key != nil {
			t.Fatal("cancelled platform operation", err)
		}
	}
	missing := filepath.Join(filepath.Dir(db), "missing", "wormhole.db")
	if key, err := createVaultUnprotectedKeyWith(ctx, missing, vaultID, slotID, protect); err != errVaultUnprotectedKeyStorage || key != nil {
		t.Fatal("missing directory created implicitly", err)
	}
	if key, err := openVaultUnprotectedKeyWith(ctx, missing, vaultID, slotID, unprotect); err != errVaultUnprotectedKeyStorage || key != nil {
		t.Fatal("missing root repaired implicitly", err)
	}
	if key, err := openVaultUnprotectedKeyWith(ctx, db, vaultID, slotID, unprotect); err != errVaultUnprotectedKeyStorage || key != nil {
		t.Fatal("missing factor repaired implicitly", err)
	}
}

func TestUnprotectedPlatformKeyFailureAndCancellationDoNotPublish(t *testing.T) {
	for _, mode := range []string{"error", "empty", "oversized", "cancel", "replacement"} {
		t.Run(mode, func(t *testing.T) {
			db, vaultID, slotID, protect, _ := unprotectedKeyFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			path, _, _ := vaultUnprotectedKeyLocation(ctx, db, vaultID, slotID)
			var plain, sealed []byte
			value, err := createVaultUnprotectedKeyWith(ctx, db, vaultID, slotID, func(path string, raw []byte) ([]byte, error) {
				plain = raw
				switch mode {
				case "error":
					return nil, errors.New("private platform diagnostic")
				case "empty":
					return nil, nil
				case "oversized":
					sealed = make([]byte, maxVaultUnprotectedKeyBlob+1)
					return sealed, nil
				case "cancel":
					cancel()
				case "replacement":
					if err := os.Rename(path, path+".old"); err != nil {
						t.Skip("filesystem refuses renaming an open reservation")
					}
					if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				sealed, err := protect(path, raw)
				return sealed, err
			})
			if err == nil || value != nil || strings.Contains(err.Error(), "private platform diagnostic") {
				t.Fatal("failed platform creation returned material or details", err)
			}
			if !bytes.Equal(plain, make([]byte, len(plain))) || !bytes.Equal(sealed, make([]byte, len(sealed))) {
				t.Fatal("failed creation retained material")
			}
			if mode == "replacement" {
				if raw, err := os.ReadFile(path); err != nil || string(raw) != "replacement" {
					t.Fatal("cleanup removed a replacement", err)
				}
			} else if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed reservation published", err)
			}
		})
	}
}

func TestUnprotectedPlatformKeyReadRejectsMalformedOrChangedFactors(t *testing.T) {
	for _, mode := range []string{"empty", "oversized", "directory", "corrupt", "short", "context", "cancel", "replacement"} {
		t.Run(mode, func(t *testing.T) {
			db, vaultID, slotID, protect, unprotect := unprotectedKeyFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			key, err := createVaultUnprotectedKeyWith(ctx, db, vaultID, slotID, protect)
			defer vault.Wipe(key)
			if err != nil {
				t.Fatal(err)
			}
			path, _, _ := vaultUnprotectedKeyLocation(ctx, db, vaultID, slotID)
			switch mode {
			case "empty":
				err = os.WriteFile(path, nil, 0o600)
			case "oversized":
				err = os.WriteFile(path, make([]byte, maxVaultUnprotectedKeyBlob+1), 0o600)
			case "directory":
				if err = os.Remove(path); err == nil {
					err = os.Mkdir(path, 0o700)
				}
			case "corrupt":
				err = os.WriteFile(path, []byte("invalid"), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			var plain []byte
			opened, err := openVaultUnprotectedKeyWith(ctx, db, vaultID, slotID, func(path string, raw []byte) ([]byte, error) {
				plain, err = unprotect(path, raw)
				if err != nil {
					return plain, err
				}
				switch mode {
				case "short":
					plain = plain[:len(plain)-1]
				case "context":
					plain[0] ^= 1
				case "cancel":
					cancel()
				case "replacement":
					if err := os.Rename(path, path+".old"); err != nil {
						t.Skip("filesystem refuses renaming an open factor")
					}
					if err := os.WriteFile(path, raw, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				return plain, nil
			})
			if err == nil || opened != nil || !bytes.Equal(plain, make([]byte, len(plain))) {
				t.Fatal("invalid or stale factor accepted/retained", err)
			}
		})
	}
}

func TestUnprotectedPlatformKeyReservesBeforeOSKeyCreation(t *testing.T) {
	db, vaultID, slotID, protect, unprotect := unprotectedKeyFixture(t)
	reserved, resume := make(chan struct{}), make(chan struct{})
	type outcome struct {
		key []byte
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		key, err := createVaultUnprotectedKeyWith(context.Background(), db, vaultID, slotID, func(path string, raw []byte) ([]byte, error) {
			close(reserved)
			<-resume
			return protect(path, raw)
		})
		done <- outcome{key, err}
	}()
	select {
	case <-reserved:
	case first := <-done:
		vault.Wipe(first.key)
		t.Fatalf("first creator returned before reserving OS custody: %v", first.err)
	}
	second, err := createVaultUnprotectedKeyWith(context.Background(), db, vaultID, slotID, func(string, []byte) ([]byte, error) {
		t.Error("losing creator touched OS custody")
		return nil, nil
	})
	close(resume)
	first := <-done
	defer vault.Wipe(first.key)
	if second != nil || err != errVaultUnprotectedKeyStorage || first.err != nil {
		t.Fatal("concurrent custody reservation", err, first.err)
	}
	opened, err := openVaultUnprotectedKeyWith(context.Background(), db, vaultID, slotID, unprotect)
	defer vault.Wipe(opened)
	if err != nil || !bytes.Equal(opened, first.key) {
		t.Fatal("winning custody was replaced", err)
	}
}
