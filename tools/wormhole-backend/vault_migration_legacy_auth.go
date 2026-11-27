package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"unicode/utf8"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Verify only an existing native protected verifier. Mutable settings never
// select a weaker mode or turn a present verifier into "no authentication".
// The factor remains bytes throughout; ownership/wiping belongs to the caller.
func verifyLegacyMigrationFactor(ctx context.Context, source, method string, factor []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if method != "none" && method != "pin" && method != "password" || len(factor) > 1024 || !utf8.Valid(factor) {
		return vault.ErrAuthentication
	}
	document, err := readLegacyMigrationAuth(ctx, source)
	if err != nil {
		return err
	}
	if method == "none" {
		if len(factor) == 0 && document.Pin == nil && document.Password == nil {
			return nil
		}
		return vault.ErrAuthentication
	}
	verifier := document.Password
	if method == "pin" {
		verifier = document.Pin
	}
	if verifier == nil || len(factor) == 0 {
		return vault.ErrAuthentication
	}
	hash, err := deriveLegacyMigrationFactor(ctx, factor, verifier.Salt, verifier.Iterations)
	defer vault.Wipe(hash)
	if err != nil {
		return err
	}
	if !hmac.Equal(hash, verifier.Hash) {
		return vault.ErrAuthentication
	}
	return nil
}

// Read only the native protected verifier. Context hints and actual proof share
// decoding, but begin always rechecks it after obtaining workspace ownership.
func readLegacyMigrationAuth(ctx context.Context, source string) (authDocument, error) {
	if err := ctx.Err(); err != nil {
		return authDocument{}, err
	}
	path, _ := authPaths(source)
	protected, err := readLegacyInventoryFile(path, authMaxStoreBytes)
	defer vault.Wipe(protected)
	if errors.Is(err, os.ErrNotExist) {
		return authDocument{Version: authStoreVersion}, nil
	}
	if err != nil {
		return authDocument{}, vault.ErrAuthentication
	}
	plain, err := unprotectAuthDocument(path, protected)
	defer vault.Wipe(plain)
	if err != nil {
		return authDocument{}, vault.ErrAuthentication
	}
	var document authDocument
	if json.Unmarshal(plain, &document) != nil || document.Version != authStoreVersion || !validAuthVerifier(document.Pin) || !validAuthVerifier(document.Password) {
		return authDocument{}, vault.ErrAuthentication
	}
	return document, nil
}

// PBKDF2-HMAC-SHA256, one 32-byte block, matching the legacy protected format.
// Reuse the HMAC state and observe cancellation while deriving a native factor.
func deriveLegacyMigrationFactor(ctx context.Context, factor, salt []byte, iterations int) (result []byte, resultErr error) {
	if len(factor) == 0 || len(factor) > 1024 || len(salt) != authSaltLength || iterations < 1 || iterations > authMaxPbkdf2Iterations {
		return nil, vault.ErrFormat
	}
	mac := hmac.New(sha256.New, factor)
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	previous := mac.Sum(nil)
	defer func() { vault.Wipe(previous) }()
	result = append([]byte(nil), previous...)
	defer func() {
		if resultErr != nil {
			vault.Wipe(result)
			result = nil
		}
	}()
	for i := 1; i < iterations; i++ {
		if i%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return result, err
			}
		}
		mac.Reset()
		mac.Write(previous)
		previous = mac.Sum(previous[:0])
		for j := range result {
			result[j] ^= previous[j]
		}
	}
	return result, ctx.Err()
}
