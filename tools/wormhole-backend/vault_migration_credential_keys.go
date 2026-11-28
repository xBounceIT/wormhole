package main

import (
	"context"
	"crypto/hmac"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// Missing is distinct from inaccessible. These native adapters return owned
// mutable values and never treat a locked/broken keychain as an absent item.
type migrationCredentialStore struct {
	Load   func(context.Context) ([]byte, bool, error)
	Delete func(context.Context) error
	Close  func()
}

type migrationCredentialStoreFactory func(context.Context, legacyInventoryRow, int) (migrationCredentialStore, error)

func migrationSecretReader(ctx context.Context, maximum int) legacyVaultSecretReader {
	return func(id, encoded, encoding string, paths ...string) ([]byte, error) {
		if runtime.GOOS == "linux" && strings.TrimSpace(encoding) == linuxLegacySecretServiceEncoding {
			return loadMigrationCredential(ctx, legacyInventoryRow{ID: id, Reference: encoded, Encoding: encoding}, maximum, openMigrationCredentialStore)
		}
		return unprotectStoredValue(id, encoded, encoding, maximum, paths...)
	}
}

func loadMigrationCredential(ctx context.Context, row legacyInventoryRow, maximum int, open migrationCredentialStoreFactory) ([]byte, error) {
	if ctx.Err() != nil || maximum < 1 || maximum > backendMaxTunnelRequestBytes {
		return nil, errVaultMigrationSource
	}
	store, err := open(ctx, row, maximum)
	if store.Close != nil {
		defer store.Close()
	}
	if err != nil || store.Load == nil || store.Close == nil {
		return nil, errVaultMigrationSource
	}
	value, present, err := store.Load(ctx)
	if err != nil || !present || len(value) > maximum || ctx.Err() != nil {
		vault.Wipe(value)
		return nil, errVaultMigrationSource
	}
	return value, nil
}
func legacyRetirementKeyRows(rows []legacyInventoryRow) ([]legacyInventoryRow, error) {
	result := []legacyInventoryRow{}
	previous := ""
	for _, row := range rows {
		kind, _ := legacyOrphanRowIdentity(row.ID)
		id := strings.ToLower(row.ID)
		if kind == "" || id <= previous || len(row.Authentication) != 32 || (row.UpdatedAt != nil && (len(*row.UpdatedAt) > 128 || !utf8.ValidString(*row.UpdatedAt) || strings.ContainsRune(*row.UpdatedAt, 0))) {
			return nil, vault.ErrFormat
		}
		previous = id
		switch strings.TrimSpace(row.Encoding) {
		case linuxLegacySecretServiceEncoding, linuxSecretServiceEncoding, darwinKeychainEncoding:
			if row.Reference == "" {
				return nil, vault.ErrFormat
			}
			if _, err := credentialSecretAccount(id, row.Reference); err != nil {
				return nil, vault.ErrFormat
			}
			result = append(result, row)
		case protectedSecretEncoding, electronSafeStorageSecretEncoding:
			if row.Reference != "" {
				return nil, vault.ErrFormat
			}
		default:
			return nil, vault.ErrFormat
		}
	}
	return result, nil
}

func retireLegacyCredentialKey(reader resolverCaptureReader, source, workspace string, key []byte, rows []legacyInventoryRow, index int, owner *localvault.Owner, state *vaultstore.LocalState, journal *legacyRetirementJournal, open migrationCredentialStoreFactory) error {
	ctx := reader.ctx
	if err := ctx.Err(); err != nil {
		return err
	}
	if open == nil || journal.Version != 2 || journal.Pending != nil || index < 0 || index >= len(rows) || (journal.PendingKey != nil && *journal.PendingKey != index) {
		return vault.ErrPolicy
	}
	row := rows[index]
	maximum, encodedMaximum := maxStoredCredentialBytes, 128*1024
	if kind, _ := legacyOrphanRowIdentity(row.ID); kind == "legacy-tunnel-row" {
		maximum, encodedMaximum = backendMaxTunnelRequestBytes, 6*1024*1024
	}
	encoded, encoding, present, err := readLegacyVaultSecretRowMatch(reader, row.ID, encodedMaximum, true)
	if err != nil || !present || encoded != row.Reference || encoding != row.Encoding {
		return vault.ErrAuthentication
	}
	store, err := open(ctx, row, maximum)
	if store.Close != nil {
		defer store.Close()
	}
	if err != nil {
		return errVaultMigrationSource
	}
	if store.Load == nil || store.Delete == nil || store.Close == nil {
		return vault.ErrFormat
	}
	// Keep the plaintext inside this bounded validation callback. Repeat it after
	// the durable intent: a keychain item can change while SQLite commits.
	loadMatching := func() (bool, error) {
		value, present, err := store.Load(ctx)
		defer vault.Wipe(value)
		if err != nil || len(value) > maximum || (!present && len(value) != 0) {
			return false, errVaultMigrationSource
		}
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if present && !matchesLegacyRetirementKey(key, source, row, encoded, value) {
			return false, vault.ErrAuthentication
		}
		return present, nil
	}
	present, err = loadMatching()
	if err != nil {
		return err
	}
	if !present && journal.PendingKey == nil && index >= journal.KeysCompleted {
		return vault.ErrAuthentication
	}
	if !present && journal.PendingKey == nil {
		return nil
	}
	if journal.PendingKey == nil {
		journal.PendingKey = &index
		next, err := writeLegacyRetirementJournal(ctx, owner, workspace, *journal, state.RowVersion)
		if err != nil {
			return err
		}
		*state = next
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if present {
		present, err = loadMatching()
		if err != nil {
			return err
		}
		if present && store.Delete(ctx) != nil {
			return errVaultMigrationSource
		}
	}
	remaining, present, err := store.Load(ctx)
	vault.Wipe(remaining)
	if err != nil || present || len(remaining) != 0 {
		return errVaultMigrationSource
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	journal.PendingKey = nil
	journal.KeysCompleted = max(journal.KeysCompleted, index+1)
	next, err := writeLegacyRetirementJournal(ctx, owner, workspace, *journal, state.RowVersion)
	if err != nil {
		return err
	}
	*state = next
	return nil
}

func matchesLegacyRetirementKey(key []byte, source string, row legacyInventoryRow, encoded string, value []byte) bool {
	expected := row.Authentication
	row.Authentication = nil
	protected := []byte(encoded)
	defer vault.Wipe(protected)
	actual, err := legacyInventoryMAC(key, source, row, protected, value)
	return err == nil && hmac.Equal(expected, actual)
}
