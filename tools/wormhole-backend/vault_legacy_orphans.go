package main

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// An encrypted archive, not a runtime credential. Source is the original row ID
// or logical file path. Row encoding/reference and nullable time are retained for
// later verified retirement. This pass never deletes or activates a source.
type legacyVaultOrphan struct {
	Version   int     `json:"version"`
	Source    string  `json:"source"`
	Encoding  string  `json:"encoding,omitempty"`
	Encoded   string  `json:"encoded,omitempty"`
	UpdatedAt *string `json:"updatedAt"`
	Value     []byte  `json:"value"`
}

type legacyOrphanReaders struct {
	secret legacyVaultSecretReader
	file   func(string, []byte) ([]byte, error)
}

func copyLegacyVaultOrphans(reader resolverCaptureReader, source, userData string, owner *localvault.Owner) (int, error) {
	count := 0
	readers := legacyOrphanReaders{
		file: unprotectFileContents, secret: migrationSecretReader(reader.ctx, backendMaxTunnelRequestBytes),
	}
	err := readLegacyVaultOrphans(reader, source, userData, readers, func(kind, scope string, archive []byte) error {
		if _, err := owner.PutLocalState(reader.ctx, kind, scope, archive, 0); err != nil {
			return err
		}
		if err := owner.WithLocalState(reader.ctx, kind, scope, 1, equalLegacyVaultValue(archive)); err != nil {
			return err
		}
		count++
		return nil
	})
	return count, err
}

// Called after the complete domain readers, under the same source reservation
// and directory/file locks. Load only identities once, avoiding a source-table
// scan per orphan file/row. Unknown schema/identities stop the unpublished copy.
func readLegacyVaultOrphans(reader resolverCaptureReader, source, userData string, readers legacyOrphanReaders, visit func(string, string, []byte) error) error {
	if !filepath.IsAbs(source) || readers.secret == nil || readers.file == nil || visit == nil || reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	hasSecrets, err := validateLegacyVaultSecretSource(reader)
	if err != nil {
		return err
	}
	activeRows := map[string]bool{mcpTokenCredentialID: true}
	activeKeys, activeTunnels := map[string]bool{}, map[string]bool{}
	for _, set := range []struct {
		query string
		ids   map[string]bool
	}{
		{`SELECT lower(Id) AS Id FROM CredentialProfiles WHERE SecretProvider=0 UNION SELECT lower(Id) FROM Nodes WHERE UseInlinePassword=1`, activeRows},
		{`SELECT lower(Id) AS Id FROM CredentialProfiles WHERE SecretProvider=0 AND Kind=1`, activeKeys},
		{`SELECT lower(Id) AS Id FROM TunnelConfigs`, activeTunnels},
	} {
		if err := readLegacyOrphanActiveIDs(reader, set.query, set.ids); err != nil {
			return err
		}
	}
	for id := range activeTunnels {
		activeRows[tunnelSecretID(id)] = true
	}
	if hasSecrets {
		after := ""
		for {
			page, err := readLegacyOrphanPage(reader, after)
			if err != nil {
				return err
			}
			for _, entry := range page[:min(len(page), 64)] {
				id := strings.ToLower(entry.Source)
				if !activeRows[id] {
					if err := borrowLegacyOrphanRow(reader, entry, userData, readers.secret, visit); err != nil {
						return err
					}
				}
				after = id
			}
			if len(page) <= 64 {
				break
			}
		}
	}
	for _, set := range []struct {
		path, kind       string
		protectedMaximum int64
		plainMaximum     int
		active           map[string]bool
	}{
		{filepath.Dir(credentialPrivateKeyPath(source, mcpTokenCredentialID)), "legacy-private-key", maxProtectedSshKeyBytes, maxSshPrivateKeyBytes, activeKeys},
		{filepath.Dir(legacyTunnelSecretPath(source, mcpTokenCredentialID)), "legacy-tunnel-file", maxTunnelProtectedBytes, backendMaxTunnelRequestBytes, activeTunnels},
	} {
		err := visitLegacyLocalDirectory(reader, set.path, ".dpapi", func(path, scope string) error {
			if set.active[scope] {
				return nil
			}
			return borrowLegacyLocalFile(reader, legacyLocalStateFile{path, set.kind, scope, set.protectedMaximum, false, true}, legacyLocalStateReaders{file: readers.file}, func(kind, scope string, value []byte) error {
				if len(value) > set.plainMaximum {
					return errVaultMigrationSource
				}
				return visitLegacyOrphanArchive(reader, kind, scope, legacyVaultOrphan{Version: 1, Source: path, Value: value}, visit)
			})
		})
		if err != nil {
			return err
		}
	}
	if reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	return nil
}

func readLegacyOrphanActiveIDs(reader resolverCaptureReader, query string, ids map[string]bool) error {
	// The caller provides a fixed query, wrapped to bound metadata before Scan.
	rows, err := reader.Query("SELECT " + shadowText("Id", 36) + " FROM (" + query + ")")
	if err != nil {
		return errVaultMigrationSource
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil || !vaultCredentialID(id) {
			return errVaultMigrationSource
		}
		ids[id] = true
	}
	if rows.Err() != nil {
		return errVaultMigrationSource
	}
	return nil
}

func legacyOrphanRowIdentity(source string) (kind, scope string) {
	id := strings.ToLower(source)
	kind, scope = "legacy-secret", id
	if strings.HasPrefix(id, tunnelSecretPrefix) {
		kind, scope = "legacy-tunnel-row", strings.TrimPrefix(id, tunnelSecretPrefix)
	}
	if !vaultCredentialID(scope) {
		return "", ""
	}
	return kind, scope
}

func readLegacyOrphanPage(reader resolverCaptureReader, after string) ([]legacyVaultOrphan, error) {
	rows, err := reader.Query("SELECT "+shadowText("Id", 43)+","+shadowText("UpdatedAt", 128)+" FROM CredentialSecrets WHERE (?='' OR lower(Id)>?) ORDER BY lower(Id),Id LIMIT 65", after, after)
	if err != nil {
		return nil, errVaultMigrationSource
	}
	defer rows.Close()
	var result []legacyVaultOrphan
	for rows.Next() {
		entry := legacyVaultOrphan{Version: 1}
		var updated sql.NullString
		if rows.Scan(&entry.Source, &updated) != nil {
			return nil, errVaultMigrationSource
		}
		kind, _ := legacyOrphanRowIdentity(entry.Source)
		if kind == "" || strings.ToLower(entry.Source) <= after || len(updated.String) > 128 || !utf8.ValidString(updated.String) || strings.ContainsRune(updated.String, 0) {
			return nil, errVaultMigrationSource
		}
		if updated.Valid {
			entry.UpdatedAt = &updated.String
		}
		after = strings.ToLower(entry.Source)
		result = append(result, entry)
	}
	if rows.Err() != nil {
		return nil, errVaultMigrationSource
	}
	return result, nil
}

func borrowLegacyOrphanRow(reader resolverCaptureReader, entry legacyVaultOrphan, userData string, decrypt legacyVaultSecretReader, visit func(string, string, []byte) error) error {
	kind, scope := legacyOrphanRowIdentity(entry.Source)
	maximum, encodedMaximum := maxStoredCredentialBytes, 128*1024
	if kind == "legacy-tunnel-row" {
		maximum, encodedMaximum = backendMaxTunnelRequestBytes, 6*1024*1024
	}
	encoded, encoding, present, err := readLegacyVaultSecretRowMatch(reader, entry.Source, encodedMaximum, true)
	if err != nil || !present || reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	value, err := decrypt(strings.ToLower(entry.Source), encoded, encoding, userData)
	defer vault.Wipe(value)
	if err != nil || len(value) > maximum || reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	entry.Encoded, entry.Encoding, entry.Value = encoded, encoding, value
	return visitLegacyOrphanArchive(reader, kind, scope, entry, visit)
}

func visitLegacyOrphanArchive(reader resolverCaptureReader, kind, scope string, entry legacyVaultOrphan, visit func(string, string, []byte) error) error {
	archive, err := json.Marshal(entry)
	defer vault.Wipe(archive)
	if err != nil || reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	if err := visit(kind, scope, archive); err != nil {
		return err
	}
	if reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	return nil
}
