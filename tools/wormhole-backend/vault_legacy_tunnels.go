package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type legacyVaultTunnel struct {
	Metadata                 vaultstore.TunnelMetadata
	Times                    localvault.ImportTimes
	ProtectedFile, LegacyRow bool
}

type legacyVaultTunnelReaders struct {
	protected func(string, int64) ([]byte, error)
	file      func(string, []byte) ([]byte, error)
	row       legacyVaultSecretReader
}

// Acquire the tunnel configuration lock before the source SQLite reservation.
// Callers own source/path binding, unpublished staging and durable retirement.
// File corruption never authorizes fallback to another source or a direct route.
func visitLegacyVaultTunnels(reader resolverCaptureReader, databasePath, userData string, visit func(legacyVaultTunnel, []byte) error) error {
	return readLegacyVaultTunnels(reader, databasePath, userData, legacyVaultTunnelReaders{
		protected: readBoundedRegularFile, file: unprotectFileContents,
		row: migrationSecretReader(reader.ctx, backendMaxTunnelRequestBytes),
	}, visit)
}

func readLegacyVaultTunnels(reader resolverCaptureReader, databasePath, userData string, readers legacyVaultTunnelReaders, visit func(legacyVaultTunnel, []byte) error) error {
	if !filepath.IsAbs(databasePath) || visit == nil || readers.protected == nil || readers.file == nil || readers.row == nil {
		return errVaultMigrationSource
	}
	hasSecrets, err := validateLegacyVaultSecretSource(reader)
	if err != nil {
		return err
	}
	after := ""
	for {
		page, err := readLegacyVaultTunnelPage(reader, after)
		if err != nil {
			return err
		}
		limit := len(page)
		if limit > 64 {
			limit = 64
		}
		for i := 0; i < limit; i++ {
			if err := borrowLegacyVaultTunnel(reader, page[i], hasSecrets, databasePath, userData, readers, visit); err != nil {
				return err
			}
			after = page[i].Metadata.ID
		}
		if reader.ctx.Err() != nil {
			return errVaultMigrationSource
		}
		if len(page) <= 64 {
			return nil
		}
	}
}

func readLegacyVaultTunnelPage(reader resolverCaptureReader, after string) ([]legacyVaultTunnel, error) {
	columns := []string{shadowText("Id", 36), shadowText("Name", 512), "Kind", shadowText("CreatedAt", 128), shadowText("UpdatedAt", 128)}
	rows, err := reader.Query("SELECT "+strings.Join(columns, ",")+" FROM TunnelConfigs WHERE (?='' OR lower(Id)>?) ORDER BY lower(Id),Id LIMIT 65;", after, after)
	if err != nil {
		return nil, errVaultMigrationSource
	}
	defer rows.Close()
	var result []legacyVaultTunnel
	previous := after
	for rows.Next() {
		var record legacyVaultTunnel
		var created, updated string
		if rows.Scan(&record.Metadata.ID, &record.Metadata.Name, &record.Metadata.Kind, &created, &updated) != nil {
			return nil, errVaultMigrationSource
		}
		record.Metadata.ID = strings.ToLower(record.Metadata.ID)
		if record.Metadata.ID <= previous || record.Metadata.Validate() != nil {
			return nil, errVaultMigrationSource
		}
		previous = record.Metadata.ID
		record.Times, err = legacyVaultTimes(created, updated)
		if err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	if rows.Err() != nil {
		return nil, errVaultMigrationSource
	}
	return result, nil
}

func borrowLegacyVaultTunnel(reader resolverCaptureReader, record legacyVaultTunnel, hasSecrets bool, databasePath, userData string, readers legacyVaultTunnelReaders, visit func(legacyVaultTunnel, []byte) error) error {
	if reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	path := legacyTunnelSecretPath(databasePath, record.Metadata.ID)
	protected, err := readers.protected(path, maxTunnelProtectedBytes)
	defer vault.Wipe(protected)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errVaultMigrationSource
	}
	var configuration []byte
	defer func() { vault.Wipe(configuration) }()
	if err == nil {
		if len(protected) == 0 || len(protected) > maxTunnelProtectedBytes || reader.ctx.Err() != nil {
			return errVaultMigrationSource
		}
		configuration, err = readers.file(path, protected)
		if err != nil || reader.ctx.Err() != nil || validateVaultTunnelConfiguration(configuration, record.Metadata.Kind) != nil {
			return errVaultMigrationSource
		}
		record.ProtectedFile = true
	}
	if reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	if hasSecrets {
		encoded, encoding, present, err := readLegacyVaultSecretRowLimit(reader, tunnelSecretID(record.Metadata.ID), 6*1024*1024)
		if err != nil {
			return err
		}
		if present {
			fallback, err := readers.row(tunnelSecretID(record.Metadata.ID), encoded, encoding, userData)
			defer vault.Wipe(fallback)
			if err != nil || reader.ctx.Err() != nil || validateVaultTunnelConfiguration(fallback, record.Metadata.Kind) != nil {
				return errVaultMigrationSource
			}
			if record.ProtectedFile {
				// Both locations may survive an interrupted legacy write. Only
				// identical payloads are unambiguous enough to retire together.
				if !bytes.Equal(configuration, fallback) {
					return errVaultMigrationSource
				}
			} else {
				configuration = fallback
			}
			record.LegacyRow = true
		}
	}
	if (!record.ProtectedFile && !record.LegacyRow) || reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	if err := visit(record, configuration); err != nil {
		return err
	}
	if reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	return nil
}
