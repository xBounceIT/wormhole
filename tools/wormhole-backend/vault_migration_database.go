package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"math"
	"sort"
	"strings"
)

const maxMigrationSourceBytes = 128 * 1024 * 1024

// Bind all source rows, including notes, non-resolver metadata and schema, to the
// encrypted inventory. The caller holds the migration's reserved transaction.
// Reading SQLite through that transaction includes committed WAL pages. Hashing
// only the main file, or only the resolver fingerprint, would miss source edits.
// This is a same-source checkpoint, not a portable database canonicalization:
// a changed physical row order may conservatively require staging again.
func captureLegacyDatabaseState(reader resolverCaptureReader, key []byte) ([]byte, error) {
	return captureLegacyDatabaseRetirementState(reader, key, false)
}

// Predict the exact logical checkpoint after retiring only CredentialSecrets.
// The query commitment and column headers stay unchanged; only its rows are
// omitted. No speculative write or source-side recovery marker is needed.
func captureLegacyDatabaseRetirementState(reader resolverCaptureReader, key []byte, retired bool) ([]byte, error) {
	if reader.ctx.Err() != nil || len(key) != 32 {
		return nil, errVaultMigrationSource
	}
	var pages, size int64
	if reader.QueryRow("PRAGMA main.page_count").Scan(&pages) != nil || reader.QueryRow("PRAGMA main.page_size").Scan(&size) != nil || pages < 1 || size < 512 || size > 65536 || pages > maxMigrationSourceBytes/size {
		return nil, errVaultMigrationSource
	}
	rows, err := reader.Query("PRAGMA main.table_list")
	if err != nil {
		return nil, errVaultMigrationSource
	}
	var tables []string
	for count := 0; rows.Next(); count++ {
		var schema, name, kind string
		var columns, withoutRowID, strict int
		if rows.Scan(&schema, &name, &kind, &columns, &withoutRowID, &strict) != nil || schema != "main" || len(name) > 1024 || columns < 1 || columns > 128 || (kind != "table" && kind != "view") || count >= 512 {
			rows.Close()
			return nil, errVaultMigrationSource
		}
		if kind == "table" && name != "sqlite_schema" {
			tables = append(tables, name)
		}
	}
	err = rows.Err()
	if closeErr := rows.Close(); err != nil || closeErr != nil {
		return nil, errVaultMigrationSource
	}
	sort.Strings(tables)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("wormhole/v1/migration-source-database\x00"))
	budget := int64(maxMigrationSourceBytes)
	for _, query := range []string{
		"PRAGMA main.user_version", "PRAGMA main.application_id",
		"SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY type COLLATE BINARY,name COLLATE BINARY",
	} {
		if err := hashLegacyMigrationRows(reader, mac, query, &budget); err != nil {
			return nil, err
		}
	}
	for _, table := range tables {
		// Names originate in SQLite, but still require identifier quoting. No
		// renderer-provided SQL, views or virtual tables are executed here.
		query, err := legacyMigrationTableQuery(reader, table)
		if err != nil {
			return nil, err
		}
		readQuery := query
		if retired && strings.EqualFold(table, "CredentialSecrets") {
			readQuery += " LIMIT 0"
		}
		if err := hashLegacyMigrationRowsQuery(reader, mac, query, readQuery, &budget); err != nil {
			return nil, err
		}
	}
	if reader.ctx.Err() != nil {
		return nil, errVaultMigrationSource
	}
	return mac.Sum(nil), nil
}

func legacyMigrationTableQuery(reader resolverCaptureReader, table string) (string, error) {
	quote := func(value string) string { return `"` + strings.ReplaceAll(value, `"`, `""`) + `"` }
	rows, err := reader.Query("PRAGMA main.table_xinfo(" + quote(table) + ")")
	if err != nil {
		return "", errVaultMigrationSource
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var id, notNull, primary, hidden int
		var name, kind string
		var defaultValue any
		if rows.Scan(&id, &name, &kind, &notNull, &defaultValue, &primary, &hidden) != nil || hidden != 0 || len(name) > 1024 || len(columns) >= 128 {
			return "", errVaultMigrationSource
		}
		// Unary + preserves the SQLite storage value while removing the declared
		// column type, preventing driver DATE/BOOLEAN conversions from collapsing
		// distinct stored values. Generated expressions are rejected above.
		columns = append(columns, "+"+quote(name))
	}
	if rows.Err() != nil || rows.Close() != nil || len(columns) == 0 {
		return "", errVaultMigrationSource
	}
	return "SELECT " + strings.Join(columns, ",") + " FROM main." + quote(table) + " NOT INDEXED", nil
}

func hashLegacyMigrationRows(reader resolverCaptureReader, mac hash.Hash, query string, budget *int64) error {
	return hashLegacyMigrationRowsQuery(reader, mac, query, query, budget)
}

func hashLegacyMigrationRowsQuery(reader resolverCaptureReader, mac hash.Hash, query, readQuery string, budget *int64) error {
	if reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	rows, err := reader.Query(readQuery)
	if err != nil {
		return errVaultMigrationSource
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil || len(columns) == 0 || len(columns) > 128 {
		return errVaultMigrationSource
	}
	write := func(tag byte, data []byte) bool {
		*budget -= int64(len(data)) + 9
		if *budget < 0 {
			return false
		}
		var header [9]byte
		header[0] = tag
		binary.BigEndian.PutUint64(header[1:], uint64(len(data)))
		mac.Write(header[:])
		mac.Write(data)
		return true
	}
	if !write('q', []byte(query)) {
		return errVaultMigrationSource
	}
	values, targets := make([]any, len(columns)), make([]any, len(columns))
	defer func() {
		for i, value := range values {
			if raw, ok := value.([]byte); ok {
				clear(raw)
			}
			values[i] = nil
		}
	}()
	for i := range targets {
		targets[i] = &values[i]
		if !write('c', []byte(columns[i])) {
			return errVaultMigrationSource
		}
	}
	for count := 0; rows.Next(); count++ {
		if count >= 500000 || reader.ctx.Err() != nil || rows.Scan(targets...) != nil || !write('r', nil) {
			return errVaultMigrationSource
		}
		for i, value := range values {
			var number [8]byte
			var tag byte
			var raw []byte
			switch v := value.(type) {
			case nil:
				tag = 'n'
			case int64:
				tag = 'i'
				binary.BigEndian.PutUint64(number[:], uint64(v))
				raw = number[:]
			case float64:
				tag = 'f'
				binary.BigEndian.PutUint64(number[:], math.Float64bits(v))
				raw = number[:]
			case string:
				tag, raw = 's', []byte(v)
			case []byte:
				tag, raw = 'b', v
			default:
				return errVaultMigrationSource
			}
			ok := write(tag, raw)
			clear(raw)
			values[i] = nil
			if !ok {
				return errVaultMigrationSource
			}
		}
	}
	if rows.Err() != nil || rows.Close() != nil || !write('e', nil) {
		return errVaultMigrationSource
	}
	return nil
}
