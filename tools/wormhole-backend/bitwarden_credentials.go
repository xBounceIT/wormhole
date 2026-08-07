package main

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const bitwardenVirtualCredentialNamespace = "wormhole-bitwarden-virtual-credential-v1"

type bitwardenCredentialCacheEntry struct {
	ItemID          string
	SshCredentialID string
	RdpCredentialID string
	VncCredentialID string
	Name            string
	Username        string
	RevisionDate    string
	LastSeenSyncUTC string
	UpdatedAtUTC    string
}

type bitwardenCredentialReference struct {
	ItemID   string
	ItemName string
	Username string
	Domain   string
	Protocol int64
	Virtual  bool
}

func ensureBitwardenCredentialCacheSchema(database *sql.DB) error {
	_, err := database.Exec(`
CREATE TABLE IF NOT EXISTS BitwardenCredentialCache (
    ItemId             TEXT PRIMARY KEY NOT NULL,
    SshCredentialId    TEXT NOT NULL,
    RdpCredentialId    TEXT NOT NULL,
    VncCredentialId    TEXT NOT NULL,
    Name               TEXT NOT NULL,
    Username           TEXT NULL,
    RevisionDate       TEXT NULL,
    LastSeenSyncUtc    TEXT NOT NULL,
    UpdatedAtUtc       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS IX_BitwardenCredentialCache_Name
    ON BitwardenCredentialCache(Name);`)
	if err != nil {
		return fmt.Errorf("could not create the Bitwarden credential cache: %w", err)
	}
	return nil
}

func replaceBitwardenCredentialCache(
	databasePath string,
	items []bitwardenCliLoginItem,
	syncTime time.Time,
) (int, error) {
	database, err := openDatabase(databasePath, false)
	if err != nil {
		return 0, err
	}
	defer database.Close()
	if err := ensureBitwardenCredentialCacheSchema(database); err != nil {
		return 0, err
	}

	byID := make(map[string]bitwardenCliLoginItem, len(items))
	for _, item := range items {
		item.ID = strings.TrimSpace(item.ID)
		if item.ID == "" {
			continue
		}
		item.Name = strings.TrimSpace(item.Name)
		if item.Name == "" {
			item.Name = item.ID
		}
		item.Username = strings.TrimSpace(item.Username)
		item.RevisionDate = strings.TrimSpace(item.RevisionDate)
		byID[item.ID] = item
	}

	tx, err := database.Begin()
	if err != nil {
		return 0, fmt.Errorf("could not start the Bitwarden cache update: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	stamp := syncTime.UTC().Format(time.RFC3339Nano)
	// Mark the previous generation before applying the new one. This keeps pruning correct even
	// when a deterministic caller supplies the same timestamp for two consecutive full syncs.
	if _, err := tx.Exec("UPDATE BitwardenCredentialCache SET LastSeenSyncUtc = ''; "); err != nil {
		return 0, fmt.Errorf("could not prepare the Bitwarden credential cache: %w", err)
	}
	for _, item := range byID {
		_, err = tx.Exec(`
INSERT INTO BitwardenCredentialCache
    (ItemId, SshCredentialId, RdpCredentialId, VncCredentialId,
     Name, Username, RevisionDate, LastSeenSyncUtc, UpdatedAtUtc)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(ItemId) DO UPDATE SET
    SshCredentialId = excluded.SshCredentialId,
    RdpCredentialId = excluded.RdpCredentialId,
    VncCredentialId = excluded.VncCredentialId,
    Name = excluded.Name,
    Username = excluded.Username,
    RevisionDate = excluded.RevisionDate,
    LastSeenSyncUtc = excluded.LastSeenSyncUtc,
    UpdatedAtUtc = excluded.UpdatedAtUtc;`,
			item.ID,
			bitwardenVirtualCredentialID(item.ID, 0),
			bitwardenVirtualCredentialID(item.ID, 1),
			bitwardenVirtualCredentialID(item.ID, 6),
			item.Name,
			nullableCredentialField(item.Username),
			nullableCredentialField(item.RevisionDate),
			stamp,
			stamp,
		)
		if err != nil {
			return 0, fmt.Errorf("could not update the Bitwarden credential cache: %w", err)
		}
	}
	// Every row seen in this full sync was stamped above. Pruning by the stamp avoids a
	// parameter per vault item, which otherwise fails once a large vault exceeds SQLite's
	// host-parameter limit.
	if _, err := tx.Exec(
		"DELETE FROM BitwardenCredentialCache WHERE LastSeenSyncUtc <> ?;",
		stamp,
	); err != nil {
		return 0, fmt.Errorf("could not prune the Bitwarden credential cache: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("could not save the Bitwarden credential cache: %w", err)
	}
	committed = true
	return len(byID), nil
}

func loadBitwardenCredentialCache(database *sql.DB) ([]bitwardenCredentialCacheEntry, error) {
	exists, err := tableExists(database, "BitwardenCredentialCache")
	if err != nil || !exists {
		return []bitwardenCredentialCacheEntry{}, err
	}
	rows, err := database.Query(`
SELECT ItemId, SshCredentialId, RdpCredentialId, VncCredentialId,
       Name, Username, RevisionDate, LastSeenSyncUtc, UpdatedAtUtc
FROM BitwardenCredentialCache
ORDER BY Name, ItemId;`)
	if err != nil {
		return nil, fmt.Errorf("cannot read the Bitwarden credential cache: %w", err)
	}
	defer rows.Close()
	entries := make([]bitwardenCredentialCacheEntry, 0)
	for rows.Next() {
		var entry bitwardenCredentialCacheEntry
		var username, revision sql.NullString
		if err := rows.Scan(
			&entry.ItemID,
			&entry.SshCredentialID,
			&entry.RdpCredentialID,
			&entry.VncCredentialID,
			&entry.Name,
			&username,
			&revision,
			&entry.LastSeenSyncUTC,
			&entry.UpdatedAtUTC,
		); err != nil {
			return nil, fmt.Errorf("cannot read a Bitwarden credential cache entry: %w", err)
		}
		entry.Username = nullableString(username)
		entry.RevisionDate = nullableString(revision)
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot enumerate the Bitwarden credential cache: %w", err)
	}
	return entries, nil
}

// new Guid(hash[..16]) in .NET interprets the first 4+2+2 bytes as little-endian fields. Preserve
// that exact representation so connections created by WinUI and Electron resolve the same virtual
// credential identifiers from the shared SQLite database.
func bitwardenVirtualCredentialID(itemID string, protocol int64) string {
	protocolName := "Ssh"
	switch protocol {
	case 1:
		protocolName = "Rdp"
	case 6:
		protocolName = "Vnc"
	}
	material := fmt.Sprintf(
		"%s:%s:%s",
		bitwardenVirtualCredentialNamespace,
		protocolName,
		strings.TrimSpace(itemID),
	)
	hash := sha256.Sum256([]byte(material))
	b := hash[:16]
	return fmt.Sprintf(
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[3], b[2], b[1], b[0],
		b[5], b[4],
		b[7], b[6],
		b[8], b[9],
		b[10], b[11], b[12], b[13], b[14], b[15],
	)
}

func resolveBitwardenCredentialReference(
	database *sql.DB,
	credentialID string,
	protocol int64,
) (bitwardenCredentialReference, bool, error) {
	id := normalizeID(credentialID)
	if id == "" {
		return bitwardenCredentialReference{}, false, nil
	}
	columns, err := tableColumns(database, "CredentialProfiles")
	if err != nil {
		return bitwardenCredentialReference{}, false, err
	}
	if len(columns) > 0 {
		column := func(name, fallback string) string {
			if _, ok := columns[name]; ok {
				return name
			}
			return fallback
		}
		var provider, storedProtocol sql.NullInt64
		var itemID, itemName, username, domain sql.NullString
		err := database.QueryRow(
			"SELECT "+column("SecretProvider", "0")+", "+column("Protocol", "0")+", "+
				column("BitwardenItemId", "NULL")+", "+column("BitwardenItemName", "NULL")+", "+
				column("Username", "NULL")+", "+column("Domain", "NULL")+
				" FROM CredentialProfiles WHERE lower(Id) = ? LIMIT 1;",
			id,
		).Scan(&provider, &storedProtocol, &itemID, &itemName, &username, &domain)
		if err == nil {
			if !provider.Valid || provider.Int64 != 1 {
				return bitwardenCredentialReference{}, false, nil
			}
			if storedProtocol.Valid && storedProtocol.Int64 != protocol {
				return bitwardenCredentialReference{}, false, errors.New("the selected Bitwarden credential has the wrong protocol")
			}
			if strings.TrimSpace(nullableString(itemID)) == "" {
				return bitwardenCredentialReference{}, false, errors.New("the selected Bitwarden credential is missing its item reference")
			}
			return bitwardenCredentialReference{
				ItemID:   strings.TrimSpace(nullableString(itemID)),
				ItemName: strings.TrimSpace(nullableString(itemName)),
				Username: strings.TrimSpace(nullableString(username)),
				Domain:   strings.TrimSpace(nullableString(domain)),
				Protocol: protocol,
			}, true, nil
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return bitwardenCredentialReference{}, false, fmt.Errorf("cannot read the Bitwarden credential: %w", err)
		}
	}

	cacheColumns, err := tableColumns(database, "BitwardenCredentialCache")
	if err != nil || len(cacheColumns) == 0 {
		return bitwardenCredentialReference{}, false, err
	}
	credentialColumn := "SshCredentialId"
	switch protocol {
	case 1:
		credentialColumn = "RdpCredentialId"
	case 6:
		credentialColumn = "VncCredentialId"
	}
	var reference bitwardenCredentialReference
	var username sql.NullString
	err = database.QueryRow(
		"SELECT ItemId, Name, Username FROM BitwardenCredentialCache WHERE lower("+credentialColumn+") = ? LIMIT 1;",
		id,
	).Scan(&reference.ItemID, &reference.ItemName, &username)
	if errors.Is(err, sql.ErrNoRows) {
		return bitwardenCredentialReference{}, false, nil
	}
	if err != nil {
		return bitwardenCredentialReference{}, false, fmt.Errorf("cannot read the virtual Bitwarden credential: %w", err)
	}
	reference.Username = strings.TrimSpace(nullableString(username))
	reference.Protocol = protocol
	reference.Virtual = true
	return reference, true, nil
}
