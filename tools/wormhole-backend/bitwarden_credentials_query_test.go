package main

import (
	"database/sql"
	"testing"
)

func TestBitwardenCredentialMetadataQueryerErrors(t *testing.T) {
	for _, mode := range []string{"missing", "closed", "schema", "scan", "enumeration"} {
		t.Run(mode, func(t *testing.T) {
			db, err := sql.Open("sqlite", ":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			statement := ""
			switch mode {
			case "closed":
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := loadBitwardenCredentialCache(db); err == nil {
					t.Fatal("closed database accepted")
				}
			case "schema":
				statement = "CREATE TABLE BitwardenCredentialCache (ItemId TEXT)"
			case "scan", "enumeration":
				name := "NULL"
				if mode == "enumeration" {
					name = "json_extract('invalid-json','$')"
				}
				statement = "CREATE VIEW BitwardenCredentialCache AS SELECT 'item' AS ItemId,'ssh' AS SshCredentialId,'rdp' AS RdpCredentialId,'vnc' AS VncCredentialId," + name + " AS Name,NULL AS Username,NULL AS RevisionDate,'' AS LastSeenSyncUtc,'' AS UpdatedAtUtc"
			}
			if statement != "" {
				if _, err := db.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
			entries, err := loadBitwardenCredentialCacheFromQueryer(db)
			if mode == "missing" {
				if err != nil || len(entries) != 0 {
					t.Fatal("absent legacy cache", err)
				}
			} else if err == nil || entries != nil {
				t.Fatal("invalid cache returned partial metadata", entries, err)
			}
		})
	}
}

func TestBitwardenCredentialMetadataQueryerKeepsTransactionSnapshot(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := ensureBitwardenCredentialCacheSchema(db); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO BitwardenCredentialCache
 (ItemId,SshCredentialId,RdpCredentialId,VncCredentialId,Name,Username,RevisionDate,LastSeenSyncUtc,UpdatedAtUtc)
 VALUES ('item','ssh','rdp','vnc','Transaction account',NULL,NULL,'now','now')`); err != nil {
		t.Fatal(err)
	}
	entries, err := loadBitwardenCredentialCacheFromQueryer(tx)
	if err != nil || len(entries) != 1 || entries[0].Name != "Transaction account" || entries[0].Username != "" || entries[0].SmbCredentialID != bitwardenVirtualCredentialID("item", smbProtocolValue) {
		t.Fatal("transaction metadata", entries, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	entries, err = loadBitwardenCredentialCache(db)
	if err != nil || len(entries) != 0 {
		t.Fatal("metadata reader escaped transaction", entries, err)
	}
}
