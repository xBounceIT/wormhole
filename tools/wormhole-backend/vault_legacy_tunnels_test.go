package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func legacyVaultTunnelRow(t *testing.T, db *sql.DB, id string, kind int) {
	t.Helper()
	legacyVaultSQL(t, db, `INSERT INTO TunnelConfigs(Id,Name,Kind,CreatedAt,UpdatedAt) VALUES(?,?,?,'2020-01-02T04:04:05+01:00','2023-02-03T04:05:06.000Z')`, id, "Tunnel "+id, kind)
}

func TestVaultLegacyTunnelTransferProvidersAndLifetime(t *testing.T) {
	configs := []string{
		`{"InterfacePrivateKey":"private-fixture","InterfaceAddress":"10.0.0.2","PeerPublicKey":"public-fixture","PeerEndpoint":"example.test:1234"}`,
		`{"ProfileOvpn":"private-profile-fixture"}`,
		`{"Host":"example.test","Username":"user","Password":"password-fixture"}`,
		`{"Server":"example.test","UseSingleSignOn":true,"Username":"old-user","Password":"old-secret-fixture"}`,
		`{"Mode":1,"ProfileOvpn":"watchguard-profile-fixture"}`,
		`{"TenantId":"tenant","Audience":"audience","Servers":["gateway.example"],"ServerSecretHex":"` + strings.Repeat("a", 512) + `"}`,
		`{"Host":"example.test","Username":"user","Password":"password-fixture"}`,
		`{"Host":"example.test","Username":"user","Password":"password-fixture","ServerCertSha256Pin":"` + strings.Repeat("ab", 32) + `"}`,
		`{"Mode":"connection","JumpConnectionId":"abcdefab-0000-4000-8000-000000000001"}`,
		`{"Host":"ipsec.test","PreSharedKey":"ipsec-private-fixture","UserAuth":0}`,
	}
	db, path := snapshotDatabase(t)
	legacyVaultSecrets(t, db)
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	want := map[string]string{}
	paths := map[string]string{}
	kinds := map[string]int{}
	for kind, config := range configs {
		id := uuid.NewString()
		legacyVaultTunnelRow(t, db, strings.ToUpper(id), kind)
		want[id] = config
		kinds[id] = kind
		if kind%2 == 0 {
			paths[legacyTunnelSecretPath(path, id)] = id
		} else {
			legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,'cipher','fixture','now')`, tunnelSecretID(id))
		}
	}
	var borrowed [][]byte
	readers := legacyVaultTunnelReaders{
		protected: func(p string, max int64) ([]byte, error) {
			if max != maxTunnelProtectedBytes {
				t.Fatal("unbounded protected read")
			}
			if paths[p] == "" {
				return nil, os.ErrNotExist
			}
			v := []byte("protected fixture")
			borrowed = append(borrowed, v)
			return v, nil
		},
		file: func(p string, _ []byte) ([]byte, error) {
			v := []byte(want[paths[p]])
			borrowed = append(borrowed, v)
			return v, nil
		},
		row: func(id, encoded, encoding string, userData ...string) ([]byte, error) {
			if encoded != "cipher" || encoding != "fixture" || len(userData) != 1 || userData[0] != "source-data" {
				t.Fatal("wrong row source")
			}
			v := []byte(want[strings.TrimPrefix(id, tunnelSecretPrefix)])
			borrowed = append(borrowed, v)
			return v, nil
		},
	}
	count := 0
	err := readLegacyVaultTunnels(resolverCaptureReader{ctx, db}, path, "source-data", readers, func(record legacyVaultTunnel, value []byte) error {
		count++
		id := record.Metadata.ID
		if record.Metadata.Kind != kinds[id] || string(value) != want[id] || record.ProtectedFile != (kinds[id]%2 == 0) || record.LegacyRow != (kinds[id]%2 != 0) {
			t.Fatal("provider bytes or provenance changed")
		}
		if record.Times.CreatedAt != "2020-01-02T03:04:05Z" || record.Times.UpdatedAt != "2023-02-03T04:05:06Z" {
			t.Fatal("source time changed")
		}
		_, err := h.owner.ImportTunnel(ctx, record.Metadata, value, record.Times)
		return err
	})
	if err != nil || count != len(configs) {
		t.Fatal(err, count)
	}
	for _, value := range borrowed {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("borrowed data retained")
		}
	}
	for id, want := range want {
		if err := h.owner.WithTunnelConfiguration(ctx, id, 1, func(value []byte) error {
			if string(value) != want {
				t.Fatal("stored provider bytes changed")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, suffix := range []string{"", "-wal"} {
		data, err := os.ReadFile(h.databasePath + suffix)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("password-fixture")) || bytes.Contains(data, []byte("private-fixture")) || bytes.Contains(data, []byte("old-secret-fixture")) {
			t.Fatal("provider plaintext persisted")
		}
	}
}

func TestVaultLegacyTunnelSourceFailuresAndWiping(t *testing.T) {
	for _, mode := range []string{"missing", "file-error", "empty-file", "large-file", "file-decrypt-error", "file-invalid", "row-error", "row-invalid", "both-equal", "both-different", "cancel-file-read", "cancel-file-decrypt", "cancel-row-decrypt", "sink-error", "cancel-sink"} {
		t.Run(mode, func(t *testing.T) {
			db, path := snapshotDatabase(t)
			legacyVaultSecrets(t, db)
			id := uuid.NewString()
			legacyVaultTunnelRow(t, db, id, 1)
			useRow := strings.HasPrefix(mode, "row-") || strings.HasPrefix(mode, "both-") || mode == "cancel-row-decrypt"
			if useRow || mode == "file-error" || mode == "file-decrypt-error" {
				legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,'cipher','fixture','now')`, tunnelSecretID(id))
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			protected := []byte("protected fixture")
			plain := []byte(`{"ProfileOvpn":"private fixture"}`)
			row := bytes.Clone(plain)
			if mode == "empty-file" {
				protected = []byte{}
			}
			if mode == "large-file" {
				protected = bytes.Repeat([]byte{'x'}, maxTunnelProtectedBytes+1)
			}
			if mode == "file-invalid" {
				plain = []byte(`{"ProfileOvpn":"a","ProfileOvpn":"b"}`)
			}
			if mode == "row-invalid" {
				row = []byte(`{}`)
			}
			if mode == "both-different" {
				row = []byte(`{"ProfileOvpn":"other"}`)
			}
			fileCalled, rowCalled, sinkCalled := false, false, false
			sentinel := errors.New("sink error")
			readers := legacyVaultTunnelReaders{
				protected: func(string, int64) ([]byte, error) {
					if mode == "cancel-file-read" {
						cancel()
					}
					if mode == "missing" || (useRow && !strings.HasPrefix(mode, "both-")) {
						return nil, os.ErrNotExist
					}
					if mode == "file-error" {
						return protected, errors.New("private path failure")
					}
					return protected, nil
				},
				file: func(string, []byte) ([]byte, error) {
					fileCalled = true
					if mode == "cancel-file-decrypt" {
						cancel()
					}
					if mode == "file-decrypt-error" {
						return plain, errors.New("private decrypt failure")
					}
					return plain, nil
				},
				row: func(string, string, string, ...string) ([]byte, error) {
					rowCalled = true
					if mode == "cancel-row-decrypt" {
						cancel()
					}
					if mode == "row-error" {
						return row, errors.New("private row failure")
					}
					return row, nil
				},
			}
			err := readLegacyVaultTunnels(resolverCaptureReader{ctx, db}, path, "", readers, func(record legacyVaultTunnel, value []byte) error {
				sinkCalled = true
				if mode == "both-equal" {
					if !record.ProtectedFile || !record.LegacyRow || string(value) != `{"ProfileOvpn":"private fixture"}` {
						t.Fatal("dual source provenance changed")
					}
					return nil
				}
				if mode == "cancel-sink" {
					cancel()
					return nil
				}
				return sentinel
			})
			want := errVaultMigrationSource
			if mode == "both-equal" {
				want = nil
			}
			if mode == "sink-error" {
				want = sentinel
			}
			if err != want || sinkCalled != (mode == "both-equal" || mode == "sink-error" || mode == "cancel-sink") {
				t.Fatal("wrong failure behavior", err, sinkCalled)
			}
			if (mode == "file-error" || mode == "file-decrypt-error") && rowCalled {
				t.Fatal("corrupt file fell back")
			}
			if mode == "cancel-file-read" && fileCalled {
				t.Fatal("cancelled file read decrypted")
			}
			if fileCalled && !bytes.Equal(plain, make([]byte, len(plain))) || rowCalled && !bytes.Equal(row, make([]byte, len(row))) {
				t.Fatal("plaintext not wiped")
			}
			if !useRow && mode != "missing" && !bytes.Equal(protected, make([]byte, len(protected))) {
				t.Fatal("protected buffer not wiped")
			}
		})
	}
}

func TestVaultLegacyTunnelPagingAndValidation(t *testing.T) {
	for _, mode := range []string{"valid", "duplicate", "empty-id", "invalid-name", "invalid-kind", "invalid-time", "null-kind", "pending-journal", "missing-table"} {
		t.Run(mode, func(t *testing.T) {
			db, path := snapshotDatabase(t)
			for i := 0; i < 130; i++ {
				legacyVaultTunnelRow(t, db, fmt.Sprintf("00000000-0000-4000-8000-%012x", i), 1)
			}
			id := "00000000-0000-4000-8000-00000000003f"
			switch mode {
			case "duplicate":
				legacyVaultTunnelRow(t, db, strings.ToUpper(id), 1)
			case "empty-id":
				legacyVaultSQL(t, db, "UPDATE TunnelConfigs SET Id='' WHERE Id=?", id)
			case "invalid-name":
				legacyVaultSQL(t, db, "UPDATE TunnelConfigs SET Name=? WHERE Id=?", "a\x00b", id)
			case "invalid-kind":
				legacyVaultSQL(t, db, "UPDATE TunnelConfigs SET Kind=99 WHERE Id=?", id)
			case "invalid-time":
				legacyVaultSQL(t, db, "UPDATE TunnelConfigs SET CreatedAt='bad' WHERE Id=?", id)
			case "null-kind":
				legacyVaultSQL(t, db, "UPDATE TunnelConfigs SET Kind='nonnumeric' WHERE Id=?", id)
			case "pending-journal":
				legacyVaultSQL(t, db, "DROP TABLE IF EXISTS CredentialSecretOperations")
				legacyVaultSQL(t, db, "CREATE TABLE CredentialSecretOperations(Id TEXT)")
				legacyVaultSQL(t, db, "INSERT INTO CredentialSecretOperations VALUES('pending')")
			case "missing-table":
				legacyVaultSQL(t, db, "DROP TABLE TunnelConfigs")
			}
			count := 0
			readers := legacyVaultTunnelReaders{protected: func(string, int64) ([]byte, error) { return []byte("protected"), nil }, file: func(string, []byte) ([]byte, error) { return []byte(`{"ProfileOvpn":"profile"}`), nil }, row: func(string, string, string, ...string) ([]byte, error) {
				t.Fatal("unexpected fallback")
				return nil, nil
			}}
			err := readLegacyVaultTunnels(resolverCaptureReader{context.Background(), db}, path, "", readers, func(legacyVaultTunnel, []byte) error { count++; return nil })
			if mode == "valid" {
				if err != nil || count != 130 {
					t.Fatal(err, count)
				}
			} else if err != errVaultMigrationSource {
				t.Fatal("invalid source accepted", err)
			}
		})
	}
}

func TestVaultLegacyTunnelBoundaries(t *testing.T) {
	db, path := snapshotDatabase(t)
	reader := resolverCaptureReader{context.Background(), db}
	if err := visitLegacyVaultTunnels(reader, path, "", func(legacyVaultTunnel, []byte) error { t.Fatal("empty source produced value"); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := visitLegacyVaultTunnels(reader, "relative.db", "", nil); err != errVaultMigrationSource {
		t.Fatal(err)
	}
	for _, max := range []int{0, -1, 6*1024*1024 + 1} {
		if _, _, _, err := readLegacyVaultSecretRowLimit(reader, uuid.NewString(), max); err != errVaultMigrationSource {
			t.Fatal("invalid encoded bound")
		}
	}
	for _, max := range []int{0, -1, backendMaxTunnelRequestBytes + 1} {
		if v, err := unprotectStoredValue("id", "cipher", "unknown", max); err == nil || v != nil {
			t.Fatal("invalid plaintext bound")
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := visitLegacyVaultTunnels(reader, path, "", func(legacyVaultTunnel, []byte) error { return nil }); err != errVaultMigrationSource {
		t.Fatal("source error escaped", err)
	}
}
