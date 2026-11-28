package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func legacyVaultNodeRow(t *testing.T, db *sql.DB, id string, parent any, kind int) {
	t.Helper()
	legacyVaultSQL(t, db, `INSERT INTO Nodes(Id,ParentId,Name,Kind,CreatedAt,UpdatedAt) VALUES(?,?,?,?,'2020-01-02T04:04:05+01:00','2023-02-03T04:05:06.123456700Z')`, id, parent, "Node "+id, kind)
}

type legacyNodeIndexAudit struct {
	*sql.DB
	checked int
}

func (a *legacyNodeIndexAudit) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if strings.Contains(query, " FROM Nodes WHERE ") {
		rows, err := a.DB.QueryContext(ctx, "EXPLAIN QUERY PLAN "+query, args...)
		if err != nil {
			return nil, err
		}
		indexed := false
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				rows.Close()
				return nil, err
			}
			if strings.HasPrefix(detail, "SEARCH Nodes ") {
				indexed = true
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		if !indexed {
			return nil, errors.New("node lookup scanned the source table")
		}
		a.checked++
	}
	return a.DB.QueryContext(ctx, query, args...)
}

func TestVaultLegacyNodeTransferAllFieldsAndSecrets(t *testing.T) {
	db, _ := snapshotDatabase(t)
	legacyVaultSecrets(t, db)
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	parent, child, empty := uuid.NewString(), uuid.NewString(), uuid.NewString()
	legacyVaultNodeRow(t, db, parent, nil, 0)
	legacyVaultNodeRow(t, db, child, parent, 1)
	legacyVaultNodeRow(t, db, empty, parent, 1)
	// Set each nullable source field to a distinctive explicit value. Compare
	// every JSON field with an independently built expectation, not scan targets.
	p := func(v string) *string { return &v }
	pi := func(v int) *int { return &v }
	pb := func(v bool) *bool { return &v }
	want := vaultstore.NodeMetadata{ID: child, ParentID: p(parent), Name: "Imported connection", Kind: 1, SortOrder: -17, Protocol: pi(1), Host: p("host.example"), Port: pi(0), HTTPPath: p("/path"), Username: p("alice"), CredentialMode: pi(1), UseInlinePassword: pb(true), SshAutoSudo: pb(false), HTTPIgnoreCertErrors: pb(true), TunnelEnabled: pb(false), SerialBaudRate: pi(115200), SerialDataBits: pi(7), SerialStopBits: pi(2), SerialParity: pi(3), SerialFlowControl: pi(2), SshKeyFileName: p("display-key"), SshKnownHostFingerprint: p("SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))), RDPDomain: p("DOMAIN"), RDPScreenSize: p("1280x720"), RDPFullScreen: pb(false), RDPColorDepth: pi(24), RDPUseAllMonitors: pb(true), RDPAudioMode: pi(1), RDPAudioCaptureMode: pi(0), RDPKeyboardHookMode: pi(2), RDPRedirectClipboard: pb(true), RDPRedirectPrinters: pb(false), RDPRedirectSmartCards: pb(true), RDPRedirectPorts: pb(false), RDPRedirectDevices: pb(true), RDPRedirectDrives: p("C:;D:"), RDPConnectionSpeed: pi(5), RDPDesktopBackground: pb(false), RDPFontSmoothing: pb(true), RDPDesktopComposition: pb(false), RDPWindowDrag: pb(true), RDPMenuAnimation: pb(false), RDPVisualStyles: pb(true), RDPBitmapCaching: pb(false), RDPAutoReconnect: pb(true), RDPServerAuthentication: pi(2), RDPGatewayUsageMethod: pi(0), RDPGatewayHostname: p("gateway.example"), RDPGatewayBypassLocal: pb(true), RDPGatewayUseSameCreds: pb(false), RDPUseExternalClient: pb(true)}
	legacyVaultSQL(t, db, `UPDATE Nodes SET Name='Imported connection',SortOrder=-17,Protocol=1,Host='host.example',Port=0,HttpPath='/path',Username='alice',CredentialMode=1,UseInlinePassword=1,SshAutoSudo=0,HttpIgnoreCertErrors=1,TunnelEnabled=0,SerialBaudRate=115200,SerialDataBits=7,SerialStopBits=2,SerialParity=3,SerialFlowControl=2,SshKeyFileName='display-key',SshKnownHostFingerprint=?,RdpDomain='DOMAIN',RdpScreenSize='1280x720',RdpFullScreen=0,RdpColorDepth=24,RdpUseAllMonitors=1,RdpAudioMode=1,RdpAudioCaptureMode=0,RdpKeyboardHookMode=2,RdpRedirectClipboard=1,RdpRedirectPrinters=0,RdpRedirectSmartCards=1,RdpRedirectPorts=0,RdpRedirectDevices=1,RdpRedirectDrives='C:;D:',RdpConnectionSpeed=5,RdpDesktopBackground=0,RdpFontSmoothing=1,RdpDesktopComposition=0,RdpWindowDrag=1,RdpMenuAnimation=0,RdpVisualStyles=1,RdpBitmapCaching=0,RdpAutoReconnect=1,RdpServerAuthentication=2,RdpGatewayUsageMethod=0,RdpGatewayHostname='gateway.example',RdpGatewayBypassLocal=1,RdpGatewayUseSameCreds=0,RdpUseExternalClient=1,Notes='private note fixture' WHERE Id=?`, *want.SshKnownHostFingerprint, child)
	legacyVaultSQL(t, db, `UPDATE Nodes SET Notes='',Username='',Port=0,UseInlinePassword=0 WHERE Id=?`, empty)
	legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,'cipher','fixture','now')`, child)
	secret := []byte("private inline fixture")
	var borrowed [][]byte
	seen := map[string]bool{}
	audit := &legacyNodeIndexAudit{DB: db}
	err := readLegacyVaultNodes(resolverCaptureReader{ctx, audit}, "user-data", func(id, encoded, encoding string, paths ...string) ([]byte, error) {
		if id != child || encoded != "cipher" || encoding != "fixture" || len(paths) != 1 || paths[0] != "user-data" {
			t.Fatal("wrong secret source")
		}
		return secret, nil
	}, func(record legacyVaultNode, changes []localvault.SecretChange) error {
		if record.Metadata.ParentID != nil && !seen[*record.Metadata.ParentID] {
			t.Fatal("child before parent")
		}
		seen[record.Metadata.ID] = true
		if record.Metadata.ID == child && !reflect.DeepEqual(record.Metadata, want) {
			t.Fatalf("metadata changed: got %#v", record.Metadata)
		}
		if record.Times.CreatedAt != "2020-01-02T03:04:05Z" || record.Times.UpdatedAt != "2023-02-03T04:05:06.1234567Z" {
			t.Fatal("time changed")
		}
		for _, c := range changes {
			borrowed = append(borrowed, c.Value)
		}
		_, err := h.owner.ImportNode(ctx, record.Metadata, changes, record.Times)
		return err
	})
	if err != nil || len(seen) != 3 || audit.checked != 3 {
		t.Fatal(err, len(seen))
	}
	for _, v := range borrowed {
		if !bytes.Equal(v, make([]byte, len(v))) {
			t.Fatal("plaintext retained")
		}
	}
	for _, item := range []struct{ id, field, want string }{{child, "notes", "private note fixture"}, {child, "inlinePassword", "private inline fixture"}, {empty, "notes", ""}} {
		if err := h.owner.WithNodeField(ctx, item.id, item.field, 1, func(value []byte) error {
			if string(value) != item.want {
				t.Fatal("sealed field changed")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.owner.WithNodeField(ctx, parent, "notes", 1, func([]byte) error { t.Fatal("invented absent note"); return nil }); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	got, err := h.owner.ReadNode(ctx, empty, 1)
	if err != nil || got.Username == nil || *got.Username != "" || got.Port == nil || *got.Port != 0 || got.UseInlinePassword == nil || *got.UseInlinePassword {
		t.Fatal("empty/NULL/false changed", err)
	}
	for _, suffix := range []string{"", "-wal"} {
		data, err := os.ReadFile(h.databasePath + suffix)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("private note fixture")) || bytes.Contains(data, []byte("private inline fixture")) {
			t.Fatal("plaintext persisted")
		}
	}
	var source string
	if err := db.QueryRow("SELECT Notes FROM Nodes WHERE Id=?", child).Scan(&source); err != nil || source != "private note fixture" {
		t.Fatal("source mutated", err)
	}
}

func TestVaultLegacyNodeTopologyBeforeSecrets(t *testing.T) {
	for _, mode := range []string{"cycle", "orphan", "connection-parent", "duplicate", "empty-parent", "invalid-id", "invalid-kind", "depth128", "depth129"} {
		t.Run(mode, func(t *testing.T) {
			db, _ := snapshotDatabase(t)
			a, b := "abcdefab-0000-4000-8000-000000000001", "abcdefab-0000-4000-8000-000000000002"
			legacyVaultNodeRow(t, db, a, nil, 0)
			legacyVaultNodeRow(t, db, b, a, 0)
			switch mode {
			case "cycle":
				legacyVaultSQL(t, db, "UPDATE Nodes SET ParentId=? WHERE Id=?", b, a)
			case "orphan":
				legacyVaultSQL(t, db, "PRAGMA foreign_keys=OFF")
				legacyVaultSQL(t, db, "UPDATE Nodes SET ParentId=? WHERE Id=?", uuid.NewString(), b)
			case "connection-parent":
				legacyVaultSQL(t, db, "UPDATE Nodes SET Kind=1 WHERE Id=?", a)
			case "duplicate":
				legacyVaultNodeRow(t, db, strings.ToUpper(a), nil, 0)
			case "empty-parent":
				legacyVaultSQL(t, db, "PRAGMA foreign_keys=OFF")
				legacyVaultSQL(t, db, "UPDATE Nodes SET ParentId='' WHERE Id=?", b)
			case "invalid-id":
				legacyVaultNodeRow(t, db, "invalid", nil, 0)
			case "invalid-kind":
				legacyVaultSQL(t, db, "UPDATE Nodes SET Kind=7 WHERE Id=?", b)
			case "depth128", "depth129":
				depth := 128
				if mode == "depth129" {
					depth = 129
				}
				last := b
				for i := 2; i < depth; i++ {
					id := fmt.Sprintf("00000000-0000-4000-8000-%012x", i)
					legacyVaultNodeRow(t, db, id, last, 0)
					last = id
				}
			}
			count := 0
			err := readLegacyVaultNodes(resolverCaptureReader{context.Background(), db}, "", func(string, string, string, ...string) ([]byte, error) {
				t.Fatal("invalid graph decrypted")
				return nil, nil
			}, func(legacyVaultNode, []localvault.SecretChange) error { count++; return nil })
			if mode == "depth128" {
				if err != nil || count != 128 {
					t.Fatal(err, count)
				}
			} else if err != errVaultMigrationSource || count != 0 {
				t.Fatal("invalid graph reached sink", err, count)
			}
		})
	}
}

func TestVaultLegacyNodeErrorsAndBorrowLifetime(t *testing.T) {
	for _, mode := range []string{"missing-secret", "duplicate-secret", "bad-note", "huge-note", "bad-time", "bad-metadata", "bad-bool", "decrypt-error", "oversize-secret", "cancel-decrypt", "cancel-sink", "sink-error"} {
		t.Run(mode, func(t *testing.T) {
			db, _ := snapshotDatabase(t)
			legacyVaultSecrets(t, db)
			id := "abcdefab-0000-4000-8000-000000000001"
			legacyVaultNodeRow(t, db, id, nil, 1)
			legacyVaultSQL(t, db, "UPDATE Nodes SET Protocol=0,UseInlinePassword=1,Notes='borrowed note'")
			if mode != "missing-secret" {
				legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,'cipher','fixture','now')`, id)
			}
			switch mode {
			case "duplicate-secret":
				legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,'cipher','fixture','now')`, strings.ToUpper(id))
			case "bad-note":
				legacyVaultSQL(t, db, "UPDATE Nodes SET Notes=?", "a\x00b")
			case "huge-note":
				legacyVaultSQL(t, db, "UPDATE Nodes SET Notes=?", strings.Repeat("a", 16385))
			case "bad-time":
				legacyVaultSQL(t, db, "UPDATE Nodes SET CreatedAt='not-time'")
			case "bad-metadata":
				legacyVaultSQL(t, db, "UPDATE Nodes SET Name=?", "a\x00b")
			case "bad-bool":
				legacyVaultSQL(t, db, "UPDATE Nodes SET SshAutoSudo=2")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			secret := []byte("temporary plaintext")
			if mode == "oversize-secret" {
				secret = bytes.Repeat([]byte{'x'}, maxStoredCredentialBytes+1)
			}
			decrypted, called := false, false
			var borrowed [][]byte
			sentinel := errors.New("sink failure")
			err := readLegacyVaultNodes(resolverCaptureReader{ctx, db}, "", func(string, string, string, ...string) ([]byte, error) {
				decrypted = true
				if mode == "cancel-decrypt" {
					cancel()
				}
				if mode == "decrypt-error" {
					return secret, errors.New("sensitive detail")
				}
				return secret, nil
			}, func(_ legacyVaultNode, changes []localvault.SecretChange) error {
				called = true
				for _, c := range changes {
					borrowed = append(borrowed, c.Value)
				}
				if mode == "cancel-sink" {
					cancel()
					return nil
				}
				return sentinel
			})
			want := errVaultMigrationSource
			if mode == "sink-error" {
				want = sentinel
			}
			if err != want || called != (mode == "sink-error" || mode == "cancel-sink") {
				t.Fatal("wrong failure behavior", err, called)
			}
			if decrypted && !bytes.Equal(secret, make([]byte, len(secret))) {
				t.Fatal("decrypted error buffer not wiped")
			}
			for _, v := range borrowed {
				if !bytes.Equal(v, make([]byte, len(v))) {
					t.Fatal("sink buffer not wiped")
				}
			}
		})
	}
}

func TestVaultLegacyNodeSourceContractAndTimes(t *testing.T) {
	db, _ := snapshotDatabase(t)
	reader := resolverCaptureReader{context.Background(), db}
	if err := visitLegacyVaultNodes(reader, "", func(legacyVaultNode, []localvault.SecretChange) error {
		t.Fatal("empty source produced row")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := visitLegacyVaultNodes(reader, "", nil); err != errVaultMigrationSource {
		t.Fatal(err)
	}
	columns, err := tableColumns(reader, "Nodes")
	if err != nil {
		t.Fatal(err)
	}
	// The complete current legacy schema must be represented: 54 metadata
	// columns plus Notes, CreatedAt and UpdatedAt; owner/slot IDs are new only.
	cols, targets := legacyVaultNodeColumns(&vaultstore.NodeMetadata{})
	if len(columns) != len(cols)+3 || len(cols) != len(targets) {
		t.Fatal("unmapped legacy column", len(columns), len(cols))
	}
	for _, pair := range [][2]string{{"bad", "2020-01-01T00:00:00Z"}, {"2020-01-01T00:00:00Z", strings.Repeat("x", 129)}, {"9999-12-31T23:59:59-01:00", "2020-01-01T00:00:00Z"}} {
		if _, err := legacyVaultTimes(pair[0], pair[1]); err != errVaultMigrationSource {
			t.Fatal("invalid timestamp accepted")
		}
	}
	legacyVaultSQL(t, db, "DROP TABLE Nodes")
	if err := visitLegacyVaultNodes(reader, "", func(legacyVaultNode, []localvault.SecretChange) error { return nil }); err != errVaultMigrationSource {
		t.Fatal("schema failure escaped", err)
	}
}

func TestVaultLegacyNodeReferenceNormalization(t *testing.T) {
	db, _ := snapshotDatabase(t)
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	parent, id := uuid.NewString(), uuid.NewString()
	credentialID, tunnelID := uuid.NewString(), uuid.NewString()
	_, err := h.owner.ImportCredential(ctx, vaultstore.CredentialMetadata{ID: credentialID, Name: "Account", Kind: "password", Protocol: "rdp", Provider: "local"}, "2020-01-01T00:00:00Z", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.owner.ImportTunnel(ctx, vaultstore.TunnelMetadata{ID: tunnelID, Name: "Tunnel", Kind: 0}, []byte("config"), localvault.ImportTimes{CreatedAt: "2020-01-01T00:00:00Z", UpdatedAt: "2020-01-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	legacyVaultNodeRow(t, db, strings.ToUpper(parent), nil, 0)
	legacyVaultNodeRow(t, db, strings.ToUpper(id), strings.ToUpper(parent), 1)
	legacyVaultSQL(t, db, `UPDATE Nodes SET Protocol=1,CredentialMode=2,CredentialId=?,TunnelEnabled=1,TunnelConfigId=?,RdpGatewayCredentialId=? WHERE Id=?`, strings.ToUpper(credentialID), strings.ToUpper(tunnelID), strings.ToUpper(credentialID), strings.ToUpper(id))
	err = visitLegacyVaultNodes(resolverCaptureReader{ctx, db}, "", func(record legacyVaultNode, changes []localvault.SecretChange) error {
		_, err := h.owner.ImportNode(ctx, record.Metadata, changes, record.Times)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	n, err := h.owner.ReadNode(ctx, id, 1)
	if err != nil || n.ParentID == nil || *n.ParentID != parent || n.CredentialID == nil || *n.CredentialID != credentialID || n.TunnelConfigID == nil || *n.TunnelConfigID != tunnelID || n.RDPGatewayCredentialID == nil || *n.RDPGatewayCredentialID != credentialID {
		t.Fatal("reference changed", err)
	}
}
