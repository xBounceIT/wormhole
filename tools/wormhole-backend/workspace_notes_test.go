package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConnectionNotesPersistAcrossProtocolsAndDuplication(t *testing.T) {
	for _, protocol := range []string{"ssh", "rdp", "http", "https", "vnc", "serial"} {
		t.Run(protocol, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "workspace.db")
			if err := ensureElectronWorkspaceSchema(path); err != nil {
				t.Fatal(err)
			}
			notes := "  Manutenzione 🛠️\r\nSeconda riga\t\n<script>literal</script>  "
			request := workspaceNodeWriteRequest{
				Name: "Connection", Kind: "connection", Protocol: protocol, Host: "example.test", Notes: &notes,
			}
			id, err := createWorkspaceNode(path, request)
			if err != nil {
				t.Fatal(err)
			}
			assertNotes := func(nodeID, want string) {
				t.Helper()
				db, err := openDatabase(path, true)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				tree, err := loadTree(db)
				if err != nil {
					t.Fatal(err)
				}
				for _, node := range tree {
					if node.ID == nodeID {
						if node.Notes != want {
							t.Fatalf("notes = %q, want %q", node.Notes, want)
						}
						return
					}
				}
				t.Fatalf("node %s missing from reloaded tree", nodeID)
			}
			assertNotes(id, notes)
			duplicate, err := duplicateWorkspaceNode(path, workspaceNodeRequest{NodeID: id})
			if err != nil {
				t.Fatal(err)
			}
			assertNotes(duplicate.NodeID, notes)
			request.ID = id
			updated := "Revised\nUnicode: è 日本語"
			request.Notes = &updated
			if err := updateWorkspaceNode(path, request); err != nil {
				t.Fatal(err)
			}
			assertNotes(id, updated)
			request.Notes = nil // Legacy callers must preserve notes.
			if err := updateWorkspaceNode(path, request); err != nil {
				t.Fatal(err)
			}
			assertNotes(id, updated)
			empty := ""
			request.Notes = &empty
			if err := updateWorkspaceNode(path, request); err != nil {
				t.Fatal(err)
			}
			assertNotes(id, "")
			assertNotes(duplicate.NodeID, notes)
		})
	}
}

func TestConnectionNotesRejectInvalidWritesWithoutChangingStoredText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspace.db")
	if err := ensureElectronWorkspaceSchema(path); err != nil {
		t.Fatal(err)
	}
	notes := strings.Repeat("a", 16384)
	request := workspaceNodeWriteRequest{Name: "Connection", Kind: "connection", Protocol: "ssh", Host: "example.test", Notes: &notes}
	id, err := createWorkspaceNode(path, request)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{strings.Repeat("a", 16385), "before\x00after", string([]byte{0xff}), strings.Repeat("🛠", 16385), strings.Repeat("🛠", 8193)} {
		request.Notes = &invalid
		request.ID = ""
		if _, err := createWorkspaceNode(path, request); err == nil {
			t.Fatal("invalid notes accepted on create")
		}
		request.ID = id
		if err := updateWorkspaceNode(path, request); err == nil {
			t.Fatal("invalid notes accepted on update")
		}
	}
	db, err := openDatabase(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var stored string
	var count int
	if err := db.QueryRow("SELECT Notes FROM Nodes WHERE Id = ?", id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM Nodes").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if stored != notes || count != 1 {
		t.Fatal("invalid write changed persisted connections")
	}
}

func TestConnectionNotesUnicodeLimitMatchesEditor(t *testing.T) {
	for _, notes := range []string{"", strings.Repeat("a", workspaceNotesMaxLength), strings.Repeat("界", workspaceNotesMaxLength), strings.Repeat("🛠", workspaceNotesMaxLength/2)} {
		if err := validateWorkspaceNotes(&notes); err != nil {
			t.Fatalf("valid Unicode notes rejected: %v", err)
		}
	}
	if err := validateWorkspaceNotes(nil); err != nil {
		t.Fatal(err)
	}
	for _, notes := range []string{strings.Repeat("🛠", workspaceNotesMaxLength/2) + "a", strings.Repeat("a", workspaceNotesMaxLength+1), strings.Repeat("🛠", workspaceNotesMaxLength+1), "\x00", string([]byte{0xff})} {
		if err := validateWorkspaceNotes(&notes); err == nil {
			t.Fatal("invalid notes accepted")
		}
	}
}

func TestConnectionNotesMaximumEscapedTextSurvivesProcessBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspace.db")
	notes := strings.Repeat("\x01", workspaceNotesMaxLength)
	request := workspaceNodeWriteRequest{Name: "Connection", Kind: "connection", Protocol: "ssh", Host: "example.test", Notes: &notes}
	for _, operation := range []string{"workspace-node-create", "workspace-node-update"} {
		payload, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		if len(payload) <= backendMaxRequestBytes {
			t.Fatal("test must exceed the generic process request limit")
		}
		var output, errorOutput bytes.Buffer
		if code := runBackendCLI([]string{"--operation", operation, "--database", path}, bytes.NewReader(payload), &output, &errorOutput); code != 0 {
			t.Fatalf("valid notes rejected by %s: %s", operation, errorOutput.String())
		}
		if operation == "workspace-node-create" {
			var result struct {
				NodeID string `json:"nodeId"`
			}
			if err := json.Unmarshal(output.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			request.ID = result.NodeID
			if request.ID == "" {
				t.Fatal("creation returned no node id")
			}
		}
	}
	for _, operation := range []string{"workspace-node-create", "workspace-node-update"} {
		var output, errorOutput bytes.Buffer
		oversized := `{"padding":"` + strings.Repeat("a", workspaceNodeWriteMaxRequestBytes) + `"}`
		if code := runBackendCLI([]string{"--operation", operation, "--database", path}, strings.NewReader(oversized), &output, &errorOutput); code == 0 {
			t.Fatalf("%s accepted an oversized request", operation)
		}
	}
	db, err := openDatabase(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var stored string
	if err := db.QueryRow("SELECT Notes FROM Nodes WHERE Id = ?", request.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != notes {
		t.Fatal("process boundary changed the note text")
	}
}

func TestConnectionNotesBackupPreservesLegacyMissingAndNullValues(t *testing.T) {
	for _, includeNull := range []bool{false, true} {
		t.Run(fmt.Sprint(includeNull), func(t *testing.T) {
			directory := t.TempDir()
			object := backupTestObject(map[string]any{"id": backupTestNodeID, "name": "Legacy", "kind": 1, "protocol": 0, "host": "example.test"})
			if includeNull {
				setBackupObjectValue(object, "notes", nil)
			}
			payload := newBackupPayload()
			payload.Nodes = []*backupObject{nil, &object}
			contents, err := json.Marshal(backupDocument{SchemaVersion: 2, Encryption: backupEncryptionNone, Payload: payload})
			if err != nil {
				t.Fatal(err)
			}
			backup := filepath.Join(directory, "backup.json")
			if err := os.WriteFile(backup, contents, 0600); err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(directory, "destination.db")
			if _, err := importBackup(destination, backupRequest{Path: backup}); err != nil {
				t.Fatal(err)
			}
			db, err := openDatabase(destination, true)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			tree, err := loadTree(db)
			if err != nil || len(tree) != 1 || tree[0].Notes != "" {
				t.Fatalf("legacy notes = %#v, %v", tree, err)
			}
		})
	}
}

func TestConnectionNotesBackupRejectsInvalidNotesBeforeAnyWrite(t *testing.T) {
	for _, invalid := range []any{strings.Repeat("a", 16385), strings.Repeat("🛠", 8193), "before\x00after", 42, []string{"notes"}, map[string]string{"text": "notes"}} {
		t.Run(fmt.Sprintf("%T-%d", invalid, len(fmt.Sprint(invalid))), func(t *testing.T) {
			directory := t.TempDir()
			destination := filepath.Join(directory, "destination.db")
			payload := newBackupPayload()
			valid := backupTestObject(map[string]any{"id": backupTestFolderID, "name": "Valid", "kind": 1, "protocol": 0, "host": "example.test", "notes": "valid notes"})
			invalidNode := backupTestObject(map[string]any{"id": backupTestNodeID, "name": "Invalid", "kind": 1, "protocol": 0, "host": "example.test", "notes": invalid})
			payload.Nodes = []*backupObject{&valid, &invalidNode}
			contents, err := json.Marshal(backupDocument{SchemaVersion: 2, Encryption: backupEncryptionNone, Payload: payload})
			if err != nil {
				t.Fatal(err)
			}
			backup := filepath.Join(directory, "backup.json")
			if err := os.WriteFile(backup, contents, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := importBackup(destination, backupRequest{Path: backup}); err == nil {
				t.Fatal("backup accepted notes rejected by the connection editor")
			}
			if _, err := os.Stat(destination); !os.IsNotExist(err) {
				t.Fatalf("invalid notes caused database writes: %v", err)
			}
		})
	}
}

func TestConnectionNotesMigrationUpgradesExistingRowsIdempotently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspace.db")
	if err := ensureElectronWorkspaceSchema(path); err != nil {
		t.Fatal(err)
	}
	db, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`ALTER TABLE Nodes DROP COLUMN Notes;
DELETE FROM __migration_history WHERE Id = '0020_connection_notes';
INSERT INTO Nodes (Id, Name, Kind, SortOrder, Protocol, Host, CreatedAt, UpdatedAt)
VALUES ('legacy', 'Legacy', 1, 0, 0, 'example.test', 'now', 'now');`)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := loadTree(db)
	if err != nil || len(legacy) != 1 || legacy[0].Notes != "" {
		t.Fatalf("legacy tree = %#v, %v", legacy, err)
	}
	db.Close()
	for range 2 {
		if err := ensureElectronWorkspaceSchema(path); err != nil {
			t.Fatal(err)
		}
	}
	db, err = openDatabase(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var notes sql.NullString
	var name string
	if err := db.QueryRow("SELECT Name, Notes FROM Nodes WHERE Id = 'legacy'").Scan(&name, &notes); err != nil {
		t.Fatal(err)
	}
	if name != "Legacy" || notes.Valid {
		t.Fatal("migration changed an existing connection")
	}
}

func TestConnectionNotesBackupRoundTrip(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source.db")
	if err := ensureElectronWorkspaceSchema(source); err != nil {
		t.Fatal(err)
	}
	notes := "  Backup notes\nUnicode: 日本語 🛠️  "
	id, err := createWorkspaceNode(source, workspaceNodeWriteRequest{Name: "Connection", Kind: "connection", Protocol: "ssh", Host: "example.test", Notes: &notes})
	if err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "backup.json")
	if _, err := exportBackup(source, backupRequest{Path: backup}); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "destination.db")
	if _, err := importBackup(destination, backupRequest{Path: backup}); err != nil {
		t.Fatal(err)
	}
	db, err := openDatabase(destination, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var restored string
	if err := db.QueryRow("SELECT Notes FROM Nodes WHERE Id = ?", id).Scan(&restored); err != nil {
		t.Fatal(err)
	}
	if restored != notes {
		t.Fatalf("restored notes = %q", restored)
	}
}
