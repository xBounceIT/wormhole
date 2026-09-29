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
				response, err := loadWorkspaceNodeNotes(path, workspaceNodeRequest{NodeID: nodeID})
				if err != nil {
					t.Fatal(err)
				}
				if response["notes"] != want {
					t.Fatalf("notes = %q, want %q", response["notes"], want)
				}
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
			if err != nil || len(tree) != 1 {
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
	if err != nil || len(legacy) != 1 {
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

func TestConnectionNotesDoNotInflateAggregateResponses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspace.db")
	if err := ensureElectronWorkspaceSchema(path); err != nil {
		t.Fatal(err)
	}
	db, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	notes := strings.Repeat("\x01", workspaceNotesMaxLength)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := range 180 {
		_, err := tx.Exec(`INSERT INTO Nodes (Id, Name, Kind, SortOrder, Protocol, Host, Notes, CreatedAt, UpdatedAt)
VALUES (?, 'Connection', 1, ?, 0, 'example.test', ?, 'now', 'now')`, fmt.Sprintf("connection-%d", i), i, notes)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	db.Close()
	for _, operation := range []string{"workspace", "startup", "workspace-node-notes"} {
		var output, errorOutput bytes.Buffer
		input := strings.NewReader(`{"nodeId":"connection-179"}`)
		if code := runBackendCLI([]string{"--operation", operation, "--database", path}, input, &output, &errorOutput); code != 0 {
			t.Fatalf("%s failed: %s", operation, errorOutput.String())
		}
		if output.Len() >= 16*1024*1024 {
			t.Fatalf("%s exceeded Electron's response limit", operation)
		}
		if operation == "workspace-node-notes" {
			var result map[string]string
			if err := json.Unmarshal(output.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result["notes"] != notes {
				t.Fatal("on-demand read changed maximum note text")
			}
		} else if bytes.Contains(output.Bytes(), []byte(`"notes"`)) {
			t.Fatalf("%s still includes aggregate note text", operation)
		}
	}
}

func TestConnectionNotesReadErrorsAndLegacySchema(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.db")
	if _, err := loadWorkspaceNodeNotes(missing, workspaceNodeRequest{NodeID: ""}); err == nil {
		t.Fatal("invalid id accepted")
	}
	if _, err := loadWorkspaceNodeNotes(missing, workspaceNodeRequest{NodeID: "missing"}); err == nil {
		t.Fatal("missing database accepted")
	}
	if _, err := loadWorkspaceNodeNotes(t.TempDir(), workspaceNodeRequest{NodeID: "missing"}); err == nil {
		t.Fatal("invalid database accepted")
	}
	path := filepath.Join(t.TempDir(), "workspace.db")
	if err := ensureElectronWorkspaceSchema(path); err != nil {
		t.Fatal(err)
	}
	id, err := createWorkspaceNode(path, workspaceNodeWriteRequest{Name: "Connection", Kind: "connection", Protocol: "ssh", Host: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, nodeID := range []string{"missing", ""} {
		if _, err := loadWorkspaceNodeNotes(path, workspaceNodeRequest{NodeID: nodeID}); err == nil {
			t.Fatal("invalid/missing connection accepted")
		}
	}
	folderID, err := createWorkspaceNode(path, workspaceNodeWriteRequest{Name: "Folder", Kind: "folder"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadWorkspaceNodeNotes(path, workspaceNodeRequest{NodeID: folderID}); err == nil {
		t.Fatal("folder accepted")
	}
	db, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE Nodes SET Notes = ? WHERE Id = ?", strings.Repeat("a", workspaceNotesMaxLength+1), id); err != nil {
		t.Fatal(err)
	}
	if _, err := loadWorkspaceNodeNotes(path, workspaceNodeRequest{NodeID: id}); err == nil {
		t.Fatal("invalid stored note accepted")
	}
	if _, err := db.Exec("ALTER TABLE Nodes DROP COLUMN Notes"); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	result, err := loadWorkspaceNodeNotes(path, workspaceNodeRequest{NodeID: id})
	if err != nil || result["notes"] != "" {
		t.Fatalf("legacy notes = %#v, %v", result, err)
	}
}

func TestConnectionNotesReadMatchesLegacyMixedCaseIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspace.db")
	if err := ensureElectronWorkspaceSchema(path); err != nil {
		t.Fatal(err)
	}
	notes := "Legacy ID notes\nUnicode: 日本語 🛠️"
	id, err := createWorkspaceNode(path, workspaceNodeWriteRequest{Name: "Connection", Kind: "connection", Protocol: "ssh", Host: "example.test", Notes: &notes})
	if err != nil {
		t.Fatal(err)
	}
	db, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, storedID := range []string{strings.ToUpper(id), strings.ToUpper(id[:8]) + id[8:]} {
		if _, err := db.Exec("UPDATE Nodes SET Id = ? WHERE lower(Id) = ?", storedID, id); err != nil {
			t.Fatal(err)
		}
		for _, requestedID := range []string{id, storedID, "  " + storedID + "  "} {
			result, err := loadWorkspaceNodeNotes(path, workspaceNodeRequest{NodeID: requestedID})
			if err != nil || result["notes"] != notes {
				t.Fatalf("stored %q requested %q: %#v, %v", storedID, requestedID, result, err)
			}
		}
	}
}

func TestConnectionNotesJSONPreservesValidEscapesAndRejectsLossyDecoding(t *testing.T) {
	valid := map[string]string{
		`""`: "", `"\ud800\udc00"`: "𐀀", `"\uDBFF\uDFFF"`: "\U0010FFFF",
		`"\ufffd"`: "�", `"literal \\ud800"`: `literal \ud800`, `"\/\n\t\u0061"`: "/\n\ta", `"🛠️"`: "🛠️",
	}
	for raw, want := range valid {
		notes, err := parseWorkspaceNotesJSON(json.RawMessage(raw))
		if err != nil || notes == nil || *notes != want {
			t.Fatalf("%s -> %v, %v; want %q", raw, notes, err, want)
		}
		var request workspaceNodeWriteRequest
		if err := json.Unmarshal([]byte(`{"name":"Connection","notes":`+raw+`}`), &request); err != nil || request.Notes == nil || *request.Notes != want || request.Name != "Connection" {
			t.Fatalf("valid request failed: %#v, %v", request, err)
		}
	}
	for _, raw := range []string{`"\ud800"`, `"\udc00"`, `"\ud800x"`, `"\ud800\u0061"`, `"\ud800\ud800\udc00"`, `"\ud800\udc00\udc00"`, `42`, `"\uZZZZ"`, `"before\u0000after"`, "\"" + string([]byte{0xff}) + "\""} {
		if _, err := parseWorkspaceNotesJSON(json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
		var request workspaceNodeWriteRequest
		if err := json.Unmarshal([]byte(`{"notes":`+raw+`}`), &request); err == nil {
			t.Fatalf("request accepted %s", raw)
		}
	}
	for _, raw := range []string{`{}`, `{"notes":null}`} {
		var request workspaceNodeWriteRequest
		if err := json.Unmarshal([]byte(raw), &request); err != nil || request.Notes != nil {
			t.Fatalf("legacy request failed: %v", err)
		}
	}
}

func TestConnectionNotesBackupRejectsLoneSurrogatesBeforeWrites(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, raw := range []string{`"\ud800"`, `"\udc00"`, `"\ud800\u0061"`} {
			t.Run(fmt.Sprintf("%t-%s", encrypted, raw), func(t *testing.T) {
				directory := t.TempDir()
				node := backupTestObject(map[string]any{"id": backupTestNodeID, "name": "Connection", "kind": 1, "protocol": 0, "host": "example.test"})
				node["notes"] = json.RawMessage(raw)
				payload := newBackupPayload()
				payload.Nodes = []*backupObject{&node}
				document := backupDocument{SchemaVersion: 2, Encryption: backupEncryptionNone, Payload: payload}
				password := ""
				if encrypted {
					plaintext, err := json.Marshal(payload)
					if err != nil {
						t.Fatal(err)
					}
					password = "test-only-password"
					sealed, err := sealBackupPayload(plaintext, password)
					if err != nil {
						t.Fatal(err)
					}
					document.Encryption = backupEncryptionAESGCM
					document.Payload = nil
					document.EncryptedPayload = &sealed
				}
				contents, err := json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
				backup := filepath.Join(directory, "backup.json")
				if err := os.WriteFile(backup, contents, 0600); err != nil {
					t.Fatal(err)
				}
				destination := filepath.Join(directory, "destination.db")
				if _, err := importBackup(destination, backupRequest{Path: backup, Password: password}); err == nil || !strings.Contains(err.Error(), "invalid connection notes") {
					t.Fatalf("lossy import accepted: %v", err)
				}
				if _, err := os.Stat(destination); !os.IsNotExist(err) {
					t.Fatalf("rejected backup wrote database: %v", err)
				}
			})
		}
	}
}
