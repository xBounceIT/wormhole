package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func vaultCredentialFixture(t *testing.T) *vaultFoundationHandler {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.db")
	doc, key := localSlotFixture(t)
	defer vault.Wipe(key)
	doc.Initializing = true
	owner, err := initializeVaultFiles(context.Background(), path, doc, key)
	if err != nil {
		t.Fatal(err)
	}
	h := &vaultFoundationHandler{databasePath: path, owner: owner}
	t.Cleanup(func() { h.Close() })
	return h
}

func TestVaultCredentialEditorCannotReplaceCreationTime(t *testing.T) {
	for _, field := range []string{"createdAt", "updatedAt"} {
		metadata := vaultInput(t, map[string]any{"id": uuid.NewString(), "name": "Account", "protocol": "ssh", "kind": "password", "provider": "local", field: "2020-01-01T00:00:00Z"})
		if _, err := decodeVaultCredentialMetadata(metadata); err != vaultwire.ErrProtocol {
			t.Fatal("editor accepted migration provenance", err)
		}
	}
}

func vaultCredentialSave(t *testing.T, id, version string, changes []map[string]any) json.RawMessage {
	t.Helper()
	return vaultInput(t, map[string]any{
		"rowVersion": version,
		"metadata":   map[string]any{"id": id, "name": "Native account " + id, "protocol": "ssh", "kind": "password", "provider": "local", "username": "alice"},
		"changes":    changes,
	})
}

func TestVaultCredentialHandlerLifecycle(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	id := uuid.NewString()
	secret := []byte("native-only-secret-fixture")
	save := vaultCredentialSave(t, id, "0", []map[string]any{{"field": "password", "remove": false, "value": secret}})
	response, err := h.Handle(ctx, "credential-save", save)
	if err != nil {
		t.Fatal(err)
	}
	var view vaultCredentialView
	if json.Unmarshal(response, &view) != nil || view.ID != id || view.RowVersion != "1" || !view.HasPassword || view.Username != "alice" {
		t.Fatalf("unexpected projection: %s", response)
	}
	var properties map[string]any
	if json.Unmarshal(response, &properties) != nil || len(properties) != 19 || view.CreatedAt == "" {
		t.Fatal("unexpected public properties")
	}
	for _, forbidden := range []string{"seal", "fields", "value", "password", "key", "deleted"} {
		if _, exists := properties[forbidden]; exists {
			t.Fatalf("private property: %s", forbidden)
		}
	}
	if bytes.Contains(response, secret) || bytes.Contains(response, []byte(base64.StdEncoding.EncodeToString(secret))) {
		t.Fatal("plaintext returned")
	}
	if err := h.owner.WithCredentialSecret(ctx, id, "password", 1, func(value []byte) error {
		if !bytes.Equal(value, secret) {
			t.Fatal("native secret not stored")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "credential-save", save); !errors.Is(err, vaultstore.ErrConflict) || h.closed {
		t.Fatal("stale write not recoverable", err)
	}
	read := vaultInput(t, map[string]any{"id": id, "rowVersion": "1"})
	if got, err := h.Handle(ctx, "credential-read", read); err != nil || !bytes.Equal(got, response) {
		t.Fatal("read did not return saved metadata", err)
	}
	list := json.RawMessage(`{"after":"","limit":16}`)
	if got, err := h.Handle(ctx, "credential-list", list); err != nil || !bytes.Contains(got, []byte(id)) {
		t.Fatal("list missing credential", err)
	}
	if _, err := h.Handle(ctx, "credential-save", vaultCredentialSave(t, id, "1", []map[string]any{{"field": "password", "remove": true}})); err != nil {
		t.Fatal(err)
	}
	if err := h.owner.WithCredentialSecret(ctx, id, "password", 2, func([]byte) error { t.Fatal("removed secret released"); return nil }); !errors.Is(err, vaultstore.ErrMissing) {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "credential-delete", read); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatal("stale delete allowed")
	}
	if got, err := h.Handle(ctx, "credential-delete", vaultInput(t, map[string]any{"id": id, "rowVersion": "2"})); err != nil || string(got) != `{"id":"`+id+`","rowVersion":"3","deleted":true}` {
		t.Fatal("delete response", string(got), err)
	}
	if _, err := h.Handle(ctx, "credential-read", read); !errors.Is(err, vaultstore.ErrMissing) || h.closed {
		t.Fatal("deleted read", err)
	}
	if got, err := h.Handle(ctx, "credential-list", list); err != nil || string(got) != `{"credentials":[]}` {
		t.Fatal("deleted item visible", string(got), err)
	}
	if _, err := h.Handle(ctx, "credential-save", save); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatal("deleted ID reused")
	}
	if _, err := h.Handle(ctx, "credential-reveal", read); err == nil {
		t.Fatal("generic plaintext release allowed")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.ReadFile(h.databasePath)
	if err != nil || bytes.Contains(file, secret) {
		t.Fatal("plaintext persisted", err)
	}
}

func TestVaultCredentialNativeProcess(t *testing.T) {
	if os.Getenv("WORMHOLE_TEST_CREDENTIAL_CHILD") == "1" {
		os.Exit(runBackendCLI([]string{"--operation", "vault", "--database", os.Getenv("WORMHOLE_TEST_CREDENTIAL_DATABASE")}, os.Stdin, os.Stdout, os.Stderr))
	}
	h := vaultCredentialFixture(t)
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVaultCredentialNativeProcess$")
	cmd.Env = append(os.Environ(), "WORMHOLE_TEST_CREDENTIAL_CHILD=1", "WORMHOLE_TEST_CREDENTIAL_DATABASE="+h.databasePath)
	var diagnostics bytes.Buffer
	cmd.Stderr = &diagnostics
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); cancel() })
	encoder, decoder := json.NewEncoder(in), json.NewDecoder(out)
	var requestID uint64
	request := func(operation string, payload json.RawMessage) vaultwire.Response {
		t.Helper()
		requestID++
		if err := encoder.Encode(vaultwire.Request{Version: 1, ID: requestID, Operation: operation, Payload: payload}); err != nil {
			t.Fatal(err)
		}
		var response vaultwire.Response
		if err := decoder.Decode(&response); err != nil {
			t.Fatal(err)
		}
		if response.ID != requestID {
			t.Fatal("response ID mismatch")
		}
		return response
	}
	id := uuid.NewString()
	secret := []byte("native-process-secret-do-not-relay")
	save := vaultCredentialSave(t, id, "0", []map[string]any{{"field": "password", "remove": false, "value": secret}})
	if r := request("credential-save", save); r.Error != "vault_operation_failed" || len(r.Result) != 0 {
		t.Fatal("pre-unlock write allowed")
	}
	doc, err := readVaultSlotFile(h.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if r := request("unlock", vaultInput(t, map[string]any{"vaultId": doc.VaultID, "slotId": doc.Slots[0].ID, "recoveryKey": bytes.Repeat([]byte{0x32}, 32)})); r.Error != "" {
		t.Fatal(r.Error)
	}
	if r := request("credential-save", save); r.Error != "" || bytes.Contains(r.Result, secret) || !bytes.Contains(r.Result, []byte(`"hasPassword":true`)) {
		t.Fatal("save failed or exposed secret")
	}
	if r := request("credential-save", save); r.Error != "vault_operation_failed" || len(r.Result) != 0 {
		t.Fatal("CAS conflict not redacted")
	}
	if r := request("credential-list", json.RawMessage(`{"after":"","limit":16}`)); r.Error != "" || !bytes.Contains(r.Result, []byte(id)) {
		t.Fatal("list failed")
	}
	tunnelID := uuid.NewString()
	tunnelConfiguration := []byte(`{"ProfileOvpn":"private-native-process-profile"}`)
	if r := request("tunnel-save", vaultTunnelSave(t, tunnelID, "0", tunnelConfiguration)); r.Error != "" || bytes.Contains(r.Result, []byte("private-native-process-profile")) {
		t.Fatal("native tunnel save failed or leaked configuration")
	}
	if r := request("tunnel-read", vaultInput(t, map[string]any{"id": tunnelID, "rowVersion": "1"})); r.Error != "" || !bytes.Contains(r.Result, []byte(tunnelID)) {
		t.Fatal("native tunnel read failed")
	}
	nodeID := uuid.NewString()
	nodeNotes := []byte("private-native-process-notes")
	nodeMetadata := map[string]any{"id": nodeID, "name": "Native node", "kind": 1, "protocol": 0, "sortOrder": "0", "credentialId": id, "tunnelConfigId": tunnelID}
	if r := request("node-save", vaultNodeSave(t, nodeID, "0", nodeMetadata, []map[string]any{{"field": "notes", "remove": false, "value": nodeNotes}})); r.Error != "" || bytes.Contains(r.Result, nodeNotes) {
		t.Fatal("native node save failed or leaked notes")
	}
	deletedFolderID, deletedChildID := uuid.NewString(), uuid.NewString()
	for _, metadata := range []map[string]any{
		{"id": deletedFolderID, "name": "Deleted folder", "kind": 0, "sortOrder": "0"},
		{"id": deletedChildID, "name": "Deleted child", "kind": 1, "parentId": deletedFolderID, "sortOrder": "0"},
	} {
		if r := request("node-save", vaultNodeSave(t, metadata["id"].(string), "0", metadata, []map[string]any{{"field": "notes", "remove": false, "value": nodeNotes}})); r.Error != "" {
			t.Fatal("native tree setup failed")
		}
	}
	if r := request("node-delete-tree", vaultInput(t, map[string]any{"id": deletedFolderID, "rowVersion": "1"})); r.Error != "" || !bytes.Contains(r.Result, []byte(`"deletedCount":"2"`)) || bytes.Contains(r.Result, nodeNotes) {
		t.Fatal("native tree deletion failed")
	}
	requestID++
	if err := encoder.Encode(vaultwire.Request{Version: 1, ID: requestID, Operation: "lock"}); err != nil {
		t.Fatal(err)
	}
	in.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if diagnostics.Len() != 0 {
		t.Fatal("native diagnostics were not empty")
	}
	// The same files reopen only after process exit; release remains native-only.
	reopened := &vaultFoundationHandler{databasePath: h.databasePath}
	defer reopened.Close()
	if _, err := reopened.Handle(context.Background(), "unlock", vaultInput(t, map[string]any{"vaultId": doc.VaultID, "slotId": doc.Slots[0].ID, "recoveryKey": bytes.Repeat([]byte{0x32}, 32)})); err != nil {
		t.Fatal(err)
	}
	if err := reopened.owner.WithCredentialSecret(context.Background(), id, "password", 1, func(value []byte) error {
		if !bytes.Equal(value, secret) {
			t.Fatal("secret lost across process exit")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := reopened.owner.WithTunnelConfiguration(context.Background(), tunnelID, 1, func(value []byte) error {
		if !bytes.Equal(value, tunnelConfiguration) {
			t.Fatal("tunnel configuration lost across process exit")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := reopened.owner.WithNodeField(context.Background(), nodeID, "notes", 1, func(value []byte) error {
		if !bytes.Equal(value, nodeNotes) {
			t.Fatal("node notes lost across process exit")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, deleted := range []string{deletedFolderID, deletedChildID} {
		if _, err := reopened.owner.ReadNode(context.Background(), deleted, 0); err != vaultstore.ErrMissing {
			t.Fatal("deleted tree returned after process exit", err)
		}
	}
}

func TestVaultCredentialStrictInput(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	id := uuid.NewString()
	valid := string(vaultCredentialSave(t, id, "0", []map[string]any{}))
	for _, raw := range []string{
		"", "null", "[]", "{", "{}", valid + "{}", strings.Replace(valid, `"rowVersion":"0"`, `"rowVersion":"0","rowVersion":"1"`, 1),
		strings.Replace(valid, `"rowVersion":"0"`, `"RowVersion":"0"`, 1), strings.Replace(valid, `"rowVersion":"0"`, `"rowVersion":0`, 1),
		strings.Replace(valid, `"rowVersion":"0"`, `"rowVersion":null`, 1), strings.Replace(valid, `"rowVersion":"0"`, `"rowVersion":"01"`, 1),
		strings.Replace(valid, `"rowVersion":"0"`, `"rowVersion":"9223372036854775807"`, 1),
		strings.Replace(valid, `"username":"alice"`, `"username":"alice","username":"bob"`, 1),
		strings.Replace(valid, `"username":"alice"`, `"ownerUserId":"`+uuid.NewString()+`"`, 1),
		strings.Replace(valid, `"username":"alice"`, `"password":"in-metadata"`, 1),
		strings.Replace(valid, `"provider":"local"`, `"provider":"unknown"`, 1),
		strings.Replace(valid, `"changes":[]`, `"changes":null`, 1),
		strings.Replace(valid, `"changes":[]`, `"changes":[{"field":"password","remove":false,"value":[65]}]`, 1),
		strings.Replace(valid, `"changes":[]`, `"changes":[{"field":"password","remove":false,"value":"c2VjcmV0","unknown":true}]`, 1),
	} {
		if _, err := h.Handle(ctx, "credential-save", json.RawMessage(raw)); err != vaultwire.ErrProtocol || h.closed {
			t.Fatalf("input not rejected before mutation: %v", err)
		}
	}
	for _, operation := range []string{"credential-read", "credential-delete"} {
		for _, raw := range []string{`{}`, `{"id":"bad","rowVersion":"1"}`, `{"id":"` + id + `","rowVersion":"-1"}`, `{"id":"` + id + `","rowVersion":"9223372036854775807"}`, strings.Repeat(" ", 1025)} {
			if operation == "credential-read" && strings.Contains(raw, "9223372036854775807") {
				continue
			}
			if _, err := h.Handle(ctx, operation, json.RawMessage(raw)); err != vaultwire.ErrProtocol {
				t.Fatal(operation, err)
			}
		}
	}
	for _, raw := range []string{`{}`, `{"after":"bad","limit":1}`, `{"after":"","limit":0}`, `{"after":"","limit":17}`, `{"after":"","limit":1.5}`, strings.Repeat(" ", 1025)} {
		if _, err := h.Handle(ctx, "credential-list", json.RawMessage(raw)); err != vaultwire.ErrProtocol {
			t.Fatal(err)
		}
	}
	if got, err := h.Handle(ctx, "credential-list", json.RawMessage(`{"after":"","limit":16}`)); err != nil || string(got) != `{"credentials":[]}` {
		t.Fatal("invalid requests mutated database")
	}
	if _, err := h.credential(ctx, "unknown", nil); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := h.Handle(cancelled, "credential-save", json.RawMessage(valid)); err != context.Canceled {
		t.Fatal(err)
	}
}

func TestVaultCredentialObjectDecoder(t *testing.T) {
	for _, raw := range []string{`{"x":1,"x":2}`, `{"x":1,"\u0078":2}`, `{"X":1}`, `{"x":null}`, `{"x":1,`, `{"x":`, `{"x":1]`, `{"x":1} null`, `{"x":1} !`, "{\"x\":\"\xff\"}", strings.Repeat(" ", vaultwire.MaxFrameBytes+1)} {
		var value int
		if err := decodeVaultObject([]byte(raw), map[string]any{"x": &value}, "x"); err != vaultwire.ErrProtocol {
			t.Fatal("malformed object accepted")
		}
	}
	var value int
	if err := decodeVaultObject([]byte(" {\"x\":1} \n"), map[string]any{"x": &value}, "x"); err != nil || value != 1 {
		t.Fatal(err)
	}
	if _, err := decodeVaultCredentialMetadata(bytes.Repeat([]byte{' '}, 128*1024+1)); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	for _, v := range []string{"", "01", "+1", "-1", "1e3", "1.0", "9223372036854775808", "0"} {
		if _, err := vaultCredentialRevision(v, false); err != vaultwire.ErrProtocol {
			t.Fatal("invalid revision", v)
		}
	}
	if v, err := vaultCredentialRevision(strconv.FormatUint(math.MaxInt64, 10), false); err != nil || v != math.MaxInt64 {
		t.Fatal(err)
	}
}

func TestVaultCredentialSecretDecoder(t *testing.T) {
	valid := `{"field":"password","remove":false,"value":"c2VjcmV0"}`
	for _, raw := range []string{
		"", "null", "{}", "[", "[!]", "[" + valid + ",", "[" + valid + "]{}", "[" + valid + "]!", "[" + valid + "," + valid + "]",
		`[{"field":"other","remove":false,"value":""}]`, `[{"field":"password","remove":false}]`,
		`[{"field":"password","remove":true,"value":""}]`, `[{"field":"password","remove":false,"value":null}]`,
		`[{"field":"password","remove":false,"value":"?"}]`,
		`[{"field":"password","remove":false,"value":"c2VjcmV0","value":""}]`,
		`[{"field":"password","remove":false,"value":"c2VjcmV0","unknown":0}]`,
		`[{"field":"password","remove":true},{"field":"privateKey","remove":true},{"field":"passphrase","remove":true},{"field":"certificate","remove":true},{}]`,
		`[{"field":"password","remove":false,"value":"` + base64.StdEncoding.EncodeToString(make([]byte, vault.MaxSecretBytes+1)) + `"}]`,
	} {
		changes, err := decodeVaultCredentialChanges([]byte(raw))
		if err != vaultwire.ErrProtocol || changes != nil {
			t.Fatal("partial secret escaped malformed input", err)
		}
	}
	changes, err := decodeVaultCredentialChanges([]byte("[" + valid + `,{"field":"privateKey","remove":false,"value":""},{"field":"passphrase","remove":true}]`))
	if err != nil || len(changes) != 3 || string(changes[0].Value) != "secret" || !changes[2].Remove {
		t.Fatal(err)
	}
	borrowed := changes[0].Value
	wipeVaultCredentialChanges(changes)
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("plaintext not wiped")
	}
}

func TestVaultCredentialProjectionAndIntegrityRetirement(t *testing.T) {
	view := credentialView(vaultstore.Credential{RowVersion: math.MaxInt64, Fields: []vaultstore.CredentialField{{Field: "password", Present: false}, {Field: "privateKey", Present: true}, {Field: "passphrase", Present: true}, {Field: "certificate", Present: true}}})
	if view.RowVersion != "9223372036854775807" || view.HasPassword || !view.HasPrivateKey || !view.HasPassphrase || !view.HasCertificate {
		t.Fatal("projection mismatch")
	}
	for _, operation := range []string{"credential-read", "credential-list", "credential-save", "credential-delete", "rollback"} {
		t.Run(operation, func(t *testing.T) {
			h := vaultCredentialFixture(t)
			ctx := context.Background()
			id := uuid.NewString()
			if _, err := h.Handle(ctx, "credential-save", vaultCredentialSave(t, id, "0", []map[string]any{})); err != nil {
				t.Fatal(err)
			}
			if operation != "rollback" {
				// Mutate on disk between owners, preserving all otherwise valid metadata.
				if err := h.Close(); err != nil {
					t.Fatal(err)
				}
				db, err := sql.Open("sqlite", h.databasePath)
				if err != nil {
					t.Fatal(err)
				}
				_, err = db.Exec(`UPDATE CredentialProfiles SET Username='substituted' WHERE Id=?`, id)
				db.Close()
				if err != nil {
					t.Fatal(err)
				}
				doc, err := readVaultSlotFile(h.databasePath)
				if err != nil {
					t.Fatal(err)
				}
				key := bytes.Repeat([]byte{0x91}, 32)
				h.owner, err = openVaultFiles(ctx, h.databasePath, doc, key)
				vault.Wipe(key)
				if err != nil {
					t.Fatal(err)
				}
				h.closed = false
			}
			actual := operation
			payload := vaultInput(t, map[string]any{"id": id, "rowVersion": "1"})
			switch operation {
			case "credential-list":
				payload = json.RawMessage(`{"after":"","limit":16}`)
			case "credential-save":
				payload = vaultCredentialSave(t, id, "1", []map[string]any{})
			case "rollback":
				actual = "credential-read"
				payload = vaultInput(t, map[string]any{"id": id, "rowVersion": "2"})
			}
			if result, err := h.Handle(ctx, actual, payload); !errors.Is(err, vaultwire.ErrRetired) || !h.closed || result != nil {
				t.Fatal("corrupt owner survived", err)
			}
			if _, err := h.Handle(ctx, "status", nil); err != vaultwire.ErrProtocol {
				t.Fatal("retired handler reused")
			}
		})
	}
}

func TestVaultCredentialProviderChangesAndPages(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	id := uuid.NewString()
	metadata := map[string]any{"id": id, "name": "SSH key", "protocol": "ssh", "kind": "sshKey", "provider": "local", "username": "alice", "privateKeyName": "id_ed25519", "certificateName": "id-cert.pub"}
	save := func(version string, changes []map[string]any) vaultCredentialView {
		t.Helper()
		response, err := h.Handle(ctx, "credential-save", vaultInput(t, map[string]any{"metadata": metadata, "rowVersion": version, "changes": changes}))
		if err != nil {
			t.Fatal(err)
		}
		var view vaultCredentialView
		if err := json.Unmarshal(response, &view); err != nil {
			t.Fatal(err)
		}
		return view
	}
	view := save("0", []map[string]any{
		{"field": "privateKey", "remove": false, "value": []byte("synthetic-key")},
		{"field": "passphrase", "remove": false, "value": []byte("")},
		{"field": "certificate", "remove": false, "value": []byte("synthetic-cert")},
	})
	if !view.HasPrivateKey || !view.HasPassphrase || !view.HasCertificate || view.HasPassword {
		t.Fatal("SSH key presence mismatch")
	}
	metadata["kind"], metadata["provider"] = "password", "bitwarden"
	metadata["privateKeyName"], metadata["certificateName"] = "", ""
	metadata["bitwardenItemId"], metadata["bitwardenItemName"], metadata["bitwardenFieldPath"] = "item-id", "external item", "login.password"
	view = save("1", []map[string]any{{"field": "privateKey", "remove": true}, {"field": "passphrase", "remove": true}, {"field": "certificate", "remove": true}})
	if view.Provider != "bitwarden" || view.HasPrivateKey || view.HasPassphrase || view.HasCertificate || view.HasPassword {
		t.Fatal("provider switch retained native secrets")
	}
	metadata["provider"] = "local"
	delete(metadata, "bitwardenItemId")
	delete(metadata, "bitwardenItemName")
	delete(metadata, "bitwardenFieldPath")
	view = save("2", []map[string]any{{"field": "password", "remove": false, "value": []byte("replacement")}})
	if !view.HasPassword || view.RowVersion != "3" {
		t.Fatal("local provider did not resume")
	}
	for i := 0; i < 18; i++ {
		if _, err := h.Handle(ctx, "credential-save", vaultCredentialSave(t, uuid.NewString(), "0", []map[string]any{})); err != nil {
			t.Fatal(err)
		}
	}
	after := ""
	seen := make(map[string]bool)
	for page := 0; page < 2; page++ {
		raw, err := h.Handle(ctx, "credential-list", vaultInput(t, map[string]any{"after": after, "limit": 16}))
		if err != nil {
			t.Fatal(err)
		}
		var response struct {
			Credentials []vaultCredentialView `json:"credentials"`
		}
		if err := json.Unmarshal(raw, &response); err != nil {
			t.Fatal(err)
		}
		if (page == 0 && len(response.Credentials) != 16) || (page == 1 && len(response.Credentials) != 3) {
			t.Fatal("wrong page size")
		}
		for _, v := range response.Credentials {
			if seen[v.ID] || v.ID <= after {
				t.Fatal("repeated or unordered cursor")
			}
			seen[v.ID] = true
			after = v.ID
		}
	}
	if !seen[id] {
		t.Fatal("edited credential disappeared")
	}
}

func TestVaultCredentialRetiresInvalidStoredShape(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	id := uuid.NewString()
	if _, err := h.Handle(ctx, "credential-save", vaultCredentialSave(t, id, "0", []map[string]any{})); err != nil {
		t.Fatal(err)
	}
	// A valid JSON request with an inconsistent aggregate cannot publish anything.
	if _, err := h.Handle(ctx, "credential-save", vaultCredentialSave(t, id, "1", []map[string]any{{"field": "password", "remove": true}})); !errors.Is(err, vaultwire.ErrRetired) {
		t.Fatal("invalid aggregate did not fail closed", err)
	}
}
