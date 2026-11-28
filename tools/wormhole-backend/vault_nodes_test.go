package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func vaultNodeSave(t *testing.T, id, revision string, metadata map[string]any, changes []map[string]any) json.RawMessage {
	t.Helper()
	if metadata == nil {
		metadata = map[string]any{"id": id, "name": "Node " + id, "kind": 1, "protocol": 0, "sortOrder": "0"}
	}
	return vaultInput(t, map[string]any{"metadata": metadata, "changes": changes, "rowVersion": revision})
}

func TestVaultNodeEditorRejectsReservedMigrationField(t *testing.T) {
	h := vaultCredentialFixture(t)
	id := uuid.NewString()
	request := vaultNodeSave(t, id, "0", nil, []map[string]any{{"field": vaultstore.NodeResolverMigrationField, "remove": false, "value": []byte("forged-plan")}})
	if _, err := h.Handle(context.Background(), "node-save", request); err != vaultwire.ErrProtocol {
		t.Fatal("reserved field passed IPC parser", err)
	}
	if _, err := h.owner.ReadNode(context.Background(), id, 0); err != vaultstore.ErrMissing {
		t.Fatal("rejected editor created node", err)
	}
}

func TestVaultNodeTreeDelete(t *testing.T) {
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	id, child := uuid.NewString(), uuid.NewString()
	for _, metadata := range []map[string]any{
		{"id": id, "name": "Folder", "kind": 0, "sortOrder": "0"},
		{"id": child, "name": "Child", "kind": 1, "parentId": id, "sortOrder": "0"},
	} {
		if _, err := h.Handle(ctx, "node-save", vaultNodeSave(t, metadata["id"].(string), "0", metadata, []map[string]any{{"field": "notes", "remove": false, "value": []byte("private tree notes")}})); err != nil {
			t.Fatal(err)
		}
	}
	for _, payload := range []string{`{}`, `{"id":"` + id + `","rowVersion":"0"}`, `{"id":"` + id + `","rowVersion":"9223372036854775807"}`, `{"id":"` + id + `","rowVersion":"1","recursive":true}`} {
		if _, err := h.Handle(ctx, "node-delete-tree", []byte(payload)); err != vaultwire.ErrProtocol {
			t.Fatal(err)
		}
	}
	request := vaultInput(t, map[string]any{"id": id, "rowVersion": "1"})
	if _, err := (&vaultFoundationHandler{}).Handle(ctx, "node-delete-tree", request); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "node-delete", request); err == nil {
		t.Fatal("leaf API deleted folder")
	}
	result, err := h.Handle(ctx, "node-delete-tree", request)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if json.Unmarshal(result, &got) != nil || len(got) != 3 || got["id"] != id || got["rowVersion"] != "2" || got["deletedCount"] != "2" {
		t.Fatal("invalid deletion projection")
	}
	if _, err := h.owner.ReadNode(ctx, child, 0); err != vaultstore.ErrMissing {
		t.Fatal("child survives", err)
	}
	if _, err := h.Handle(ctx, "node-delete-tree", request); err == nil {
		t.Fatal("stale delete succeeded")
	}
}

func TestVaultNodeServiceLifecycle(t *testing.T) {
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	id := uuid.NewString()
	password := []byte("native-inline-password")
	notes := []byte("native-private-notes")
	metadata := map[string]any{"id": id, "name": "Native node", "kind": 1, "protocol": 0, "sortOrder": "9223372036854775807", "parentId": nil, "useInlinePassword": true, "rdpGatewayUseSameCreds": false, "sshAutoSudo": nil}
	request := vaultNodeSave(t, id, "0", metadata, []map[string]any{{"field": "inlinePassword", "remove": false, "value": password}, {"field": "notes", "remove": false, "value": notes}})
	if _, err := (&vaultFoundationHandler{}).Handle(ctx, "node-save", request); err != vaultwire.ErrProtocol {
		t.Fatal("preunlock node write", err)
	}
	result, err := h.Handle(ctx, "node-save", request)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if json.Unmarshal(result, &fields) != nil || len(fields) != 61 {
		t.Fatal("unexpected response fields", len(fields))
	}
	if fields["sortOrder"] != "9223372036854775807" || fields["rowVersion"] != "1" || fields["hasNotes"] != true || fields["hasInlinePassword"] != true || fields["rdpGatewayUseSameCreds"] != false || fields["sshAutoSudo"] != nil {
		t.Fatal("projection lost precision/inheritance")
	}
	for _, key := range []string{"notes", "inlinePassword", "fields", "seal", "sealSignerKeyId", "sealSuite"} {
		if _, ok := fields[key]; ok {
			t.Fatal("private field in response", key)
		}
	}
	if bytes.Contains(result, password) || bytes.Contains(result, notes) {
		t.Fatal("secret leaked")
	}
	read := vaultInput(t, map[string]any{"id": id, "rowVersion": "1"})
	if got, err := h.Handle(ctx, "node-read", read); err != nil || !bytes.Equal(result, got) {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "node-save", request); err != vaultstore.ErrConflict || h.closed {
		t.Fatal("stale write", err)
	}
	if got, err := h.Handle(ctx, "node-list", json.RawMessage(`{"after":"","limit":16}`)); err != nil || !bytes.Contains(got, []byte(id)) {
		t.Fatal(err)
	}
	metadata["name"] = "Renamed"
	metadata["rdpGatewayUseSameCreds"] = nil
	metadata["sshAutoSudo"] = false
	if _, err := h.Handle(ctx, "node-save", vaultNodeSave(t, id, "1", metadata, []map[string]any{})); err != nil {
		t.Fatal(err)
	}
	if err := h.owner.WithNodeField(ctx, id, "notes", 2, func(value []byte) error {
		if !bytes.Equal(value, notes) {
			t.Fatal("notes lost on rename")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "node-delete", read); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	if got, err := h.Handle(ctx, "node-delete", vaultInput(t, map[string]any{"id": id, "rowVersion": "2"})); err != nil || string(got) != `{"id":"`+id+`","rowVersion":"3","deleted":true}` {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "node-read", read); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	if got, err := h.Handle(ctx, "node-list", json.RawMessage(`{"after":"","limit":16}`)); err != nil || string(got) != `{"nodes":[]}` {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "node-field", read); err != vaultwire.ErrProtocol {
		t.Fatal("generic secret release allowed")
	}
	if _, err := h.node(ctx, "unknown", nil); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
}

func TestVaultNodeStrictNullableMetadata(t *testing.T) {
	id := uuid.NewString()
	valid := `{"id":"` + id + `","name":"Node","kind":1,"protocol":0,"sortOrder":"0"}`
	for _, raw := range []string{`null`, `[]`, `{}`, valid + `{}`, strings.Replace(valid, `"name":"Node"`, `"name":null`, 1), strings.Replace(valid, `"sortOrder":"0"`, `"sortOrder":0`, 1), strings.Replace(valid, `"sortOrder":"0"`, `"sortOrder":"01"`, 1), strings.Replace(valid, `"sortOrder":"0"`, `"sortOrder":"9223372036854775808"`, 1), strings.Replace(valid, `"kind":1`, `"kind":1,"kind":0`, 1), strings.Replace(valid, `"protocol":0`, `"protocol":2`, 1), strings.Replace(valid, `"protocol":0`, `"Protocol":0`, 1), strings.Replace(valid, `"protocol":0`, `"protocol":5,"tunnelEnabled":true`, 1), strings.Replace(valid, `"protocol":0`, `"protocol":0,"ownerUserId":"`+uuid.NewString()+`"`, 1), strings.Replace(valid, `"protocol":0`, `"protocol":0,"credentialMode":3,"credentialSlotId":"`+uuid.NewString()+`"`, 1), strings.Replace(valid, `"protocol":0`, `"protocol":0,"notes":"secret"`, 1), strings.Replace(valid, `"protocol":0`, `"protocol":0,"sshAutoSudo":0`, 1), strings.Repeat(" ", 512*1024+1)} {
		if _, err := decodeVaultNodeMetadata([]byte(raw)); err != vaultwire.ErrProtocol {
			t.Fatal("invalid metadata", err)
		}
	}
	raw := strings.Replace(valid, `"protocol":0`, `"protocol":null,"parentId":null,"ownerUserId":null,"sshAutoSudo":false,"tunnelEnabled":null,"httpIgnoreCertErrors":true,"rdpFullScreen":false,"rdpGatewayUseSameCreds":null,"serialStopBits":3,"serialFlowControl":3`, 1)
	m, err := decodeVaultNodeMetadata([]byte(raw))
	if err != nil || m.Protocol != nil || m.SshAutoSudo == nil || *m.SshAutoSudo || m.HTTPIgnoreCertErrors == nil || !*m.HTTPIgnoreCertErrors || m.RDPGatewayUseSameCreds != nil || *m.SerialStopBits != 3 || *m.SerialFlowControl != 3 {
		t.Fatal("nullable metadata mismatch", err)
	}
	raw = strings.Replace(valid, `"sortOrder":"0"`, `"sortOrder":"-9223372036854775808"`, 1)
	m, err = decodeVaultNodeMetadata([]byte(raw))
	if err != nil || m.SortOrder != -9223372036854775808 {
		t.Fatal(err)
	}
}

func TestVaultNodeInputFailuresAndRollback(t *testing.T) {
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	id := uuid.NewString()
	valid := string(vaultNodeSave(t, id, "0", nil, []map[string]any{}))
	for _, raw := range []string{`{}`, `null`, strings.Replace(valid, `"rowVersion":"0"`, `"rowVersion":null`, 1), strings.Replace(valid, `"rowVersion":"0"`, `"rowVersion":"9223372036854775807"`, 1), strings.Replace(valid, `"changes":[]`, `"changes":null`, 1), strings.Replace(valid, `"changes":[]`, `"changes":[{"field":"password","remove":false,"value":""}]`, 1), strings.Replace(valid, `"changes":[]`, `"changes":[{"field":"notes","remove":false,"value":null}]`, 1), strings.Replace(valid, `"kind":1`, `"Kind":1`, 1)} {
		if _, err := h.Handle(ctx, "node-save", json.RawMessage(raw)); err != vaultwire.ErrProtocol || h.closed {
			t.Fatal(err)
		}
	}
	for _, op := range []string{"node-read", "node-delete"} {
		for _, raw := range []string{`{}`, `{"id":"bad","rowVersion":"1"}`, `{"id":"` + id + `","rowVersion":"-1"}`, strings.Repeat(" ", 1025)} {
			if _, err := h.Handle(ctx, op, json.RawMessage(raw)); err != vaultwire.ErrProtocol {
				t.Fatal(err)
			}
		}
	}
	if _, err := h.Handle(ctx, "node-delete", vaultInput(t, map[string]any{"id": id, "rowVersion": "9223372036854775807"})); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	for _, raw := range []string{`{}`, `{"after":"bad","limit":1}`, `{"after":"","limit":0}`, `{"after":"","limit":17}`, strings.Repeat(" ", 1025)} {
		if _, err := h.Handle(ctx, "node-list", json.RawMessage(raw)); err != vaultwire.ErrProtocol {
			t.Fatal(err)
		}
	}
	if _, err := h.Handle(ctx, "node-save", json.RawMessage(valid)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "node-read", vaultInput(t, map[string]any{"id": id, "rowVersion": "2"})); !errors.Is(err, vaultwire.ErrRetired) || !errors.Is(err, vault.ErrRollback) {
		t.Fatal("rollback did not retire", err)
	}
}
