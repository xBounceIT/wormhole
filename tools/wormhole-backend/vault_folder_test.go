package main

import (
	"context"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func vaultFolderInput(id, version, parent string) map[string]any {
	return map[string]any{"id": id, "rowVersion": version, "parentId": parent, "name": " Folder 🐛 ", "sshAutoSudo": nil, "tunnelEnabled": nil, "tunnelConfigId": "", "credentialMode": 0, "credentialId": ""}
}

func TestVaultFolderEditorPreservesAuthenticatedHiddenFieldsAndSecrets(t *testing.T) {
	h, ctx := vaultCredentialFixture(t), context.Background()
	call := func(input map[string]any) vaultstore.Node {
		t.Helper()
		raw, err := h.Handle(ctx, "folder-save", vaultInput(t, input))
		var result struct {
			NodeID     string `json:"nodeId"`
			RowVersion string `json:"rowVersion"`
			Updated    bool   `json:"updated"`
		}
		if err != nil || json.Unmarshal(raw, &result) != nil || !result.Updated || !vaultCredentialID(result.NodeID) || result.RowVersion == "" {
			t.Fatal(string(raw), err)
		}
		if len(strings.Split(string(raw), ":")) != 4 {
			t.Fatal("unexpected public fields", string(raw))
		}
		node, err := h.owner.ReadNode(ctx, result.NodeID, 0)
		if err != nil {
			t.Fatal(err)
		}
		return node
	}
	parent := call(vaultFolderInput("", "0", ""))
	first := call(vaultFolderInput("", "0", parent.ID))
	second := call(vaultFolderInput("", "0", parent.ID))
	if first.SortOrder != 0 || second.SortOrder != 1 || first.Name != "Folder 🐛" || first.SshAutoSudo != nil || first.TunnelEnabled != nil {
		t.Fatal(first, second)
	}
	// Migrated folders can contain settings the folder form does not display.
	host, domain, protocol := "retained-host", "retained-domain", 0
	first.Host, first.RDPDomain, first.Protocol = &host, &domain, &protocol
	stored, err := h.owner.PutNode(ctx, first.NodeMetadata, []localvault.SecretChange{{Field: "notes", Value: []byte("private-note")}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	input := vaultFolderInput(first.ID, "2", parent.ID)
	input["name"], input["sshAutoSudo"], input["tunnelEnabled"], input["credentialMode"] = "Renamed", false, false, 1
	changed := call(input)
	if changed.Name != "Renamed" || changed.RowVersion != 3 || changed.SortOrder != first.SortOrder || *changed.Host != host || *changed.RDPDomain != domain || changed.CreatedAt != stored.CreatedAt || !reflect.DeepEqual(changed.Fields, stored.Fields) || *changed.SshAutoSudo || *changed.TunnelEnabled {
		t.Fatal(changed)
	}
	for field, want := range map[string]string{"notes": "private-note"} {
		if err := h.owner.WithNodeField(ctx, first.ID, field, 3, func(value []byte) error {
			if string(value) != want {
				t.Fatal("secret changed")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.Handle(ctx, "folder-save", vaultInput(t, input)); err != vaultstore.ErrConflict {
		t.Fatal("stale editor overwrote newer row", err)
	}
	input["rowVersion"], input["parentId"] = "3", first.ID
	if _, err := h.Handle(ctx, "folder-save", vaultInput(t, input)); err == nil {
		t.Fatal("cycle accepted")
	}
	unchanged, err := h.owner.ReadNode(ctx, first.ID, 0)
	if err != nil || !reflect.DeepEqual(unchanged, changed) {
		t.Fatal("failed mutation changed stored row", err)
	}
}

func TestVaultFolderRejectsInvalidAndUnownedRequests(t *testing.T) {
	h, ctx := vaultCredentialFixture(t), context.Background()
	for key, values := range map[string][]any{
		"id": {nil, 1, "bad", uuid.NewString()}, "rowVersion": {nil, 0, "01", "-1", "9223372036854775807", "1"},
		"parentId": {nil, "bad"}, "name": {nil, "", "  ", "line\nfeed", strings.Repeat("x", 257)},
		"sshAutoSudo": {0, "true"}, "tunnelEnabled": {1, "false"}, "tunnelConfigId": {nil, "bad"},
		"credentialMode": {nil, -1, 3, "0", 2}, "credentialId": {nil, "bad", uuid.NewString()}, "notes": {"never accepted"},
	} {
		for _, value := range values {
			input := vaultFolderInput("", "0", "")
			input[key] = value
			if _, err := h.Handle(ctx, "folder-save", vaultInput(t, input)); err != vaultwire.ErrProtocol {
				t.Fatalf("%s accepted: %v", key, err)
			}
		}
	}
	valid := vaultInput(t, vaultFolderInput("", "0", ""))
	for _, raw := range [][]byte{nil, []byte(`null`), []byte(`{}`), []byte(strings.Repeat(" ", 8193)), []byte(strings.Replace(string(valid), `"name":`, `"name":"duplicate","name":`, 1))} {
		if _, err := h.Handle(ctx, "folder-save", raw); err != vaultwire.ErrProtocol {
			t.Fatal(err)
		}
	}
	if _, err := (&vaultFoundationHandler{}).Handle(ctx, "folder-save", valid); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	for _, input := range []map[string]any{vaultFolderInput(uuid.NewString(), "1", ""), vaultFolderInput("", "0", uuid.NewString())} {
		if _, err := h.Handle(ctx, "folder-save", vaultInput(t, input)); err == nil {
			t.Fatal("missing reference accepted")
		}
	}
	connection, err := h.owner.PutNode(ctx, vaultstore.NodeMetadata{ID: uuid.NewString(), Kind: 1, Name: "Connection"}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "folder-save", vaultInput(t, vaultFolderInput(connection.ID, "1", ""))); err != vaultstore.ErrConflict {
		t.Fatal("connection converted to folder", err)
	}
	credential := uuid.NewString()
	if _, err := h.Handle(ctx, "credential-save", vaultCredentialSave(t, credential, "0", []map[string]any{})); err != nil {
		t.Fatal(err)
	}
	input := vaultFolderInput("", "0", "")
	input["credentialMode"], input["credentialId"] = 2, credential
	if _, err := h.Handle(ctx, "folder-save", vaultInput(t, input)); err != nil {
		t.Fatal(err)
	}
	input["tunnelConfigId"] = uuid.NewString()
	if _, err := h.Handle(ctx, "folder-save", vaultInput(t, input)); err == nil {
		t.Fatal("missing tunnel accepted")
	}
	if _, err := h.owner.PutNode(ctx, vaultstore.NodeMetadata{ID: uuid.NewString(), Kind: 0, Name: "End", SortOrder: math.MaxInt64}, nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "folder-save", valid); err != vaultstore.ErrConflict {
		t.Fatal("sort overflow", err)
	}
	if err := h.owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.saveFolder(ctx, valid); err == nil {
		t.Fatal("closed owner accepted")
	}
}

func TestVaultFolderAppendPagesAuthenticatedNodes(t *testing.T) {
	h, ctx := vaultCredentialFixture(t), context.Background()
	for i := 0; i < 130; i++ {
		if _, err := h.owner.PutNode(ctx, vaultstore.NodeMetadata{ID: uuid.NewString(), Kind: 0, Name: "Folder", SortOrder: int64(i)}, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	if order, err := h.nextNodeSortOrder(ctx, ""); err != nil || order != 130 {
		t.Fatal(order, err)
	}
}
