package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestVaultNodeDeleteTreesStrictVersionedRequest(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	id, child := uuid.NewString(), uuid.NewString()
	for _, metadata := range []map[string]any{{"id": id, "name": "Folder", "kind": 0, "sortOrder": "0"}, {"id": child, "parentId": id, "name": "Child", "kind": 1, "sortOrder": "0"}} {
		if _, err := h.Handle(ctx, "node-save", vaultNodeSave(t, metadata["id"].(string), "0", metadata, []map[string]any{})); err != nil {
			t.Fatal(err)
		}
	}
	valid := `{"nodes":[{"id":"` + id + `","rowVersion":"1"},{"id":"` + child + `","rowVersion":"1"}]}`
	for _, payload := range []string{`{}`, `{"nodes":null}`, `{"nodes":[]}`, `{"nodes":{}}`, `{"nodes":[{}]}`, `{"nodes":[{"id":"` + id + `","rowVersion":"0"}]}`, strings.Replace(valid, `"1"`, `"9223372036854775807"`, 1), strings.Replace(valid, child, id, 1), strings.Replace(valid, `"rowVersion":"1"`, `"rowVersion":1`, 1), strings.Replace(valid, `"id":"`+id+`"`, `"id":"bad"`, 1), strings.Repeat(" ", 512*1024+1), `{"nodes":[` + strings.Repeat(`{"id":"`+id+`","rowVersion":"1"},`, vaultstore.MaxNodeDeleteRoots) + `{}]}`} {
		if _, err := h.Handle(ctx, "node-delete-trees", []byte(payload)); err != vaultwire.ErrProtocol {
			t.Fatalf("invalid request accepted: %v", err)
		}
	}
	if _, err := (&vaultFoundationHandler{}).Handle(ctx, "node-delete-trees", []byte(valid)); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	stale := strings.Replace(valid, `"1"`, `"2"`, 1)
	if _, err := h.Handle(ctx, "node-delete-trees", []byte(stale)); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	if _, err := h.owner.ReadNode(ctx, child, 1); err != nil {
		t.Fatal(err)
	}
	result, err := h.Handle(ctx, "node-delete-trees", []byte(valid))
	var got struct {
		Deleted bool   `json:"deleted"`
		Count   string `json:"deletedCount"`
	}
	if err != nil || json.Unmarshal(result, &got) != nil || !got.Deleted || got.Count != "2" {
		t.Fatal(string(result), err)
	}
}
