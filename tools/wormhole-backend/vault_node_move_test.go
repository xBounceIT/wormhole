package main

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
	"strings"
	"testing"
)

func TestVaultNodeMoveStrictRequest(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	id, target := uuid.NewString(), uuid.NewString()
	for _, v := range []string{id, target} {
		if _, err := h.Handle(ctx, "node-save", vaultNodeSave(t, v, "0", map[string]any{"id": v, "name": "Folder", "kind": 0, "sortOrder": "0"}, []map[string]any{})); err != nil {
			t.Fatal(err)
		}
	}
	valid := `{"nodes":[{"id":"` + id + `","rowVersion":"1"}],"target":{"id":"` + target + `","rowVersion":"1"},"placement":"inside"}`
	for _, bad := range []string{`{}`, `null`, strings.Replace(valid, `"inside"`, `null`, 1), strings.Replace(valid, `"inside"`, `"around"`, 1), strings.Replace(valid, `"nodes":[{`, `"nodes":[null,{`, 1), strings.Replace(valid, `"1"`, `"0"`, 1), strings.Replace(valid, `"1"`, `"9223372036854775807"`, 1), strings.Replace(valid, target, id, 1), strings.Replace(valid, id, "bad", 1), strings.Replace(valid, `"rowVersion":"1"`, `"rowVersion":1`, 1), strings.Repeat(" ", 512*1024+1), `{"nodes":[],"target":{},"placement":"inside"}`} {
		if _, err := h.Handle(ctx, "node-move", []byte(bad)); err != vaultwire.ErrProtocol {
			t.Fatal("bad input", err)
		}
	}
	if _, err := (&vaultFoundationHandler{}).Handle(ctx, "node-move", []byte(valid)); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "node-move", []byte(strings.Replace(valid, `"1"`, `"2"`, 1))); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	result, err := h.Handle(ctx, "node-move", []byte(valid))
	var got struct {
		Moved bool   `json:"moved"`
		Count string `json:"updatedCount"`
	}
	if err != nil || json.Unmarshal(result, &got) != nil || !got.Moved || got.Count != "1" {
		t.Fatal(string(result), err)
	}
}
