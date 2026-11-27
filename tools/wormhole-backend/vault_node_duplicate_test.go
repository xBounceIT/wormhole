package main

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
	"strings"
	"testing"
)

func TestVaultDuplicateConnectionStrictRequestAndPublicResult(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	id := uuid.NewString()
	inline := true
	n, err := h.owner.PutNode(ctx, vaultstore.NodeMetadata{ID: id, Name: "Source", Kind: 1, UseInlinePassword: &inline}, []localvault.SecretChange{{Field: "inlinePassword", Value: []byte("private-copy-password")}, {Field: "notes", Value: []byte("private-copy-notes")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	valid := `{"id":"` + id + `","rowVersion":"1"}`
	for _, bad := range []string{`null`, `{}`, `{"id":"` + id + `"}`, strings.Replace(valid, `"1"`, `null`, 1), strings.Replace(valid, `"1"`, `"0"`, 1), strings.Replace(valid, `"1"`, `1`, 1), strings.Replace(valid, `"1"`, `"01"`, 1), strings.Replace(valid, `"1"`, `"9223372036854775807"`, 1), strings.Replace(valid, id, "bad", 1), strings.Replace(valid, `}`, `,"password":"extra"}`, 1), strings.Repeat(" ", 1025)} {
		if _, err := h.Handle(ctx, "node-duplicate", []byte(bad)); err != vaultwire.ErrProtocol {
			t.Fatal("bad duplicate request accepted", err)
		}
	}
	if _, err := (&vaultFoundationHandler{}).Handle(ctx, "node-duplicate", []byte(valid)); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "node-duplicate", []byte(strings.Replace(valid, `"1"`, `"2"`, 1))); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	body, err := h.Handle(ctx, "node-duplicate", []byte(valid))
	var result map[string]string
	if err != nil || json.Unmarshal(body, &result) != nil || len(result) != 3 || result["nodeId"] == id || result["name"] != "Source (copy)" || result["rowVersion"] != "1" {
		t.Fatal("bad public acknowledgement", string(body), err)
	}
	if strings.Contains(string(body), "private-copy") {
		t.Fatal("plaintext crossed protocol")
	}
	if got, err := h.owner.ReadNode(ctx, n.ID, n.RowVersion); err != nil || got.RowVersion != n.RowVersion {
		t.Fatal("source mutated", err)
	}
}
