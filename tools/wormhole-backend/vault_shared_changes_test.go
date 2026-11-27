package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestVaultSharedChanges(t *testing.T) {
	c, p, _, _, _, _ := catalogControllerFixture(t)
	id := uuid.New()
	p.changes = func(_ context.Context, e, s uint64) (*sharedpg.CatalogChanges, error) {
		if e != 1 || s != 8 {
			t.Fatal("cursor")
		}
		return &sharedpg.CatalogChanges{Epoch: 1, ChangeSeq: 9, Nodes: []uuid.UUID{id}}, nil
	}
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c}}
	t.Cleanup(func() { _ = h.Close() })
	raw, err := h.Handle(context.Background(), "shared-changes", []byte(`{"epoch":"1","changeSeq":"8"}`))
	var value vaultSharedChanges
	if err != nil || json.Unmarshal(raw, &value) != nil || len(value.Nodes) != 1 || value.Nodes[0] != id.String() || value.Epoch != "1" || value.ChangeSeq != "9" || value.Reset {
		t.Fatal("projection", err)
	}
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	if len(fields) != 4 {
		t.Fatal("unexpected data")
	}
	if _, err := h.Handle(context.Background(), "shared-changes", []byte(`{}`)); err != vaultwire.ErrProtocol || !c.Unlocked() {
		t.Fatal("invalid request retired owner", err)
	}
	p.changes = func(context.Context, uint64, uint64) (*sharedpg.CatalogChanges, error) { return nil, sharedpg.ErrQuery }
	if raw, err := h.Handle(context.Background(), "shared-changes", []byte(`{"epoch":"1","changeSeq":"8"}`)); err == nil || raw != nil || !h.closed {
		t.Fatal("read failure kept owner", err)
	}
	if _, err := (&vaultFoundationHandler{}).sharedChanges(context.Background(), nil); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
}

func TestSharedChangesRequest(t *testing.T) {
	for _, raw := range []string{"", `null`, `{}`, strings.Repeat(" ", 257), `{"epoch":"0","changeSeq":"0","password":"x"}`, `{"epoch":"0","epoch":"0","changeSeq":"0"}`, `{"epoch":0,"changeSeq":"0"}`, `{"epoch":"00","changeSeq":"0"}`, `{"epoch":"0","changeSeq":"1"}`, `{"epoch":"-1","changeSeq":"0"}`, `{"epoch":"1","changeSeq":"9223372036854775808"}`} {
		if _, _, err := decodeSharedChangesRequest([]byte(raw)); err != vaultwire.ErrProtocol {
			t.Fatal("invalid request", err)
		}
	}
	for _, raw := range []string{`{"epoch":"0","changeSeq":"0"}`, `{"epoch":"1","changeSeq":"9223372036854775807"}`} {
		if _, _, err := decodeSharedChangesRequest([]byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
}
