package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestSharedNodeEditRejectsMalformedSelectionBeforeOpeningVault(t *testing.T) {
	id := uuid.NewString()
	for _, tc := range []struct {
		name  string
		extra map[string]any
	}{
		{"read with empty snapshot", map[string]any{"workspaceId": ""}},
		{"extra property", map[string]any{"ownerUserId": id}},
		{"invalid node", map[string]any{"nodeId": "bad"}},
		{"noncanonical revision", map[string]any{"revision": "01"}},
		{"missing snapshot", map[string]any{"changes": map[string]string{"name": "New"}}},
		{"noncanonical sequence", map[string]any{"workspaceId": id, "epoch": "1", "changeSeq": "00", "changes": map[string]string{"name": "New"}}},
		{"invalid epoch", map[string]any{"workspaceId": id, "epoch": "0", "changeSeq": "1", "changes": map[string]string{"name": "New"}}},
		{"exhausted revision", map[string]any{"revision": "9223372036854775807", "workspaceId": id, "epoch": "1", "changeSeq": "1", "changes": map[string]string{"name": "New"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			action := map[string]any{"nodeId": id, "revision": "1"}
			for name, value := range tc.extra {
				action[name] = value
			}
			raw, err := json.Marshal(map[string]any{"action": action})
			if err != nil {
				t.Fatal(err)
			}
			_, err = (*vaultFoundationHandler)(nil).sharedNodeEdit(context.Background(), raw)
			if !errors.Is(err, vaultwire.ErrProtocol) || !bytes.Equal(raw, make([]byte, len(raw))) {
				t.Fatal("malformed selection or retained request bytes", err)
			}
		})
	}
}

func TestSharedMoveDestination(t *testing.T) {
	id := uuid.New()
	folder := `{"id":"` + id.String() + `","revision":"7"}`
	move, err := decodeSharedMove([]byte(`{"parent":` + folder + `}`))
	if err != nil || move == nil || move.id == nil || *move.id != id || move.revision != 7 {
		t.Fatal("lost folder identity or revision", err)
	}
	move, err = decodeSharedMove([]byte(`{"parent":null}`))
	if err != nil || move == nil || move.id != nil {
		t.Fatal("workspace root unavailable", err)
	}
	for _, parent := range []string{`{}`, `false`, `{"id":"bad","revision":"1"}`, `{"id":"` + id.String() + `","revision":"07"}`} {
		if move, err := decodeSharedMove([]byte(`{"parent":` + parent + `}`)); move != nil || err == nil {
			t.Fatal("invalid folder accepted", parent)
		}
	}
	if move, err := decodeSharedMove([]byte(`{"name":"Folder"}`)); err != nil || move != nil {
		t.Fatal("ordinary edit interpreted as move", err)
	}
}
