package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestVaultSharedConnectionContextResolvesInheritedProtocolWithoutRelease(t *testing.T) {
	for _, protocol := range []int{0, 7} {
		t.Run(string(rune('0'+protocol)), func(t *testing.T) {
			c, p, o, _, account, _, node, wire := credentialControllerFixture(t, vault.Default)
			metadata := wire["metadata"].(map[string]any)
			leafRow := metadata["chain"].([]any)[0].([]any)
			var leaf vaultstore.NodeMetadata
			var credential sharedcatalog.CredentialRecord
			if json.Unmarshal([]byte(leafRow[4].(string)), &leaf) != nil || json.Unmarshal([]byte(metadata["credential"].([]any)[4].(string)), &credential) != nil {
				t.Fatal("fixture")
			}
			parent := vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Parent", Kind: 0, Protocol: &protocol}
			leaf.Protocol = nil
			leaf.ParentID = &parent.ID
			key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{34}, 32))
			defer vault.Wipe(key)
			parentRow := append([]any(nil), leafRow...)
			parentRow[1] = parent.ID
			for i, n := range []vaultstore.NodeMetadata{leaf, parent} {
				row := leafRow
				if i == 1 {
					row = parentRow
				}
				raw, _ := json.Marshal(n)
				seal, err := sharedcatalog.SignNode(o.Binding.WorkspaceID, uuid.MustParse(row[5].(string)), n, 1, account.State.Signing, key)
				if err != nil {
					t.Fatal(err)
				}
				row[4], row[11] = string(raw), hex.EncodeToString(seal.Signature)
			}
			metadata["chain"] = []any{leafRow, parentRow}
			plan, err := resolver.Resolve([]vaultstore.NodeMetadata{leaf, parent}, "")
			if err != nil {
				t.Fatal(err)
			}
			plan, err = resolver.ApplyCredential(plan, credential.Metadata)
			if err != nil {
				t.Fatal(err)
			}
			metadata["plan"] = plan
			p.begin = func(context.Context, uuid.UUID, string) (*sharedpg.UseIntent, error) {
				t.Fatal("public context issued a ticket")
				return nil, nil
			}
			p.fetch = func(context.Context, sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
				t.Fatal("public context fetched ciphertext")
				return nil, nil
			}
			if err := c.privateKeys.With(func(value []byte) error { vault.Wipe(value); return nil }); err != nil {
				t.Fatal(err)
			}
			h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c}}
			t.Cleanup(func() { _ = h.Close() })
			request, _ := json.Marshal(map[string]any{"nodeId": node.String()})
			raw, err := h.Handle(context.Background(), "shared-connection-context", request)
			var result struct {
				NodeID   string `json:"nodeId"`
				Protocol int    `json:"protocol"`
			}
			var fields map[string]json.RawMessage
			if err != nil || json.Unmarshal(raw, &result) != nil || json.Unmarshal(raw, &fields) != nil || len(fields) != 2 || result.NodeID != node.String() || result.Protocol != protocol {
				t.Fatal("inherited public context", err)
			}
			for _, bad := range [][]byte{nil, []byte(`{}`), []byte(`{"nodeId":1}`), []byte(`{"nodeId":"invalid"}`), []byte(`{"nodeId":"` + node.String() + `","password":"private"}`), bytes.Repeat([]byte(" "), 257)} {
				if _, err := h.Handle(context.Background(), "shared-connection-context", bad); err != vaultwire.ErrProtocol || !c.Unlocked() {
					t.Fatal("invalid context changed owner", err)
				}
			}
		})
	}
	if _, err := (&vaultFoundationHandler{}).sharedConnectionContext(context.Background(), nil); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
}

func TestVaultSharedConnectionContextRequiresAdmittedController(t *testing.T) {
	h := &vaultFoundationHandler{shared: &vaultSharedSession{}}
	raw, err := h.Handle(context.Background(), "shared-connection-context", []byte(`{"nodeId":"11111111-1111-4111-8111-111111111111"}`))
	if err != vaultwire.ErrProtocol || len(raw) != 0 || h.closed {
		t.Fatal("unadmitted context", err)
	}
}

func TestVaultSharedConnectionContextFailureRetiresOwner(t *testing.T) {
	c, p, _, _, _, _, node, _ := credentialControllerFixture(t, vault.Default)
	p.plan = func(context.Context, uuid.UUID) (*sharedpg.UnverifiedConnectionPlan, error) {
		return nil, errors.New("private")
	}
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c}}
	request, _ := json.Marshal(map[string]any{"nodeId": node.String()})
	raw, err := h.Handle(context.Background(), "shared-connection-context", request)
	if !errors.Is(err, vaultwire.ErrRetired) || len(raw) != 0 || !h.closed || c.Unlocked() {
		t.Fatal("failed context retained owner", err)
	}
}
