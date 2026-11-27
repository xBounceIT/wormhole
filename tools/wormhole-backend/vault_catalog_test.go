package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestVaultCatalogRequiresOwnerAndProjectsMetadata(t *testing.T) {
	ctx := context.Background()
	if _, err := (&vaultFoundationHandler{}).Handle(ctx, "catalog", nil); err != vaultwire.ErrProtocol {
		t.Fatal("locked catalog", err)
	}
	var h *vaultFoundationHandler
	if path := os.Getenv("WORMHOLE_TEST_CATALOG_DATABASE"); path != "" {
		doc, key := localSlotFixture(t)
		defer vault.Wipe(key)
		doc.Initializing = true
		password, err := vault.CreatePasswordSlot(ctx, doc.VaultID, uuid.NewString(), 1, key, []byte("native-password-🧪"), nil, vault.KDFV1)
		if err != nil {
			t.Fatal(err)
		}
		doc.Slots = append(doc.Slots, password)
		owner, err := initializeVaultFiles(ctx, path, doc, key)
		if err != nil {
			t.Fatal(err)
		}
		h = &vaultFoundationHandler{databasePath: path, owner: owner}
		t.Cleanup(func() { h.Close() })
	} else {
		h = vaultCredentialFixture(t)
	}
	if raw, err := h.Handle(ctx, "catalog", nil); err != nil || string(raw) != `{"nodes":[],"credentials":[],"tunnels":[]}` {
		t.Fatal("empty catalog", string(raw), err)
	}
	if _, err := h.Handle(ctx, "catalog", json.RawMessage(`{}`)); err != vaultwire.ErrProtocol {
		t.Fatal("payload accepted", err)
	}
	c := vaultstore.CredentialMetadata{ID: uuid.NewString(), Name: "Account <&> 日本語\u2028😀", Protocol: "ssh", Kind: "password", Provider: "local", Username: "user", Domain: "domain"}
	if _, err := h.owner.PutCredential(ctx, c, []localvault.SecretChange{{Field: "password", Value: []byte("catalog-private-password")}}, 0); err != nil {
		t.Fatal(err)
	}
	n := vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Connection", Kind: 1, SortOrder: -9223372036854775808, Protocol: displayPtr(1), Host: displayPtr("host.example"), RDPDomain: displayPtr(" domain 🧪 "), RDPScreenSize: displayPtr("\u0085fitToWindow\u0085")}
	if _, err := h.owner.PutNode(ctx, n, []localvault.SecretChange{{Field: "notes", Value: []byte("catalog-private-notes")}}, 0); err != nil {
		t.Fatal(err)
	}
	tunnel := vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "VPN", Kind: 2}
	if _, err := h.owner.PutTunnel(ctx, tunnel, []byte(`{"password":"catalog-private-tunnel"}`), 0); err != nil {
		t.Fatal(err)
	}
	raw, err := h.Handle(ctx, "catalog", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"catalog-private-", "seal", "fields", "root", "keyVersion", "configuration", "createdAt"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatal("private/native field in catalog", forbidden)
		}
	}
	var result struct {
		Nodes       []vaultCatalogNode
		Credentials []vaultCatalogCredential
		Tunnels     []vaultCatalogTunnel
	}
	if json.Unmarshal(raw, &result) != nil || len(result.Nodes) != 1 || len(result.Credentials) != 1 || len(result.Tunnels) != 1 {
		t.Fatal("missing domain")
	}
	if result.Nodes[0].SortOrder != "-9223372036854775808" || !result.Nodes[0].HasNotes || result.Nodes[0].Protocol == nil || *result.Nodes[0].Protocol != 1 || result.Credentials[0].Name != c.Name || result.Tunnels[0].Kind != 2 {
		t.Fatal("projection changed metadata")
	}
	// The Electron native integration test consumes the real Go-encoded metadata.
	// Only this synthetic fixture is exported; no secret payload or key is written.
	if path := os.Getenv("WORMHOLE_TEST_CATALOG_FRAME"); path != "" {
		frame, err := json.Marshal(struct {
			Version int             `json:"version"`
			ID      int             `json:"id"`
			Result  json.RawMessage `json:"result"`
		}{1, 1, raw})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, frame, 0o600); err != nil {
			t.Fatal(err)
		}
		workspace, err := h.Handle(ctx, "workspace", nil)
		if err != nil {
			t.Fatal(err)
		}
		frame, err = json.Marshal(struct {
			Version int             `json:"version"`
			ID      int             `json:"id"`
			Result  json.RawMessage `json:"result"`
		}{1, 1, workspace})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".workspace", frame, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "catalog", nil); !errors.Is(err, vaultstore.ErrClosed) || !errors.Is(err, vaultwire.ErrRetired) || !h.closed {
		t.Fatal("retired owner used", err)
	}
}
