package main

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// A real protected SQLite fixture for native-client interoperability. No user
// profile is opened; only public node/workspace identities leave this process.
func TestVaultWebPlanFixture(t *testing.T) {
	path := os.Getenv("WORMHOLE_TEST_WEB_PLAN_DATABASE")
	if path == "" {
		t.Skip("native web plan fixture")
	}
	doc, root := localSlotFixture(t)
	defer vault.Wipe(root)
	doc.Initializing = true
	o, err := initializeVaultFiles(context.Background(), path, doc, root)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	host, port, protocol, webPath, ignore := "127.0.0.1", 8443, 4, "/native%2Fpath?not=persisted#page", true
	if originPort := os.Getenv("WORMHOLE_TEST_WEB_COOKIE_PORT"); originPort != "" {
		n, err := strconv.Atoi(originPort)
		if err != nil || n < 1 || n > 65535 {
			t.Fatal("invalid web cookie fixture port")
		}
		port, protocol, webPath, ignore = n, 3, "/login", false
	}
	m := vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Native web plan", Kind: 1, Host: &host, Port: &port, Protocol: &protocol, HTTPPath: &webPath, HTTPIgnoreCertErrors: &ignore}
	if os.Getenv("WORMHOLE_TEST_WEB_PLAN_ROUTED") == "1" {
		tunnel, e := o.PutTunnel(context.Background(), vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "Private web VPN", Kind: 6}, []byte("web-native-private-vpn-settings"), 0)
		if e != nil {
			t.Fatal(e)
		}
		enabled := true
		m.TunnelEnabled, m.TunnelConfigID = &enabled, &tunnel.ID
	}
	if _, err = o.PutNode(context.Background(), m, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err = o.Close(); err != nil {
		t.Fatal(err)
	}
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"workspaceId": doc.VaultID, "nodeId": m.ID}); err != nil {
		t.Fatal(err)
	}
}
