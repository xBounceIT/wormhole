package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// The Electron integration fixture persists a real protected credential. Only
// public connection identifiers are printed; the fake RFB server independently
// checks the VNCAuth response before accepting any frame/input traffic.
func TestVaultVNCRelayFixture(t *testing.T) {
	path := os.Getenv("WORMHOLE_TEST_VNC_RELAY")
	if path == "" {
		t.Skip("Electron native VNC integration fixture")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	doc, root := localSlotFixture(t)
	defer vault.Wipe(root)
	doc.Initializing = true
	owner, err := initializeVaultFiles(context.Background(), path, doc, root)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	credential, err := owner.PutCredential(context.Background(), vaultstore.CredentialMetadata{ID: uuid.NewString(), Name: "VNC relay account", Protocol: "vnc", Kind: "password", Provider: "local"}, []localvault.SecretChange{{Field: "password", Value: []byte("relay-native-only-password")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	host, port, protocol, mode := "127.0.0.1", listener.Addr().(*net.TCPAddr).Port, 6, 2
	metadata := vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Native VNC fixture", Kind: 1, Protocol: &protocol, Host: &host, Port: &port, CredentialID: &credential.ID, CredentialMode: &mode}
	if os.Getenv("WORMHOLE_TEST_VNC_RELAY_ROUTE") == "1" {
		host = "127.0.0.2"
		tunnel, e := owner.PutTunnel(context.Background(), vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "VNC fixture VPN", Kind: 6}, []byte(`{"Host":"gateway.invalid","Username":"vpn-user","Password":"route-sidecar-password"}`), 0)
		if e != nil {
			t.Fatal(e)
		}
		enabled := true
		metadata.TunnelEnabled = &enabled
		metadata.TunnelConfigID = &tunnel.ID
	}
	if os.Getenv("WORMHOLE_TEST_VNC_RELAY_QUICK") != "1" {
		if _, err = owner.PutNode(context.Background(), metadata, nil, 0); err != nil {
			t.Fatal(err)
		}
	} else {
		metadata.ID = ""
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"workspaceId": doc.VaultID, "nodeId": metadata.ID, "port": port, "host": host, "credentialId": credential.ID, "tunnelId": metadata.TunnelConfigID}); err != nil {
		t.Fatal(err)
	}
	inputs := make(chan string, 2)
	password := "relay-native-only-password"
	if os.Getenv("WORMHOLE_TEST_VNC_RELAY_MANUAL") == "1" {
		password = "temporary-only-password"
	}
	special := os.Getenv("WORMHOLE_TEST_VNC_RELAY_SPECIAL")
	if special == "empty" || special == "absent" {
		password = ""
	}
	if err := serveFakeVncWithFormat(listener, inputs, [16]byte{32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0}, password, special == "empty"); err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 2 {
		t.Fatal("VNC server did not receive mouse and keyboard input")
	}
}
