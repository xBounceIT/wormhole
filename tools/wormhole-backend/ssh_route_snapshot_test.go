package main

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSSHDelegatedRouteRejectsChangedSavedTargets(t *testing.T) {
	const oldID = "11111111-2222-4333-8444-555555555555"
	const newID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	for _, mode := range []string{"terminal", "sftp", "smb"} {
		t.Run(mode, func(t *testing.T) {
			server := sshRouteSnapshotTestServer(t, mode, 1, true, newID)
			for _, prior := range []string{"", oldID} {
				for _, socks := range []string{"", "127.0.0.1:1"} {
					command := sshWireCommand{
						NodeID: "node", Mode: mode, SocksEndpoint: socks,
						CredentialOverride: true, UsernameOverride: "user", PasswordOverride: "test",
					}
					// Exercise the actual wire field rather than a separate route-validation helper.
					payload, err := json.Marshal(map[string]string{"configured_tunnel_id": prior})
					require.NoError(t, err)
					require.NoError(t, json.Unmarshal(payload, &command))
					if socks == "" {
						direct := false
						command.TunnelEnabled = &direct
					}
					native, _, err := server.openNativeSSH(context.Background(), &sshReconnectState{command: command})
					require.Nil(t, native)
					require.ErrorContains(t, err, "VPN route no longer matches")
				}
			}
		})
	}
}

func TestSSHDelegatedRoutePreservesUnchangedRoutesAndRejectsMissingMetadata(t *testing.T) {
	const tunnelID = "11111111-2222-4333-8444-555555555555"
	empty, configured := "", tunnelID
	direct := false
	for _, mode := range []string{"terminal", "sftp", "smb"} {
		for _, row := range []struct {
			name     string
			enabled  bool
			selected *string
			override *bool
			socks    bool
			reject   bool
		}{
			{"disabled-with-unused-id", false, &empty, &direct, false, false},
			{"explicit-direct", true, &configured, &direct, false, false},
			{"delegated-socks", true, &configured, nil, true, false},
			{"standalone-go-direct", false, nil, nil, false, false},
			{"missing-direct-snapshot", true, nil, &direct, false, true},
			{"missing-socks-snapshot", true, nil, nil, true, true},
			{"removed-vpn", false, &configured, &direct, false, true},
		} {
			t.Run(mode+"/"+row.name, func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				defer listener.Close()
				accepted := make(chan struct{}, 1)
				go func() {
					connection, err := listener.Accept()
					if err == nil {
						accepted <- struct{}{}
						_ = connection.Close()
					}
				}()
				server := sshRouteSnapshotTestServer(t, mode, listener.Addr().(*net.TCPAddr).Port, row.enabled, tunnelID)
				command := sshWireCommand{
					NodeID: "node", Mode: mode, ConfiguredTunnelID: row.selected, TunnelEnabled: row.override,
					CredentialOverride: true, UsernameOverride: "user", PasswordOverride: "test",
				}
				if row.socks {
					command.SocksEndpoint = listener.Addr().String()
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				native, _, err := server.openNativeSSH(ctx, &sshReconnectState{command: command})
				require.Nil(t, native)
				// The loopback fixture closes immediately; reaching it proves valid routes proceed.
				require.Error(t, err)
				if row.reject {
					require.ErrorContains(t, err, "VPN route no longer matches")
					select {
					case <-accepted:
						t.Fatal("changed route reached the network")
					default:
					}
				} else {
					require.NotContains(t, err.Error(), "VPN route no longer matches")
					select {
					case <-accepted:
					case <-ctx.Done():
						t.Fatal("unchanged route did not reach the loopback fixture")
					}
				}
			})
		}
	}
}

func sshRouteSnapshotTestServer(t *testing.T, mode string, port int, enabled bool, tunnelID string) *sshServer {
	t.Helper()
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	require.NoError(t, err)
	defer database.Close()
	protocol, host := int64(0), "127.0.0.1"
	if mode == "smb" {
		protocol, host = smbProtocolValue, "smb://127.0.0.1/share"
	}
	_, err = database.Exec(`CREATE TABLE Nodes (
Id TEXT PRIMARY KEY, ParentId TEXT, Name TEXT, Kind INTEGER, Protocol INTEGER, Host TEXT,
Port INTEGER, Username TEXT, TunnelEnabled INTEGER, TunnelConfigId TEXT);
INSERT INTO Nodes VALUES ('node', NULL, 'Edited target', 1, ?, ?, ?, 'user', ?, ?);`, protocol, host, port, enabled, tunnelID)
	require.NoError(t, err)
	return &sshServer{databasePath: databasePath}
}
