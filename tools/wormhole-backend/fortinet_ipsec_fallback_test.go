package main

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
)

func fallbackFixture(t *testing.T) (tunnelConfigSnapshot, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vpn.db")
	ssl, err := createTunnel(path, tunnelWriteRequest{Name: "SSL", Kind: 2, Settings: json.RawMessage(`{"Host":"vpn.test","Port":443,"Username":"user","Password":"ssl-private"}`)})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"Host": "vpn.test", "PreSharedKey": "ipsec-private", "UserAuth": 0, "IkeVersion": 2, "FallbackTunnelId": ssl.ID})
	vpn, err := createTunnel(path, tunnelWriteRequest{Name: "IPsec", Kind: 9, Settings: raw})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := loadTunnelSnapshot(path, vpn.ID)
	if err == nil {
		snapshot, err = loadTunnelSnapshotSettings(snapshot)
	}
	if err != nil {
		t.Fatal(err)
	}
	snapshot.identity = "source-pinned"
	t.Cleanup(func() { clearBytes(snapshot.settings) })
	return snapshot, ssl.ID
}
func TestFortinetSSLFallback(t *testing.T) {
	for _, mode := range []string{"primary-success", "ssl-success", "ssl-failure", "cancel-context", "cancel-prompt", "changed", "no-fallback", "different-provider"} {
		t.Run(mode, func(t *testing.T) {
			snapshot, id := fallbackFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			if mode == "cancel-prompt" {
				snapshot.prompt = func(context.Context, tunnelPrompt) (string, error) { return "", errors.New("cancelled") }
			}
			if mode == "no-fallback" {
				snapshot.settings = json.RawMessage(`{"Host":"vpn.test","PreSharedKey":"private","UserAuth":0}`)
				snapshot.fallbackIdentity = ""
			}
			if mode == "different-provider" {
				snapshot.kind = 2
			}
			start := func(ctx context.Context, s tunnelConfigSnapshot) (*tunnelProcess, error) {
				calls++
				if calls == 1 {
					switch mode {
					case "primary-success", "different-provider":
						return &tunnelProcess{}, nil
					case "cancel-context":
						cancel()
					case "cancel-prompt":
						_, _ = s.prompt(ctx, tunnelPrompt{})
					case "changed":
						_, err := updateTunnel(snapshot.databasePath, tunnelWriteRequest{ID: id, Name: "Changed SSL", Kind: 2, Settings: json.RawMessage(`{"Host":"different.test","Username":"user","Password":"new"}`)})
						if err != nil {
							t.Fatal(err)
						}
					}
					return nil, errors.New("IPsec failed")
				}
				if s.kind != 2 || s.id != id {
					t.Fatal("fallback is not the selected SSL profile")
				}
				if mode == "ssl-failure" {
					return nil, errors.New("ssl-private error")
				}
				return &tunnelProcess{}, nil
			}
			process, err := startTunnelWithFallback(ctx, snapshot, start)
			success := mode == "primary-success" || mode == "ssl-success" || mode == "different-provider"
			if (err == nil) != success {
				t.Fatal("unexpected fallback outcome", err)
			}
			expected := 1
			if mode == "ssl-success" || mode == "ssl-failure" {
				expected = 2
			}
			if calls != expected {
				t.Fatal("wrong startup count", calls)
			}
			if mode == "ssl-success" && process.identity != snapshot.identity {
				t.Fatal("fallback lost source lease identity")
			}
		})
	}
}
func TestFortinetFallbackValidationAndIdentity(t *testing.T) {
	snapshot, id := fallbackFixture(t)
	if snapshot.fallbackIdentity == "" {
		t.Fatal("fallback not pinned")
	}
	database, err := openDatabase(snapshot.databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if validateFortinetFallback(database, id) != nil || validateFortinetFallback(nil, "") != nil {
		t.Fatal("valid fallback rejected")
	}
	for _, invalid := range []string{snapshot.id, "missing"} {
		if validateFortinetFallback(database, invalid) == nil {
			t.Fatal("invalid fallback accepted")
		}
	}
	snapshot.fallbackIdentity = "changed"
	if _, err := startTunnelWithFallback(context.Background(), snapshot, func(context.Context, tunnelConfigSnapshot) (*tunnelProcess, error) {
		t.Fatal("changed fallback started")
		return nil, nil
	}); err == nil {
		t.Fatal("changed fallback not detected")
	}
	if fortinetFallbackID(json.RawMessage(`null`)) != "" {
		t.Fatal("invalid settings yielded fallback")
	}
	values := ipsecTestSettings()
	values["FallbackTunnelId"] = "invalid"
	raw, _ := json.Marshal(values)
	if _, err := createTunnel(snapshot.databasePath, tunnelWriteRequest{Name: "bad", Kind: 9, Settings: raw}); err == nil {
		t.Fatal("invalid fallback persisted")
	}
}
