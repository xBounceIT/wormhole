package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFortinetIPsecEditorNeverReturnsGatewayKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wormhole.db")
	raw, _ := json.Marshal(ipsecTestSettings())
	created, err := createTunnel(path, tunnelWriteRequest{Name: "IPsec", Kind: 9, Settings: raw})
	if err != nil {
		t.Fatal(err)
	}
	assertPublic := func(raw json.RawMessage) {
		t.Helper()
		if bytes.Contains(raw, []byte("fixture-psk")) || bytes.Contains(raw, []byte(`"PreSharedKey"`)) || !bytes.Contains(raw, []byte(`"HasPreSharedKey":true`)) {
			t.Fatal("editor received a gateway key")
		}
	}
	assertPublic(created.Settings)
	read, err := readTunnel(path, tunnelReadRequest{ID: created.ID})
	if err != nil {
		t.Fatal(err)
	}
	assertPublic(read.Settings)
	updated, err := updateTunnel(path, tunnelWriteRequest{ID: created.ID, Name: "Renamed", Kind: 9, Settings: read.Settings})
	if err != nil {
		t.Fatal(err)
	}
	assertPublic(updated.Settings)
	private, err := readTunnelUnlocked(path, tunnelReadRequest{ID: created.ID})
	if err != nil || !bytes.Contains(private.Settings, []byte("fixture-psk")) || bytes.Contains(private.Settings, []byte("HasPreSharedKey")) {
		t.Fatal("preserved runtime key lost", err)
	}
	settings := ipsecTestSettings()
	settings["PreSharedKey"] = "replacement-key"
	replacement, _ := json.Marshal(settings)
	updated, err = updateTunnel(path, tunnelWriteRequest{ID: created.ID, Name: "Renamed", Kind: 9, Settings: replacement})
	if err != nil || bytes.Contains(updated.Settings, []byte("replacement-key")) {
		t.Fatal("replacement returned to editor", err)
	}
	private, err = readTunnelUnlocked(path, tunnelReadRequest{ID: created.ID})
	if err != nil || !bytes.Contains(private.Settings, []byte("replacement-key")) {
		t.Fatal("replacement not saved", err)
	}
	if _, err := createTunnel(path, tunnelWriteRequest{Name: "Forged", Kind: 9, Settings: read.Settings}); err == nil {
		t.Fatal("create accepted a foreign preservation marker")
	}
	if _, err := updateTunnel(path, tunnelWriteRequest{ID: newTunnelID(), Name: "Missing", Kind: 9, Settings: read.Settings}); err == nil {
		t.Fatal("missing key was accepted")
	}
	database, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE TunnelConfigs SET Kind = 2 WHERE Id = ?;", created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := updateTunnel(path, tunnelWriteRequest{ID: created.ID, Name: "Wrong provider", Kind: 9, Settings: read.Settings}); err == nil {
		t.Fatal("another provider's key was preserved")
	}
	if _, err := database.Exec("UPDATE TunnelConfigs SET Kind = 9 WHERE Id = ?;", created.ID); err != nil {
		t.Fatal(err)
	}
	database.Close()
	if err := os.WriteFile(legacyTunnelSecretPath(path, created.ID), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := updateTunnel(path, tunnelWriteRequest{ID: created.ID, Name: "Corrupt", Kind: 9, Settings: read.Settings}); err == nil {
		t.Fatal("unreadable preserved key was accepted")
	}
	if _, err := updateTunnel(path, tunnelWriteRequest{ID: created.ID, Name: "Recovered", Kind: 9, Settings: replacement}); err != nil {
		t.Fatal("native replacement could not recover an unreadable key", err)
	}
}

func TestFortinetIPsecKeyMarkerValidation(t *testing.T) {
	for _, marker := range []string{`null`, `false`, `"true"`, `1`, `{}`} {
		settings := map[string]json.RawMessage{"Host": json.RawMessage(`"vpn.test"`), "HasPreSharedKey": json.RawMessage(marker)}
		if validateFortinetIPsecWriteSettings(settings) == nil {
			t.Fatal("invalid key marker accepted", marker)
		}
	}
	settings := map[string]json.RawMessage{"Host": json.RawMessage(`"vpn.test"`), "HasPreSharedKey": json.RawMessage(`true`), "PreSharedKey": json.RawMessage(`"conflict"`)}
	if validateFortinetIPsecWriteSettings(settings) == nil {
		t.Fatal("conflicting key sources accepted")
	}
	if _, err := tunnelEditorSettings(9, "", json.RawMessage(`null`)); err == nil {
		t.Fatal("invalid editor object accepted")
	}
	public, err := tunnelEditorSettings(9, "", json.RawMessage(`{"Host":"vpn.test"}`))
	if err != nil || !bytes.Contains(public, []byte(`"HasPreSharedKey":false`)) {
		t.Fatal("missing key presence is incorrect", err)
	}
	if _, err := resolveFortinetIPsecWriteSettings(nil, "", "", json.RawMessage(`null`), true); err == nil {
		t.Fatal("invalid write object accepted")
	}
	if _, err := resolveFortinetIPsecWriteSettings(nil, "", "", json.RawMessage(`{"HasPreSharedKey":false}`), true); err == nil {
		t.Fatal("invalid key settings accepted")
	}
}
