package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestFortinetIPsecDraftProtectionAndExpiry(t *testing.T) {
	var store fortinetIPsecDraftStore
	t.Cleanup(store.clear)
	reference := newTunnelID()
	secret := []byte(" private gateway key ")
	for _, invalid := range [][]byte{nil, []byte(" "), []byte("x\x00"), {0xff}, bytes.Repeat([]byte("x"), 4097)} {
		if err := store.stage(reference, "PreSharedKey", invalid); err == nil {
			t.Fatal("invalid secret accepted")
		}
	}
	if err := store.stage(reference, "ClientKey", secret); err == nil {
		t.Fatal("invalid field accepted")
	}
	if err := store.stage(reference, "PreSharedKey", secret); err != nil {
		t.Fatal(err)
	}
	if err := store.stage(reference, "PreSharedKey", secret); err == nil {
		t.Fatal("existing reference was overwritten")
	}
	entry := store.entries[reference]
	if bytes.Contains(entry.sealed, secret) {
		t.Fatal("the service retained a plaintext draft")
	}
	value, err := store.open(reference, "PreSharedKey")
	if err != nil || !bytes.Equal(value, secret) {
		t.Fatal("the protected draft did not preserve the secret", err)
	}
	clearBytes(value)
	if _, err := store.open(reference, "Password"); !errors.Is(err, errFortinetIPsecDraftExpired) {
		t.Fatal("the reference could be repurposed as another field", err)
	}
	store.mu.Lock()
	entry.expires = time.Now().Add(-time.Second)
	store.mu.Unlock()
	if _, err := store.open(reference, "PreSharedKey"); !errors.Is(err, errFortinetIPsecDraftExpired) {
		t.Fatal("an expired draft was accepted", err)
	}
	if entry.key != [authProtectionKeyLength]byte{} || !bytes.Equal(entry.sealed, make([]byte, len(entry.sealed))) {
		t.Fatal("expiration did not clear the key and ciphertext")
	}
}

func TestFortinetIPsecDraftCommandsSaveAndDiscard(t *testing.T) {
	var output bytes.Buffer
	manager := newVncManager(nil, newBackendLineWriter(&output))
	manager.databasePath = filepath.Join(t.TempDir(), "wormhole.db")
	t.Cleanup(manager.close)
	send := func(command backendCommand) (backendResponse, []byte) {
		t.Helper()
		command.ID = "test"
		raw, err := json.Marshal(command)
		if err != nil {
			t.Fatal(err)
		}
		var next backendCommand
		if err := json.Unmarshal(raw, &next); err != nil {
			t.Fatal(err)
		}
		output.Reset()
		manager.handle(next)
		manager.cleanup.Wait()
		body := bytes.Clone(output.Bytes())
		var response backendResponse
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatal("invalid service response", err)
		}
		return response, body
	}
	stage := func(field, secret string) string {
		t.Helper()
		id := newTunnelID()
		response, body := send(backendCommand{Action: "tunnel.ipsec-stage", SessionID: id, IPsecField: field, IPsecSecret: []byte(secret)})
		if !response.OK || bytes.Contains(body, []byte(secret)) {
			t.Fatal("the service did not stage the credential safely")
		}
		return id
	}
	psk := "fixture-gateway-key"
	password := "fixture-saved-password"
	references := map[string]string{"PreSharedKey": stage("PreSharedKey", psk), "Password": stage("Password", password)}
	settings := json.RawMessage(`{"Host":"vpn.example.test","UserAuth":2,"Username":"fixture-user"}`)
	request := tunnelWriteRequest{Name: "IPsec draft", Kind: 9, Settings: settings}
	create := backendCommand{Action: "tunnel.ipsec-create", IPsecWrite: &request, IPsecReferences: references}
	failedRequest := request
	failedRequest.Name = ""
	if failed, _ := send(backendCommand{Action: create.Action, IPsecWrite: &failedRequest, IPsecReferences: references}); failed.OK {
		t.Fatal("invalid VPN configuration accepted")
	}
	saved, body := send(create)
	if !saved.OK || bytes.Contains(body, []byte(psk)) || bytes.Contains(body, []byte(password)) {
		t.Fatal("save failed or exposed a secret", saved.Error)
	}
	id := saved.Result.(map[string]any)["id"].(string)
	private, err := readTunnelUnlocked(manager.databasePath, tunnelReadRequest{ID: id})
	if err != nil || !bytes.Contains(private.Settings, []byte(psk)) || !bytes.Contains(private.Settings, []byte(password)) {
		t.Fatal("draft values were not persisted", err)
	}
	if replay, _ := send(create); replay.OK {
		t.Fatal("a saved reference could be reused")
	}

	replacement := "fixture-replacement"
	update := tunnelWriteRequest{ID: id, Name: request.Name, Kind: 9,
		Settings: json.RawMessage(`{"Host":"vpn.example.test","UserAuth":2,"Username":"fixture-user","HasPreSharedKey":true}`)}
	updated, body := send(backendCommand{Action: "tunnel.ipsec-update", IPsecWrite: &update,
		IPsecReferences: map[string]string{"Password": stage("Password", replacement)}})
	if !updated.OK || bytes.Contains(body, []byte(replacement)) {
		t.Fatal("the replacement was not saved safely", updated.Error)
	}
	private, err = readTunnelUnlocked(manager.databasePath, tunnelReadRequest{ID: id})
	if err != nil || !bytes.Contains(private.Settings, []byte(psk)) || !bytes.Contains(private.Settings, []byte(replacement)) {
		t.Fatal("update did not replace the password and retain the PSK", err)
	}
	inactivePassword := "fixture-inactive-password"
	update.Settings = json.RawMessage(`{"Host":"vpn.example.test","UserAuth":0,"HasPreSharedKey":true}`)
	disabled, _ := send(backendCommand{Action: "tunnel.ipsec-update", IPsecWrite: &update,
		IPsecReferences: map[string]string{"Password": stage("Password", inactivePassword)}})
	if !disabled.OK {
		t.Fatal("disabling user authentication failed", disabled.Error)
	}
	private, err = readTunnelUnlocked(manager.databasePath, tunnelReadRequest{ID: id})
	if err != nil || bytes.Contains(private.Settings, []byte(inactivePassword)) || bytes.Contains(private.Settings, []byte(replacement)) {
		t.Fatal("an inactive password entered the saved tunnel", err)
	}

	for _, action := range []string{"tunnel.ipsec-discard", "tunnel.ipsec-clear"} {
		ref := stage("PreSharedKey", psk)
		if cleared, _ := send(backendCommand{Action: action, SessionID: ref}); !cleared.OK {
			t.Fatal("cleanup failed", cleared.Error)
		}
		if _, err := manager.fortinetIPsecDrafts.open(ref, "PreSharedKey"); !errors.Is(err, errFortinetIPsecDraftExpired) {
			t.Fatal("cleanup left a usable draft", err)
		}
	}
}

func TestFortinetIPsecDraftStdinDoesNotReturnOrLogSecrets(t *testing.T) {
	var input, output bytes.Buffer
	reference := newTunnelID()
	secret := []byte("fixture-private-stdin-secret")
	encoder := json.NewEncoder(&input)
	for _, command := range []backendCommand{
		{ID: "stage", Action: "tunnel.ipsec-stage", SessionID: reference, IPsecField: "Password", IPsecSecret: secret},
		{ID: "clear", Action: "tunnel.ipsec-clear"},
		{ID: "invalid", Action: "tunnel.ipsec-stage", SessionID: ".", IPsecField: "Password", IPsecSecret: secret},
	} {
		if err := encoder.Encode(command); err != nil {
			t.Fatal(err)
		}
	}
	if err := serveBackendIO(filepath.Join(t.TempDir(), "missing.db"), &input, &output); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output.Bytes(), secret) {
		t.Fatal("stdin secret appeared in service output")
	}
	decoder := json.NewDecoder(&output)
	for _, want := range []struct {
		id string
		ok bool
	}{{"stage", true}, {"clear", true}, {"invalid", false}} {
		var response backendResponse
		if err := decoder.Decode(&response); err != nil || response.ID != want.id || response.OK != want.ok || response.Result != nil {
			t.Fatalf("unexpected response for %s: %v", want.id, err)
		}
	}
}
