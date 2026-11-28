package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func vaultTunnelSave(t *testing.T, id, revision string, configuration []byte) json.RawMessage {
	t.Helper()
	input := map[string]any{"metadata": map[string]any{"id": id, "name": "VPN " + id, "kind": 1}, "rowVersion": revision}
	if configuration != nil {
		input["configuration"] = configuration
	}
	return vaultInput(t, input)
}

func TestVaultTunnelServiceLifecycle(t *testing.T) {
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	id := uuid.NewString()
	configuration := []byte(`{"ProfileOvpn":"synthetic-private-profile"}`)
	input := vaultTunnelSave(t, id, "0", configuration)
	if _, err := (&vaultFoundationHandler{}).Handle(ctx, "tunnel-save", input); err != vaultwire.ErrProtocol {
		t.Fatal("preunlock accepted", err)
	}
	response, err := h.Handle(ctx, "tunnel-save", input)
	if err != nil {
		t.Fatal(err)
	}
	var view vaultTunnelView
	if err := json.Unmarshal(response, &view); err != nil || view.ID != id || view.RowVersion != "1" || view.Kind != 1 {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(response, &fields); err != nil || len(fields) != 6 {
		t.Fatal("unexpected projection", err)
	}
	for _, name := range []string{"configuration", "settings", "seal", "configurationVersion", "endpoint", "password"} {
		if _, ok := fields[name]; ok {
			t.Fatal("private field returned", name)
		}
	}
	if bytes.Contains(response, []byte("synthetic-private-profile")) {
		t.Fatal("configuration leaked")
	}
	if err := h.owner.WithTunnelConfiguration(ctx, id, 1, func(value []byte) error {
		if !bytes.Equal(value, configuration) {
			t.Fatal("wrong encrypted configuration")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "tunnel-save", input); err != vaultstore.ErrConflict || h.closed {
		t.Fatal("conflict handling", err)
	}
	read := vaultInput(t, map[string]any{"id": id, "rowVersion": "1"})
	if got, err := h.Handle(ctx, "tunnel-read", read); err != nil || !bytes.Equal(got, response) {
		t.Fatal(err)
	}
	if got, err := h.Handle(ctx, "tunnel-list", json.RawMessage(`{"after":"","limit":128}`)); err != nil || !bytes.Contains(got, []byte(id)) {
		t.Fatal(err)
	}
	if got, err := h.Handle(ctx, "tunnel-save", vaultTunnelSave(t, id, "1", nil)); err != nil || !bytes.Contains(got, []byte(`"rowVersion":"2"`)) {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "tunnel-delete", read); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	if got, err := h.Handle(ctx, "tunnel-delete", vaultInput(t, map[string]any{"id": id, "rowVersion": "2"})); err != nil || string(got) != `{"id":"`+id+`","rowVersion":"3","deleted":true}` {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "tunnel-read", read); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	if got, err := h.Handle(ctx, "tunnel-list", json.RawMessage(`{"after":"","limit":128}`)); err != nil || string(got) != `{"tunnels":[]}` {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "tunnel-save", input); err != vaultstore.ErrConflict {
		t.Fatal("tombstone reused", err)
	}
	if _, err := h.Handle(ctx, "tunnel-settings", read); err != vaultwire.ErrProtocol {
		t.Fatal("generic settings release", err)
	}
	if _, err := h.tunnel(ctx, "unknown", nil); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
}

func TestVaultTunnelInputAndProviderValidation(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	id := uuid.NewString()
	valid := string(vaultTunnelSave(t, id, "0", []byte(`{"ProfileOvpn":"synthetic"}`)))
	for _, raw := range []string{
		"", "{}", "null", valid + "{}", strings.Replace(valid, `"rowVersion":"0"`, `"rowVersion":0`, 1), strings.Replace(valid, `"rowVersion":"0"`, `"rowVersion":"9223372036854775807"`, 1),
		strings.Replace(valid, `"kind":1`, `"kind":1,"kind":2`, 1), strings.Replace(valid, `"kind":1`, `"kind":10`, 1), strings.Replace(valid, `"kind":1`, `"kind":null`, 1), strings.Replace(valid, `"kind":1`, `"Kind":1`, 1),
		string(vaultTunnelSave(t, id, "0", nil)), string(vaultTunnelSave(t, id, "0", []byte(`{}`))), string(vaultTunnelSave(t, id, "0", []byte(`{"ProfileOvpn":"first","ProfileOvpn":"second"}`))),
		string(vaultInput(t, map[string]any{"metadata": strings.Repeat("x", 4097), "rowVersion": "0"})),
	} {
		if _, err := h.Handle(ctx, "tunnel-save", json.RawMessage(raw)); err != vaultwire.ErrProtocol || h.closed {
			t.Fatal("invalid input not rejected safely", err)
		}
	}
	for _, op := range []string{"tunnel-read", "tunnel-delete"} {
		for _, raw := range []string{`{}`, `{"id":"bad","rowVersion":"1"}`, `{"id":"` + id + `","rowVersion":"-1"}`, strings.Repeat(" ", 1025)} {
			if _, err := h.Handle(ctx, op, json.RawMessage(raw)); err != vaultwire.ErrProtocol {
				t.Fatal(err)
			}
		}
	}
	if _, err := h.Handle(ctx, "tunnel-delete", vaultInput(t, map[string]any{"id": id, "rowVersion": "9223372036854775807"})); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	for _, raw := range []string{`{}`, `{"after":"bad","limit":1}`, `{"after":"","limit":0}`, `{"after":"","limit":129}`, strings.Repeat(" ", 1025)} {
		if _, err := h.Handle(ctx, "tunnel-list", json.RawMessage(raw)); err != vaultwire.ErrProtocol {
			t.Fatal(err)
		}
	}
	if _, err := h.Handle(ctx, "tunnel-save", json.RawMessage(valid)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "tunnel-read", vaultInput(t, map[string]any{"id": id, "rowVersion": "2"})); !errors.Is(err, vaultwire.ErrRetired) || !errors.Is(err, vault.ErrRollback) {
		t.Fatal("rollback session survived", err)
	}
}

func TestVaultTunnelConfigurationDecoder(t *testing.T) {
	encode := func(value []byte) []byte {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	for _, raw := range [][]byte{nil, []byte("null"), []byte("[65]"), []byte(`"?"`), encode([]byte{}), encode(make([]byte, backendMaxTunnelRequestBytes+1)), encode([]byte("\xff")), encode([]byte(`null`)), encode([]byte(`[]`)), encode([]byte(`{"x":`)), encode([]byte(`{"x":1,`)), encode([]byte(`{"x":1]`)), encode([]byte(`{"x":1} !`)), encode([]byte(`{"x":1} {}`)), encode([]byte(`{"":"x"}`)), encode([]byte(`{"x":"y","x":"z"}`)), encode([]byte(`{"\u0000":"x"}`)), encode([]byte(`{"` + strings.Repeat("x", 129) + `":"x"}`)), encode([]byte(`{"ProfileOvpn":null}`))} {
		value, err := decodeVaultTunnelConfiguration(raw, 1)
		if err != vaultwire.ErrProtocol || value != nil {
			t.Fatal("malformed configuration accepted", err)
		}
	}
	var b strings.Builder
	b.WriteString(`{"ProfileOvpn":"synthetic"`)
	for i := 0; i < 128; i++ {
		fmt.Fprintf(&b, `,"field%d":0`, i)
	}
	b.WriteByte('}')
	if value, err := decodeVaultTunnelConfiguration(encode([]byte(b.String())), 1); err != vaultwire.ErrProtocol || value != nil {
		t.Fatal("unbounded property count")
	}
	if _, err := decodeVaultTunnelConfiguration(encode([]byte(`{}`)), 9); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	for kind, configuration := range map[int]string{
		0: `{"InterfacePrivateKey":"private","InterfaceAddress":"10.0.0.2","PeerPublicKey":"public","PeerEndpoint":"example.test:1234"}`,
		1: `{"ProfileOvpn":"synthetic"}`,
		2: `{"Host":"example.test","Username":"user","Password":"password"}`,
	} {
		decoded, err := decodeVaultTunnelConfiguration(encode([]byte(configuration)), kind)
		if err != nil || string(decoded) != configuration {
			t.Fatal("provider compatibility", kind, err)
		}
		vault.Wipe(decoded)
	}
	for _, configuration := range []string{`{"Host":"example.test","Username":"user"}`, `{"Host":"example.test","UseSingleSignOn":true,"Port":0}`, `{"Host":"example.test","UseSingleSignOn":true,"TrustServerCertificate":"true"}`} {
		if _, err := decodeVaultTunnelConfiguration(encode([]byte(configuration)), 2); err != vaultwire.ErrProtocol {
			t.Fatal("invalid provider configuration accepted")
		}
	}
}
