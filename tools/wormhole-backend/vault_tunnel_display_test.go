package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestVaultTunnelEditorSealedDisplay(t *testing.T) {
	ctx, h := context.Background(), vaultCredentialFixture(t)
	input := tunnelEditorInput(1, `{"ProfileOvpn":"private-profile","Username":"visible-user","Password":"private-password"}`)
	saved := saveTunnelEditor(t, h, input)
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	request := map[string]any{"tunnelId": saved.ID, "rowVersion": "1", "requestId": uuid.NewString(), "publicKey": key.PublicKey().Bytes()}
	raw, err := h.Handle(ctx, "tunnel-editor-display", vaultInput(t, request))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"private-profile", "private-password", "visible-user", "VPN editor", "ProfileOvpn"} {
		if bytes.Contains(raw, []byte(value)) {
			t.Fatal("plaintext editor response", value)
		}
	}
	var result localvault.TunnelEditorDisplay
	if json.Unmarshal(raw, &result) != nil || result.TunnelID != saved.ID || result.RequestID != request["requestId"] || result.RowVersion != "1" {
		t.Fatal("bad binding")
	}
	open := func(domain, workspace, id, request, version string) ([]byte, error) {
		info := []byte(domain)
		for _, value := range []string{workspace, id, request, version} {
			info = binary.BigEndian.AppendUint32(info, uint32(len(value)))
			info = append(info, []byte(value)...)
		}
		recipientKey, _ := hpke.NewDHKEMPrivateKey(key)
		recipient, e := hpke.NewRecipient(result.Bundle.Enc, recipientKey, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
		if e != nil {
			return nil, e
		}
		return recipient.Open(nil, result.Bundle.Ciphertext)
	}
	projection, err := open("wormhole/v1/tunnel-editor", result.WorkspaceID, result.TunnelID, result.RequestID, result.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(projection)
	var display struct {
		Name     string
		Kind     int
		Settings map[string]any
		Present  []string
	}
	if json.Unmarshal(projection, &display) != nil || display.Name != "VPN editor" || display.Kind != 1 || !reflect.DeepEqual(display.Settings, map[string]any{"Username": "visible-user"}) || !reflect.DeepEqual(display.Present, []string{"Password", "ProfileOvpn"}) {
		t.Fatal("bad redaction")
	}
	for _, params := range [][5]string{
		{"wormhole/v1/notes-display", result.WorkspaceID, result.TunnelID, result.RequestID, result.RowVersion},
		{"wormhole/v1/tunnel-editor", uuid.NewString(), result.TunnelID, result.RequestID, result.RowVersion},
		{"wormhole/v1/tunnel-editor", result.WorkspaceID, uuid.NewString(), result.RequestID, result.RowVersion},
		{"wormhole/v1/tunnel-editor", result.WorkspaceID, result.TunnelID, uuid.NewString(), result.RowVersion},
		{"wormhole/v1/tunnel-editor", result.WorkspaceID, result.TunnelID, result.RequestID, "2"},
	} {
		if _, err := open(params[0], params[1], params[2], params[3], params[4]); err == nil {
			t.Fatal("display binding bypass")
		}
	}
	input["patch"] = []byte(`{}`)
	saveTunnelEditor(t, h, input)
	if _, err = h.Handle(ctx, "tunnel-editor-display", vaultInput(t, request)); err != vaultstore.ErrConflict || h.closed {
		t.Fatal("stale editor admitted", err)
	}
	request["rowVersion"] = "3"
	if _, err = h.Handle(ctx, "tunnel-editor-display", vaultInput(t, request)); err != vaultstore.ErrConflict {
		t.Fatal("future editor admitted", err)
	}
	request["rowVersion"] = "2"
	if _, err = h.Handle(ctx, "tunnel-editor-display", vaultInput(t, request)); err != nil {
		t.Fatal(err)
	}
	if err = h.owner.DeleteTunnel(ctx, saved.ID, 2); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Handle(ctx, "tunnel-editor-display", vaultInput(t, request)); err != vaultstore.ErrMissing {
		t.Fatal("deleted tunnel displayed", err)
	}
	request["tunnelId"] = uuid.NewString()
	if _, err = h.Handle(ctx, "tunnel-editor-display", vaultInput(t, request)); err != vaultstore.ErrMissing {
		t.Fatal("missing tunnel displayed", err)
	}
}

func TestVaultTunnelEditorProjectionAllowlist(t *testing.T) {
	configuration := []byte(`{"InterfacePrivateKey":"private-key","PeerPresharedKey":"pre-shared","Password":"password","SecondaryPassword":"second","TotpSecret":"totp","ClientKeyPem":"pem-key","ClientCertPem":"pem-certificate","CaPem":"pem-ca","ProfileOvpn":"profile-with-private-key","ServerSecretHex":"azure-secret","AppToken":"portal-token","LegacyCookie":"unrecognized-cookie","Host":"visible-host","Username":"visible-user"}`)
	for kind := 0; kind <= 9; kind++ {
		raw, err := projectVaultTunnelEditor(vaultstore.Tunnel{TunnelMetadata: vaultstore.TunnelMetadata{Name: "VPN", Kind: kind}}, configuration)
		if err != nil {
			t.Fatal(kind, err)
		}
		for _, secret := range []string{"private-key", "pre-shared", "password", "second", "totp", "pem-key", "pem-certificate", "pem-ca", "profile-with-private-key", "azure-secret", "portal-token", "unrecognized-cookie"} {
			if bytes.Contains(raw, []byte(`"`+secret+`"`)) {
				t.Fatal("stored factor returned", kind, secret)
			}
		}
		if bytes.Contains(raw, []byte("LegacyCookie")) {
			t.Fatal("unknown legacy field exposed")
		}
		vault.Wipe(raw)
	}
	for _, configuration := range []string{`{"Host":{}}`, `{"Port":false}`, `{"Password":`, strings.Repeat("x", backendMaxTunnelRequestBytes+1)} {
		raw, err := projectVaultTunnelEditor(vaultstore.Tunnel{TunnelMetadata: vaultstore.TunnelMetadata{Kind: 2}}, []byte(configuration))
		if err != vaultwire.ErrProtocol || raw != nil {
			t.Fatal("malformed projection", err)
		}
	}
	raw, err := projectVaultTunnelEditor(vaultstore.Tunnel{TunnelMetadata: vaultstore.TunnelMetadata{Kind: 1}}, []byte(`{"Password":null,"ProfileOvpn":"","Username":"visible"}`))
	if err != nil || !bytes.Contains(raw, []byte(`"present":[]`)) {
		t.Fatal("empty presence", err)
	}
	raw, err = projectVaultTunnelEditor(vaultstore.Tunnel{TunnelMetadata: vaultstore.TunnelMetadata{Kind: 2}}, []byte(`{"Host":"`+strings.Repeat("x", 512*1024)+`"}`))
	if err != vaultwire.ErrProtocol || raw != nil {
		t.Fatal("oversized projection", err)
	}
	if vaultTunnelPublicEditorField(0, "Password") || vaultTunnelPublicEditorField(10, "Host") {
		t.Fatal("cross-provider display field")
	}
}

func TestVaultTunnelEditorDisplayInput(t *testing.T) {
	ctx, h := context.Background(), vaultCredentialFixture(t)
	saved := saveTunnelEditor(t, h, tunnelEditorInput(1, `{"ProfileOvpn":"profile"}`))
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	base := map[string]any{"tunnelId": saved.ID, "rowVersion": "1", "requestId": uuid.NewString(), "publicKey": key.PublicKey().Bytes()}
	for field, values := range map[string][]any{"tunnelId": {nil, "", uuid.Nil.String(), "bad"}, "requestId": {nil, "", uuid.Nil.String(), "bad"}, "rowVersion": {nil, 1, "0", "01", "9223372036854775808"}, "publicKey": {nil, []int{1, 2}, "!", []byte{1}, make([]byte, 32)}} {
		for _, value := range values {
			request := map[string]any{}
			for k, v := range base {
				request[k] = v
			}
			request[field] = value
			if _, err := h.Handle(ctx, "tunnel-editor-display", vaultInput(t, request)); err == nil {
				t.Fatal("bad input admitted", field)
			}
		}
	}
	for _, raw := range []string{"null", "{}", strings.Repeat(" ", 1025), `{"tunnelId":"x","tunnelId":"x"}`, `{"extra":true}`} {
		if _, err := h.Handle(ctx, "tunnel-editor-display", []byte(raw)); err == nil {
			t.Fatal("malformed request")
		}
	}
	if _, err := (&vaultFoundationHandler{}).displayTunnelEditor(ctx, vaultInput(t, base)); err == nil {
		t.Fatal("locked display")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := h.Handle(canceled, "tunnel-editor-display", vaultInput(t, base)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := h.owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.displayTunnelEditor(ctx, vaultInput(t, base)); err == nil {
		t.Fatal("closed display")
	}
}

func TestVaultTunnelPublicProjectionReaderCompatibility(t *testing.T) {
	for _, sample := range []struct {
		kind         int
		field, value string
		valid        bool
	}{
		{0, "Mtu", "9007199254740991", true}, {0, "Mtu", "-9007199254740991", true},
		{0, "Mtu", "9007199254740992", false}, {0, "Mtu", "-9007199254740992", false},
		{0, "Mtu", "null", true}, {2, "UseSingleSignOn", "true", true}, {2, "UseSingleSignOn", "false", true},
		{2, "UseSamlCallback", "true", true}, {2, "UseSamlCallback", `"yes"`, false},
		{0, "Dns", `["one","two"]`, true}, {0, "Dns", `["one\u0000"]`, false},
		{0, "Dns", `["\ud800"]`, false}, {0, "Dns", `["\ud800\udfff"]`, true},
		{2, "Host", `"\ud800"`, false}, {2, "Host", `"\udfff"`, false}, {2, "Host", `"a\u0000b"`, false},
		{2, "Host", `"\ud800\udfff"`, true}, {2, "Host", `"literal\\ud800"`, true},
		{2, "Host", `"\ud800\u0041"`, false}, {2, "Host", `"日本語"`, true}, {2, "Host", `{}`, false},
	} {
		if got := validVaultTunnelPublicValue(sample.kind, sample.field, []byte(sample.value)); got != sample.valid {
			t.Fatalf("%s: %v", sample.field, got)
		}
	}
}
