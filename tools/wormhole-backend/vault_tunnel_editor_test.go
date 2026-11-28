package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func tunnelEditorInput(kind int, patch string) map[string]any {
	return map[string]any{"metadata": map[string]any{"id": "", "name": " VPN editor ", "kind": kind}, "rowVersion": "0", "patch": []byte(patch), "forgetHostKey": false}
}
func saveTunnelEditor(t *testing.T, h *vaultFoundationHandler, input map[string]any) vaultstore.Tunnel {
	t.Helper()
	raw, err := h.Handle(context.Background(), "tunnel-edit", vaultInput(t, input))
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		ID, RowVersion string
		Updated        bool
	}
	if json.Unmarshal(raw, &result) != nil || !result.Updated || !vaultCredentialID(result.ID) {
		t.Fatal("invalid acknowledgement")
	}
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	if len(fields) != 3 {
		t.Fatal("private data in acknowledgement")
	}
	input["metadata"].(map[string]any)["id"] = result.ID
	input["rowVersion"] = result.RowVersion
	saved, err := h.owner.ReadTunnel(context.Background(), result.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	return saved
}
func vaultTestTunnelEditorSettings(t *testing.T, h *vaultFoundationHandler, id string) map[string]any {
	t.Helper()
	var settings map[string]any
	if err := h.owner.WithTunnelConfiguration(context.Background(), id, 0, func(value []byte) error { return json.Unmarshal(value, &settings) }); err != nil {
		t.Fatal(err)
	}
	return settings
}
func TestVaultTunnelEditorProviderPatches(t *testing.T) {
	valid := map[int]string{
		0: `{"InterfacePrivateKey":"private","InterfaceAddress":"10.0.0.2/32","PeerPublicKey":"public","PeerEndpoint":"vpn.example:1234","AllowedIps":"0.0.0.0/0","PersistentKeepaliveSeconds":30}`,
		1: `{"ProfileOvpn":"synthetic profile","Username":"alice","Password":"secret"}`,
		2: `{"Host":"vpn.example","Username":"alice","Password":"secret"}`,
		3: `{"Server":"vpn.example","Username":"alice","Password":"secret","AuthMode":1}`,
		4: `{"Server":"vpn.example","Username":"alice","Password":"secret","Mode":0}`,
		5: `{"TenantId":"tenant","Audience":"audience","Servers":["vpn.example"],"ServerSecretHex":"` + strings.Repeat("ab", 256) + `"}`,
		6: `{"Host":"vpn.example","Username":"alice","Password":"secret","SecondaryPassword":"second"}`,
		7: `{"Host":"vpn.example","Username":"alice","Password":"secret"}`,
		8: `{"Mode":"manual","Host":"vpn.example","Port":22,"Username":"alice","CredentialId":"` + uuid.NewString() + `"}`,
	}
	for kind, configuration := range valid {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			h := vaultCredentialFixture(t)
			input := tunnelEditorInput(kind, configuration)
			saved := saveTunnelEditor(t, h, input)
			if saved.Name != "VPN editor" {
				t.Fatal("name not normalized")
			}
			before := vaultTestTunnelEditorSettings(t, h, saved.ID)
			input["patch"] = []byte(`{}`)
			input["metadata"].(map[string]any)["name"] = "Renamed"
			updated := saveTunnelEditor(t, h, input)
			if updated.ConfigurationVersion != saved.ConfigurationVersion || updated.CreatedAt != saved.CreatedAt || !reflect.DeepEqual(before, vaultTestTunnelEditorSettings(t, h, saved.ID)) {
				t.Fatal("metadata-only edit replaced secret")
			}
			input["metadata"].(map[string]any)["kind"] = 1
			input["patch"] = []byte(`{"ProfileOvpn":"replacement profile"}`)
			if kind == 1 {
				input["patch"] = []byte(`{"ProfileOvpn":"replacement profile","Username":null,"Password":null}`)
			}
			saveTunnelEditor(t, h, input)
			settings := vaultTestTunnelEditorSettings(t, h, saved.ID)
			if len(settings) != 1 || settings["ProfileOvpn"] != "replacement profile" {
				t.Fatal("provider change retained old configuration")
			}
		})
	}
}

func TestVaultTunnelEditorPreservesSecretsAndNormalizes(t *testing.T) {
	ctx, h := context.Background(), vaultCredentialFixture(t)
	input := tunnelEditorInput(3, `{"Server":"vpn.example","Username":"alice","Password":"original secret","AuthMode":1}`)
	saved := saveTunnelEditor(t, h, input)
	input["patch"] = []byte(`{"Server":"new.example"}`)
	saveTunnelEditor(t, h, input)
	if vaultTestTunnelEditorSettings(t, h, saved.ID)["Password"] != "original secret" {
		t.Fatal("omitted secret lost")
	}
	input["patch"] = []byte(`{"Password":"replacement"}`)
	saveTunnelEditor(t, h, input)
	before := vaultTestTunnelEditorSettings(t, h, saved.ID)
	for _, patch := range []string{`{"Password":null}`, `{"Server":false}`, `{"Port":-1}`, `{"UseSingleSignOn":"true"}`, `{"Unsupported":1}`} {
		input["patch"] = []byte(patch)
		if _, err := h.Handle(ctx, "tunnel-edit", vaultInput(t, input)); !errors.Is(err, vaultwire.ErrProtocol) {
			t.Fatal(patch, err)
		}
		if !reflect.DeepEqual(before, vaultTestTunnelEditorSettings(t, h, saved.ID)) {
			t.Fatal("partial failed mutation")
		}
	}
	input["patch"] = []byte(`{"AuthMode":2}`)
	saveTunnelEditor(t, h, input)
	settings := vaultTestTunnelEditorSettings(t, h, saved.ID)
	if _, ok := settings["Password"]; ok {
		t.Fatal("SSO retained obsolete password")
	}
	if _, ok := settings["Username"]; ok {
		t.Fatal("SSO retained obsolete username")
	}
	input["patch"] = []byte(`{"AuthMode":1,"Username":"bob","Password":"new secret"}`)
	saveTunnelEditor(t, h, input)
	// Unknown legacy extension values survive normal edits but cannot be added by
	// the editor; they never enter its public acknowledgement.
	current, err := h.owner.ReadTunnel(ctx, saved.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.owner.PutTunnel(ctx, current.TunnelMetadata, []byte(`{"Server":"legacy.example","Username":"alice","Password":"hidden","LegacyExtension":"preserve"}`), current.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	input["rowVersion"] = fmt.Sprint(current.RowVersion + 1)
	input["patch"] = []byte(`{"Port":443}`)
	saveTunnelEditor(t, h, input)
	if vaultTestTunnelEditorSettings(t, h, saved.ID)["LegacyExtension"] != "preserve" {
		t.Fatal("hidden extension dropped")
	}
}

func TestVaultTunnelEditorSSHTrust(t *testing.T) {
	ctx, h := context.Background(), vaultCredentialFixture(t)
	id := uuid.NewString()
	credential := uuid.NewString()
	pin := "SHA256:" + strings.Repeat("a", 43)
	metadata := vaultstore.TunnelMetadata{ID: id, Name: "Jump", Kind: 8}
	config := []byte(`{"Mode":"manual","Host":"host.example","Port":22,"Username":"alice","CredentialId":"` + credential + `","HostKeySha256":"` + pin + `"}`)
	old, err := h.owner.PutTunnel(ctx, metadata, config, 0)
	if err != nil {
		t.Fatal(err)
	}
	input := tunnelEditorInput(8, `{"KeepaliveSeconds":60}`)
	input["metadata"].(map[string]any)["id"] = id
	input["rowVersion"] = "1"
	saveTunnelEditor(t, h, input)
	if vaultTestTunnelEditorSettings(t, h, id)["HostKeySha256"] != pin {
		t.Fatal("unrelated edit lost pin")
	}
	input["patch"] = []byte(`{"HostKeySha256":"` + pin + `"}`)
	if _, err = h.Handle(ctx, "tunnel-edit", vaultInput(t, input)); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("editor established trust", err)
	}
	input["patch"] = []byte(`{}`)
	input["forgetHostKey"] = true
	saveTunnelEditor(t, h, input)
	if _, ok := vaultTestTunnelEditorSettings(t, h, id)["HostKeySha256"]; ok {
		t.Fatal("pin not forgotten")
	}
	input["forgetHostKey"] = false
	input["patch"] = []byte(`{"Host":"changed.example"}`)
	saveTunnelEditor(t, h, input)
	input["patch"] = []byte(`{"Mode":"connection","JumpConnectionId":"` + uuid.NewString() + `"}`)
	saveTunnelEditor(t, h, input)
	settings := vaultTestTunnelEditorSettings(t, h, id)
	if settings["Host"] != nil || settings["CredentialId"] != nil || settings["Port"] != nil {
		t.Fatal("mode change retained manual target")
	}
	input["forgetHostKey"] = true
	input["patch"] = []byte(`{}`)
	if _, err = h.Handle(ctx, "tunnel-edit", vaultInput(t, input)); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("connection pin changed outside node", err)
	}
	input["forgetHostKey"] = false
	input["patch"] = []byte(`{"Mode":"manual","Host":"other.example","Port":2222,"Username":"bob","CredentialId":"` + credential + `"}`)
	saveTunnelEditor(t, h, input)
	if vaultTestTunnelEditorSettings(t, h, id)["JumpConnectionId"] != nil {
		t.Fatal("manual mode retained connection reference")
	}
	// JSON escape spelling does not change a target identity or revoke its pin.
	old, err = h.owner.ReadTunnel(ctx, id, 0)
	if err != nil {
		t.Fatal(err)
	}
	unicodeConfig := bytes.Replace(config, []byte(`"Username":"alice"`), []byte(`"Username":"alice\u0026ops"`), 1)
	old, err = h.owner.PutTunnel(ctx, metadata, unicodeConfig, old.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	input["rowVersion"] = fmt.Sprint(old.RowVersion)
	input["patch"] = []byte(`{"Username":"alice&ops","Port":22,"JumpConnectionId":null}`)
	saveTunnelEditor(t, h, input)
	if vaultTestTunnelEditorSettings(t, h, id)["HostKeySha256"] != pin {
		t.Fatal("equivalent identity revoked pin")
	}
	// Target changes discard an old pin even when the patch does not mention it.
	old, err = h.owner.ReadTunnel(ctx, id, 0)
	if err != nil {
		t.Fatal(err)
	}
	old, err = h.owner.PutTunnel(ctx, metadata, config, old.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	input["rowVersion"] = fmt.Sprint(old.RowVersion)
	input["patch"] = []byte(`{"Username":"changed"}`)
	saveTunnelEditor(t, h, input)
	if vaultTestTunnelEditorSettings(t, h, id)["HostKeySha256"] != nil {
		t.Fatal("new identity retained old pin")
	}
}

func TestVaultTunnelEditorRejectsMalformedAndStale(t *testing.T) {
	ctx, h := context.Background(), vaultCredentialFixture(t)
	valid := func() map[string]any { return tunnelEditorInput(1, `{"ProfileOvpn":"profile"}`) }
	for _, mutate := range []func(map[string]any){
		func(q map[string]any) { delete(q, "patch") }, func(q map[string]any) { q["extra"] = true }, func(q map[string]any) { q["patch"] = nil }, func(q map[string]any) { q["patch"] = []int{1} },
		func(q map[string]any) { q["rowVersion"] = "01" }, func(q map[string]any) { q["rowVersion"] = "9223372036854775807" }, func(q map[string]any) { q["rowVersion"] = "1" }, func(q map[string]any) { q["forgetHostKey"] = true },
		func(q map[string]any) { q["metadata"].(map[string]any)["id"] = "bad"; q["rowVersion"] = "1" }, func(q map[string]any) { q["metadata"].(map[string]any)["kind"] = 10 }, func(q map[string]any) { q["metadata"].(map[string]any)["name"] = "" }, func(q map[string]any) { q["metadata"].(map[string]any)["extra"] = "private" },
		func(q map[string]any) { q["patch"] = []byte(`{"ProfileOvpn":"a","ProfileOvpn":"b"}`) }, func(q map[string]any) { q["patch"] = []byte(`{}`) }, func(q map[string]any) { q["patch"] = []byte(`{"Password":"secret"}`) }, func(q map[string]any) { q["metadata"] = strings.Repeat("a", 4097) },
	} {
		input := valid()
		mutate(input)
		if _, err := h.Handle(ctx, "tunnel-edit", vaultInput(t, input)); !errors.Is(err, vaultwire.ErrProtocol) || h.closed {
			t.Fatal(err)
		}
	}
	if _, err := (&vaultFoundationHandler{}).editTunnel(ctx, vaultInput(t, valid())); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	if _, err := h.editTunnel(ctx, make([]byte, 6*1024*1024+1)); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	input := valid()
	saved := saveTunnelEditor(t, h, input)
	duplicate := valid()
	if _, err := h.Handle(ctx, "tunnel-edit", vaultInput(t, duplicate)); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatal(err)
	}
	input["rowVersion"] = "2"
	if _, err := h.Handle(ctx, "tunnel-edit", vaultInput(t, input)); !errors.Is(err, vaultstore.ErrConflict) || h.closed {
		t.Fatal(err)
	}
	input["metadata"].(map[string]any)["id"] = uuid.NewString()
	if _, err := h.Handle(ctx, "tunnel-edit", vaultInput(t, input)); err == nil {
		t.Fatal("missing tunnel edited")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := h.Handle(canceled, "tunnel-edit", vaultInput(t, valid())); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if got := vaultTestTunnelEditorSettings(t, h, saved.ID); !reflect.DeepEqual(got, map[string]any{"ProfileOvpn": "profile"}) {
		t.Fatal("failed writes changed data")
	}
	// Public responses cannot contain either replacement or preserved settings.
	input["metadata"].(map[string]any)["id"] = saved.ID
	input["rowVersion"] = "1"
	input["patch"] = []byte(`{}`)
	raw, err := h.Handle(ctx, "tunnel-edit", vaultInput(t, input))
	if err != nil || bytes.Contains(raw, []byte("profile")) {
		t.Fatal("settings response", err)
	}
}

func TestVaultTunnelEditorFieldShapes(t *testing.T) {
	for _, q := range []struct {
		kind       int
		field, raw string
		valid      bool
	}{
		{0, "Dns", `["1.1.1.1","8.8.8.8"]`, true}, {0, "AllowedIps", `"0.0.0.0/0"`, true}, {5, "Servers", `["gateway.example"]`, true},
		{5, "Servers", `[1]`, false},
		{5, "Servers", `[null]`, false},
		{5, "Servers", `[`, false}, {0, "Dns", `[]`, true},
		{0, "Dns", `"` + strings.Repeat("a,", 256) + `a"`, false}, {0, "Dns", `[` + strings.Repeat(`"a",`, 256) + `"a"]`, false},
		{2, "UseSingleSignOn", `true`, true}, {2, "UseSingleSignOn", `"true"`, false}, {2, "Port", `443`, true}, {2, "Port", `443.5`, false}, {2, "Port", `"443"`, false},
		{4, "Mode", `1`, true}, {4, "Mode", `"manual"`, false}, {8, "Mode", `"manual"`, true}, {8, "Mode", `1`, false},
		{1, "Password", `{}`, false}, {1, "Password", `[]`, false}, {1, "Password", `null`, true}, {1, "Password", `"secret"`, true},
	} {
		if got := validVaultTunnelEditorValue(q.kind, q.field, []byte(q.raw)); got != q.valid {
			t.Fatalf("shape %d %s", q.kind, q.field)
		}
	}
	if vaultTunnelEditorField(-1, "Host") || vaultTunnelEditorField(10, "Host") || vaultTunnelEditorField(0, "host") {
		t.Fatal("unknown field accepted")
	}
}

func TestVaultTunnelEditorNormalization(t *testing.T) {
	for _, q := range []struct {
		kind            int
		input, expected string
	}{
		{0, `{"Dns":" 1.1.1.1, ,8.8.8.8 ","AllowedIps":" ","PeerPresharedKey":" "}`, `{"Dns":["1.1.1.1","8.8.8.8"],"AllowedIps":[]}`},
		{1, `{"Username":" ","Password":" "}`, `{}`},
		{2, `{"Host":"vpn","UseSingleSignOn":true,"UseExternalBrowser":true,"Realm":"old","Username":"old","Password":"old","TotpSecret":"old"}`, `{"Host":"vpn","UseSingleSignOn":true,"UseExternalBrowser":true}`},
		{2, `{"Password":" secret \r\n","Realm":" ","TotpSecret":" A B ","ServerCertSha256Pin":" a b "}`, `{"Password":" secret ","TotpSecret":"AB","ServerCertSha256Pin":"ab"}`},
		{3, `{"Password":"pw\n","Domain":" "}`, `{"Password":"pw","VerifyX509Name":"/O=WatchGuard_Technologies/OU=Fireware/CN=Fireware_SSLVPN_Server"}`},
		{3, `{"VerifyX509Name":"custom"}`, `{"VerifyX509Name":"custom"}`},
		{4, `{"ProfileOvpn":"client","UseSingleSignOn":true,"Password":"pw\r"}`, `{"ProfileOvpn":"client","Password":"pw","Mode":1,"AppToken":"sslclient"}`},
		{4, `{}`, `{"Mode":0,"AppToken":"sslclient"}`},
		{4, `{"Mode":0,"AppToken":"custom"}`, `{"Mode":0,"AppToken":"custom"}`},
		{5, `{"Servers":" a.example, b.example ","ApplicationId":" ","Issuer":" ","CaPem":" ","ServerSecretHex":"a b"}`, `{"Servers":["a.example","b.example"],"ServerSecretHex":"ab"}`},
		{6, `{"Password":"pw\n","SecondaryPassword":" ","Group":" ","TotpSecret":" A B ","ServerCertSha256Pin":"  "}`, `{"Password":"pw","TotpSecret":"AB"}`},
		{7, `{"Password":"pw\n","ServerCertSha256Pin":"aa bb"}`, `{"Password":"pw","ServerCertSha256Pin":"aabb"}`},
		{8, `{"Mode":"connection"}`, `{"Mode":"connection"}`},
	} {
		t.Run(fmt.Sprint(q.kind)+q.input, func(t *testing.T) {
			settings, err := decodeVaultTunnelSettings([]byte(q.input))
			if err != nil {
				t.Fatal(err)
			}
			defer clearTunnelSettingsMap(settings)
			for _, value := range settings {
				defer clearBytes(value)
			}
			patch := make(map[string]json.RawMessage)
			for field, value := range settings {
				patch[field] = value
			}
			cleanup := normalizeVaultTunnelEditorSettings(q.kind, settings, patch)
			var got, want map[string]any
			encoded, err := json.Marshal(settings)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.Unmarshal(encoded, &got)
			_ = json.Unmarshal([]byte(q.expected), &want)
			if !reflect.DeepEqual(got, want) {
				t.Fatal("normalization mismatch")
			}
			var borrowed [][]byte
			for field, value := range settings {
				if !bytes.Equal(value, patch[field]) {
					borrowed = append(borrowed, value)
				}
			}
			cleanup()
			for _, value := range borrowed {
				for _, b := range value {
					if b != 0 {
						t.Fatal("normalizer retained allocated value")
					}
				}
			}
		})
	}
	// Unrelated edits must not alter a stored factor, including whitespace.
	for _, kind := range []int{0, 1, 2, 3, 4, 6, 7} {
		settings, _ := decodeVaultTunnelSettings([]byte(`{"Password":" old \r\n","TotpSecret":" A B ","SecondaryPassword":" ","PeerPresharedKey":" "}`))
		cleanup := normalizeVaultTunnelEditorSettings(kind, settings, map[string]json.RawMessage{})
		if tunnelSettingString(settings, "Password") != " old \r\n" || tunnelSettingString(settings, "TotpSecret") != " A B " || tunnelSettingString(settings, "SecondaryPassword") != " " || tunnelSettingString(settings, "PeerPresharedKey") != " " {
			t.Fatal("omitted factor modified", kind)
		}
		cleanup()
		clearTunnelSettingsMap(settings)
	}
}

func TestVaultTunnelEditorMergedSizeLimit(t *testing.T) {
	ctx, h := context.Background(), vaultCredentialFixture(t)
	profile := strings.Repeat("p", 2*1024*1024)
	initial, _ := json.Marshal(map[string]string{"ProfileOvpn": profile})
	input := tunnelEditorInput(1, string(initial))
	saved := saveTunnelEditor(t, h, input)
	patch, _ := json.Marshal(map[string]string{"Password": strings.Repeat("s", 2*1024*1024)})
	input["patch"] = patch
	if _, err := h.Handle(ctx, "tunnel-edit", vaultInput(t, input)); err != vaultwire.ErrProtocol {
		t.Fatal("oversized merged configuration accepted", err)
	}
	current, err := h.owner.ReadTunnel(ctx, saved.ID, 0)
	if err != nil || current.RowVersion != saved.RowVersion {
		t.Fatal("failed oversized edit advanced revision", err)
	}
	if err := h.owner.WithTunnelConfiguration(ctx, saved.ID, saved.RowVersion, func(raw []byte) error {
		if !bytes.Equal(raw, initial) {
			t.Fatal("oversized edit replaced original settings")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestVaultTunnelEditorWatchguardLegacyAuthMode(t *testing.T) {
	h := vaultCredentialFixture(t)
	input := tunnelEditorInput(3, `{"Server":"vpn.example","AuthMode":2}`)
	saved := saveTunnelEditor(t, h, input)
	// Native migration preserves this historical representation.
	if _, err := h.owner.PutTunnel(context.Background(), saved.TunnelMetadata,
		[]byte(`{"Server":"vpn.example","UseSingleSignOn":true}`), saved.RowVersion); err != nil {
		t.Fatal(err)
	}
	input["rowVersion"] = "2"
	input["patch"] = []byte(`{"AuthMode":1,"Username":"alice","Password":"replacement"}`)
	saveTunnelEditor(t, h, input)
	settings := vaultTestTunnelEditorSettings(t, h, saved.ID)
	if settings["AuthMode"] != float64(1) || settings["Username"] != "alice" || settings["Password"] != "replacement" {
		t.Fatal("legacy SSO overrode explicit authentication edit")
	}
	if _, exists := settings["UseSingleSignOn"]; exists {
		t.Fatal("obsolete SSO flag retained")
	}
	input["patch"] = []byte(`{"AuthMode":2}`)
	saveTunnelEditor(t, h, input)
	settings = vaultTestTunnelEditorSettings(t, h, saved.ID)
	if settings["AuthMode"] != float64(2) || settings["Password"] != nil || settings["Username"] != nil {
		t.Fatal("SSO transition retained manual factors")
	}
}

func TestVaultTunnelEditorRejectsUnreadableProjectionAtomically(t *testing.T) {
	h := vaultCredentialFixture(t)
	input := tunnelEditorInput(1, `{"ProfileOvpn":"profile","Username":"`+strings.Repeat("x", 512*1024)+`"}`)
	if _, err := h.Handle(context.Background(), "tunnel-edit", vaultInput(t, input)); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	values, err := h.owner.ListTunnels(context.Background(), "", 128)
	if err != nil || len(values) != 0 {
		t.Fatal("unreadable create persisted", err)
	}
	// The larger secret profile never enters the display and remains supported.
	input["patch"] = []byte(`{"ProfileOvpn":"` + strings.Repeat("p", 1024*1024) + `","Username":"alice"}`)
	saved := saveTunnelEditor(t, h, input)
	before := vaultTestTunnelEditorSettings(t, h, saved.ID)
	input["patch"] = []byte(`{"Username":"` + strings.Repeat("x", 512*1024) + `"}`)
	if _, err := h.Handle(context.Background(), "tunnel-edit", vaultInput(t, input)); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	current, err := h.owner.ReadTunnel(context.Background(), saved.ID, 0)
	if err != nil || current.RowVersion != saved.RowVersion || current.ConfigurationVersion != saved.ConfigurationVersion ||
		!reflect.DeepEqual(before, vaultTestTunnelEditorSettings(t, h, saved.ID)) {
		t.Fatal("failed display check changed configuration", err)
	}
}

func TestVaultTunnelEditorRenameKeepsProjectionReadable(t *testing.T) {
	h := vaultCredentialFixture(t)
	metadata := vaultstore.TunnelMetadata{Name: "A", Kind: 1}
	base, err := projectVaultTunnelEditor(vaultstore.Tunnel{TunnelMetadata: metadata}, []byte(`{"ProfileOvpn":"profile","Username":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	size := 512*1024 - len(base) + 1
	input := tunnelEditorInput(1, `{"ProfileOvpn":"profile","Username":"`+strings.Repeat("x", size)+`"}`)
	input["metadata"].(map[string]any)["name"] = "A"
	saved := saveTunnelEditor(t, h, input)
	input["metadata"].(map[string]any)["name"] = strings.Repeat("<", 128)
	input["patch"] = []byte(`{}`)
	if _, err = h.Handle(context.Background(), "tunnel-edit", vaultInput(t, input)); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	current, err := h.owner.ReadTunnel(context.Background(), saved.ID, 0)
	if err != nil || current.RowVersion != saved.RowVersion || current.ConfigurationVersion != saved.ConfigurationVersion || current.Name != "A" {
		t.Fatal("oversized rename persisted", err)
	}
}

func TestVaultTunnelEditorRejectsUnrepresentablePublicValuesAtomically(t *testing.T) {
	h := vaultCredentialFixture(t)
	input := tunnelEditorInput(0, `{"InterfacePrivateKey":"private","InterfaceAddress":"10.0.0.1","PeerPublicKey":"public","PeerEndpoint":"vpn:51820"}`)
	saved := saveTunnelEditor(t, h, input)
	for _, patch := range []string{`{"Mtu":9007199254740992}`, `{"InterfaceAddress":"a\u0000b"}`, `{"Dns":["\ud800"]}`} {
		input["patch"] = []byte(patch)
		if _, err := h.Handle(context.Background(), "tunnel-edit", vaultInput(t, input)); err != vaultwire.ErrProtocol {
			t.Fatal("unreadable value saved", err)
		}
		current, err := h.owner.ReadTunnel(context.Background(), saved.ID, 0)
		if err != nil || current.RowVersion != saved.RowVersion || current.ConfigurationVersion != saved.ConfigurationVersion {
			t.Fatal("failed projection advanced revision", err)
		}
	}
}
