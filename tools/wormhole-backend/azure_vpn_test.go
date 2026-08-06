package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareAzureVPNUsesInteractiveCodeThenSilentRefresh(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Path != "/tenant/oauth2/v2.0/token" {
			t.Fatalf("unexpected token path: %s", request.URL.Path)
		}
		if err := request.ParseForm(); err != nil {
			t.Fatal(err)
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.Form.Get("grant_type") {
		case "authorization_code":
			if request.Form.Get("code") != "auth-code" || request.Form.Get("code_verifier") == "" {
				t.Fatalf("invalid code exchange: %#v", request.Form)
			}
			_, _ = writer.Write([]byte(`{"access_token":"access-one","refresh_token":"refresh-one"}`))
		case "refresh_token":
			if request.Form.Get("refresh_token") != "refresh-one" {
				t.Fatalf("invalid refresh exchange: %#v", request.Form)
			}
			_, _ = writer.Write([]byte(`{"access_token":"access-two","refresh_token":"refresh-two"}`))
		default:
			t.Fatalf("unexpected grant: %#v", request.Form)
		}
	}))
	defer server.Close()
	previousAuthority := azureOAuthAuthority
	azureOAuthAuthority = server.URL
	defer func() { azureOAuthAuthority = previousAuthority }()
	raw, _ := json.Marshal(map[string]any{
		"Servers": []string{"gateway.vpn.azure.com"}, "Protocol": 0,
		"TenantId": "tenant", "Audience": "client-id",
	})
	snapshot := tunnelConfigSnapshot{
		databasePath: filepath.Join(t.TempDir(), "wormhole.db"),
		id:           "11111111-2222-3333-4444-555555555555",
	}
	prompts := 0
	ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, prompt tunnelPrompt) (string, error) {
		prompts++
		if !prompt.Browser || prompt.Completion != "oauth-code" || prompt.ExpectedState == "" {
			t.Fatalf("unexpected Azure browser prompt: %#v", prompt)
		}
		encoded, _ := json.Marshal(azureBrowserResult{Code: "auth-code", State: prompt.ExpectedState})
		return string(encoded), nil
	})
	prepared, err := prepareAzureVPN(ctx, raw, snapshot)
	if err != nil {
		t.Fatalf("interactive Azure prepare: %v", err)
	}
	var settings map[string]json.RawMessage
	_ = json.Unmarshal(prepared, &settings)
	if tunnelSettingString(settings, "Username") != "AzureAD" || tunnelSettingString(settings, "Password") != "access-one" {
		t.Fatalf("interactive token was not routed: %s", prepared)
	}
	prepared, err = prepareAzureVPN(ctx, raw, snapshot)
	if err != nil {
		t.Fatalf("silent Azure prepare: %v", err)
	}
	_ = json.Unmarshal(prepared, &settings)
	if tunnelSettingString(settings, "Password") != "access-two" || prompts != 1 || requests != 2 {
		t.Fatalf("silent refresh failed: prepared=%s prompts=%d requests=%d", prepared, prompts, requests)
	}
}

func TestParseAzureVPNProfile(t *testing.T) {
	secret := strings.Repeat("ab", 256)
	profile := `<AzVpnProfile xmlns="urn:test"><name>Production P2S</name><serverlist>` +
		`<ServerEntry><fqdn>primary.vpn.azure.com</fqdn></ServerEntry>` +
		`<ServerEntry><fqdn>backup.vpn.azure.com</fqdn></ServerEntry></serverlist>` +
		`<protocolconfig><sslprotocolConfig><transportprotocol>udp</transportprotocol></sslprotocolConfig></protocolconfig>` +
		`<clientauth><type>aad</type><aad><tenant>https://login.microsoftonline.com/tenant-id/</tenant>` +
		`<audience>audience-id</audience><issuer>issuer</issuer><applicationid>client-id</applicationid></aad></clientauth>` +
		`<servervalidation><serversecret>` + secret + `</serversecret></servervalidation></AzVpnProfile>`
	result, err := parseAzureVPNProfile([]byte(profile))
	if err != nil {
		t.Fatal(err)
	}
	servers, ok := result.Settings["Servers"].([]string)
	if result.Name != "Production P2S" || !ok || len(servers) != 2 || result.Settings["TenantId"] != "tenant-id" || result.Settings["Protocol"] != 1 {
		t.Fatalf("parsed Azure profile = %#v", result)
	}
	if _, err := url.Parse(azureRedirectURI); err != nil {
		t.Fatal(err)
	}
}
