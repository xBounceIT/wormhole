package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
)

func TestParseFortinetSAMLAuthID(t *testing.T) {
	authID, ok := parseFortinetSAMLAuthID("/remote/saml/auth_id?id=token%2Bvalue")
	if !ok || authID != "token+value" {
		t.Fatalf("auth id = %q, %v", authID, ok)
	}
	for _, target := range []string{"", "https://attacker.test/?id=x", "/callback", "/callback?id=%zz", "/callback?id="} {
		if value, ok := parseFortinetSAMLAuthID(target); ok {
			t.Fatalf("accepted invalid callback %q as %q", target, value)
		}
	}
}

func TestReadFortinetSAMLCallbackAcceptsBoundedHTTPGet(t *testing.T) {
	server, client := net.Pipe()
	result := make(chan struct {
		id string
		ok bool
	}, 1)
	go func() {
		defer server.Close()
		id, ok := readFortinetSAMLCallback(server)
		result <- struct {
			id string
			ok bool
		}{id, ok}
	}()
	if _, err := io.WriteString(client, "GET /callback?id=ephemeral HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(client)
	_ = client.Close()
	if err != nil || !strings.Contains(string(response), "200 OK") {
		t.Fatalf("response = %q, %v", response, err)
	}
	actual := <-result
	if !actual.ok || actual.id != "ephemeral" {
		t.Fatalf("callback = %#v", actual)
	}
}

func TestFortinetSSOSidecarPayloadContainsOnlyEphemeralAuth(t *testing.T) {
	executable, payload, err := tunnelSidecarCommand(2, json.RawMessage(`{
        "Host":"vpn.example.test","Port":443,"UseSingleSignOn":true,
        "Username":"must-not-cross","Password":"must-not-cross","Realm":"must-not-cross",
        "TotpSecret":"must-not-cross","SamlAuthId":"ephemeral"
    }`))
	if err != nil || executable != "wormhole-fortiproxy" {
		t.Fatalf("sidecar config: %q, %v", executable, err)
	}
	var config map[string]any
	if err := json.Unmarshal(payload, &config); err != nil {
		t.Fatal(err)
	}
	if config["saml_auth_id"] != "ephemeral" {
		t.Fatalf("missing SAML auth id: %#v", config)
	}
	for _, key := range []string{"username", "password", "realm", "totp_secret"} {
		if config[key] != nil {
			t.Fatalf("SSO payload retained %s: %#v", key, config[key])
		}
	}
}

func TestPrepareFortinetAuthenticationUsesEmbeddedBrowserCookie(t *testing.T) {
	ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, prompt tunnelPrompt) (string, error) {
		if !prompt.Browser || prompt.Completion != "cookie" || prompt.CookieName != "SVPNCOOKIE" || !prompt.RequireHTTPOnly {
			t.Fatalf("unexpected prompt: %#v", prompt)
		}
		if len(prompt.URLs) != 1 || prompt.URLs[0] != "https://vpn.example.test:10443/remote/saml/start?realm=employees" {
			t.Fatalf("unexpected SAML URL: %#v", prompt.URLs)
		}
		return "opaque-cookie", nil
	})
	prepared, err := prepareTunnelAuthentication(ctx, 2, json.RawMessage(`{
		"Host":"vpn.example.test","Port":10443,"UseSingleSignOn":true,
		"UseExternalBrowser":false,"Realm":"employees"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(prepared, &settings); err != nil {
		t.Fatal(err)
	}
	if got := tunnelSettingString(settings, "SvpnCookie"); got != "opaque-cookie" {
		t.Fatalf("SVPNCOOKIE = %q", got)
	}
	if got := tunnelSettingString(settings, "SamlAuthId"); got != "" {
		t.Fatalf("unexpected external SAML auth id = %q", got)
	}
}
