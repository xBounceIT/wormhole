package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

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

func TestFortinetSAMLAlwaysUsesDedicatedWindow(t *testing.T) {
	for _, legacy := range []string{"", `,"UseExternalBrowser":true,"SamlRedirectPort":-1`, `,"UseExternalBrowser":false`} {
		t.Run(legacy, func(t *testing.T) {
			prompted := false
			ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, prompt tunnelPrompt) (string, error) {
				prompted = true
				if !prompt.Browser || prompt.Completion != "cookie" || prompt.CookieName != "SVPNCOOKIE" || !prompt.RequireHTTPOnly || !prompt.IgnoreCertificateErrors || prompt.Title != "Fortinet SAML sign-in" {
					t.Fatalf("unexpected browser prompt: %#v", prompt)
				}
				if len(prompt.URLs) != 1 || prompt.URLs[0] != "https://vpn.example.test:443/remote/saml/start?realm=staff+%26+admin" {
					t.Fatalf("unexpected URL: %#v", prompt.URLs)
				}
				return "fresh-cookie", nil
			})
			raw := json.RawMessage(`{"Host":"vpn.example.test","UseSingleSignOn":true,"Realm":"staff & admin","TrustServerCertificate":true,"SamlAuthId":"stale-id","SvpnCookie":"stale-cookie"` + legacy + `}`)
			prepared, err := prepareTunnelAuthentication(ctx, 2, raw)
			if err != nil || !prompted {
				t.Fatalf("authentication: %v, prompted=%v", err, prompted)
			}
			var settings map[string]json.RawMessage
			if err := json.Unmarshal(prepared, &settings); err != nil {
				t.Fatal(err)
			}
			if tunnelSettingString(settings, "SvpnCookie") != "fresh-cookie" {
				t.Fatal("fresh cookie missing")
			}
			for _, key := range []string{"UseExternalBrowser", "SamlRedirectPort", "SamlAuthId"} {
				if _, found := settings[key]; found {
					t.Fatalf("retained legacy field %s", key)
				}
			}
			executable, payload, err := tunnelSidecarCommand(2, prepared)
			if err != nil || executable != "wormhole-fortiproxy" {
				t.Fatalf("sidecar: %v", err)
			}
			var config map[string]any
			if err := json.Unmarshal(payload, &config); err != nil {
				t.Fatal(err)
			}
			if config["svpn_cookie"] != "fresh-cookie" || config["saml_auth_id"] != nil {
				t.Fatal("sidecar did not receive only the fresh cookie")
			}
		})
	}
}

func TestFortinetDedicatedSAMLFailures(t *testing.T) {
	for _, tc := range []struct {
		name, raw, cookie string
		promptErr         error
		wantPrompt        bool
	}{
		{name: "malformed", raw: `{`},
		{name: "gateway", raw: `{"Host":"bad host","UseSingleSignOn":true}`},
		{name: "legacy certificate pin", raw: `{"Host":"vpn.example.test","UseSingleSignOn":true,"UseExternalBrowser":true,"ServerCertSha256Pin":"abcd"}`},
		{name: "empty cookie", cookie: "", wantPrompt: true},
		{name: "blank cookie", cookie: "  ", wantPrompt: true},
		{name: "oversized cookie", cookie: strings.Repeat("x", 16*1024+1), wantPrompt: true},
		{name: "cancelled", promptErr: context.Canceled, wantPrompt: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prompted := false
			ctx := withTunnelPromptHandler(context.Background(), func(context.Context, tunnelPrompt) (string, error) {
				prompted = true
				return tc.cookie, tc.promptErr
			})
			raw := tc.raw
			if raw == "" {
				raw = `{"Host":"vpn.example.test","UseSingleSignOn":true}`
			}
			prepared, err := prepareTunnelAuthentication(ctx, 2, json.RawMessage(raw))
			if err == nil || prepared != nil || prompted != tc.wantPrompt {
				t.Fatalf("failure = %v, prompted=%v", err, prompted)
			}
			if tc.promptErr != nil && !errors.Is(err, tc.promptErr) {
				t.Fatalf("lost cancellation: %v", err)
			}
		})
	}
	raw := json.RawMessage(`{"Host":"vpn.example.test","Username":"alice","Password":"password","UseExternalBrowser":true}`)
	got, err := prepareTunnelAuthentication(context.Background(), 2, raw)
	if err != nil || string(got) != string(raw) {
		t.Fatal("password authentication changed")
	}
	if _, err := prepareTunnelAuthentication(context.Background(), 2, json.RawMessage(`{"Host":"vpn.example.test","UseSingleSignOn":true}`)); err == nil {
		t.Fatal("missing native prompt handler accepted")
	}
}

func TestFortinetLegacySettingsValidation(t *testing.T) {
	for _, useSSO := range []bool{false, true} {
		settings := map[string]json.RawMessage{
			"Host": json.RawMessage(`"vpn.example.test"`), "Username": json.RawMessage(`"alice"`), "Password": json.RawMessage(`"password"`),
			"UseExternalBrowser": json.RawMessage(`true`), "SamlRedirectPort": json.RawMessage(`-1`), "Realm": json.RawMessage(`"staff"`),
		}
		settings["UseSingleSignOn"], _ = json.Marshal(useSSO)
		if err := validateTunnelSettings(2, settings); err != nil {
			t.Fatal(err)
		}
		if _, ok := settings["UseExternalBrowser"]; ok {
			t.Fatal("legacy browser flag retained")
		}
		if _, ok := settings["SamlRedirectPort"]; ok {
			t.Fatal("legacy callback retained")
		}
		if tunnelSettingString(settings, "Realm") != "staff" {
			t.Fatal("realm lost")
		}
		if useSSO {
			settings["ServerCertSha256Pin"] = json.RawMessage(`"abcd"`)
			if err := validateTunnelSettings(2, settings); err == nil {
				t.Fatal("SSO certificate pin accepted")
			}
		}
	}
}

func TestFortinetSAMLBoundsNativePromptURL(t *testing.T) {
	const prefix = "https://vpn.example.test:443/remote/saml/start?realm="
	for _, size := range []int{4095, 4096, 4097} {
		realm := strings.Repeat("a", size-len(prefix))
		raw, _ := json.Marshal(map[string]any{"Host": "vpn.example.test", "UseSingleSignOn": true, "Realm": realm})
		prompted := false
		ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, prompt tunnelPrompt) (string, error) {
			prompted = true
			if len(prompt.URLs[0]) != size {
				t.Fatal("unexpected encoded URL length")
			}
			return "fresh-cookie", nil
		})
		_, err := prepareFortinetAuthentication(ctx, raw)
		if (err == nil) != (size <= 4096) || prompted != (size <= 4096) {
			t.Fatalf("URL length %d: error=%v, prompted=%v", size, err, prompted)
		}
	}
	for _, settings := range []map[string]any{
		{"Host": "vpn.example.test", "UseSingleSignOn": true, "Realm": strings.Repeat("é", 700)},
		{"Host": strings.Repeat("a", 4097), "UseSingleSignOn": true},
	} {
		raw, _ := json.Marshal(settings)
		ctx := withTunnelPromptHandler(context.Background(), func(context.Context, tunnelPrompt) (string, error) {
			t.Fatal("oversized native browser prompt emitted")
			return "", nil
		})
		if _, err := prepareFortinetAuthentication(ctx, raw); err == nil || strings.Contains(err.Error(), "aaaa") || strings.Contains(err.Error(), "é") {
			t.Fatalf("expected fixed length error: %v", err)
		}
	}
}
