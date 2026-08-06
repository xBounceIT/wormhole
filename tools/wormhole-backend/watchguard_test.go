package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareWatchguardAutomaticAuthenticatesDownloadsAndCachesProfile(t *testing.T) {
	bundle := testWatchguardBundle(t, map[string]string{
		"client.ovpn": "client\ndev tun\nauth-user-pass\nca ca.crt\ncert client.crt\nkey client.pem\nremote firebox.example.test 443 tcp\n",
		"ca.crt":      "CA-CONTENT",
		"client.crt":  "CERT-CONTENT",
		"client.pem":  "KEY-CONTENT",
	})
	logons, downloads := 0, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Query().Get("action") {
		case "sslvpn_logon":
			logons++
			writer.Header().Set("Content-Type", "application/xml")
			if request.URL.Query().Get("fw_logon_type") == "logon" {
				if request.URL.Query().Get("fw_username") != "alice" || request.URL.Query().Get("fw_password") != "secret" {
					t.Errorf("unexpected WatchGuard credentials")
				}
				_, _ = writer.Write([]byte(`<resp><logon_status>8</logon_status><logon_id>42</logon_id><chaStr>OTP please</chaStr></resp>`))
			} else {
				if request.URL.Query().Get("response") != "111111" || request.URL.Query().Get("fw_logon_id") != "42" {
					t.Errorf("unexpected WatchGuard challenge response: %s", request.URL.RawQuery)
				}
				_, _ = writer.Write([]byte(`<resp><logon_status>1</logon_status></resp>`))
			}
		case "sslvpn_download":
			downloads++
			_, _ = writer.Write(bundle)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)
	raw, _ := json.Marshal(map[string]any{
		"Server": serverURL.Hostname(), "Port": mustTestPort(t, serverURL.Port()), "AuthMode": 1,
		"Username": "alice", "Password": "secret", "TrustServerCertificate": true,
	})
	snapshot := tunnelConfigSnapshot{
		databasePath: filepath.Join(t.TempDir(), "wormhole.db"),
		id:           "11111111-2222-3333-4444-555555555555",
	}
	codes := []string{"111111", "222222"}
	promptIndex := 0
	ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, _ tunnelPrompt) (string, error) {
		code := codes[promptIndex]
		promptIndex++
		return code, nil
	})

	prepared, err := prepareWatchguardProfile(ctx, raw, snapshot)
	if err != nil {
		t.Fatalf("automatic WatchGuard prepare: %v", err)
	}
	var settings map[string]json.RawMessage
	_ = json.Unmarshal(prepared, &settings)
	if tunnelSettingString(settings, "Password") != "111111" || tunnelSettingString(settings, "ChallengeResponse") != "" {
		t.Fatalf("web-auth credentials were not routed correctly: %s", prepared)
	}
	if profile := tunnelSettingString(settings, "ProfileOvpn"); !strings.Contains(profile, "<key>\nKEY-CONTENT\n</key>") {
		t.Fatalf("downloaded profile was not inlined: %s", profile)
	}

	prepared, err = prepareWatchguardProfile(ctx, raw, snapshot)
	if err != nil {
		t.Fatalf("cached WatchGuard prepare: %v", err)
	}
	_ = json.Unmarshal(prepared, &settings)
	if tunnelSettingString(settings, "Password") != "secret" || tunnelSettingString(settings, "ChallengeResponse") != "222222" {
		t.Fatalf("cached profile challenge was not routed correctly: %s", prepared)
	}
	if logons != 2 || downloads != 1 || promptIndex != 2 {
		t.Fatalf("logons=%d downloads=%d prompts=%d, want 2/1/2", logons, downloads, promptIndex)
	}
}

func TestBuildWatchguardImportedProfileRejectsMissingKeyMaterial(t *testing.T) {
	settings := stormshieldTestSettings(t, map[string]any{
		"ProfileOvpn": "client\nca ca.crt\ncert client.crt\nkey client.pem\n",
		"CaPem":       "CA", "ClientCertPem": "CERT",
	})
	_, err := buildWatchguardProfile(settings)
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing key error = %v", err)
	}
}

func TestPrepareWatchguardSAMLUsesBrowserResultAndDownloadsWithCookies(t *testing.T) {
	bundle := testWatchguardBundle(t, map[string]string{
		"client.ovpn": "client\nca ca.crt\ncert client.crt\nkey client.pem\nremote firebox.example.test 443 tcp\n",
		"ca.crt":      "CA", "client.crt": "CERT", "client.pem": "KEY",
	})
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("action") != "sslvpn_download" {
			t.Fatalf("unexpected SAML follow-up: %s", request.URL.String())
		}
		cookie, err := request.Cookie("session")
		if err != nil || cookie.Value != "browser-cookie" {
			t.Fatalf("SAML cookie was not forwarded: %#v, %v", cookie, err)
		}
		_, _ = writer.Write(bundle)
	}))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)
	raw, _ := json.Marshal(map[string]any{
		"Server": serverURL.Hostname(), "Port": mustTestPort(t, serverURL.Port()),
		"AuthMode": 2, "TrustServerCertificate": true,
	})
	ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, prompt tunnelPrompt) (string, error) {
		if !prompt.Browser || len(prompt.URLs) != 3 || !prompt.IgnoreCertificateErrors {
			t.Fatalf("unexpected browser prompt: %#v", prompt)
		}
		result, _ := json.Marshal(watchguardSAMLResult{
			Username: "saml-user", Token: "ephemeral-token",
			Cookies: []watchguardBrowserCookie{{
				Name: "session", Value: "browser-cookie", Path: "/", Domain: serverURL.Hostname(), Secure: true,
			}},
		})
		return string(result), nil
	})
	prepared, err := prepareWatchguardProfile(ctx, raw)
	if err != nil {
		t.Fatalf("SAML prepare: %v", err)
	}
	var settings map[string]json.RawMessage
	_ = json.Unmarshal(prepared, &settings)
	if tunnelSettingString(settings, "Username") != "saml-user" || tunnelSettingString(settings, "Password") != "ephemeral-token" {
		t.Fatalf("SAML credentials were not routed to OpenVPN: %s", prepared)
	}
}

func TestPrepareWatchguardAutomaticUsesAdvertisedSAML(t *testing.T) {
	bundle := testWatchguardBundle(t, map[string]string{
		"client.ovpn": "client\nca ca.crt\ncert client.crt\nkey client.pem\nremote firebox.example.test 443 tcp\n",
		"ca.crt":      "CA", "client.crt": "CERT", "client.pem": "KEY",
	})
	statusRequests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Query().Get("action") {
		case "sslvpn_logon":
			statusRequests++
			writer.Header().Set("Content-Type", "application/xml")
			_, _ = writer.Write([]byte(`<resp><saml_enabled>yes</saml_enabled></resp>`))
		case "sslvpn_download":
			_, _ = writer.Write(bundle)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)
	raw, _ := json.Marshal(map[string]any{
		"Server": serverURL.Hostname(), "Port": mustTestPort(t, serverURL.Port()),
		"AuthMode": 0, "TrustServerCertificate": true,
	})
	ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, prompt tunnelPrompt) (string, error) {
		if !prompt.Browser {
			t.Fatalf("automatic SAML did not request a browser: %#v", prompt)
		}
		result, _ := json.Marshal(watchguardSAMLResult{Username: "saml-user", Token: "token"})
		return string(result), nil
	})
	if _, err := prepareWatchguardProfile(ctx, raw); err != nil {
		t.Fatal(err)
	}
	if statusRequests != 1 {
		t.Fatalf("status requests = %d, want 1", statusRequests)
	}
}

func TestPrepareWatchguardStoredProfileApprovesPushBeforeOpenVPNChallenge(t *testing.T) {
	legs := make([]string, 0, 2)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		leg := request.URL.Query().Get("fw_logon_type")
		legs = append(legs, leg)
		writer.Header().Set("Content-Type", "application/xml")
		if leg == "logon" {
			_, _ = writer.Write([]byte(`<resp><logon_status>8</logon_status><logon_id>push-id</logon_id></resp>`))
			return
		}
		if leg != "mfa_response" || request.URL.Query().Get("mfa_choice") != "p" {
			t.Errorf("unexpected push request: %s", request.URL.RawQuery)
		}
		_, _ = writer.Write([]byte(`<resp><logon_status>1</logon_status></resp>`))
	}))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)
	raw, _ := json.Marshal(map[string]any{
		"Server": serverURL.Hostname(), "Port": mustTestPort(t, serverURL.Port()), "AuthMode": 1,
		"Username": "alice", "Password": "secret", "TrustServerCertificate": true,
		"ProfileOvpn": "client\nremote firebox.example.test 443\n",
	})
	ctx := withTunnelPromptHandler(context.Background(), func(context.Context, tunnelPrompt) (string, error) {
		return "P", nil
	})
	prepared, err := prepareWatchguardProfile(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]json.RawMessage
	_ = json.Unmarshal(prepared, &settings)
	if got := tunnelSettingString(settings, "ChallengeResponse"); got != "p" {
		t.Fatalf("challenge response = %q", got)
	}
	if strings.Join(legs, ",") != "logon,mfa_response" {
		t.Fatalf("push legs = %#v", legs)
	}
}

func testWatchguardBundle(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	archive := tar.NewWriter(gzipWriter)
	for name, contents := range files {
		header := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(contents))}
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write([]byte(contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
