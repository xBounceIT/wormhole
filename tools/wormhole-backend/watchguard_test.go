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
	"os"
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

func TestPrepareWatchguardAutomaticSupportsMultipleChallengeRounds(t *testing.T) {
	bundle := testWatchguardBundle(t, map[string]string{
		"client.ovpn": "client\ndev tun\nca ca.crt\ncert client.crt\nkey client.pem\nremote firebox.example.test 443 tcp\n",
		"ca.crt":      "CA",
		"client.crt":  "CERT",
		"client.pem":  "KEY",
	})
	challengeLeg := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Query().Get("action") {
		case "sslvpn_logon":
			writer.Header().Set("Content-Type", "application/xml")
			if request.URL.Query().Get("fw_logon_type") == "logon" {
				_, _ = writer.Write([]byte(`<resp><logon_status>8</logon_status><logon_id>first</logon_id><chaStr>First code</chaStr></resp>`))
				return
			}
			challengeLeg++
			if challengeLeg == 1 {
				if request.URL.Query().Get("response") != "111111" || request.URL.Query().Get("fw_logon_id") != "first" {
					t.Errorf("first challenge request: %s", request.URL.RawQuery)
				}
				_, _ = writer.Write([]byte(`<resp><logon_status>4</logon_status><logon_id>second</logon_id><chaStr>Second code</chaStr></resp>`))
				return
			}
			if request.URL.Query().Get("response") != "222222" || request.URL.Query().Get("fw_logon_id") != "second" {
				t.Errorf("second challenge request: %s", request.URL.RawQuery)
			}
			_, _ = writer.Write([]byte(`<resp><logon_status>1</logon_status></resp>`))
		case "sslvpn_download":
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
	codes := []string{"111111", "222222"}
	prompt := 0
	ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, _ tunnelPrompt) (string, error) {
		answer := codes[prompt]
		prompt++
		return answer, nil
	})
	prepared, err := prepareWatchguardProfile(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]json.RawMessage
	_ = json.Unmarshal(prepared, &settings)
	if password := tunnelSettingString(settings, "Password"); password != "222222" {
		t.Fatalf("data-plane password=%q, want final response", password)
	}
	if prompt != 2 || challengeLeg != 2 {
		t.Fatalf("prompts=%d challenge legs=%d, want 2/2", prompt, challengeLeg)
	}
}

func TestPrepareWatchguardAutomaticPushKeepsAccountPasswordForOpenVPN(t *testing.T) {
	bundle := testWatchguardBundle(t, map[string]string{
		"client.ovpn": "client\nca ca.crt\ncert client.crt\nkey client.pem\nremote firebox.example.test 443 tcp\n",
		"ca.crt":      "CA", "client.crt": "CERT", "client.pem": "KEY",
	})
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Query().Get("action") {
		case "sslvpn_logon":
			writer.Header().Set("Content-Type", "application/xml")
			if request.URL.Query().Get("fw_logon_type") == "logon" {
				_, _ = writer.Write([]byte(`<resp><logon_status>8</logon_status><logon_id>push</logon_id></resp>`))
			} else {
				if request.URL.Query().Get("fw_logon_type") != "mfa_response" || request.URL.Query().Get("mfa_choice") != "p" {
					t.Errorf("unexpected push response: %s", request.URL.RawQuery)
				}
				_, _ = writer.Write([]byte(`<resp><logon_status>1</logon_status></resp>`))
			}
		case "sslvpn_download":
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
	ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, _ tunnelPrompt) (string, error) {
		return "P", nil
	})
	prepared, err := prepareWatchguardProfile(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]json.RawMessage
	_ = json.Unmarshal(prepared, &settings)
	if password := tunnelSettingString(settings, "Password"); password != "secret" {
		t.Fatalf("OpenVPN password=%q, want the account password after push approval", password)
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

func TestImportWatchguardFileReturnsNormalizedGatewayProfile(t *testing.T) {
	bundle := testWatchguardBundle(t, map[string]string{
		"client.ovpn": "client\n<ca>\nremote ignored.example 1\n</ca>\nremote firebox.example.test 444 tcp\nca ca.crt\ncert client.crt\nkey client.pem\n",
		"ca.crt":      "CA", "client.crt": "CERT", "client.pem": "KEY",
	})
	path := filepath.Join(t.TempDir(), "watchguard.tgz")
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := importWatchguardFile(watchguardImportRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if result.Server != "firebox.example.test" || result.Port != 444 || !strings.Contains(result.ProfileOvpn, "<ca>\nCA\n</ca>") {
		t.Fatalf("import result = %#v", result)
	}

	for _, invalid := range []string{"", "relative.tgz", t.TempDir()} {
		if _, err := importWatchguardFile(watchguardImportRequest{Path: invalid}); err == nil {
			t.Fatalf("invalid import path %q was accepted", invalid)
		}
	}
	empty := filepath.Join(t.TempDir(), "empty.tgz")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := importWatchguardFile(watchguardImportRequest{Path: empty}); err == nil {
		t.Fatal("empty WatchGuard bundle was accepted")
	}
	malformed := filepath.Join(t.TempDir(), "malformed.tgz")
	if err := os.WriteFile(malformed, []byte("not a bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := importWatchguardFile(watchguardImportRequest{Path: malformed}); err == nil {
		t.Fatal("malformed WatchGuard bundle was accepted")
	}
}

func TestWatchguardRemoteValidatesGatewayOutsideInlineBlocks(t *testing.T) {
	host, port, err := watchguardRemote("client\nremote gateway.example\n")
	if err != nil || host != "gateway.example" || port != 443 {
		t.Fatalf("default remote = %q:%d, %v", host, port, err)
	}
	for _, profile := range []string{
		"client\n",
		"remote gateway.example invalid\n",
		"remote gateway.example 70000\n",
		"remote bad/host 443\n",
		"<ca>\nremote hidden.example 443\n</ca>\n",
	} {
		if _, _, err := watchguardRemote(profile); err == nil {
			t.Fatalf("invalid remote profile was accepted: %q", profile)
		}
	}
}

func TestBuildWatchguardProfileFromManualMaterial(t *testing.T) {
	settings := stormshieldTestSettings(t, map[string]any{
		"Server": "firebox.example", "Port": 444, "VerifyX509Name": "firebox.example",
		"CaPem": "CA DATA", "ClientCertPem": "CERT DATA", "ClientKeyPem": "KEY DATA",
	})
	profile, err := buildWatchguardProfile(settings)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"remote firebox.example 444", `verify-x509-name "firebox.example" subject`,
		"<ca>\nCA DATA\n</ca>", "<cert>\nCERT DATA\n</cert>", "<key>\nKEY DATA\n</key>",
	} {
		if !strings.Contains(profile, fragment) {
			t.Fatalf("manual profile missing %q: %s", fragment, profile)
		}
	}

	for _, values := range []map[string]any{
		{"Server": "bad\nhost", "CaPem": "CA", "ClientCertPem": "CERT", "ClientKeyPem": "KEY"},
		{"Server": "firebox.example", "CaPem": "<CA>", "ClientCertPem": "CERT", "ClientKeyPem": "KEY"},
		{"Server": "firebox.example", "CaPem": "CA", "ClientCertPem": "CERT", "ClientKeyPem": "KEY\n</key>"},
	} {
		if _, err := buildWatchguardProfile(stormshieldTestSettings(t, values)); err == nil {
			t.Fatalf("invalid manual material was accepted: %#v", values)
		}
	}

	inlined, err := buildWatchguardProfile(stormshieldTestSettings(t, map[string]any{
		"ProfileOvpn": "client\nca ca.crt\ncert client.crt\nkey client.pem\nremote firebox.example 443\n",
		"CaPem":       "CA", "ClientCertPem": "CERT", "ClientKeyPem": "KEY",
	}))
	if err != nil || !strings.Contains(inlined, "<key>\nKEY\n</key>") {
		t.Fatalf("inlined profile = %s, %v", inlined, err)
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
