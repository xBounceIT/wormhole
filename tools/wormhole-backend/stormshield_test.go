package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDownloadStormshieldProfilePostsCredentialsAndInlinesBundle(t *testing.T) {
	bundle := testStormshieldBundle(t, map[string]string{
		"client.ovpn": "client\ndev tun\nremote sns.example.test 443 tcp\nca \"ca.pem\"\ncert client.pem\nkey client.key\n",
		"ca.pem":      "CA-CONTENT",
		"client.pem":  "CERT-CONTENT",
		"client.key":  "KEY-CONTENT",
	})
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/auth/config.html" || request.URL.Query().Get("version") != "1" || request.URL.Query().Get("type") != "openvpn" {
			t.Errorf("unexpected request URL: %s", request.URL.String())
		}
		if err := request.ParseForm(); err != nil {
			t.Error(err)
		}
		if request.Form.Get("user") != "alice" || request.Form.Get("pass") != "secret" {
			t.Errorf("unexpected credentials form")
		}
		writer.Header().Set("Content-Type", "application/zip")
		_, _ = writer.Write(bundle)
	}))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)
	settings := stormshieldTestSettings(t, map[string]any{
		"Server": serverURL.Hostname(), "Port": mustTestPort(t, serverURL.Port()),
		"Username": "alice", "Password": "secret", "TrustServerCertificate": true,
	})

	profile, err := downloadStormshieldProfile(context.Background(), settings)
	if err != nil {
		t.Fatalf("download profile: %v", err)
	}
	for _, marker := range []string{"<ca>\nCA-CONTENT\n</ca>", "<cert>\nCERT-CONTENT\n</cert>", "<key>\nKEY-CONTENT\n</key>"} {
		if !strings.Contains(profile, marker) {
			t.Fatalf("assembled profile is missing %q:\n%s", marker, profile)
		}
	}
}

func TestDownloadStormshieldProfileSurfacesXMLPortalError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/xml")
		_, _ = writer.Write([]byte(`<response><ret code="4" msg="invalid credentials"/></response>`))
	}))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)
	settings := stormshieldTestSettings(t, map[string]any{
		"Server": serverURL.Hostname(), "Port": mustTestPort(t, serverURL.Port()), "TrustServerCertificate": true,
	})

	_, err := downloadStormshieldProfile(context.Background(), settings)
	if err == nil || !strings.Contains(err.Error(), "invalid credentials") || !strings.Contains(err.Error(), "code 4") {
		t.Fatalf("portal error = %v", err)
	}
}

func TestAssembleStormshieldProfileRejectsMissingReferencedMaterial(t *testing.T) {
	bundle := testStormshieldBundle(t, map[string]string{
		"client.ovpn": "client\ndev tun\nremote sns.example.test 443\nkey missing.pem\n",
	})
	_, err := assembleStormshieldProfile(bundle)
	if err == nil || !strings.Contains(err.Error(), "missing.pem") {
		t.Fatalf("missing material error = %v", err)
	}
}

func TestNormalizeStormshieldProfileAndTransportOverride(t *testing.T) {
	profile := "client\r\ndev tun\r\nproto udp\r\nremote sns.example.test 1194 udp\r\nremote sns.example.test 443 tcp\r\ncipher AES-128-CBC\r\ntls-cipher DEFAULT\r\n<ca>\r\ntls-cipher KEEP-IN-BLOCK\r\n</ca>\r\n"
	normalized, err := normalizeStormshieldProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(normalized, "\r") || strings.Contains(normalized, "tls-cipher DEFAULT") || !strings.Contains(normalized, "tls-cipher KEEP-IN-BLOCK") {
		t.Fatalf("unexpected normalized profile:\n%s", normalized)
	}
	if !strings.Contains(normalized, "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC") || !strings.Contains(normalized, "data-ciphers-fallback AES-128-CBC") {
		t.Fatalf("cipher negotiation was not added:\n%s", normalized)
	}
	tcpOnly, err := applyStormshieldTransportOverride(normalized, 1)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(tcpOnly, "1194 udp") || !strings.Contains(tcpOnly, "443 tcp") || !strings.Contains(tcpOnly, "proto tcp-client") {
		t.Fatalf("transport override failed:\n%s", tcpOnly)
	}
}

func TestPrepareStormshieldAutomaticProducesSidecarReadyProfile(t *testing.T) {
	bundle := testStormshieldBundle(t, map[string]string{
		"client.ovpn": "client\ndev tun\nremote sns.example.test 443 tcp\ncipher AES-256-CBC\n",
	})
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/zip")
		_, _ = writer.Write(bundle)
	}))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)
	raw, _ := json.Marshal(map[string]any{
		"Server": serverURL.Hostname(), "Port": mustTestPort(t, serverURL.Port()), "Mode": 0,
		"Username": "alice", "Password": "secret", "TrustServerCertificate": true,
	})
	prepared, err := prepareStormshieldProfile(context.Background(), raw)
	if err != nil {
		t.Fatalf("prepare profile: %v", err)
	}
	var settings map[string]json.RawMessage
	_ = json.Unmarshal(prepared, &settings)
	if !strings.Contains(tunnelSettingString(settings, "ProfileOvpn"), "data-ciphers") || tunnelSettingString(settings, "Password") != "secret" {
		t.Fatalf("prepared settings are incomplete: %s", prepared)
	}
}

func TestPrepareStormshieldOtpCachesDownloadedProfileAndUsesFreshCodeForDataPlane(t *testing.T) {
	bundle := testStormshieldBundle(t, map[string]string{
		"client.ovpn": "client\ndev tun\nauth-user-pass\nremote sns.example.test 443 tcp\n",
	})
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if err := request.ParseForm(); err != nil {
			t.Error(err)
		}
		if request.Form.Get("pass") != "secret111111" {
			t.Errorf("download password = %q", request.Form.Get("pass"))
		}
		writer.Header().Set("Content-Type", "application/zip")
		_, _ = writer.Write(bundle)
	}))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)
	raw, _ := json.Marshal(map[string]any{
		"Server": serverURL.Hostname(), "Port": mustTestPort(t, serverURL.Port()), "Mode": 0,
		"Username": "alice", "Password": "secret", "UseOtp": true, "TrustServerCertificate": true,
	})
	snapshot := tunnelConfigSnapshot{
		databasePath: filepath.Join(t.TempDir(), "wormhole.db"),
		id:           "11111111-2222-3333-4444-555555555555",
	}
	codes := []string{"111111", "222222"}
	promptIndex := 0
	ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, prompt tunnelPrompt) (string, error) {
		if prompt.Title == "" || !prompt.Secret {
			t.Fatalf("unexpected prompt: %#v", prompt)
		}
		code := codes[promptIndex]
		promptIndex++
		return code, nil
	})

	_, err := prepareStormshieldProfile(ctx, raw, snapshot)
	if err == nil || !strings.Contains(err.Error(), "connect again") {
		t.Fatalf("first OTP prepare = %v", err)
	}
	cacheContents, err := os.ReadFile(stormshieldCachePath(snapshot))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cacheContents, []byte("auth-user-pass")) {
		t.Fatal("Stormshield cache contains the plaintext profile")
	}
	prepared, err := prepareStormshieldProfile(ctx, raw, snapshot)
	if err != nil {
		t.Fatalf("cached OTP prepare: %v", err)
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(prepared, &settings); err != nil {
		t.Fatal(err)
	}
	if password := tunnelSettingString(settings, "Password"); password != "secret222222" {
		t.Fatalf("data-plane password = %q", password)
	}
	if requests != 1 || promptIndex != 2 {
		t.Fatalf("requests=%d prompts=%d, want 1/2", requests, promptIndex)
	}
}

func testStormshieldBundle(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var output bytes.Buffer
	archive := zip.NewWriter(&output)
	for name, contents := range files {
		entry, err := archive.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func stormshieldTestSettings(t *testing.T, values map[string]any) map[string]json.RawMessage {
	t.Helper()
	payload, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(payload, &settings); err != nil {
		t.Fatal(err)
	}
	return settings
}

func mustTestPort(t *testing.T, value string) int {
	t.Helper()
	port, err := strconv.Atoi(value)
	if err != nil {
		t.Fatal(err)
	}
	return port
}
