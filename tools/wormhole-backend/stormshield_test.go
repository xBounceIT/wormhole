package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

func TestStormshieldLegacyCompressionStubPreservesFraming(t *testing.T) {
	if _, err := applyStormshieldLegacyCompressionStub(""); err == nil {
		t.Fatal("empty Stormshield profile was accepted")
	}
	profile, err := applyStormshieldLegacyCompressionStub("client\n<ca>\ncompress inside-certificate\n</ca>\nremote vpn.example 443\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(profile, "comp-lzo no") || !strings.Contains(profile, "compress inside-certificate") {
		t.Fatalf("legacy compression profile = %s", profile)
	}
	framed, err := applyStormshieldLegacyCompressionStub("client\ncompress stub-v2\n")
	if err != nil || strings.Count(framed, "compress") != 1 || strings.Contains(framed, "comp-lzo no") {
		t.Fatalf("existing compression framing changed: %s, %v", framed, err)
	}
}

func TestStormshieldTransportOverrideRewritesConnectionBlocks(t *testing.T) {
	profile := strings.Join([]string{
		"client",
		"<connection>",
		"remote tcp.example 443 tcp-client",
		"proto tcp-client",
		"</connection>",
		"<connection>",
		"remote udp.example 1194 udp",
		"</connection>",
		"<ca>",
		"remote certificate-text 1 tcp",
		"</ca>",
	}, "\n")
	tcpProfile, err := applyStormshieldTransportOverride(profile, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tcpProfile, "tcp.example") || strings.Contains(tcpProfile, "udp.example") || !strings.Contains(tcpProfile, "remote certificate-text") {
		t.Fatalf("TCP override = %s", tcpProfile)
	}
	udpProfile, err := applyStormshieldTransportOverride(profile, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(udpProfile, "udp.example") || strings.Contains(udpProfile, "tcp.example") {
		t.Fatalf("UDP override = %s", udpProfile)
	}
	if unchanged, err := applyStormshieldTransportOverride(profile, 0); err != nil || unchanged != profile {
		t.Fatalf("unchanged override = %q, %v", unchanged, err)
	}
	if _, err := applyStormshieldTransportOverride("<connection>\nremote vpn.example 443\n", 1); err == nil {
		t.Fatal("unterminated connection block was accepted")
	}
	if _, err := applyStormshieldTransportOverride("remote udp.example 1194 udp\n", 1); err == nil {
		t.Fatal("profile without requested TCP remote was accepted")
	}

	rewritten, sawRemote, keptRemote := rewriteStormshieldConnectionBlock([]string{
		"<connection>", "remote vpn.example 443", "</connection>",
	}, "tcp", "tcp-client")
	if !sawRemote || !keptRemote || !strings.Contains(strings.Join(rewritten, "\n"), "proto tcp-client") {
		t.Fatalf("rewritten unqualified block = %#v, %v, %v", rewritten, sawRemote, keptRemote)
	}
}

func TestStormshieldPortalErrorAndEndpointValidation(t *testing.T) {
	portalErr := &stormshieldPortalRequestError{cause: context.DeadlineExceeded}
	if portalErr.Error() == "" || !errors.Is(portalErr, context.DeadlineExceeded) {
		t.Fatalf("portal error = %v", portalErr)
	}
	for _, values := range []map[string]any{
		{"Host": ""},
		{"Host": "bad\nhost"},
		{"Host": "vpn.example", "Port": 70000},
		{"Host": "vpn.example", "ServerCertSha256Pin": "invalid"},
	} {
		settings := stormshieldTestSettings(t, values)
		if _, _, closeTransport, err := stormshieldPortalEndpoint(settings, "/path", ""); err == nil {
			closeTransport()
			t.Fatalf("invalid endpoint settings were accepted: %#v", values)
		}
	}
}

func TestStormshieldCacheRetainsBaseProfileForOverrideChanges(t *testing.T) {
	snapshot := tunnelConfigSnapshot{
		databasePath: filepath.Join(t.TempDir(), "wormhole.db"),
		id:           "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
	}
	base := "client\ndev tun\nproto udp\nremote sns.example.test 1194 udp\nremote sns.example.test 443 tcp\n"
	if err := writeStormshieldCachedProfile(snapshot, "identity", strings.Repeat("a", 64), base); err != nil {
		t.Fatal(err)
	}
	record := readStormshieldCachedProfile(snapshot, "identity")
	if record == nil {
		t.Fatal("fresh cache record was not readable")
	}
	tcpOnly, err := applyStormshieldTransportOverride(record.Profile, 1)
	if err != nil {
		t.Fatal(err)
	}
	automatic, err := applyStormshieldTransportOverride(record.Profile, 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(tcpOnly, "1194 udp") || !strings.Contains(tcpOnly, "443 tcp") {
		t.Fatalf("TCP override did not filter the cached base profile:\n%s", tcpOnly)
	}
	if !strings.Contains(automatic, "1194 udp") || !strings.Contains(automatic, "443 tcp") {
		t.Fatalf("returning to Automatic could not restore the cached base profile:\n%s", automatic)
	}
}

func TestExtractOpenVPNTransportRemotesHonorsDirectiveScopesAndQuotes(t *testing.T) {
	profile := "port 1194\nproto udp\nremote 'primary gateway.test'\n<ca>\nremote ignored.test 1 tcp\n</ca>\n<connection>\nport 443\nproto tcp-client\nremote fallback.test\n</connection>\nremote explicit.test 8443 tcp\n"
	remotes := extractOpenVPNTransportRemotes(profile)
	want := []openVPNTransportRemote{
		{Host: "primary gateway.test", Port: "1194", Protocol: "udp"},
		{Host: "fallback.test", Port: "443", Protocol: "tcp-client"},
		{Host: "explicit.test", Port: "8443", Protocol: "tcp"},
	}
	if len(remotes) != len(want) {
		t.Fatalf("remotes=%#v", remotes)
	}
	for index := range want {
		if remotes[index] != want[index] {
			t.Fatalf("remote[%d]=%#v, want %#v", index, remotes[index], want[index])
		}
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
		if request.URL.Path == "/auth/v1/sslvpn/hash" {
			_, _ = writer.Write([]byte(`"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"`))
			return
		}
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

func TestPrepareStormshieldOtpInvalidatesCacheWhenPortalHashChanges(t *testing.T) {
	bundle := testStormshieldBundle(t, map[string]string{
		"client.ovpn": "client\ndev tun\nauth-user-pass\nremote sns.example.test 443 tcp\n",
	})
	configHash := strings.Repeat("a", 64)
	downloads := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/auth/v1/sslvpn/hash" {
			_, _ = writer.Write([]byte(`"` + configHash + `"`))
			return
		}
		downloads++
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
	prompt := 0
	ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, _ tunnelPrompt) (string, error) {
		prompt++
		return strconv.Itoa(100000 + prompt), nil
	})
	if _, err := prepareStormshieldProfile(ctx, raw, snapshot); err == nil || !strings.Contains(err.Error(), "connect again") {
		t.Fatalf("first prepare = %v", err)
	}
	configHash = strings.Repeat("b", 64)
	if _, err := prepareStormshieldProfile(ctx, raw, snapshot); err == nil || !strings.Contains(err.Error(), "connect again") {
		t.Fatalf("changed-hash prepare = %v", err)
	}
	if downloads != 2 || prompt != 2 {
		t.Fatalf("downloads=%d prompts=%d, want 2/2", downloads, prompt)
	}
}

func TestPrepareStormshieldRejectsImmediatelyReusedSpentOtp(t *testing.T) {
	bundle := testStormshieldBundle(t, map[string]string{
		"client.ovpn": "client\ndev tun\nauth-user-pass\nremote sns.example.test 443 tcp\n",
	})
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/auth/v1/sslvpn/hash" {
			_, _ = writer.Write([]byte(`"` + strings.Repeat("c", 64) + `"`))
			return
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
		id:           "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
	}
	clearStormshieldOTPGuard(snapshot.id)
	t.Cleanup(func() { clearStormshieldOTPGuard(snapshot.id) })
	ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, _ tunnelPrompt) (string, error) {
		return "654321", nil
	})
	if _, err := prepareStormshieldProfile(ctx, raw, snapshot); err == nil || !strings.Contains(err.Error(), "connect again") {
		t.Fatalf("first prepare = %v", err)
	}
	if _, err := prepareStormshieldProfile(ctx, raw, snapshot); err == nil || !strings.Contains(err.Error(), "just used") {
		t.Fatalf("reused OTP prepare = %v", err)
	}
}

func TestPrepareStormshieldOffersCertificateConsentBeforeRetry(t *testing.T) {
	bundle := testStormshieldBundle(t, map[string]string{
		"client.ovpn": "client\ndev tun\nremote sns.example.test 443 tcp\n",
	})
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/zip")
		_, _ = writer.Write(bundle)
	}))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)
	raw, _ := json.Marshal(map[string]any{
		"Server": serverURL.Hostname(), "Port": mustTestPort(t, serverURL.Port()), "Mode": 0,
		"Username": "alice", "Password": "secret",
	})
	prompts := 0
	ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, prompt tunnelPrompt) (string, error) {
		prompts++
		if !prompt.Confirmation || prompt.AcceptLabel != "Trust and connect" || prompt.Secret || prompt.Browser {
			t.Fatalf("unexpected trust prompt: %#v", prompt)
		}
		return "accept", nil
	})
	prepared, err := prepareStormshieldProfile(ctx, raw)
	if err != nil {
		t.Fatalf("prepare after consent: %v", err)
	}
	var settings map[string]json.RawMessage
	if json.Unmarshal(prepared, &settings) != nil || !tunnelSettingBool(settings, "TrustServerCertificate") {
		t.Fatalf("prepared settings did not retain attempt trust: %s", prepared)
	}
	if prompts != 1 {
		t.Fatalf("prompts=%d, want 1", prompts)
	}
}

func TestPrepareStormshieldCachedProfileDoesNotPromptForHashEndpointCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/auth/v1/sslvpn/hash" {
			t.Fatalf("cached flow unexpectedly sent credentials to %s", request.URL.Path)
		}
		_, _ = writer.Write([]byte(`"` + strings.Repeat("d", 64) + `"`))
	}))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)
	raw, _ := json.Marshal(map[string]any{
		"Server": serverURL.Hostname(), "Port": mustTestPort(t, serverURL.Port()), "Mode": 0,
		"Username": "alice", "Password": "secret", "UseOtp": true,
	})
	var values map[string]json.RawMessage
	_ = json.Unmarshal(raw, &values)
	snapshot := tunnelConfigSnapshot{
		databasePath: filepath.Join(t.TempDir(), "wormhole.db"),
		id:           "dddddddd-eeee-4fff-8aaa-bbbbbbbbbbbb",
	}
	profile := "client\ndev tun\nauth-user-pass\nremote sns.example.test 443 tcp\n"
	if err := writeStormshieldCachedProfile(snapshot, providerCacheIdentity(4, values), strings.Repeat("a", 64), profile); err != nil {
		t.Fatal(err)
	}
	ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, prompt tunnelPrompt) (string, error) {
		if prompt.Confirmation {
			t.Fatal("the cache-only flow requested portal certificate consent")
		}
		return "123456", nil
	})
	prepared, err := prepareStormshieldProfile(ctx, raw, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var preparedSettings map[string]json.RawMessage
	_ = json.Unmarshal(prepared, &preparedSettings)
	if !tunnelSettingBool(preparedSettings, "_WormholeStormshieldOptimisticCache") {
		t.Fatalf("certificate-failed hash check was not marked optimistic: %s", prepared)
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
