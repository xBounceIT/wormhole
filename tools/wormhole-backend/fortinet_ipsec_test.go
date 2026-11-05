package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func ipsecTestSettings() map[string]any {
	return map[string]any{"Host": "vpn.example.test", "PreSharedKey": "fixture-psk", "Port": 500, "SamlPort": 1001}
}

func TestFortinetIPsecPersistenceAndProvider(t *testing.T) {
	raw, _ := json.Marshal(ipsecTestSettings())
	path := filepath.Join(t.TempDir(), "wormhole.db")
	created, err := createTunnel(path, tunnelWriteRequest{Name: "IPsec", Kind: 9, Settings: raw})
	if err != nil {
		t.Fatal(err)
	}
	if created.Kind != 9 || created.Endpoint != "vpn.example.test:500" {
		t.Fatal("invalid provider metadata")
	}
	details, err := readTunnel(path, tunnelReadRequest{ID: created.ID})
	if err != nil || bytes.Contains(details.Settings, []byte("fixture-psk")) || !bytes.Contains(details.Settings, []byte(`"HasPreSharedKey":true`)) {
		t.Fatal("editor exposed the stored gateway key", err)
	}
	list, err := loadTunnelSummaries(path)
	if err != nil || len(list) != 1 || list[0].Kind != "Fortinet IPsec" {
		t.Fatal("IPsec provider missing", err)
	}
	public, _ := json.Marshal(list)
	if bytes.Contains(public, []byte("fixture-psk")) {
		t.Fatal("public summary exposed PSK")
	}
	if got := tunnelEndpointSummary(9, json.RawMessage(`{"Host":"2001:db8::1"}`)); got != "[2001:db8::1]:500" {
		t.Fatal(got)
	}
	if _, _, err := tunnelSidecarCommand(9, raw); err == nil {
		t.Fatal("IPsec bypassed SAML")
	}
}

func TestFortinetIPsecValidation(t *testing.T) {
	for _, mutation := range []struct {
		key   string
		value any
	}{
		{"Host", ""}, {"Host", "https://vpn.test"}, {"Host", "bad host"}, {"Host", "a:b"}, {"Host", strings.Repeat("a", 254)},
		{"PreSharedKey", ""}, {"PreSharedKey", 42}, {"PreSharedKey", nil}, {"PreSharedKey", "secret\n"}, {"PreSharedKey", strings.Repeat("a", 4097)},
		{"Port", 0}, {"Port", 65536}, {"Port", "500"}, {"SamlPort", false}, {"SamlPort", -1},
		{"TrustServerCertificate", "true"}, {"LocalId", []string{"a"}}, {"RemoteId", "a\x00b"},
		{"SamlToken", strings.Repeat("a", 32)}, {"SamlUid", strings.Repeat("a", 32)}, {"UseSingleSignOn", true},
	} {
		t.Run(mutation.key+fmt.Sprint(mutation.value), func(t *testing.T) {
			settings := ipsecTestSettings()
			settings[mutation.key] = mutation.value
			raw, _ := json.Marshal(settings)
			request := tunnelWriteRequest{Name: "IPsec", Kind: 9, Settings: raw}
			if err := validateTunnelWriteRequest(&request, false); err == nil {
				t.Fatal("invalid settings accepted")
			}
		})
	}
	settings := ipsecTestSettings()
	delete(settings, "Port")
	delete(settings, "SamlPort")
	settings["TrustServerCertificate"] = false
	settings["LocalId"] = "vpn-client"
	settings["RemoteId"] = "vpn.test"
	raw, _ := json.Marshal(settings)
	request := tunnelWriteRequest{Name: "IPsec", Kind: 9, Settings: raw}
	if err := validateTunnelWriteRequest(&request, false); err != nil {
		t.Fatal(err)
	}
}

func TestFortinetIPsecSAMLAndNativePayload(t *testing.T) {
	var uid string
	var callbackPort int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/saml_login" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("invalid SAML initialization")
		}
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil || body["type"] != "rawData" {
			t.Error("invalid SAML body")
		}
		values, _ := url.ParseQuery(body["bytes"])
		uid = values.Get("UID")
		callbackPort, _ = strconv.Atoi(values.Get("REDIRECT_PORT"))
		fmt.Fprint(w, `window.location="/saml?request=fixture";`)
	}))
	defer server.Close()
	parsed, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(parsed.Port())
	settings := ipsecTestSettings()
	settings["Host"] = parsed.Hostname()
	settings["SamlPort"] = port
	settings["TrustServerCertificate"] = true
	raw, _ := json.Marshal(settings)
	token := strings.Repeat("a1", 16)
	ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, prompt tunnelPrompt) (string, error) {
		if prompt.Completion != "fortinet-ipsec" || !prompt.Browser || !prompt.IgnoreCertificateErrors || prompt.URLs[0] != server.URL+"/saml?request=fixture" || len(uid) != 32 {
			t.Fatal("incorrect native SAML prompt")
		}
		if prompt.RedirectPrefix != fmt.Sprintf("http://127.0.0.1:%d/", callbackPort) {
			t.Fatal("callback mismatch")
		}
		listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", callbackPort))
		if err == nil {
			listener.Close()
			t.Fatal("callback port was not reserved")
		}
		return token, nil
	})
	prepared, err := prepareTunnelAuthentication(ctx, 9, raw)
	if err != nil {
		t.Fatal(err)
	}
	expectedUID := uid
	executable, payload, err := tunnelSidecarCommand(9, prepared)
	if err != nil || executable != "wormhole-fortiipsecproxy" {
		t.Fatal("incorrect IPsec sidecar", err)
	}
	t.Setenv("WORMHOLE_FORTIIPSECPROXY_PATH", os.Args[0])
	t.Setenv("WORMHOLE_TUNNEL_TEST_HELPER", "ready")
	process, err := startTunnelProcess(ctx, tunnelConfigSnapshot{kind: 9, settings: raw})
	if err != nil {
		t.Fatal(err)
	}
	if process.socks != "127.0.0.1:32123" || !process.alive() {
		t.Fatal("IPsec bypassed supervised SOCKS lifecycle")
	}
	process.close()
	if process.alive() {
		t.Fatal("IPsec sidecar survived lease release")
	}
	var cfg map[string]any
	json.Unmarshal(payload, &cfg)
	if cfg["saml_uid"] != expectedUID || cfg["saml_token"] != token || cfg["pre_shared_key"] != "fixture-psk" || cfg["port"] != float64(500) {
		t.Fatal("native configuration is incomplete")
	}
	for _, forbidden := range []string{"svpn_cookie", "password", "saml_port", "trust_server_certificate"} {
		if _, present := cfg[forbidden]; present {
			t.Fatal("unrelated SSL setting in IPsec payload")
		}
	}
	for _, outcome := range []struct {
		value string
		err   error
	}{{"", nil}, {"invalid", nil}, {"", errors.New("cancelled")}} {
		ctx := withTunnelPromptHandler(context.Background(), func(context.Context, tunnelPrompt) (string, error) { return outcome.value, outcome.err })
		if _, err := prepareFortinetIPsecAuthentication(ctx, raw); err == nil {
			t.Fatal("invalid or cancelled login accepted")
		}
	}
	if _, err := prepareFortinetIPsecAuthentication(ctx, json.RawMessage(`[]`)); err == nil {
		t.Fatal("malformed settings accepted")
	}
}

func TestFortinetIPsecSAMLRedirectBoundaries(t *testing.T) {
	for _, body := range []string{`nothing`, `location="https://evil.test/saml?token=private"`, `location="http://vpn.test/saml"`, `location="/wrong"`, `location="/saml#fragment"`, `location="/saml?` + strings.Repeat("x", 4100) + `"`, strings.Repeat("x", 65537), `location="https://user@vpn.test/saml"`} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body) }))
		_, err := requestFortinetIPsecSAML(context.Background(), server.URL, "UID", 8000, true)
		server.Close()
		if err == nil || strings.Contains(err.Error(), "private") {
			t.Fatal("unsafe SAML redirect accepted or exposed")
		}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "https://evil.test", 302) }))
	defer server.Close()
	if _, err := requestFortinetIPsecSAML(context.Background(), server.URL, "UID", 8000, true); err == nil {
		t.Fatal("HTTP redirect followed")
	}
	if _, err := requestFortinetIPsecSAML(context.Background(), server.URL, "UID", 8000, false); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := requestFortinetIPsecSAML(ctx, server.URL, "UID", 8000, true); err == nil {
		t.Fatal("cancelled initialization accepted")
	}
}
