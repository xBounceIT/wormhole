package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
		"Server": serverURL.Hostname(), "Port": mustTestPort(t, serverURL.Port()), "AuthMode": 0,
		"UseSingleSignOn": false,
		"Username":        "alice", "Password": "secret", "TrustServerCertificate": true,
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

func TestPrepareWatchguardSAMLStartsProviderLoginAndDownloadsWithCookies(t *testing.T) {
	bundle := testWatchguardBundle(t, map[string]string{
		"client.ovpn": "client\nca ca.crt\ncert client.crt\nkey client.pem\nremote firebox.example.test 443 tcp\n",
		"ca.crt":      "CA", "client.crt": "CERT", "client.pem": "KEY",
	})
	metadataRequests, loginRequests, providerRequests, statusRequests := 0, 0, 0, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("fw_logon_type") == "status" {
			statusRequests++
			writer.Header().Set("Content-Type", "application/xml")
			_, _ = writer.Write([]byte(`<resp><saml_enabled>1</saml_enabled><saml_idp_name>Entra_ID_SAML</saml_idp_name></resp>`))
			return
		}
		switch request.URL.Path {
		case "/auth/saml":
			// The metadata endpoint can succeed without ever starting authentication.
			metadataRequests++
			writer.WriteHeader(http.StatusOK)
			return
		case "/auth/saml/login":
			loginRequests++
			if request.URL.Query().Get("from") != "sslvpn_client" {
				t.Error("SAML login did not request the VPN client flow")
			}
			http.Redirect(writer, request, "/test-idp/login", http.StatusFound)
			return
		case "/test-idp/login":
			providerRequests++
			_, _ = writer.Write([]byte("Provider sign-in"))
			return
		}
		if request.URL.Query().Get("action") != "sslvpn_download" {
			t.Errorf("unexpected SAML follow-up: %s", request.URL.String())
			http.NotFound(writer, request)
			return
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
		"Domain": "Firebox-DB", "Username": "stale-user", "Password": "stale-password", "ChallengeResponse": "stale-otp",
	})
	ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, prompt tunnelPrompt) (string, error) {
		if !prompt.Browser || len(prompt.URLs) == 0 || !prompt.IgnoreCertificateErrors {
			t.Fatalf("unexpected browser prompt: %#v", prompt)
		}
		response, err := server.Client().Get(prompt.URLs[0])
		if err != nil {
			t.Fatalf("open SAML login: %v", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK || response.Request.URL.Path != "/test-idp/login" {
			t.Fatal("SAML browser did not reach the provider sign-in page")
		}
		if len(prompt.URLs) != 2 {
			t.Fatalf("SAML login URLs = %v, want two login endpoints", prompt.URLs)
		}
		for index, path := range []string{"/auth/saml/login", "/saml/login"} {
			if prompt.URLs[index] != server.URL+path+"?from=sslvpn_client" {
				t.Fatalf("unexpected SAML login URL: %s", prompt.URLs[index])
			}
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
	if tunnelSettingString(settings, "Username") != `Entra_ID_SAML\saml-user` || tunnelSettingString(settings, "Password") != "ephemeral-token" {
		t.Fatal("SAML credentials were not qualified with the gateway's authentication domain")
	}
	_, payload, err := tunnelSidecarCommand(3, prepared)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(payload, &config); err != nil {
		t.Fatal(err)
	}
	if config["username"] != `Entra_ID_SAML\saml-user` || config["password"] != "ephemeral-token" || config["challenge_response"] != nil {
		t.Fatal("OpenVPN did not receive the domain-qualified SAML user and token without a stale OTP")
	}
	if metadataRequests != 0 || loginRequests != 1 || providerRequests != 1 || statusRequests != 1 {
		t.Fatalf("SAML requests: metadata=%d login=%d provider=%d status=%d, want 0/1/1/1", metadataRequests, loginRequests, providerRequests, statusRequests)
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
			_, _ = writer.Write([]byte(`<resp><saml_enabled>yes</saml_enabled><saml_idp_name>Microsoft Entra</saml_idp_name></resp>`))
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
	prepared, err := prepareWatchguardProfile(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]json.RawMessage
	_ = json.Unmarshal(prepared, &settings)
	if tunnelSettingString(settings, "Username") != `Microsoft Entra\saml-user` {
		t.Fatal("automatic SAML lost the advertised IdP name")
	}
	if statusRequests != 1 {
		t.Fatalf("status requests = %d, want 1", statusRequests)
	}
}

func TestPrepareWatchguardSAMLRejectsInvalidGatewayDomainBeforeSignIn(t *testing.T) {
	for _, test := range []struct {
		name, body, want string
		status           int
	}{
		{name: "disabled", body: `<resp><saml_enabled>0</saml_enabled></resp>`, want: "does not advertise SAML"},
		{name: "missing domain", body: `<resp><saml_enabled>1</saml_enabled></resp>`, want: "valid SAML authentication domain"},
		{name: "empty domain", body: `<resp><saml_enabled>1</saml_enabled><saml_idp_name> </saml_idp_name></resp>`, want: "valid SAML authentication domain"},
		{name: "domain separator", body: `<resp><saml_enabled>true</saml_enabled><saml_idp_name>Entra\other</saml_idp_name></resp>`, want: "valid SAML authentication domain"},
		{name: "control character", body: "<resp><saml_enabled>1</saml_enabled><saml_idp_name>Entra\nother</saml_idp_name></resp>", want: "valid SAML authentication domain"},
		{name: "oversized domain", body: `<resp><saml_enabled>1</saml_enabled><saml_idp_name>` + strings.Repeat("a", 1025) + `</saml_idp_name></resp>`, want: "valid SAML authentication domain"},
		{name: "unavailable", status: http.StatusServiceUnavailable, want: "HTTP 503"},
		{name: "malformed status", body: `<resp>`, want: "malformed XML"},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requests++
				query := request.URL.Query()
				if query.Get("action") != "sslvpn_logon" || query.Get("fw_logon_type") != "status" ||
					query.Get("style") != "fw_logon.xsl" || query.Has("fw_username") || query.Has("fw_password") {
					t.Error("SAML discovery must only request unauthenticated gateway status")
				}
				writer.Header().Set("Content-Type", "application/xml")
				if test.status != 0 {
					writer.WriteHeader(test.status)
				}
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()
			serverURL, _ := url.Parse(server.URL)
			raw, _ := json.Marshal(map[string]any{
				"Server": serverURL.Hostname(), "Port": mustTestPort(t, serverURL.Port()),
				"UseSingleSignOn": true, "TrustServerCertificate": true, "Domain": "Firebox-DB",
			})
			ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, _ tunnelPrompt) (string, error) {
				t.Error("invalid SAML domain must fail before opening the browser")
				return "", context.Canceled
			})
			prepared, err := prepareWatchguardProfile(ctx, raw)
			if prepared != nil || err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("prepare error = %v, want %q and no tunnel settings", err, test.want)
			}
			if requests != 1 {
				t.Fatalf("gateway requests = %d, want only one status request", requests)
			}
		})
	}
}

func TestPrepareWatchguardSAMLRejectsInvalidCallbacksAndPropagatesFailures(t *testing.T) {
	valid := watchguardSAMLResult{Username: "saml-user", Token: "secret-token"}
	for _, test := range []struct {
		name, want        string
		result            watchguardSAMLResult
		promptErr         error
		cancelProgress    bool
		downloadStatus    int
		wantDownloads     int
		malformedResponse bool
	}{
		{name: "malformed response", malformedResponse: true, want: "response is invalid"},
		{name: "missing user", result: watchguardSAMLResult{Token: valid.Token}, want: "response is invalid"},
		{name: "missing token", result: watchguardSAMLResult{Username: valid.Username}, want: "response is invalid"},
		{name: "NUL token", result: watchguardSAMLResult{Username: valid.Username, Token: "secret-token\x00suffix"}, want: "response is invalid"},
		{name: "qualified user exceeds limit", result: watchguardSAMLResult{Username: strings.Repeat("a", 1020), Token: valid.Token}, want: "response is invalid"},
		{name: "user control character", result: watchguardSAMLResult{Username: "saml-user\nother", Token: valid.Token}, want: "response is invalid"},
		{name: "oversized token", result: watchguardSAMLResult{Username: valid.Username, Token: strings.Repeat("t", 16*1024+1)}, want: "response is invalid"},
		{name: "too many cookies", result: watchguardSAMLResult{Username: valid.Username, Token: valid.Token, Cookies: make([]watchguardBrowserCookie, 257)}, want: "response is invalid"},
		{name: "invalid cookie", result: watchguardSAMLResult{Username: valid.Username, Token: valid.Token, Cookies: []watchguardBrowserCookie{{Name: "bad=cookie"}}}, want: "invalid cookie"},
		{name: "cancelled sign-in", promptErr: context.Canceled, want: "context canceled"},
		{name: "cancelled download", result: valid, cancelProgress: true, want: "context canceled"},
		{name: "rejected download", result: valid, downloadStatus: http.StatusForbidden, wantDownloads: 1, want: "HTTP 403"},
		{name: "invalid bundle", result: valid, wantDownloads: 1, want: "bundle"},
	} {
		t.Run(test.name, func(t *testing.T) {
			downloads := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				downloads++
				if test.downloadStatus != 0 {
					writer.WriteHeader(test.downloadStatus)
				}
				_, _ = writer.Write([]byte("invalid bundle"))
			}))
			defer server.Close()
			serverURL, _ := url.Parse(server.URL)
			raw, _ := json.Marshal(map[string]any{
				"Server": serverURL.Hostname(), "Port": mustTestPort(t, serverURL.Port()), "TrustServerCertificate": true,
			})
			var settings map[string]json.RawMessage
			_ = json.Unmarshal(raw, &settings)
			ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, _ tunnelPrompt) (string, error) {
				if test.malformedResponse {
					return "{", nil
				}
				encoded, _ := json.Marshal(test.result)
				return string(encoded), test.promptErr
			})
			ctx = withTunnelProgressHandler(ctx, func(_ context.Context, _, _ string) error {
				if test.cancelProgress {
					return context.Canceled
				}
				return nil
			})
			prepared, err := prepareWatchguardSAML(ctx, settings, &watchguardLogonResponse{SAMLEnabled: "1", SAMLIdPName: "Entra"})
			if prepared != nil || err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("prepare error = %v, want %q and no tunnel settings", err, test.want)
			}
			if strings.Contains(err.Error(), valid.Token) || strings.Contains(err.Error(), valid.Username) {
				t.Fatal("SAML error exposed callback credentials")
			}
			if (test.promptErr != nil || test.cancelProgress) && !errors.Is(err, context.Canceled) {
				t.Fatal("SAML cancellation was not propagated")
			}
			if downloads != test.wantDownloads {
				t.Fatalf("downloads = %d, want %d", downloads, test.wantDownloads)
			}
		})
	}
}

func TestPrepareWatchguardSAMLQualifiedUsernameByteBoundary(t *testing.T) {
	bundle := testWatchguardBundle(t, map[string]string{
		"client.ovpn": "client\nca ca.crt\ncert client.crt\nkey client.pem\nremote firebox.example.test 443 tcp\n",
		"ca.crt":      "CA", "client.crt": "CERT", "client.pem": "KEY",
	})
	for _, test := range []struct {
		name, username string
		legacy, reject bool
	}{
		{name: "ASCII at limit", username: strings.Repeat("a", 1018)},
		{name: "Unicode at limit", username: strings.Repeat("é", 509)},
		{name: "ASCII over limit", username: strings.Repeat("a", 1019), reject: true},
		{name: "Unicode over limit", username: strings.Repeat("é", 510), reject: true},
		{name: "legacy SSO flag", username: "mário@example.test", legacy: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			downloads := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Query().Get("fw_logon_type") == "status" {
					writer.Header().Set("Content-Type", "application/xml")
					_, _ = writer.Write([]byte(`<resp><saml_enabled>true</saml_enabled><saml_idp_name>Entra</saml_idp_name></resp>`))
					return
				}
				downloads++
				_, _ = writer.Write(bundle)
			}))
			defer server.Close()
			serverURL, _ := url.Parse(server.URL)
			authMode := 2
			if test.legacy {
				authMode = 0
			}
			raw, _ := json.Marshal(map[string]any{
				"Server": serverURL.Hostname(), "Port": mustTestPort(t, serverURL.Port()),
				"AuthMode": authMode, "UseSingleSignOn": test.legacy, "TrustServerCertificate": true,
			})
			const token = " token+/=&\"é "
			ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, _ tunnelPrompt) (string, error) {
				encoded, _ := json.Marshal(watchguardSAMLResult{Username: test.username, Token: token})
				return string(encoded), nil
			})
			prepared, err := prepareWatchguardProfile(ctx, raw)
			if test.reject {
				if prepared != nil || err == nil || err.Error() != "WatchGuard SAML response is invalid" || downloads != 0 {
					t.Fatalf("oversized qualified user: error=%v downloads=%d", err, downloads)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			_, payload, err := tunnelSidecarCommand(3, prepared)
			if err != nil {
				t.Fatal(err)
			}
			var config map[string]any
			if err := json.Unmarshal(payload, &config); err != nil {
				t.Fatal(err)
			}
			if downloads != 1 || config["username"] != `Entra\`+test.username || config["password"] != token {
				t.Fatal("SAML byte boundary or opaque token changed before reaching OpenVPN")
			}
		})
	}
}

func TestPrepareWatchguardSAMLHTTPFailuresPreserveCancellation(t *testing.T) {
	for _, test := range []struct {
		phase    string
		body     bool
		authMode int
	}{
		{phase: "status", authMode: 2}, {phase: "status", body: true, authMode: 2},
		{phase: "download", authMode: 2}, {phase: "download", body: true, authMode: 2},
		{phase: "status"}, {phase: "status", body: true},
		{phase: "download"}, {phase: "download", body: true},
	} {
		t.Run(fmt.Sprintf("%s/body=%t/mode=%d", test.phase, test.body, test.authMode), func(t *testing.T) {
			started := make(chan struct{})
			var prompts atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				status := request.URL.Query().Get("fw_logon_type") == "status"
				if status && test.phase == "download" {
					writer.Header().Set("Content-Type", "application/xml")
					_, _ = writer.Write([]byte(`<resp><saml_enabled>1</saml_enabled><saml_idp_name>Entra</saml_idp_name></resp>`))
					return
				}
				if test.body {
					writer.Header().Set("Content-Type", "application/xml")
					writer.WriteHeader(http.StatusOK)
					writer.(http.Flusher).Flush()
				}
				close(started)
				<-request.Context().Done()
			}))
			defer server.Close()
			serverURL, _ := url.Parse(server.URL)
			raw, _ := json.Marshal(map[string]any{
				"Server": serverURL.Hostname(), "Port": mustTestPort(t, serverURL.Port()),
				"AuthMode": test.authMode, "TrustServerCertificate": true,
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx = withTunnelPromptHandler(ctx, func(_ context.Context, _ tunnelPrompt) (string, error) {
				prompts.Add(1)
				return `{"username":"user","token":"private-token"}`, nil
			})
			finished := make(chan error, 1)
			go func() {
				prepared, err := prepareWatchguardProfile(ctx, raw)
				if prepared != nil {
					finished <- errors.New("cancelled SAML request returned tunnel settings")
					return
				}
				finished <- err
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("SAML HTTP request did not start")
			}
			cancel()
			select {
			case err := <-finished:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation error = %v, want context.Canceled", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("SAML HTTP cancellation did not finish")
			}
			wantPrompts := int32(0)
			if test.phase == "download" {
				wantPrompts = 1
			}
			if prompts.Load() != wantPrompts {
				t.Fatalf("browser prompts = %d, want %d", prompts.Load(), wantPrompts)
			}
		})
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
