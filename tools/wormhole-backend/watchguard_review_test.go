package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestWatchguardSidecarPreservesAuthenticationDomain(t *testing.T) {
	for _, tc := range []struct {
		name, username, domain, want string
		mode                         int
		legacySSO                    bool
	}{
		{name: "default", username: "alice", want: "alice", mode: 1},
		{name: "directory", username: "alice", domain: " ad.example ", want: `ad.example\alice`, mode: 1},
		{name: "local database", username: "alice", domain: "Firebox-DB", want: `Firebox-DB\alice`, mode: 1},
		{name: "already qualified", username: `radius\alice`, domain: "ad.example", want: `radius\alice`, mode: 1},
		{name: "SAML identity", username: `Entra\alice`, domain: "old.example", want: `Entra\alice`, mode: 2},
		{name: "legacy SAML", username: `Entra\alice`, domain: "old.example", want: `Entra\alice`, legacySSO: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{
				"ProfileOvpn": "client\nremote gateway.example 443\n", "Username": tc.username,
				"Password": "opaque password", "Domain": tc.domain, "AuthMode": tc.mode, "UseSingleSignOn": tc.legacySSO,
			})
			_, payload, err := tunnelSidecarCommand(3, raw)
			if err != nil {
				t.Fatal(err)
			}
			var config map[string]json.RawMessage
			if err := json.Unmarshal(payload, &config); err != nil {
				t.Fatal(err)
			}
			if tunnelSettingString(config, "username") != tc.want || tunnelSettingString(config, "password") != "opaque password" {
				t.Fatal("sidecar credentials did not preserve the selected authentication domain and password")
			}
		})
	}
}

func TestWatchguardSidecarRejectsNativeCredentialTruncation(t *testing.T) {
	for _, field := range []string{"Username", "Password", "ChallengeResponse", "Domain"} {
		t.Run(field, func(t *testing.T) {
			values := map[string]any{
				"ProfileOvpn": "client\nremote gateway.example 443\n", "AuthMode": 1,
				"Username": "alice", "Password": "secret", "Domain": "directory", "ChallengeResponse": "123456",
			}
			values[field] = "prefix\x00private-suffix"
			raw, _ := json.Marshal(values)
			_, payload, err := tunnelSidecarCommand(3, raw)
			if err == nil || payload != nil || strings.Contains(err.Error(), "private-suffix") {
				t.Fatal("NUL credential must be rejected without exposing its contents")
			}
		})
	}
}

func TestWatchguardDomainChangesInvalidateCachedProfiles(t *testing.T) {
	old := stormshieldTestSettings(t, map[string]any{"Server": "gateway.example", "Username": "alice", "Domain": "first.example", "AuthMode": 1})
	next := stormshieldTestSettings(t, map[string]any{"Server": "gateway.example", "Username": "alice", "Domain": "second.example", "AuthMode": 1})
	if providerCacheIdentity(3, old) == providerCacheIdentity(3, next) || !tunnelProviderCacheMustClear(3, 3, old, next) {
		t.Fatal("changing authentication domain retained the previous account's cache identity")
	}
	snapshot := tunnelConfigSnapshot{databasePath: filepath.Join(t.TempDir(), "wormhole.db"), id: "11111111-2222-3333-4444-555555555555"}
	if err := writeWatchguardCachedProfile(snapshot, providerCacheIdentity(3, old), "client\nremote gateway.example 443\n"); err != nil {
		t.Fatal(err)
	}
	if readWatchguardCachedProfile(snapshot, providerCacheIdentity(3, next)) != "" {
		t.Fatal("a cached profile crossed authentication domains")
	}
}

func TestPrepareWatchguardStoredProfilesAllowPasswordOnlyAccounts(t *testing.T) {
	profile := "client\nremote gateway.example 443\n"
	for _, source := range []string{"imported", "manual", "cache"} {
		t.Run(source, func(t *testing.T) {
			values := map[string]any{"Server": "gateway.example", "AuthMode": 1, "Username": "alice", "Password": "secret"}
			snapshot := tunnelConfigSnapshot{databasePath: filepath.Join(t.TempDir(), "wormhole.db"), id: "11111111-2222-3333-4444-555555555555"}
			switch source {
			case "imported":
				values["ProfileOvpn"] = profile
			case "manual":
				values["CaPem"], values["ClientCertPem"], values["ClientKeyPem"] = "CA", "CERT", "KEY"
			case "cache":
				if err := writeWatchguardCachedProfile(snapshot, providerCacheIdentity(3, stormshieldTestSettings(t, values)), profile); err != nil {
					t.Fatal(err)
				}
			}
			raw, _ := json.Marshal(values)
			prompts := 0
			ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, prompt tunnelPrompt) (string, error) {
				prompts++
				if !strings.Contains(prompt.Message, "type '-'") || !prompt.Secret {
					t.Error("prompt does not explain the password-only option")
				}
				return " - ", nil
			})
			prepared, err := prepareWatchguardProfile(ctx, raw, snapshot)
			if err != nil {
				t.Fatal(err)
			}
			_, payload, err := tunnelSidecarCommand(3, prepared)
			if err != nil {
				t.Fatal(err)
			}
			var config map[string]json.RawMessage
			_ = json.Unmarshal(payload, &config)
			if prompts != 1 || tunnelSettingString(config, "password") != "secret" || tunnelSettingString(config, "challenge_response") != "" {
				t.Fatal("password-only profile did not reach the sidecar without an OTP")
			}
			ctx = withTunnelPromptHandler(context.Background(), func(context.Context, tunnelPrompt) (string, error) { return "", context.Canceled })
			if prepared, err := prepareWatchguardProfile(ctx, raw, snapshot); !errors.Is(err, context.Canceled) || prepared != nil {
				t.Fatal("cancelling the prompt must not select password-only authentication")
			}
		})
	}
}

func TestPrepareWatchguardAuthenticationErrorsDoNotEchoGatewayText(t *testing.T) {
	for _, field := range []string{"message", "errStr"} {
		t.Run(field, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("action") != "sslvpn_logon" {
					t.Error("rejected authentication attempted to download a profile")
				}
				w.Header().Set("Content-Type", "application/xml")
				fmt.Fprintf(w, "<resp><logon_status>0</logon_status><%s>private-password private-token private-cookie</%s></resp>", field, field)
			}))
			defer server.Close()
			u, _ := url.Parse(server.URL)
			raw, _ := json.Marshal(map[string]any{"Server": u.Hostname(), "Port": mustTestPort(t, u.Port()), "AuthMode": 1, "Username": "alice", "Password": "private-password", "TrustServerCertificate": true})
			prepared, err := prepareWatchguardProfile(context.Background(), raw)
			if err == nil || prepared != nil || strings.Contains(err.Error(), "private-") || !strings.Contains(err.Error(), "status 0") {
				t.Fatal("authentication error must contain a safe status without gateway response text")
			}
		})
	}
}

func TestPrepareWatchguardGatewayChallengesRemainMandatory(t *testing.T) {
	for _, answer := range []string{"", "-"} {
		t.Run("answer="+answer, func(t *testing.T) {
			requests := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.Header().Set("Content-Type", "application/xml")
				if requests == 1 {
					_, _ = w.Write([]byte(`<resp><logon_status>8</logon_status><logon_id>mandatory</logon_id></resp>`))
					return
				}
				if r.URL.Query().Get("fw_logon_type") != "response" || r.URL.Query().Get("response") != "-" {
					t.Error("a mandatory gateway challenge was bypassed")
				}
				_, _ = w.Write([]byte(`<resp><logon_status>0</logon_status></resp>`))
			}))
			defer server.Close()
			u, _ := url.Parse(server.URL)
			raw, _ := json.Marshal(map[string]any{"Server": u.Hostname(), "Port": mustTestPort(t, u.Port()), "AuthMode": 1, "Username": "alice", "Password": "secret", "TrustServerCertificate": true})
			ctx := withTunnelPromptHandler(context.Background(), func(context.Context, tunnelPrompt) (string, error) { return answer, nil })
			prepared, err := prepareWatchguardProfile(ctx, raw)
			wantRequests := 1
			if answer != "" {
				wantRequests = 2
			}
			if err == nil || prepared != nil || requests != wantRequests {
				t.Fatalf("gateway challenge was not enforced: err=%v requests=%d", err, requests)
			}
		})
	}
}

func TestWatchguardHTTPRedirectPolicyBoundsRequests(t *testing.T) {
	client, err := newWatchguardHTTPClient(stormshieldTestSettings(t, map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	original, _ := http.NewRequest(http.MethodGet, "https://gateway.example/", nil)
	for _, tc := range []struct {
		name, target string
		hops         int
		wantError    bool
	}{
		{"same origin", "https://gateway.example/login", 1, false},
		{"last allowed", "https://gateway.example/login", 9, false},
		{"redirect loop", "https://gateway.example/login", 10, true},
		{"downgrade", "http://gateway.example/login", 1, true},
		{"other host", "https://other.example/login", 1, true},
		{"other port", "https://gateway.example:444/login", 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request, _ := http.NewRequest(http.MethodGet, tc.target, nil)
			via := make([]*http.Request, tc.hops)
			for i := range via {
				via[i] = original
			}
			if err := client.CheckRedirect(request, via); (err != nil) != tc.wantError {
				t.Fatalf("redirect decision = %v, want error %t", err, tc.wantError)
			}
		})
	}
}

func TestImportWatchguardBundleEntryLimitIncludesBoundary(t *testing.T) {
	for _, count := range []int{63, 64, 65} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			files := map[string]string{"client.ovpn": "client\nremote gateway.example 443\nca ca.crt\ncert client.crt\nkey client.pem\n", "ca.crt": "CA", "client.crt": "CERT", "client.pem": "KEY"}
			for i := len(files); i < count; i++ {
				files[fmt.Sprintf("extra-%d", i)] = "unused"
			}
			profile, err := importWatchguardBundle(testWatchguardBundle(t, files))
			if count <= 64 {
				if err != nil || !strings.Contains(profile, "<key>\nKEY\n</key>") {
					t.Fatalf("valid bounded bundle rejected: %v", err)
				}
			} else if err == nil || profile != "" {
				t.Fatal("oversized bundle accepted")
			}
		})
	}
}
