package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
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

func TestFortinetSAMLCallbackListenerSkipsInvalidRequestsAndCancels(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan struct {
		id  string
		err error
	}, 1)
	go func() {
		id, err := waitForFortinetSAMLCallback(context.Background(), listener)
		result <- struct {
			id  string
			err error
		}{id, err}
	}()
	for _, request := range []string{
		"POST /callback?id=ignored HTTP/1.1\r\nHost: localhost\r\n\r\n",
		"GET /callback?id=accepted HTTP/1.1\r\nHost: localhost\r\n\r\n",
	} {
		connection, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(connection, request); err != nil {
			connection.Close()
			t.Fatal(err)
		}
		_, _ = io.ReadAll(connection)
		_ = connection.Close()
	}
	select {
	case actual := <-result:
		if actual.err != nil || actual.id != "accepted" {
			t.Fatalf("callback result = %#v", actual)
		}
	case <-time.After(time.Second):
		t.Fatal("callback listener did not accept the valid request")
	}

	cancelListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := waitForFortinetSAMLCallback(ctx, cancelListener); err == nil {
		t.Fatal("cancelled callback listener returned no error")
	}
}

func TestAuthenticateFortinetExternalSAMLCoordinatesBrowserAndCallback(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	original := openExternalURLForFortinet
	t.Cleanup(func() { openExternalURLForFortinet = original })
	opened := make(chan string, 1)
	openExternalURLForFortinet = func(_ context.Context, target string) error {
		opened <- target
		go func() {
			connection, dialErr := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if dialErr != nil {
				return
			}
			_, _ = io.WriteString(connection, "GET /callback?id=browser-token HTTP/1.1\r\nHost: localhost\r\n\r\n")
			_, _ = io.ReadAll(connection)
			_ = connection.Close()
		}()
		return nil
	}
	authID, err := authenticateFortinetExternalSAML(context.Background(), "vpn.example.test", 10443, port)
	if err != nil || authID != "browser-token" {
		t.Fatalf("external SAML = (%q, %v)", authID, err)
	}
	if target := <-opened; target != "https://vpn.example.test:10443/remote/saml/start?redirect=1" {
		t.Fatalf("browser target = %q", target)
	}

	openExternalURLForFortinet = func(context.Context, string) error { return context.Canceled }
	if _, err := authenticateFortinetExternalSAML(context.Background(), "vpn.example.test", 443, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("browser open error = %v", err)
	}
	if _, err := authenticateFortinetExternalSAML(context.Background(), "bad host", 443, 0); err == nil {
		t.Fatal("invalid gateway was accepted")
	}
	if err := openExternalURL(context.Background(), "http://vpn.example.test"); err == nil {
		t.Fatal("non-HTTPS browser target was accepted")
	}
}

func TestOpenExternalURLUsesThePlatformLauncherWithoutASecretChannel(t *testing.T) {
	original := newExternalURLCommand
	t.Cleanup(func() { newExternalURLCommand = original })
	var program string
	var arguments []string
	newExternalURLCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		program = name
		arguments = append([]string(nil), args...)
		return exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
	}
	target := "https://vpn.example.test/remote/saml/start?redirect=1"
	if err := openExternalURL(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	wantProgram := "xdg-open"
	wantArguments := []string{target}
	if runtime.GOOS == "windows" {
		wantProgram = "rundll32.exe"
		wantArguments = []string{"url.dll,FileProtocolHandler", target}
	} else if runtime.GOOS == "darwin" {
		wantProgram = "open"
	}
	if program != wantProgram || !slices.Equal(arguments, wantArguments) {
		t.Fatalf("platform launcher = %q %#v", program, arguments)
	}
	newExternalURLCommand = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, filepath.Join(t.TempDir(), "missing-browser-launcher.exe"))
	}
	if err := openExternalURL(context.Background(), target); err == nil {
		t.Fatal("missing browser launcher returned no error")
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
