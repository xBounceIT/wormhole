package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func init() {
	mode := os.Getenv("WORMHOLE_TUNNEL_TEST_HELPER")
	if mode == "" {
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		os.Exit(3)
	}
	switch mode {
	case "ready":
		_, _ = fmt.Fprintln(os.Stdout, "READY 32123")
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	case "failure":
		_, _ = fmt.Fprintln(os.Stderr, "AUTH_FAILED fixture rejection")
		os.Exit(2)
	case "invalid":
		_, _ = fmt.Fprintln(os.Stdout, "NOT_READY")
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	case "silent":
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	default:
		os.Exit(4)
	}
}

func TestStartTunnelProcessSupervisesReadySidecar(t *testing.T) {
	t.Setenv("WORMHOLE_WGPROXY_PATH", os.Args[0])
	t.Setenv("WORMHOLE_TUNNEL_TEST_HELPER", "ready")
	var phases []string
	ctx := withTunnelProgressHandler(context.Background(), func(_ context.Context, phase, _ string) error {
		phases = append(phases, phase)
		return nil
	})
	process, err := startTunnelProcess(ctx, tunnelConfigSnapshot{
		kind: 0,
		settings: json.RawMessage(`{
			"InterfacePrivateKey":"private",
			"InterfaceAddress":"10.0.0.2/32",
			"PeerPublicKey":"public",
			"PeerEndpoint":"vpn.example:51820",
			"AllowedIps":["0.0.0.0/0"]
		}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if process.socks != "127.0.0.1:32123" || !process.alive() {
		t.Fatalf("ready sidecar = %#v", process)
	}
	if strings.Join(phases, ",") != "preparing,authenticating,starting" {
		t.Fatalf("progress phases = %#v", phases)
	}
	process.close()
	if process.alive() {
		t.Fatal("closed sidecar is still alive")
	}
}

func TestStartTunnelProcessClassifiesFailureAndInvalidReadiness(t *testing.T) {
	t.Setenv("WORMHOLE_WGPROXY_PATH", os.Args[0])
	settings := func() json.RawMessage {
		return json.RawMessage(`{"InterfacePrivateKey":"private","PeerPublicKey":"public"}`)
	}

	t.Setenv("WORMHOLE_TUNNEL_TEST_HELPER", "failure")
	if _, err := startTunnelProcess(context.Background(), tunnelConfigSnapshot{kind: 0, settings: settings()}); err == nil || !strings.Contains(strings.ToLower(err.Error()), "couldn't start") {
		t.Fatalf("classified startup failure = %v", err)
	}

	t.Setenv("WORMHOLE_TUNNEL_TEST_HELPER", "invalid")
	if _, err := startTunnelProcess(context.Background(), tunnelConfigSnapshot{kind: 0, settings: settings()}); err == nil {
		t.Fatalf("invalid readiness failure = %v", err)
	}
}

func TestStartTunnelProcessHonorsCancellationDuringStartup(t *testing.T) {
	t.Setenv("WORMHOLE_WGPROXY_PATH", os.Args[0])
	t.Setenv("WORMHOLE_TUNNEL_TEST_HELPER", "silent")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := startTunnelProcess(ctx, tunnelConfigSnapshot{
			kind:     0,
			settings: json.RawMessage(`{"InterfacePrivateKey":"private","PeerPublicKey":"public"}`),
		})
		done <- err
	}()
	time.Sleep(25 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled startup = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled sidecar startup did not return")
	}
}

func TestTunnelSidecarCommandCoversEveryPortableProvider(t *testing.T) {
	tests := []struct {
		kind       int64
		settings   string
		executable string
		wantError  bool
	}{
		{kind: 0, settings: `{"Dns":"1.1.1.1, 8.8.8.8","AllowedIps":"0.0.0.0/0;::/0"}`, executable: "wormhole-wgproxy"},
		{kind: 1, settings: `{"ProfileOvpn":"client\n","Username":"u","Password":"p"}`, executable: "wormhole-ovpnproxy"},
		{kind: 2, settings: `{"Host":"vpn.example","Port":443,"Username":"u","Password":"p"}`, executable: "wormhole-fortiproxy"},
		{kind: 2, settings: `{"Host":"vpn.example","UseSingleSignOn":true}`, wantError: true},
		{kind: 3, settings: `{"ProfileOvpn":"client\n","Username":"u","Password":"p","ChallengeResponse":"otp"}`, executable: "wormhole-ovpnproxy"},
		{kind: 3, settings: `{}`, wantError: true},
		{kind: 5, settings: `{"ProfileOvpn":"client\n","Password":"token"}`, executable: "wormhole-ovpnproxy"},
		{kind: 5, settings: `{}`, wantError: true},
		{kind: 6, settings: `{"Host":"vpn.example","Port":443,"Username":"u","Password":"p","Group":"staff"}`, executable: "wormhole-ciscoproxy"},
		{kind: 99, settings: `{}`, wantError: true},
	}
	for _, test := range tests {
		executable, payload, err := tunnelSidecarCommand(test.kind, json.RawMessage(test.settings))
		if test.wantError {
			if err == nil {
				t.Fatalf("kind %d unexpectedly returned %s %s", test.kind, executable, payload)
			}
			continue
		}
		if err != nil || executable != test.executable || !json.Valid(payload) {
			t.Fatalf("kind %d = executable:%q payload:%s err:%v", test.kind, executable, payload, err)
		}
	}
	if _, _, err := tunnelSidecarCommand(0, json.RawMessage(`{`)); err == nil {
		t.Fatal("malformed tunnel settings were accepted")
	}
}

func TestTunnelEndpointSummaryProjectsGenericProviderEndpoints(t *testing.T) {
	tests := []struct {
		name     string
		kind     int64
		settings string
		want     string
	}{
		{
			name: "WireGuard", kind: 0,
			settings: `{"PeerEndpoint":"wg.example.test:51820","InterfacePrivateKey":"must-not-leak"}`,
			want:     "wg.example.test:51820",
		},
		{
			name: "WireGuard IPv6", kind: 0,
			settings: `{"PeerEndpoint":"[2001:db8::20]:51820"}`,
			want:     "[2001:db8::20]:51820",
		},
		{
			name: "OpenVPN", kind: 1,
			settings: `{"ProfileOvpn":"client\n<ca>\nremote ignored.example 1\n</ca>\nremote ovpn.example.test\n","Password":"must-not-leak"}`,
			want:     "ovpn.example.test:1194",
		},
		{
			name: "Fortinet IPv6", kind: 2,
			settings: `{"Host":"2001:db8::10","Port":10443,"Password":"must-not-leak"}`,
			want:     "[2001:db8::10]:10443",
		},
		{
			name: "WatchGuard default port", kind: 3,
			settings: `{"Server":"firebox.example.test"}`,
			want:     "firebox.example.test:443",
		},
		{
			name: "Stormshield imported profile", kind: 4,
			settings: `{"Mode":1,"Server":"stale.example.test","ProfileOvpn":"remote sns.example.test 8443 tcp\n"}`,
			want:     "sns.example.test:8443",
		},
		{
			name: "Azure first gateway", kind: 5,
			settings: `{"Servers":"primary.vpn.azure.test, backup.vpn.azure.test","ServerSecretHex":"must-not-leak"}`,
			want:     "primary.vpn.azure.test:443",
		},
		{
			name: "Cisco default port", kind: 6,
			settings: `{"Host":"anyconnect.example.test","Password":"must-not-leak"}`,
			want:     "anyconnect.example.test:443",
		},
		{name: "WireGuard credential-shaped endpoint", kind: 0, settings: `{"PeerEndpoint":"secret@wg.example.test:51820"}`, want: ""},
		{name: "Host credential-shaped endpoint", kind: 2, settings: `{"Host":"secret@vpn.example.test","Port":443}`, want: ""},
		{name: "Profile credential-shaped endpoint", kind: 1, settings: `{"ProfileOvpn":"remote secret@vpn.example.test 443\n"}`, want: ""},
		{name: "Profile port out of range", kind: 1, settings: `{"ProfileOvpn":"remote vpn.example.test 70000\n"}`, want: ""},
		{name: "Profile non-numeric port", kind: 1, settings: `{"ProfileOvpn":"remote vpn.example.test https\n"}`, want: ""},
		{name: "Host control character", kind: 2, settings: `{"Host":"vpn.example.test\\nsecret","Port":443}`, want: ""},
		{name: "Endpoint too long", kind: 0, settings: `{"PeerEndpoint":"` + strings.Repeat("a", 513) + `:443"}`, want: ""},
		{name: "Malformed settings", kind: 1, settings: `{`, want: ""},
		{name: "Unknown provider", kind: 99, settings: `{}`, want: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := tunnelEndpointSummary(test.kind, json.RawMessage(test.settings)); got != test.want {
				t.Fatalf("endpoint = %q, want %q", got, test.want)
			}
		})
	}
}

func TestTunnelSummaryProjectionIncludesEndpointWithoutSecrets(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	created, err := createTunnel(databasePath, tunnelWriteRequest{
		Name: "safe summary",
		Kind: 0,
		Settings: json.RawMessage(`{
            "InterfacePrivateKey":"must-not-leak",
            "InterfaceAddress":"10.0.0.2/32",
            "PeerPublicKey":"public",
            "PeerEndpoint":"wg.example.test:51820"
        }`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Endpoint != "wg.example.test:51820" {
		t.Fatalf("created endpoint = %q", created.Endpoint)
	}

	read, err := readTunnel(databasePath, tunnelReadRequest{ID: created.ID})
	if err != nil {
		t.Fatal(err)
	}
	if read.Endpoint != created.Endpoint {
		t.Fatalf("read endpoint = %q, want %q", read.Endpoint, created.Endpoint)
	}

	workspace, err := loadWorkspace(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(workspace.Tunnels) != 1 || workspace.Tunnels[0].Endpoint != "" {
		t.Fatalf("workspace tunnels = %#v", workspace.Tunnels)
	}
	summaries, err := loadTunnelSummaries(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 1 || summaries[0].Endpoint != created.Endpoint {
		t.Fatalf("tunnel summaries = %#v", summaries)
	}
	encoded, err := json.Marshal(summaries)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("must-not-leak")) || bytes.Contains(encoded, []byte("InterfacePrivateKey")) {
		t.Fatalf("tunnel summary projection exposed settings: %s", encoded)
	}

	if err := os.Remove(legacyTunnelSecretPath(databasePath, created.ID)); err != nil {
		t.Fatal(err)
	}
	workspace, err = loadWorkspace(databasePath)
	if err != nil || len(workspace.Tunnels) != 1 {
		t.Fatalf("missing settings affected the workspace: %#v, %v", workspace.Tunnels, err)
	}
	summaries, err = loadTunnelSummaries(databasePath)
	if err != nil {
		t.Fatalf("missing settings made the tunnel list unusable: %v", err)
	}
	if len(summaries) != 1 || summaries[0].Endpoint != "" {
		t.Fatalf("summary with missing settings = %#v", summaries)
	}
}

func TestStormshieldSidecarBindsPhysicalTransportAndValidatesProfile(t *testing.T) {
	original := physicalTransportAdapterIDsForTunnel
	t.Cleanup(func() { physicalTransportAdapterIDsForTunnel = original })
	physicalTransportAdapterIDsForTunnel = func() ([]string, error) { return []string{"adapter-1"}, nil }
	program, payload, err := tunnelSidecarCommand(4, json.RawMessage(`{
        "ProfileOvpn":"client\nremote vpn.example.test 443 tcp\n","Username":"user","Password":"password"
    }`))
	if err != nil || program != "wormhole-ovpnproxy" {
		t.Fatalf("Stormshield sidecar = %q, %s, %v", program, payload, err)
	}
	var config map[string]any
	if err := json.Unmarshal(payload, &config); err != nil {
		t.Fatal(err)
	}
	if adapters, ok := config["transport_adapter_ids"].([]any); !ok || len(adapters) != 1 {
		t.Fatalf("physical adapters missing from payload: %#v", config)
	}
	if remotes, ok := config["transport_remotes"].([]any); !ok || len(remotes) != 1 {
		t.Fatalf("transport remotes missing from payload: %#v", config)
	}
	if _, _, err := tunnelSidecarCommand(4, json.RawMessage(`{"ProfileOvpn":"client\n"}`)); err == nil {
		t.Fatal("Stormshield profile without a transport remote was accepted")
	}
	if _, _, err := tunnelSidecarCommand(4, json.RawMessage(`{}`)); err == nil {
		t.Fatal("missing Stormshield profile was accepted")
	}
	physicalTransportAdapterIDsForTunnel = func() ([]string, error) { return nil, errors.New("enumeration failed") }
	if _, _, err := tunnelSidecarCommand(4, json.RawMessage(`{"ProfileOvpn":"client\nremote vpn.example 443\n"}`)); err == nil {
		t.Fatal("physical adapter enumeration error was ignored")
	}
}

func TestTunnelProcessProbeAndSidecarLookupCoverHealthBoundaries(t *testing.T) {
	if err := probeTunnelProcess(context.Background(), nil); err == nil {
		t.Fatal("nil tunnel process was healthy")
	}
	closed := make(chan struct{})
	close(closed)
	if err := probeTunnelProcess(context.Background(), &tunnelProcess{socks: "127.0.0.1:1", exited: closed}); err == nil {
		t.Fatal("exited tunnel process was healthy")
	}
	if err := probeTunnelProcess(context.Background(), &tunnelProcess{socks: "remote.example:1080", exited: make(chan struct{})}); err == nil {
		t.Fatal("non-loopback tunnel process was healthy")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	process := &tunnelProcess{socks: listener.Addr().String(), exited: make(chan struct{})}
	if err := probeTunnelProcess(context.Background(), process); err != nil {
		t.Fatalf("live tunnel process probe failed: %v", err)
	}

	override := filepath.Join(t.TempDir(), "custom-sidecar.exe")
	if err := os.WriteFile(override, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WORMHOLE_CUSTOMPROXY_PATH", override)
	if path, err := findTunnelSidecar("wormhole-customproxy"); err != nil || path != override {
		t.Fatalf("sidecar override = %q, %v", path, err)
	}
	t.Setenv("WORMHOLE_MISSINGPROXY_PATH", filepath.Join(t.TempDir(), "missing"))
	if _, err := findTunnelSidecar("wormhole-missingproxy"); err == nil {
		t.Fatal("missing sidecar override was accepted")
	}
}

func TestPrepareFortinetEmbeddedSamlAuthentication(t *testing.T) {
	ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, prompt tunnelPrompt) (string, error) {
		if !prompt.Browser || prompt.CookieName != "SVPNCOOKIE" || len(prompt.URLs) != 1 {
			t.Fatalf("unexpected Fortinet prompt: %#v", prompt)
		}
		return "cookie-value", nil
	})
	prepared, err := prepareTunnelAuthentication(ctx, 2, json.RawMessage(`{
		"Host":"vpn.example","Port":443,"UseSingleSignOn":true,"Realm":"staff",
		"TrustServerCertificate":true
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(prepared, []byte(`"SvpnCookie":"cookie-value"`)) {
		t.Fatalf("prepared settings = %s", prepared)
	}

	if _, err := prepareTunnelAuthentication(context.Background(), 2, json.RawMessage(`{
		"Host":"vpn.example","UseSingleSignOn":true,"UseExternalBrowser":true,"Realm":"staff"
	}`)); err == nil {
		t.Fatal("external SAML realm was accepted")
	}
	if _, err := prepareTunnelAuthentication(context.Background(), 2, json.RawMessage(`{`)); err == nil {
		t.Fatal("malformed Fortinet settings were accepted")
	}
}

func TestBoundedTunnelDiagnosticsAndNilRuntimeHelpers(t *testing.T) {
	builder := &boundedStderrBuilder{limit: 8}
	if !builder.append("abc") || !builder.append("defghijk") || builder.append("ignored") {
		t.Fatal("bounded stderr append state was incorrect")
	}
	if len(builder.text()) != 8 {
		t.Fatalf("bounded stderr = %q", builder.text())
	}
	var runtime *tunnelRuntime
	if runtime.socksEndpoint() != "" {
		t.Fatal("nil runtime exposed a SOCKS endpoint")
	}
	select {
	case <-runtime.exited():
	default:
		t.Fatal("nil runtime exit channel was not closed")
	}
	if _, err := runtime.dialContext(context.Background(), "tcp", "example:443"); err == nil {
		t.Fatal("nil runtime accepted a dial")
	}
	runtime.close()
}

func TestWritePrivateFileAtomicReplacesExistingContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tunnels", "secret.dpapi")
	if err := writePrivateFileAtomic(path, []byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFileAtomic(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "new" {
		t.Fatalf("contents = %q, want new", contents)
	}
}

func TestWritePrivateFileAtomicReportsReplacementBeforeDirectorySyncFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tunnels", "secret.dpapi")
	if err := writePrivateFileAtomic(path, []byte("old")); err != nil {
		t.Fatal(err)
	}

	previousDirectorySync := privateFileDirectorySync
	privateFileDirectorySync = func(string) error { return os.ErrPermission }
	t.Cleanup(func() { privateFileDirectorySync = previousDirectorySync })
	err := writePrivateFileAtomic(path, []byte("new"))
	if !privateFileDestinationWasReplaced(err) {
		t.Fatalf("directory sync error did not report its completed replacement: %v", err)
	}
	contents, readErr := os.ReadFile(path)
	if readErr != nil || string(contents) != "new" {
		t.Fatalf("replacement after directory sync failure = %q, %v", contents, readErr)
	}
}

func TestUpdateTunnelRestoresMetadataAndSecretAfterDirectorySyncFailure(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	original, err := createTunnel(databasePath, tunnelWriteRequest{
		Name: "original",
		Kind: 0,
		Settings: json.RawMessage(`{
            "InterfacePrivateKey":"private",
            "InterfaceAddress":"10.0.0.2/32",
            "PeerPublicKey":"public",
            "PeerEndpoint":"old.example.test:51820"
        }`),
	})
	if err != nil {
		t.Fatal(err)
	}

	previousDirectorySync := privateFileDirectorySync
	privateFileDirectorySync = func(string) error { return os.ErrPermission }
	t.Cleanup(func() { privateFileDirectorySync = previousDirectorySync })
	_, err = updateTunnel(databasePath, tunnelWriteRequest{
		ID:   original.ID,
		Name: "replacement",
		Kind: 0,
		Settings: json.RawMessage(`{
            "InterfacePrivateKey":"replacement-private",
            "InterfaceAddress":"10.0.0.3/32",
            "PeerPublicKey":"replacement-public",
            "PeerEndpoint":"new.example.test:51820"
        }`),
	})
	privateFileDirectorySync = previousDirectorySync
	if err == nil {
		t.Fatal("tunnel update succeeded despite the directory sync failure")
	}

	current, err := readTunnel(databasePath, tunnelReadRequest{ID: original.ID})
	if err != nil {
		t.Fatal(err)
	}
	if current.Name != original.Name || current.Kind != original.Kind ||
		!bytes.Equal(current.Settings, original.Settings) {
		t.Fatalf("tunnel after rollback = %#v, want %#v", current, original)
	}
}

func TestCreateTunnelRemovesReplacedSecretAfterDirectorySyncFailure(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	previousDirectorySync := privateFileDirectorySync
	privateFileDirectorySync = func(string) error { return os.ErrPermission }
	t.Cleanup(func() { privateFileDirectorySync = previousDirectorySync })
	_, err := createTunnel(databasePath, tunnelWriteRequest{
		Name: "not committed",
		Kind: 0,
		Settings: json.RawMessage(`{
            "InterfacePrivateKey":"private",
            "InterfaceAddress":"10.0.0.2/32",
            "PeerPublicKey":"public",
            "PeerEndpoint":"vpn.example.test:51820"
        }`),
	})
	privateFileDirectorySync = previousDirectorySync
	if err == nil {
		t.Fatal("tunnel creation succeeded despite the directory sync failure")
	}

	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var tunnels int
	if err := database.QueryRow("SELECT COUNT(*) FROM TunnelConfigs;").Scan(&tunnels); err != nil {
		t.Fatal(err)
	}
	if tunnels != 0 {
		t.Fatalf("tunnels committed after directory sync failure = %d", tunnels)
	}
	secretPaths, err := filepath.Glob(filepath.Join(filepath.Dir(databasePath), "tunnels", "*.dpapi"))
	if err != nil {
		t.Fatal(err)
	}
	if len(secretPaths) != 0 {
		t.Fatalf("orphaned tunnel secrets after rollback = %#v", secretPaths)
	}
}

func TestReadTunnelProtectedFileRejectsOversizedPayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.dpapi")
	if err := os.WriteFile(path, make([]byte, maxTunnelProtectedBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTunnelProtectedFile(path); err == nil {
		t.Fatal("oversized protected tunnel payload was accepted")
	}
}

func TestBridgeTunnelConnectionsStopsWhenRemoteCloses(t *testing.T) {
	client, forwardedClient := net.Pipe()
	forwardedRemote, remote := net.Pipe()
	done := make(chan struct{})
	go func() {
		bridgeTunnelConnections(forwardedClient, forwardedRemote)
		close(done)
	}()

	go func() {
		_, _ = remote.Write([]byte("response"))
		_ = remote.Close()
	}()
	response := make([]byte, len("response"))
	if _, err := client.Read(response); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bridge did not stop after the remote half closed")
	}
	_ = client.Close()
}

func TestDialSocks5CancellationInterruptsHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, dialErr := dialSocks5(ctx, listener.Addr().String(), "tcp", "example.test:22")
		result <- dialErr
	}()
	connection := <-accepted
	defer connection.Close()
	cancel()
	select {
	case dialErr := <-result:
		if dialErr == nil {
			t.Fatalf("dialSocks5() error = %v", dialErr)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled SOCKS5 handshake did not stop promptly")
	}
}

func TestTunnelSidecarFailureMessageClassifiesOpenVPNStub(t *testing.T) {
	t.Setenv("WORMHOLE_TUNNEL_DEBUG", "")
	err := tunnelSidecarFailureMessage("wormhole-ovpnproxy", "fatal: openvpn start: OpenVPN3 binding not linked in this build of wormhole-ovpnproxy.", 1)
	if err == nil || !strings.Contains(err.Error(), "missing the OpenVPN engine") {
		t.Fatalf("error = %v", err)
	}
}

func TestTunnelSidecarFailureMessageNeverEchoesRawStderr(t *testing.T) {
	t.Setenv("WORMHOLE_TUNNEL_DEBUG", "")
	err := tunnelSidecarFailureMessage("wormhole-ciscoproxy", "fatal: login failed password=super-secret", 1)
	if err == nil || !strings.Contains(err.Error(), "rejected the username") {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("sidecar stderr leaked into the UI error: %v", err)
	}
}

func TestWatchguardTypedOTPFailureGetsCooldownGuidance(t *testing.T) {
	settings := json.RawMessage(`{"_WormholeWatchguardTypedOTP":true}`)
	err := tunnelSidecarStartupFailure(
		tunnelConfigSnapshot{id: "watchguard", kind: 3}, settings, "wormhole-ovpnproxy",
		"TRANSPORT_ERROR CONNECTION_TIMEOUT", 1,
	)
	if !strings.Contains(err.Error(), "wait about 30 seconds") || !strings.Contains(err.Error(), "fresh code") {
		t.Fatalf("typed OTP failure guidance = %v", err)
	}
}

func TestElectronProviderCachesDoNotCollideWithWinUI(t *testing.T) {
	snapshot := tunnelConfigSnapshot{
		databasePath: filepath.Join(t.TempDir(), "wormhole.db"),
		id:           "11111111-2222-3333-8444-555555555555",
	}
	pairs := [][2]string{
		{stormshieldCachePath(snapshot), winUIStormshieldCachePath(snapshot)},
		{watchguardCachePath(snapshot), winUIWatchguardCachePath(snapshot)},
		{azureRefreshPath(snapshot), winUIAzureRefreshPath(snapshot)},
	}
	for _, pair := range pairs {
		if filepath.Clean(pair[0]) == filepath.Clean(pair[1]) {
			t.Fatalf("Electron and WinUI cache paths collide: %q", pair[0])
		}
	}
}

func TestStormshieldDataPlaneFailureRequiresANewOTP(t *testing.T) {
	settings := json.RawMessage(`{"Mode":0,"UseOtp":true}`)
	err := tunnelSidecarStartupFailure(
		tunnelConfigSnapshot{id: "stormshield", kind: 4}, settings, "wormhole-ovpnproxy",
		"AUTH_FAILED", 1,
	)
	if !strings.Contains(err.Error(), "new code") || !strings.Contains(err.Error(), "may have been used") {
		t.Fatalf("Stormshield OTP failure guidance = %v", err)
	}
}

func TestTunnelSidecarFailureMessageDebugOptInShowsBoundedDetail(t *testing.T) {
	t.Setenv("WORMHOLE_TUNNEL_DEBUG", "1")
	long := strings.Repeat("x", 2000)
	err := tunnelSidecarFailureMessage("wormhole-fortiproxy", "fatal: "+long, 1)
	if err == nil || !strings.Contains(err.Error(), "failed during startup") {
		t.Fatalf("error = %v", err)
	}
	if len(err.Error()) > 1200 {
		t.Fatalf("debug detail was not bounded: %d bytes", len(err.Error()))
	}
}

func TestTunnelSidecarStartupFailureInvalidatesOnlyActionableProviderCaches(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	snapshot := tunnelConfigSnapshot{
		databasePath: databasePath,
		id:           "11111111-2222-3333-4444-555555555555",
		kind:         3,
	}
	watchguardPath := watchguardCachePath(snapshot)
	if err := os.MkdirAll(filepath.Dir(watchguardPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(watchguardPath, []byte("cache"), 0o600); err != nil {
		t.Fatal(err)
	}
	settings := json.RawMessage(`{"_WormholeWatchguardCacheHit":true}`)
	_ = tunnelSidecarStartupFailure(snapshot, settings, "wormhole-ovpnproxy", "AUTH_FAILED", 1)
	if _, err := os.Stat(watchguardPath); err != nil {
		t.Fatalf("an OTP/auth failure must retain the WatchGuard cache: %v", err)
	}
	message := tunnelSidecarStartupFailure(snapshot, settings, "wormhole-ovpnproxy", "VERIFY ERROR certificate expired", 1)
	if _, err := os.Stat(watchguardPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale WatchGuard cache was retained: %v", err)
	}
	if !strings.Contains(message.Error(), "cleared") {
		t.Fatalf("cache reset was not explained: %v", message)
	}

	snapshot.kind = 4
	stormshieldPath := stormshieldCachePath(snapshot)
	if err := os.MkdirAll(filepath.Dir(stormshieldPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stormshieldPath, []byte("cache"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = tunnelSidecarStartupFailure(snapshot, json.RawMessage(`{"_WormholeStormshieldOptimisticCache":true}`), "wormhole-ovpnproxy", "transport failed", 1)
	if _, err := os.Stat(stormshieldPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("optimistic Stormshield cache was retained: %v", err)
	}

	snapshot.kind = 5
	azurePath := azureRefreshPath(snapshot)
	if err := os.MkdirAll(filepath.Dir(azurePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(azurePath, []byte("cache"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = tunnelSidecarStartupFailure(snapshot, nil, "wormhole-ovpnproxy", "AUTH_FAILED", 1)
	if _, err := os.Stat(azurePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected Azure refresh cache was retained: %v", err)
	}
}

func TestSocksForwarderPreservesOriginalRdpTargetAndBridgesTraffic(t *testing.T) {
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	targets := make(chan string, 1)
	go func() {
		connection, acceptErr := proxy.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		greeting := make([]byte, 3)
		if _, acceptErr = io.ReadFull(connection, greeting); acceptErr != nil {
			return
		}
		_, _ = connection.Write([]byte{5, 0})
		header := make([]byte, 5)
		if _, acceptErr = io.ReadFull(connection, header); acceptErr != nil || header[3] != 3 {
			return
		}
		host := make([]byte, int(header[4]))
		port := make([]byte, 2)
		if _, acceptErr = io.ReadFull(connection, host); acceptErr != nil {
			return
		}
		if _, acceptErr = io.ReadFull(connection, port); acceptErr != nil {
			return
		}
		targets <- net.JoinHostPort(string(host), strconv.Itoa(int(binary.BigEndian.Uint16(port))))
		_, _ = connection.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
		payload := make([]byte, 4)
		if _, acceptErr = io.ReadFull(connection, payload); acceptErr == nil {
			_, _ = connection.Write(payload)
		}
	}()

	forwarder, err := startSocksForwarder(proxy.Addr().String(), "rdp.internal.example:3389")
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.close()
	host, port := forwarder.address()
	client, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(client, response); err != nil || string(response) != "ping" {
		t.Fatalf("forwarded response = %q, %v", response, err)
	}
	select {
	case target := <-targets:
		if target != "rdp.internal.example:3389" {
			t.Fatalf("SOCKS target = %q", target)
		}
	case <-time.After(time.Second):
		t.Fatal("SOCKS target was not observed")
	}
}

func TestReadTunnelReadyRejectsOversizedLine(t *testing.T) {
	ready := make(chan string, 1)
	failures := make(chan error, 1)
	readTunnelReady(bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 2048)+"\n"), 1024), ready, failures)
	select {
	case <-failures:
	case port := <-ready:
		t.Fatalf("oversized readiness line was accepted as port %q", port)
	default:
		t.Fatal("readTunnelReady returned no result")
	}
}

func TestReadTunnelReadyMapsEarlyExitToFriendlyError(t *testing.T) {
	ready := make(chan string, 1)
	failures := make(chan error, 1)
	readTunnelReady(bufio.NewReader(strings.NewReader("")), ready, failures)
	select {
	case err := <-failures:
		if err == nil || err.Error() == "EOF" || !strings.Contains(err.Error(), "exited before reporting readiness") {
			t.Fatalf("error = %v", err)
		}
	case port := <-ready:
		t.Fatalf("early exit was accepted as ready port %q", port)
	default:
		t.Fatal("readTunnelReady returned no result")
	}
}

func TestPublicBackendErrorMapsRawEOF(t *testing.T) {
	if got := publicBackendError(io.EOF); got != "the VPN gateway closed the connection" {
		t.Fatalf("publicBackendError(io.EOF) = %q", got)
	}
	if got := publicBackendError(io.ErrUnexpectedEOF); got != "the VPN gateway closed the connection unexpectedly" {
		t.Fatalf("publicBackendError(io.ErrUnexpectedEOF) = %q", got)
	}
}

func TestFindTunnelSidecarUsesDocumentedOverrideName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wormhole-wgproxy")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WORMHOLE_WGPROXY_PATH", path)
	resolved, err := findTunnelSidecar("wormhole-wgproxy")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != path {
		t.Fatalf("findTunnelSidecar() = %q, want %q", resolved, path)
	}
}

func TestVncFailureClosesTunnelAndRemovesSession(t *testing.T) {
	session, manager, output := newTestVncSessionWithClosedTunnel("failed")

	session.fail(errors.New("handshake failed"))

	if !session.isStopped() {
		t.Fatal("failed VNC session was not stopped")
	}
	if manager.sessions[session.id] != nil {
		t.Fatal("failed VNC session remained registered")
	}
	if !strings.Contains(output.String(), `"status":"failed"`) {
		t.Fatalf("failure event was not emitted: %s", output.String())
	}
}

func TestVncRemoteDisconnectClosesTunnelAndRemovesSession(t *testing.T) {
	session, manager, output := newTestVncSessionWithClosedTunnel("disconnected")

	session.disconnected("remote closed")

	if !session.isStopped() || manager.sessions[session.id] != nil {
		t.Fatal("remotely disconnected VNC session retained native resources")
	}
	if !strings.Contains(output.String(), `"status":"disconnected"`) {
		t.Fatalf("disconnect event was not emitted: %s", output.String())
	}
}

func TestVncUserDisconnectAcknowledgesAfterTunnelReleaseAndSessionRemoval(t *testing.T) {
	session, manager, output := newTestVncSessionWithClosedTunnel("user-disconnect")
	pool := session.tunnel.pool

	manager.disconnect(backendCommand{ID: "disconnect-1", SessionID: session.id})

	if !session.isStopped() || manager.sessions[session.id] != nil {
		t.Fatal("user-disconnected VNC session retained native resources")
	}
	pool.mu.Lock()
	remaining := len(pool.entries)
	pool.mu.Unlock()
	if remaining != 0 {
		t.Fatal("VNC disconnect acknowledged before releasing its tunnel lease")
	}
	if !strings.Contains(output.String(), `"id":"disconnect-1","ok":true`) {
		t.Fatalf("VNC disconnect was not acknowledged: %s", output.String())
	}
}

func newTestVncSessionWithClosedTunnel(id string) (*vncSession, *vncManager, *bytes.Buffer) {
	output := &bytes.Buffer{}
	lineWriter := &backendLineWriter{writer: bufio.NewWriter(output)}
	manager := newVncManager(nil, lineWriter)
	session := newVncSession(id, manager.output, manager)
	exited := make(chan struct{})
	close(exited)
	pool := newTunnelRuntimePool(func(context.Context, tunnelConfigSnapshot) (*tunnelProcess, error) {
		return nil, errors.New("unexpected start")
	})
	entry := &sharedTunnelEntry{key: id, refs: 1, process: &tunnelProcess{exited: exited}}
	pool.entries[entry.key] = entry
	session.tunnel = &tunnelRuntime{entry: entry, pool: pool}
	manager.sessions[session.id] = session
	return session, manager, output
}

type closeWriterFunc func() error

func (close closeWriterFunc) Write(payload []byte) (int, error) { return len(payload), nil }
func (close closeWriterFunc) Close() error                      { return close() }

func newTestTunnelProcess() *tunnelProcess {
	exited := make(chan struct{})
	return &tunnelProcess{
		socks:  "127.0.0.1:1080",
		exited: exited,
		stdin: closeWriterFunc(func() error {
			close(exited)
			return nil
		}),
	}
}

func TestTunnelRuntimePoolCoalescesAndReferenceCounts(t *testing.T) {
	start := make(chan struct{})
	started := make(chan struct{}, 2)
	var starts int
	var startsMu sync.Mutex
	pool := newTunnelRuntimePool(func(context.Context, tunnelConfigSnapshot) (*tunnelProcess, error) {
		startsMu.Lock()
		starts++
		startsMu.Unlock()
		started <- struct{}{}
		<-start
		return newTestTunnelProcess(), nil
	})
	snapshot := tunnelConfigSnapshot{id: "id", updatedAt: "one"}
	results := make(chan *tunnelRuntime, 2)
	errors := make(chan error, 2)
	for range 2 {
		go func() {
			lease, err := pool.acquire(context.Background(), "database\x00id", snapshot)
			results <- lease
			errors <- err
		}()
	}
	<-started
	close(start)
	first, second := <-results, <-results
	if err := <-errors; err != nil {
		t.Fatal(err)
	}
	if err := <-errors; err != nil {
		t.Fatal(err)
	}
	if first.entry.process != second.entry.process {
		t.Fatal("concurrent leases did not share one sidecar")
	}
	startsMu.Lock()
	startCount := starts
	startsMu.Unlock()
	if startCount != 1 {
		t.Fatalf("sidecar starts = %d, want 1", startCount)
	}
	process := first.entry.process
	first.close()
	if !process.alive() {
		t.Fatal("first release closed a sidecar that still had a lease")
	}
	second.close()
	if process.alive() {
		t.Fatal("last release did not close the shared sidecar")
	}
}

func TestTunnelRuntimePoolReplaysCurrentProgressToLateJoiner(t *testing.T) {
	continueStart := make(chan struct{})
	reported := make(chan struct{})
	pool := newTunnelRuntimePool(func(ctx context.Context, _ tunnelConfigSnapshot) (*tunnelProcess, error) {
		if err := reportTunnelProgress(ctx, "authenticating", "waiting for approval"); err != nil {
			return nil, err
		}
		close(reported)
		<-continueStart
		return newTestTunnelProcess(), nil
	})
	firstProgress := make(chan string, 2)
	secondProgress := make(chan string, 2)
	firstResult := make(chan *tunnelRuntime, 1)
	secondResult := make(chan *tunnelRuntime, 1)
	snapshot := tunnelConfigSnapshot{id: "id", updatedAt: "one", progress: func(_ context.Context, phase, detail string) error {
		firstProgress <- phase + ":" + detail
		return nil
	}}
	go func() {
		lease, _ := pool.acquire(context.Background(), "database\x00id", snapshot)
		firstResult <- lease
	}()
	<-reported
	late := snapshot
	late.progress = func(_ context.Context, phase, detail string) error {
		secondProgress <- phase + ":" + detail
		return nil
	}
	go func() {
		lease, _ := pool.acquire(context.Background(), "database\x00id", late)
		secondResult <- lease
	}()
	select {
	case value := <-secondProgress:
		if value != "authenticating:waiting for approval" {
			t.Fatalf("late progress = %q", value)
		}
	case <-time.After(time.Second):
		t.Fatal("late joiner did not receive the current shared-establishment phase")
	}
	close(continueStart)
	first, second := <-firstResult, <-secondResult
	first.close()
	second.close()
}

func TestTunnelRuntimePoolRefreshesEditedConfig(t *testing.T) {
	var starts int
	pool := newTunnelRuntimePool(func(context.Context, tunnelConfigSnapshot) (*tunnelProcess, error) {
		starts++
		return newTestTunnelProcess(), nil
	})
	first, err := pool.acquire(context.Background(), "database\x00id", tunnelConfigSnapshot{
		id: "id", updatedAt: "one",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := pool.acquire(context.Background(), "database\x00id", tunnelConfigSnapshot{
		id: "id", updatedAt: "two",
	})
	if err != nil {
		t.Fatal(err)
	}
	if starts != 2 || first.entry.process == second.entry.process {
		t.Fatalf("edited config reused stale sidecar (starts=%d)", starts)
	}
	oldProcess := first.entry.process
	newProcess := second.entry.process
	second.close()
	if newProcess.alive() {
		t.Fatal("new config sidecar stayed alive after its final release")
	}
	if !oldProcess.alive() {
		t.Fatal("refresh closed the stale sidecar while an existing session still leased it")
	}
	first.close()
	if oldProcess.alive() {
		t.Fatal("stale sidecar stayed alive after its final release")
	}
}

func TestTunnelRuntimePoolEvictsAProcessWithDeadSocksListener(t *testing.T) {
	oldProcess := newTestTunnelProcess()
	pool := newTunnelRuntimePool(func(context.Context, tunnelConfigSnapshot) (*tunnelProcess, error) {
		return newTestTunnelProcess(), nil
	})
	pool.probe = func(context.Context, *tunnelProcess) error {
		return errors.New("listener is closed")
	}
	entry := &sharedTunnelEntry{
		key: "database\x00id", updatedAt: "one", refs: 1, process: oldProcess,
		ready: make(chan struct{}), settled: make(chan struct{}),
	}
	close(entry.ready)
	close(entry.settled)
	pool.entries[entry.key] = entry
	oldLease := &tunnelRuntime{entry: entry, pool: pool}

	replacement, err := pool.acquire(context.Background(), entry.key, tunnelConfigSnapshot{id: "id", updatedAt: "one"})
	if err != nil {
		t.Fatal(err)
	}
	if replacement.entry == entry || replacement.entry.process == oldProcess {
		t.Fatal("dead SOCKS listener reused the stale pooled process")
	}
	if !oldProcess.alive() {
		t.Fatal("eviction interrupted an existing lease on the stale process")
	}
	replacement.close()
	oldLease.close()
}

func TestLoadTunnelSnapshotDefersSecretReadUntilNewSidecarStarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE TunnelConfigs (
    Id TEXT PRIMARY KEY, Name TEXT, Kind INTEGER, CreatedAt TEXT, UpdatedAt TEXT
);
INSERT INTO TunnelConfigs (Id, Name, Kind, CreatedAt, UpdatedAt) VALUES
    ('b2a0a6b0-69c8-4f3e-a4cb-f3395aa0a9f7', 'metadata only', 0, 'one', 'two');`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	snapshot, err := loadTunnelSnapshot(path, "b2a0a6b0-69c8-4f3e-a4cb-f3395aa0a9f7")
	if err != nil {
		t.Fatalf("metadata load unexpectedly required a DPAPI payload: %v", err)
	}
	if snapshot.settings != nil || snapshot.updatedAt != "two" {
		t.Fatalf("snapshot = %#v, want metadata without settings", snapshot)
	}
}

func TestValidateTunnelWriteRequestNormalizesProviderSettings(t *testing.T) {
	request := tunnelWriteRequest{
		ID:   "B2A0A6B0-69C8-4F3E-A4CB-F3395AA0A9F7",
		Name: "  corporate VPN  ",
		Kind: 0,
		Settings: json.RawMessage(`{
            "InterfacePrivateKey":"private",
            "InterfaceAddress":"10.0.0.2/32",
            "PeerPublicKey":"public",
            "PeerEndpoint":"vpn.example.test:51820"
        }`),
	}
	if err := validateTunnelWriteRequest(&request, true); err != nil {
		t.Fatalf("validateTunnelWriteRequest() error = %v", err)
	}
	if request.ID != strings.ToLower(request.ID) || request.Name != "corporate VPN" {
		t.Fatalf("request was not normalized: %#v", request)
	}
	if !json.Valid(request.Settings) {
		t.Fatalf("settings are not canonical JSON: %s", request.Settings)
	}
}

func TestValidateTunnelWriteRequestRejectsIncompleteWireGuard(t *testing.T) {
	request := tunnelWriteRequest{
		Name:     "incomplete",
		Kind:     0,
		Settings: json.RawMessage(`{"InterfacePrivateKey":"private"}`),
	}
	if err := validateTunnelWriteRequest(&request, false); err == nil || !strings.Contains(err.Error(), "InterfaceAddress") {
		t.Fatalf("validateTunnelWriteRequest() error = %v, want missing InterfaceAddress", err)
	}
}

func TestValidateTunnelWriteRequestRejectsInvalidExplicitPort(t *testing.T) {
	request := tunnelWriteRequest{
		Name: "invalid port",
		Kind: 2,
		Settings: json.RawMessage(`{
            "Host":"vpn.example.test",
            "Port":70000,
            "Username":"user",
            "Password":"password"
        }`),
	}
	if err := validateTunnelWriteRequest(&request, false); err == nil || !strings.Contains(err.Error(), "Port") {
		t.Fatalf("validateTunnelWriteRequest() error = %v, want invalid Port", err)
	}
}

func TestValidateTunnelWriteRequestMatchesProviderRequirements(t *testing.T) {
	tests := []struct {
		name     string
		kind     int64
		settings string
		missing  string
	}{
		{
			name: "WatchGuard username mode", kind: 3,
			settings: `{"Server":"firebox.example.test","AuthMode":1}`,
			missing:  "Username",
		},
		{
			name: "WatchGuard legacy automatic mode", kind: 3,
			settings: `{"Server":"firebox.example.test","AuthMode":0,"UseSingleSignOn":false}`,
			missing:  "Username",
		},
		{
			name: "Stormshield automatic credentials", kind: 4,
			settings: `{"Server":"sns.example.test","Mode":0}`,
			missing:  "Username",
		},
		{
			name: "Stormshield obsolete SSO", kind: 4,
			settings: `{"Server":"sns.example.test","Mode":0,"UseSingleSignOn":true}`,
			missing:  "Username",
		},
		{
			name: "Azure gateway list", kind: 5,
			settings: `{"TenantId":"tenant","Audience":"audience","Servers":[]}`,
			missing:  "Servers",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := tunnelWriteRequest{Name: test.name, Kind: test.kind, Settings: json.RawMessage(test.settings)}
			if err := validateTunnelWriteRequest(&request, false); err == nil || !strings.Contains(err.Error(), test.missing) {
				t.Fatalf("validateTunnelWriteRequest() error = %v, want %s requirement", err, test.missing)
			}
		})
	}
}

func TestValidateTunnelWriteRequestRejectsFortinetEmbeddedSSOPin(t *testing.T) {
	request := tunnelWriteRequest{
		Name: "fortinet pin",
		Kind: 2,
		Settings: json.RawMessage(`{
            "Host":"vpn.example.test",
            "UseSingleSignOn":true,
            "UseExternalBrowser":false,
            "ServerCertSha256Pin":"abcd"
        }`),
	}
	err := validateTunnelWriteRequest(&request, false)
	if err == nil || !strings.Contains(err.Error(), "server certificate pin") {
		t.Fatalf("validateTunnelWriteRequest() error = %v, want embedded SSO pin rejection", err)
	}
}

func TestValidateTunnelWriteRequestCanonicalizesWatchGuardSSO(t *testing.T) {
	request := tunnelWriteRequest{
		Name: "watchguard sso",
		Kind: 3,
		Settings: json.RawMessage(`{
            "Server":"firebox.example.test",
            "AuthMode":1,
            "UseSingleSignOn":true,
            "Username":"must-go",
            "Password":"must-go"
        }`),
	}
	if err := validateTunnelWriteRequest(&request, false); err != nil {
		t.Fatalf("WatchGuard SSO settings were rejected: %v", err)
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(request.Settings, &settings); err != nil {
		t.Fatal(err)
	}
	if tunnelSettingNumber(settings, "AuthMode") != 2 {
		t.Fatalf("WatchGuard SSO mode was not canonicalized: %s", request.Settings)
	}
	if _, found := settings["UseSingleSignOn"]; found {
		t.Fatalf("WatchGuard SSO retained its legacy checkbox state: %s", request.Settings)
	}
	if _, found := settings["Username"]; found {
		t.Fatalf("WatchGuard SSO retained the username: %s", request.Settings)
	}
	if _, found := settings["Password"]; found {
		t.Fatalf("WatchGuard SSO retained the password: %s", request.Settings)
	}
}

func TestValidateTunnelWriteRequestCanonicalizesLegacyWatchGuardPasswordMode(t *testing.T) {
	request := tunnelWriteRequest{
		Name: "watchguard password",
		Kind: 3,
		Settings: json.RawMessage(`{
            "Server":"firebox.example.test",
            "AuthMode":0,
            "UseSingleSignOn":false,
            "Username":"alice",
            "Password":"secret"
        }`),
	}
	if err := validateTunnelWriteRequest(&request, false); err != nil {
		t.Fatalf("legacy WatchGuard password settings were rejected: %v", err)
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(request.Settings, &settings); err != nil {
		t.Fatal(err)
	}
	if tunnelSettingNumber(settings, "AuthMode") != 1 {
		t.Fatalf("WatchGuard password mode was not canonicalized: %s", request.Settings)
	}
	if _, found := settings["UseSingleSignOn"]; found {
		t.Fatalf("WatchGuard password mode retained its legacy checkbox state: %s", request.Settings)
	}
	if tunnelSettingString(settings, "Username") != "alice" || tunnelSettingString(settings, "Password") != "secret" {
		t.Fatalf("WatchGuard password mode lost its credentials: %s", request.Settings)
	}
}

func TestValidateTunnelWriteRequestRemovesObsoleteStormshieldSSO(t *testing.T) {
	request := tunnelWriteRequest{
		Name: "stormshield credentials",
		Kind: 4,
		Settings: json.RawMessage(`{
            "Server":"sns.example.test",
            "Mode":0,
            "UseSingleSignOn":true,
            "Username":"alice",
            "Password":"secret"
        }`),
	}
	if err := validateTunnelWriteRequest(&request, false); err != nil {
		t.Fatalf("Stormshield credentials were rejected: %v", err)
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(request.Settings, &settings); err != nil {
		t.Fatal(err)
	}
	if _, found := settings["UseSingleSignOn"]; found {
		t.Fatalf("Stormshield retained obsolete SSO state: %s", request.Settings)
	}
}

func TestValidateTunnelWriteRequestRejectsMalformedAzureServerSecret(t *testing.T) {
	for _, secret := range []string{"abcd", strings.Repeat("0", 511), strings.Repeat("z", 512)} {
		request := tunnelWriteRequest{
			Name: "azure secret",
			Kind: 5,
			Settings: json.RawMessage(`{
                "TenantId":"tenant","Audience":"audience",
                "Servers":["gateway.vpn.azure.com"],"ServerSecretHex":"` + secret + `"
            }`),
		}
		if err := validateTunnelWriteRequest(&request, false); err == nil || !strings.Contains(err.Error(), "ServerSecretHex") {
			t.Fatalf("validateTunnelWriteRequest() error = %v, want invalid ServerSecretHex", err)
		}
	}
	request := tunnelWriteRequest{
		Name: "azure secret",
		Kind: 5,
		Settings: json.RawMessage(`{
            "TenantId":"tenant","Audience":"audience",
            "Servers":["gateway.vpn.azure.com"],"ServerSecretHex":"` + strings.Repeat("a", 512) + `"
        }`),
	}
	if err := validateTunnelWriteRequest(&request, false); err != nil {
		t.Fatalf("valid 512-hex ServerSecretHex was rejected: %v", err)
	}
}

func TestValidateTunnelWriteRequestRejectsOpenVPNDirectiveInjection(t *testing.T) {
	tests := []struct {
		name     string
		kind     int64
		settings string
	}{
		{
			name: "WatchGuard certificate subject", kind: 3,
			settings: `{"Server":"firebox.example.test","AuthMode":0,"VerifyX509Name":"safe'\nup evil"}`,
		},
		{
			name: "WatchGuard inline PEM", kind: 3,
			settings: `{"Server":"firebox.example.test","AuthMode":0,"CaPem":"base64</ca>up evil"}`,
		},
		{
			name: "Azure gateway", kind: 5,
			settings: `{"TenantId":"tenant","Audience":"audience","Servers":["gateway.test up evil"]}`,
		},
		{
			name: "Azure inline CA", kind: 5,
			settings: `{"TenantId":"tenant","Audience":"audience","Servers":["gateway.test"],"CaPem":"base64</ca>up evil"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := tunnelWriteRequest{Name: test.name, Kind: test.kind, Settings: json.RawMessage(test.settings)}
			if err := validateTunnelWriteRequest(&request, false); err == nil {
				t.Fatal("directive-bearing input was accepted")
			}
		})
	}
}

func TestProviderCacheIdentityIgnoresRotatedPasswordsButTracksSiteTrust(t *testing.T) {
	base := stormshieldTestSettings(t, map[string]any{
		"Server": "vpn.example.test", "Port": 443, "Username": "alice", "Password": "old",
	})
	rotated := stormshieldTestSettings(t, map[string]any{
		"Server": "vpn.example.test", "Port": 443, "Username": "alice", "Password": "new",
	})
	trusted := stormshieldTestSettings(t, map[string]any{
		"Server": "vpn.example.test", "Port": 443, "Username": "alice", "Password": "new",
		"TrustServerCertificate": true,
	})
	for _, kind := range []int64{3, 4} {
		if providerCacheIdentity(kind, base) != providerCacheIdentity(kind, rotated) {
			t.Fatalf("kind %d cache identity changed with password rotation", kind)
		}
		if providerCacheIdentity(kind, rotated) == providerCacheIdentity(kind, trusted) {
			t.Fatalf("kind %d cache identity ignored trust change", kind)
		}
	}
}

func TestValidateTunnelWriteRequestRejectsMalformedProviderTypes(t *testing.T) {
	tests := []struct {
		name     string
		kind     int64
		settings string
		field    string
	}{
		{
			name: "Fortinet boolean", kind: 2, field: "UseSingleSignOn",
			settings: `{"Host":"vpn.example.test","Username":"user","Password":"password","UseSingleSignOn":"false"}`,
		},
		{
			name: "WatchGuard boolean", kind: 3, field: "UseSingleSignOn",
			settings: `{"Server":"firebox.example.test","AuthMode":0,"UseSingleSignOn":"false"}`,
		},
		{
			name: "Stormshield enum", kind: 4, field: "Mode",
			settings: `{"Server":"sns.example.test","Username":"user","Password":"password","Mode":3}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := tunnelWriteRequest{Name: test.name, Kind: test.kind, Settings: json.RawMessage(test.settings)}
			if err := validateTunnelWriteRequest(&request, false); err == nil || !strings.Contains(err.Error(), test.field) {
				t.Fatalf("validateTunnelWriteRequest() error = %v, want invalid %s", err, test.field)
			}
		})
	}
}

func TestTunnelSidecarCommandPreservesWireGuardRouteSettings(t *testing.T) {
	program, payload, err := tunnelSidecarCommand(0, json.RawMessage(`{
        "InterfacePrivateKey":"private",
        "InterfaceAddress":"10.0.0.2/32",
        "PeerPublicKey":"public",
        "PeerEndpoint":"vpn.example.test:51820",
        "AllowedIps":["10.0.0.0/8"],
        "Dns":["1.1.1.1"]
    }`))
	if err != nil {
		t.Fatalf("tunnelSidecarCommand() error = %v", err)
	}
	if program != "wormhole-wgproxy" {
		t.Fatalf("program = %q, want wormhole-wgproxy", program)
	}
	var config struct {
		AllowedIPs []string `json:"allowed_ips"`
		DNS        []string `json:"dns"`
	}
	if err := json.Unmarshal(payload, &config); err != nil {
		t.Fatalf("payload is invalid JSON: %v", err)
	}
	if len(config.AllowedIPs) != 1 || config.AllowedIPs[0] != "10.0.0.0/8" || len(config.DNS) != 1 {
		t.Fatalf("route settings were not retained: %#v", config)
	}
}

func TestResolveNodeTunnelHonorsChildOffOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY, ParentId TEXT NULL, TunnelEnabled INTEGER NULL, TunnelConfigId TEXT NULL
);
INSERT INTO Nodes (Id, ParentId, TunnelEnabled, TunnelConfigId) VALUES
    ('folder', NULL, 1, 'b2a0a6b0-69c8-4f3e-a4cb-f3395aa0a9f7'),
    ('connection', 'folder', 0, NULL);`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	id, enabled, err := resolveNodeTunnel(path, "connection")
	if err != nil {
		t.Fatalf("resolveNodeTunnel() error = %v", err)
	}
	if enabled || id != "b2a0a6b0-69c8-4f3e-a4cb-f3395aa0a9f7" {
		t.Fatalf("resolveNodeTunnel() = (%q, %v), want inherited id with disabled route", id, enabled)
	}
}

func TestResolveNodeTunnelMatchesLegacyMissingParentBehavior(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY, ParentId TEXT NULL, TunnelEnabled INTEGER NULL, TunnelConfigId TEXT NULL
);
INSERT INTO Nodes (Id, ParentId, TunnelEnabled, TunnelConfigId) VALUES
    ('connection', 'missing-folder', 1, 'b2a0a6b0-69c8-4f3e-a4cb-f3395aa0a9f7');`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	id, enabled, err := resolveNodeTunnel(path, "connection")
	if err != nil {
		t.Fatalf("missing ancestor should terminate inheritance, got %v", err)
	}
	if !enabled || id == "" {
		t.Fatalf("resolveNodeTunnel() = (%q, %v), want leaf route", id, enabled)
	}
}

func TestUpdateWorkspaceTunnelRejectsForceOnWithoutSelectedTunnel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY, TunnelEnabled INTEGER NULL, TunnelConfigId TEXT NULL, UpdatedAt TEXT NULL
);
CREATE TABLE TunnelConfigs (
    Id TEXT PRIMARY KEY, Name TEXT, Kind INTEGER, CreatedAt TEXT, UpdatedAt TEXT
);
INSERT INTO Nodes (Id) VALUES ('connection');`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()
	enabled := true
	if err := updateWorkspaceNodeTunnelSettings(path, workspaceNodeTunnelSettingsRequest{
		NodeID: "connection", TunnelEnabled: &enabled,
	}); err == nil {
		t.Fatal("force-on without a selected tunnel was accepted")
	}

	database, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var storedEnabled sql.NullInt64
	var storedConfig sql.NullString
	if err := database.QueryRow(
		"SELECT TunnelEnabled, TunnelConfigId FROM Nodes WHERE Id = 'connection';",
	).Scan(&storedEnabled, &storedConfig); err != nil {
		t.Fatal(err)
	}
	if storedEnabled.Valid || storedConfig.Valid {
		t.Fatalf("rejected route changed storage = (%v, %v), want (null, null)", storedEnabled, storedConfig)
	}
}

func TestUpdateWorkspaceTunnelRejectsInheritedEnableWithSelectedTunnel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY, TunnelEnabled INTEGER NULL, TunnelConfigId TEXT NULL, UpdatedAt TEXT NULL
);
CREATE TABLE TunnelConfigs (
    Id TEXT PRIMARY KEY, Name TEXT, Kind INTEGER, CreatedAt TEXT, UpdatedAt TEXT
);
INSERT INTO Nodes (Id) VALUES ('connection');
INSERT INTO TunnelConfigs (Id, Name, Kind) VALUES ('b2a0a6b0-69c8-4f3e-a4cb-f3395aa0a9f7', 'WireGuard', 0);`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	if err := updateWorkspaceNodeTunnelSettings(path, workspaceNodeTunnelSettingsRequest{
		NodeID:         "connection",
		TunnelConfigID: "b2a0a6b0-69c8-4f3e-a4cb-f3395aa0a9f7",
	}); err == nil {
		t.Fatal("inherit-on/off with a selected tunnel was accepted")
	}

	enabled := true
	if err := updateWorkspaceNodeTunnelSettings(path, workspaceNodeTunnelSettingsRequest{
		NodeID:         "connection",
		TunnelEnabled:  &enabled,
		TunnelConfigID: "b2a0a6b0-69c8-4f3e-a4cb-f3395aa0a9f7",
	}); err != nil {
		t.Fatalf("explicit tunnel selection was rejected: %v", err)
	}

	database, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var storedEnabled sql.NullInt64
	var storedConfig sql.NullString
	if err := database.QueryRow(
		"SELECT TunnelEnabled, TunnelConfigId FROM Nodes WHERE Id = 'connection';",
	).Scan(&storedEnabled, &storedConfig); err != nil {
		t.Fatal(err)
	}
	if !storedEnabled.Valid || storedEnabled.Int64 != 1 || !storedConfig.Valid || storedConfig.String != "b2a0a6b0-69c8-4f3e-a4cb-f3395aa0a9f7" {
		t.Fatalf("stored explicit route = (%v, %v), want (true, selected tunnel)", storedEnabled, storedConfig)
	}
}
