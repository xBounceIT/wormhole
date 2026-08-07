package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
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
			name: "Stormshield automatic credentials", kind: 4,
			settings: `{"Server":"sns.example.test","Mode":0}`,
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
		settings string
		field    string
	}{
		{
			name: "boolean", field: "UseSingleSignOn",
			settings: `{"Host":"vpn.example.test","Username":"user","Password":"password","UseSingleSignOn":"false"}`,
		},
		{
			name: "enum", field: "Mode",
			settings: `{"Server":"sns.example.test","Username":"user","Password":"password","Mode":3}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kind := int64(2)
			if test.field == "Mode" {
				kind = 4
			}
			request := tunnelWriteRequest{Name: test.name, Kind: kind, Settings: json.RawMessage(test.settings)}
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
