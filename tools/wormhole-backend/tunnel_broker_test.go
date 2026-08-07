package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestTunnelBrokerSharesSidecarAndReleasesLastLease(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE TunnelConfigs (Id TEXT PRIMARY KEY, Name TEXT, Kind INTEGER, CreatedAt TEXT, UpdatedAt TEXT);
INSERT INTO TunnelConfigs (Id, Name, Kind, CreatedAt, UpdatedAt) VALUES
    ('11111111-2222-3333-4444-555555555555', 'Shared', 0, 'one', 'one');`)
	_ = database.Close()
	if err != nil {
		t.Fatal(err)
	}

	starts := 0
	process := newTestTunnelProcess()
	previousPool := processTunnelPool
	processTunnelPool = newTunnelRuntimePool(func(context.Context, tunnelConfigSnapshot) (*tunnelProcess, error) {
		starts++
		return process, nil
	})
	defer func() { processTunnelPool = previousPool }()

	outputReader, outputWriter := io.Pipe()
	defer outputReader.Close()
	defer outputWriter.Close()
	manager := newVncManager(nil, &backendLineWriter{writer: bufio.NewWriter(outputWriter)})
	manager.databasePath = databasePath
	defer manager.close()
	responses := json.NewDecoder(outputReader)

	for index, leaseID := range []string{"web-one", "ssh-two"} {
		manager.handle(backendCommand{
			ID: "acquire-" + leaseID, Action: "tunnel.acquire", SessionID: leaseID,
			TunnelConfigID: "11111111-2222-3333-4444-555555555555",
		})
		response := readTunnelResponse(t, responses, "acquire-"+leaseID)
		if !response.OK || response.SocksEndpoint != "127.0.0.1:1080" || response.LeaseID != leaseID {
			t.Fatalf("acquire response = %#v", response)
		}
		if starts != 1 {
			t.Fatalf("sidecar starts after lease %d = %d, want 1", index+1, starts)
		}
	}

	go manager.handle(backendCommand{ID: "release-one", Action: "tunnel.release", SessionID: "web-one"})
	release := readTunnelResponse(t, responses, "release-one")
	if !release.OK {
		t.Fatalf("first release = %#v", release)
	}
	if !process.alive() {
		t.Fatal("first broker release closed a sidecar with another live lease")
	}
	go manager.handle(backendCommand{ID: "release-two", Action: "tunnel.release", SessionID: "ssh-two"})
	release = readTunnelResponse(t, responses, "release-two")
	if !release.OK {
		t.Fatalf("second release = %#v", release)
	}
	deadline := time.Now().Add(time.Second)
	for process.alive() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if process.alive() {
		t.Fatal("last broker release retained the sidecar")
	}
}

func TestTunnelBrokerDedicatedAcquireDoesNotReuseLiveSidecar(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE TunnelConfigs (Id TEXT PRIMARY KEY, Name TEXT, Kind INTEGER, CreatedAt TEXT, UpdatedAt TEXT);
INSERT INTO TunnelConfigs (Id, Name, Kind, CreatedAt, UpdatedAt) VALUES
    ('11111111-2222-3333-4444-555555555555', 'Diagnostic', 0, 'one', 'one');`)
	_ = database.Close()
	if err != nil {
		t.Fatal(err)
	}

	starts := 0
	previousPool := processTunnelPool
	processTunnelPool = newTunnelRuntimePool(func(context.Context, tunnelConfigSnapshot) (*tunnelProcess, error) {
		starts++
		return newTestTunnelProcess(), nil
	})
	defer func() { processTunnelPool = previousPool }()

	outputReader, outputWriter := io.Pipe()
	defer outputReader.Close()
	defer outputWriter.Close()
	manager := newVncManager(nil, &backendLineWriter{writer: bufio.NewWriter(outputWriter)})
	manager.databasePath = databasePath
	defer manager.close()
	responses := json.NewDecoder(outputReader)

	for _, command := range []backendCommand{
		{ID: "shared", Action: "tunnel.acquire", SessionID: "live", TunnelConfigID: "11111111-2222-3333-4444-555555555555"},
		{ID: "diagnostic", Action: "tunnel.acquire", SessionID: "test", TunnelConfigID: "11111111-2222-3333-4444-555555555555", Dedicated: true},
	} {
		manager.handle(command)
		if response := readTunnelResponse(t, responses, command.ID); !response.OK {
			t.Fatalf("%s acquire = %#v", command.ID, response)
		}
	}
	if starts != 2 {
		t.Fatalf("sidecar starts = %d, want a fresh diagnostic start in addition to the live tunnel", starts)
	}
}

func TestTunnelBrokerOwnsLoopbackForwarderForLeaseLifetime(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE TunnelConfigs (Id TEXT PRIMARY KEY, Name TEXT, Kind INTEGER, CreatedAt TEXT, UpdatedAt TEXT);
INSERT INTO TunnelConfigs VALUES ('11111111-2222-3333-4444-555555555555', 'Web', 0, 'one', 'one');`)
	_ = database.Close()
	if err != nil {
		t.Fatal(err)
	}

	process := newTestTunnelProcess()
	previousPool := processTunnelPool
	processTunnelPool = newTunnelRuntimePool(func(context.Context, tunnelConfigSnapshot) (*tunnelProcess, error) {
		return process, nil
	})
	defer func() { processTunnelPool = previousPool }()

	outputReader, outputWriter := io.Pipe()
	defer outputReader.Close()
	defer outputWriter.Close()
	manager := newVncManager(nil, &backendLineWriter{writer: bufio.NewWriter(outputWriter)})
	manager.databasePath = databasePath
	defer manager.close()
	responses := json.NewDecoder(outputReader)

	manager.handle(backendCommand{
		ID: "acquire", Action: "tunnel.acquire", SessionID: "web",
		TunnelConfigID: "11111111-2222-3333-4444-555555555555",
	})
	if response := readTunnelResponse(t, responses, "acquire"); !response.OK {
		t.Fatalf("acquire response = %#v", response)
	}
	go manager.handle(backendCommand{
		ID: "forward", Action: "tunnel.forward", SessionID: "web",
		Host: "appliance.internal", Port: 443,
	})
	forward := readTunnelResponse(t, responses, "forward")
	if !forward.OK || forward.ForwardHost != "127.0.0.1" || forward.ForwardPort < 1 {
		t.Fatalf("forward response = %#v", forward)
	}
	address := net.JoinHostPort(forward.ForwardHost, strconv.Itoa(forward.ForwardPort))
	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("forwarder did not accept a local connection: %v", err)
	}
	_ = connection.Close()

	go manager.handle(backendCommand{ID: "release", Action: "tunnel.release", SessionID: "web"})
	if response := readTunnelResponse(t, responses, "release"); !response.OK {
		t.Fatalf("release response = %#v", response)
	}
	if connection, err = net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
		_ = connection.Close()
		t.Fatal("lease release left the loopback forwarder accepting connections")
	}
}

// readTunnelLine decodes the next raw backend output line.
func readTunnelLine(t *testing.T, responses *json.Decoder) json.RawMessage {
	t.Helper()
	var raw json.RawMessage
	if err := responses.Decode(&raw); err != nil {
		t.Fatalf("decode backend output: %v", err)
	}
	return raw
}

// readTunnelEvent decodes output lines until an event of the given type is seen, skipping
// responses and unrelated events that may precede it.
func readTunnelEvent(t *testing.T, responses *json.Decoder, eventType string) backendEvent {
	t.Helper()
	for {
		raw := readTunnelLine(t, responses)
		var event backendEvent
		if err := json.Unmarshal(raw, &event); err != nil {
			t.Fatalf("decode backend event: %v", err)
		}
		if event.Type == eventType {
			return event
		}
	}
}

// readTunnelResponse decodes output lines until the response for the given command ID arrives,
// skipping events such as tunnel.progress or tunnel.route that are emitted before it.
func readTunnelResponse(t *testing.T, responses *json.Decoder, id string) backendResponse {
	t.Helper()
	for {
		raw := readTunnelLine(t, responses)
		var header struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		}
		if err := json.Unmarshal(raw, &header); err != nil {
			t.Fatalf("decode backend line: %v", err)
		}
		if header.Type != "" {
			continue
		}
		if header.ID != id {
			t.Fatalf("backend response ID = %q, want %q", header.ID, id)
		}
		var response backendResponse
		if err := json.Unmarshal(raw, &response); err != nil {
			t.Fatalf("decode backend response: %v", err)
		}
		return response
	}
}

func TestTunnelBrokerAsksWhetherToUseTunnel(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (Id TEXT PRIMARY KEY, ParentId TEXT, Name TEXT, TunnelEnabled INTEGER, TunnelConfigId TEXT);
INSERT INTO Nodes (Id, ParentId, Name, TunnelEnabled, TunnelConfigId) VALUES
    ('node-1', NULL, 'Web Server', 1, '11111111-2222-3333-4444-555555555555');
CREATE TABLE TunnelConfigs (Id TEXT PRIMARY KEY, Name TEXT, Kind INTEGER, CreatedAt TEXT, UpdatedAt TEXT);
INSERT INTO TunnelConfigs (Id, Name, Kind, CreatedAt, UpdatedAt) VALUES
    ('11111111-2222-3333-4444-555555555555', 'Office VPN', 0, 'one', 'one');`)
	_ = database.Close()
	if err != nil {
		t.Fatal(err)
	}
	_, settingsPath := authPaths(databasePath)
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte(`{"PromptBeforeTunnelConnect": true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	starts := 0
	process := newTestTunnelProcess()
	previousPool := processTunnelPool
	processTunnelPool = newTunnelRuntimePool(func(context.Context, tunnelConfigSnapshot) (*tunnelProcess, error) {
		starts++
		return process, nil
	})
	defer func() { processTunnelPool = previousPool }()

	outputReader, outputWriter := io.Pipe()
	defer outputReader.Close()
	defer outputWriter.Close()
	manager := newVncManager(nil, &backendLineWriter{writer: bufio.NewWriter(outputWriter)})
	manager.databasePath = databasePath
	defer manager.close()
	responses := json.NewDecoder(outputReader)

	manager.handle(backendCommand{ID: "acquire-direct", Action: "tunnel.acquire", SessionID: "lease-direct", NodeID: "node-1"})
	route := readTunnelEvent(t, responses, "tunnel.route")
	if route.SessionID != "lease-direct" || route.LeaseID != "lease-direct" ||
		route.ConnectionName != "Web Server" || route.TunnelName != "Office VPN" {
		t.Fatalf("route event = %#v", route)
	}
	go manager.handle(backendCommand{ID: "answer-direct", Action: "tunnel.route-response", SessionID: "lease-direct", PromptID: route.PromptID, Value: "direct"})
	answer := readTunnelResponse(t, responses, "answer-direct")
	if !answer.OK {
		t.Fatalf("route response = %#v", answer)
	}
	response := readTunnelResponse(t, responses, "acquire-direct")
	if !response.OK || response.SocksEndpoint != "" {
		t.Fatalf("direct acquire response = %#v", response)
	}
	if starts != 0 {
		t.Fatalf("direct route started the sidecar %d times", starts)
	}

	manager.handle(backendCommand{ID: "acquire-tunnel", Action: "tunnel.acquire", SessionID: "lease-tunnel", NodeID: "node-1"})
	route = readTunnelEvent(t, responses, "tunnel.route")
	go manager.handle(backendCommand{ID: "answer-tunnel", Action: "tunnel.route-response", SessionID: "lease-tunnel", PromptID: route.PromptID, Value: "tunnel"})
	_ = readTunnelResponse(t, responses, "answer-tunnel")
	response = readTunnelResponse(t, responses, "acquire-tunnel")
	if !response.OK || response.SocksEndpoint != "127.0.0.1:1080" {
		t.Fatalf("tunnel acquire response = %#v", response)
	}
	if starts != 1 {
		t.Fatalf("sidecar starts = %d, want 1", starts)
	}

	manager.handle(backendCommand{ID: "acquire-cancel", Action: "tunnel.acquire", SessionID: "lease-cancel", NodeID: "node-1"})
	route = readTunnelEvent(t, responses, "tunnel.route")
	go manager.handle(backendCommand{ID: "answer-cancel", Action: "tunnel.route-response", SessionID: "lease-cancel", PromptID: route.PromptID, Value: "cancel"})
	_ = readTunnelResponse(t, responses, "answer-cancel")
	response = readTunnelResponse(t, responses, "acquire-cancel")
	if response.OK || !strings.Contains(strings.ToLower(response.Error), "cancel") {
		t.Fatalf("cancel acquire response = %#v", response)
	}

	if err := os.WriteFile(
		settingsPath,
		[]byte(`{"SettingsSchemaVersion": 8, "PromptBeforeTunnelConnect": false}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	manager.handle(backendCommand{ID: "acquire-noask", Action: "tunnel.acquire", SessionID: "lease-noask", NodeID: "node-1"})
	response = readTunnelResponse(t, responses, "acquire-noask")
	if !response.OK || response.SocksEndpoint != "127.0.0.1:1080" {
		t.Fatalf("no-ask acquire response = %#v", response)
	}
	if starts != 1 {
		t.Fatalf("sidecar starts = %d, want 1 (shared sidecar reused)", starts)
	}
}

func TestTunnelBrokerReportsTunnelProgress(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE TunnelConfigs (Id TEXT PRIMARY KEY, Name TEXT, Kind INTEGER, CreatedAt TEXT, UpdatedAt TEXT);
INSERT INTO TunnelConfigs VALUES ('11111111-2222-3333-4444-555555555555', 'Shared', 0, 'one', 'one');`)
	_ = database.Close()
	if err != nil {
		t.Fatal(err)
	}

	process := newTestTunnelProcess()
	previousPool := processTunnelPool
	processTunnelPool = newTunnelRuntimePool(func(ctx context.Context, _ tunnelConfigSnapshot) (*tunnelProcess, error) {
		if err := reportTunnelProgress(ctx, "preparing", ""); err != nil {
			return nil, err
		}
		if err := reportTunnelProgress(ctx, "authenticating", "gateway.example"); err != nil {
			return nil, err
		}
		return process, nil
	})
	defer func() { processTunnelPool = previousPool }()

	outputReader, outputWriter := io.Pipe()
	defer outputReader.Close()
	defer outputWriter.Close()
	manager := newVncManager(nil, &backendLineWriter{writer: bufio.NewWriter(outputWriter)})
	manager.databasePath = databasePath
	defer manager.close()
	responses := json.NewDecoder(outputReader)

	manager.handle(backendCommand{ID: "acquire-progress", Action: "tunnel.acquire", SessionID: "lease", TunnelConfigID: "11111111-2222-3333-4444-555555555555"})
	var phases []string
	for {
		raw := readTunnelLine(t, responses)
		var event backendEvent
		if json.Unmarshal(raw, &event) == nil && event.Type == "tunnel.progress" {
			phases = append(phases, event.Phase)
			continue
		}
		var response backendResponse
		if err := json.Unmarshal(raw, &response); err != nil || response.ID != "acquire-progress" {
			t.Fatalf("unexpected backend line: %s", raw)
		}
		if !response.OK || response.SocksEndpoint != "127.0.0.1:1080" {
			t.Fatalf("acquire response = %#v", response)
		}
		break
	}
	want := []string{"preparing", "authenticating", "ready"}
	if len(phases) != len(want) {
		t.Fatalf("progress phases = %v, want %v", phases, want)
	}
	for i := range want {
		if phases[i] != want[i] {
			t.Fatalf("progress phases = %v, want %v", phases, want)
		}
	}
}

func TestPromptBeforeTunnelConnectSettingsMerge(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	_, settingsPath := authPaths(databasePath)
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte(`{"Fallback": 1, "IdleTimeoutMinutes": 30}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writePromptBeforeTunnelConnect(databasePath, false); err != nil {
		t.Fatalf("writePromptBeforeTunnelConnect() error = %v", err)
	}
	enabled, err := readPromptBeforeTunnelConnect(databasePath)
	if err != nil {
		t.Fatalf("readPromptBeforeTunnelConnect() error = %v", err)
	}
	if enabled {
		t.Fatal("readPromptBeforeTunnelConnect() = true, want false")
	}
	contents, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatalf("saved settings are invalid JSON: %v", err)
	}
	for _, key := range []string{"Fallback", "IdleTimeoutMinutes"} {
		if _, ok := document[key]; !ok {
			t.Fatalf("saved settings lost auth key %q: %s", key, contents)
		}
	}
	var saved bool
	if err := json.Unmarshal(document["PromptBeforeTunnelConnect"], &saved); err != nil || saved {
		t.Fatalf("saved PromptBeforeTunnelConnect = %s, want false", document["PromptBeforeTunnelConnect"])
	}

	if err := os.Remove(settingsPath); err != nil {
		t.Fatal(err)
	}
	enabled, err = readPromptBeforeTunnelConnect(databasePath)
	if err != nil || !enabled {
		t.Fatalf("absent setting = %v, %v; want true default", enabled, err)
	}
	if err := os.WriteFile(settingsPath, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	enabled, err = readPromptBeforeTunnelConnect(databasePath)
	if err != nil || !enabled {
		t.Fatalf("invalid setting document = %v, %v; want true default", enabled, err)
	}
}

func TestTunnelBrokerRelaysInteractivePromptResponse(t *testing.T) {
	outputReader, outputWriter := io.Pipe()
	defer outputReader.Close()
	defer outputWriter.Close()
	manager := newVncManager(nil, &backendLineWriter{writer: bufio.NewWriter(outputWriter)})
	defer manager.close()
	responses := json.NewDecoder(outputReader)
	result := make(chan string, 1)
	go func() {
		value, err := manager.promptTunnel("lease-one")(context.Background(), tunnelPrompt{
			Title: "OTP", Message: "Enter code", Secret: true,
		})
		if err != nil {
			result <- "error: " + err.Error()
			return
		}
		result <- value
	}()

	var event backendEvent
	if err := responses.Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.Type != "tunnel.prompt" || event.SessionID != "lease-one" || event.PromptID == "" || !event.Secret {
		t.Fatalf("prompt event = %#v", event)
	}
	go manager.handle(backendCommand{
		ID: "answer-one", Action: "tunnel.prompt-response", SessionID: "lease-one",
		PromptID: event.PromptID, Value: "123456",
	})
	var response backendResponse
	if err := responses.Decode(&response); err != nil || !response.OK {
		t.Fatalf("prompt response = %#v, %v", response, err)
	}
	var closed backendEvent
	if err := responses.Decode(&closed); err != nil {
		t.Fatal(err)
	}
	if closed.Type != "tunnel.prompt-closed" || closed.PromptID != event.PromptID || closed.SessionID != "lease-one" {
		t.Fatalf("prompt closed event = %#v", closed)
	}
	if value := <-result; value != "123456" {
		t.Fatalf("prompt result = %q", value)
	}
}

func TestTunnelBrokerClosesDistinctSidecarsConcurrently(t *testing.T) {
	manager := newVncManager(nil, nil)
	entered := make(chan struct{}, 2)
	unblock := make(chan struct{})
	for _, id := range []string{"one", "two"} {
		exited := make(chan struct{})
		process := &tunnelProcess{
			exited: exited,
			stdin: closeWriterFunc(func() error {
				entered <- struct{}{}
				<-unblock
				close(exited)
				return nil
			}),
		}
		pool := newTunnelRuntimePool(func(context.Context, tunnelConfigSnapshot) (*tunnelProcess, error) {
			return nil, errors.New("unexpected start")
		})
		entry := &sharedTunnelEntry{key: id, refs: 1, process: process}
		pool.entries[id] = entry
		manager.tunnelLeases[id] = &tunnelRuntime{entry: entry, pool: pool}
	}
	done := make(chan struct{})
	go func() {
		manager.close()
		close(done)
	}()
	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("sidecar cleanup ran sequentially")
		}
	}
	close(unblock)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("broker cleanup did not complete")
	}
}

func TestTunnelBrokerShutdownWaitsForCancelledAcquisition(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE TunnelConfigs (Id TEXT PRIMARY KEY, Name TEXT, Kind INTEGER, CreatedAt TEXT, UpdatedAt TEXT);
INSERT INTO TunnelConfigs VALUES ('11111111-2222-3333-4444-555555555555', 'Pending', 0, 'one', 'one');`)
	_ = database.Close()
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	finished := make(chan struct{})
	previousPool := processTunnelPool
	processTunnelPool = newTunnelRuntimePool(func(ctx context.Context, _ tunnelConfigSnapshot) (*tunnelProcess, error) {
		close(started)
		<-ctx.Done()
		close(finished)
		return nil, ctx.Err()
	})
	defer func() { processTunnelPool = previousPool }()
	manager := newVncManager(nil, &backendLineWriter{writer: bufio.NewWriter(&bytes.Buffer{})})
	manager.databasePath = databasePath
	manager.handle(backendCommand{
		ID: "pending", Action: "tunnel.acquire", SessionID: "lease",
		TunnelConfigID: "11111111-2222-3333-4444-555555555555",
	})
	<-started
	manager.close()
	select {
	case <-finished:
	default:
		t.Fatal("broker shutdown returned before the acquisition goroutine stopped")
	}
}
