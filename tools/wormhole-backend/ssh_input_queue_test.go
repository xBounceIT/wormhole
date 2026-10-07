package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSSHInputQueueByteBoundAndOwnership(t *testing.T) {
	queue := newSSHInputQueue(8)
	input := []byte("abcd")
	if err := queue.write(input); err != nil {
		t.Fatal(err)
	}
	input[0] = 'X'
	if err := queue.write([]byte("efgh")); err != nil {
		t.Fatal(err)
	}
	if err := queue.write([]byte("lost")); !errors.Is(err, errSSHInputFull) {
		t.Fatalf("overflow error = %v", err)
	}
	if queue.size() != 8 {
		t.Fatalf("queued bytes = %d", queue.size())
	}
	select {
	case <-queue.ready:
	default:
		t.Fatal("queued bytes did not wake the pump")
	}
	first := queue.take()
	if string(first) != "abcdefgh" || queue.size() != 0 {
		t.Fatalf("drained input = %q, remaining = %d", first, queue.size())
	}
	if err := queue.write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	if string(first) != "abcdefgh" {
		t.Fatal("enqueue mutated an in-flight write")
	}
	queue.stop()
	if queue.size() != 0 || len(queue.take()) != 0 {
		t.Fatal("shutdown retained pending input")
	}
	if err := queue.write([]byte("after-close")); !errors.Is(err, errSSHSessionClosed) {
		t.Fatalf("closed queue error = %v", err)
	}
}

func TestSSHInputQueueConcurrentRepliesWakePump(t *testing.T) {
	queue := newSSHInputQueue(sshInputQueueMaxBytes)
	const producers, replies = 4, 512
	var writers sync.WaitGroup
	t.Cleanup(writers.Wait)
	for index := range producers {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for range replies {
				if err := queue.write([]byte{byte('a' + index)}); err != nil {
					t.Errorf("enqueue reply: %v", err)
					return
				}
			}
		}()
	}
	var received []byte
	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	for len(received) < producers*replies {
		select {
		case <-queue.ready:
			received = append(received, queue.take()...)
		case <-timeout.C:
			t.Fatal("pump missed a wakeup")
		}
	}
	writers.Wait()
	for index := range producers {
		if count := bytes.Count(received, []byte{byte('a' + index)}); count != replies {
			t.Fatalf("producer %d: received %d replies", index, count)
		}
	}
}

func TestSSHInputShutdownDiscardsPendingBytesAndRejectsWrites(t *testing.T) {
	input := &recordingSSHInput{}
	native := &sshNativeSession{stdin: input,
		inputQueue: newSSHInputQueue(sshInputQueueMaxBytes), done: make(chan struct{})}
	if err := native.write([]byte("pending")); err != nil {
		t.Fatal(err)
	}
	native.close(false)
	native.startInputPump()
	if native.inputQueue.size() != 0 || input.String() != "" {
		t.Fatal("shutdown retained or sent pending input")
	}
	if err := native.write([]byte("after-close")); !errors.Is(err, errSSHSessionClosed) {
		t.Fatalf("write after shutdown = %v", err)
	}
	if err := native.writeRaw([]byte("after-close")); !errors.Is(err, errSSHSessionClosed) {
		t.Fatalf("raw write after shutdown = %v", err)
	}
	if err := native.writeRaw(nil); err != nil {
		t.Fatalf("empty write after shutdown = %v", err)
	}
	// Cancellation can precede lifecycle cleanup; never accept input in that gap.
	cancelled := &sshNativeSession{inputQueue: newSSHInputQueue(sshInputQueueMaxBytes), done: make(chan struct{})}
	close(cancelled.done)
	if err := cancelled.writeRaw([]byte("cancelled")); !errors.Is(err, errSSHSessionClosed) || cancelled.inputQueue.size() != 0 {
		t.Fatalf("input accepted after cancellation: %v", err)
	}
}

func TestSSHServerQueryReplyBurstSurvivesBlockedWrite(t *testing.T) {
	var output synchronizedBuffer
	server := newSSHTestServer(&output)
	input := &recordingSSHInput{}
	started, release := make(chan struct{}), make(chan struct{})
	var first sync.Once
	native := &sshNativeSession{
		id: "burst", server: server, inputQueue: newSSHInputQueue(sshInputQueueMaxBytes),
		done: make(chan struct{}),
		stdin: callbackWriteCloser{write: func(data []byte) (int, error) {
			first.Do(func() { close(started); <-release })
			return input.Write(data)
		}},
	}
	server.sessions[native.id] = native
	native.pasteMode.enabled = true
	t.Cleanup(func() { native.close(false) })
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	native.startInputPump()
	if err := native.write([]byte("start")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("input pump did not start writing")
	}
	want := "start"
	for range 256 {
		for _, reply := range []string{"\x1b[0n", "\x1b[1;1R", "\x1b[?1;2c"} {
			server.input(sshWireCommand{SessionID: native.id, Data: base64.StdEncoding.EncodeToString([]byte(reply))})
			want += reply
		}
	}
	server.input(sshWireCommand{SessionID: native.id, Paste: true, Data: base64.StdEncoding.EncodeToString([]byte("é\nnext"))})
	want += "\x1b[200~é\rnext\x1b[201~"
	binaryMouse := []byte{'\x1b', '[', 'M', 0xff, 0xa0, 0x80}
	server.input(sshWireCommand{SessionID: native.id, Data: base64.StdEncoding.EncodeToString(binaryMouse)})
	want += string(binaryMouse)
	if output.String() != "" {
		t.Fatalf("reply burst failed the session: %s", output.String())
	}
	unblock()
	waitForSSHTestCondition(t, "ordered reply burst and paste", func() bool { return input.String() == want })
	if native.isClosed() || !server.isActive(native) {
		t.Fatal("normal reply burst closed the session")
	}
}

func TestSSHInputFailuresAreLoggedWithoutSecrets(t *testing.T) {
	for _, level := range []string{logLevelInfo, logLevelDebug} {
		for _, failure := range []string{"overflow", "remote write"} {
			t.Run(level+"/"+failure, func(t *testing.T) {
				databasePath := filepath.Join(t.TempDir(), "wormhole.db")
				logger, err := newAppLogger(databasePath)
				if err != nil {
					t.Fatal(err)
				}
				logger.level = level
				previous := appLog
				appLog = logger
				t.Cleanup(func() { logger.close(); appLog = previous })
				var output synchronizedBuffer
				server := newSSHTestServer(&output)
				const secret = "private-input-token"
				native := &sshNativeSession{id: "failure", server: server,
					inputQueue: newSSHInputQueue(len(secret)), done: make(chan struct{})}
				server.sessions[native.id] = native
				t.Cleanup(func() { native.close(false) })
				if failure == "overflow" {
					if err := native.write([]byte(secret)); err != nil {
						t.Fatal(err)
					}
					server.input(sshWireCommand{SessionID: native.id, Data: base64.StdEncoding.EncodeToString([]byte(secret))})
					events := decodeSSHEvents(t, output.Bytes())
					if len(events) == 0 || events[len(events)-1].Error != errSSHInputFull.Error() {
						t.Fatalf("missing overflow event: %s", output.String())
					}
				} else {
					native.stdin = callbackWriteCloser{write: func([]byte) (int, error) { return 0, errors.New(secret) }}
					native.startInputPump()
					server.input(sshWireCommand{SessionID: native.id, Data: base64.StdEncoding.EncodeToString([]byte(secret))})
					waitForSSHTestCondition(t, "write failure closes the session", func() bool {
						return strings.Contains(output.String(), `"type":"closed"`)
					})
				}
				contents, err := os.ReadFile(currentDayLogFilePath(databasePath))
				if err != nil {
					t.Fatal(err)
				}
				logs := string(contents)
				if !strings.Contains(logs, "[ERR] SSH input") || !strings.Contains(logs, `session="failure"`) ||
					!strings.Contains(logs, "input_bytes=19") || !strings.Contains(logs, "traceback:") {
					t.Fatalf("missing safe input diagnostics: %s", logs)
				}
				if strings.Contains(logs, secret) || strings.Contains(output.String(), secret) {
					t.Fatal("input or remote error contents leaked into diagnostics")
				}
			})
		}
	}
}

func TestSSHInputOverflowRetiresSessionAndReconnectState(t *testing.T) {
	var output synchronizedBuffer
	server := newSSHTestServer(&output)
	input := &blockingSSHInput{started: make(chan struct{}), release: make(chan struct{})}
	native := &sshNativeSession{id: "full", server: server, stdin: input,
		inputQueue: newSSHInputQueue(8), done: make(chan struct{})}
	pool := newTunnelRuntimePool(nil)
	process := newTestTunnelProcess()
	entry := &sharedTunnelEntry{key: "input-tunnel", refs: 1, process: process}
	pool.entries[entry.key] = entry
	native.tunnel = &tunnelRuntime{entry: entry, pool: pool}
	state := &sshReconnectState{command: sshWireCommand{SessionID: native.id,
		Password: "secret", PasswordOverride: "override", KeyPassphraseOverride: "passphrase"}}
	server.sessions[native.id], server.lifecycles[native.id] = native, state
	transferContext, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	server.transfers["transfer"] = &sshSftpTransfer{sessionID: native.id, cancel: cancel}
	unrelatedContext, unrelatedCancel := context.WithCancel(context.Background())
	t.Cleanup(unrelatedCancel)
	server.transfers["other-transfer"] = &sshSftpTransfer{sessionID: "other", cancel: unrelatedCancel}
	t.Cleanup(func() { native.close(false) })
	native.startInputPump()
	if err := native.write([]byte("inflight")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-input.started:
	case <-time.After(time.Second):
		t.Fatal("input pump did not start writing")
	}
	if err := native.write([]byte("pending!")); err != nil {
		t.Fatal(err)
	}
	server.input(sshWireCommand{SessionID: native.id, Data: "eA=="})
	if !native.isClosed() || native.inputQueue.size() != 0 || server.session(native.id) != nil || server.lifecycles[native.id] != nil {
		t.Fatal("overflow retained the failed session or reconnect state")
	}
	command := state.commandSnapshot()
	if command.Password != "" || command.PasswordOverride != "" || command.KeyPassphraseOverride != "" {
		t.Fatal("overflow retained reconnect secrets")
	}
	if transferContext.Err() != context.Canceled || unrelatedContext.Err() != nil {
		t.Fatal("overflow did not cancel only the affected session's transfers")
	}
	if pool.entries[entry.key] != nil || entry.refs != 0 || process.alive() {
		t.Fatal("overflow retained its VPN tunnel lease")
	}
	select {
	case <-input.release:
	default:
		t.Fatal("overflow did not close remote input")
	}
	native.close(true) // A late remote close must not start automatic reconnect.
	events := decodeSSHEvents(t, output.Bytes())
	if len(events) != 2 || events[0].Type != "closed" || events[1].Type != "error" || events[1].Error != errSSHInputFull.Error() {
		t.Fatalf("overflow must clean up Electron ownership and leave the error visible: %#v", events)
	}
	if err := native.write([]byte("later")); !errors.Is(err, errSSHSessionClosed) {
		t.Fatalf("accepted input after overflow: %v", err)
	}
}

func TestSSHInputFailureDoesNotRetireAReplacementSession(t *testing.T) {
	var output synchronizedBuffer
	server := newSSHTestServer(&output)
	old := &sshNativeSession{id: "reused", server: server, closed: true}
	replacement := &sshNativeSession{id: old.id, server: server, done: make(chan struct{})}
	state := &sshReconnectState{command: sshWireCommand{SessionID: replacement.id, Password: "replacement-secret"}}
	server.sessions[replacement.id], server.lifecycles[replacement.id] = replacement, state
	t.Cleanup(func() { replacement.close(false) })
	server.failInput(old, errSSHInputFull.Error(), 1)
	if server.session(replacement.id) != replacement || replacement.isClosed() || server.lifecycles[replacement.id] != state ||
		state.commandSnapshot().Password != "replacement-secret" || output.String() != "" {
		t.Fatal("stale input failure affected the replacement session")
	}
}

func TestSSHInputFailureDoesNotPublishOverReplacementDuringCleanup(t *testing.T) {
	var output synchronizedBuffer
	server := newSSHTestServer(&output)
	replacement := &sshNativeSession{id: "reused", server: server, done: make(chan struct{})}
	state := &sshReconnectState{command: sshWireCommand{SessionID: replacement.id, Password: "replacement-secret"}}
	old := &sshNativeSession{id: replacement.id, server: server, stdin: closeWriterFunc(func() error {
		server.mu.Lock()
		server.sessions[replacement.id], server.lifecycles[replacement.id] = replacement, state
		server.mu.Unlock()
		return nil
	})}
	server.sessions[old.id] = old
	t.Cleanup(func() { replacement.close(false) })
	server.failInput(old, errSSHInputFull.Error(), 1)
	if !old.isClosed() || server.session(replacement.id) != replacement || replacement.isClosed() ||
		state.commandSnapshot().Password != "replacement-secret" || output.String() != "" {
		t.Fatal("cleanup or late failure notification affected the replacement session")
	}
}

func TestSSHInputDuringRemoteClosePreservesAutomaticReconnect(t *testing.T) {
	var output synchronizedBuffer
	server := newSSHTestServer(&output)
	t.Cleanup(server.shutdown)
	// close(true) marks the native session closed before nativeClosed removes it.
	native := &sshNativeSession{id: "closing", server: server, closed: true}
	state := &sshReconnectState{command: sshWireCommand{SessionID: native.id, Password: "reconnect-secret"}}
	server.sessions[native.id], server.lifecycles[native.id] = native, state
	server.input(sshWireCommand{SessionID: native.id, Data: "eA=="})
	if output.String() != "" || server.session(native.id) != native || server.lifecycles[native.id] != state ||
		state.commandSnapshot().Password != "reconnect-secret" {
		t.Fatal("input during remote close discarded the automatic reconnect lifecycle")
	}
	server.nativeClosed(native)
	events := decodeSSHEvents(t, output.Bytes())
	if len(events) != 1 || events[0].Type != "reconnecting" || events[0].Attempt != 1 {
		t.Fatalf("remote shutdown did not reconnect normally: %#v", events)
	}
}
