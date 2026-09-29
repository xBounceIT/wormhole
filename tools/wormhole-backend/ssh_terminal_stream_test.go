package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func streamEvent(t *testing.T, events <-chan sshWireEvent) sshWireEvent {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(time.Second):
		t.Fatal("terminal stream stalled")
		return sshWireEvent{}
	}
}

func TestSSHTerminalStreamPreservesBytesAndBoundsCredits(t *testing.T) {
	events := make(chan sshWireEvent, 64)
	stream := newSSHTerminalStream(func(event sshWireEvent) { events <- event })
	defer stream.stop()
	stream.send(sshTerminalPacket{reset: true, columns: 80, rows: 24})
	initial := streamEvent(t, events)
	if !initial.Reset || initial.Columns != 80 || initial.Rows != 24 {
		t.Fatal("missing initial geometry")
	}
	stream.acknowledge(initial.Sequence)
	stream.acknowledge(initial.Sequence) // duplicate acknowledgments grant no extra credit
	stream.acknowledge(initial.Sequence + 10000)
	data := []byte(strings.Repeat("\x1b[38;2;1;2;3m日本語\x1b[0m\r\n", 10000))
	produced := make(chan struct{})
	go func() {
		remaining := data
		for len(remaining) > 0 {
			if !stream.waitForRoom() {
				break
			}
			count := min(len(remaining), sshOutputChunk)
			if !stream.write(remaining[:count]) {
				break
			}
			remaining = remaining[count:]
		}
		close(produced)
	}()
	var received bytes.Buffer
	var sequences []uint64
	for range sshTerminalStreamWindow {
		event := streamEvent(t, events)
		decoded, err := base64.StdEncoding.DecodeString(event.Data)
		if err != nil || len(decoded) > sshOutputChunk {
			t.Fatalf("invalid packet: %v", err)
		}
		received.Write(decoded)
		sequences = append(sequences, event.Sequence)
	}
	select {
	case <-events:
		t.Fatal("credit limit exceeded")
	case <-time.After(20 * time.Millisecond):
	}
	for _, sequence := range sequences {
		stream.acknowledge(sequence)
	}
	for received.Len() < len(data) {
		event := streamEvent(t, events)
		decoded, _ := base64.StdEncoding.DecodeString(event.Data)
		received.Write(decoded)
		stream.acknowledge(event.Sequence)
	}
	<-produced
	stream.drain(time.Second)
	if !bytes.Equal(received.Bytes(), data) {
		t.Fatal("ANSI or UTF-8 bytes changed")
	}
}

func TestSSHTerminalStreamStopWakesBlockedProducerAndDrain(t *testing.T) {
	events := make(chan sshWireEvent, 64)
	stream := newSSHTerminalStream(func(event sshWireEvent) { events <- event })
	finished := make(chan struct{})
	go func() {
		for range 100 {
			if !stream.waitForRoom() {
				break
			}
			stream.write(bytes.Repeat([]byte("x"), sshOutputChunk))
		}
		close(finished)
	}()
	for range sshTerminalStreamWindow {
		streamEvent(t, events)
	}
	stream.drain(time.Millisecond)
	stream.stop()
	stream.stop()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("shutdown deadlocked on presentation lock")
	}
	stream.drain(time.Second)
	stream.send(sshTerminalPacket{})
}

func TestSSHTerminalStreamBypassesCellEmulationAndKeepsMcpReplay(t *testing.T) {
	events := make(chan sshWireEvent, 16)
	stream := newSSHTerminalStream(func(event sshWireEvent) { events <- event })
	defer stream.stop()
	terminal, err := newSSHTerminalEmulator(80, 24)
	if err != nil {
		t.Fatal(err)
	}
	native := &sshNativeSession{terminal: terminal, terminalStream: stream, mcpReplay: newMcpReplayBuffer(4096)}
	data := []byte("\x1b[1;3;4;38;2;12;34;56mstyled\x1b[0m")
	native.publishVisibleTerminalDataLocked(data)
	event := streamEvent(t, events)
	decoded, _ := base64.StdEncoding.DecodeString(event.Data)
	stream.acknowledge(event.Sequence)
	if !bytes.Equal(decoded, data) || !bytes.Equal(native.mcpReplay.snapshotTail(4096), data) {
		t.Fatal("stream or MCP replay lost output")
	}
	if terminal.sequence != 0 {
		t.Fatal("SSH presentation still traverses the cell emulator")
	}
	native.snapshot()
	stream.drain(time.Second)
}

func TestSSHTerminalStreamBackpressureKeepsPasteAndShutdownResponsive(t *testing.T) {
	events := make(chan sshWireEvent, 64)
	stream := newSSHTerminalStream(func(event sshWireEvent) { events <- event })
	defer stream.stop()
	terminal, err := newSSHTerminalEmulator(80, 24)
	if err != nil {
		t.Fatal(err)
	}
	var output synchronizedBuffer
	server := newSSHTestServer(&output)
	native := &sshNativeSession{id: "stream", server: server, terminal: terminal, terminalStream: stream,
		mcpReplay: newMcpReplayBuffer(4096), mcpCommandReplay: newMcpReplayBuffer(4096),
		inputQueue: make(chan []byte, 16), done: make(chan struct{})}
	server.sessions[native.id] = native
	reading := make(chan struct{})
	go func() { native.readOutput(strings.NewReader(strings.Repeat("output\r\n", 100000))); close(reading) }()
	for range sshTerminalStreamWindow {
		streamEvent(t, events)
	}
	commands := make(chan struct{})
	go func() {
		server.handle(sshWireCommand{Type: "input", SessionID: native.id, Paste: true, Data: base64.StdEncoding.EncodeToString([]byte("pasted"))})
		server.handle(sshWireCommand{Type: "snapshot", SessionID: native.id})
		close(commands)
	}()
	select {
	case <-commands:
	case <-time.After(time.Second):
		t.Fatal("paste blocked ACK processing behind terminal output")
	}
	if input := <-native.inputQueue; string(input) != "pasted" {
		t.Fatalf("input changed: %q", input)
	}
	native.close(false)
	select {
	case <-reading:
	case <-time.After(time.Second):
		t.Fatal("reader did not exit on close")
	}

}

func TestSSHTerminalStreamRejectsOverflowWithoutBlockingCommandLocks(t *testing.T) {
	stream := newSSHTerminalStream(func(sshWireEvent) {})
	defer stream.stop()
	// No ACKs; first exhaust credits and then the bounded queue.
	overflow := false
	for range sshTerminalStreamQueuePackets + sshTerminalStreamWindow + 2 {
		if !stream.send(sshTerminalPacket{data: []byte("x")}) {
			overflow = true
			break
		}
	}
	if !overflow {
		t.Fatal("unbounded presentation queue")
	}
}

func TestSSHTerminalStreamOverflowClosesOnlyItsSession(t *testing.T) {
	var output synchronizedBuffer
	server := newSSHTestServer(&output)
	terminal, err := newSSHTerminalEmulator(80, 24)
	if err != nil {
		t.Fatal(err)
	}
	native := &sshNativeSession{id: "overflow", server: server, terminal: terminal,
		terminalStream: newSSHTerminalStream(func(sshWireEvent) {}),
		mcpReplay:      newMcpReplayBuffer(4096), done: make(chan struct{})}
	server.sessions[native.id] = native
	server.sessions["other"] = &sshNativeSession{id: "other"}
	native.terminalOutputMu.Lock()
	native.publishVisibleTerminalDataLocked(bytes.Repeat([]byte("x"), (sshTerminalStreamQueuePackets+sshTerminalStreamWindow+2)*sshOutputChunk))
	native.terminalOutputMu.Unlock()
	select {
	case <-native.done:
	case <-time.After(time.Second):
		t.Fatal("overflow shutdown deadlocked")
	}
	if server.session("other") == nil {
		t.Fatal("overflow closed an unrelated session")
	}
	if !strings.Contains(output.String(), "SSH terminal output queue is full") {
		t.Fatal("overflow was silently discarded")
	}
}

func TestSSHTerminalStreamOpenPublishesResetBeforeOutput(t *testing.T) {
	var output synchronizedBuffer
	server := newSSHTestServer(&output)
	terminal, err := newSSHTerminalEmulator(100, 30)
	if err != nil {
		t.Fatal(err)
	}
	native := &sshNativeSession{terminal: terminal, started: true, done: make(chan struct{}),
		mcpReplay: newMcpReplayBuffer(4096), mcpCommandReplay: newMcpReplayBuffer(4096)}
	server.openSSH = func(context.Context, *sshReconnectState) (*sshNativeSession, sshTarget, error) {
		return native, sshTarget{host: "test", port: 22, username: "test"}, nil
	}
	state := &sshReconnectState{command: sshWireCommand{SessionID: "stream-open", TerminalStream: true}}
	server.pending[state.command.SessionID] = func() {}
	server.lifecycles[state.command.SessionID] = state
	server.connectSSH(context.Background(), state, true)
	defer native.close(false)
	deadline := time.Now().Add(time.Second)
	for {
		events := decodeSSHEvents(t, output.Bytes())
		if len(events) >= 2 {
			if events[0].Type != "connected" || events[1].Type != "terminal-output" ||
				!events[1].Reset || events[1].Columns != 100 || events[1].Rows != 30 {
				t.Fatalf("unexpected initial presentation: %#v", events)
			}
			server.handle(sshWireCommand{Type: "terminal-ack", SessionID: native.id, Sequence: events[1].Sequence})
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stream reset missing")
		}
		time.Sleep(time.Millisecond)
	}
	if native.terminalStream == nil {
		t.Fatal("stream presentation was not enabled")
	}
}
