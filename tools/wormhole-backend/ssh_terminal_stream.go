package main

import (
	"encoding/base64"
	"sync"
	"sync/atomic"
	"time"
)

// A bounded presentation stream. MCP replay and presentation filtering stay in Go.
// Credits are returned only after xterm has parsed the corresponding packet.
// Stop wakes both the producer and the pump before session shutdown takes locks.
const sshTerminalStreamWindow = 16

// A retired MCP wrapper can hold a quoted echo up to four times the command
// limit. Reserve enough for every bounded filter to flush in a single read,
// while ordinary remote reads pause as soon as four packets are queued.
const sshTerminalStreamQueuePackets = ((mcpMaxRetiredPresentations+1)*(4*mcpMaxCommandBytes+512)+sshOutputChunk-1)/sshOutputChunk + sshTerminalStreamWindow

var sshTerminalStreamSequence atomic.Uint64

type sshTerminalPacket struct {
	data          []byte
	reset         bool
	columns, rows int
	flushed       chan struct{}
}

type sshTerminalStream struct {
	queue    chan sshTerminalPacket
	credits  chan struct{}
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	readerMu sync.Mutex
	room     chan struct{}
	pending  map[uint64]bool
}

func newSSHTerminalStream(publish func(sshWireEvent)) *sshTerminalStream {
	stream := &sshTerminalStream{
		queue:   make(chan sshTerminalPacket, sshTerminalStreamQueuePackets),
		credits: make(chan struct{}, sshTerminalStreamWindow),
		done:    make(chan struct{}), pending: make(map[uint64]bool),
		room: make(chan struct{}, 1),
	}
	for range sshTerminalStreamWindow {
		stream.credits <- struct{}{}
	}
	go stream.pump(publish)
	return stream
}

func (stream *sshTerminalStream) send(packet sshTerminalPacket) bool {
	packet.data = append([]byte(nil), packet.data...)
	// Never wait while a caller owns terminalOutputMu: the command scanner
	// needs that lock for paste/resize and must remain able to process ACKs.
	select {
	case <-stream.done:
		return false
	case stream.queue <- packet:
		return true
	default:
		return false
	}
}

func (stream *sshTerminalStream) write(data []byte) bool {
	for len(data) > 0 {
		count := min(len(data), sshOutputChunk)
		if !stream.send(sshTerminalPacket{data: data[:count]}) {
			return false
		}
		data = data[count:]
	}
	return true
}

// Readers serialize admission outside terminalOutputMu. Spare queue capacity
// accommodates bounded MCP presentation flushes from the command scanner.
func (stream *sshTerminalStream) waitForRoom() bool {
	for {
		select {
		case <-stream.done:
			return false
		default:
		}
		if len(stream.queue) <= sshTerminalStreamWindow/4 {
			return true
		}
		select {
		case <-stream.done:
			return false
		case <-stream.room:
		}
	}
}

func (stream *sshTerminalStream) pump(publish func(sshWireEvent)) {
	for {
		var packet sshTerminalPacket
		select {
		case <-stream.done:
			return
		case packet = <-stream.queue:
		}
		select {
		case stream.room <- struct{}{}:
		default:
		}
		if packet.flushed != nil {
			// A barrier runs after the output readers finish. Acquiring every credit
			// guarantees all preceding packets were parsed before publishing closed.
			for range sshTerminalStreamWindow {
				select {
				case <-stream.done:
					return
				case <-stream.credits:
				}
			}
			for range sshTerminalStreamWindow {
				stream.credits <- struct{}{}
			}
			close(packet.flushed)
			continue
		}
		select {
		case <-stream.done:
			return
		case <-stream.credits:
		}
		stream.mu.Lock()
		sequence := sshTerminalStreamSequence.Add(1)
		stream.pending[sequence] = true
		stream.mu.Unlock()
		publish(sshWireEvent{Type: "terminal-output", Data: base64.StdEncoding.EncodeToString(packet.data),
			Sequence: sequence, Reset: packet.reset, Columns: packet.columns, Rows: packet.rows})
	}
}

func (stream *sshTerminalStream) acknowledge(sequence uint64) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if !stream.pending[sequence] {
		return
	}
	delete(stream.pending, sequence)
	stream.credits <- struct{}{}
}

func (stream *sshTerminalStream) stop() { stream.once.Do(func() { close(stream.done) }) }

func (stream *sshTerminalStream) drain(timeout time.Duration) {
	flushed := make(chan struct{})
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-stream.done:
		return
	case <-timer.C:
		return
	case stream.queue <- sshTerminalPacket{flushed: flushed}:
	}
	select {
	case <-stream.done:
	case <-timer.C:
	case <-flushed:
	}
}
