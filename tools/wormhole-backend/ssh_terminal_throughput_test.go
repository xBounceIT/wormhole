package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func terminalLogBatch(start, count int) []byte {
	var output strings.Builder
	for i := start; i < start+count; i++ {
		fmt.Fprintf(&output, "\x1b[32mlog-%06d\x1b[0m work completed\r\n", i)
	}
	return []byte(output.String())
}

func TestSSHTerminalSustainedOutputUsesBoundedDeltas(t *testing.T) {
	emulator, err := newSSHTerminalEmulator(80, 24)
	if err != nil {
		t.Fatal(err)
	}
	_ = emulator.initialFrame()
	var rendered []sshTerminalScrollbackLine
	// Cross both the scrollback cap and the history-recorder rebase several times.
	for start := 0; start < 18000; start += 50 {
		frame, changed, err := emulator.write(terminalLogBatch(start, 50))
		if err != nil || !changed || frame == nil {
			t.Fatalf("batch %d: changed=%v err=%v", start, changed, err)
		}
		if frame.ScrollbackReset || len(frame.Scrollback) > 50 {
			t.Fatalf("batch %d retransmitted history: reset=%v lines=%d", start, frame.ScrollbackReset, len(frame.Scrollback))
		}
		rendered = append(rendered, frame.Scrollback...)
		if len(rendered) > sshTerminalMaxScrollbackLines {
			rendered = rendered[len(rendered)-sshTerminalMaxScrollbackLines:]
		}
		if len(emulator.scrollback) != len(rendered) {
			t.Fatalf("history length differs at %d", start)
		}
		for index, line := range rendered {
			if sshTerminalScrollbackLineText(line) != sshTerminalScrollbackLineText(emulator.scrollback[index]) {
				t.Fatalf("history mismatch at batch %d row %d", start, index)
			}
		}
	}
	snapshot := emulator.snapshot()
	if !snapshot.ScrollbackReset || len(snapshot.Scrollback) != sshTerminalMaxScrollbackLines {
		t.Fatal("reconnect snapshot lost history")
	}
	if got := sshTerminalScrollbackLineText(rendered[0]); got != "log-012977 work completed" {
		t.Fatalf("first row: %q", got)
	}
	if got := sshTerminalScrollbackLineText(rendered[len(rendered)-1]); got != "log-017976 work completed" {
		t.Fatalf("last row: %q", got)
	}
}

func BenchmarkSSHTerminalSustainedOutput(b *testing.B) {
	emulator, err := newSSHTerminalEmulator(80, 24)
	if err != nil {
		b.Fatal(err)
	}
	_ = emulator.initialFrame()
	if _, _, err := emulator.write(terminalLogBatch(0, 5100)); err != nil {
		b.Fatal(err)
	}
	batch := terminalLogBatch(5100, 50)
	var wireBytes int64
	b.ReportAllocs()
	b.SetBytes(int64(len(batch)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		frame, _, err := emulator.write(batch)
		if err != nil {
			b.Fatal(err)
		}
		encoded, err := json.Marshal(frame)
		if err != nil {
			b.Fatal(err)
		}
		wireBytes += int64(len(encoded))
	}
	b.ReportMetric(float64(wireBytes)/float64(b.N), "wire-B/op")
}

func TestSSHTerminalRepeatedOutputDoesNotResendUnchangedViewport(t *testing.T) {
	emulator, err := newSSHTerminalEmulator(80, 24)
	if err != nil {
		t.Fatal(err)
	}
	_ = emulator.initialFrame()
	batch := terminalLogBatch(0, 50)
	first, _, err := emulator.write(batch)
	if err != nil {
		t.Fatal(err)
	}
	frame, changed, err := emulator.write(batch)
	if err != nil || !changed || frame == nil {
		t.Fatalf("repeat: changed=%v err=%v", changed, err)
	}
	if frame.Full || len(frame.Cells) != 0 || len(frame.Changes) != 0 || len(frame.Scrollback) != 50 {
		t.Fatal("history-only update resent the viewport")
	}
	if frame.Sequence != first.Sequence+1 || frame.CursorX != first.CursorX || frame.CursorY != first.CursorY || frame.Columns != 80 || frame.Rows != 24 {
		t.Fatal("history-only update lost frame metadata")
	}
}
