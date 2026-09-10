package main

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestSSHTerminalPartialEraseKeepsFrameBounded(t *testing.T) {
	emulator, err := newSSHTerminalEmulator(120, 40)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := emulator.write([]byte("retained shell output\x1b[40;1Hprogress 100%")); err != nil {
		t.Fatal(err)
	}
	frame, changed, err := emulator.write([]byte("\r\x1b[Jprogress 9%"))
	if err != nil || !changed || frame == nil {
		t.Fatalf("partial erase was not published: changed=%v err=%v", changed, err)
	}
	wire, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) > 4096 {
		t.Fatalf("one-line progress update retransmitted the viewport: %d wire bytes", len(wire))
	}
	if got := sshTerminalScrollbackLineFromCells(emulator.snapshot().Cells[:120]); scrollbackLineText(got) != "retained shell output" {
		t.Fatal("partial erase changed preceding shell output")
	}
	t.Logf("partial-erase frame: %d wire bytes", len(wire))
}

func TestSSHTerminalControlStringsDoNotRequestRedraws(t *testing.T) {
	for _, introducer := range []string{"]0;", "P", "^", "_", "k"} {
		for _, terminator := range []string{"\x07", "\x1b\\"} {
			for _, chunkSize := range []int{1, 4, 4096} {
				for _, payload := range []string{"", "\x1b[2J", "\x1b[?1049h", "\x1bc", "\x18\x1a\x1b[2J"} {
					t.Run(fmt.Sprintf("%q-%q-%d-%q", introducer, terminator, chunkSize, payload), func(t *testing.T) {
						emulator, err := newSSHTerminalEmulator(40, 6)
						if err != nil {
							t.Fatal(err)
						}
						emulator.initialFrame()
						data := []byte("\x1b" + introducer + "payload" + payload + terminator)
						for chunk := range slices.Chunk(data, chunkSize) {
							frame, _, err := emulator.write(chunk)
							if err != nil {
								t.Fatal(err)
							}
							if frame != nil && (frame.Full || frame.ViewportReset || frame.ScrollbackReset || frame.AlternateScreen) {
								t.Fatalf("control-string payload triggered a redraw: %q", chunk)
							}
						}
						frame, _, err := emulator.write([]byte("\x1b[H\x1b[2J$ "))
						if err != nil || frame == nil || !frame.Full || !frame.ViewportReset {
							t.Fatalf("clear after string terminator was lost: frame=%#v err=%v", frame, err)
						}
					})
				}
			}
		}
	}
}

func TestSSHTerminalEraseUsesCursorAtControlExecution(t *testing.T) {
	for name, test := range map[string]struct {
		before, output string
		full           bool
	}{
		"full clear then move down":     {before: "\x1b[H", output: "\x1b[J\x1b[4;1Htext", full: true},
		"partial clear then home":       {before: "\x1b[4;1H", output: "\x1b[0J\x1b[H", full: false},
		"partial top row":               {before: "\x1b[1;2H", output: "\x1b[J", full: false},
		"chunked full clear":            {before: "\x1b[H\x1b[0", output: "J\r\ntext", full: true},
		"explicit clear away from home": {before: "\x1b[4;2H", output: "\x1b[2J", full: true},
	} {
		t.Run(name, func(t *testing.T) {
			emulator, err := newSSHTerminalEmulator(40, 6)
			if err != nil {
				t.Fatal(err)
			}
			emulator.initialFrame()
			if _, _, err := emulator.write([]byte(test.before)); err != nil {
				t.Fatal(err)
			}
			frame, changed, err := emulator.write([]byte(test.output))
			if err != nil || !changed || frame == nil || frame.Full != test.full || !frame.ViewportReset {
				t.Fatalf("erase classification: frame=%#v changed=%v err=%v", frame, changed, err)
			}
		})
	}
}

func TestSSHTerminalControlParserBoundsAndRecovery(t *testing.T) {
	for _, data := range []string{
		"\x1b[" + strings.Repeat("0", 256) + "2J",
		"\x1b[" + strings.Repeat("0", 256),
		"\x1b[999999999999999999999999J",
		"\x1b[2 J", "\x1b[?2J",
		"\x1b[1J", "\x1b[31m", "\x1b[?2004h", "\x1b[?1049$h",
	} {
		var parser sshTerminalControlParser
		for _, value := range []byte(data) {
			if controls := parser.write([]byte{value}); len(controls) != 0 {
				t.Fatalf("invalid/unrelated input triggered a control: %q", data)
			}
			if len(parser.parameters) > 255 {
				t.Fatal("parser retained an oversized CSI")
			}
		}
		controls := parser.write([]byte("\x1b[2J"))
		if len(controls) != 1 || controls[0].kind != sshTerminalControlErase || controls[0].parameter != 2 {
			t.Fatalf("parser did not recover after %q", data)
		}
	}
}

func TestSSHTerminalScreenRestorationIsIndependentOfChunkBoundaries(t *testing.T) {
	data := []byte("old output\r\n\x1b[H\x1b[02J$ nano caffè.txt\r\n" +
		"\x1b[?1049;25h\x1b[H\x1b[2Jeditor €\x1b[4;1H\x1b[0J" +
		"\x1b]0;nano\x07\x1b[6;1H\x1b[?25;1049l\r$ ")
	render := func(chunks [][]byte) *sshTerminalFrame {
		t.Helper()
		emulator, err := newSSHTerminalEmulator(40, 6)
		if err != nil {
			t.Fatal(err)
		}
		emulator.initialFrame()
		for _, chunk := range chunks {
			if _, _, err := emulator.write(chunk); err != nil {
				t.Fatal(err)
			}
		}
		return emulator.snapshot()
	}
	expected := render([][]byte{data})
	for split := 1; split < len(data); split++ {
		actual := render([][]byte{data[:split], data[split:]})
		if !slices.Equal(actual.Cells, expected.Cells) || actual.CursorX != expected.CursorX ||
			actual.CursorY != expected.CursorY || actual.AlternateScreen != expected.AlternateScreen || actual.Title != expected.Title {
			t.Fatalf("screen restoration changed at byte boundary %d", split)
		}
	}
}

func TestSSHTerminalPaddedModesAndControlBoundaries(t *testing.T) {
	for _, data := range []string{
		"\x1b[" + strings.Repeat("0", 254) + "2J",
		"\x1b\x1b[2J", "\x1b[2\x00J",
		"\x1b[2\x7fJ", "\x1b\x7f[2J",
		"\x1b\x00[2J", "\x1b[2\x18J", "\x1b[2\x1aJ",
		"\x1b]0;title\x1b[discarded\x1b[2J",
		"\x1b]0;title\x1b\x1b[2J",
		"\x1b[?00047h", "\x1b[?001047h", "\x1b[?25;001049h", "\x1b[?001049;25h",
		"\x1b[0003J", "\x1bc",
	} {
		emulator, err := newSSHTerminalEmulator(40, 6)
		if err != nil {
			t.Fatal(err)
		}
		emulator.initialFrame()
		var frame *sshTerminalFrame
		for _, value := range []byte(data) {
			current, _, err := emulator.write([]byte{value})
			if err != nil {
				t.Fatal(err)
			}
			if current != nil {
				frame = current
			}
		}
		if frame == nil || !frame.Full || !frame.ViewportReset {
			t.Fatalf("valid fragmented control did not redraw: %q", data)
		}
	}
}
