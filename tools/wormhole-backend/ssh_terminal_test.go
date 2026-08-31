package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	vt10x "github.com/ActiveState/vt10x"
)

func TestSSHTerminalEmulatorParsesANSIIntoCells(t *testing.T) {
	emulator, err := newSSHTerminalEmulator(12, 3)
	if err != nil {
		t.Fatal(err)
	}
	initial := emulator.initialFrame()
	if initial == nil || !initial.Full || len(initial.Cells) != 36 {
		t.Fatalf("unexpected initial frame: %#v", initial)
	}

	frame, changed, err := emulator.write([]byte("\x1b[31mred\x1b[0m"))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || frame == nil || frame.Full || len(frame.Changes) < 3 {
		t.Fatalf("ANSI output did not produce a screen diff: %#v", frame)
	}

	cells := append([]sshTerminalCell(nil), initial.Cells...)
	for _, change := range frame.Changes {
		cells[change.Index] = sshTerminalCell{
			Character:  change.Character,
			Foreground: change.Foreground,
			Background: change.Background,
		}
	}
	if cells[0].Character != "r" || cells[1].Character != "e" || cells[2].Character != "d" {
		t.Fatalf("ANSI escape sequence leaked into the screen: %#v", cells[:4])
	}
	if cells[0].Foreground != uint16(vt10x.Red) {
		t.Fatalf("unexpected ANSI foreground: %d", cells[0].Foreground)
	}
}

func TestSSHTerminalEmulatorCarriesPartialSequencesAndUTF8(t *testing.T) {
	emulator, err := newSSHTerminalEmulator(12, 3)
	if err != nil {
		t.Fatal(err)
	}
	_ = emulator.initialFrame()

	if frame, changed, err := emulator.write([]byte("\x1b[31")); err != nil || changed || frame != nil {
		t.Fatalf("incomplete CSI was rendered early: frame=%#v changed=%v err=%v", frame, changed, err)
	}
	if frame, changed, err := emulator.write([]byte("m€")); err != nil || !changed || frame == nil {
		t.Fatalf("completed CSI/UTF-8 was not rendered: frame=%#v changed=%v err=%v", frame, changed, err)
	}

	second, changed, err := emulator.write([]byte("\x1b[?1h"))
	if err != nil || !changed || second == nil || !second.ApplicationCursor {
		t.Fatalf("application cursor mode was not tracked: frame=%#v changed=%v err=%v", second, changed, err)
	}
}

func TestSSHTerminalEmulatorResizeReturnsFullFrame(t *testing.T) {
	emulator, err := newSSHTerminalEmulator(12, 3)
	if err != nil {
		t.Fatal(err)
	}
	_ = emulator.initialFrame()

	frame := emulator.resize(8, 2)
	if frame == nil || !frame.Full || frame.Columns != 8 || frame.Rows != 2 || len(frame.Cells) != 16 {
		t.Fatalf("resize did not return a complete frame: %#v", frame)
	}
	if !frame.ScrollbackReset {
		t.Fatal("resize did not reset scrollback")
	}
}

func TestSSHTerminalEmulatorPublishesScrollbackRows(t *testing.T) {
	emulator, err := newSSHTerminalEmulator(12, 3)
	if err != nil {
		t.Fatal(err)
	}
	_ = emulator.initialFrame()

	frame, changed, err := emulator.write([]byte("one\r\ntwo\r\nthree\r\nfour\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || frame == nil || len(frame.Scrollback) == 0 {
		t.Fatalf("scrollback was not published: frame=%#v changed=%v", frame, changed)
	}
	if !strings.Contains(strings.Join(scrollbackLineTexts(frame.Scrollback), "\n"), "one") {
		t.Fatalf("scrollback did not retain the first scrolled row: %#v", frame.Scrollback)
	}

	frame, changed, err = emulator.write([]byte("five\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || frame == nil || len(frame.Scrollback) != 1 || scrollbackLineText(frame.Scrollback[0]) != "three" {
		t.Fatalf("incremental scrollback was not published: frame=%#v changed=%v", frame, changed)
	}
}

func TestSSHTerminalEmulatorPreservesScrollbackColors(t *testing.T) {
	emulator, err := newSSHTerminalEmulator(12, 3)
	if err != nil {
		t.Fatal(err)
	}
	_ = emulator.initialFrame()

	if _, _, err := emulator.write([]byte("\x1b[31")); err != nil {
		t.Fatal(err)
	}
	frame, changed, err := emulator.write([]byte("mred\r\n\x1b[32mgreen\r\n\x1b[34mblue\r\n\x1b[0mplain\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || frame == nil || len(frame.Scrollback) != 2 {
		t.Fatalf("colored scrollback was not published: frame=%#v changed=%v", frame, changed)
	}
	if scrollbackLineText(frame.Scrollback[0]) != "red" ||
		len(frame.Scrollback[0].Runs) != 1 ||
		frame.Scrollback[0].Runs[0].Foreground != uint16(vt10x.Red) {
		t.Fatalf("red scrollback lost its style: %#v", frame.Scrollback[0])
	}
	if scrollbackLineText(frame.Scrollback[1]) != "green" ||
		len(frame.Scrollback[1].Runs) != 1 ||
		frame.Scrollback[1].Runs[0].Foreground != uint16(vt10x.Green) {
		t.Fatalf("green scrollback lost its style: %#v", frame.Scrollback[1])
	}
}

func TestSSHTerminalEmulatorResetClearsScrollback(t *testing.T) {
	emulator, err := newSSHTerminalEmulator(12, 3)
	if err != nil {
		t.Fatal(err)
	}
	_ = emulator.initialFrame()
	if _, _, err := emulator.write([]byte("one\r\ntwo\r\nthree\r\nfour\r\n")); err != nil {
		t.Fatal(err)
	}

	frame, changed, err := emulator.write([]byte("\x1bc"))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || frame == nil || !frame.ScrollbackReset || len(frame.Scrollback) != 0 {
		t.Fatalf("terminal reset did not clear scrollback: frame=%#v changed=%v", frame, changed)
	}

	if _, _, err := emulator.write([]byte("one\r\ntwo\r\nthree\r\nfour\r\n")); err != nil {
		t.Fatal(err)
	}
	frame, changed, err = emulator.write([]byte("\x1bcnew-one\r\nnew-two\r\nnew-three\r\nnew-four\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || frame == nil || !frame.ScrollbackReset || len(frame.Scrollback) != 0 {
		t.Fatalf("reset followed by output retained stale scrollback: frame=%#v changed=%v", frame, changed)
	}
}

func TestSSHTerminalEmulatorClearScreenResetsViewportWithoutErasingScrollback(t *testing.T) {
	emulator, err := newSSHTerminalEmulator(12, 3)
	if err != nil {
		t.Fatal(err)
	}
	_ = emulator.initialFrame()
	if _, _, err := emulator.write([]byte("one\r\ntwo\r\nthree\r\nfour\r\n")); err != nil {
		t.Fatal(err)
	}
	if len(emulator.scrollback) == 0 {
		t.Fatal("test setup did not create scrollback")
	}

	if _, _, err := emulator.write([]byte("\x1b[H\x1b[")); err != nil {
		t.Fatal(err)
	}
	frame, changed, err := emulator.write([]byte("2Jprompt"))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || frame == nil || !frame.ViewportReset || frame.ScrollbackReset {
		t.Fatalf("clear screen did not reset only the viewport: frame=%#v changed=%v", frame, changed)
	}
	if len(emulator.scrollback) == 0 {
		t.Fatal("screen clear erased scrollback")
	}

	frame, changed, err = emulator.write([]byte(" next"))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || frame == nil || frame.ViewportReset || frame.ScrollbackReset {
		t.Fatalf("ordinary output after clear reset terminal state again: frame=%#v changed=%v", frame, changed)
	}

	frame, changed, err = emulator.write([]byte("\x1b[3J"))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || frame == nil || !frame.ViewportReset || !frame.ScrollbackReset || len(frame.Scrollback) != 0 {
		t.Fatalf("scrollback erase did not reset scrollback: frame=%#v changed=%v", frame, changed)
	}
}

func TestSSHTerminalEmulatorClearScreenPublishesViewportResetWithoutScreenChanges(t *testing.T) {
	emulator, err := newSSHTerminalEmulator(12, 3)
	if err != nil {
		t.Fatal(err)
	}
	_ = emulator.initialFrame()

	if _, _, err := emulator.write([]byte("\x1b[H\x1b[2J")); err != nil {
		t.Fatal(err)
	}
	frame, changed, err := emulator.write([]byte("\x1b[H\x1b[2J"))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || frame == nil || !frame.ViewportReset || frame.ScrollbackReset {
		t.Fatalf("repeated clear did not publish a viewport reset: frame=%#v changed=%v", frame, changed)
	}

	frame, changed, err = emulator.write([]byte("\x1b[J"))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || frame == nil || !frame.ViewportReset || frame.ScrollbackReset {
		t.Fatalf("default clear did not publish a viewport reset: frame=%#v changed=%v", frame, changed)
	}
	frame, changed, err = emulator.write([]byte("after"))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || frame == nil || frame.ViewportReset || frame.ScrollbackReset {
		t.Fatalf("default clear was detected again on later output: frame=%#v changed=%v", frame, changed)
	}
}

func TestSSHTerminalEmulatorBoundsScrollbackAndRebasesRecorder(t *testing.T) {
	emulator, err := newSSHTerminalEmulator(12, 3)
	if err != nil {
		t.Fatal(err)
	}
	_ = emulator.initialFrame()

	var output strings.Builder
	for index := 0; index < sshTerminalHistoryRebaseLines+100; index++ {
		output.WriteString("line\r\n")
	}
	frame, changed, err := emulator.write([]byte(output.String()))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || frame == nil {
		t.Fatalf("large output did not update the terminal: frame=%#v changed=%v", frame, changed)
	}
	if len(emulator.scrollback) > sshTerminalMaxScrollbackLines {
		t.Fatalf("scrollback exceeded its bound: %d", len(emulator.scrollback))
	}
	if emulator.historyLineCount >= sshTerminalHistoryRebaseLines {
		t.Fatalf("history recorder was not rebased: %d", emulator.historyLineCount)
	}
}

func TestSSHTerminalEmulatorPreservesChunkedLargeOutput(t *testing.T) {
	emulator, err := newSSHTerminalEmulator(32, 4)
	if err != nil {
		t.Fatal(err)
	}
	_ = emulator.initialFrame()

	var output strings.Builder
	output.WriteString("\x1b[31m")
	for index := 0; index < 6000; index++ {
		fmt.Fprintf(&output, "large-output-%05d\r\n", index)
	}
	output.WriteString("\x1b[0m")
	frame, changed, err := emulator.write([]byte(output.String()))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || frame == nil || !frame.ScrollbackReset {
		t.Fatalf("large output did not publish a rebased scrollback snapshot: frame=%#v changed=%v", frame, changed)
	}
	if len(frame.Scrollback) != sshTerminalMaxScrollbackLines {
		t.Fatalf("large output published the wrong scrollback size: got %d want %d", len(frame.Scrollback), sshTerminalMaxScrollbackLines)
	}
	if scrollbackLineText(frame.Scrollback[0]) != "large-output-00997" || scrollbackLineText(frame.Scrollback[len(frame.Scrollback)-1]) != "large-output-05996" {
		t.Fatalf("large output lost or duplicated rows: first=%q last=%q", frame.Scrollback[0], frame.Scrollback[len(frame.Scrollback)-1])
	}
	if len(frame.Scrollback[0].Runs) == 0 || frame.Scrollback[0].Runs[0].Foreground != uint16(vt10x.Red) {
		t.Fatalf("large output lost its color during history rebase: %#v", frame.Scrollback[0])
	}
}

func scrollbackLineText(line sshTerminalScrollbackLine) string {
	return sshTerminalScrollbackLineText(line)
}

func scrollbackLineTexts(lines []sshTerminalScrollbackLine) []string {
	text := make([]string, 0, len(lines))
	for _, line := range lines {
		text = append(text, scrollbackLineText(line))
	}
	return text
}

func TestSSHTerminalEmulatorDoesNotMixAlternateScreenIntoScrollback(t *testing.T) {
	emulator, err := newSSHTerminalEmulator(12, 3)
	if err != nil {
		t.Fatal(err)
	}
	_ = emulator.initialFrame()
	if _, _, err := emulator.write([]byte("one\r\ntwo\r\nthree\r\nfour\r\n")); err != nil {
		t.Fatal(err)
	}
	initialScrollback := len(emulator.scrollback)
	if initialScrollback == 0 {
		t.Fatal("test setup did not create scrollback")
	}

	frame, changed, err := emulator.write([]byte("\x1b[?1049h"))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || frame == nil || !frame.AlternateScreen || !frame.ViewportReset {
		t.Fatalf("entering alternate screen was not published: frame=%#v changed=%v", frame, changed)
	}
	if _, _, err := emulator.write([]byte("alt-one\r\nalt-two\r\nalt-three\r\nalt-four\r\n")); err != nil {
		t.Fatal(err)
	}
	if len(emulator.scrollback) != initialScrollback {
		t.Fatalf("alternate-screen output polluted scrollback: got %d want %d", len(emulator.scrollback), initialScrollback)
	}
	frame, changed, err = emulator.write([]byte("\x1b[?1049l"))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || frame == nil || frame.AlternateScreen || !frame.ViewportReset {
		t.Fatalf("leaving alternate screen was not published: frame=%#v changed=%v", frame, changed)
	}
	if len(emulator.scrollback) != initialScrollback {
		t.Fatalf("leaving alternate screen changed scrollback: got %d want %d", len(emulator.scrollback), initialScrollback)
	}
	frame, changed, err = emulator.write([]byte("\x1b[?1049halt-one\r\nhalt-two\r\nhalt-three\r\nhalt-four\r\n\x1b[?1049l"))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || frame == nil || frame.AlternateScreen || !frame.ViewportReset {
		t.Fatalf("combined alternate-screen transitions were not published in their final state: frame=%#v changed=%v", frame, changed)
	}
	if len(emulator.scrollback) != initialScrollback {
		t.Fatalf("combined alternate-screen output polluted scrollback: got %d want %d", len(emulator.scrollback), initialScrollback)
	}
}

func TestSSHTerminalFrameWireAlwaysIncludesAlternateScreen(t *testing.T) {
	emulator, err := newSSHTerminalEmulator(12, 3)
	if err != nil {
		t.Fatal(err)
	}

	assertAlternateScreen := func(frame *sshTerminalFrame, expected bool) {
		t.Helper()
		payload, err := json.Marshal(frame)
		if err != nil {
			t.Fatal(err)
		}
		var wire struct {
			AlternateScreen *bool `json:"alternate_screen"`
		}
		if err := json.Unmarshal(payload, &wire); err != nil {
			t.Fatal(err)
		}
		if wire.AlternateScreen == nil || *wire.AlternateScreen != expected {
			t.Fatalf("alternate_screen wire value = %v, want %t; payload=%s", wire.AlternateScreen, expected, payload)
		}
	}

	assertAlternateScreen(emulator.initialFrame(), false)
	frame, changed, err := emulator.write([]byte("\x1b[?1049h"))
	if err != nil || !changed || frame == nil {
		t.Fatalf("entering alternate screen was not published: frame=%#v changed=%v err=%v", frame, changed, err)
	}
	assertAlternateScreen(frame, true)
}

func TestSSHTerminalEmulatorIgnoresRedundantAlternateScreenExit(t *testing.T) {
	for name, chunks := range map[string][][]byte{
		"47":           {[]byte("\x1b[?47ltext")},
		"1047":         {[]byte("\x1b[?1047ltext")},
		"1049":         {[]byte("\x1b[?1049ltext")},
		"1049 chunked": {[]byte("\x1b[?1049"), []byte("ltext")},
	} {
		t.Run(name, func(t *testing.T) {
			emulator, err := newSSHTerminalEmulator(12, 3)
			if err != nil {
				t.Fatal(err)
			}
			_ = emulator.initialFrame()
			for _, chunk := range chunks {
				if _, _, err := emulator.write(chunk); err != nil {
					t.Fatal(err)
				}
			}

			frame := emulator.snapshot()
			if frame.AlternateScreen {
				t.Fatalf("redundant alternate-screen exit activated the alternate screen: %#v", frame)
			}
			if text := frame.Cells[0].Character + frame.Cells[1].Character + frame.Cells[2].Character + frame.Cells[3].Character; text != "text" {
				t.Fatalf("output following redundant alternate-screen exit = %q, want text", text)
			}
		})
	}
}

func TestSSHTerminalEmulatorAlternateScreenDetectionHandlesChunksWithoutRepeating(t *testing.T) {
	emulator := &sshTerminalEmulator{}
	if transitions := emulator.alternateScreenTransitions([]byte("\x1b[?1049")); len(transitions) != 0 {
		t.Fatal("partial alternate-screen transition was reported too early")
	}
	transitions := emulator.alternateScreenTransitions([]byte("h"))
	if len(transitions) != 1 || transitions[0].end != 1 || !transitions[0].active {
		t.Fatal("split alternate-screen transition was not recognized")
	}
	if transitions := emulator.alternateScreenTransitions([]byte("later output")); len(transitions) != 0 {
		t.Fatal("alternate-screen transition repeated on later output")
	}
}

func TestSSHHistoryHelpersCoverColorsEscapesAndTextRows(t *testing.T) {
	var colors strings.Builder
	for _, test := range []struct {
		foreground bool
		color      uint16
	}{
		{true, uint16(vt10x.DefaultFG)}, {true, 3}, {true, 12}, {true, 200}, {true, 300},
		{false, uint16(vt10x.DefaultBG)}, {false, 4}, {false, 14}, {false, 201}, {false, 300},
	} {
		appendTerminalSgrColor(&colors, test.foreground, test.color)
	}
	for _, fragment := range []string{"\x1b[39m", "\x1b[33m", "\x1b[94m", "\x1b[38;5;200m", "\x1b[49m", "\x1b[44m", "\x1b[106m", "\x1b[48;5;201m"} {
		if !strings.Contains(colors.String(), fragment) {
			t.Fatalf("SGR seed %q is missing %q", colors.String(), fragment)
		}
	}

	emulator := &sshTerminalEmulator{columns: 2}
	sequences := [][]byte{
		{0x1b}, {'['}, {'3'}, {'1'}, {'m'},
		{0x1b}, {']'}, {'t'}, {0x07},
		{0x1b}, {'P'}, {'x'}, {0x1b}, {'\\'},
		{0x1b}, {0x1b}, {'x'},
		{0x1b}, {'['}, {0x1b}, {'x'},
	}
	for _, sequence := range sequences {
		emulator.updateHistoryEscapeMode(sequence)
	}
	if emulator.historyEscapeMode != sshTerminalHistoryEscapeNone {
		t.Fatalf("history escape parser ended in mode %d", emulator.historyEscapeMode)
	}
	if emulator.historyInputUnitLength(nil) != 0 || emulator.historyInputUnitLength([]byte{0x1b, '['}) != 1 {
		t.Fatal("history input control boundary was invalid")
	}
	if length := emulator.historyInputUnitLength([]byte("éabc")); length != len([]byte("éa")) {
		t.Fatalf("history UTF-8 unit length = %d", length)
	}
	if !historyUnitIsControl([]byte{0x7f}) || historyUnitIsControl([]byte("x")) || historyUnitIsControl(nil) {
		t.Fatal("history control classification was invalid")
	}

	line := sshTerminalScrollbackLineFromCells([]sshTerminalCell{
		{Character: "A", Foreground: 1, Background: 2},
		{Character: "", Foreground: 1, Background: 2},
		{Character: "B", Foreground: 3, Background: 4},
		{Character: " "},
	})
	if text := sshTerminalScrollbackLineText(line); text != "A B" || len(line.Runs) != 2 || line.Runs[0].Cells != 2 {
		t.Fatalf("scrollback line = %#v / %q", line, text)
	}
	textLine := sshTerminalScrollbackLineFromText("hé")
	if len(textLine.Runs) != 1 || textLine.Runs[0].Cells != 2 || sshTerminalScrollbackLineFromText("").Runs != nil {
		t.Fatalf("text scrollback line = %#v", textLine)
	}
	if !sshTerminalScrollbackRowsMatch([]sshTerminalScrollbackLine{textLine}, []string{"hé"}) ||
		sshTerminalScrollbackRowsMatch([]sshTerminalScrollbackLine{textLine}, nil) ||
		sshTerminalScrollbackRowsMatch([]sshTerminalScrollbackLine{textLine}, []string{"other"}) {
		t.Fatal("scrollback row comparison did not enforce exact text")
	}
}
