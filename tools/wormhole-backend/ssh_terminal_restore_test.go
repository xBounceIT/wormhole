package main

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestSSHTerminalEmulatorRestoresClearedShellAfterEditor(t *testing.T) {
	for _, chunkSize := range []int{1, 7, 4096} {
		t.Run(fmt.Sprintf("chunk-%d", chunkSize), func(t *testing.T) {
			emulator, err := newSSHTerminalEmulator(40, 6)
			if err != nil {
				t.Fatal(err)
			}
			write := func(data string) {
				t.Helper()
				for len(data) > 0 {
					length := min(chunkSize, len(data))
					if _, _, err := emulator.write([]byte(data[:length])); err != nil {
						t.Fatal(err)
					}
					data = data[length:]
				}
			}
			write("old-one\r\nold-two\r\nold-three\r\nold-four\r\nold-five\r\nold-six\r\n$ ")
			// Readline clears the viewport on Ctrl+L before redrawing the command line.
			write("\x1b[H\x1b[2J$ nano example.txt\r\n\x1b[?2004l")
			before := emulator.snapshot()
			write("\x1b[?1049h\x1b[22;0;0t\x1b[1;6r\x1b(B\x1b[m\x1b[?7h\x1b[H\x1b[2JGNU nano\x1b[3;1Heditor content")
			// Ctrl+L inside the editor redraws its buffer without changing the shell.
			write("\x1b[H\x1b[2JGNU nano\x1b[3;1Heditor content")
			write("\x1b[6;1H\x1b[?1049l\x1b[23;0;0t\r\x1b[?1l\x1b>")
			after := emulator.snapshot()
			if after.AlternateScreen || !slices.Equal(before.Cells, after.Cells) {
				t.Fatal("leaving the editor did not restore the cleared shell screen")
			}
			if after.CursorX != before.CursorX || after.CursorY != before.CursorY {
				t.Fatalf("shell cursor = (%d, %d), want (%d, %d)", after.CursorX, after.CursorY, before.CursorX, before.CursorY)
			}
		})
	}
}

func TestSSHTerminalEmulatorRestoresShellCursorAfterEditorScroll(t *testing.T) {
	for name, cursor := range map[string]struct{ save, restore string }{
		"DEC":  {"\x1b7", "\x1b8"},
		"ANSI": {"\x1b[s", "\x1b[u"},
		"1048": {"\x1b[?1048h", "\x1b[?1048l"},
	} {
		for _, chunkSize := range []int{1, 7, 4096} {
			t.Run(fmt.Sprintf("%s/chunk-%d", name, chunkSize), func(t *testing.T) {
				emulator, err := newSSHTerminalEmulator(40, 12)
				if err != nil {
					t.Fatal(err)
				}
				write := func(data string) {
					t.Helper()
					for chunk := range slices.Chunk([]byte(data), chunkSize) {
						if _, _, err := emulator.write(chunk); err != nil {
							t.Fatal(err)
						}
					}
				}
				write(strings.Repeat("old output\r\n", 20) + "\x1b[H\x1b[2J$ nano example.txt\r\n")
				before := emulator.snapshot()
				write("\x1b[?1049h\x1b[H\x1b[2JGNU nano\x1b[3;1Heditor content")
				for page := 0; page < 30; page++ {
					// ncurses saves/restores the editor cursor around scrolling-region
					// changes. That save must not replace the shell's saved cursor.
					write("\x1b[8;7H" + cursor.save + "\x1b[3;10r\x1b[10;1H\n\x1b[1;12r" + cursor.restore)
					frame := emulator.snapshot()
					if frame.CursorX != 6 || frame.CursorY != 7 {
						t.Fatalf("editor cursor = (%d, %d), want (6, 7)", frame.CursorX, frame.CursorY)
					}
				}
				write("\x1b[12;1H\x1b[?1049l\r")
				after := emulator.snapshot()
				if after.AlternateScreen || !slices.Equal(before.Cells, after.Cells) ||
					!slices.Equal(scrollbackLineTexts(before.Scrollback), scrollbackLineTexts(after.Scrollback)) {
					t.Fatal("editor scroll changed the restored shell screen or scrollback")
				}
				if after.CursorX != before.CursorX || after.CursorY != before.CursorY {
					t.Fatalf("shell cursor = (%d, %d), want (%d, %d)", after.CursorX, after.CursorY, before.CursorX, before.CursorY)
				}
			})
		}
	}
}

func TestSSHTerminalReplaysNanoScrollCapture(t *testing.T) {
	data, err := os.ReadFile("testdata/terminal/nano-scroll.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Columns uint32 `json:"columns"`
		Rows    uint32 `json:"rows"`
		Output  string `json:"output"`
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	for name, shell := range map[string]string{
		"cleared shell with history": strings.Repeat("old output\r\n", 60) + "\x1b[H\x1b[2J$ nano example.txt\r\n",
		"uncleared shell":            "previous command\r\noutput\r\n$ nano example.txt\r\n",
	} {
		for _, chunkSize := range []int{1, 7, 4096, len(capture.Output)} {
			t.Run(fmt.Sprintf("%s/chunk-%d", name, chunkSize), func(t *testing.T) {
				emulator, err := newSSHTerminalEmulator(capture.Columns, capture.Rows)
				if err != nil {
					t.Fatal(err)
				}
				write := func(data string) {
					t.Helper()
					for chunk := range slices.Chunk([]byte(data), chunkSize) {
						if _, _, err := emulator.write(chunk); err != nil {
							t.Fatal(err)
						}
					}
				}
				write(shell)
				before := emulator.snapshot()
				for session := 1; session <= 3; session++ {
					write(capture.Output)
					after := emulator.snapshot()
					if after.AlternateScreen || !after.CursorVisible || after.ApplicationCursor ||
						!slices.Equal(before.Cells, after.Cells) ||
						!slices.Equal(scrollbackLineTexts(before.Scrollback), scrollbackLineTexts(after.Scrollback)) {
						t.Fatal("nano capture did not restore the shell screen, modes and scrollback")
					}
					if after.CursorX != 0 || after.CursorY != before.CursorY {
						t.Fatalf("shell cursor after session %d = (%d, %d), want (0, %d)",
							session, after.CursorX, after.CursorY, before.CursorY)
					}
				}
				write("$ echo restored")
				after := emulator.snapshot()
				start := before.CursorY * after.Columns
				if got := scrollbackLineText(sshTerminalScrollbackLineFromCells(after.Cells[start : start+after.Columns])); got != "$ echo restored" {
					t.Fatalf("next shell command painted on the wrong row: %q", got)
				}
			})
		}
	}
}

func TestSSHTerminalViewportResetRepairsStaleRenderedCells(t *testing.T) {
	for name, redraw := range map[string]struct{ before, reset string }{
		"readline clear":       {reset: "\x1b[H\x1b[2J$ "},
		"zero-padded clear":    {reset: "\x1b[H\x1b[02J$ "},
		"default erase":        {reset: "\x1b[H\x1b[J$ "},
		"explicit erase":       {reset: "\x1b[H\x1b[0J$ "},
		"chunked clear":        {before: "\x1b[H\x1b[2", reset: "J$ "},
		"editor entry":         {reset: "\x1b[?1049h\x1b[H\x1b[2Jnano"},
		"editor redraw":        {before: "\x1b[?1049h\x1b[H\x1b[2Jnano", reset: "\x1b[H\x1b[2Jnano"},
		"editor exit":          {before: "\x1b[?1049h\x1b[H\x1b[2Jnano", reset: "\x1b[?1049l"},
		"chunked editor exit":  {before: "\x1b[?1049h\x1b[H\x1b[2Jnano\x1b[?1049", reset: "l"},
		"combined editor exit": {reset: "\x1b[?1049h\x1b[H\x1b[2Jnano\x1b[?1049l"},
	} {
		t.Run(name, func(t *testing.T) {
			emulator, err := newSSHTerminalEmulator(40, 6)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := emulator.write([]byte(strings.Repeat("old output\r\n", 8))); err != nil {
				t.Fatal(err)
			}
			stale := emulator.snapshot()
			history := scrollbackLineTexts(stale.Scrollback)
			// The renderer missed this earlier clear. A redraw must repair even the
			// blank cells that have not changed in the backend since that clear.
			if _, _, err := emulator.write([]byte("\x1b[H\x1b[2J$ ")); err != nil {
				t.Fatal(err)
			}
			if _, _, err := emulator.write([]byte(redraw.before)); err != nil {
				t.Fatal(err)
			}
			frame, changed, err := emulator.write([]byte(redraw.reset))
			if err != nil || !changed || frame == nil || !frame.ViewportReset {
				t.Fatalf("redraw was not published: frame=%#v changed=%v err=%v", frame, changed, err)
			}
			rendered := slices.Clone(stale.Cells)
			if frame.Full {
				rendered = slices.Clone(frame.Cells)
			}
			for _, change := range frame.Changes {
				rendered[change.Index] = sshTerminalCell{
					Character: change.Character, Foreground: change.Foreground, Background: change.Background,
				}
			}
			expected := emulator.snapshot()
			if !slices.Equal(rendered, expected.Cells) {
				t.Fatal("redraw left old output visible around the current cursor")
			}
			if frame.CursorX != expected.CursorX || frame.CursorY != expected.CursorY || frame.AlternateScreen != expected.AlternateScreen {
				t.Fatal("redraw did not pair the screen with its current cursor and buffer")
			}
			if frame.ScrollbackReset || len(frame.Scrollback) != 0 || !slices.Equal(history, scrollbackLineTexts(expected.Scrollback)) {
				t.Fatal("viewport redraw discarded or resent retained scrollback")
			}
		})
	}
}
