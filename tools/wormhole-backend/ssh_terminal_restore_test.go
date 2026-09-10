package main

import (
	"fmt"
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
