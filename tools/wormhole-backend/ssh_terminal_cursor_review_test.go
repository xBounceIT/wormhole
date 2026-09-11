package main

import (
	"fmt"
	"slices"
	"testing"
)

func TestSSHTerminalEditorResizeKeepsShellCursorWithItsText(t *testing.T) {
	for _, shellRow := range []int{1, 8, 11} {
		for _, editorRow := range []int{1, 11} {
			for _, growAgain := range []bool{false, true} {
				t.Run(fmt.Sprintf("shell-%d/editor-%d/grow-%t", shellRow, editorRow, growAgain), func(t *testing.T) {
					terminal, err := newSSHTerminalEmulator(40, 12)
					if err != nil {
						t.Fatal(err)
					}
					write := func(data string) {
						t.Helper()
						for chunk := range slices.Chunk([]byte(data), 7) {
							if _, _, err := terminal.write(chunk); err != nil {
								t.Fatal(err)
							}
						}
					}
					write(fmt.Sprintf("\x1b[%d;1Hshell$ \x1b[?1049h\x1b[%d;1Heditor\x1b7", shellRow+1, editorRow+1))
					frame := terminal.resize(20, 6)
					if !frame.Full || !frame.ViewportReset || !frame.AlternateScreen {
						t.Fatal("resizing the editor lost its active viewport")
					}
					if growAgain {
						terminal.resize(40, 12)
					}
					write("\x1b[?1049lX")
					frame = terminal.snapshot()
					wantRow := min(shellRow, 5)
					if frame.AlternateScreen || frame.CursorX != 8 || frame.CursorY != wantRow {
						t.Fatalf("shell cursor = (%d, %d), want (8, %d)", frame.CursorX, frame.CursorY, wantRow)
					}
					start := wantRow * frame.Columns
					if line := scrollbackLineText(sshTerminalScrollbackLineFromCells(frame.Cells[start : start+frame.Columns])); line != "shell$ X" {
						t.Fatalf("resized shell cursor no longer matches its text: %q", line)
					}
				})
			}
		}
	}
}
