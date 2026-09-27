package main

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestSSHTerminalProgressFramesKeepBlankHistorySerializable(t *testing.T) {
	var output strings.Builder
	output.WriteString("Summary:\r\n\r\nInstalling packages\r\n")
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&output, "\rGet:%d package download [532 kB]\r\x1b[KFetched package %d\r\n", i, i)
		output.WriteString("\x1b7\x1b[1;5r\x1b8")
		fmt.Fprintf(&output, "\x1b7\x1b[6;1H\x1b[42mProgress: [%d%%]\x1b[0m\x1b[K\x1b8", i)
		output.WriteString("Unpacking package…\r\n\r\n")
	}
	output.WriteString("\x1b[r\x1b[6;1H\r\x1b[KDone\r\nroot# ")
	for _, chunkSize := range []int{1, 7, 64, 4096} {
		t.Run(fmt.Sprint(chunkSize), func(t *testing.T) {
			terminal, err := newSSHTerminalEmulator(80, 6)
			if err != nil {
				t.Fatal(err)
			}
			cells := terminal.initialFrame().Cells
			blankLines := 0
			for chunk := range slices.Chunk([]byte(output.String()), chunkSize) {
				frame, _, err := terminal.write(chunk)
				if err != nil {
					t.Fatal(err)
				}
				if frame == nil {
					continue
				}
				wire, err := json.Marshal(frame)
				if err != nil {
					t.Fatal(err)
				}
				var decoded sshTerminalFrame
				if err := json.Unmarshal(wire, &decoded); err != nil {
					t.Fatal(err)
				}
				for _, line := range decoded.Scrollback {
					if line.Runs == nil {
						t.Fatal("blank history serialized as null; Electron rejects the entire screen update")
					}
					if len(line.Runs) == 0 {
						blankLines++
					}
				}
				if decoded.Full {
					cells = decoded.Cells
				}
				for _, change := range decoded.Changes {
					cells[change.Index] = sshTerminalCell{Character: change.Character, Foreground: change.Foreground, Background: change.Background}
				}
			}
			if blankLines == 0 {
				t.Fatal("fixture did not scroll any blank lines")
			}
			if !slices.Equal(cells, terminal.snapshot().Cells) {
				t.Fatal("rendered progress deltas differ from the terminal screen")
			}
		})
	}
}
