package vt10x

import (
	"fmt"
	"testing"
)

func cursorTestTerminal(t *testing.T) (*State, *VT, func(string)) {
	t.Helper()
	state := &State{}
	term, err := Create(state, nil)
	if err != nil {
		t.Fatal(err)
	}
	term.Resize(40, 12)
	return state, term, func(data string) {
		t.Helper()
		if _, err := term.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
}

func assertCursor(t *testing.T, state *State, wantX, wantY int) {
	t.Helper()
	if x, y := state.Cursor(); x != wantX || y != wantY {
		t.Fatalf("cursor = (%d, %d), want (%d, %d)", x, y, wantX, wantY)
	}
}

func TestSavedCursorBelongsToScreen(t *testing.T) {
	for _, mode := range []int{47, 1047, 1049} {
		for _, control := range []struct{ name, save, restore string }{
			{"DEC", "\x1b7", "\x1b8"},
			{"ANSI", "\x1b[s", "\x1b[u"},
			{"1048", "\x1b[?1048h", "\x1b[?1048l"},
		} {
			t.Run(fmt.Sprintf("%d/%s", mode, control.name), func(t *testing.T) {
				state, _, write := cursorTestTerminal(t)
				write("\x1b[4;6H" + control.save)
				write(fmt.Sprintf("\x1b[?%dh", mode))
				write("\x1b[8;9H" + control.save + "\x1b[H" + control.restore)
				assertCursor(t, state, 8, 7)
				write(fmt.Sprintf("\x1b[?%dl", mode))
				if mode == 1049 {
					assertCursor(t, state, 5, 3)
				}
				write(control.restore)
				assertCursor(t, state, 5, 3)
				write(fmt.Sprintf("\x1b[?%dh", mode) + control.restore)
				assertCursor(t, state, 8, 7)
			})
		}
	}
}

func TestEditorExitRestoresCursorRenditionAndOrigin(t *testing.T) {
	state, _, write := cursorTestTerminal(t)
	write("\x1b[2;10r\x1b[?6h\x1b[3;6H\x1b[31;44m\x1b[?1049h")
	write("\x1b[?6l\x1b[8;9H\x1b[32;45m\x1b7\x1b[H\x1b[?1049l")
	assertCursor(t, state, 5, 3)
	write("\x1b[1;1HX")
	char, foreground, background := state.Cell(0, 1)
	if char != 'X' || foreground != Red || background != Blue {
		t.Fatalf("shell cursor lost origin or rendition: char=%q fg=%d bg=%d", char, foreground, background)
	}
}

func TestRepeatedEditorTransitionsPreserveNormalCursor(t *testing.T) {
	state, _, write := cursorTestTerminal(t)
	write("\x1b[4;6H\x1b[?1049h\x1b[8;9H\x1b7\x1b[?1049h\x1b[?1049l")
	assertCursor(t, state, 5, 3)
	write("\x1b[?1049l")
	assertCursor(t, state, 5, 3)
	if state.Mode(ModeAltScreen) {
		t.Fatal("redundant editor exit switched to the alternate screen")
	}
}

func TestResetClearsBothSavedCursors(t *testing.T) {
	for _, screen := range []int{47, 1047, 1049} {
		t.Run(fmt.Sprint(screen), func(t *testing.T) {
			state, _, write := cursorTestTerminal(t)
			write("\x1b[4;6H\x1b[31;44m\x1b7\x1b[?1049h\x1b[8;9H\x1b[32;45m\x1b7\x1bc\x1b8")
			assertCursor(t, state, 0, 0)
			write("N")
			_, foreground, background := state.Cell(0, 0)
			if foreground != DefaultFG || background != DefaultBG {
				t.Fatal("reset retained the saved normal rendition")
			}
			write(fmt.Sprintf("\x1b[?%dh\x1b8", screen))
			assertCursor(t, state, 0, 0)
			write("A")
			_, foreground, background = state.Cell(0, 0)
			if foreground != DefaultFG || background != DefaultBG {
				t.Fatal("reset retained the saved alternate rendition")
			}
		})
	}
}

func TestEditorExitClampsSavedCursorAfterResize(t *testing.T) {
	state, term, write := cursorTestTerminal(t)
	write("\x1b[12;40H\x1b[?1049h\x1b[2;3H\x1b7")
	term.Resize(20, 6)
	write("\x1b[?1049l")
	assertCursor(t, state, 19, 5)
	write("X")
	if char, _, _ := state.Cell(19, 5); char != 'X' {
		t.Fatal("output after editor resize missed the restored cursor")
	}
}

func TestSavedCursorsStayClampedAfterGrowingAgain(t *testing.T) {
	state, term, write := cursorTestTerminal(t)
	write("\x1b[12;40H\x1b[?1049h\x1b[11;31H\x1b7\x1b[H")
	term.Resize(20, 6)
	term.Resize(40, 12)
	write("\x1b[?1049l")
	assertCursor(t, state, 19, 5)
	write("\x1b[?47h\x1b8")
	assertCursor(t, state, 19, 5)
}

func TestInvalidOrUnchangedResizePreservesBothSavedCursors(t *testing.T) {
	state, term, write := cursorTestTerminal(t)
	write("\x1b[4;6H\x1b[?1049h\x1b[8;9H\x1b7")
	for _, size := range [][2]int{{40, 12}, {0, 6}, {20, 0}, {-1, 6}, {20, -1}} {
		term.Resize(size[0], size[1])
		if rows, cols := state.Size(); rows != 12 || cols != 40 {
			t.Fatalf("no-op resize changed size to %dx%d", cols, rows)
		}
	}
	write("\x1b[H\x1b8")
	assertCursor(t, state, 8, 7)
	write("\x1b[?1049l")
	assertCursor(t, state, 5, 3)
}

func TestRepeated1049EntrySavesTheEditorCursorBeforeClearing(t *testing.T) {
	state, _, write := cursorTestTerminal(t)
	write("\x1b[4;6H\x1b[?1049h\x1b[8;9H\x1b7\x1b[10;11H\x1b[?1049h\x1b[H\x1b8")
	assertCursor(t, state, 10, 9)
	write("\x1b[?1049l")
	assertCursor(t, state, 5, 3)
}

func TestAlternateScreenClearContracts(t *testing.T) {
	for _, mode := range []int{47, 1047} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			state, _, write := cursorTestTerminal(t)
			write(fmt.Sprintf("N\x1b[?%dh\x1b[HA\x1b[?%dh", mode, mode))
			if char, _, _ := state.Cell(0, 0); char != 'A' {
				t.Fatal("selecting the active alternate buffer erased the editor")
			}
			write(fmt.Sprintf("\x1b[?%dl", mode))
			if char, _, _ := state.Cell(0, 0); char != 'N' {
				t.Fatal("leaving the alternate buffer erased the shell")
			}
			write("\x1b[?47h")
			want := 'A'
			if mode == 1047 {
				want = ' '
			}
			if char, _, _ := state.Cell(0, 0); char != want {
				t.Fatalf("mode %d exit retained %q, want %q", mode, char, want)
			}
			write("\x1b[?47l\x1b[?1049h")
			if char, _, _ := state.Cell(0, 0); char != ' ' {
				t.Fatal("1049 entry did not clear retained alternate content")
			}
		})
	}
}

func TestEditorEntryAfterResetStartsWithAClearScreen(t *testing.T) {
	state, _, write := cursorTestTerminal(t)
	write("old shell\x1b[?1049h\x1bc\x1b[?1049h")
	for y := 0; y < 12; y++ {
		for x := 0; x < 40; x++ {
			if char, _, _ := state.Cell(x, y); char != ' ' {
				t.Fatalf("editor entry exposed old buffer text %q at (%d, %d)", char, x, y)
			}
		}
	}
}

func TestResetClearsEveryCellInBothScreens(t *testing.T) {
	for _, size := range [][2]int{{40, 12}, {12, 40}, {1, 1}} {
		for _, resetInEditor := range []bool{false, true} {
			t.Run(fmt.Sprintf("%dx%d/editor-%t", size[0], size[1], resetInEditor), func(t *testing.T) {
				state, term, write := cursorTestTerminal(t)
				term.Resize(size[0], size[1])
				lastCell := fmt.Sprintf("\x1b[%d;%dH", size[1], size[0])
				write(lastCell + "N\x1b[?47h" + lastCell + "A")
				if !resetInEditor {
					write("\x1b[?47l")
				}
				write("\x1bc")
				if state.Mode(ModeAltScreen) {
					t.Fatal("reset did not return to the normal buffer")
				}
				for screen := 0; screen < 2; screen++ {
					assertCursor(t, state, 0, 0)
					for y := 0; y < size[1]; y++ {
						for x := 0; x < size[0]; x++ {
							char, foreground, background := state.Cell(x, y)
							if char != ' ' || foreground != DefaultFG || background != DefaultBG {
								t.Fatalf("reset left stale cell %q in screen %d at (%d,%d)", char, screen, x, y)
							}
						}
					}
					write("\x1b[?47h")
				}
			})
		}
	}
}
