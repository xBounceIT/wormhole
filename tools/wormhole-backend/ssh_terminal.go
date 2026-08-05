package main

import (
	"bytes"
	"fmt"
	"strings"
	"unicode/utf8"

	vt10x "github.com/ActiveState/vt10x"
)

const (
	sshTerminalMaxCells           = sshMaxColumns * sshMaxRows
	sshTerminalMaxScrollbackLines = 5000
	sshTerminalHistoryRebaseLines = sshTerminalMaxScrollbackLines + 512
	sshTerminalHistoryWriteChunk  = 1024
)

// sshTerminalCell is the renderer-neutral representation of one terminal cell.
// The ANSI parser and all cursor/screen state live in Go; the renderer only paints
// these already-interpreted cells.
type sshTerminalCell struct {
	Character  string `json:"character"`
	Foreground uint16 `json:"foreground"`
	Background uint16 `json:"background"`
}

type sshTerminalCellChange struct {
	Index      int    `json:"index"`
	Character  string `json:"character"`
	Foreground uint16 `json:"foreground"`
	Background uint16 `json:"background"`
}

type sshTerminalFrame struct {
	Columns           int                     `json:"columns"`
	Rows              int                     `json:"rows"`
	Full              bool                    `json:"full,omitempty"`
	Cells             []sshTerminalCell       `json:"cells,omitempty"`
	Changes           []sshTerminalCellChange `json:"changes,omitempty"`
	ScrollbackReset   bool                    `json:"scrollback_reset,omitempty"`
	Scrollback        []string                `json:"scrollback,omitempty"`
	CursorX           int                     `json:"cursor_x"`
	CursorY           int                     `json:"cursor_y"`
	CursorVisible     bool                    `json:"cursor_visible"`
	ApplicationCursor bool                    `json:"application_cursor"`
	Title             string                  `json:"title,omitempty"`
	Sequence          uint64                  `json:"sequence"`
}

type sshTerminalEmulator struct {
	state        *vt10x.State
	vt           *vt10x.VT
	historyState *vt10x.State
	historyVT    *vt10x.VT

	columns int
	rows    int
	pending []byte

	historyLineCount int
	historyAltScreen bool
	scrollback       []string
	resetEscape      bool
	controlTail      []byte

	previousCells         []sshTerminalCell
	previousCursorX       int
	previousCursorY       int
	previousCursorVisible bool
	previousAppCursor     bool
	previousTitle         string
	sequence              uint64
}

func newSSHTerminalEmulator(columns, rows uint32) (*sshTerminalEmulator, error) {
	columns, rows = normalizeTerminalSize(columns, rows)
	state := &vt10x.State{}
	vt, err := vt10x.Create(state, nil)
	if err != nil {
		return nil, err
	}
	vt.Resize(int(columns), int(rows))
	historyState, historyVT, err := newSSHHistoryRecorder(int(columns), int(rows), nil, 0, 0, false)
	if err != nil {
		return nil, err
	}
	return &sshTerminalEmulator{
		state:        state,
		vt:           vt,
		historyState: historyState,
		historyVT:    historyVT,
		columns:      int(columns),
		rows:         int(rows),
	}, nil
}

func (terminal *sshTerminalEmulator) initialFrame() *sshTerminalFrame {
	return terminal.snapshot()
}

func (terminal *sshTerminalEmulator) snapshot() *sshTerminalFrame {
	terminal.state.Lock()
	frame, _ := terminal.snapshotLocked(true)
	terminal.state.Unlock()
	frame.ScrollbackReset = true
	frame.Scrollback = append([]string(nil), terminal.scrollback...)
	return frame
}

func (terminal *sshTerminalEmulator) resize(columns, rows uint32) *sshTerminalFrame {
	columns, rows = normalizeTerminalSize(columns, rows)
	terminal.vt.Resize(int(columns), int(rows))
	terminal.columns = int(columns)
	terminal.rows = int(rows)
	terminal.state.Lock()
	frame, _ := terminal.snapshotLocked(true)
	cells := append([]sshTerminalCell(nil), terminal.previousCells...)
	cursorX := terminal.previousCursorX
	cursorY := terminal.previousCursorY
	applicationCursor := terminal.previousAppCursor
	altScreen := terminal.state.Mode(vt10x.ModeAltScreen)
	terminal.state.Unlock()
	terminal.rebaseHistoryRecorder(cells, cursorX, cursorY, applicationCursor)
	terminal.historyLineCount = 0
	terminal.historyAltScreen = altScreen
	terminal.scrollback = nil
	frame.ScrollbackReset = true
	return frame
}

func (terminal *sshTerminalEmulator) write(data []byte) (*sshTerminalFrame, bool, error) {
	if len(data) == 0 {
		return nil, false, nil
	}

	terminal.pending = append(terminal.pending, data...)
	complete := completeUTF8Prefix(terminal.pending)
	if complete == 0 {
		return nil, false, nil
	}

	if _, err := terminal.vt.Write(terminal.pending[:complete]); err != nil {
		return nil, false, err
	}
	terminalReset := terminal.sawTerminalReset(terminal.pending[:complete])
	terminalAltTransition := terminal.sawAlternateScreenTransition(terminal.pending[:complete])
	var historyRows []string
	var historyReset bool
	if terminal.historyVT != nil {
		var err error
		historyRows, historyReset, err = terminal.writeHistory(
			terminal.pending[:complete],
			terminalReset || terminalAltTransition,
		)
		if err != nil {
			return nil, false, err
		}
	}
	terminal.pending = append(terminal.pending[:0], terminal.pending[complete:]...)

	terminal.state.Lock()
	frame, changed := terminal.snapshotLocked(false)
	cells := append([]sshTerminalCell(nil), terminal.previousCells...)
	cursorX := terminal.previousCursorX
	cursorY := terminal.previousCursorY
	applicationCursor := terminal.previousAppCursor
	altScreen := terminal.state.Mode(vt10x.ModeAltScreen)
	terminal.state.Unlock()

	scrollbackChanged, scrollbackReset, scrollback := terminal.updateScrollback(
		altScreen,
		terminalReset,
		terminalAltTransition,
		cells,
		cursorX,
		cursorY,
		applicationCursor,
	)
	if len(historyRows) > 0 {
		scrollbackChanged = true
		scrollback = append(historyRows, scrollback...)
	}
	if historyReset {
		scrollbackChanged = true
		scrollbackReset = true
	}
	if frame == nil && scrollbackChanged {
		terminal.state.Lock()
		frame, _ = terminal.snapshotLocked(true)
		terminal.state.Unlock()
		changed = true
	}
	if frame == nil {
		return nil, false, nil
	}
	frame.ScrollbackReset = scrollbackReset
	if scrollbackReset {
		frame.Scrollback = append([]string(nil), terminal.scrollback...)
	} else if len(scrollback) > 0 {
		frame.Scrollback = scrollback
	}
	return frame, changed || scrollbackChanged, nil
}

func completeUTF8Prefix(data []byte) int {
	for index := 0; index < len(data); {
		_, size := utf8.DecodeRune(data[index:])
		if size == 1 && data[index] >= utf8.RuneSelf && !utf8.FullRune(data[index:]) {
			return index
		}
		index += size
	}
	return len(data)
}

func (terminal *sshTerminalEmulator) snapshotLocked(forceFull bool) (*sshTerminalFrame, bool) {
	rows, columns := terminal.state.Size()
	if rows < 1 || columns < 1 || rows*columns > sshTerminalMaxCells {
		return nil, false
	}

	cells := make([]sshTerminalCell, rows*columns)
	for y := 0; y < rows; y++ {
		for x := 0; x < columns; x++ {
			character, foreground, background := terminal.state.Cell(x, y)
			if character == 0 {
				character = ' '
			}
			cells[y*columns+x] = sshTerminalCell{
				Character:  string(character),
				Foreground: uint16(foreground),
				Background: uint16(background),
			}
		}
	}

	cursorX, cursorY := terminal.state.Cursor()
	cursorVisible := terminal.state.CursorVisible()
	applicationCursor := terminal.state.Mode(vt10x.ModeAppCursor)
	title := terminal.state.Title()
	full := forceFull || len(terminal.previousCells) != len(cells)
	changes := make([]sshTerminalCellChange, 0)
	if !full {
		for index, cell := range cells {
			if terminal.previousCells[index] == cell {
				continue
			}
			changes = append(changes, sshTerminalCellChange{
				Index:      index,
				Character:  cell.Character,
				Foreground: cell.Foreground,
				Background: cell.Background,
			})
		}
	}

	changed := full || len(changes) > 0 ||
		cursorX != terminal.previousCursorX ||
		cursorY != terminal.previousCursorY ||
		cursorVisible != terminal.previousCursorVisible ||
		applicationCursor != terminal.previousAppCursor ||
		title != terminal.previousTitle
	terminal.previousCells = cells
	terminal.previousCursorX = cursorX
	terminal.previousCursorY = cursorY
	terminal.previousCursorVisible = cursorVisible
	terminal.previousAppCursor = applicationCursor
	terminal.previousTitle = title
	if !changed {
		return nil, false
	}

	terminal.sequence++
	frame := &sshTerminalFrame{
		Columns:           columns,
		Rows:              rows,
		Full:              full,
		CursorX:           cursorX,
		CursorY:           cursorY,
		CursorVisible:     cursorVisible,
		ApplicationCursor: applicationCursor,
		Title:             title,
		Sequence:          terminal.sequence,
	}
	if full {
		frame.Cells = cells
	} else {
		frame.Changes = changes
	}
	return frame, true
}

func newSSHHistoryRecorder(
	columns, rows int,
	cells []sshTerminalCell,
	cursorX, cursorY int,
	applicationCursor bool,
) (*vt10x.State, *vt10x.VT, error) {
	state := &vt10x.State{}
	vt, err := vt10x.Create(state, nil)
	if err != nil {
		return nil, nil, err
	}
	vt.Resize(columns, rows)
	state.RecordHistory = true
	if len(cells) != columns*rows {
		return state, vt, nil
	}

	var seed strings.Builder
	seed.Grow(columns*rows + rows*12 + 32)
	seed.WriteString("\x1b[2J\x1b[H")
	for y := 0; y < rows; y++ {
		fmt.Fprintf(&seed, "\x1b[%d;1H", y+1)
		for x := 0; x < columns; x++ {
			character := cells[y*columns+x].Character
			if character == "" {
				character = " "
			}
			seed.WriteString(character)
		}
	}
	cursorX = minInt(maxInt(cursorX, 0), columns-1)
	cursorY = minInt(maxInt(cursorY, 0), rows-1)
	fmt.Fprintf(&seed, "\x1b[%d;%dH", cursorY+1, cursorX+1)
	if applicationCursor {
		seed.WriteString("\x1b[?1h")
	} else {
		seed.WriteString("\x1b[?1l")
	}
	if _, err := vt.Write([]byte(seed.String())); err != nil {
		return nil, nil, err
	}
	return state, vt, nil
}

func (terminal *sshTerminalEmulator) rebaseHistoryRecorder(
	cells []sshTerminalCell,
	cursorX, cursorY int,
	applicationCursor bool,
) {
	state, vt, err := newSSHHistoryRecorder(
		terminal.columns,
		terminal.rows,
		cells,
		cursorX,
		cursorY,
		applicationCursor,
	)
	if err != nil {
		return
	}
	terminal.historyState = state
	terminal.historyVT = vt
	terminal.historyLineCount = 0
}

func (terminal *sshTerminalEmulator) writeHistory(
	data []byte,
	suppressScrollback bool,
) ([]string, bool, error) {
	var appended []string
	reset := false
	for offset := 0; offset < len(data); {
		end := minInt(offset+sshTerminalHistoryWriteChunk, len(data))
		for end < len(data) && !utf8.RuneStart(data[end]) {
			end++
		}
		if _, err := terminal.historyVT.Write(data[offset:end]); err != nil {
			return nil, false, err
		}
		rows, compactReset := terminal.compactHistoryRecorder(suppressScrollback)
		appended = append(appended, rows...)
		reset = reset || compactReset
		offset = end
	}
	return appended, reset, nil
}

func (terminal *sshTerminalEmulator) compactHistoryRecorder(
	suppressScrollback bool,
) ([]string, bool) {
	if terminal.historyState == nil {
		return nil, false
	}
	_, currentCursorY := terminal.historyState.Cursor()
	_, globalCursorY := terminal.historyState.GlobalCursor()
	historyLines := globalCursorY - currentCursorY
	if historyLines < 0 {
		historyLines = 0
	}
	if terminal.historyState.Mode(vt10x.ModeAltScreen) || terminal.historyAltScreen {
		if historyLines >= sshTerminalHistoryRebaseLines {
			cells, cursorX, cursorY, applicationCursor := terminal.historyRecorderSnapshot()
			terminal.rebaseHistoryRecorder(cells, cursorX, cursorY, applicationCursor)
			terminal.historyAltScreen = true
		}
		return nil, false
	}
	if historyLines < terminal.historyLineCount {
		cells, cursorX, cursorY, applicationCursor := terminal.historyRecorderSnapshot()
		terminal.rebaseHistoryRecorder(cells, cursorX, cursorY, applicationCursor)
		if suppressScrollback {
			return nil, false
		}
		terminal.scrollback = nil
		return nil, true
	}
	if historyLines < sshTerminalHistoryRebaseLines {
		return nil, false
	}

	rows, ok := terminal.historyRowsSince(historyLines)
	if !ok {
		cells, cursorX, cursorY, applicationCursor := terminal.historyRecorderSnapshot()
		terminal.rebaseHistoryRecorder(cells, cursorX, cursorY, applicationCursor)
		return nil, false
	}
	terminal.historyLineCount = historyLines
	reset, appended := terminal.appendScrollbackRows(rows)
	cells, cursorX, cursorY, applicationCursor := terminal.historyRecorderSnapshot()
	terminal.rebaseHistoryRecorder(cells, cursorX, cursorY, applicationCursor)
	return appended, reset
}

func (terminal *sshTerminalEmulator) historyRowsSince(historyLines int) ([]string, bool) {
	newLineCount := historyLines - terminal.historyLineCount
	if newLineCount < 0 {
		return nil, false
	}
	text := terminal.historyState.StringToCursorFrom(terminal.historyLineCount, 0)
	rows := strings.Split(text, "\n")
	if newLineCount > len(rows) {
		return nil, false
	}
	newRows := make([]string, 0, newLineCount)
	for _, row := range rows[:newLineCount] {
		newRows = append(newRows, strings.TrimRight(row, " "))
	}
	return newRows, true
}

func (terminal *sshTerminalEmulator) appendScrollbackRows(rows []string) (bool, []string) {
	if len(rows) == 0 {
		return false, nil
	}
	terminal.scrollback = append(terminal.scrollback, rows...)
	if len(terminal.scrollback) > sshTerminalMaxScrollbackLines {
		overflow := len(terminal.scrollback) - sshTerminalMaxScrollbackLines
		terminal.scrollback = append([]string(nil), terminal.scrollback[overflow:]...)
		return true, nil
	}
	return false, rows
}

func (terminal *sshTerminalEmulator) historyRecorderSnapshot() (
	[]sshTerminalCell,
	int,
	int,
	bool,
) {
	terminal.historyState.Lock()
	rows, columns := terminal.historyState.Size()
	cells := make([]sshTerminalCell, rows*columns)
	for y := 0; y < rows; y++ {
		for x := 0; x < columns; x++ {
			character, foreground, background := terminal.historyState.Cell(x, y)
			if character == 0 {
				character = ' '
			}
			cells[y*columns+x] = sshTerminalCell{
				Character:  string(character),
				Foreground: uint16(foreground),
				Background: uint16(background),
			}
		}
	}
	cursorX, cursorY := terminal.historyState.Cursor()
	applicationCursor := terminal.historyState.Mode(vt10x.ModeAppCursor)
	terminal.historyState.Unlock()
	return cells, cursorX, cursorY, applicationCursor
}

func (terminal *sshTerminalEmulator) updateScrollback(
	altScreen bool,
	terminalReset bool,
	alternateScreenTransition bool,
	cells []sshTerminalCell,
	cursorX, cursorY int,
	applicationCursor bool,
) (changed, reset bool, appended []string) {
	if terminal.historyState == nil {
		terminal.rebaseHistoryRecorder(cells, cursorX, cursorY, applicationCursor)
	}
	if terminal.historyState == nil {
		return false, false, nil
	}
	if terminalReset {
		terminal.scrollback = nil
		terminal.rebaseHistoryRecorder(cells, cursorX, cursorY, applicationCursor)
		terminal.historyAltScreen = altScreen
		return true, true, nil
	}
	if alternateScreenTransition {
		terminal.rebaseHistoryRecorder(cells, cursorX, cursorY, applicationCursor)
		terminal.historyAltScreen = altScreen
		return false, false, nil
	}
	if altScreen {
		if !terminal.historyAltScreen {
			terminal.rebaseHistoryRecorder(cells, cursorX, cursorY, applicationCursor)
			terminal.historyAltScreen = true
		}
		return false, false, nil
	}
	if terminal.historyAltScreen {
		terminal.rebaseHistoryRecorder(cells, cursorX, cursorY, applicationCursor)
		terminal.historyAltScreen = false
		return false, false, nil
	}

	_, currentCursorY := terminal.historyState.Cursor()
	_, globalCursorY := terminal.historyState.GlobalCursor()
	historyLines := globalCursorY - currentCursorY
	if historyLines < 0 {
		historyLines = 0
	}
	if historyLines < terminal.historyLineCount {
		terminal.scrollback = nil
		terminal.rebaseHistoryRecorder(cells, cursorX, cursorY, applicationCursor)
		return true, true, nil
	}
	if historyLines == terminal.historyLineCount {
		return false, false, nil
	}

	newRows, ok := terminal.historyRowsSince(historyLines)
	if !ok {
		terminal.rebaseHistoryRecorder(cells, cursorX, cursorY, applicationCursor)
		return false, false, nil
	}
	terminal.historyLineCount = historyLines
	if len(newRows) == 0 {
		return false, false, nil
	}

	reset, appended = terminal.appendScrollbackRows(newRows)
	changed = true

	if terminal.historyLineCount >= sshTerminalHistoryRebaseLines {
		terminal.rebaseHistoryRecorder(cells, cursorX, cursorY, applicationCursor)
	}
	return changed, reset, appended
}

func (terminal *sshTerminalEmulator) sawTerminalReset(data []byte) bool {
	seen := false
	for _, value := range data {
		if terminal.resetEscape {
			terminal.resetEscape = false
			if value == 'c' {
				seen = true
				continue
			}
		}
		if value == 0x1b {
			terminal.resetEscape = true
		}
	}
	return seen
}

func (terminal *sshTerminalEmulator) sawAlternateScreenTransition(data []byte) bool {
	combined := append(append([]byte(nil), terminal.controlTail...), data...)
	seen := bytes.Contains(combined, []byte("\x1b[?47h")) ||
		bytes.Contains(combined, []byte("\x1b[?47l")) ||
		bytes.Contains(combined, []byte("\x1b[?1047h")) ||
		bytes.Contains(combined, []byte("\x1b[?1047l")) ||
		bytes.Contains(combined, []byte("\x1b[?1049h")) ||
		bytes.Contains(combined, []byte("\x1b[?1049l"))
	if len(combined) > 16 {
		terminal.controlTail = append([]byte(nil), combined[len(combined)-16:]...)
	} else {
		terminal.controlTail = combined
	}
	return seen
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}
