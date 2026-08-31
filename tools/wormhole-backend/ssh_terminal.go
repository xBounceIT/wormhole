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

type sshTerminalScrollbackRun struct {
	Text       string `json:"text"`
	Cells      int    `json:"cells"`
	Foreground uint16 `json:"foreground"`
	Background uint16 `json:"background"`
}

type sshTerminalScrollbackLine struct {
	Runs []sshTerminalScrollbackRun `json:"runs"`
}

type sshTerminalFrame struct {
	Columns           int                         `json:"columns"`
	Rows              int                         `json:"rows"`
	Full              bool                        `json:"full,omitempty"`
	Cells             []sshTerminalCell           `json:"cells,omitempty"`
	Changes           []sshTerminalCellChange     `json:"changes,omitempty"`
	ScrollbackReset   bool                        `json:"scrollback_reset,omitempty"`
	ViewportReset     bool                        `json:"viewport_reset,omitempty"`
	Scrollback        []sshTerminalScrollbackLine `json:"scrollback,omitempty"`
	CursorX           int                         `json:"cursor_x"`
	CursorY           int                         `json:"cursor_y"`
	CursorVisible     bool                        `json:"cursor_visible"`
	ApplicationCursor bool                        `json:"application_cursor"`
	AlternateScreen   bool                        `json:"alternate_screen"`
	Title             string                      `json:"title,omitempty"`
	Sequence          uint64                      `json:"sequence"`
}

type sshTerminalControlEffects struct {
	scrollbackReset bool
	viewportReset   bool
}

type sshTerminalHistoryEscapeMode uint8

const (
	sshTerminalHistoryEscapeNone sshTerminalHistoryEscapeMode = iota
	sshTerminalHistoryEscapeAfterEsc
	sshTerminalHistoryEscapeCsi
	sshTerminalHistoryEscapeString
)

var sshViewportClearSequences = [][]byte{
	[]byte("\x1b[J"),
	[]byte("\x1b[0J"),
	[]byte("\x1b[2J"),
	[]byte("\x1b[3J"),
}

type sshTerminalAlternateScreenTransition struct {
	end      int
	active   bool
	sequence []byte
}

type sshTerminalAlternateScreenEscapeMode uint8

const (
	sshTerminalAlternateScreenEscapeNone sshTerminalAlternateScreenEscapeMode = iota
	sshTerminalAlternateScreenEscapeAfterEsc
	sshTerminalAlternateScreenEscapeCSI
	sshTerminalAlternateScreenEscapeParameters
)

type sshTerminalAlternateScreenParser struct {
	escapeMode         sshTerminalAlternateScreenEscapeMode
	parameter          int
	parameterSeen      bool
	alternateParameter int
}

var sshAlternateScreenModes = []struct {
	parameter int
	enter     []byte
	exit      []byte
}{
	{47, []byte("\x1b[?47h"), []byte("\x1b[?47l")},
	{1047, []byte("\x1b[?1047h"), []byte("\x1b[?1047l")},
	{1049, []byte("\x1b[?1049h"), []byte("\x1b[?1049l")},
}

var sshScrollbackEraseSequence = []byte("\x1b[3J")

type sshTerminalEmulator struct {
	state        *vt10x.State
	vt           *vt10x.VT
	historyState *vt10x.State
	historyVT    *vt10x.VT

	columns int
	rows    int
	pending []byte

	historyLineCount  int
	historyAltScreen  bool
	scrollback        []sshTerminalScrollbackLine
	resetEscape       bool
	clearTail         []byte
	historyEscapeMode sshTerminalHistoryEscapeMode
	historyStringEsc  bool
	historyCapture    []sshTerminalCell
	historyCaptureOK  bool
	alternateParser   sshTerminalAlternateScreenParser

	previousCells         []sshTerminalCell
	previousCursorX       int
	previousCursorY       int
	previousCursorVisible bool
	previousAppCursor     bool
	previousAltScreen     bool
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
	frame := terminal.snapshot()
	frame.ViewportReset = true
	return frame
}

func (terminal *sshTerminalEmulator) snapshot() *sshTerminalFrame {
	terminal.state.Lock()
	frame, _ := terminal.snapshotLocked(true)
	terminal.state.Unlock()
	frame.ScrollbackReset = true
	frame.Scrollback = append([]sshTerminalScrollbackLine(nil), terminal.scrollback...)
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
	frame.ViewportReset = true
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

	completeData := terminal.pending[:complete]
	alternateScreenTransitions := terminal.alternateScreenTransitions(completeData)
	if err := terminal.writeVT(completeData, alternateScreenTransitions); err != nil {
		return nil, false, err
	}
	controlEffects := terminal.sawTerminalControlEffects(completeData)
	terminalReset := controlEffects.scrollbackReset
	terminalAltTransition := len(alternateScreenTransitions) > 0
	viewportReset := controlEffects.viewportReset || terminalAltTransition
	var historyRows []sshTerminalScrollbackLine
	if terminal.historyVT != nil {
		var err error
		historyRows, err = terminal.writeHistory(
			completeData,
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
		historyRows,
	)
	if frame == nil && (scrollbackChanged || viewportReset) {
		terminal.state.Lock()
		frame, _ = terminal.snapshotLocked(true)
		terminal.state.Unlock()
		changed = true
	}
	if frame == nil {
		return nil, false, nil
	}
	frame.ScrollbackReset = scrollbackReset
	frame.ViewportReset = viewportReset
	if scrollbackReset {
		frame.Scrollback = append([]sshTerminalScrollbackLine(nil), terminal.scrollback...)
	} else if len(scrollback) > 0 {
		frame.Scrollback = scrollback
	}
	return frame, changed || scrollbackChanged, nil
}

func (terminal *sshTerminalEmulator) writeVT(
	data []byte,
	transitions []sshTerminalAlternateScreenTransition,
) error {
	offset := 0
	for _, transition := range transitions {
		if _, err := terminal.vt.Write(data[offset:transition.end]); err != nil {
			return err
		}
		offset = transition.end

		terminal.state.Lock()
		active := terminal.state.Mode(vt10x.ModeAltScreen)
		terminal.state.Unlock()
		if active != transition.active {
			if _, err := terminal.vt.Write(transition.sequence); err != nil {
				return err
			}
		}
	}
	if _, err := terminal.vt.Write(data[offset:]); err != nil {
		return err
	}
	return nil
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
	alternateScreen := terminal.state.Mode(vt10x.ModeAltScreen)
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
		alternateScreen != terminal.previousAltScreen ||
		title != terminal.previousTitle
	terminal.previousCells = cells
	terminal.previousCursorX = cursorX
	terminal.previousCursorY = cursorY
	terminal.previousCursorVisible = cursorVisible
	terminal.previousAppCursor = applicationCursor
	terminal.previousAltScreen = alternateScreen
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
		AlternateScreen:   alternateScreen,
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
	currentForeground := uint16(vt10x.DefaultFG)
	currentBackground := uint16(vt10x.DefaultBG)
	for y := 0; y < rows; y++ {
		fmt.Fprintf(&seed, "\x1b[%d;1H", y+1)
		for x := 0; x < columns; x++ {
			cell := cells[y*columns+x]
			if cell.Foreground != currentForeground {
				appendTerminalSgrColor(&seed, true, cell.Foreground)
				currentForeground = cell.Foreground
			}
			if cell.Background != currentBackground {
				appendTerminalSgrColor(&seed, false, cell.Background)
				currentBackground = cell.Background
			}
			character := cell.Character
			if character == "" {
				character = " "
			}
			seed.WriteString(character)
		}
	}
	cursorX = minInt(maxInt(cursorX, 0), columns-1)
	cursorY = minInt(maxInt(cursorY, 0), rows-1)
	cursorCell := cells[cursorY*columns+cursorX]
	if cursorCell.Foreground != currentForeground {
		appendTerminalSgrColor(&seed, true, cursorCell.Foreground)
	}
	if cursorCell.Background != currentBackground {
		appendTerminalSgrColor(&seed, false, cursorCell.Background)
	}
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

func appendTerminalSgrColor(seed *strings.Builder, foreground bool, color uint16) {
	if foreground {
		switch {
		case color == uint16(vt10x.DefaultFG):
			seed.WriteString("\x1b[39m")
		case color < 8:
			fmt.Fprintf(seed, "\x1b[%dm", 30+color)
		case color < 16:
			fmt.Fprintf(seed, "\x1b[%dm", 90+color-8)
		case color < 256:
			fmt.Fprintf(seed, "\x1b[38;5;%dm", color)
		}
		return
	}
	switch {
	case color == uint16(vt10x.DefaultBG):
		seed.WriteString("\x1b[49m")
	case color < 8:
		fmt.Fprintf(seed, "\x1b[%dm", 40+color)
	case color < 16:
		fmt.Fprintf(seed, "\x1b[%dm", 100+color-8)
	case color < 256:
		fmt.Fprintf(seed, "\x1b[48;5;%dm", color)
	}
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
	terminal.historyEscapeMode = sshTerminalHistoryEscapeNone
	terminal.historyStringEsc = false
	terminal.historyCapture = nil
	terminal.historyCaptureOK = false
}

func (terminal *sshTerminalEmulator) writeHistory(
	data []byte,
	suppressScrollback bool,
) ([]sshTerminalScrollbackLine, error) {
	var appended []sshTerminalScrollbackLine
	for offset := 0; offset < len(data); {
		unitLength := terminal.historyInputUnitLength(data[offset:])
		if unitLength < 1 {
			return nil, fmt.Errorf("SSH history parser produced an empty input unit")
		}
		unit := data[offset : offset+unitLength]
		beforeY, beforeAlt := terminal.historyPosition()
		beforeEscapeMode := terminal.historyEscapeMode
		terminal.captureHistoryRow(unit)
		if _, err := terminal.historyVT.Write(unit); err != nil {
			return nil, err
		}
		afterY, afterAlt := terminal.historyPosition()
		terminal.updateHistoryEscapeMode(unit)
		if !suppressScrollback && !beforeAlt && !afterAlt && afterY-beforeY == 1 && terminal.historyCaptureOK {
			appended = append(appended, terminal.historyScrollbackLine())
		}
		if afterY != beforeY ||
			((beforeEscapeMode != sshTerminalHistoryEscapeNone || historyUnitIsControl(unit)) &&
				terminal.historyEscapeMode == sshTerminalHistoryEscapeNone) {
			terminal.historyCaptureOK = false
		}
		offset += unitLength
	}
	return appended, nil
}

func (terminal *sshTerminalEmulator) historyInputUnitLength(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	if terminal.historyEscapeMode != sshTerminalHistoryEscapeNone ||
		data[0] == 0x1b || data[0] < 0x20 || data[0] == 0x7f {
		return 1
	}

	limit := terminal.columns
	if limit < 1 {
		limit = 1
	}
	offset := 0
	runes := 0
	for offset < len(data) && runes < limit {
		if data[offset] == 0x1b || data[offset] < 0x20 || data[offset] == 0x7f {
			break
		}
		_, size := utf8.DecodeRune(data[offset:])
		if size < 1 || offset+size > len(data) {
			break
		}
		offset += size
		runes++
	}
	if offset == 0 {
		return 1
	}
	return offset
}

func historyUnitIsControl(unit []byte) bool {
	return len(unit) > 0 && (unit[0] == 0x1b || unit[0] < 0x20 || unit[0] == 0x7f)
}

func (terminal *sshTerminalEmulator) historyPosition() (int, bool) {
	if terminal.historyState == nil {
		return 0, false
	}
	terminal.historyState.Lock()
	_, globalY := terminal.historyState.GlobalCursor()
	altScreen := terminal.historyState.Mode(vt10x.ModeAltScreen)
	terminal.historyState.Unlock()
	return globalY, altScreen
}

func (terminal *sshTerminalEmulator) captureHistoryRow(unit []byte) {
	if terminal.historyCaptureOK || terminal.historyState == nil {
		return
	}
	terminal.historyState.Lock()
	rows, columns := terminal.historyState.Size()
	_, cursorY := terminal.historyState.Cursor()
	shouldCapture := cursorY == rows-1 ||
		terminal.historyEscapeMode != sshTerminalHistoryEscapeNone ||
		(len(unit) > 0 && unit[0] == 0x1b)
	if shouldCapture && rows > 0 && columns > 0 {
		terminal.historyCapture = make([]sshTerminalCell, columns)
		for x := 0; x < columns; x++ {
			character, foreground, background := terminal.historyState.Cell(x, 0)
			if character == 0 {
				character = ' '
			}
			terminal.historyCapture[x] = sshTerminalCell{
				Character:  string(character),
				Foreground: uint16(foreground),
				Background: uint16(background),
			}
		}
		terminal.historyCaptureOK = true
	}
	terminal.historyState.Unlock()
}

func (terminal *sshTerminalEmulator) updateHistoryEscapeMode(data []byte) {
	for _, value := range data {
		switch terminal.historyEscapeMode {
		case sshTerminalHistoryEscapeNone:
			if value == 0x1b {
				terminal.historyEscapeMode = sshTerminalHistoryEscapeAfterEsc
			}
		case sshTerminalHistoryEscapeAfterEsc:
			switch value {
			case '[':
				terminal.historyEscapeMode = sshTerminalHistoryEscapeCsi
			case ']', 'P', '^', '_':
				terminal.historyEscapeMode = sshTerminalHistoryEscapeString
				terminal.historyStringEsc = false
			case 0x1b:
				terminal.historyEscapeMode = sshTerminalHistoryEscapeAfterEsc
			default:
				terminal.historyEscapeMode = sshTerminalHistoryEscapeNone
			}
		case sshTerminalHistoryEscapeCsi:
			if value == 0x1b {
				terminal.historyEscapeMode = sshTerminalHistoryEscapeAfterEsc
			} else if value >= 0x40 && value <= 0x7e {
				terminal.historyEscapeMode = sshTerminalHistoryEscapeNone
			}
		case sshTerminalHistoryEscapeString:
			if terminal.historyStringEsc {
				terminal.historyStringEsc = false
				if value == '\\' {
					terminal.historyEscapeMode = sshTerminalHistoryEscapeNone
				}
			} else if value == 0x07 {
				terminal.historyEscapeMode = sshTerminalHistoryEscapeNone
			} else if value == 0x1b {
				terminal.historyStringEsc = true
			}
		}
	}
}

func (terminal *sshTerminalEmulator) historyScrollbackLine() sshTerminalScrollbackLine {
	return sshTerminalScrollbackLineFromCells(terminal.historyCapture)
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

func sshTerminalScrollbackLineFromCells(cells []sshTerminalCell) sshTerminalScrollbackLine {
	end := len(cells)
	for end > 0 && (cells[end-1].Character == "" || cells[end-1].Character == " ") {
		end--
	}

	runs := make([]sshTerminalScrollbackRun, 0)
	for _, cell := range cells[:end] {
		character := cell.Character
		if character == "" {
			character = " "
		}
		last := len(runs) - 1
		if last >= 0 && runs[last].Foreground == cell.Foreground && runs[last].Background == cell.Background {
			runs[last].Text += character
			runs[last].Cells++
			continue
		}
		runs = append(runs, sshTerminalScrollbackRun{
			Text:       character,
			Cells:      1,
			Foreground: cell.Foreground,
			Background: cell.Background,
		})
	}
	return sshTerminalScrollbackLine{Runs: runs}
}

func sshTerminalScrollbackLineText(line sshTerminalScrollbackLine) string {
	var text strings.Builder
	for _, run := range line.Runs {
		text.WriteString(run.Text)
	}
	return strings.TrimRight(text.String(), " ")
}

func sshTerminalScrollbackLineFromText(text string) sshTerminalScrollbackLine {
	if text == "" {
		return sshTerminalScrollbackLine{}
	}
	return sshTerminalScrollbackLine{Runs: []sshTerminalScrollbackRun{{
		Text:       text,
		Cells:      utf8.RuneCountInString(text),
		Foreground: uint16(vt10x.DefaultFG),
		Background: uint16(vt10x.DefaultBG),
	}}}
}

func sshTerminalScrollbackRowsMatch(lines []sshTerminalScrollbackLine, textRows []string) bool {
	if len(lines) != len(textRows) {
		return false
	}
	for index, line := range lines {
		if sshTerminalScrollbackLineText(line) != textRows[index] {
			return false
		}
	}
	return true
}

func (terminal *sshTerminalEmulator) appendScrollbackRows(rows []sshTerminalScrollbackLine) (bool, []sshTerminalScrollbackLine) {
	if len(rows) == 0 {
		return false, nil
	}
	terminal.scrollback = append(terminal.scrollback, rows...)
	if len(terminal.scrollback) > sshTerminalMaxScrollbackLines {
		overflow := len(terminal.scrollback) - sshTerminalMaxScrollbackLines
		terminal.scrollback = append([]sshTerminalScrollbackLine(nil), terminal.scrollback[overflow:]...)
		return true, nil
	}
	return false, rows
}

func (terminal *sshTerminalEmulator) updateScrollback(
	altScreen bool,
	terminalReset bool,
	alternateScreenTransition bool,
	cells []sshTerminalCell,
	cursorX, cursorY int,
	applicationCursor bool,
	capturedRows []sshTerminalScrollbackLine,
) (changed, reset bool, appended []sshTerminalScrollbackLine) {
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

	styledRows := capturedRows
	if !sshTerminalScrollbackRowsMatch(styledRows, newRows) {
		styledRows = make([]sshTerminalScrollbackLine, 0, len(newRows))
		for _, row := range newRows {
			styledRows = append(styledRows, sshTerminalScrollbackLineFromText(row))
		}
	}
	reset, appended = terminal.appendScrollbackRows(styledRows)
	changed = true

	if terminal.historyLineCount >= sshTerminalHistoryRebaseLines {
		terminal.rebaseHistoryRecorder(cells, cursorX, cursorY, applicationCursor)
	}
	return changed, reset, appended
}

func (terminal *sshTerminalEmulator) sawTerminalControlEffects(data []byte) sshTerminalControlEffects {
	viewportReset := false
	for _, sequence := range sshViewportClearSequences {
		if terminalControlSequenceSeen(terminal.clearTail, data, sequence) {
			viewportReset = true
			break
		}
	}
	scrollbackReset := terminalControlSequenceSeen(terminal.clearTail, data, sshScrollbackEraseSequence)
	for _, value := range data {
		if terminal.resetEscape {
			terminal.resetEscape = false
			if value == 'c' {
				scrollbackReset = true
				viewportReset = true
				continue
			}
		}
		if value == 0x1b {
			terminal.resetEscape = true
		}
	}
	terminal.clearTail = terminalTail(terminal.clearTail, data, 3)
	return sshTerminalControlEffects{
		scrollbackReset: scrollbackReset,
		viewportReset:   viewportReset,
	}
}

func terminalControlSequenceSeen(tail, data, sequence []byte) bool {
	if bytes.Contains(data, sequence) {
		return true
	}
	for prefixLength := 1; prefixLength < len(sequence); prefixLength++ {
		if len(tail) < prefixLength || len(data) < len(sequence)-prefixLength {
			continue
		}
		if bytes.Equal(tail[len(tail)-prefixLength:], sequence[:prefixLength]) &&
			bytes.Equal(data[:len(sequence)-prefixLength], sequence[prefixLength:]) {
			return true
		}
	}
	return false
}

func (terminal *sshTerminalEmulator) alternateScreenTransitions(data []byte) []sshTerminalAlternateScreenTransition {
	var transitions []sshTerminalAlternateScreenTransition
	parser := &terminal.alternateParser
	for index, value := range data {
		switch parser.escapeMode {
		case sshTerminalAlternateScreenEscapeNone:
			if value == 0x1b {
				parser.escapeMode = sshTerminalAlternateScreenEscapeAfterEsc
				parser.resetParameters()
			}
		case sshTerminalAlternateScreenEscapeAfterEsc:
			switch value {
			case '[':
				parser.escapeMode = sshTerminalAlternateScreenEscapeCSI
			case 0x1b:
				parser.resetParameters()
			default:
				parser.escapeMode = sshTerminalAlternateScreenEscapeNone
			}
		case sshTerminalAlternateScreenEscapeCSI:
			switch value {
			case '?':
				parser.escapeMode = sshTerminalAlternateScreenEscapeParameters
				parser.resetParameters()
			case 0x1b:
				parser.escapeMode = sshTerminalAlternateScreenEscapeAfterEsc
				parser.resetParameters()
			default:
				parser.escapeMode = sshTerminalAlternateScreenEscapeNone
			}
		case sshTerminalAlternateScreenEscapeParameters:
			switch {
			case value >= '0' && value <= '9':
				parser.appendParameterDigit(value)
			case value == ';':
				parser.finishParameter()
			case value == 'h' || value == 'l':
				parser.finishParameter()
				active := value == 'h'
				if sequence := sshAlternateScreenSequence(parser.alternateParameter, active); sequence != nil {
					transitions = append(transitions, sshTerminalAlternateScreenTransition{
						end:      index + 1,
						active:   active,
						sequence: sequence,
					})
				}
				parser.escapeMode = sshTerminalAlternateScreenEscapeNone
				parser.resetParameters()
			case value == 0x1b:
				parser.escapeMode = sshTerminalAlternateScreenEscapeAfterEsc
				parser.resetParameters()
			default:
				parser.escapeMode = sshTerminalAlternateScreenEscapeNone
				parser.resetParameters()
			}
		}
	}
	return transitions
}

func (parser *sshTerminalAlternateScreenParser) resetParameters() {
	parser.parameter = 0
	parser.parameterSeen = false
	parser.alternateParameter = 0
}

func (parser *sshTerminalAlternateScreenParser) appendParameterDigit(value byte) {
	digit := int(value - '0')
	if parser.parameter > (1049-digit)/10 {
		parser.parameter = 1050
	} else {
		parser.parameter = parser.parameter*10 + digit
	}
	parser.parameterSeen = true
}

func (parser *sshTerminalAlternateScreenParser) finishParameter() {
	if parser.parameterSeen && parser.alternateParameter == 0 {
		if sshAlternateScreenSequence(parser.parameter, true) != nil {
			parser.alternateParameter = parser.parameter
		}
	}
	parser.parameter = 0
	parser.parameterSeen = false
}

func sshAlternateScreenSequence(parameter int, active bool) []byte {
	for _, mode := range sshAlternateScreenModes {
		if mode.parameter != parameter {
			continue
		}
		if active {
			return mode.enter
		}
		return mode.exit
	}
	return nil
}

func terminalTail(previous, data []byte, limit int) []byte {
	if limit <= 0 {
		return nil
	}
	if len(data) >= limit {
		return append([]byte(nil), data[len(data)-limit:]...)
	}
	previousLength := limit - len(data)
	if previousLength > len(previous) {
		previousLength = len(previous)
	}
	tail := make([]byte, 0, previousLength+len(data))
	tail = append(tail, previous[len(previous)-previousLength:]...)
	return append(tail, data...)
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
