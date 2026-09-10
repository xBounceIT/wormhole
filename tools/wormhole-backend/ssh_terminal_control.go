package main

import "strings"

type sshTerminalControlKind uint8

const (
	sshTerminalControlErase sshTerminalControlKind = iota
	sshTerminalControlAlternateScreen
	sshTerminalControlReset
)

type sshTerminalControl struct {
	end       int
	kind      sshTerminalControlKind
	parameter int
	active    bool
}

// Observe screen controls without retaining unbounded remote output. Match
// vt10x's CSI limit and string termination/recovery so redraws follow its state.
type sshTerminalControlParser struct {
	state      byte
	parameters []byte
}

func (parser *sshTerminalControlParser) write(data []byte) []sshTerminalControl {
	var controls []sshTerminalControl
	for index, value := range data {
		switch parser.state {
		case 0:
			if value == 0x1b {
				parser.state = 'e'
			}
		case 'e':
			switch value {
			case '[':
				parser.state = 'c'
				parser.parameters = parser.parameters[:0]
			case ']', 'P', '^', '_', 'k':
				parser.state = 's'
			case 'c':
				controls = append(controls, sshTerminalControl{end: index + 1, kind: sshTerminalControlReset})
				parser.state = 0
			case 0x1b:
			default:
				if value >= 0x20 && value != 0x7f {
					parser.state = 0
				}
			}
		case 's':
			if value == 0x07 {
				parser.state = 0
			} else if value == 0x1b {
				parser.state = 't'
			}
		case 't':
			// vt10x consumes a printable byte after ESC to terminate or abort
			// a string. A second ESC starts a new escape sequence.
			if value == 0x1b {
				parser.state = 'e'
			} else if value >= 0x20 && value != 0x7f {
				parser.state = 0
			}
		case 'c':
			switch {
			case value == 0x1b:
				parser.state = 'e'
			case value == 0x18 || value == 0x1a:
				// vt10x cancels the parameters but stays in CSI parsing state.
				parser.parameters = parser.parameters[:0]
			case value >= 0x40 && value <= 0x7e:
				if control, ok := parser.finish(value); ok {
					control.end = index + 1
					controls = append(controls, control)
				}
				parser.state = 0
			case value >= 0x20 && value != 0x7f:
				valid := value >= '0' && value <= '9' || value == ';' || value == '?' && len(parser.parameters) == 0
				if valid && len(parser.parameters) < 255 {
					parser.parameters = append(parser.parameters, value)
				} else {
					parser.state = 'd'
				}
			}
		case 'd':
			if value == 0x1b {
				parser.state = 'e'
			} else if value >= 0x40 && value <= 0x7e {
				parser.state = 0
			}
		}
	}
	return controls
}

func (parser *sshTerminalControlParser) finish(final byte) (sshTerminalControl, bool) {
	parameters := string(parser.parameters)
	if final == 'J' {
		switch strings.TrimLeft(parameters, "0") {
		case "":
			return sshTerminalControl{kind: sshTerminalControlErase}, true
		case "2":
			return sshTerminalControl{kind: sshTerminalControlErase, parameter: 2}, true
		case "3":
			return sshTerminalControl{kind: sshTerminalControlErase, parameter: 3}, true
		}
	}
	if (final == 'h' || final == 'l') && strings.HasPrefix(parameters, "?") {
		for _, parameter := range strings.Split(parameters[1:], ";") {
			var mode int
			switch strings.TrimLeft(parameter, "0") {
			case "47":
				mode = 47
			case "1047":
				mode = 1047
			case "1049":
				mode = 1049
			default:
				continue
			}
			return sshTerminalControl{kind: sshTerminalControlAlternateScreen, parameter: mode, active: final == 'h'}, true
		}
	}
	return sshTerminalControl{}, false
}
