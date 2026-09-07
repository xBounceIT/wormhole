package main

import (
	"bytes"
	"errors"
	"strings"
)

const (
	sshTerminalPasteStart    = "\x1b[200~"
	sshTerminalPasteEnd      = "\x1b[201~"
	sshTerminalPasteOverhead = len(sshTerminalPasteStart) + len(sshTerminalPasteEnd)
)

// Track DECSET/DECRST 2004 independently because vt10x does not expose it.
// The parser retains bounded state across remote output chunks and ignores
// escape-looking text inside OSC/DCS/APC/PM strings and legacy screen titles.
type sshTerminalPasteMode struct {
	enabled    bool
	state      byte
	parameters []byte
}

func (mode *sshTerminalPasteMode) write(data []byte) {
	for _, value := range data {
		if value == 0x18 || value == 0x1a {
			mode.state = 0
			continue
		}
		switch mode.state {
		case 0:
			if value == 0x1b {
				mode.state = 'e'
			}
		case 'e':
			switch value {
			case '[':
				mode.state = 'c'
				mode.parameters = mode.parameters[:0]
			case ']', 'P', '^', '_', 'k':
				mode.state = 's'
			case 'c':
				mode.enabled = false
				mode.state = 0
			case 0x1b:
			default:
				mode.state = 0
			}
		case 's':
			if value == 0x07 {
				mode.state = 0
			} else if value == 0x1b {
				mode.state = 't'
			}
		case 't':
			if value == '\\' || value == 0x07 {
				mode.state = 0
			} else if value != 0x1b {
				mode.state = 's'
			}
		case 'c':
			switch {
			case value == 0x1b:
				mode.state = 'e'
			case value >= 0x40 && value <= 0x7e:
				if (value == 'h' || value == 'l') && len(mode.parameters) > 0 && mode.parameters[0] == '?' {
					for _, parameter := range strings.Split(string(mode.parameters[1:]), ";") {
						if strings.TrimLeft(parameter, "0") == "2004" {
							mode.enabled = value == 'h'
						}
					}
				}
				mode.state = 0
			case value >= 0x20 && value <= 0x3f:
				valid := value >= '0' && value <= '9' || value == ';' || value == '?' && len(mode.parameters) == 0
				if valid && len(mode.parameters) < 64 {
					mode.parameters = append(mode.parameters, value)
				} else {
					mode.state = 'd'
				}
			}
		case 'd':
			if value == 0x1b {
				mode.state = 'e'
			} else if value >= 0x40 && value <= 0x7e {
				mode.state = 0
			}
		}
	}
}

func sshTerminalPaste(data []byte, bracketed bool) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\r"))
	data = bytes.ReplaceAll(data, []byte("\n"), []byte("\r"))
	if len(data) > sshInputMaxBytes {
		return nil, errors.New("SSH clipboard text is too large to paste")
	}
	if !bracketed {
		return data, nil
	}
	// Clipboard text must not be able to terminate its own paste envelope.
	data = bytes.ReplaceAll(data, []byte{0x1b}, nil)
	result := append([]byte(sshTerminalPasteStart), data...)
	return append(result, []byte(sshTerminalPasteEnd)...), nil
}
