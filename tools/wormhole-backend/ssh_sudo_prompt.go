package main

import "strings"

// sshSudoPrompt recognizes only a bounded, current line with optional SGR
// attributes. Keep control-string and overflow state across reads: truncating
// raw output can turn a banner or hidden title into an apparent password prompt.
// Unsupported controls invalidate the line rather than guessing its contents.
type sshSudoPrompt struct {
	line    [sshAutoSudoTailBytes]byte
	length  int
	state   byte
	invalid bool
}

func (prompt *sshSudoPrompt) write(data []byte) bool {
	for _, value := range data {
		switch prompt.state {
		case 'e':
			switch value {
			case 0x1b:
				prompt.invalid = true
			case '[':
				prompt.state = 'c'
			case ']', 'P', '^', '_', 'k':
				prompt.invalid = true
				prompt.state = 's'
			default:
				prompt.invalid = true
				prompt.state = 0
			}
		case 'c':
			switch {
			case value == 0x1b:
				prompt.invalid = true
				prompt.state = 'e'
			case value >= 0x40 && value <= 0x7e:
				prompt.invalid = prompt.invalid || value != 'm'
				prompt.state = 0
			case value >= '0' && value <= '9' || value == ';' || value == ':':
			default:
				prompt.invalid = true
			}
		case 's':
			if value == 0x07 {
				prompt.state = 0
			} else if value == 0x1b {
				prompt.state = 't'
			}
		case 't':
			if value == '\\' || value == 0x07 {
				prompt.state = 0
			} else if value != 0x1b {
				prompt.state = 's'
			}
		default:
			switch {
			case value == 0x1b:
				prompt.state = 'e'
			case value == '\r' || value == '\n':
				prompt.length = 0
				prompt.invalid = false
			case value < 0x20 && value != '\t' || value == 0x7f:
				prompt.invalid = true
			case prompt.length == len(prompt.line):
				prompt.invalid = true
			default:
				prompt.line[prompt.length] = value
				prompt.length++
			}
		}
	}
	if prompt.invalid || prompt.state != 0 {
		return false
	}
	line := strings.TrimSpace(string(prompt.line[:prompt.length]))
	return (strings.HasPrefix(line, "[sudo]") || strings.HasPrefix(line, "[sudo: authenticate]")) && strings.HasSuffix(line, ":")
}
