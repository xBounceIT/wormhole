package main

import "strings"

// sshSudoPrompt recognizes only a bounded, current line with optional SGR
// attributes and harmless shell mode toggles. Keep control-string and overflow
// state across reads: truncating raw output can turn a banner or hidden title
// into an apparent password prompt.
// Unsupported controls invalidate the line rather than guessing its contents.
type sshSudoPrompt struct {
	line       [sshAutoSudoTailBytes]byte
	length     int
	state      byte
	invalid    bool
	csi        [8]byte
	csiLen     int
	csiPrivate bool
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
				prompt.csiLen = 0
				prompt.csiPrivate = false
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
				// Bash may turn off bracketed paste or show the cursor immediately before
				// sudo-rs prints its prompt. These modes do not alter visible text.
				allowed := value == 'm' && !prompt.csiPrivate
				if !allowed && prompt.length == 0 && prompt.csiLen <= len(prompt.csi) {
					mode := string(prompt.csi[:prompt.csiLen]) + string(value)
					allowed = mode == "?2004l" || mode == "?25h" || mode == "?25l"
				}
				prompt.invalid = prompt.invalid || !allowed
				prompt.state = 0
			case value >= '0' && value <= '9' || value == ';' || value == ':' || value == '?':
				if value == '?' {
					prompt.csiPrivate = true
				}
				if prompt.csiLen < len(prompt.csi) {
					prompt.csi[prompt.csiLen] = value
				}
				prompt.csiLen++
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
