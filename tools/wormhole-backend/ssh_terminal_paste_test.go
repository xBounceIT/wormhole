package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestSSHServerPasteNormalizedSizeLimit(t *testing.T) {
	for _, bracketed := range []bool{false, true} {
		for _, tc := range []struct {
			name, text      string
			paste, accepted bool
		}{
			{"maximum CRLF", strings.Repeat("\r\n", sshInputMaxBytes), true, true},
			{"maximum LF", strings.Repeat("\n", sshInputMaxBytes), true, true},
			{"maximum ASCII", strings.Repeat("a", sshInputMaxBytes), true, true},
			{"oversized normalized", strings.Repeat("a", sshInputMaxBytes+1), true, false},
			{"oversized Unicode", strings.Repeat("é", sshInputMaxBytes/2+1), true, false},
			{"oversized wire", strings.Repeat("\r\n", sshInputMaxBytes+1), true, false},
			{"raw keyboard limit", strings.Repeat("\r\n", sshInputMaxBytes), false, false},
		} {
			t.Run(tc.name+fmt.Sprint(bracketed), func(t *testing.T) {
				var output bytes.Buffer
				server := newSSHTestServer(&output)
				native := &sshNativeSession{inputQueue: make(chan []byte, 1), done: make(chan struct{})}
				native.pasteMode.enabled = bracketed
				server.sessions["paste"] = native
				server.input(sshWireCommand{SessionID: "paste", Data: base64.StdEncoding.EncodeToString([]byte(tc.text)), Paste: tc.paste})
				if !tc.accepted {
					if len(native.inputQueue) != 0 || output.Len() == 0 {
						t.Fatal("oversized input was not rejected")
					}
					return
				}
				if len(native.inputQueue) != 1 || output.Len() != 0 {
					t.Fatal("valid normalized input was rejected")
				}
				data := <-native.inputQueue
				if bracketed {
					if !bytes.HasPrefix(data, []byte("\x1b[200~")) || !bytes.HasSuffix(data, []byte("\x1b[201~")) {
						t.Fatal("missing paste envelope")
					}
					data = data[6 : len(data)-6]
				}
				if len(data) != sshInputMaxBytes {
					t.Fatalf("normalized size = %d", len(data))
				}
				if strings.ContainsAny(tc.text, "\r\n") && bytes.Count(data, []byte("\r")) != sshInputMaxBytes {
					t.Fatal("newline normalization changed")
				}
			})
		}
	}
}

func TestSSHCommandChannelAcceptsMaximumRawPaste(t *testing.T) {
	var input, output bytes.Buffer
	encoder := json.NewEncoder(&input)
	for _, data := range []string{strings.Repeat("\r\n", sshInputMaxBytes), "next"} {
		if err := encoder.Encode(sshWireCommand{Type: "input", SessionID: "missing", Paste: true, Data: base64.StdEncoding.EncodeToString([]byte(data))}); err != nil {
			t.Fatal(err)
		}
	}
	if err := serveSSH("", &input, &output); err != nil {
		t.Fatal(err)
	}
	events := decodeSSHEvents(t, output.Bytes())
	if len(events) != 2 {
		t.Fatalf("channel stopped processing after large paste: %d events", len(events))
	}
	for _, event := range events {
		if event.Error != "SSH session is not connected" {
			t.Fatalf("unexpected event: %#v", event)
		}
	}
}

func TestSSHTerminalPasteMode(t *testing.T) {
	cases := []struct {
		name, output string
		enabled      bool
	}{
		{"default", "prompt", false},
		{"enable", "\x1b[?2004h", true},
		{"disable", "\x1b[?2004h\x1b[?2004l", false},
		{"last mode wins", "\x1b[?2004l\x1b[?2004h", true},
		{"multiple parameters", "\x1b[?1;02004;25h", true},
		{"unrelated mode", "\x1b[?2004h\x1b[?25l", true},
		{"reset", "\x1b[?2004h\x1bc", false},
		{"nonprivate", "\x1b[2004h", false},
		{"other final", "\x1b[?2004m", false},
		{"empty csi", "\x1b[h", false},
		{"intermediate", "\x1b[?2004;1 h", false},
		{"overflow", "\x1b[?2004;" + strings.Repeat("1", 80) + "h", false},
		{"overflow recovery", "\x1b[?" + strings.Repeat("1", 80) + "\x1b[?2004h", true},
		{"cancel", "\x1b[?2004\x18h", false},
		{"substitute", "\x1b[?2004\x1ah", false},
		{"escape recovery", "\x1b[?2\x1b\x1b[?2004h", true},
		{"other escape", "\x1b7[?2004h", false},
		{"title", "\x1b]0;title\x1b[?2004h\x07", false},
		{"legacy screen title", "\x1b[?2004h\x1bktitle\x1b[?2004l\x1b\\", true},
		{"string escape", "\x1bP\x1b\x1b[?2004h\x1b\\", false},
		{"string bel after escape", "\x1b_ignored\x1b\x07\x1b[?2004h", true},
		{"string recovery", "\x1b^ignored\x1b\\\x1b[?2004h", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Every split must produce the same mode as one complete network chunk.
			for split := 0; split <= len(tc.output); split++ {
				var mode sshTerminalPasteMode
				mode.write([]byte(tc.output[:split]))
				mode.write([]byte(tc.output[split:]))
				if mode.enabled != tc.enabled {
					t.Fatalf("split %d: enabled = %v", split, mode.enabled)
				}
				if len(mode.parameters) > 64 {
					t.Fatal("unbounded parser state")
				}
			}
		})
	}
}

func TestSSHTerminalPasteEncoding(t *testing.T) {
	for _, bracketed := range []bool{false, true} {
		for _, tc := range []struct{ input, expected string }{
			{"", ""},
			{"printf 'caffè ☕'", "printf 'caffè ☕'"},
			{"one\r\ntwo\nthree\rfour\n", "one\rtwo\rthree\rfour\r"},
			{"cat <<'EOF'\nline\nEOF", "cat <<'EOF'\rline\rEOF"},
			{"a\\\nb", "a\\\rb"},
		} {
			expected := tc.expected
			if bracketed && tc.input != "" {
				expected = "\x1b[200~" + expected + "\x1b[201~"
			}
			data, err := sshTerminalPaste([]byte(tc.input), bracketed)
			if err != nil {
				t.Fatal(err)
			}
			if got := string(data); got != expected {
				t.Fatalf("paste(%q, %v) = %q, want %q", tc.input, bracketed, got, expected)
			}
		}
	}
	data, err := sshTerminalPaste([]byte("a\x1b[201~\rbad"), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != "\x1b[200~a[201~\rbad\x1b[201~" {
		t.Fatalf("escape broke envelope: %q", got)
	}
}

func TestSSHServerMultilinePaste(t *testing.T) {
	commands := strings.Join([]string{
		`sudo multipathd resize map iscsi\_zabbix\_db`,
		`sudo udevadm settle`,
		`sudo multipath -ll iscsi\_zabbix\_db`,
		`sudo blockdev --getsize64 /dev/mapper/iscsi\_zabbix\_db`,
		`lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS /dev/mapper/iscsi\_zabbix\_db`,
	}, "\r\n")
	for _, mode := range []string{"", "\x1b[?2004h", "\x1b[?2004h\x1b[?2004l"} {
		for _, paste := range []bool{false, true} {
			terminal, err := newSSHTerminalEmulator(80, 24)
			if err != nil {
				t.Fatal(err)
			}
			server := newSSHTestServer(io.Discard)
			native := &sshNativeSession{server: server, terminal: terminal, inputQueue: make(chan []byte, 16), done: make(chan struct{})}
			server.sessions["paste"] = native
			for _, value := range []byte(mode) {
				native.publishTerminalData([]byte{value})
			}
			server.handle(sshWireCommand{Type: "input", SessionID: "paste", Data: base64.StdEncoding.EncodeToString([]byte(commands)), Paste: paste})
			if len(native.inputQueue) != 1 {
				t.Fatal("paste must be queued as one block")
			}
			got := string(<-native.inputQueue)
			want := commands
			if paste {
				want = strings.ReplaceAll(want, "\r\n", "\r")
				if mode == "\x1b[?2004h" {
					want = "\x1b[200~" + want + "\x1b[201~"
				}
			}
			if got != want {
				t.Fatalf("paste=%v mode=%q: got %q, want %q", paste, mode, got, want)
			}
			server.handle(sshWireCommand{Type: "input", SessionID: "paste", Data: "DQ=="})
			if len(native.inputQueue) != 1 {
				t.Fatal("Enter must be queued once")
			}
			if got := string(<-native.inputQueue); got != "\r" {
				t.Fatalf("Enter was changed: %q", got)
			}
		}
	}
}

func TestSSHMultilinePasteSurvivesTerminalRecovery(t *testing.T) {
	terminal, err := newSSHTerminalEmulator(80, 24)
	if err != nil {
		t.Fatal(err)
	}
	server := newSSHTestServer(io.Discard)
	native := &sshNativeSession{id: "paste", server: server, terminal: terminal,
		inputQueue: make(chan []byte, 16), done: make(chan struct{})}
	server.sessions[native.id] = native
	native.publishTerminalData([]byte("\x1b[?2004h"))
	terminal.vt = nil // Force the existing recoverable emulator failure boundary.
	native.publishTerminalData([]byte("output"))
	if native.terminal == terminal {
		t.Fatal("emulator was not recovered")
	}
	server.input(sshWireCommand{SessionID: native.id, Data: "b25lCnR3bw==", Paste: true})
	select {
	case data := <-native.inputQueue:
		if string(data) != "\x1b[200~one\rtwo\x1b[201~" {
			t.Fatalf("paste lost its envelope after recovery: %q", data)
		}
	default:
		t.Fatal("paste was not queued")
	}
}
