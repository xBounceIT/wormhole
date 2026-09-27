package main

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestSSHSudoPasswordPromptFormats(t *testing.T) {
	tests := []struct {
		name string
		text string
		want bool
	}{
		{"classic", "[sudo] password for operator: ", true},
		{"classic localized", "[sudo] Passwort für operator: ", true},
		{"authenticate", "[sudo: authenticate] Password: ", true},
		{"authenticate localized", "[sudo: authenticate] Mot de passe : ", true},
		{"styled authenticate", "\x1b[1m[sudo: authenticate]\x1b[0m Password: \x1b[0m", true},
		{"styled classic", "\x1b[33m[sudo] password for operator:\x1b[m ", true},
		{"incomplete styling", "[sudo: authenticate] Password: \x1b[0", false},
		{"completed old prompt", "[sudo: authenticate] Password: \r\n", false},
		{"hidden prompt", "\x1b]0;[sudo: authenticate] Password: ", false},
		{"cursor movement", "\x1b[2C[sudo: authenticate] Password: ", false},
		{"partial color parameter", "[sudo: authenticate] \x1b[38:", false},
		{"hidden multiline prompt", "\x1b]0;title\n[sudo: authenticate] Password: ", false},
		{"command echo before prompt", "operator@host:~$ sudo su\r\n[sudo: authenticate] Password: ", true},
		{"empty", "", false},
		{"generic password", "Password: ", false},
		{"banner", "Welcome: [sudo: authenticate] Password: ", false},
		{"command echo", "operator@host:~$ echo '[sudo: authenticate] Password:'", false},
		{"incomplete prefix", "[sudo: authenticate", false},
		{"incomplete prompt", "[sudo: authenticate] Password", false},
		{"other sudo message", "[sudo: error] Password: ", false},
		{"unknown operation", "[sudo: authenticate-other] Password: ", false},
		{"old prompt before shell", "[sudo: authenticate] Password: \r\noperator@host:~$ ", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var prompt sshSudoPrompt
			if got := prompt.write([]byte(tt.text)); got != tt.want {
				t.Fatalf("prompt recognized = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSSHSudoPromptControlStringsAcrossChunks(t *testing.T) {
	const passwordPrompt = "[sudo: authenticate] Password:"
	for _, hidden := range []string{
		"\x1b]title\n" + passwordPrompt + "\x07",
		"\x1bP" + strings.Repeat("x", 1024) + "\n" + passwordPrompt + "\x1b\\",
		"\x1b_title\x1b?\n" + passwordPrompt + "\x1b\x1b\x07",
		"\x1b\x1b]title\n" + passwordPrompt + "\x1b\\",
		"\x1b[38:\x1b]title\n" + passwordPrompt + "\x07",
	} {
		for split := 0; split <= len(hidden); split++ {
			var prompt sshSudoPrompt
			if prompt.write([]byte(hidden[:split])) || prompt.write([]byte(hidden[split:])) {
				t.Fatalf("hidden text recognized at split %d", split)
			}
			if !prompt.write([]byte("\r\n" + passwordPrompt)) {
				t.Fatalf("real prompt not recognized after control string at split %d", split)
			}
		}
	}
}

func TestSSHSudoPromptInvalidLineRecovery(t *testing.T) {
	for _, invalid := range []string{
		strings.Repeat("x", sshAutoSudoTailBytes+1),
		"\x1b7", "\x1b[?2004h", "\b", "\x00", "\x7f",
	} {
		var prompt sshSudoPrompt
		if prompt.write([]byte(invalid + "[sudo] password:")) {
			t.Fatal("invalid line recognized as prompt")
		}
		if !prompt.write([]byte("\r\n\x1b[1;33m[sudo] password:\x1b[m")) {
			t.Fatal("valid prompt not recognized on the next line")
		}
	}
}

func TestSSHAutoSudoManualTakeoverRacesWithPrompt(t *testing.T) {
	for attempt := 0; attempt < 100; attempt++ {
		input := &recordingSSHInput{}
		native := &sshNativeSession{stdin: input}
		driver := newSSHAutoSudoDriver(native, "secret")
		native.autoSudo = driver
		driver.start()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			driver.observe([]byte("[sudo: authenticate] Password:"))
		}()
		go func() {
			defer wg.Done()
			if err := native.write([]byte("manual\r")); err != nil {
				t.Error(err)
			}
		}()
		wg.Wait()
		driver.dispose()
		if got := input.String(); got != "sudo su\rmanual\r" && got != "sudo su\rsecret\rmanual\r" {
			t.Fatal("automatic credential was mixed with or sent after manual input")
		}
	}
}

func TestSSHAutoSudoDoesNotAnswerHiddenOrTruncatedText(t *testing.T) {
	const prompt = "[sudo: authenticate] Password:"
	for _, prefix := range []string{
		"banner " + strings.Repeat("x", sshAutoSudoTailBytes-len(prompt)-7),
		"\x1b]0;title\n",
		"\x1b]0;" + strings.Repeat("x", 2*sshAutoSudoTailBytes) + "\n",
	} {
		input := &recordingSSHInput{}
		driver := newSSHAutoSudoDriver(&sshNativeSession{stdin: input}, "secret")
		defer driver.dispose()
		driver.start()
		driver.observe([]byte(prefix))
		driver.observe([]byte(prompt))
		driver.observe([]byte(strings.Repeat(" ", sshAutoSudoTailBytes-len(prompt))))
		if input.String() != "sudo su\r" {
			t.Fatal("non-prompt output caused automatic credential submission")
		}
	}
}

func TestSSHAutoSudoStyledPromptAcrossChunks(t *testing.T) {
	const prompt = "\x1b[1m[sudo: authenticate]\x1b[0m Password: \x1b[0m"
	for split := 0; split <= len(prompt); split++ {
		input := &recordingSSHInput{}
		driver := newSSHAutoSudoDriver(&sshNativeSession{stdin: input}, "secret")
		driver.start()
		driver.observe([]byte(strings.Repeat("banner\r\n", 200)))
		driver.observe([]byte(prompt[:split]))
		driver.observe([]byte(prompt[split:]))
		if input.String() != "sudo su\rsecret\r" || driver.timeout != nil || driver.password != "" {
			t.Fatalf("split %d: styled prompt did not complete authentication", split)
		}
		driver.dispose()
	}
}

func TestSSHAutoSudoManualTakeover(t *testing.T) {
	for _, started := range []bool{false, true} {
		for _, typed := range []string{"p", "\x03", "\x04", "manual-password\r"} {
			input := &recordingSSHInput{}
			native := &sshNativeSession{stdin: input}
			driver := newSSHAutoSudoDriver(native, "secret")
			native.autoSudo = driver
			if started {
				driver.start()
			}
			initial := input.String()
			if err := native.write([]byte(typed)); err != nil {
				t.Fatal(err)
			}
			if input.String() != initial+typed || driver.timeout != nil || driver.password != "" {
				t.Fatal("manual takeover did not immediately release input and credentials")
			}
			driver.start()
			driver.observe([]byte("[sudo: authenticate] Password: "))
			driver.onTimeout()
			if err := native.write([]byte("next")); err != nil {
				t.Fatal(err)
			}
			if input.String() != initial+typed+"next" {
				t.Fatal("automatic reply or duplicate input after manual takeover")
			}
			driver.dispose()
		}
	}
}

func TestSSHAutoSudoManualTakeoverReportsInputError(t *testing.T) {
	native := &sshNativeSession{inputQueue: make(chan []byte, 1), done: make(chan struct{})}
	driver := newSSHAutoSudoDriver(native, "secret")
	native.autoSudo = driver
	driver.start() // Fill the queue with the sudo command.
	if err := native.write([]byte("\x03")); !errors.Is(err, errSSHInputFull) {
		t.Fatalf("write error = %v", err)
	}
	if driver.password != "" || driver.timeout != nil {
		t.Fatal("write failure retained automatic authentication")
	}
	driver.dispose()
}

func TestSSHAutoSudoAuthenticatePromptAcrossChunks(t *testing.T) {
	const prompt = "[sudo: authenticate] Password:"
	for split := 0; split <= len(prompt); split++ {
		input := &recordingSSHInput{}
		driver := newSSHAutoSudoDriver(&sshNativeSession{stdin: input}, "secret")
		t.Cleanup(driver.dispose)
		driver.start()
		driver.observe([]byte("operator@host:~$ sudo su\r\n"))
		driver.observe([]byte(prompt[:split]))
		if split < len(prompt) {
			requireAutoSudoCommand(t, input.String())
		}
		driver.observe([]byte(prompt[split:] + " "))
		if got := input.String(); got != "sudo su\rsecret\r" {
			t.Fatalf("split %d: expected one password response", split)
		}
		driver.observe([]byte("\r\nSorry, try again.\r\n" + prompt))
		if got := input.String(); got != "sudo su\rsecret\r" {
			t.Fatalf("split %d: password was sent again", split)
		}
		if driver.password != "" {
			t.Fatal("password retained after response")
		}
	}
}

func TestSSHAutoSudoAuthenticatePromptAfterStop(t *testing.T) {
	for _, stop := range []string{"timeout", "cancel"} {
		t.Run(stop, func(t *testing.T) {
			input := &recordingSSHInput{}
			driver := newSSHAutoSudoDriver(&sshNativeSession{stdin: input}, "secret")
			defer driver.dispose()
			driver.start()
			if stop == "timeout" {
				driver.onTimeout()
			} else {
				driver.dispose()
			}
			driver.observe([]byte("[sudo: authenticate] Password: "))
			requireAutoSudoCommand(t, input.String())
		})
	}
}
