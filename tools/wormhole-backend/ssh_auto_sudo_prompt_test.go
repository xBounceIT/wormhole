package main

import "testing"

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
			if got := hasSSHSudoPasswordPrompt([]byte(tt.text)); got != tt.want {
				t.Fatalf("prompt recognized = %v, want %v", got, tt.want)
			}
		})
	}
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
