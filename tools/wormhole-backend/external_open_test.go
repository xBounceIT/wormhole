package main

import (
	"slices"
	"testing"
)

func TestExternalOpenCommandUsesNativeLaunchersWithoutAShell(t *testing.T) {
	t.Parallel()
	target := "/tmp/Wormhole log - 20260810.txt"
	tests := []struct {
		goos      string
		program   string
		arguments []string
	}{
		{goos: "windows", program: "rundll32.exe", arguments: []string{"url.dll,FileProtocolHandler", target}},
		{goos: "darwin", program: "open", arguments: []string{target}},
		{goos: "linux", program: "xdg-open", arguments: []string{target}},
	}
	for _, test := range tests {
		program, arguments := externalOpenCommand(test.goos, target)
		if program != test.program || !slices.Equal(arguments, test.arguments) {
			t.Fatalf("externalOpenCommand(%q) = %q %#v, want %q %#v", test.goos, program, arguments, test.program, test.arguments)
		}
	}
}
