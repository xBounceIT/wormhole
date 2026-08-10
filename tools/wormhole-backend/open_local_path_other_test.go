//go:build !windows

package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func TestOpenLocalPathStartsAndReapsThePlatformLauncher(t *testing.T) {
	original := newLocalPathOpenCommand
	t.Cleanup(func() { newLocalPathOpenCommand = original })

	var program string
	var arguments []string
	newLocalPathOpenCommand = func(name string, args ...string) *exec.Cmd {
		program = name
		arguments = append([]string(nil), args...)
		return exec.Command("true")
	}
	target := filepath.Join(t.TempDir(), "Wormhole log.txt")
	if err := openLocalPathWithShell(target); err != nil {
		t.Fatal(err)
	}
	wantProgram, wantArguments := externalOpenCommand(runtime.GOOS, target)
	if program != wantProgram || !slices.Equal(arguments, wantArguments) {
		t.Fatalf("platform launcher = %q %#v, want %q %#v", program, arguments, wantProgram, wantArguments)
	}

	newLocalPathOpenCommand = func(string, ...string) *exec.Cmd {
		return exec.Command(filepath.Join(t.TempDir(), "missing-file-opener"))
	}
	if err := openLocalPathWithShell(target); err == nil {
		t.Fatal("missing platform launcher returned no error")
	}
}
