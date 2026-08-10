//go:build !windows

package main

import (
	"fmt"
	"os/exec"
	"runtime"
)

var newLocalPathOpenCommand = exec.Command

func openLocalPathWithShell(path string) error {
	program, arguments := externalOpenCommand(runtime.GOOS, path)
	command := newLocalPathOpenCommand(program, arguments...)
	if err := command.Start(); err != nil {
		return fmt.Errorf("could not start the system file opener: %w", err)
	}
	// Reap the short-lived launcher without blocking the backend request. The launcher owns the
	// desktop application after Start returns, matching ShellExecuteW on Windows.
	go func() { _ = command.Wait() }()
	return nil
}
