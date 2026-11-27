//go:build !windows

package main

import "os/exec"

func startOwnedHelper(cmd *exec.Cmd) error { return cmd.Start() }
