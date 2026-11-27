//go:build !linux && !windows

package main

import "io"

func runVaultSessionMonitor(io.Reader, io.Writer) int { return 1 }
