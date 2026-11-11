// Package vlog deliberately discards protocol diagnostics, which can contain secrets.
package vlog

import "io"

type Logger struct{}

func Plain(io.Writer) *Logger         { return &Logger{} }
func (*Logger) Printf(string, ...any) {}
