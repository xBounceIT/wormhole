//go:build windows

package main

import (
	"strings"
	"testing"
)

func TestShellExecuteErrorMapping(t *testing.T) {
	tests := []struct {
		code uintptr
		want string
	}{
		{2, "cannot find the specified file"},
		{3, "cannot find the specified path"},
		{5, "access was denied"},
		{31, "no application is associated"},
		{32, "specified DLL was not found"},
		{99, "error code 99"},
	}
	for _, test := range tests {
		message := shellExecuteError(test.code).Error()
		if !strings.Contains(message, test.want) {
			t.Fatalf("shellExecuteError(%d) = %q, want it to contain %q", test.code, message, test.want)
		}
	}
}
