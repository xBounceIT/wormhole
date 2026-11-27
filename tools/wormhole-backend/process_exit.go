package main

import (
	"encoding/json"
	"io"
	"math"
)

// Secret-free native lifecycle query. It opens no workspace, log or key store.
// An exit code alone is not a termination proof on Windows.
func runProcessExitProof(pid uint64, output, diagnostics io.Writer) int {
	return writeProcessExitProof(pid, output, diagnostics, nativeProcessTerminated)
}

func writeProcessExitProof(pid uint64, output, diagnostics io.Writer, query func(uint32) (bool, error)) int {
	if pid == 0 || pid > math.MaxUint32 {
		_, _ = io.WriteString(diagnostics, "process_exit_unconfirmed\n")
		return 1
	}
	terminated, err := query(uint32(pid))
	if err != nil {
		_, _ = io.WriteString(diagnostics, "process_exit_unconfirmed\n")
		return 1
	}
	if json.NewEncoder(output).Encode(struct {
		Version    int    `json:"version"`
		PID        uint32 `json:"pid"`
		Terminated bool   `json:"terminated"`
	}{1, uint32(pid), terminated}) != nil {
		return 1
	}
	return 0
}
