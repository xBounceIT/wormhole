package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"testing"
)

type processExitFailWriter struct{}

func (processExitFailWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

// The response contract is portable even though only Windows needs this fallback.
// Exercise every reply/error branch on Linux/macOS too, without claiming native
// support or replacing the actual Windows kernel adapter tests.
func TestVaultProcessExitOutputContract(t *testing.T) {
	for _, terminated := range []bool{false, true} {
		var output, diagnostics bytes.Buffer
		query := func(pid uint32) (bool, error) {
			if pid != 123 {
				t.Fatal("wrong PID")
			}
			return terminated, nil
		}
		if writeProcessExitProof(123, &output, &diagnostics, query) != 0 || diagnostics.Len() != 0 {
			t.Fatal("valid response rejected")
		}
		var value map[string]any
		if json.Unmarshal(output.Bytes(), &value) != nil || len(value) != 3 || value["version"] != float64(1) || value["pid"] != float64(123) || value["terminated"] != terminated {
			t.Fatal("wrong public response", output.String())
		}
		if writeProcessExitProof(123, processExitFailWriter{}, &diagnostics, query) != 1 {
			t.Fatal("output failure acknowledged")
		}
	}
	var output, diagnostics bytes.Buffer
	if writeProcessExitProof(123, &output, &diagnostics, func(uint32) (bool, error) {
		return true, errors.New("private native failure")
	}) != 1 || output.Len() != 0 || diagnostics.String() != "process_exit_unconfirmed\n" {
		t.Fatal("native failure leaked or acknowledged")
	}
	for _, pid := range []uint64{0, 1 << 32} {
		if writeProcessExitProof(pid, io.Discard, io.Discard, func(uint32) (bool, error) {
			t.Fatal("invalid PID reached native query")
			return false, nil
		}) != 1 {
			t.Fatal("invalid PID accepted")
		}
	}
}

func TestVaultProcessExitCLIRejectsInvalidPIDWithoutWorkspace(t *testing.T) {
	for _, pid := range []string{"0", "4294967296"} {
		var out, diagnostic bytes.Buffer
		if code := runBackendCLI([]string{"--operation", "process-exit-proof", "--process-id", pid}, bytes.NewReader(nil), &out, &diagnostic); code != 1 || out.Len() != 0 || diagnostic.String() != "process_exit_unconfirmed\n" {
			t.Fatal("invalid PID accepted", code, out.String(), diagnostic.String())
		}
	}
	var out, diagnostic bytes.Buffer
	code := runProcessExitProof(uint64(os.Getpid()), &out, &diagnostic)
	if runtime.GOOS != "windows" {
		if code != 1 || out.Len() != 0 {
			t.Fatal("unsupported query acknowledged")
		}
		return
	}
	var result struct {
		Version    int
		PID        uint32
		Terminated bool
	}
	if code != 0 || json.Unmarshal(out.Bytes(), &result) != nil || result.Version != 1 || result.PID != uint32(os.Getpid()) || result.Terminated {
		t.Fatal("live process acknowledged", code, out.String())
	}
	if runProcessExitProof(uint64(os.Getpid()), processExitFailWriter{}, &diagnostic) != 1 {
		t.Fatal("output failure acknowledged")
	}
}
