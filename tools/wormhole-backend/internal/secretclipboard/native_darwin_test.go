//go:build darwin && cgo

package secretclipboard

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestMacClipboardNativeBridge(t *testing.T) {
	// Creation alone never writes or reads the general clipboard.
	general, err := NewNative()
	if err != nil {
		t.Fatal(err)
	}
	if err = general.Close(); err != nil {
		t.Fatal(err)
	}
	d, err := newMacClipboard(true)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	value := []byte("synthetic-clipboard-😀")
	original := bytes.Clone(value)
	ticket, err := d.Write(context.Background(), value)
	if err != nil || ticket == 0 || !bytes.Equal(value, original) {
		t.Fatal("native write", err)
	}
	if err = d.Clear(context.Background(), ticket); err != nil {
		t.Fatal(err)
	}
}

func TestMacClipboardAppKitOwnershipAndCoverage(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "pasteboard-tests")
	run := func(name string, args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, name, args...)
		out, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("native clipboard harness %s: %v\n%s", name, err, out)
		}
		return out
	}
	// A private named NSPasteboard exercises AppKit without touching user contents.
	// The same translation unit covers Objective-C exceptions and ownership races
	// with native fake boards, including the conditional erase after owner loss.
	run("xcrun", "clang", "-fprofile-instr-generate", "-fcoverage-mapping", "-Werror", "-Wall", "-Wextra", "testdata/pasteboard.m", "-framework", "AppKit", "-o", binary)
	raw := filepath.Join(directory, "native.profraw")
	profile := filepath.Join(directory, "native.profdata")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary)
	command.Env = append(os.Environ(), "LLVM_PROFILE_FILE="+raw)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("AppKit integration: %v\n%s", err, out)
	}
	run("xcrun", "llvm-profdata", "merge", "-sparse", raw, "-o", profile)
	report := run("xcrun", "llvm-cov", "export", binary, "-instr-profile="+profile)
	var result struct {
		Data []struct {
			Files []struct {
				Filename string
				Summary  struct{ Lines struct{ Count, Covered int } }
			}
		}
	}
	if err := json.Unmarshal(report, &result); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, data := range result.Data {
		for _, file := range data.Files {
			if filepath.Base(file.Filename) == "api_darwin.m" {
				found = true
				counts := file.Summary.Lines
				if counts.Count == 0 || 100*counts.Covered < 80*counts.Count {
					t.Fatalf("native clipboard coverage %d/%d", counts.Covered, counts.Count)
				}
				t.Logf("AppKit clipboard native coverage: %d/%d lines", counts.Covered, counts.Count)
			}
		}
	}
	if !found {
		t.Fatal("missing native clipboard coverage")
	}
}
