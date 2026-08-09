package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestReadConfigDefaultsPort(t *testing.T) {
	originalStdin := os.Stdin
	t.Cleanup(func() { os.Stdin = originalStdin })
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = read
	_, _ = io.WriteString(write, `{"host":"vpn.example.test"}`)
	_ = write.Close()
	cfg, err := readConfig()
	if err != nil || cfg.Host != "vpn.example.test" || cfg.Port != 443 {
		t.Fatalf("readConfig = %#v, %v", cfg, err)
	}
}

func TestRunMockReadsConfigAndStopsAtEOF(t *testing.T) {
	originalStdin := os.Stdin
	originalStdout := os.Stdout
	t.Cleanup(func() {
		os.Stdin = originalStdin
		os.Stdout = originalStdout
	})
	stdinRead, stdinWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutRead, stdoutWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = stdinRead
	os.Stdout = stdoutWrite
	outputResult := make(chan []byte, 1)
	go func() {
		output, _ := io.ReadAll(stdoutRead)
		outputResult <- output
	}()
	_, _ = io.WriteString(stdinWrite, `{}`)
	_ = stdinWrite.Close()
	if err := run(true); err != nil {
		t.Fatalf("run(true) returned %v", err)
	}
	_ = stdoutWrite.Close()
	if output := <-outputResult; !strings.HasPrefix(string(output), "READY ") {
		t.Fatalf("output = %q", output)
	}
}

func TestRunRejectsInvalidJSON(t *testing.T) {
	originalStdin := os.Stdin
	t.Cleanup(func() { os.Stdin = originalStdin })
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = read
	_, _ = io.WriteString(write, "{")
	_ = write.Close()
	if err := run(true); err == nil || !strings.Contains(err.Error(), "reading config") {
		t.Fatalf("run(true) error = %v", err)
	}
}
