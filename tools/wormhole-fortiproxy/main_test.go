package main

import (
	"context"
	"io"
	"net"
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

func TestStartFortinetValidatesBeforeNetwork(t *testing.T) {
	value := "value"
	valid := config{Host: "vpn.example.test", Port: 443, Username: "alice", Password: "secret"}
	tests := []struct {
		name   string
		cfg    config
		cancel context.CancelFunc
		want   string
	}{
		{name: "cancel", cfg: valid, want: "outerCancel"},
		{name: "host", cfg: config{Port: 443, Username: "alice", Password: "secret"}, cancel: func() {}, want: "host"},
		{name: "credentials", cfg: config{Host: "vpn.example.test", Port: 443}, cancel: func() {}, want: "username and password"},
		{name: "SAML credentials", cfg: config{Host: "vpn.example.test", Port: 443, SamlAuthID: &value, TotpSecret: &value}, cancel: func() {}, want: "mutually exclusive"},
		{name: "low port", cfg: config{Host: "vpn.example.test", Port: -1, Username: "alice", Password: "secret"}, cancel: func() {}, want: "invalid port"},
		{name: "high port", cfg: config{Host: "vpn.example.test", Port: 65536, Username: "alice", Password: "secret"}, cancel: func() {}, want: "invalid port"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, _, err := startFortinet(context.Background(), test.cancel, test.cfg)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("startFortinet error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestOSDialerConnectsToLocalListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, _ := listener.Accept()
		accepted <- connection
	}()
	connection, err := (osDialer{}).DialContext(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	peer := <-accepted
	if peer == nil {
		t.Fatal("listener did not accept connection")
	}
	_ = peer.Close()
}
