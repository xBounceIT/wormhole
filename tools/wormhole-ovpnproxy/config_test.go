package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

func TestConfigDecodesPhysicalTransportPlan(t *testing.T) {
	const payload = `{
		"profile_ovpn":"client\nremote vpn.example.test 443 tcp\n",
		"transport_adapter_ids":["adapter-a","adapter-b"],
		"transport_remotes":[
			{"host":"vpn.example.test","port":"443","protocol":"tcp"},
			{"host":"198.51.100.7","port":"1194","protocol":"udp4"}
		]
	}`

	var cfg config
	if err := json.Unmarshal([]byte(payload), &cfg); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(cfg.TransportAdapterIDs) != 2 || cfg.TransportAdapterIDs[1] != "adapter-b" {
		t.Fatalf("unexpected adapter IDs: %#v", cfg.TransportAdapterIDs)
	}
	if len(cfg.TransportRemotes) != 2 {
		t.Fatalf("unexpected remotes: %#v", cfg.TransportRemotes)
	}
	if got := cfg.TransportRemotes[0]; got.Host != "vpn.example.test" || got.Port != "443" || got.Protocol != "tcp" {
		t.Fatalf("unexpected first remote: %#v", got)
	}
	if got := cfg.TransportRemotes[1]; got.Host != "198.51.100.7" || got.Protocol != "udp4" {
		t.Fatalf("unexpected second remote: %#v", got)
	}
}

func TestValidateTransportIsolationRequiresBothHalves(t *testing.T) {
	t.Parallel()

	err := validateTransportIsolation(config{
		TransportAdapterIDs: []string{"adapter-a"},
	})
	if err == nil || !strings.Contains(err.Error(), "must be supplied together") {
		t.Fatalf("validateTransportIsolation() error = %v, want paired-field error", err)
	}
}

func TestValidateTransportIsolationRejectsIncompleteRemote(t *testing.T) {
	t.Parallel()

	err := validateTransportIsolation(config{
		TransportAdapterIDs: []string{"adapter-a"},
		TransportRemotes:    []transportRemote{{Host: "vpn.example.test", Port: "443"}},
	})
	if err == nil || !strings.Contains(err.Error(), "incomplete endpoint") {
		t.Fatalf("validateTransportIsolation() error = %v, want incomplete-endpoint error", err)
	}
}

func TestValidateTransportIsolationAcceptsCompleteOrAbsentPlan(t *testing.T) {
	if err := validateTransportIsolation(config{}); err != nil {
		t.Fatalf("empty plan: %v", err)
	}
	if err := validateTransportIsolation(config{
		TransportAdapterIDs: []string{" adapter-a "},
		TransportRemotes:    []transportRemote{{Host: " vpn.example.test ", Port: " 443 ", Protocol: " tcp "}},
	}); err != nil {
		t.Fatalf("complete plan: %v", err)
	}
}

func TestValidateTransportIsolationRejectsInvalidAdapters(t *testing.T) {
	tests := []config{
		{TransportAdapterIDs: []string{"adapter-a"}, TransportRemotes: nil},
		{TransportRemotes: []transportRemote{{Host: "host", Port: "443", Protocol: "tcp"}}},
		{TransportAdapterIDs: make([]string, 9), TransportRemotes: []transportRemote{{Host: "host", Port: "443", Protocol: "tcp"}}},
		{TransportAdapterIDs: []string{" "}, TransportRemotes: []transportRemote{{Host: "host", Port: "443", Protocol: "tcp"}}},
	}
	for index, cfg := range tests {
		if err := validateTransportIsolation(cfg); err == nil {
			t.Fatalf("case %d succeeded", index)
		}
	}
}

func TestStartOpenVPNStubExplainsMissingBinding(t *testing.T) {
	dialer, cleanup, err := startOpenVpn(context.Background(), config{})
	if err == nil || dialer != nil || cleanup != nil || !strings.Contains(err.Error(), "binding not linked") {
		t.Fatalf("startOpenVpn = dialer %#v, cleanup nil %v, error %v", dialer, cleanup == nil, err)
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
	t.Cleanup(func() {
		_ = stdinRead.Close()
		_ = stdinWrite.Close()
	})
	stdoutRead, stdoutWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdoutRead.Close()
		_ = stdoutWrite.Close()
	})
	os.Stdin = stdinRead
	os.Stdout = stdoutWrite
	outputResult := make(chan []byte, 1)
	go func() {
		output, _ := io.ReadAll(stdoutRead)
		outputResult <- output
	}()
	_, _ = io.WriteString(stdinWrite, `{"mock":true}`)
	_ = stdinWrite.Close()
	if err := run(false); err != nil {
		t.Fatalf("run(false) returned %v", err)
	}
	_ = stdoutWrite.Close()
	if output := <-outputResult; !strings.HasPrefix(string(output), "READY ") {
		t.Fatalf("output = %q", output)
	}
}

func TestRunRejectsBadInputAndMissingProfile(t *testing.T) {
	originalStdin := os.Stdin
	t.Cleanup(func() { os.Stdin = originalStdin })
	for _, test := range []struct {
		name    string
		payload string
		want    string
	}{
		{name: "JSON", payload: "{", want: "reading config"},
		{name: "transport", payload: `{"transport_adapter_ids":["adapter"]}`, want: "physical transport isolation"},
		{name: "profile", payload: `{}`, want: "profile_ovpn"},
	} {
		t.Run(test.name, func(t *testing.T) {
			read, write, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			os.Stdin = read
			_, _ = io.WriteString(write, test.payload)
			_ = write.Close()
			if err := run(false); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("run(false) error = %v", err)
			}
			_ = read.Close()
		})
	}
}
