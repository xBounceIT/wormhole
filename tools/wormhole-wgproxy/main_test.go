package main

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
)

func testKey(seed byte) string {
	raw := make([]byte, 32)
	for index := range raw {
		raw[index] = seed + byte(index)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestParseAddrFromCIDROrPlain(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "plain IPv4", input: " 10.0.0.2 ", want: "10.0.0.2"},
		{name: "IPv4 prefix", input: "10.0.0.2/24", want: "10.0.0.2"},
		{name: "IPv6 prefix", input: "fd00::2/64", want: "fd00::2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseAddrFromCidrOrPlain(test.input)
			if err != nil || got.String() != test.want {
				t.Fatalf("parseAddrFromCidrOrPlain(%q) = %q, %v", test.input, got, err)
			}
		})
	}
	for _, input := range []string{"invalid", "10.0.0.2/not-a-prefix"} {
		if _, err := parseAddrFromCidrOrPlain(input); err == nil {
			t.Fatalf("parseAddrFromCidrOrPlain(%q) succeeded", input)
		}
	}
}

func TestBase64KeyToHex(t *testing.T) {
	key := testKey(1)
	got, err := base64KeyToHex(" \n" + key + "\t")
	if err != nil {
		t.Fatalf("base64KeyToHex returned an error: %v", err)
	}
	if len(got) != 64 || !strings.HasPrefix(got, "01020304") {
		t.Fatalf("base64KeyToHex returned %q", got)
	}
	for _, input := range []string{"%%%", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := base64KeyToHex(input); err == nil {
			t.Fatalf("base64KeyToHex(%q) succeeded", input)
		}
	}
}

func TestResolveEndpoint(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "127.0.0.1:51820", want: "127.0.0.1:51820"},
		{input: "[::1]:51820", want: "[::1]:51820"},
	} {
		got, err := resolveEndpoint(context.Background(), test.input)
		if err != nil || got != test.want {
			t.Fatalf("resolveEndpoint(%q) = %q, %v", test.input, got, err)
		}
	}
	if _, err := resolveEndpoint(context.Background(), "missing-port"); err == nil {
		t.Fatal("resolveEndpoint accepted an endpoint without a port")
	}

	got, err := resolveEndpoint(context.Background(), "localhost:53")
	if err != nil {
		t.Fatalf("resolveEndpoint(localhost) returned an error: %v", err)
	}
	host, port, err := net.SplitHostPort(got)
	if err != nil || net.ParseIP(host) == nil || port != "53" {
		t.Fatalf("resolveEndpoint(localhost) returned %q", got)
	}
}

func TestStartWireGuardValidatesConfig(t *testing.T) {
	valid := config{
		InterfacePrivateKey: testKey(1),
		InterfaceAddress:    "10.0.0.2/32",
		PeerPublicKey:       testKey(33),
		PeerEndpoint:        "127.0.0.1:51820",
	}
	tests := []struct {
		name   string
		mutate func(*config)
		want   string
	}{
		{name: "private key", mutate: func(cfg *config) { cfg.InterfacePrivateKey = "" }, want: "interface_private_key"},
		{name: "interface address", mutate: func(cfg *config) { cfg.InterfaceAddress = "" }, want: "interface_address"},
		{name: "public key", mutate: func(cfg *config) { cfg.PeerPublicKey = "" }, want: "peer_public_key"},
		{name: "endpoint", mutate: func(cfg *config) { cfg.PeerEndpoint = "" }, want: "peer_endpoint"},
		{name: "invalid address", mutate: func(cfg *config) { cfg.InterfaceAddress = "invalid" }, want: "interface_address"},
		{name: "invalid DNS", mutate: func(cfg *config) { cfg.Dns = []string{"invalid"} }, want: "dns"},
		{name: "invalid endpoint", mutate: func(cfg *config) { cfg.PeerEndpoint = "invalid" }, want: "resolve endpoint"},
		{name: "invalid private key", mutate: func(cfg *config) { cfg.InterfacePrivateKey = "invalid" }, want: "interface private key"},
		{name: "invalid public key", mutate: func(cfg *config) { cfg.PeerPublicKey = "invalid" }, want: "peer public key"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid
			test.mutate(&cfg)
			_, _, err := startWireGuard(context.Background(), cfg)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("startWireGuard error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestStartWireGuardCreatesAndCleansUpDevice(t *testing.T) {
	mtu := 1280
	keepalive := 15
	psk := testKey(65)
	dialer, cleanup, err := startWireGuard(context.Background(), config{
		InterfacePrivateKey:        testKey(1),
		InterfaceAddress:           "10.0.0.2/32",
		Mtu:                        &mtu,
		Dns:                        []string{"1.1.1.1", "2606:4700:4700::1111"},
		PeerPublicKey:              testKey(33),
		PeerPresharedKey:           &psk,
		PeerEndpoint:               "127.0.0.1:51820",
		AllowedIps:                 []string{" 10.0.0.0/8 ", " fd00::/8 "},
		PersistentKeepaliveSeconds: &keepalive,
	})
	if err != nil {
		t.Fatalf("startWireGuard returned an error: %v", err)
	}
	if dialer == nil || cleanup == nil {
		t.Fatal("startWireGuard returned nil resources")
	}
	cleanup()
}

func TestStartWireGuardRejectsInvalidPresharedKey(t *testing.T) {
	psk := "invalid"
	_, _, err := startWireGuard(context.Background(), config{
		InterfacePrivateKey: testKey(1),
		InterfaceAddress:    "10.0.0.2/32",
		PeerPublicKey:       testKey(33),
		PeerPresharedKey:    &psk,
		PeerEndpoint:        "127.0.0.1:51820",
	})
	if err == nil || !strings.Contains(err.Error(), "peer preshared key") {
		t.Fatalf("startWireGuard error = %v", err)
	}
}

func TestRunMockReadsConfigAndStopsAtStdinEOF(t *testing.T) {
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
	if err := run(true); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("run(true) returned an error: %v", err)
	}
	_ = stdoutWrite.Close()
	output := <-outputResult
	if !strings.HasPrefix(string(output), "READY ") {
		t.Fatalf("run(true) output = %q", output)
	}
}

func TestReadConfigRejectsInvalidJSON(t *testing.T) {
	originalStdin := os.Stdin
	t.Cleanup(func() { os.Stdin = originalStdin })
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = read
	_, _ = io.WriteString(write, "{")
	_ = write.Close()
	if _, err := readConfig(); err == nil {
		t.Fatal("readConfig accepted invalid JSON")
	}
}
