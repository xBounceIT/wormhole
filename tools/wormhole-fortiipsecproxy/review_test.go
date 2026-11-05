package main

import (
	"bufio"
	"context"
	"errors"
	ipsec "github.com/n0madic/go-ipsec"
	"io"
	"strings"
	"testing"
)

func TestReviewAdmittedEscapedConfigFitsSidecar(t *testing.T) {
	cfg := fixtureConfig()
	cfg.PreSharedKey = strings.Repeat("<", 4096)
	cfg.LocalID = strings.Repeat("&", 4096)
	cfg.RemoteID = strings.Repeat(">", 4096)
	line := configLine(cfg)
	if len(line) <= 32*1024 {
		t.Fatal("fixture must exercise JSON expansion beyond old line limit")
	}
	read, err := readConfig(bufio.NewReaderSize(strings.NewReader(line), 96*1024+1))
	if err != nil {
		t.Fatal("backend-admitted settings rejected after JSON escaping", err)
	}
	if read.PreSharedKey != cfg.PreSharedKey || read.LocalID != cfg.LocalID || read.RemoteID != cfg.RemoteID {
		t.Fatal("valid settings were altered")
	}
	called := false
	_ = run(context.Background(), strings.NewReader(line), io.Discard, func(_ context.Context, received ipsec.Config) (tunnelClient, error) {
		called = true
		if received.ServerPSK != cfg.PreSharedKey {
			t.Error("runner changed the PSK")
		}
		return nil, errors.New("stop after decoding")
	})
	if !called {
		t.Fatal("runner rejected the encoded configuration before handshake")
	}
}

func TestReviewBracketedIPv6Gateway(t *testing.T) {
	cfg := fixtureConfig()
	cfg.Host = "[2001:db8::1]"
	read, err := readConfig(bufio.NewReader(strings.NewReader(configLine(cfg))))
	if err != nil {
		t.Fatal(err)
	}
	if got := clientConfig(read, func() {}).Server; got != "[2001:db8::1]:500" {
		t.Fatalf("admitted IPv6 gateway became %q", got)
	}
}
