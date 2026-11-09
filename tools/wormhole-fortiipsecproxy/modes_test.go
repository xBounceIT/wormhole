package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	ipsec "github.com/n0madic/go-ipsec"
)

func TestNativeAuthenticationModes(t *testing.T) {
	for _, auth := range []int{0, 1, 2, 3} {
		options := ipsec.DefaultFortinetOptions()
		options.UserAuth = auth
		cfg := fixtureConfig()
		cfg.Options = &options
		cfg.Username = "user"
		cfg.Password = "password"
		if auth != 3 {
			cfg.SamlUID = ""
			cfg.SamlToken = ""
		}
		parsed, err := readConfig(bufio.NewReader(strings.NewReader(configLine(cfg))))
		if err != nil {
			t.Fatal("non-SAML mode required a token", err)
		}
		prepared, err := prepareClientConfig(parsed, func() {})
		if err != nil {
			t.Fatal(err)
		}
		if auth == 0 {
			if prepared.PSK != cfg.PreSharedKey || prepared.FortinetSAML || prepared.LocalID.IsZero() {
				t.Fatal("PSK mode incorrect")
			}
		} else if !prepared.FortinetSAML {
			t.Fatal("PSK/EAP responder authentication omitted")
		}
		if auth == 1 || auth == 2 {
			if prepared.EAP.Username != cfg.Username || prepared.EAP.Password != cfg.Password {
				t.Fatal("EAP credentials lost")
			}
		}
	}
	cfg := fixtureConfig()
	options := ipsec.DefaultFortinetOptions()
	options.AuthMethod = 1
	cfg.Options = &options
	cfg.PreSharedKey = ""
	cfg.SamlUID = ""
	cfg.SamlToken = ""
	if _, err := readConfig(bufio.NewReader(strings.NewReader(configLine(cfg)))); err != nil {
		t.Fatal("certificate mode requires PSK", err)
	}
	if _, err := prepareClientConfig(cfg, func() {}); err == nil {
		t.Fatal("missing certificate accepted")
	}
	for _, value := range []string{"bad/host", "bad host", "a,,b", strings.Repeat("a,", 9) + "b"} {
		options.RemoteGateways = value
		if _, err := readConfig(bufio.NewReader(strings.NewReader(configLine(cfg)))); err == nil {
			t.Fatal("invalid fallback gateway accepted")
		}
	}
}

func TestGatewayFailoverClosesFailedAttempts(t *testing.T) {
	options := ipsec.DefaultFortinetOptions()
	options.RemoteGateways = "backup.test"
	cfg := fixtureConfig()
	cfg.Options = &options
	input, writer := io.Pipe()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := &fakeClient{closed: make(chan struct{})}
	second := &fakeClient{closed: make(chan struct{})}
	var visited []string
	var output bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, input, &output, func(_ context.Context, prepared ipsec.Config) (tunnelClient, error) {
			visited = append(visited, prepared.Server)
			if len(visited) == 1 {
				return first, errors.New("private diagnostics")
			}
			cancel()
			return second, nil
		})
	}()
	fmt.Fprint(writer, configLine(cfg))
	err := <-done
	if err == nil || output.Len() != 0 || len(visited) != 2 || visited[1] != "backup.test:500" {
		t.Fatal("incorrect failover behavior", err, visited)
	}
	for _, client := range []*fakeClient{first, second} {
		select {
		case <-client.closed:
		default:
			t.Fatal("failed attempt leaked")
		}
	}
}

func TestUnsupportedOptionsFailBeforeConnecting(t *testing.T) {
	options := ipsec.DefaultFortinetOptions()
	options.NatTraversal = false
	cfg := fixtureConfig()
	cfg.Options = &options
	input, writer := io.Pipe()
	defer writer.Close()
	done := make(chan error, 1)
	var output bytes.Buffer
	go func() {
		done <- run(context.Background(), input, &output, func(context.Context, ipsec.Config) (tunnelClient, error) {
			t.Error("unsupported configuration reached network")
			return nil, nil
		})
	}()
	fmt.Fprint(writer, configLine(cfg))
	if err := <-done; err == nil || output.Len() != 0 {
		t.Fatal("unsupported option was ignored")
	}
}
