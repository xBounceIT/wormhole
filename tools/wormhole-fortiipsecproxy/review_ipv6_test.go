package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	ipsec "github.com/n0madic/go-ipsec"
)

func TestGatewayIPv6NormalizationAppliesToEachAttempt(t *testing.T) {
	cfg := fixtureConfig()
	options := ipsec.DefaultFortinetOptions()
	options.RemoteGateways = "[2001:db8::2]"
	cfg.Options = &options
	cfg.Host = "[2001:db8::1]"
	input, writer := io.Pipe()
	defer writer.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var output bytes.Buffer
	var visited []string
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, input, &output, func(_ context.Context, prepared ipsec.Config) (tunnelClient, error) {
			visited = append(visited, prepared.Server)
			if len(visited) == 1 {
				return nil, errors.New("primary unavailable")
			}
			cancel()
			return &fakeClient{closed: make(chan struct{})}, nil
		})
	}()
	fmt.Fprint(writer, configLine(cfg))
	<-done
	if len(visited) != 2 || visited[0] != "[2001:db8::1]:500" || visited[1] != "[2001:db8::2]:500" {
		t.Fatalf("IPv6 gateway normalization differs across attempts: %v", visited)
	}
}
