package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	ipsec "github.com/n0madic/go-ipsec"
	"io"
	"testing"
)

func TestGatewayDeathDuringStartupStillTriesBackup(t *testing.T) {
	cfg := fixtureConfig()
	options := ipsec.DefaultFortinetOptions()
	options.RemoteGateways = "backup.test"
	cfg.Options = &options
	input, writer := io.Pipe()
	defer writer.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var output bytes.Buffer
	calls := make(chan []string, 1)
	done := make(chan error, 1)
	go func() {
		var visited []string
		done <- run(ctx, input, &output, func(_ context.Context, prepared ipsec.Config) (tunnelClient, error) {
			visited = append(visited, prepared.Server)
			if len(visited) == 1 {
				prepared.OnDead()
				return nil, errors.New("peer deleted initial SA")
			}
			cancel()
			return &fakeClient{closed: make(chan struct{})}, nil
		})
		calls <- visited
	}()
	fmt.Fprint(writer, configLine(cfg))
	_ = <-done
	visited := <-calls
	if len(visited) != 2 || visited[1] != "backup.test:500" {
		t.Fatalf("startup death cancelled all gateways: %v", visited)
	}
}
