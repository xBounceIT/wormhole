package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"time"
)

var errOpenVPNUnavailable = errors.New("This build has no usable OpenVPN engine. OpenVPN, WatchGuard, Stormshield and Azure VPN are unavailable.")

type tunnelCapabilities struct {
	OpenVPN bool `json:"openVpn"`
}

func tunnelRequiresOpenVPN(kind int64) bool {
	return kind == 1 || kind == 3 || kind == 4 || kind == 5
}

type capabilityOutput struct{ buffer bytes.Buffer }

func (b *capabilityOutput) Write(p []byte) (int, error) {
	if b.buffer.Len()+len(p) > 1024 {
		return 0, errOpenVPNUnavailable
	}
	return b.buffer.Write(p)
}

func probeOpenVPN(ctx context.Context, path string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, path, "--capabilities")
	command.WaitDelay = 100 * time.Millisecond
	var output capabilityOutput
	command.Stdout = &output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errOpenVPNUnavailable
	}
	var result struct {
		Version int  `json:"version"`
		OpenVPN bool `json:"openVpn"`
	}
	decoder := json.NewDecoder(&output.buffer)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || result.Version != 1 || !result.OpenVPN {
		return errOpenVPNUnavailable
	}
	return nil
}

func requireOpenVPN(ctx context.Context) (string, error) {
	path, err := findTunnelSidecar("wormhole-ovpnproxy")
	if err != nil {
		return "", errOpenVPNUnavailable
	}
	if err := probeOpenVPN(ctx, path); err != nil {
		return "", err
	}
	return path, nil
}

func readTunnelCapabilities(ctx context.Context) tunnelCapabilities {
	_, err := requireOpenVPN(ctx)
	return tunnelCapabilities{OpenVPN: err == nil}
}
