package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Native process integration only: public route metadata, synthetic profile,
// actual HPKE and the production controller/launcher. No VPN or network access.
func TestSealedTunnelRetirementInteropFixture(t *testing.T) {
	mode := os.Getenv("WORMHOLE_TEST_ROUTE_RETIREMENT")
	if mode == "" {
		t.Skip("native route retirement fixture")
	}
	raw := []byte(os.Getenv("WORMHOLE_TEST_ROUTE_BINDING"))
	if len(raw) > 4096 {
		os.Exit(2)
	}
	binding, err := decodeTunnelBundleBinding(raw)
	if err != nil {
		os.Exit(2)
	}
	configuration := []byte(`{"ProfileOvpn":"test-profile"}`)
	if mode == "seal" {
		var public []byte
		decoder := json.NewDecoder(io.LimitReader(os.Stdin, 256))
		if decoder.Decode(&public) != nil || len(public) != 32 || decoder.Decode(new(any)) != io.EOF {
			os.Exit(2)
		}
		bundle, err := vault.SealTunnelBundle(public, binding, configuration)
		if err != nil || json.NewEncoder(os.Stdout).Encode(map[string]any{"binding": binding, "bundle": bundle}) != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	if mode != "ready" && mode != "startup-error" {
		os.Exit(2)
	}
	var owned *tunnelProcess
	err = serveSealedTunnel(os.Stdin, os.Stdout, func(ctx context.Context, got vault.TunnelBundleBinding, raw []byte) (*tunnelProcess, error) {
		if got != binding || !bytes.Equal(raw, configuration) {
			return nil, vault.ErrAuthentication
		}
		command := exec.Command(os.Args[0], "-test.run=^TestSealedTunnelSidecarFixture$", "-test.timeout=20s")
		command.Env = append(os.Environ(), "WORMHOLE_TEST_SEALED_TUNNEL=slow-shutdown")
		var err error
		owned, err = launchSealedTunnel(ctx, command, raw)
		if err == nil {
			_, _ = fmt.Fprintln(os.Stderr, "sidecar-started")
			if mode == "startup-error" {
				return owned, vault.ErrPolicy
			}
		}
		return owned, err
	})
	if owned == nil || owned.command.ProcessState == nil || owned.alive() {
		os.Exit(3)
	}
	_, _ = fmt.Fprintln(os.Stderr, "sidecar-retired")
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

// Only the sidecar/provider transport is synthetic. Both native recipients,
// purpose-bound HPKE packets and the original OS retirement barrier are real.
func TestSealedTunnelFallbackInteropFixture(t *testing.T) {
	mode := os.Getenv("WORMHOLE_TEST_ROUTE_FALLBACK")
	if mode == "" {
		t.Skip("native route fallback fixture")
	}
	raw := []byte(os.Getenv("WORMHOLE_TEST_ROUTE_PAIR"))
	if len(raw) > 8192 {
		os.Exit(2)
	}
	pair, err := decodeTunnelFallbackBinding(raw)
	if err != nil {
		os.Exit(2)
	}
	primary := primaryTunnelConfiguration(t, pair.Fallback.TunnelConfigID, 0)
	secondary := []byte(`{"Host":"ssl.test","Username":"test-user","Password":"test-profile"}`)
	if mode == "seal-primary" || mode == "seal-secondary" {
		var public []byte
		decoder := json.NewDecoder(io.LimitReader(os.Stdin, 256))
		if decoder.Decode(&public) != nil || len(public) != 32 || decoder.Decode(new(any)) != io.EOF {
			os.Exit(2)
		}
		var binding any = pair.Primary
		bundle, err := vault.SealTunnelBundle(public, pair.Primary, primary)
		if mode == "seal-secondary" {
			binding = pair
			bundle, err = vault.SealTunnelFallback(public, pair, secondary)
		}
		if err != nil || json.NewEncoder(os.Stdout).Encode(map[string]any{"binding": binding, "bundle": bundle}) != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	if mode != "primary" && mode != "secondary" {
		os.Exit(2)
	}
	open := openSealedTunnelConfiguration
	if mode == "secondary" {
		open = openSealedTunnelFallbackConfiguration
	}
	var owned *tunnelProcess
	err = serveSealedTunnelActor(os.Stdin, os.Stdout, func(ctx context.Context, got vault.TunnelBundleBinding, raw []byte) (*tunnelProcess, error) {
		if mode == "primary" {
			expected, eligible, e := prepareSealedPrimaryTunnel(pair.Primary, primary)
			if e != nil || !eligible || got != pair.Primary || !bytes.Equal(raw, expected) {
				return nil, vault.ErrAuthentication
			}
		} else if got != pair.Fallback || !bytes.Equal(raw, secondary) {
			return nil, vault.ErrAuthentication
		}
		command := exec.Command(os.Args[0], "-test.run=^TestSealedTunnelSidecarFixture$", "-test.timeout=20s")
		command.Env = append(os.Environ(), "WORMHOLE_TEST_SEALED_TUNNEL=slow-shutdown")
		var err error
		owned, err = launchSealedTunnel(ctx, command, raw)
		if err == nil {
			_, _ = fmt.Fprintln(os.Stderr, "sidecar-started")
			if mode == "primary" {
				return owned, vault.ErrPolicy
			}
		}
		return owned, err
	}, open, mode == "primary")
	if owned == nil || owned.command.ProcessState == nil || owned.alive() {
		os.Exit(3)
	}
	_, _ = fmt.Fprintln(os.Stderr, "sidecar-retired")
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
