package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func init() {
	mode := os.Getenv("WORMHOLE_CAPABILITY_TEST_HELPER")
	if mode == "" {
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--capabilities" {
		switch mode {
		case "yes":
			fmt.Print(`{"version":1,"openVpn":true}`)
		case "no":
			fmt.Print(`{"version":1,"openVpn":false}`)
		case "future":
			fmt.Print(`{"version":2,"openVpn":true}`)
		case "unknown":
			fmt.Print(`{"version":1,"openVpn":true,"secret":"private"}`)
		case "trailing":
			fmt.Print(`{"version":1,"openVpn":true} {}`)
		case "large":
			fmt.Print(strings.Repeat("x", 4096))
		case "wait":
			time.Sleep(10 * time.Second)
		default:
			fmt.Fprintln(os.Stderr, "private provider diagnostic")
			os.Exit(2)
		}
		os.Exit(0)
	}
	// A normal tunnel launch still receives its config through stdin.
	var config json.RawMessage
	if json.NewDecoder(os.Stdin).Decode(&config) != nil {
		os.Exit(3)
	}
	fmt.Println("READY 32123")
	io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

func TestOpenVPNCapabilityProbe(t *testing.T) {
	for _, mode := range []string{"yes", "no", "future", "unknown", "trailing", "large", "error", "wait"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("WORMHOLE_CAPABILITY_TEST_HELPER", mode)
			timeout := 3 * time.Second
			if mode == "wait" {
				timeout = 100 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			err := probeOpenVPN(ctx, os.Args[0])
			if (err == nil) != (mode == "yes") {
				t.Fatalf("unexpected result: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "private") {
				t.Fatal("diagnostics leaked")
			}
		})
	}
	if err := probeOpenVPN(context.Background(), filepath.Join(t.TempDir(), "missing")); !errors.Is(err, errOpenVPNUnavailable) {
		t.Fatal(err)
	}
}

func TestOpenVPNGatePrecedesSecretReadAndVendorAuthentication(t *testing.T) {
	t.Setenv("WORMHOLE_OVPNPROXY_PATH", os.Args[0])
	t.Setenv("WORMHOLE_CAPABILITY_TEST_HELPER", "no")
	for _, kind := range []int64{1, 3, 4, 5} {
		ctx := withTunnelProgressHandler(context.Background(), func(context.Context, string, string) error {
			t.Fatal("provider preparation started before capability gate")
			return nil
		})
		// No database exists; an attempt to read saved credentials would change
		// the error. No SSO or refresh-token path may run before this check.
		if _, err := startTunnelProcess(ctx, tunnelConfigSnapshot{kind: kind, databasePath: "missing"}); !errors.Is(err, errOpenVPNUnavailable) {
			t.Fatal(err)
		}
	}
	for _, kind := range []int64{0, 2, 6, 7, 8, 99} {
		if tunnelRequiresOpenVPN(kind) {
			t.Fatalf("unrelated provider %d gated", kind)
		}
	}
	raw := json.RawMessage(`{"Password":"typed-secret"}`)
	startTunnelProcess(context.Background(), tunnelConfigSnapshot{kind: 1, settings: raw})
	if !bytes.Equal(raw, make([]byte, len(raw))) {
		t.Fatal("rejected settings not cleared")
	}
}

func TestOpenVPNAvailableStartsProbedSidecar(t *testing.T) {
	t.Setenv("WORMHOLE_OVPNPROXY_PATH", os.Args[0])
	t.Setenv("WORMHOLE_CAPABILITY_TEST_HELPER", "yes")
	process, err := startTunnelProcess(context.Background(), tunnelConfigSnapshot{kind: 1, settings: json.RawMessage(`{"ProfileOvpn":"client\n"}`)})
	if err != nil {
		t.Fatal(err)
	}
	defer process.close()
	if process.socks != "127.0.0.1:32123" {
		t.Fatal("tunnel not started")
	}
}

func TestTunnelCapabilitiesCLIRequiresNoDatabase(t *testing.T) {
	t.Setenv("WORMHOLE_OVPNPROXY_PATH", os.Args[0])
	t.Setenv("WORMHOLE_CAPABILITY_TEST_HELPER", "yes")
	var output, diagnostic bytes.Buffer
	if code := runBackendCLI([]string{"--operation", "tunnel-capabilities"}, nil, &output, &diagnostic); code != 0 || output.String() != "{\"openVpn\":true}\n" || diagnostic.Len() != 0 {
		t.Fatalf("capability CLI failed: %d, output=%q diagnostic=%q", code, output.String(), diagnostic.String())
	}
	if code := runBackendCLI([]string{"--operation", "tunnel-capabilities"}, nil, failedCapabilityOutput{}, &diagnostic); code != 1 {
		t.Fatal("closed capability output ignored")
	}
	t.Setenv("WORMHOLE_CAPABILITY_TEST_HELPER", "no")
	if readTunnelCapabilities(context.Background()).OpenVPN {
		t.Fatal("stub enabled")
	}
	t.Setenv("WORMHOLE_OVPNPROXY_PATH", filepath.Join(t.TempDir(), "missing"))
	if readTunnelCapabilities(context.Background()).OpenVPN {
		t.Fatal("missing engine enabled")
	}
}

type failedCapabilityOutput struct{}

func (failedCapabilityOutput) Write([]byte) (int, error) { return 0, errors.New("closed") }
