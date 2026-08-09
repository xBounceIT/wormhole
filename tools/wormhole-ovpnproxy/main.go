// wormhole-ovpnproxy is the userspace OpenVPN sidecar that Wormhole launches per active
// connection. It runs an OpenVPN3-core client entirely in user space, plugs its TUN
// endpoint into gVisor netstack (no Wintun adapter, no routes, nothing the OS sees), and
// exposes the resulting virtual network through a local SOCKS5 listener on 127.0.0.1.
//
// Protocol with the parent (mirrors wormhole-wgproxy):
//
//   - stdin:  one JSON object on the first line, then EOF acts as the shutdown signal.
//   - stdout: a single line "READY <port>\n" once the SOCKS5 listener is up AND the
//             OpenVPN session is in the CONNECTED state.
//   - stderr: structured log lines (one per event, free-form text).
//
// The process exits when stdin closes (parent died), or when it receives SIGTERM/Ctrl-C.
//
// No OS network interfaces are touched; no admin rights are required.
//
// # Build tags
//
//   - default: real-mode connect attempts surface a clear "ovpn3 binding not linked"
//     error. --mock and the SOCKS5 surface still work — sufficient for CI / wire-protocol
//     tests.
//   - -tags ovpn3: links against the CGO-wrapped OpenVPN3 shim (see ovpn_shim/). The
//     Fetch-OvpnProxy.ps1 script enables this tag when CMake + a C++ toolchain are on
//     PATH and the openvpn3 + mbedtls submodules are populated.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/xBounceIT/wormhole/tools/internal/sockstun"
)

// config is the wire shape passed in on stdin. Mirrors Wormhole.Services.Tunneling.OpenVpn
// .OpenVpnSidecarConfig on the managed side; field names are lower_snake_case to match Go
// JSON conventions. ProfileOvpn is opaque to this binary — OpenVPN3 parses every directive.
type config struct {
	ProfileOvpn string `json:"profile_ovpn"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	// ChallengeResponse, when non-empty, answers an OpenVPN data-channel dynamic challenge
	// (CRV1) that the server issues after the initial username/password auth — e.g. WatchGuard
	// AuthPoint 2FA presented at the OpenVPN layer. It is the user's one-time passcode, or
	// "p"/"push" to request a push notification. The sidecar connects, and if the server
	// challenges, it reconnects carrying this response. Empty for non-2FA / non-challenge VPNs.
	ChallengeResponse string `json:"challenge_response"`
	// Stable Windows adapter IDs and effective profile remotes for the OUTER OpenVPN
	// transport. The native shim prefers DNS through those adapters, falls back to the
	// system resolver when physical DNS is blocked, and refreshes the current interface
	// index before every socket connect.
	TransportAdapterIDs []string          `json:"transport_adapter_ids"`
	TransportRemotes    []transportRemote `json:"transport_remotes"`
	Mock                bool              `json:"mock"`
}

type transportRemote struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

type stderrLogger struct{}

func (stderrLogger) Logf(format string, args ...any) { logf(format, args...) }

func main() {
	mock := flag.Bool("mock", false, "skip OpenVPN handshake; dial via OS sockets (CI / tests only). Equivalent to passing \"mock\": true in the stdin config.")
	flag.Parse()

	if err := run(*mock); err != nil {
		logf("fatal: %v", err)
		os.Exit(1)
	}
}

func run(cliMock bool) error {
	cfg, err := readConfig()
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}
	if err := validateTransportIsolation(cfg); err != nil {
		return fmt.Errorf("invalid physical transport isolation: %w", err)
	}
	// CLI flag wins if either is set — handy for ad-hoc invocations where the operator
	// pipes a real config but wants mock dialing for a quick smoke test.
	mock := cliMock || cfg.Mock

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	input := os.Stdin

	// Watch for stdin EOF (parent gone). When it fires, cancel the context so the SOCKS5
	// server unblocks and the OpenVPN session tears down.
	go func() {
		_, _ = io.Copy(io.Discard, input)
		logf("stdin closed; shutting down")
		cancel()
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)
	go func() {
		select {
		case <-sigs:
			logf("signal received; shutting down")
			cancel()
		case <-ctx.Done():
		}
	}()

	var dial sockstun.Dialer
	var cleanup func()

	if mock {
		logf("mock mode: skipping OpenVPN, dialing via OS sockets")
		dial = sockstun.OSDialer{}
		cleanup = func() {}
	} else {
		if cfg.ProfileOvpn == "" {
			return fmt.Errorf("profile_ovpn is required in real (non-mock) mode")
		}
		d, c, err := startOpenVpn(ctx, cfg)
		if err != nil {
			return fmt.Errorf("openvpn start: %w", err)
		}
		dial = d
		cleanup = c
	}
	defer cleanup()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	fmt.Fprintf(os.Stdout, "READY %d\n", port)
	_ = os.Stdout.Sync()
	logf("socks5 listening on 127.0.0.1:%d", port)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	return sockstun.Serve(ctx, ln, dial, stderrLogger{})
}

func validateTransportIsolation(cfg config) error {
	hasAdapters := len(cfg.TransportAdapterIDs) > 0
	hasRemotes := len(cfg.TransportRemotes) > 0
	if hasAdapters != hasRemotes {
		return errors.New("transport_adapter_ids and transport_remotes must be supplied together")
	}
	if !hasAdapters {
		return nil
	}
	if len(cfg.TransportAdapterIDs) > 8 {
		return fmt.Errorf("too many transport_adapter_ids: %d (maximum 8)", len(cfg.TransportAdapterIDs))
	}
	for _, adapterID := range cfg.TransportAdapterIDs {
		if strings.TrimSpace(adapterID) == "" {
			return errors.New("transport_adapter_ids contains an empty stable adapter ID")
		}
	}
	for _, remote := range cfg.TransportRemotes {
		if strings.TrimSpace(remote.Host) == "" ||
			strings.TrimSpace(remote.Port) == "" ||
			strings.TrimSpace(remote.Protocol) == "" {
			return errors.New("transport_remotes contains an incomplete endpoint")
		}
	}
	return nil
}

func readConfig() (config, error) {
	dec := json.NewDecoder(os.Stdin)
	var cfg config
	if err := dec.Decode(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}
