// wormhole-ciscoproxy is the userspace Cisco Secure Client (AnyConnect) SSL VPN sidecar that
// Wormhole launches per active connection. It owns an AnyConnect SSL VPN session — aggregate-auth
// XML login over HTTPS, then a CSTP tunnel (STF-framed IP packets over TLS) — running in TUN-less
// netstack mode (gVisor) and exposes the resulting virtual network through a local SOCKS5 listener
// on 127.0.0.1.
//
// Protocol with the parent:
//
//   - stdin:  one JSON object on the first line, then EOF acts as the shutdown signal.
//   - stdout: a single line "READY <port>\n" once the SOCKS5 listener is up.
//   - stderr: structured log lines (one per event, free-form text).
//
// The process exits when stdin closes (parent died), or when it receives SIGTERM/Ctrl-C.
//
// No OS network interfaces are touched; no admin rights are required. This intentionally does NOT
// drive the locally-installed Cisco Secure Client (which builds a system-wide, single-session
// tunnel and cannot expose a loopback SOCKS5); it speaks the AnyConnect protocol directly, the
// same way openconnect does.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/xBounceIT/wormhole/tools/internal/sockstun"
)

type config struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	// Group is the tunnel group / connection profile to select on the gateway login form
	// (AnyConnect's "Group" dropdown). Optional — many gateways have a single default group.
	Group *string `json:"group"`
	// SecondaryPassword answers a second authentication form (challenge/response) when the
	// gateway runs two-factor with a static secondary credential. Mutually complementary with
	// TotpSecret: if TotpSecret is set, a generated TOTP code is preferred for the challenge.
	SecondaryPassword *string `json:"secondary_password"`
	// TotpSecret (Base32) lets the sidecar answer a second-factor challenge form with a freshly
	// generated TOTP code, the same way the Fortinet sidecar does. Optional.
	TotpSecret             *string `json:"totp_secret"`
	TrustServerCertificate bool    `json:"trust_server_certificate"`
	ServerCertSha256Pin    *string `json:"server_cert_sha256_pin"`
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// stderrLogger adapts logf to sockstun.Logger.
type stderrLogger struct{}

func (stderrLogger) Logf(format string, args ...any) { logf(format, args...) }

// debugLog enables verbose, secret-redacted logging of the gateway's aggregate-auth XML
// responses during the login flow. Off by default so normal logs never carry response bytes;
// the parent opts in for a one-shot diagnostic capture by setting WORMHOLE_CISCOPROXY_DEBUG in
// Wormhole's environment, which this child process inherits.
var debugLog bool

func main() {
	mock := flag.Bool("mock", false, "skip AnyConnect handshake; dial via OS sockets (CI / tests only)")
	flag.Parse()

	debugLog = os.Getenv("WORMHOLE_CISCOPROXY_DEBUG") != ""

	if err := run(*mock); err != nil {
		logf("fatal: %v", err)
		os.Exit(1)
	}
}

func run(mock bool) error {
	cfg, err := readConfig()
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Watch for stdin EOF (parent gone). When it fires, cancel the context so the SOCKS5
	// server unblocks and the tunnel tears down.
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		logf("stdin closed; shutting down")
		cancel()
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
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
	arm := func() {} // no-op default; startCisco supplies the real one

	if mock {
		logf("mock mode: skipping AnyConnect handshake, dialing via OS sockets")
		dial = sockstun.OSDialer{}
		cleanup = func() {}
	} else {
		d, a, c, err := startCisco(ctx, cancel, cfg)
		if err != nil {
			return fmt.Errorf("cisco start: %w", err)
		}
		dial = d
		arm = a
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
	// Arm the CSTP-teardown watcher AFTER the listener is published — same phantom-READY guard
	// the Fortinet sidecar uses: a fast tunnel exit (gateway RST mid-handshake) should cancel the
	// outer ctx so the SOCKS5 accept loop exits promptly, but only once READY has been written.
	arm()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	return sockstun.Serve(ctx, ln, dial, stderrLogger{})
}

func readConfig() (config, error) {
	dec := json.NewDecoder(os.Stdin)
	var cfg config
	if err := dec.Decode(&cfg); err != nil {
		return cfg, err
	}
	if cfg.Port == 0 {
		cfg.Port = 443
	}
	return cfg, nil
}
