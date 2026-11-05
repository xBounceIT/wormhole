// wormhole-fortiipsecproxy exposes a single Fortinet IKEv2/SAML tunnel over
// loopback SOCKS5. Configuration and secrets arrive only on stdin; EOF tears
// down the tunnel. No kernel routes, TUN interfaces or direct fallback exist.
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	ipsec "github.com/n0madic/go-ipsec"
	"github.com/xBounceIT/wormhole/tools/internal/sockstun"
)

type config struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	PreSharedKey string `json:"pre_shared_key"`
	LocalID      string `json:"local_id"`
	RemoteID     string `json:"remote_id"`
	SamlUID      string `json:"saml_uid"`
	SamlToken    string `json:"saml_token"`
}

// Three admitted 4096-byte strings can expand sixfold under JSON escaping.
// Keep the input bounded while covering the backend's complete settings schema.
const maxConfigBytes = 96 * 1024

type tunnelClient interface {
	DialContext(context.Context, string, string) (net.Conn, error)
	Resolver(string) *net.Resolver
	Close() error
}

type vpnDialer struct{ client tunnelClient }

func (d vpnDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid IPsec destination")
	}
	if net.ParseIP(host) != nil {
		return d.client.DialContext(ctx, network, address)
	}
	// Resolve only using DNS transported inside ESP. Never use the OS resolver
	// for destinations. The gateway's outer address is resolved before IKE.
	addresses, err := d.client.Resolver("").LookupHost(ctx, host)
	if err != nil {
		return nil, errors.New("IPsec DNS resolution failed")
	}
	for _, ip := range addresses {
		connection, err := d.client.DialContext(ctx, network, net.JoinHostPort(ip, port))
		if err == nil {
			return connection, nil
		}
	}
	return nil, errors.New("IPsec destination is unreachable")
}

func readConfig(reader *bufio.Reader) (config, error) {
	var cfg config
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) > maxConfigBytes {
		return cfg, errors.New("invalid Fortinet IPsec configuration")
	}
	if json.Unmarshal(line, &cfg) != nil {
		return cfg, errors.New("invalid Fortinet IPsec configuration")
	}
	if cfg.Port == 0 {
		cfg.Port = 500
	}
	if strings.HasPrefix(cfg.Host, "[") && strings.HasSuffix(cfg.Host, "]") {
		candidate := strings.TrimSuffix(strings.TrimPrefix(cfg.Host, "["), "]")
		if ip := net.ParseIP(candidate); ip != nil && strings.Contains(candidate, ":") {
			cfg.Host = candidate
		}
	}
	if cfg.Host == "" || len(cfg.Host) > 253 || strings.ContainsAny(cfg.Host, "/\\?#@ \t\r\n\x00") || cfg.Port < 1 || cfg.Port > 65535 || cfg.PreSharedKey == "" || len(cfg.PreSharedKey) > 4096 || len(cfg.LocalID) > 4096 || len(cfg.RemoteID) > 4096 {
		return cfg, errors.New("invalid Fortinet IPsec gateway or PSK")
	}
	for _, value := range []string{cfg.SamlUID, cfg.SamlToken} {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 16 {
			return cfg, errors.New("invalid Fortinet IPsec SAML credentials")
		}
	}
	return cfg, nil
}

func identity(value string) ipsec.Identity {
	if value == "" {
		return ipsec.Identity{}
	}
	if ip, err := netip.ParseAddr(value); err == nil {
		if ip.Is4() {
			return ipsec.IPv4(ip)
		}
		return ipsec.IPv6(ip)
	}
	if strings.Contains(value, "@") {
		return ipsec.Email(value)
	}
	return ipsec.FQDN(value)
}

func clientConfig(cfg config, cancel context.CancelFunc) ipsec.Config {
	reconnect := false
	return ipsec.Config{
		Server:  net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
		LocalID: identity(cfg.LocalID), RemoteID: identity(cfg.RemoteID),
		FortinetSAML: true, ServerPSK: cfg.PreSharedKey,
		EAP:           ipsec.EAPMSCHAPv2{Username: cfg.SamlUID, Password: cfg.SamlToken},
		AutoReconnect: &reconnect, OnDead: cancel,
	}
}

// No diagnostics from the protocol or SOCKS dialer are forwarded: their error
// values may contain authentication material or private destination names.
type quietLogger struct{}

func (quietLogger) Logf(string, ...any) {}

type connectFunc func(context.Context, ipsec.Config) (tunnelClient, error)

// Bound idle SOCKS handshakes to the tunnel lifetime as well as active streams.
// sockstun's context-aware pump starts only after its greeting has completed.
type contextListener struct {
	net.Listener
	ctx context.Context
}
type contextConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *contextConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}
func (c *contextConn) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return nil
}
func (l contextListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	wrapped := &contextConn{Conn: c, done: make(chan struct{})}
	go func() {
		select {
		case <-l.ctx.Done():
			_ = wrapped.Close()
		case <-wrapped.done:
		}
	}()
	return wrapped, nil
}

func run(ctx context.Context, input io.Reader, output io.Writer, connect connectFunc) error {
	reader := bufio.NewReaderSize(input, maxConfigBytes+1)
	cfg, err := readConfig(reader)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _, _ = io.Copy(io.Discard, reader); cancel() }()
	startup, stopStartup := context.WithTimeout(ctx, 90*time.Second)
	client, err := connect(startup, clientConfig(cfg, cancel))
	stopStartup()
	if err != nil {
		return errors.New("Fortinet IPsec IKEv2 authentication failed; verify PSK, identities, UDP ports and gateway proposals")
	}
	defer client.Close()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return errors.New("could not start Fortinet IPsec proxy")
	}
	defer listener.Close()
	if _, err := fmt.Fprintf(output, "READY %d\n", listener.Addr().(*net.TCPAddr).Port); err != nil {
		return errors.New("could not publish Fortinet IPsec proxy")
	}
	go func() { <-ctx.Done(); _ = listener.Close() }()
	return sockstun.Serve(ctx, contextListener{listener, ctx}, vpnDialer{client}, quietLogger{})
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Stdin, os.Stdout, func(ctx context.Context, cfg ipsec.Config) (tunnelClient, error) {
		client, err := ipsec.Dial(ctx, cfg)
		if err != nil {
			return nil, err
		}
		// Validate the assigned userspace network before reporting readiness.
		if _, err := client.Net(); err != nil {
			client.Close()
			return nil, err
		}
		return client, nil
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
