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
	Options      *ipsec.FortinetOptions `json:"options"`
	Username     string                 `json:"username"`
	Password     string                 `json:"password"`
	ClientCert   string                 `json:"client_cert"`
	ClientKey    string                 `json:"client_key"`
	CaCert       string                 `json:"ca_cert"`
	Host         string                 `json:"host"`
	Port         int                    `json:"port"`
	PreSharedKey string                 `json:"pre_shared_key"`
	LocalID      string                 `json:"local_id"`
	RemoteID     string                 `json:"remote_id"`
	SamlUID      string                 `json:"saml_uid"`
	SamlToken    string                 `json:"saml_token"`
}

// Three admitted 4096-byte strings can expand sixfold under JSON escaping.
// Keep the input bounded while covering the backend's complete settings schema.
const maxConfigBytes = 1024 * 1024

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
	if cfg.Host == "" || len(cfg.Host) > 253 || strings.ContainsAny(cfg.Host, "/\\?#@ \t\r\n\x00") || cfg.Port < 1 || cfg.Port > 65535 || (cfg.PreSharedKey == "" && (cfg.Options == nil || cfg.Options.AuthMethod != 1)) || len(cfg.PreSharedKey) > 4096 || len(cfg.LocalID) > 4096 || len(cfg.RemoteID) > 4096 || len(cfg.Username) > 4096 || len(cfg.Password) > 4096 || len(cfg.ClientCert) > 131072 || len(cfg.ClientKey) > 131072 || len(cfg.CaCert) > 131072 {
		return cfg, errors.New("invalid Fortinet IPsec gateway or PSK")
	}
	if cfg.Options == nil || cfg.Options.UserAuth == 3 {
		for _, value := range []string{cfg.SamlUID, cfg.SamlToken} {
			decoded, err := hex.DecodeString(value)
			if err != nil || len(decoded) != 16 {
				return cfg, errors.New("invalid Fortinet IPsec SAML credentials")
			}
		}
	}
	if cfg.Options != nil && cfg.Options.RemoteGateways != "" {
		hosts := strings.Split(cfg.Options.RemoteGateways, ",")
		if len(hosts) > 8 {
			return cfg, errors.New("too many Fortinet IPsec gateways")
		}
		for _, host := range hosts {
			host = strings.TrimSpace(host)
			if host == "" || len(host) > 253 || strings.ContainsAny(host, "/\\?#@ \t\r\n\x00") {
				return cfg, errors.New("invalid Fortinet IPsec gateway")
			}
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

func prepareClientConfig(cfg config, cancel context.CancelFunc) (ipsec.Config, error) {
	c := clientConfig(cfg, cancel)
	if cfg.Options == nil {
		return c, nil
	}
	o := cfg.Options
	c.FortinetSAML = o.UserAuth == 3 || o.AuthMethod == 0 && (o.UserAuth == 1 || o.UserAuth == 2)
	if o.UserAuth != 3 {
		c.EAP = ipsec.EAPMSCHAPv2{Username: cfg.Username, Password: cfg.Password}
	}
	if o.UserAuth == 0 {
		c.PSK = cfg.PreSharedKey
		c.ServerPSK = ""
		c.EAP = ipsec.EAPMSCHAPv2{}
		if c.LocalID.IsZero() && o.IkeVersion == 2 {
			c.LocalID = ipsec.FQDN("wormhole")
		}
	}
	if o.AuthMethod == 1 && c.RemoteID.IsZero() {
		c.RemoteID = identity(cfg.Host)
	}
	return ipsec.ConfigureFortinet(c, *o, cfg.ClientCert, cfg.ClientKey, cfg.CaCert)
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
	gateways := []string{cfg.Host}
	if cfg.Options != nil && cfg.Options.UserAuth != 3 && cfg.Options.RemoteGateways != "" {
		for _, host := range strings.Split(cfg.Options.RemoteGateways, ",") {
			gateways = append(gateways, strings.TrimSpace(host))
		}
	}
	if len(gateways) > 9 {
		stopStartup()
		return errors.New("too many Fortinet IPsec gateways")
	}
	var client tunnelClient
	for _, host := range gateways {
		cfg.Host = host
		prepared, prepareErr := prepareClientConfig(cfg, cancel)
		if prepareErr != nil {
			stopStartup()
			return prepareErr
		}
		attempt, stopAttempt := context.WithTimeout(startup, 90*time.Second/time.Duration(len(gateways)))
		client, err = connect(attempt, prepared)
		stopAttempt()
		if err == nil {
			break
		}
		if client != nil {
			client.Close()
			client = nil
		}
		if startup.Err() != nil {
			break
		}
	}
	stopStartup()
	if err != nil {
		return errors.New("Fortinet IPsec authentication failed; verify credentials, identities, UDP ports and gateway proposals")
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
		client, err := ipsec.DialFortinet(ctx, cfg)
		if err != nil {
			return nil, err
		}
		return client, nil
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
