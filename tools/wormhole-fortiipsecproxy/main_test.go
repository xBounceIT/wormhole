package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	ipsec "github.com/n0madic/go-ipsec"
)

func fixtureConfig() config {
	return config{Host: "vpn.test", Port: 500, PreSharedKey: "private-psk", SamlUID: strings.Repeat("A1", 16), SamlToken: strings.Repeat("b2", 16)}
}
func configLine(cfg config) string { data, _ := json.Marshal(cfg); return string(data) + "\n" }

func TestReadConfig(t *testing.T) {
	for _, mutate := range []func(*config){func(c *config) { c.Port = 0 }, func(c *config) { c.Host = "2001:db8::1" }, func(c *config) { c.LocalID = "client"; c.RemoteID = "vpn.test" }} {
		cfg := fixtureConfig()
		mutate(&cfg)
		read, err := readConfig(bufio.NewReaderSize(strings.NewReader(configLine(cfg)), 32769))
		if err != nil || read.Port == 0 {
			t.Fatal("valid config rejected", err)
		}
	}
	for _, input := range []string{"", "{}", "[]\n", "invalid\n", strings.Repeat("x", 32770) + "\n"} {
		if _, err := readConfig(bufio.NewReaderSize(strings.NewReader(input), 32769)); err == nil {
			t.Fatal("malformed input accepted")
		}
	}
	for _, mutate := range []func(*config){
		func(c *config) { c.Host = "" }, func(c *config) { c.Host = "bad/host" }, func(c *config) { c.Port = -1 }, func(c *config) { c.Port = 65536 },
		func(c *config) { c.PreSharedKey = "" }, func(c *config) { c.PreSharedKey = strings.Repeat("a", 4097) },
		func(c *config) { c.LocalID = strings.Repeat("a", 4097) }, func(c *config) { c.RemoteID = strings.Repeat("a", 4097) },
		func(c *config) { c.SamlUID = "wrong" }, func(c *config) { c.SamlToken = "private-token" },
	} {
		cfg := fixtureConfig()
		mutate(&cfg)
		if _, err := readConfig(bufio.NewReader(strings.NewReader(configLine(cfg)))); err == nil || strings.Contains(err.Error(), "private") {
			t.Fatal("invalid config accepted or exposed")
		}
	}
}

func TestClientConfig(t *testing.T) {
	cfg := fixtureConfig()
	cfg.LocalID = "vpn-client"
	cfg.RemoteID = "vpn.test"
	cancelled := false
	client := clientConfig(cfg, func() { cancelled = true })
	if client.Server != "vpn.test:500" || !client.FortinetSAML || client.ServerPSK != cfg.PreSharedKey || client.EAP.Username != cfg.SamlUID || client.EAP.Password != cfg.SamlToken || client.AutoReconnect == nil || *client.AutoReconnect {
		t.Fatal("incomplete SAML IKE configuration")
	}
	client.OnDead()
	if !cancelled {
		t.Fatal("peer loss did not cancel lease")
	}
	for _, input := range []string{"", "192.0.2.1", "2001:db8::1", "user@example.test", "vpn.test"} {
		id := identity(input)
		if input == "" {
			if !id.IsZero() {
				t.Fatal("identity not empty")
			}
		} else if id.IsZero() {
			t.Fatal("identity missing")
		}
	}
}

type fakeClient struct {
	closeOnce sync.Once
	closed    chan struct{}
	dial      func(context.Context, string, string) (net.Conn, error)
	resolver  *net.Resolver
}

func (f *fakeClient) Close() error { f.closeOnce.Do(func() { close(f.closed) }); return nil }
func (f *fakeClient) DialContext(ctx context.Context, n, a string) (net.Conn, error) {
	return f.dial(ctx, n, a)
}
func (f *fakeClient) Resolver(string) *net.Resolver { return f.resolver }

func TestDialerFailsClosedAndResolvesInsideTunnel(t *testing.T) {
	fake := &fakeClient{closed: make(chan struct{})}
	var destinations []string
	fake.dial = func(_ context.Context, _ string, address string) (net.Conn, error) {
		destinations = append(destinations, address)
		return nil, errors.New("unreachable")
	}
	fake.resolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("tunnel DNS offline") }}
	d := vpnDialer{fake}
	for _, address := range []string{"bad", "192.0.2.1:443", "[2001:db8::1]:443", "internal.invalid:443"} {
		if _, err := d.DialContext(context.Background(), "tcp", address); err == nil {
			t.Fatal("failed dial succeeded")
		}
	}
	if len(destinations) != 2 {
		t.Fatal("hostname escaped tunnel resolver")
	}
	// Answer DNS using an in-memory stream. No system DNS or network is used.
	fake.resolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			var size [2]byte
			if _, err := io.ReadFull(server, size[:]); err != nil {
				return
			}
			query := make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, err := io.ReadFull(server, query); err != nil {
				return
			}
			end := 12
			for query[end] != 0 {
				end += int(query[end]) + 1
			}
			end += 5
			response := append([]byte(nil), query[:end]...)
			response[2] = 0x81
			response[3] = 0x80
			response[10] = 0
			response[11] = 0
			if binary.BigEndian.Uint16(query[end-4:end-2]) == 1 {
				response[7] = 1
				response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 2)
			}
			binary.BigEndian.PutUint16(size[:], uint16(len(response)))
			server.Write(append(size[:], response...))
		}()
		return client, nil
	}}
	fake.dial = func(_ context.Context, _ string, address string) (net.Conn, error) {
		if address != "192.0.2.2:443" {
			t.Error(address)
		}
		client, peer := net.Pipe()
		peer.Close()
		return client, nil
	}
	connection, err := d.DialContext(context.Background(), "tcp", "internal.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	fake.dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unreachable") }
	if _, err := d.DialContext(context.Background(), "tcp", "internal.invalid:443"); err == nil {
		t.Fatal("unreachable destination accepted")
	}
}

func TestRunPublishesOnlyAfterHandshakeAndStopsOnEOF(t *testing.T) {
	input, writer := io.Pipe()
	defer writer.Close()
	output, readOutput := io.Pipe()
	defer output.Close()
	defer readOutput.Close()
	fake := &fakeClient{closed: make(chan struct{}), dial: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("offline") }}
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), input, readOutput, func(_ context.Context, cfg ipsec.Config) (tunnelClient, error) {
			if !cfg.FortinetSAML {
				t.Error("wrong auth mode")
			}
			return fake, nil
		})
	}()
	fmt.Fprint(writer, configLine(fixtureConfig()))
	var port int
	if _, err := fmt.Fscanf(bufio.NewReader(output), "READY %d\n", &port); err != nil || port < 1 {
		t.Fatal("not ready", err)
	}
	idle, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	idle.Write([]byte{5}) // incomplete greeting must not delay EOF cleanup
	writer.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("EOF did not stop proxy")
	}
	select {
	case <-fake.closed:
	default:
		t.Fatal("VPN not closed")
	}
	if connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
		connection.Close()
		t.Fatal("SOCKS listener survived release")
	}
}

func TestRunFailureAndCancellationNeverPublishReady(t *testing.T) {
	for _, fail := range []bool{true, false} {
		input, writer := io.Pipe()
		var output bytes.Buffer
		ctx, cancel := context.WithCancel(context.Background())
		fake := &fakeClient{closed: make(chan struct{})}
		done := make(chan error, 1)
		go func() {
			done <- run(ctx, input, &output, func(context.Context, ipsec.Config) (tunnelClient, error) {
				if fail {
					return nil, errors.New("private-token")
				}
				cancel()
				return fake, nil
			})
		}()
		fmt.Fprint(writer, configLine(fixtureConfig()))
		err := <-done
		writer.Close()
		cancel()
		if err == nil || strings.Contains(err.Error(), "private-token") || output.Len() != 0 {
			t.Fatal("failed tunnel exposed readiness or a secret")
		}
	}
	if err := run(context.Background(), strings.NewReader("invalid\n"), io.Discard, nil); err == nil {
		t.Fatal("malformed config accepted")
	}
}

func TestPeerDeathClosesPublishedListener(t *testing.T) {
	input, writer := io.Pipe()
	defer writer.Close()
	output, readOutput := io.Pipe()
	defer output.Close()
	defer readOutput.Close()
	fake := &fakeClient{closed: make(chan struct{})}
	var peerDied func()
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), input, readOutput, func(_ context.Context, cfg ipsec.Config) (tunnelClient, error) {
			peerDied = cfg.OnDead
			return fake, nil
		})
	}()
	fmt.Fprint(writer, configLine(fixtureConfig()))
	var port int
	if _, err := fmt.Fscanf(bufio.NewReader(output), "READY %d\n", &port); err != nil {
		t.Fatal(err)
	}
	peerDied()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dead peer did not release SOCKS lease")
	}
	select {
	case <-fake.closed:
	default:
		t.Fatal("dead VPN was not closed")
	}
}

func TestContextListenerPreservesTCPHalfClose(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := (contextListener{listener, context.Background()}).Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.(*contextConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("TCP half-close was hidden by lifetime wrapper", err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	if err := (&contextConn{Conn: left}).CloseWrite(); err != nil {
		t.Fatal(err)
	}
}
