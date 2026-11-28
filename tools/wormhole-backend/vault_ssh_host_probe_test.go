package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

func hostProbeRequest() sshHostProbeRequest {
	return sshHostProbeRequest{Host: "127.0.0.1", Port: 22, RequestID: uuid.NewString()}
}
func hostProbePacket(t *testing.T, q sshHostProbeRequest) []byte {
	return vaultInput(t, map[string]any{"host": q.Host, "port": q.Port, "endpoint": q.Endpoint, "requestId": q.RequestID})
}

func TestSSHHostProbeRealHandshakeNeverAuthenticates(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []bool{false, true} {
		t.Run(strconv.FormatBool(route), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			var authentication atomic.Bool
			done := make(chan struct{})
			go func() {
				defer close(done)
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				defer connection.Close()
				config := &ssh.ServerConfig{NoClientAuth: true, AuthLogCallback: func(ssh.ConnMetadata, string, error) { authentication.Store(true) }}
				config.AddHostKey(signer)
				server, _, _, err := ssh.NewServerConn(connection, config)
				if err == nil {
					server.Close()
					authentication.Store(true)
				}
			}()
			q := hostProbeRequest()
			q.Port = uint16(listener.Addr().(*net.TCPAddr).Port)
			if route {
				proxy, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer proxy.Close()
				q.Host, q.Endpoint = "127.0.0.2", proxy.Addr().String()
				go func() {
					connection, err := proxy.Accept()
					if err != nil {
						return
					}
					defer connection.Close()
					greeting := make([]byte, 3)
					if _, err := io.ReadFull(connection, greeting); err != nil || !bytes.Equal(greeting, []byte{5, 1, 0}) {
						return
					}
					if _, err := connection.Write([]byte{5, 0}); err != nil {
						return
					}
					request := make([]byte, 10)
					if _, err := io.ReadFull(connection, request); err != nil || !bytes.Equal(request[:8], []byte{5, 1, 0, 1, 127, 0, 0, 2}) {
						return
					}
					remote, err := net.Dial("tcp", listener.Addr().String())
					if err != nil {
						return
					}
					defer remote.Close()
					if _, err := connection.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1}); err != nil {
						return
					}
					bridgeTunnelConnections(connection, remote)
				}()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			fingerprint, err := probeSSHHost(ctx, q)
			if err != nil || fingerprint != ssh.FingerprintSHA256(signer.PublicKey()) {
				t.Fatal(fingerprint, err)
			}
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("server did not stop")
			}
			if authentication.Load() {
				t.Fatal("probe reached user authentication")
			}
		})
	}
}

func TestSSHHostProbeNetworkFailureAndCancellation(t *testing.T) {
	q := hostProbeRequest()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := probeSSHHost(ctx, q); err == nil {
		t.Fatal("cancelled direct dial")
	}
	q.Endpoint = "127.0.0.1:1"
	if _, err := probeSSHHost(ctx, q); err == nil {
		t.Fatal("cancelled route fell back")
	}
	for _, mode := range []string{"invalid-handshake", "cancel-handshake"} {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		q.Endpoint, q.Port = "", uint16(listener.Addr().(*net.TCPAddr).Port)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		accepted := make(chan struct{})
		go func() {
			connection, err := listener.Accept()
			close(accepted)
			if err != nil {
				return
			}
			defer connection.Close()
			if mode == "invalid-handshake" {
				_, _ = connection.Write([]byte("SSH-2.0-invalid\r\n"))
				return
			}
			<-ctx.Done()
		}()
		done := make(chan error, 1)
		go func() { _, err := probeSSHHost(ctx, q); done <- err }()
		<-accepted
		if mode == "cancel-handshake" {
			cancel()
		}
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("bad handshake accepted")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("probe stuck")
		}
		cancel()
		listener.Close()
	}
}

func TestSSHHostProbeProcessProtocolAndCancellation(t *testing.T) {
	for _, mode := range []string{"success", "eof", "extra", "error", "invalid-result", "output-failure"} {
		t.Run(mode, func(t *testing.T) {
			input, writer := io.Pipe()
			output, reader := io.Pipe()
			defer input.Close()
			defer writer.Close()
			defer output.Close()
			defer reader.Close()
			q := hostProbeRequest()
			entered := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				done <- serveSSHHostProbe(input, reader, func(ctx context.Context, got sshHostProbeRequest) (string, error) {
					if got != q {
						t.Error("request changed")
					}
					close(entered)
					if mode == "eof" || mode == "extra" {
						<-ctx.Done()
						return "", ctx.Err()
					}
					if mode == "error" {
						return "", errors.New("private detail")
					}
					if mode == "invalid-result" {
						return "bad", nil
					}
					return sealedSSHFixturePayload().Fingerprint, nil
				})
			}()
			if _, err := writer.Write(append(hostProbePacket(t, q), '\n')); err != nil {
				t.Fatal(err)
			}
			<-entered
			switch mode {
			case "eof":
				writer.Close()
			case "extra":
				_, _ = writer.Write([]byte("x"))
			case "output-failure":
				output.Close()
			case "success":
				raw, err := bufio.NewReader(output).ReadBytes('\n')
				var result struct{ RequestID, Fingerprint string }
				if err != nil || json.Unmarshal(raw, &result) != nil || result.RequestID != q.RequestID || result.Fingerprint != sealedSSHFixturePayload().Fingerprint {
					t.Fatal(string(raw), err)
				}
			}
			select {
			case err := <-done:
				if (err == nil) != (mode == "success") {
					t.Fatal(mode, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("child stuck")
			}
		})
	}
	for _, raw := range []string{"", "{}\n", "{}", strings.Repeat("x", 8194) + "\n", "{\"host\":null}\n"} {
		if err := serveSSHHostProbe(io.NopCloser(strings.NewReader(raw)), io.Discard, func(context.Context, sshHostProbeRequest) (string, error) {
			t.Error("invalid input reached probe")
			return "", nil
		}); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	var output, diagnostic bytes.Buffer
	if code := runBackendCLI([]string{"--operation", "ssh-host-probe"}, strings.NewReader("{}\n"), &output, &diagnostic); code != 1 || output.Len() != 0 || strings.TrimSpace(diagnostic.String()) != "ssh_host_probe_stopped" {
		t.Fatal(code, output.String(), diagnostic.String())
	}
}

func TestSSHHostProbeBoundaryValidation(t *testing.T) {
	q := hostProbeRequest()
	if got, err := decodeSSHHostProbe(hostProbePacket(t, q)); err != nil || got != q {
		t.Fatal(got, err)
	}
	for field, values := range map[string][]any{
		"host": {"", "a b", "a\x00b", strings.Repeat("x", 1025)}, "port": {0, 65536, -1, "22"},
		"endpoint":  {"localhost:22", "127.0.0.1:0", "127.0.0.1:022", "127.0.0.1:65536"},
		"requestId": {"bad", uuid.Nil.String()}, "password": {"never accepted"},
	} {
		for _, value := range values {
			var packet map[string]any
			if json.Unmarshal(hostProbePacket(t, q), &packet) != nil {
				t.Fatal("fixture")
			}
			packet[field] = value
			if _, err := decodeSSHHostProbe(vaultInput(t, packet)); err == nil {
				t.Fatal(field, value)
			}
		}
	}
}

func TestTunnelBridgeEitherPeerEOFClosesBothDirections(t *testing.T) {
	for _, clientFirst := range []bool{false, true} {
		client, clientPeer := net.Pipe()
		remote, remotePeer := net.Pipe()
		done := make(chan struct{})
		go func() { bridgeTunnelConnections(client, remote); close(done) }()
		if clientFirst {
			clientPeer.Close()
		} else {
			remotePeer.Close()
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("bridge retained idle reverse stream")
		}
		clientPeer.Close()
		remotePeer.Close()
	}
}
