package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/internal/sockstun"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

func testSigner(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(block)
}

type testServer struct {
	address string
	pin     string
	close   func()
}

func startServer(t *testing.T, otp, silent bool, certificateOnly ...bool) testServer {
	t.Helper()
	signer, _ := testSigner(t)
	cfg := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if string(password) != "secret" {
			return nil, fmt.Errorf("rejected")
		}
		return nil, nil
	}, PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if len(certificateOnly) > 0 && certificateOnly[0] {
			if _, ok := key.(*ssh.Certificate); !ok {
				return nil, fmt.Errorf("certificate required")
			}
		}
		return nil, nil
	}}
	if otp {
		cfg.PasswordCallback = nil
		cfg.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := challenge("ops", "", []string{"OTP:"}, []bool{false})
			if err != nil || len(answers) != 1 || answers[0] != "654321" {
				return nil, fmt.Errorf("rejected")
			}
			return nil, nil
		}
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var connections []net.Conn
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections = append(connections, conn)
			mu.Unlock()
			go func() {
				defer conn.Close()
				server, channels, requests, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer server.Close()
				go func() {
					for req := range requests {
						if !silent {
							_ = req.Reply(false, nil)
						}
					}
				}()
				for channel := range channels {
					if channel.ChannelType() != "direct-tcpip" {
						_ = channel.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					var target struct {
						Host       string
						Port       uint32
						Origin     string
						OriginPort uint32
					}
					if ssh.Unmarshal(channel.ExtraData(), &target) != nil {
						_ = channel.Reject(ssh.ConnectionFailed, "bad target")
						continue
					}
					remote, err := net.Dial("tcp", net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port))))
					if err != nil {
						_ = channel.Reject(ssh.ConnectionFailed, "failed")
						continue
					}
					stream, reqs, err := channel.Accept()
					if err != nil {
						remote.Close()
						continue
					}
					go ssh.DiscardRequests(reqs)
					go func() {
						defer remote.Close()
						defer stream.Close()
						go func() { _, _ = io.Copy(remote, stream); remote.Close() }()
						_, _ = io.Copy(stream, remote)
					}()
				}
			}()
		}
	}()
	closeAll := func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range connections {
			_ = conn.Close()
		}
	}
	t.Cleanup(closeAll)
	return testServer{ln.Addr().String(), ssh.FingerprintSHA256(signer.PublicKey()), closeAll}
}

func serverConfig(server testServer) config {
	host, port, _ := net.SplitHostPort(server.address)
	n, _ := strconv.Atoi(port)
	return config{Host: host, Port: n, Username: "ops", Password: "secret", HostKeySHA256: server.pin, KeepaliveSeconds: 1}
}

func startRun(t *testing.T, cfg config, mock bool, answer string) (string, io.Closer, <-chan error) {
	t.Helper()
	input, writer := io.Pipe()
	output, stdout := io.Pipe()
	done := make(chan error, 1)
	t.Cleanup(func() { writer.Close(); input.Close(); output.Close(); stdout.Close() })
	go func() { done <- run(context.Background(), input, stdout, mock); stdout.Close() }()
	if err := json.NewEncoder(writer).Encode(cfg); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(output)
	line, err := reader.ReadString('\n')
	if strings.HasPrefix(line, "PROMPT ") {
		if !strings.Contains(line, "OTP:") {
			t.Fatal(line)
		}
		_ = json.NewEncoder(writer).Encode(map[string]string{"answer": answer})
		line, err = reader.ReadString('\n')
	}
	if err != nil || !strings.HasPrefix(line, "READY ") {
		t.Fatalf("readiness: %q %v", line, err)
	}
	return "127.0.0.1:" + strings.TrimSpace(strings.TrimPrefix(line, "READY ")), writer, done
}

func awaitExit(t *testing.T, done <-chan error, wantError bool) {
	t.Helper()
	select {
	case err := <-done:
		if (err != nil) != wantError {
			t.Fatalf("exit: %v", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("sidecar did not exit")
	}
}

func TestTunnelSOCKSAndLifecycle(t *testing.T) {
	for _, mode := range []string{"password", "key", "encrypted", "certificate", "otp", "mock"} {
		t.Run(mode, func(t *testing.T) {
			server := startServer(t, mode == "otp", false, mode == "certificate")
			cfg := serverConfig(server)
			if mode == "key" || mode == "encrypted" || mode == "certificate" {
				signer, key := testSigner(t)
				cfg.PrivateKey = string(key)
				cfg.Password = ""
				if mode == "encrypted" {
					_, private, _ := ed25519.GenerateKey(rand.Reader)
					block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "", []byte("phrase"))
					if err != nil {
						t.Fatal(err)
					}
					cfg.PrivateKey = string(pem.EncodeToMemory(block))
					cfg.KeyPassphrase = "phrase"
				}
				if mode == "certificate" {
					ca, _ := testSigner(t)
					cert := &ssh.Certificate{Key: signer.PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{"ops"}, ValidBefore: ssh.CertTimeInfinity}
					if err := cert.SignCert(rand.Reader, ca); err != nil {
						t.Fatal(err)
					}
					cfg.Certificate = string(ssh.MarshalAuthorizedKey(cert))
				}
			}
			endpoint, stdin, done := startRun(t, cfg, mode == "mock", "654321")
			echo, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				c, err := echo.Accept()
				if err == nil {
					defer c.Close()
					_, _ = io.Copy(c, c)
				}
			}()
			dialer, err := proxy.SOCKS5("tcp", endpoint, nil, proxy.Direct)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := dialer.Dial("tcp", echo.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			_, _ = conn.Write([]byte("echo"))
			out := make([]byte, 4)
			if _, err := io.ReadFull(conn, out); err != nil || string(out) != "echo" {
				t.Fatalf("echo: %q %v", out, err)
			}
			conn.Close()
			stdin.Close()
			awaitExit(t, done, false)
			if conn, err := net.DialTimeout("tcp", endpoint, time.Second); err == nil {
				conn.Close()
				t.Fatal("SOCKS survived stdin EOF")
			}
		})
	}
}

func TestTunnelDropsAndKeepalive(t *testing.T) {
	for _, silent := range []bool{false, true} {
		t.Run(fmt.Sprint(silent), func(t *testing.T) {
			server := startServer(t, false, silent)
			endpoint, _, done := startRun(t, serverConfig(server), false, "")
			if !silent {
				server.close()
			}
			awaitExit(t, done, true)
			if conn, err := net.DialTimeout("tcp", endpoint, time.Second); err == nil {
				conn.Close()
				t.Fatal("failed tunnel still accepts")
			}
		})
	}
}

func TestTunnelUpstream(t *testing.T) {
	server := startServer(t, false, false)
	cfg := serverConfig(server)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = sockstun.Serve(ctx, ln, sockstun.OSDialer{}, quietLogger{}) }()
	cfg.UpstreamSocks = ln.Addr().String()
	_, stdin, done := startRun(t, cfg, false, "")
	stdin.Close()
	awaitExit(t, done, false)
}

func TestTunnelConfigAndFailures(t *testing.T) {
	server := startServer(t, false, false)
	valid := serverConfig(server)
	for _, change := range []func(*config){
		func(c *config) { c.HostKeySHA256 = "" }, func(c *config) { c.Port = 0 }, func(c *config) { c.Host = "bad\n" }, func(c *config) { c.Username = "" },
		func(c *config) { c.PrivateKey = strings.Repeat("x", sshauthMaxKeyBytes+1) }, func(c *config) { c.KeepaliveSeconds = -1 }, func(c *config) { c.UpstreamSocks = "192.0.2.1:1234" },
	} {
		c := valid
		change(&c)
		if c.validate() == nil {
			t.Fatal("invalid config accepted")
		}
	}
	for _, input := range []string{"", "{bad}\n", "{}\n"} {
		if run(context.Background(), strings.NewReader(input), io.Discard, false) == nil {
			t.Fatal("bad input accepted")
		}
	}
	for _, change := range []func(*config){func(c *config) { other, _ := testSigner(t); c.HostKeySHA256 = ssh.FingerprintSHA256(other.PublicKey()) }, func(c *config) { c.PrivateKey = "invalid" }, func(c *config) { c.Password = "wrong" }, func(c *config) { c.Port = 1 }} {
		c := valid
		change(&c)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if client, _, err := connect(ctx, c, func(string) (string, error) { return "", fmt.Errorf("cancelled") }); err == nil {
			client.Close()
			t.Fatal("failure accepted")
		}
		cancel()
	}
	var output bytes.Buffer
	c := valid
	raw, _ := json.Marshal(c)
	if err := run(context.Background(), strings.NewReader(string(raw)+"\n"), &output, false); err == nil && strings.Contains(output.String(), "READY") {
		t.Fatal("EOF during startup published readiness")
	}
}

const sshauthMaxKeyBytes = 1024 * 1024

func TestParentEOFWithAnUnsolicitedAnswer(t *testing.T) {
	server := startServer(t, false, false)
	_, stdin, done := startRun(t, serverConfig(server), true, "")
	if _, err := stdin.(io.Writer).Write([]byte("{\"answer\":\"unexpected\"}\n")); err != nil {
		t.Fatal(err)
	}
	stdin.Close()
	awaitExit(t, done, false)
}
