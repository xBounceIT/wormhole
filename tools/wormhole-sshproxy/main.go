// wormhole-sshproxy exposes SSH direct-tcpip through loopback SOCKS5. Secrets arrive only on
// stdin. Before READY, PROMPT JSON lines request keyboard-interactive answers on stdin; EOF
// always shuts down the process, including during the handshake. Diagnostics never echo input.
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/xBounceIT/wormhole/tools/internal/sockstun"
	"github.com/xBounceIT/wormhole/tools/internal/sshauth"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

type config struct {
	Host             string `json:"host"`
	Port             int    `json:"port"`
	Username         string `json:"username"`
	Password         string `json:"password,omitempty"`
	PrivateKey       string `json:"private_key,omitempty"`
	KeyPassphrase    string `json:"key_passphrase,omitempty"`
	Certificate      string `json:"certificate,omitempty"`
	HostKeySHA256    string `json:"host_key_sha256"`
	KeepaliveSeconds int    `json:"keepalive_s,omitempty"`
	UpstreamSocks    string `json:"upstream_socks,omitempty"`
}

func (c *config) validate() error {
	if c.Host == "" || len(c.Host) > 1024 || strings.ContainsAny(c.Host, " /\\?#@%") || strings.IndexFunc(c.Host, unicode.IsControl) >= 0 ||
		c.Port < 1 || c.Port > 65535 || strings.TrimSpace(c.Username) == "" || len(c.Username) > 512 || strings.IndexFunc(c.Username, unicode.IsControl) >= 0 {
		return errors.New("SSH tunnel endpoint is invalid")
	}
	pin, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(c.HostKeySHA256, "SHA256:"))
	if !strings.HasPrefix(c.HostKeySHA256, "SHA256:") || err != nil || len(pin) != 32 {
		return errors.New("SSH tunnel host-key pin is required")
	}
	if len(c.PrivateKey) > sshauth.MaxKeyBytes || len(c.Certificate) > sshauth.MaxKeyBytes || len(c.Password) > 16384 || len(c.KeyPassphrase) > 16384 {
		return errors.New("SSH tunnel credential is too large")
	}
	if c.KeepaliveSeconds == 0 {
		c.KeepaliveSeconds = 30
	}
	if c.KeepaliveSeconds < 1 || c.KeepaliveSeconds > 3600 {
		return errors.New("SSH tunnel keepalive is invalid")
	}
	if c.UpstreamSocks != "" {
		host, port, err := net.SplitHostPort(c.UpstreamSocks)
		n, parseErr := strconv.Atoi(port)
		if err != nil || host != "127.0.0.1" || parseErr != nil || n < 1 || n > 65535 {
			return errors.New("SSH tunnel upstream proxy is invalid")
		}
	}
	return nil
}

type quietLogger struct{}

func (quietLogger) Logf(string, ...any) {} // SOCKS errors can include remote input; never log it.

func main() {
	mock := flag.Bool("mock", false, "use OS sockets instead of SSH (tests only)")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Stdin, os.Stdout, *mock); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(parent context.Context, input io.Reader, output io.Writer, mock bool) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 3*sshauth.MaxKeyBytes)
	if !scanner.Scan() {
		return errors.New("SSH tunnel configuration is missing")
	}
	raw := append([]byte(nil), scanner.Bytes()...)
	var c config
	err := json.Unmarshal(raw, &c)
	clear(raw)
	clear(scanner.Bytes())
	if err != nil {
		return errors.New("SSH tunnel configuration is invalid")
	}
	if err := c.validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	answers := make(chan string, 1)
	go func() {
		defer cancel()
		for scanner.Scan() {
			var answer struct {
				Answer string `json:"answer"`
			}
			err := json.Unmarshal(scanner.Bytes(), &answer)
			clear(scanner.Bytes())
			if err != nil || len(answer.Answer) > 16384 {
				return
			}
			select {
			case answers <- answer.Answer:
			case <-ctx.Done():
				return
			default:
				return // Unexpected queued answers must not prevent observing parent EOF.
			}
		}
	}()
	var dial sockstun.Dialer = sockstun.OSDialer{}
	var client *ssh.Client
	var transport net.Conn
	if !mock {
		client, transport, err = connect(ctx, c, func(question string) (string, error) {
			message, _ := json.Marshal(struct {
				Message string `json:"message"`
			}{question})
			if _, err := fmt.Fprintf(output, "PROMPT %s\n", message); err != nil {
				return "", errors.New("SSH tunnel prompt failed")
			}
			select {
			case answer := <-answers:
				return answer, nil
			case <-ctx.Done():
				return "", ctx.Err()
			}
		})
		if err != nil {
			return err
		}
		defer client.Close()
		dial = client
	}
	c.Password, c.PrivateKey, c.KeyPassphrase, c.Certificate = "", "", "", ""
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return errors.New("SSH tunnel SOCKS listener failed")
	}
	defer ln.Close()
	stop := context.AfterFunc(ctx, func() {
		_ = ln.Close()
		if client != nil {
			_ = client.Close()
		}
	})
	defer stop()
	failed := make(chan error, 1)
	if client != nil {
		go func() {
			_ = client.Wait()
			if ctx.Err() == nil {
				select {
				case failed <- errors.New("SSH jump connection closed"):
				default:
				}
				cancel()
			}
		}()
		go keepalive(ctx, client, transport, time.Duration(c.KeepaliveSeconds)*time.Second, failed, cancel)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if _, err := fmt.Fprintf(output, "READY %d\n", ln.Addr().(*net.TCPAddr).Port); err != nil {
		return errors.New("SSH tunnel readiness failed")
	}
	_ = sockstun.Serve(ctx, ln, dial, quietLogger{})
	select {
	case err := <-failed:
		return err
	default:
		return nil
	}
}

func connect(ctx context.Context, c config, prompt func(string) (string, error)) (*ssh.Client, net.Conn, error) {
	var auth []ssh.AuthMethod
	if c.PrivateKey != "" {
		key, passphrase, cert := []byte(c.PrivateKey), []byte(c.KeyPassphrase), []byte(c.Certificate)
		signer, err := sshauth.ParseSigner(key, passphrase, cert)
		clear(key)
		clear(passphrase)
		clear(cert)
		if err != nil {
			return nil, nil, errors.New("SSH tunnel private key or certificate is invalid")
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if c.Password != "" {
		auth = append(auth, ssh.Password(c.Password))
	}
	rounds := 0
	auth = append(auth, ssh.KeyboardInteractive(func(_, _ string, questions []string, echoes []bool) ([]string, error) {
		rounds++
		if rounds > 8 || len(questions) > 8 || len(questions) != len(echoes) {
			return nil, errors.New("SSH tunnel challenge exceeds limits")
		}
		result := make([]string, len(questions))
		for i, question := range questions {
			if len(question) > 1024 || strings.IndexFunc(question, unicode.IsControl) >= 0 {
				return nil, errors.New("SSH tunnel challenge is invalid")
			}
			if rounds == 1 && len(questions) == 1 && !echoes[i] && strings.EqualFold(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(question), ":")), "password") && c.Password != "" {
				result[i] = c.Password
			} else {
				var err error
				result[i], err = prompt(question)
				if err != nil {
					return nil, err
				}
			}
		}
		return result, nil
	}))
	dialer := proxy.ContextDialer(&net.Dialer{Timeout: 15 * time.Second})
	if c.UpstreamSocks != "" {
		upstream, err := proxy.SOCKS5("tcp", c.UpstreamSocks, nil, &net.Dialer{Timeout: 15 * time.Second})
		if err != nil {
			return nil, nil, errors.New("SSH tunnel upstream proxy is invalid")
		}
		dialer = upstream.(proxy.ContextDialer)
	}
	address := net.JoinHostPort(strings.Trim(c.Host, "[]"), strconv.Itoa(c.Port))
	transport, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, errors.New("could not reach SSH jump host")
	}
	stop := context.AfterFunc(ctx, func() { _ = transport.Close() })
	defer stop()
	_ = transport.SetDeadline(time.Now().Add(4 * time.Minute))
	conn, channels, requests, err := ssh.NewClientConn(transport, address, &ssh.ClientConfig{
		User: c.Username, Auth: auth,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) != c.HostKeySHA256 {
				return errors.New("SSH host key mismatch")
			}
			return nil
		},
	})
	if err != nil {
		_ = transport.Close()
		return nil, nil, errors.New("SSH tunnel authentication or host-key verification failed")
	}
	_ = transport.SetDeadline(time.Time{})
	return ssh.NewClient(conn, channels, requests), transport, nil
}

func keepalive(ctx context.Context, client *ssh.Client, transport net.Conn, interval time.Duration, failed chan<- error, cancel context.CancelFunc) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = transport.SetDeadline(time.Now().Add(interval))
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				select {
				case failed <- errors.New("SSH jump host keepalive failed"):
				default:
				}
				cancel()
				return
			}
			_ = transport.SetDeadline(time.Time{})
		}
	}
}
