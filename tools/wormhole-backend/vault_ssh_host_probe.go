package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
	"golang.org/x/crypto/ssh"
)

type sshHostProbeRequest struct {
	Host                string
	Port                uint16
	Endpoint, RequestID string
}

func decodeSSHHostProbe(raw []byte) (sshHostProbeRequest, error) {
	var q sshHostProbeRequest
	if len(raw) > 8192 || decodeVaultObject(raw, map[string]any{"host": &q.Host, "port": &q.Port, "endpoint": &q.Endpoint, "requestId": &q.RequestID}, "host", "port", "endpoint", "requestId") != nil || q.Host == "" || len(q.Host) > vault.MaxContextBytes || strings.IndexFunc(q.Host, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) }) >= 0 || q.Port == 0 || !vaultCredentialID(q.RequestID) || (q.Endpoint != "" && !vault.ValidRouteEndpoint(q.Endpoint)) {
		return sshHostProbeRequest{}, vaultwire.ErrProtocol
	}
	return q, nil
}

// Abort in HostKeyCallback, before any user authentication or channel request.
// No credential, database, agent or local SSH configuration is consulted.
func probeSSHHost(ctx context.Context, q sshHostProbeRequest) (string, error) {
	address := net.JoinHostPort(normalizeSSHHost(q.Host), strconv.Itoa(int(q.Port)))
	var connection net.Conn
	var err error
	if q.Endpoint != "" {
		connection, err = dialSocks5(ctx, q.Endpoint, "tcp", address)
	} else {
		connection, err = (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return "", err
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	observed := ""
	stopBeforeAuthentication := errors.New("host identity observed")
	config := &ssh.ClientConfig{
		User: "wormhole-host-key-probe",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			observed = ssh.FingerprintSHA256(key)
			return stopBeforeAuthentication
		},
	}
	_, _, _, err = ssh.NewClientConn(connection, address, config)
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if !errors.Is(err, stopBeforeAuthentication) || !vault.ValidSSHFingerprint(observed) {
		return "", vaultwire.ErrProtocol
	}
	return observed, nil
}

func serveSSHHostProbe(input io.ReadCloser, output io.Writer, probe func(context.Context, sshHostProbeRequest) (string, error)) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stopClosing := context.AfterFunc(ctx, func() { _ = input.Close() })
	defer stopClosing()
	first := make(chan []byte, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer cancel()
		reader := bufio.NewReaderSize(input, 8193)
		line, err := reader.ReadSlice('\n')
		if err != nil || len(line) > 8192 {
			return
		}
		first <- bytes.Clone(line)
		// EOF, a second command or malformed trailing input cancels this attempt.
		// Main keeps stdin open until it has received the single response.
		_, _ = reader.ReadByte()
	}()
	defer func() { _ = input.Close(); <-done }()
	var raw []byte
	select {
	case raw = <-first:
	case <-ctx.Done():
		return vaultwire.ErrProtocol
	}
	q, err := decodeSSHHostProbe(raw)
	if err != nil {
		return err
	}
	fingerprint, err := probe(ctx, q)
	if err != nil || ctx.Err() != nil || !vault.ValidSSHFingerprint(fingerprint) {
		return vaultwire.ErrProtocol
	}
	return json.NewEncoder(output).Encode(struct {
		RequestID   string `json:"requestId"`
		Fingerprint string `json:"fingerprint"`
	}{q.RequestID, fingerprint})
}

func runSSHHostProbeCLI(input io.Reader, output, errorOutput io.Writer) int {
	reader, ok := input.(io.ReadCloser)
	if !ok {
		reader = io.NopCloser(input)
	}
	if serveSSHHostProbe(reader, output, probeSSHHost) != nil {
		writeErrorTo(errorOutput, "ssh_host_probe_stopped")
		return 1
	}
	return 0
}
