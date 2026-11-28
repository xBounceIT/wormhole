package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

const sealedVNCFrameLimit = 32 * 1024

type sealedVNCDial func(context.Context, string, string) (net.Conn, error)
type sealedVNCSession struct {
	binding  vault.BundleBinding
	endpoint string
	auth     *sealedVNCAuth
	dial     sealedVNCDial
	ready    func()
}

func (s *vncSession) connectSealed() {
	native := s.sealed
	defer native.auth.dispose()
	ctx, ok := s.beginConnect()
	if !ok {
		return
	}
	defer s.endConnect()
	s.emitStatus("connecting", "", false)
	// Normalize only after HPKE authenticated the original binding. The explicit
	// authenticated port keeps precedence, matching the legacy VNC adapter.
	host, port, err := splitVncHostPort(native.binding.Host, int(native.binding.Port))
	if err != nil || host == "" {
		s.fail(errSealedVNCAuth)
		return
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	network, err := native.dial(ctx, native.endpoint, address)
	if err != nil {
		s.fail(err)
		return
	}
	if !s.setNetworkConnection(network) {
		_ = network.Close()
		return
	}
	_ = network.SetDeadline(time.Now().Add(vncConnectTimeout))
	authenticated, err := authenticateSealedVNC(ctx, network, native.auth)
	if err != nil {
		s.fail(err)
		return
	}
	guarded := newVncReadGuard(&vncPixelFormatConn{Conn: authenticated})
	if !s.setNetworkConnection(guarded) {
		_ = guarded.Close()
		return
	}
	s.serveNetwork(ctx, guarded, sealedVNCClientConfig(), native.binding.Host, int(native.binding.Port))
}

type sealedVNCOpening struct {
	binding  vault.BundleBinding
	bundle   vault.SealedBundle
	route    *vault.TunnelBundleBinding
	endpoint string
}

func decodeSealedVNCOpening(raw []byte) (sealedVNCOpening, error) {
	var o sealedVNCOpening
	var binding, bundle json.RawMessage
	var endpoint *string
	if decodeVaultObject(raw, map[string]any{"binding": &binding, "bundle": &bundle, "endpoint": &endpoint}, "binding", "bundle") != nil {
		return o, vaultwire.ErrProtocol
	}
	if decodeVaultObject(bundle, map[string]any{"formatVersion": &o.bundle.FormatVersion, "suiteId": &o.bundle.SuiteID, "enc": &o.bundle.Enc, "ciphertext": &o.bundle.Ciphertext}, "formatVersion", "suiteId", "enc", "ciphertext") != nil {
		return o, vaultwire.ErrProtocol
	}
	if endpoint != nil {
		route, err := decodeTunnelBundleBinding(binding)
		if err != nil || route.Protocol != "vnc" || !vault.ValidRouteEndpoint(*endpoint) {
			return o, vaultwire.ErrProtocol
		}
		o.binding, o.route, o.endpoint = route.BundleBinding, &route, *endpoint
	} else {
		b, err := decodeVNCConnectionBinding(binding)
		if err != nil {
			return o, err
		}
		o.binding = b
	}
	if !validVNCConnectionBinding(o.binding, o.route != nil) {
		return o, vaultwire.ErrProtocol
	}
	return o, nil
}

func decodeVNCConnectionBinding(raw []byte) (vault.BundleBinding, error) {
	var b vault.BundleBinding
	if decodeVaultObject(raw, map[string]any{"workspaceId": &b.WorkspaceID, "sessionId": &b.SessionID, "requestId": &b.RequestID, "nodeId": &b.NodeID, "protocol": &b.Protocol, "host": &b.Host, "port": &b.Port, "tunnelConfigId": &b.TunnelConfigID, "useExternalClient": &b.UseExternalClient, "epoch": &b.Epoch}, "workspaceId", "sessionId", "requestId", "nodeId", "protocol", "host", "port", "tunnelConfigId", "useExternalClient", "epoch") != nil || !validVNCConnectionBinding(b, false) {
		return b, vaultwire.ErrProtocol
	}
	return b, nil
}
func validVNCConnectionBinding(b vault.BundleBinding, routed bool) bool {
	for _, id := range []string{b.WorkspaceID, b.NodeID, b.SessionID, b.RequestID} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id {
			return false
		}
	}
	return b.Protocol == "vnc" && !b.UseExternalClient && b.Epoch > 0 && b.Epoch <= 9007199254740991 && b.Port > 0 && len(b.Host) > 0 && len(b.Host) <= maxVncHostLength && strings.IndexFunc(b.Host, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) }) < 0 && (routed || b.TunnelConfigID == "")
}

func decodeSealedVNCCommand(raw []byte, session string) (backendCommand, error) {
	var command backendCommand
	if len(raw) > 4096 {
		return command, vaultwire.ErrProtocol
	}
	if decodeVaultObject(raw, map[string]any{"type": &command.Action, "sessionId": &command.SessionID, "x": &command.X, "y": &command.Y, "buttons": &command.Buttons, "down": &command.Down, "keysym": &command.KeySym}, "type", "sessionId") != nil || command.SessionID != session {
		return command, vaultwire.ErrProtocol
	}
	// Per-command exact schemas reject ignored, secret-bearing or replay fields.
	fields := map[string]any{"type": &command.Action, "sessionId": &command.SessionID}
	required := []string{"type", "sessionId"}
	switch command.Action {
	case "pointer":
		fields["x"], fields["y"], fields["buttons"] = &command.X, &command.Y, &command.Buttons
		required = append(required, "x", "y", "buttons")
	case "key":
		fields["down"], fields["keysym"] = &command.Down, &command.KeySym
		required = append(required, "down", "keysym")
	case "close", "app-lock":
	default:
		return command, vaultwire.ErrProtocol
	}
	if decodeVaultObject(raw, fields, required...) != nil || command.X < 0 || command.Y < 0 || command.X > 65535 || command.Y > 65535 {
		return command, vaultwire.ErrProtocol
	}
	return command, nil
}

// One ephemeral recipient, one session and one authenticated destination. This
// process has no database handle, legacy logging, Bitwarden or route prompts.
func serveSealedVNC(input io.ReadCloser, output io.Writer, dial sealedVNCDial) error {
	return serveSealedVNCMode(input, output, dial, false)
}

func serveSealedVNCMode(input io.ReadCloser, output io.Writer, dial sealedVNCDial, manual bool) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output = sealedSSHOutput{writer: output, cancel: cancel}
	stop := context.AfterFunc(ctx, func() { _ = input.Close() })
	defer stop()
	defer input.Close()
	key, err := securemem.New(32, false)
	if err != nil {
		return err
	}
	defer key.Close()
	var public []byte
	if err = key.With(func(raw []byte) error {
		if _, e := rand.Read(raw); e != nil {
			return e
		}
		private, e := ecdh.X25519().NewPrivateKey(raw)
		if e == nil {
			public = private.PublicKey().Bytes()
		}
		return e
	}); err != nil {
		return err
	}
	if json.NewEncoder(output).Encode(struct {
		Type      string `json:"type"`
		PublicKey []byte `json:"publicKey"`
	}{"recipient", public}) != nil {
		return vaultwire.ErrProtocol
	}
	openingTimeout := 30 * time.Second
	if manual {
		openingTimeout = 5 * time.Minute
	}
	timer := time.AfterFunc(openingTimeout, cancel)
	defer timer.Stop()
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), sealedVNCFrameLimit+2)
	if !scanner.Scan() || len(scanner.Bytes()) > sealedVNCFrameLimit {
		return vaultwire.ErrProtocol
	}
	opening, err := decodeSealedVNCOpening(scanner.Bytes())
	if err != nil {
		return err
	}
	var authorization, plaintext []byte
	defer func() { vault.Wipe(authorization); vault.Wipe(plaintext) }()
	err = key.With(func(raw []byte) error {
		var e error
		if opening.route == nil {
			authorization, e = vault.OpenBundle(raw, opening.binding, opening.bundle)
		} else {
			authorization, e = vault.OpenRoutedBundle(raw, *opening.route, opening.endpoint, opening.bundle)
		}
		if e != nil {
			return e
		}
		if manual {
			inner, e := vault.DecodeVNCManualAuthorization(authorization)
			if e != nil {
				return e
			}
			plaintext, e = vault.OpenManualVNCPassword(raw, opening.binding, opening.route, opening.endpoint, inner)
			return e
		}
		plaintext = authorization
		return nil
	})
	closeErr := key.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	payload, err := vault.DecodeVNCBundle(plaintext)
	if err != nil {
		return err
	}
	auth := &sealedVNCAuth{password: payload.Password, provided: payload.PasswordProvided}
	defer auth.dispose()
	manager := newVncManager(nil, newBackendLineWriter(output))
	session := newVncSession(opening.binding.SessionID, manager.output, manager)
	session.sealed = &sealedVNCSession{binding: opening.binding, endpoint: opening.endpoint, auth: auth, dial: dial, ready: func() { timer.Stop() }}
	manager.sessions[session.id] = session
	// Cancellation closes the socket even while a handshake blocks. Never wipe
	// borrowed plaintext until the connection worker has joined.
	closing := context.AfterFunc(ctx, session.close)
	defer closing()
	session.start(backendCommand{}, nil)
	defer session.closeAndWait()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-session.done:
			cancel()
		case <-finished:
		}
	}()
	for scanner.Scan() {
		command, err := decodeSealedVNCCommand(scanner.Bytes(), session.id)
		if err != nil {
			return err
		}
		switch command.Action {
		case "close", "app-lock":
			return nil
		case "pointer":
			if err := session.pointer(command.X, command.Y, command.Buttons); err != nil {
				return vaultwire.ErrProtocol
			}
		case "key":
			if err := session.key(command.Down, command.KeySym); err != nil {
				return vaultwire.ErrProtocol
			}
		}
	}
	if scanner.Err() != nil {
		return vaultwire.ErrProtocol
	}
	return nil
}

func runSealedVNCCLI(input io.Reader, output, errorOutput io.Writer) int {
	return runSealedVNCModeCLI(input, output, errorOutput, false)
}
func runSealedVNCModeCLI(input io.Reader, output, errorOutput io.Writer, manual bool) int {
	if securemem.DisableProcessDumps() != nil {
		writeErrorTo(errorOutput, "vault_memory_unavailable")
		return 1
	}
	reader, ok := input.(io.ReadCloser)
	if !ok {
		reader = io.NopCloser(input)
	}
	err := serveSealedVNCMode(reader, output, func(ctx context.Context, endpoint, address string) (net.Conn, error) {
		if endpoint != "" {
			return dialSocks5(ctx, endpoint, "tcp", address)
		}
		dialer := net.Dialer{Timeout: vncConnectTimeout}
		return dialer.DialContext(ctx, "tcp", address)
	}, manual)
	if err != nil {
		writeErrorTo(errorOutput, "sealed_vnc_stopped")
		return 1
	}
	return 0
}
