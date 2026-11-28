package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sealedSSHDial func(context.Context, sshTarget, uint16, uint16) (*sshNativeSession, string, error)

type sealedSSHOutput struct {
	writer io.Writer
	cancel context.CancelFunc
}

func (w sealedSSHOutput) Write(value []byte) (int, error) {
	n, err := w.writer.Write(value)
	if err == nil && n != len(value) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.cancel()
	}
	return n, err
}

func validSealedSSHBinding(b vault.BundleBinding) bool {
	for _, id := range []string{b.WorkspaceID, b.SessionID, b.RequestID, b.NodeID} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed.String() != id {
			return false
		}
	}
	return (b.Protocol == "ssh" || b.Protocol == "sftp") && b.TunnelConfigID == "" && !b.UseExternalClient && b.Epoch > 0 && b.Epoch <= 9007199254740991 && b.Port > 0 && len(b.Host) > 0 && len(b.Host) <= vault.MaxContextBytes && strings.IndexFunc(b.Host, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) }) < 0
}

func decodeSSHBundleBinding(raw []byte) (vault.BundleBinding, error) {
	var binding vault.BundleBinding
	err := decodeVaultObject(raw, map[string]any{
		"workspaceId": &binding.WorkspaceID, "sessionId": &binding.SessionID, "requestId": &binding.RequestID,
		"nodeId": &binding.NodeID, "protocol": &binding.Protocol, "host": &binding.Host, "port": &binding.Port,
		"tunnelConfigId": &binding.TunnelConfigID, "useExternalClient": &binding.UseExternalClient, "epoch": &binding.Epoch,
	}, "workspaceId", "sessionId", "requestId", "nodeId", "protocol", "host", "port", "tunnelConfigId", "useExternalClient", "epoch")
	return binding, err
}

type sealedSSHOpening struct {
	binding       vault.BundleBinding
	bundle        vault.SealedBundle
	route         *vault.TunnelBundleBinding
	endpoint      string
	sftpOnly      bool
	columns, rows uint16
}

func decodeSealedSSHOpening(raw []byte) (sealedSSHOpening, error) {
	var o sealedSSHOpening
	var binding, bundle json.RawMessage
	var endpoint *string
	var fileMode *bool
	if decodeVaultObject(raw, map[string]any{"binding": &binding, "bundle": &bundle, "endpoint": &endpoint, "sftpOnly": &fileMode, "columns": &o.columns, "rows": &o.rows}, "binding", "bundle", "columns", "rows") != nil || (fileMode != nil && !*fileMode) {
		return o, vaultwire.ErrProtocol
	}
	o.sftpOnly = fileMode != nil
	if o.columns == 0 || o.rows == 0 || o.columns > 500 || o.rows > 500 {
		return o, vaultwire.ErrProtocol
	}
	if decodeVaultObject(bundle, map[string]any{"formatVersion": &o.bundle.FormatVersion, "suiteId": &o.bundle.SuiteID, "enc": &o.bundle.Enc, "ciphertext": &o.bundle.Ciphertext}, "formatVersion", "suiteId", "enc", "ciphertext") != nil {
		return o, vaultwire.ErrProtocol
	}
	if endpoint != nil {
		route, err := decodeTunnelBundleBinding(binding)
		if err != nil || (route.Protocol != "ssh" && route.Protocol != "sftp") || !vault.ValidRouteEndpoint(*endpoint) {
			return o, vaultwire.ErrProtocol
		}
		o.binding, o.route, o.endpoint = route.BundleBinding, &route, *endpoint
	} else {
		b, err := decodeSSHBundleBinding(binding)
		if err != nil || !validSealedSSHBinding(b) {
			return o, vaultwire.ErrProtocol
		}
		o.binding = b
	}
	return o, nil
}

func decodeSealedSSHCommand(raw []byte, sessionID string) (sshWireCommand, error) {
	var c sshWireCommand
	// This schema deliberately has no credentials, MCP, host-key
	// trust, open/reconnect, or route override. They require vault authorization.
	if decodeVaultObject(raw, map[string]any{"type": &c.Type, "sessionId": &c.SessionID, "data": &c.Data, "paste": &c.Paste, "columns": &c.Columns, "rows": &c.Rows, "sequence": &c.Sequence}, "type", "sessionId") != nil || c.SessionID != sessionID {
		return decodeSealedSFTPCommand(raw, sessionID)
	}
	switch c.Type {
	case "input", "resize", "snapshot", "terminal-ack", "auto-sudo-cancel", "close", "app-lock":
		return c, nil
	default:
		return decodeSealedSFTPCommand(raw, sessionID)
	}
}

// serveSealedSSH owns one authenticated transport and one ephemeral recipient key. It never
// opens a database, initializes legacy logging, starts MCP or reloads credentials.
// EOF, lock and malformed messages cancel the handshake and retire this child.
func serveSealedSSH(input io.ReadCloser, output io.Writer, dial sealedSSHDial, editOptions ...sealedSFTPEditOptions) error {
	return serveSealedSSHMode(input, output, dial, "", editOptions...)
}

func serveSealedSSHMode(input io.ReadCloser, output io.Writer, dial sealedSSHDial, manualMode string, editOptions ...sealedSFTPEditOptions) error {
	if manualMode != "" && manualMode != "account" && manualMode != "passphrase" {
		return vaultwire.ErrProtocol
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output = sealedSSHOutput{writer: output, cancel: cancel}
	stopClosing := context.AfterFunc(ctx, func() { _ = input.Close() })
	defer stopClosing()
	defer input.Close()
	key, err := securemem.New(32, false)
	if err != nil {
		return err
	}
	defer key.Close()
	var public []byte
	err = key.With(func(raw []byte) error {
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		private, err := ecdh.X25519().NewPrivateKey(raw)
		if err != nil {
			return err
		}
		public = private.PublicKey().Bytes()
		return nil
	})
	if err != nil {
		return err
	}
	if err := json.NewEncoder(output).Encode(struct {
		Type      string `json:"type"`
		PublicKey []byte `json:"publicKey"`
	}{"recipient", public}); err != nil {
		return vaultwire.ErrProtocol
	}
	timeout := 30 * time.Second
	if manualMode != "" {
		timeout = 330 * time.Second
	}
	timer := time.AfterFunc(timeout, cancel)
	defer timer.Stop()
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), vaultwire.MaxFrameBytes)
	if !scanner.Scan() {
		return vaultwire.ErrProtocol
	}
	opening, err := decodeSealedSSHOpening(scanner.Bytes())
	binding, sealed, columns, rows := opening.binding, opening.bundle, opening.columns, opening.rows
	if err != nil {
		return err
	}
	var plaintext []byte
	err = key.With(func(raw []byte) error {
		var e error
		if opening.route == nil {
			plaintext, e = vault.OpenBundle(raw, binding, sealed)
		} else {
			plaintext, e = vault.OpenRoutedBundle(raw, *opening.route, opening.endpoint, sealed)
		}
		return e
	})
	if err != nil {
		_ = key.Close()
		return err
	}
	defer vault.Wipe(plaintext)
	var manualPlaintext []byte
	var payload vault.SSHBundlePayload
	if manualMode == "" {
		payload, err = vault.DecodeSSHBundle(plaintext)
	} else {
		err = key.With(func(raw []byte) error {
			var e error
			payload, manualPlaintext, e = openSealedSSHManualPayload(raw, opening, manualMode, plaintext)
			return e
		})
	}
	defer vault.Wipe(manualPlaintext)
	closeErr := key.Close() // consume once, including inner authentication failure
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if payload.SFTPOnly != opening.sftpOnly {
		return vaultwire.ErrProtocol
	}
	sftpOnly := binding.Protocol == "sftp" || payload.SFTPOnly
	server := &sshServer{output: &sshEventWriter{encoder: json.NewEncoder(output), sealed: true}, sessions: make(map[string]*sshNativeSession), transfers: make(map[string]*sshSftpTransfer), sftpWork: &sftpWorkGroup{}}
	options := sealedSFTPEditOptions{}
	if len(editOptions) > 0 {
		options = editOptions[0]
	}
	server.sealedEdits = &sealedSFTPEdits{options: options, workspaceID: binding.WorkspaceID, nodeID: binding.NodeID, stop: make(chan struct{})}
	members := newSealedSSHMembers(ctx, cancel, server, binding.SessionID, sftpOnly)
	var worker sync.WaitGroup
	worker.Add(1)
	defer func() {
		server.sftpWork.stop()
		cancel()
		worker.Wait()
		members.shutdown()
		server.transferWG.Wait()
		server.sftpWork.wg.Wait()
		server.closeSealedEdits()
	}()
	go func() {
		defer worker.Done()
		defer vault.Wipe(plaintext)
		defer vault.Wipe(manualPlaintext)
		target := sshTarget{sftpOnly: sftpOnly, nodeID: binding.NodeID, host: binding.Host, port: int(binding.Port), socksEndpoint: opening.endpoint, tunnelConfigID: binding.TunnelConfigID, username: payload.Username, knownHostFingerprint: payload.Fingerprint, autoSudo: !sftpOnly && payload.AutoSudo,
			password: string(payload.Password), privateKey: payload.PrivateKey, keyPassphrase: string(payload.Passphrase), certificate: payload.Certificate}
		native, fingerprint, err := dial(ctx, target, columns, rows)
		target.password, target.keyPassphrase = "", ""
		if err != nil {
			server.writeError(binding.SessionID, "sealed SSH connection failed")
			cancel()
			return
		}
		if ctx.Err() != nil {
			native.close(false)
			return
		}
		timer.Stop()
		native.fingerprint = fingerprint
		native.sftpEditRoute = sealedSFTPEditRoute(opening.route)
		if !members.promote(binding.SessionID, native, sshWireEvent{Host: binding.Host, Port: int(binding.Port), Username: payload.Username, Fingerprint: fingerprint}) {
			native.close(false)
			return
		}
		native.start()
	}()
	for scanner.Scan() {
		command, retired, err := members.command(scanner.Bytes())
		if err != nil {
			return err
		}
		if command.Type == "app-lock" {
			return nil
		}
		if retired {
			continue
		}
		if command.Type == "close" {
			if members.close(command.SessionID) {
				return nil
			}
			continue
		}
		if command.Type == "sftp-share" {
			if err := members.share(command); err != nil {
				return err
			}
			continue
		}
		server.handle(command)
	}
	if scanner.Err() != nil {
		return vaultwire.ErrProtocol
	}
	return nil
}

func runSealedSSHModeCLI(input io.Reader, output, errorOutput io.Writer, manualMode string, editOptions ...sealedSFTPEditOptions) int {
	if securemem.DisableProcessDumps() != nil {
		writeErrorTo(errorOutput, "vault_memory_unavailable")
		return 1
	}
	reader, ok := input.(io.ReadCloser)
	if !ok {
		reader = io.NopCloser(input)
	}
	err := serveSealedSSHMode(reader, output, func(ctx context.Context, target sshTarget, columns, rows uint16) (*sshNativeSession, string, error) {
		return dialNativeSSH(ctx, target, uint32(columns), uint32(rows))
	}, manualMode, editOptions...)
	if err != nil {
		writeErrorTo(errorOutput, "sealed_ssh_stopped")
		return 1
	}
	return 0
}
