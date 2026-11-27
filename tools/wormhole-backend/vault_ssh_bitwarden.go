package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

const maxBitwardenFrame = 144 * 1024

func (h *vaultFoundationHandler) prepareConnectionBitwarden(ctx context.Context, protocol string, raw []byte) (json.RawMessage, error) {
	if h.owner == nil || h.shared != nil || len(raw) > 8192 {
		return nil, vaultwire.ErrProtocol
	}
	var q localvault.TunnelBundleRequest
	var sftpOnly bool
	var epoch, endpoint, reviewed string
	var resolverKey []byte
	var routeRaw json.RawMessage
	fields := map[string]any{
		"nodeId": &q.NodeID, "credentialOverride": &q.CredentialOverride,
		"sessionId": &q.SessionID, "requestId": &q.RequestID, "epoch": &epoch, "publicKey": &q.PublicKey,
		"route": &routeRaw, "endpoint": &endpoint, "resolverPublicKey": &resolverKey, "revision": &reviewed,
	}
	if protocol == "ssh" {
		fields["sftpOnly"] = &sftpOnly
	}
	if decodeVaultObject(raw, fields, "nodeId", "credentialOverride", "sessionId", "requestId", "epoch", "publicKey") != nil ||
		(len(resolverKey) != 0 && len(resolverKey) != 32) {
		return nil, vaultwire.ErrProtocol
	}
	var err error
	q.Epoch, err = strconv.ParseUint(epoch, 10, 64)
	if err != nil || strconv.FormatUint(q.Epoch, 10) != epoch {
		return nil, vaultwire.ErrProtocol
	}
	var route *vault.TunnelBundleBinding
	if len(routeRaw) != 0 {
		value, err := decodeTunnelBundleBinding(routeRaw)
		if err != nil {
			return nil, err
		}
		route = &value
	}
	var prepared localvault.BitwardenPreparation
	switch protocol {
	case "ssh":
		prepared, err = h.owner.PrepareSSHBitwarden(ctx, localvault.SSHBundleRequest{
			NodeID: q.NodeID, CredentialOverride: q.CredentialOverride, SessionID: q.SessionID,
			RequestID: q.RequestID, Epoch: q.Epoch, PublicKey: q.PublicKey, SFTPOnly: sftpOnly,
		}, route, endpoint, resolverKey, reviewed)
	case "vnc":
		prepared, err = h.owner.PrepareVNCBitwarden(ctx, q, route, endpoint, resolverKey, reviewed)
	case "rdp":
		prepared, err = h.owner.PrepareRDPBitwarden(ctx, q, route, endpoint, resolverKey, reviewed)
	default:
		return nil, vaultwire.ErrProtocol
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(prepared)
}

type bitwardenItemLookup func(context.Context, []byte, string) (*bitwardenCliLoginItem, error)

type bitwardenCLI struct {
	get  func(context.Context, string, bitwardenCliSettings, string, string) (*bitwardenCliLoginItem, error)
	sync func(context.Context, string, bitwardenCliSettings, string) error
}

func resolveVaultBitwardenItem(ctx context.Context, databasePath string, session []byte, itemID string, cli bitwardenCLI) (*bitwardenCliLoginItem, error) {
	settings, err := readBitwardenCliSettings(databasePath)
	if err != nil || !settings.Enabled {
		return nil, vault.ErrPolicy
	}
	var saved bitwardenSavedSession
	if json.Unmarshal(session, &saved) != nil || !bitwardenCliPathsEqual(saved.Path, settings.Path) ||
		saved.Region != settings.ServerRegion {
		return nil, vault.ErrAuthentication
	}
	key, err := bitwardenCliReadSessionKey(saved.Key)
	if err != nil {
		return nil, vault.ErrAuthentication
	}
	item, err := cli.get(ctx, databasePath, settings, key, itemID)
	if err != nil || item != nil || cli.sync == nil {
		return item, err
	}
	if err := cli.sync(ctx, databasePath, settings, key); err != nil {
		return nil, err
	}
	return cli.get(ctx, databasePath, settings, key, itemID)
}

func sealVaultConnectionBitwardenResult(ctx context.Context, b vault.BundleBinding, p vault.ConnectionBitwardenTicketPayload, lookup bitwardenItemLookup) (any, error) {
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(p.ExpiresAt))
	defer cancel()
	if ctx.Err() != nil {
		return nil, vault.ErrPolicy
	}
	if b.Protocol == "rdp" {
		return sealVaultRDPBitwardenAccounts(ctx, b, p, lookup)
	}
	item, err := lookup(ctx, p.SavedSession, p.ItemID)
	if err != nil || item == nil || item.ID != p.ItemID || item.Password == "" {
		return nil, vault.ErrAuthentication
	}
	if ctx.Err() != nil {
		return nil, vault.ErrPolicy
	}
	password := []byte(item.Password)
	defer vault.Wipe(password)
	if b.Protocol == "vnc" {
		raw, err := vault.EncodeVNCBundle(vault.VNCBundlePayload{Password: password, PasswordProvided: true})
		if err != nil {
			return nil, err
		}
		defer vault.Wipe(raw)
		if p.Route != nil {
			bundle, err := vault.SealRoutedBundle(p.TargetPublicKey, *p.Route, p.Endpoint, raw)
			return localvault.RoutedVNCConnectionBundle{Binding: *p.Route, Endpoint: p.Endpoint, Bundle: bundle}, err
		}
		bundle, err := vault.SealBundle(p.TargetPublicKey, b, raw)
		return localvault.VNCConnectionBundle{Binding: b, Bundle: bundle}, err
	}
	username := p.Username
	if username == "" {
		username = strings.TrimSpace(item.Username)
	}
	raw, err := vault.EncodeSSHBundle(vault.SSHBundlePayload{
		Username: username, Password: password, Fingerprint: p.Fingerprint,
		SFTPOnly: p.SFTPOnly, AutoSudo: p.AutoSudo,
	})
	defer vault.Wipe(raw)
	if err != nil {
		return nil, err
	}
	if p.Route != nil {
		bundle, err := vault.SealRoutedBundle(p.TargetPublicKey, *p.Route, p.Endpoint, raw)
		if err != nil {
			return nil, err
		}
		return localvault.RoutedSSHConnectionBundle{SFTPOnly: p.SFTPOnly, Binding: *p.Route, Endpoint: p.Endpoint, Bundle: bundle}, nil
	}
	bundle, err := vault.SealBundle(p.TargetPublicKey, b, raw)
	if err != nil {
		return nil, err
	}
	return localvault.SSHConnectionBundle{SFTPOnly: p.SFTPOnly, Binding: b, Bundle: bundle}, nil
}

// One reply per process. Extra input or EOF cancels the native CLI, including
// while it is waiting on a sync. Main keeps stdin open until it gets the reply.
func serveVaultConnectionBitwarden(parent context.Context, input io.ReadCloser, output io.Writer, protocol string, lookup bitwardenItemLookup) error {
	return serveVaultBitwardenExchange(parent, input, output, vault.BitwardenTicketLifetime, func(ctx context.Context, key *securemem.Buffer, line []byte) (any, error) {
		return resolveVaultConnectionBitwardenTicket(ctx, key, line, protocol, lookup)
	})
}

type bitwardenExchange func(context.Context, *securemem.Buffer, []byte) (any, error)

func serveVaultBitwardenExchange(parent context.Context, input io.ReadCloser, output io.Writer, lifetime time.Duration, execute bitwardenExchange) error {
	defer input.Close()
	ctx, cancel := context.WithTimeout(parent, lifetime)
	defer cancel()
	interrupt := context.AfterFunc(ctx, func() { _ = input.Close() })
	defer interrupt()
	key, publicKey, err := newSealedTunnelRecipientKey()
	if err != nil {
		return err
	}
	defer key.Close()
	encoder := json.NewEncoder(output)
	if err := encoder.Encode(struct {
		PublicKey []byte `json:"publicKey"`
	}{publicKey}); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(input, maxBitwardenFrame)
	line, err := reader.ReadSlice('\n')
	if err != nil || reader.Buffered() != 0 {
		return vaultwire.ErrProtocol
	}
	line = append([]byte(nil), line...)
	go func() {
		_, _ = reader.ReadByte()
		cancel()
	}()
	result, err := execute(ctx, key, line)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return encoder.Encode(result)
}

func decodeBitwardenExchangeBundle(raw []byte, bundle *vault.SealedBundle) error {
	return decodeVaultObject(raw, map[string]any{
		"formatVersion": &bundle.FormatVersion, "suiteId": &bundle.SuiteID,
		"enc": &bundle.Enc, "ciphertext": &bundle.Ciphertext,
	}, "formatVersion", "suiteId", "enc", "ciphertext")
}

func resolveVaultConnectionBitwardenTicket(ctx context.Context, key *securemem.Buffer, line []byte, protocol string, lookup bitwardenItemLookup) (any, error) {
	var ticket vault.ConnectionBitwardenTicket
	var bindingRaw, bundleRaw json.RawMessage
	if decodeVaultObject(line, map[string]any{"binding": &bindingRaw, "ticket": &bundleRaw}, "binding", "ticket") != nil {
		return nil, vaultwire.ErrProtocol
	}
	var err error
	ticket.Binding, err = decodeSSHBundleBinding(bindingRaw)
	if err != nil || decodeBitwardenExchangeBundle(bundleRaw, &ticket.Ticket) != nil ||
		(ticket.Binding.Protocol != protocol && (protocol != "ssh" || ticket.Binding.Protocol != "sftp")) {
		return nil, vaultwire.ErrProtocol
	}
	var payload vault.ConnectionBitwardenTicketPayload
	err = key.With(func(private []byte) error {
		var err error
		payload, err = vault.OpenConnectionBitwardenTicket(private, ticket, time.Now())
		return err
	})
	_ = key.Close()
	defer vault.Wipe(payload.SavedSession)
	if payload.RDP != nil {
		defer vault.Wipe(payload.RDP.Link)
	}
	if err != nil {
		return nil, err
	}
	return sealVaultConnectionBitwardenResult(ctx, ticket.Binding, payload, lookup)
}

func runVaultConnectionBitwardenServe(databasePath string, input io.Reader, output, diagnostic io.Writer, protocol string) int {
	if !filepath.IsAbs(databasePath) || securemem.DisableProcessDumps() != nil {
		writeErrorTo(diagnostic, "vault_bitwarden_unavailable")
		return 1
	}
	reader, ok := input.(io.ReadCloser)
	if !ok {
		writeErrorTo(diagnostic, "vault_bitwarden_unavailable")
		return 1
	}
	cli := bitwardenCLI{get: bitwardenCliGetItemContext}
	if protocol == "ssh" {
		cli.sync = bitwardenCliSyncContext
	}
	err := serveVaultConnectionBitwarden(context.Background(), reader, output, protocol, func(ctx context.Context, session []byte, itemID string) (*bitwardenCliLoginItem, error) {
		return resolveVaultBitwardenItem(ctx, databasePath, session, itemID, cli)
	})
	if err != nil {
		writeErrorTo(diagnostic, "vault_bitwarden_unavailable")
		return 1
	}
	return 0
}
