package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestVaultSSHBitwardenHandoff(t *testing.T) {
	for _, routed := range []bool{false, true} {
		name := "direct"
		if routed {
			name = "routed"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			h := vaultCredentialFixture(t)
			fingerprint := sealedSSHFixturePayload().Fingerprint
			itemID := uuid.NewString()
			account := vaultstore.CredentialMetadata{
				ID: uuid.NewString(), Name: "linked", Protocol: "ssh", Provider: "bitwarden", Kind: "password",
				BitwardenItemID: itemID, BitwardenFieldPath: "login.password",
			}
			wantUser := "live"
			if !routed {
				account.Username, wantUser = "saved", "saved"
			}
			c, err := h.owner.PutCredential(ctx, account, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			mode, protocol, host, on := 2, 0, "localhost", true
			node := vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "host", Kind: 1, Host: &host,
				Protocol: &protocol, CredentialID: &c.ID, CredentialMode: &mode, SshKnownHostFingerprint: &fingerprint}
			if routed {
				tunnel, err := h.owner.PutTunnel(ctx, vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "VPN", Kind: 6}, []byte(`{"Host":"vpn","Username":"u","Password":"vpn-fixture"}`), 0)
				if err != nil {
					t.Fatal(err)
				}
				node.TunnelEnabled, node.TunnelConfigID = &on, &tunnel.ID
			}
			if _, err := h.owner.PutNode(ctx, node, nil, 0); err != nil {
				t.Fatal(err)
			}
			target, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			q := map[string]any{"nodeId": node.ID, "credentialOverride": "", "sessionId": uuid.NewString(), "requestId": uuid.NewString(), "epoch": "1"}
			var route vault.TunnelBundleBinding
			endpoint := "127.0.0.1:12345"
			if routed {
				plan, err := h.Handle(ctx, "connection-route", vaultInput(t, q))
				if err != nil || json.Unmarshal(plan, &route) != nil {
					t.Fatal("could not plan route", err)
				}
				q["route"], q["endpoint"], q["sftpOnly"] = route, endpoint, true
			}
			q["publicKey"] = target.PublicKey().Bytes()
			prepare := func() (localvault.BitwardenPreparation, []byte, error) {
				raw, err := h.Handle(ctx, "ssh-bitwarden-prepare", vaultInput(t, q))
				var p localvault.BitwardenPreparation
				if err == nil {
					err = json.Unmarshal(raw, &p)
				}
				return p, raw, err
			}
			probe, _, err := prepare()
			if err != nil || !probe.Required || probe.Revision == "" || probe.Ticket != nil {
				t.Fatal("probe read session state or changed selection", err)
			}

			body := []byte(`{"path":"bw-fixture","region":0,"key":"synthetic-session"}`)
			password := []byte("synthetic-bitwarden-password")
			input, sender := io.Pipe()
			reader, output := io.Pipe()
			defer sender.Close()
			defer reader.Close()
			stopped := make(chan error, 1)
			go func() {
				defer output.Close()
				stopped <- serveVaultConnectionBitwarden(ctx, input, output, "ssh", func(_ context.Context, session []byte, id string) (*bitwardenCliLoginItem, error) {
					if id != itemID || !bytes.Equal(session, body) {
						t.Error("serve resolved a different item or session")
						return nil, vault.ErrAuthentication
					}
					return &bitwardenCliLoginItem{ID: id, Username: "live", Password: string(password)}, nil
				})
			}()
			reply := bufio.NewReader(reader)
			line, err := reply.ReadBytes('\n')
			var recipient struct{ PublicKey []byte }
			if err != nil || json.Unmarshal(line, &recipient) != nil || len(recipient.PublicKey) != 32 {
				t.Fatal("serve did not publish a recipient", err)
			}
			q["revision"], q["resolverPublicKey"] = probe.Revision, recipient.PublicKey
			if _, _, err := prepare(); err == nil {
				t.Fatal("missing session accepted for a release")
			}
			workspace, err := h.owner.WorkspaceID(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = h.owner.PutLocalState(ctx, "bitwarden-cli", workspace, body, 0); err != nil {
				t.Fatal(err)
			}
			q["revision"] = "stale"
			if _, _, err := prepare(); err == nil {
				t.Fatal("stale plan lent the session")
			}
			q["revision"] = probe.Revision
			p, raw, err := prepare()
			if err != nil || p.Ticket == nil || bytes.Contains(raw, body) ||
				bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(body))) {
				t.Fatal("unsealed credential release", err)
			}
			if err := json.NewEncoder(sender).Encode(p.Ticket); err != nil {
				t.Fatal(err)
			}
			line, err = reply.ReadBytes('\n')
			if err != nil || bytes.Contains(line, password) || bytes.Contains(line, body) {
				t.Fatal("unsealed target result", err)
			}
			var plain []byte
			if routed {
				var targetBundle localvault.RoutedSSHConnectionBundle
				if json.Unmarshal(line, &targetBundle) != nil || targetBundle.Binding != route ||
					targetBundle.Endpoint != endpoint || !targetBundle.SFTPOnly {
					t.Fatal("wrong routed target")
				}
				plain, err = vault.OpenRoutedBundle(target.Bytes(), route, endpoint, targetBundle.Bundle)
			} else {
				var targetBundle localvault.SSHConnectionBundle
				if json.Unmarshal(line, &targetBundle) != nil || targetBundle.Binding != p.Ticket.Binding || targetBundle.SFTPOnly {
					t.Fatal("wrong direct target")
				}
				plain, err = vault.OpenBundle(target.Bytes(), targetBundle.Binding, targetBundle.Bundle)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(plain)
			decoded, err := vault.DecodeSSHBundle(plain)
			defer vault.Wipe(decoded.Password)
			if err != nil || !bytes.Equal(decoded.Password, password) || decoded.Fingerprint != fingerprint || decoded.Username != wantUser || bytes.Contains(plain, body) {
				t.Fatal("connection got the wrong credential", err)
			}
			if err := <-stopped; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVaultSSHBitwardenReaderCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	input, sender := io.Pipe()
	defer sender.Close()
	receiver, output := io.Pipe()
	defer receiver.Close()
	started := make(chan struct{})
	cancelled := make(chan error, 1)
	stopped := make(chan error, 1)
	go func() {
		defer output.Close()
		stopped <- serveVaultConnectionBitwarden(ctx, input, output, "ssh", func(ctx context.Context, _ []byte, _ string) (*bitwardenCliLoginItem, error) {
			close(started)
			<-ctx.Done()
			cancelled <- ctx.Err()
			return nil, ctx.Err()
		})
	}()
	var recipient struct{ PublicKey []byte }
	if err := json.NewDecoder(receiver).Decode(&recipient); err != nil {
		t.Fatal(err)
	}
	target, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ticket, err := vault.SealConnectionBitwardenTicket(recipient.PublicKey, sealedSSHFixtureBinding(), vault.ConnectionBitwardenTicketPayload{
		TargetPublicKey: target.PublicKey().Bytes(), ItemID: uuid.NewString(), SavedSession: []byte("synthetic"),
		Fingerprint: sealedSSHFixturePayload().Fingerprint, ExpiresAt: now.Add(time.Minute).UnixMilli(),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(sender).Encode(ticket); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	sender.Close()
	if err := <-cancelled; !errors.Is(err, context.Canceled) {
		t.Fatal("closing the relay did not cancel native resolution", err)
	}
	if err := <-stopped; err == nil {
		t.Fatal("resolver succeeded after relay closed")
	}
}

func TestVaultSSHBitwardenSavedSessionSelection(t *testing.T) {
	database := filepath.Join(t.TempDir(), "workspace.db")
	settings := defaultBitwardenCliSettings()
	settings.Enabled = true
	if err := writeBitwardenCliSettings(database, settings); err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	session := func(path, key string, region int) []byte {
		return vaultInput(t, map[string]any{"path": path, "key": key, "region": region})
	}
	ctx := context.Background()
	failure := errors.New("native failure")
	valid := session(settings.Path, "fixture-session", settings.ServerRegion)
	for _, mode := range []string{"disabled", "bad-json", "path", "region", "no-factor", "found", "sync", "cache-only", "lookup-failed", "sync-failed"} {
		t.Run(mode, func(t *testing.T) {
			raw, db := valid, database
			switch mode {
			case "disabled":
				db = filepath.Join(t.TempDir(), "disabled.db")
			case "bad-json":
				raw = []byte("{")
			case "path":
				raw = session("different-bw", "fixture-session", settings.ServerRegion)
			case "region":
				raw = session(settings.Path, "fixture-session", settings.ServerRegion+1)
			case "no-factor":
				raw = session(settings.Path, " ", settings.ServerRegion)
			}
			gets, syncs := 0, 0
			cli := bitwardenCLI{
				get: func(c context.Context, d string, options bitwardenCliSettings, key, gotID string) (*bitwardenCliLoginItem, error) {
					gets++
					if c != ctx || d != database || options.Path != settings.Path || key != "fixture-session" || gotID != id {
						t.Fatal("CLI received a different session or item")
					}
					if mode == "lookup-failed" {
						return nil, failure
					}
					if mode == "found" || gets == 2 {
						return &bitwardenCliLoginItem{ID: id}, nil
					}
					return nil, nil
				},
				sync: func(context.Context, string, bitwardenCliSettings, string) error {
					syncs++
					if mode == "sync-failed" {
						return failure
					}
					return nil
				},
			}
			if mode == "cache-only" {
				cli.sync = nil
			}
			result, err := resolveVaultBitwardenItem(ctx, db, raw, id, cli)
			switch mode {
			case "found":
				if result == nil || err != nil || gets != 1 || syncs != 0 {
					t.Fatal("cache hit changed", err)
				}
			case "sync":
				if result == nil || err != nil || gets != 2 || syncs != 1 {
					t.Fatal("cache miss was not synced exactly once", err)
				}
			case "cache-only":
				if result != nil || err != nil || gets != 1 || syncs != 0 {
					t.Fatal("cache-only resolver synchronized", err)
				}
			case "lookup-failed", "sync-failed":
				if result != nil || !errors.Is(err, failure) || gets != 1 {
					t.Fatal("CLI failure swallowed", err)
				}
			default:
				if result != nil || err == nil || gets != 0 || syncs != 0 {
					t.Fatal("unbound session reached CLI", err)
				}
			}
		})
	}
}

func TestVaultSSHBitwardenRejectsUnboundRelay(t *testing.T) {
	var diagnostic bytes.Buffer
	if code := runBackendCLI([]string{"--operation", "serve", "--sealed-ssh-bitwarden", "--database", "relative"}, strings.NewReader(""), io.Discard, &diagnostic); code == 0 || diagnostic.String() != "vault_bitwarden_unavailable\n" {
		t.Fatal("invalid startup emitted an unexpected diagnostic")
	}
	binding := sealedSSHFixtureBinding()
	p := vault.ConnectionBitwardenTicketPayload{ItemID: uuid.NewString(), ExpiresAt: time.Now().Add(time.Minute).UnixMilli()}
	for _, item := range []*bitwardenCliLoginItem{
		nil, {ID: uuid.NewString(), Password: "synthetic"}, {ID: p.ItemID}, {ID: p.ItemID, Password: "synthetic"},
	} {
		result, err := sealVaultConnectionBitwardenResult(context.Background(), binding, p, func(context.Context, []byte, string) (*bitwardenCliLoginItem, error) {
			return item, nil
		})
		if err == nil || result != nil {
			t.Fatal("unbound credential released")
		}
	}
	for _, frame := range []string{
		"", "{\"extra\":true}\n", "{\"binding\":{},\"ticket\":{}}\n",
	} {
		if err := serveVaultConnectionBitwarden(context.Background(), io.NopCloser(strings.NewReader(frame)), io.Discard, "ssh", func(context.Context, []byte, string) (*bitwardenCliLoginItem, error) {
			t.Error("bad frame reached the resolver")
			return nil, nil
		}); err == nil {
			t.Fatal("invalid relay input admitted")
		}
	}
}
