package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func setSharedVNCPassword(t *testing.T, wire map[string]any, password []byte) {
	t.Helper()
	metadata := wire["metadata"].(map[string]any)
	account := wire["accounts"].([]any)[0].(map[string]any)
	row := account["values"].([]any)[0].([]any)
	binding := vault.SharedValueBinding{WorkspaceID: uuid.MustParse(metadata["workspaceId"].(string)), OwnerKind: "credential", OwnerID: uuid.MustParse(row[1].(string)), Field: "password", Version: 9, DEK: vault.KeyRef{ID: uuid.MustParse(row[6].(string)), Version: 1}}
	value, err := vault.SealSharedValue(bytes.Repeat([]byte{23}, 32), binding, password)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := vault.EncodeSharedEnvelope(value)
	if err != nil {
		t.Fatal(err)
	}
	row[8] = hex.EncodeToString(raw)
}

func TestSharedVNCConnectionSealsAuditedPasswordPresence(t *testing.T) {
	for _, mode := range []string{"saved", "saved-path", "empty", "absent", "none"} {
		t.Run(mode, func(t *testing.T) {
			c, p, o, root, account, _, node, wire := credentialControllerFixture(t, vault.Default)
			editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, credential *sharedcatalog.CredentialRecord) {
				protocol := 6
				n.Protocol = &protocol
				credential.Metadata.Protocol = "vnc"
				if mode == "none" {
					none := 0
					n.CredentialMode = &none
					n.CredentialID = nil
				}
				if mode == "absent" {
					credential.Fields = []vaultstore.CredentialField{}
				}
			})
			if mode == "empty" {
				setSharedVNCPassword(t, wire, []byte{})
			}
			if mode == "none" {
				wire["metadata"].(map[string]any)["credential"] = nil
				wire["accounts"] = []any{}
				wire["roots"] = []any{}
			}
			if mode == "absent" {
				a := wire["accounts"].([]any)[0].(map[string]any)
				a["values"], a["copies"] = []any{}, []any{}
				wire["roots"] = []any{}
			}
			begins, fetches := 0, 0
			begin, fetch := p.begin, p.fetch
			p.begin = func(ctx context.Context, id uuid.UUID, source string) (*sharedpg.UseIntent, error) {
				begins++
				return begin(ctx, id, source)
			}
			if mode == "saved-path" {
				addSharedPathProjection(wire, "vnc", nil)
				p.begin = func(context.Context, uuid.UUID, string) (*sharedpg.UseIntent, error) {
					t.Fatal("a path-aware VNC workspace requested a legacy ticket")
					return nil, nil
				}
				c.session = &sharedPathProbe{credentialReleaseProbe: p,
					capability: func() (bool, error) { return true, nil },
					beginPath: func(ctx context.Context, id uuid.UUID, source, path string) (*sharedpg.UseIntent, error) {
						if path != "vnc" {
							t.Fatal("VNC requested a different credential path")
						}
						begins++
						intent, err := begin(ctx, id, source)
						intent.Path = path
						return intent, err
					},
				}
			}
			p.fetch = func(ctx context.Context, intent sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
				fetches++
				return fetch(ctx, intent)
			}
			ssh, private := sharedSSHRequest(node)
			q := localvault.TunnelBundleRequest{NodeID: ssh.NodeID, SessionID: ssh.SessionID, RequestID: ssh.RequestID, Epoch: ssh.Epoch, PublicKey: ssh.PublicKey}
			h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c}}
			t.Cleanup(func() { _ = h.Close() })
			payload := sharedPlanPayload(ssh)
			payload["publicKey"] = q.PublicKey
			raw, _ := json.Marshal(payload)
			response, err := h.Handle(context.Background(), "vnc-bundle", raw)
			var result localvault.VNCConnectionBundle
			if err != nil || json.Unmarshal(response, &result) != nil || begins != 1 || fetches != 1 {
				t.Fatal("audited VNC sealing", err, begins, fetches)
			}
			if result.Binding.Protocol != "vnc" || result.Binding.Host != "server.example" || result.Binding.Port != 5900 || result.Binding.NodeID != node.String() || result.Binding.Epoch != 7 {
				t.Fatal("VNC binding")
			}
			if bytes.Contains(response, []byte("native-connection-secret")) {
				t.Fatal("plaintext in relay")
			}
			frame, err := vault.OpenBundle(private, result.Binding, result.Bundle)
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(frame)
			decoded, err := vault.DecodeVNCBundle(frame)
			if err != nil || decoded.PasswordProvided != (mode == "saved" || mode == "saved-path" || mode == "empty") {
				t.Fatal("password presence", err)
			}
			want := ""
			if mode == "saved" || mode == "saved-path" {
				want = "native-connection-secret"
			}
			if string(decoded.Password) != want {
				t.Fatal("password bytes")
			}
			if _, err = readSharedTrustFile(o.TrustPath, root, o.Binding, c.trustRevision); err != nil {
				t.Fatal("trust not committed", err)
			}
		})
	}
}

func TestSharedVNCConnectionRejectsInvalidOrChangedPlans(t *testing.T) {
	for _, mode := range []string{"protocol", "route", "host", "long-host", "provider", "large", "recipient", "fetch"} {
		t.Run(mode, func(t *testing.T) {
			c, p, o, _, account, _, node, wire := credentialControllerFixture(t, vault.Default)
			editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, credential *sharedcatalog.CredentialRecord) {
				protocol := 6
				n.Protocol = &protocol
				credential.Metadata.Protocol = "vnc"
				switch mode {
				case "protocol":
					protocol = 0
					credential.Metadata.Protocol = "ssh"
				case "route":
					enabled := true
					id := uuid.NewString()
					n.TunnelEnabled = &enabled
					n.TunnelConfigID = &id
				case "host":
					host := "bad host"
					n.Host = &host
				case "long-host":
					host := string(bytes.Repeat([]byte("h"), 1025))
					n.Host = &host
				case "provider":
					credential.Metadata.Provider = "bitwarden"
					credential.Metadata.BitwardenItemID = "fixture-item"
					credential.Fields = []vaultstore.CredentialField{}
				}
			})
			if mode == "provider" {
				a := wire["accounts"].([]any)[0].(map[string]any)
				a["values"], a["copies"] = []any{}, []any{}
				wire["roots"] = []any{}
			}
			if mode == "large" {
				setSharedVNCPassword(t, wire, bytes.Repeat([]byte{3}, vault.MaxVNCPasswordBytes+1))
			}
			if mode == "fetch" {
				p.fetch = func(context.Context, sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
					return nil, errors.New("private")
				}
			}
			ssh, _ := sharedSSHRequest(node)
			q := localvault.TunnelBundleRequest{NodeID: ssh.NodeID, SessionID: ssh.SessionID, RequestID: ssh.RequestID, Epoch: ssh.Epoch, PublicKey: ssh.PublicKey}
			if mode == "recipient" {
				q.PublicKey = make([]byte, 32)
			}
			result, err := c.SealVNCConnection(context.Background(), q, "ui")
			if err == nil || len(result.Bundle.Ciphertext) != 0 || result.Binding.NodeID != "" {
				t.Fatal("invalid VNC emitted packet", err)
			}
		})
	}
	c, _, _, _, _, _, node, _ := credentialControllerFixture(t, vault.Default)
	ssh, _ := sharedSSHRequest(node)
	q := localvault.TunnelBundleRequest{NodeID: ssh.NodeID, SessionID: ssh.SessionID, RequestID: ssh.RequestID, Epoch: ssh.Epoch, PublicKey: ssh.PublicKey}
	if _, err := c.SealVNCConnection(nil, q, "ui"); err != vault.ErrFormat {
		t.Fatal(err)
	}
	bad := q
	bad.CredentialOverride = uuid.NewString()
	if _, err := c.SealVNCConnection(context.Background(), bad, "ui"); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	bad = q
	bad.PublicKey = nil
	if _, err := c.SealVNCConnection(context.Background(), bad, "ui"); err != vault.ErrFormat {
		t.Fatal(err)
	}
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c}}
	for _, operation := range []string{"vnc-route-bundle", "vnc-bundle"} {
		if _, err := h.Handle(context.Background(), operation, []byte(`{}`)); err != vaultwire.ErrProtocol {
			t.Fatal(err)
		}
	}
}

func TestSharedVNCBindingBounds(t *testing.T) {
	node := uuid.NewString()
	q := localvault.TunnelPlanRequest{NodeID: node, SessionID: uuid.NewString(), RequestID: uuid.NewString(), Epoch: 1}
	p := resolver.Plan{NodeID: node, Protocol: 6, Host: "server.example", Port: 5900}
	if _, err := sharedVNCBinding(uuid.New(), p, q); err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{0, 65536} {
		bad := p
		bad.Port = port
		if _, err := sharedVNCBinding(uuid.New(), bad, q); err != vault.ErrPolicy {
			t.Fatal(err)
		}
	}
	bad := q
	bad.CredentialOverride = uuid.NewString()
	if _, err := sharedVNCBinding(uuid.New(), p, bad); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	bad = q
	bad.NodeID = uuid.NewString()
	if _, err := sharedVNCBinding(uuid.New(), p, bad); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	bad = q
	bad.Epoch = 0
	if _, err := sharedVNCBinding(uuid.New(), p, bad); err != vault.ErrPolicy {
		t.Fatal(err)
	}
}
