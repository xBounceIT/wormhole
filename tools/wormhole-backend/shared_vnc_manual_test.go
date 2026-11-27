package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestSharedVNCManualAuthorizesWithoutOpeningSavedValues(t *testing.T) {
	for _, password := range [][]byte{[]byte("manual-shared-password"), {}} {
		c, p, o, root, account, _, node, wire := credentialControllerFixture(t, vault.Default)
		editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, credential *sharedcatalog.CredentialRecord) {
			protocol := 6
			n.Protocol = &protocol
			credential.Metadata.Protocol = "vnc"
		})
		// Neither public planning nor manual authorization needs the account private
		// key. An accidental WithValues call would fail to open this valid graph.
		if err := c.privateKeys.With(func(key []byte) error { vault.Wipe(key); return nil }); err != nil {
			t.Fatal(err)
		}
		begins, fetches := 0, 0
		begin, fetch := p.begin, p.fetch
		p.begin = func(ctx context.Context, id uuid.UUID, source string) (*sharedpg.UseIntent, error) {
			begins++
			return begin(ctx, id, source)
		}
		p.fetch = func(ctx context.Context, intent sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
			fetches++
			return fetch(ctx, intent)
		}
		h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c}}
		t.Cleanup(func() { _ = h.Close() })
		ssh, private := sharedSSHRequest(node)
		plan := sharedPlanPayload(ssh)
		raw, err := h.Handle(context.Background(), "vnc-plan", vaultInput(t, plan))
		var planned struct {
			Binding vault.BundleBinding `json:"binding"`
		}
		if err != nil || json.Unmarshal(raw, &planned) != nil || begins != 0 || fetches != 0 {
			t.Fatal("manual planning fetched secrets", err, begins, fetches)
		}
		inner, err := vault.SealManualVNCPassword(ssh.PublicKey, planned.Binding, nil, "", password)
		if err != nil {
			t.Fatal(err)
		}
		request := cloneSFTPPacket(plan)
		request["publicKey"], request["binding"], request["manual"] = ssh.PublicKey, planned.Binding, inner
		raw, err = h.Handle(context.Background(), "vnc-manual-bundle", vaultInput(t, request))
		var result localvault.VNCConnectionBundle
		if err != nil || json.Unmarshal(raw, &result) != nil || begins != 1 || fetches != 1 {
			t.Fatal("manual authorization not audited", err, begins, fetches)
		}
		if bytes.Contains(raw, []byte("manual-shared-password")) || bytes.Contains(raw, []byte("native-connection-secret")) {
			t.Fatal("plaintext relay")
		}
		outer, err := vault.OpenBundle(private, planned.Binding, result.Bundle)
		if err != nil {
			t.Fatal(err)
		}
		defer vault.Wipe(outer)
		envelope, err := vault.DecodeVNCManualAuthorization(outer)
		if err != nil || !bytes.Equal(envelope.Ciphertext, inner.Ciphertext) || !bytes.Equal(envelope.Enc, inner.Enc) {
			t.Fatal("opaque envelope altered", err)
		}
		decoded, err := vault.OpenManualVNCPassword(private, planned.Binding, nil, "", envelope)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := vault.DecodeVNCBundle(decoded)
		if err != nil || !payload.PasswordProvided || !bytes.Equal(payload.Password, password) {
			t.Fatal("manual password changed", err)
		}
		vault.Wipe(decoded)
		if _, err = readSharedTrustFile(o.TrustPath, root, o.Binding, c.trustRevision); err != nil {
			t.Fatal("manual authorization escaped trust publication", err)
		}
	}
}

func TestSharedVNCManualRejectsChangedAuthorityAndMalformedRequests(t *testing.T) {
	for _, mode := range []string{"endpoint", "route", "protocol", "recipient", "fetch", "cancel", "anchor", "binding", "inner", "override", "source"} {
		t.Run(mode, func(t *testing.T) {
			c, p, o, _, account, _, node, wire := credentialControllerFixture(t, vault.Default)
			edit := func(change func(*vaultstore.NodeMetadata, *sharedcatalog.CredentialRecord)) {
				editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, change)
			}
			edit(func(n *vaultstore.NodeMetadata, credential *sharedcatalog.CredentialRecord) {
				protocol := 6
				n.Protocol = &protocol
				credential.Metadata.Protocol = "vnc"
			})
			ssh, _ := sharedSSHRequest(node)
			q := localvault.TunnelBundleRequest{NodeID: ssh.NodeID, SessionID: ssh.SessionID, RequestID: ssh.RequestID, Epoch: ssh.Epoch, PublicKey: ssh.PublicKey}
			expected, err := c.PlanVNCConnection(context.Background(), q.Plan())
			if err != nil {
				t.Fatal(err)
			}
			inner, err := vault.SealManualVNCPassword(q.PublicKey, expected, nil, "", []byte("temporary"))
			if err != nil {
				t.Fatal(err)
			}
			source := "ui"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "endpoint":
				edit(func(n *vaultstore.NodeMetadata, _ *sharedcatalog.CredentialRecord) {
					host := "redirected.example"
					n.Host = &host
				})
			case "route":
				edit(func(n *vaultstore.NodeMetadata, _ *sharedcatalog.CredentialRecord) {
					enabled, id := true, uuid.NewString()
					n.TunnelEnabled = &enabled
					n.TunnelConfigID = &id
				})
			case "protocol":
				edit(func(n *vaultstore.NodeMetadata, credential *sharedcatalog.CredentialRecord) {
					protocol := 0
					n.Protocol = &protocol
					credential.Metadata.Protocol = "ssh"
				})
			case "recipient":
				q.PublicKey = make([]byte, 32)
			case "fetch":
				p.fetch = func(context.Context, sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
					return nil, errors.New("private")
				}
			case "cancel":
				fetch := p.fetch
				p.fetch = func(ctx context.Context, i sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
					v, e := fetch(ctx, i)
					cancel()
					return v, e
				}
			case "anchor":
				c.catalogAnchor = func(context.Context, string, []byte, sharedpg.TrustBinding, sharedpg.TrustState) error {
					return errors.New("private")
				}
			case "binding":
				expected.SessionID = uuid.NewString()
			case "inner":
				inner = vault.SealedBundle{}
			case "override":
				q.CredentialOverride = uuid.NewString()
			case "source":
				source = "untrusted"
			}
			result, err := c.SealManualVNCConnection(ctx, q, expected, inner, source)
			if err == nil || result.Binding.NodeID != "" || len(result.Bundle.Ciphertext) != 0 {
				t.Fatal("invalid authorization emitted packet", err)
			}
		})
	}
	c, _, _, _, _, _, node, _ := credentialControllerFixture(t, vault.Default)
	ssh, _ := sharedSSHRequest(node)
	q := localvault.TunnelBundleRequest{NodeID: ssh.NodeID, SessionID: ssh.SessionID, RequestID: ssh.RequestID, Epoch: ssh.Epoch, PublicKey: ssh.PublicKey}
	if _, err := c.PlanVNCConnection(nil, q.Plan()); err != vault.ErrFormat {
		t.Fatal(err)
	}
	bad := q
	bad.CredentialOverride = uuid.NewString()
	if _, err := c.PlanVNCConnection(context.Background(), bad.Plan()); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	if _, err := c.SealManualVNCConnection(nil, q, vault.BundleBinding{}, vault.SealedBundle{}, "ui"); err != vault.ErrFormat {
		t.Fatal(err)
	}
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c}}
	for _, operation := range []string{"vnc-plan", "vnc-manual-bundle", "vnc-manual-route-bundle"} {
		if _, err := h.Handle(context.Background(), operation, []byte(`{}`)); err != vaultwire.ErrProtocol {
			t.Fatal(err)
		}
	}
}

// This joins the real signed shared graph and native RPC output to the actual
// sealed recipient CLI and a TCP RFB server, including authentication and input.
func TestSharedVNCNativeRecipientRFB(t *testing.T) {
	for _, routed := range []bool{false, true} {
		for _, mode := range []string{"saved", "manual", "manual-empty"} {
			t.Run(mode+"/routed="+strconv.FormatBool(routed), func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				password := "native-connection-secret"
				if mode == "manual" {
					password = "temporary-shared-password"
				} else if mode == "manual-empty" {
					password = ""
				}
				serverDone := make(chan error, 1)
				go func() {
					serverDone <- serveFakeVncWithFormat(listener, make(chan string, 2), [16]byte{32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0}, password, true)
				}()
				c, p, o, _, account, _, node, wire := credentialControllerFixture(t, vault.Default)
				editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, credential *sharedcatalog.CredentialRecord) {
					protocol, host, port := 6, "127.0.0.1", listener.Addr().(*net.TCPAddr).Port
					if routed {
						host, port = "unreachable-shared-vnc.invalid", 5900
						enabled, id := true, uuid.NewString()
						n.TunnelEnabled, n.TunnelConfigID = &enabled, &id
					}
					n.Protocol, n.Host, n.Port = &protocol, &host, &port
					credential.Metadata.Protocol = "vnc"
				})
				if routed {
					installSharedTunnelReleaseFixture(t, wire, account, []byte("native-test-settings"))
				}
				begins := 0
				begin := p.begin
				p.begin = func(ctx context.Context, id uuid.UUID, source string) (*sharedpg.UseIntent, error) {
					begins++
					return begin(ctx, id, source)
				}
				h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c, fileID: uuid.NewString()}}
				t.Cleanup(func() { _ = h.Close() })
				child := startSealedVNCTestChild(t, nil, mode != "saved")
				ssh, _ := sharedSSHRequest(node)
				q := sharedPlanPayload(ssh)
				operation := "vnc-bundle"
				var route *vault.TunnelBundleBinding
				var endpoint string
				var proxyDone <-chan error
				if routed {
					value := sharedRoutedPlan(t, h, ssh)
					route = &value
					endpoint, proxyDone = sharedRouteSOCKSFixture(t, listener.Addr().String(), value.Host, int(value.Port))
					q["route"], q["endpoint"] = value, endpoint
					operation = "vnc-route-bundle"
				} else {
					raw, err := h.Handle(context.Background(), "connection-route", vaultInput(t, q))
					if err != nil || string(raw) != "null" || begins != 0 {
						t.Fatal("direct VNC route planning", err)
					}
				}
				if mode != "saved" {
					// Corrupting the unused private key makes a saved-secret fallback fail.
					if err := c.privateKeys.With(func(key []byte) error { vault.Wipe(key); return nil }); err != nil {
						t.Fatal(err)
					}
					var binding vault.BundleBinding
					if route != nil {
						binding = route.BundleBinding
					} else {
						raw, err := h.Handle(context.Background(), "vnc-plan", vaultInput(t, q))
						if err != nil {
							t.Fatal(err)
						}
						var planned struct {
							Binding vault.BundleBinding `json:"binding"`
						}
						if json.Unmarshal(raw, &planned) != nil {
							t.Fatal("invalid plan")
						}
						binding = planned.Binding
					}
					inner, err := vault.SealManualVNCPassword(child.public, binding, route, endpoint, []byte(password))
					if err != nil {
						t.Fatal(err)
					}
					q["manual"] = inner
					if route == nil {
						q["binding"] = binding
						operation = "vnc-manual-bundle"
					} else {
						operation = "vnc-manual-route-bundle"
					}
				}
				q["publicKey"] = child.public
				packet, err := h.Handle(context.Background(), operation, vaultInput(t, q))
				if err != nil || begins != 1 {
					t.Fatal("shared release failed", err, begins)
				}
				if len(password) > 0 && bytes.Contains(packet, []byte(password)) {
					t.Fatal("plaintext protocol relay")
				}
				child.send(t, packet)
				vncChildEvent(t, child, "connecting")
				vncChildEvent(t, child, "connected")
				frame := vncChildEvent(t, child, "frame")
				if frame.SessionID != ssh.SessionID || frame.Width != 1 || frame.Height != 1 {
					t.Fatal("shared frame lost")
				}
				child.send(t, vaultInput(t, map[string]any{"type": "pointer", "sessionId": ssh.SessionID, "x": 0, "y": 0, "buttons": 1}))
				child.send(t, vaultInput(t, map[string]any{"type": "key", "sessionId": ssh.SessionID, "keysym": 0xff0d, "down": true}))
				select {
				case err := <-serverDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("shared VNC input timeout")
				}
				child.wait(t)
				if proxyDone != nil {
					select {
					case err := <-proxyDone:
						if err != nil {
							t.Fatal(err)
						}
					case <-time.After(5 * time.Second):
						t.Fatal("VNC proxy did not close")
					}
				}

			})
		}
	}
}
