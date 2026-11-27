package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strconv"
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

func installSharedTunnelReleaseFixture(t *testing.T, wire map[string]any, account *sharedpg.UnverifiedAccountKeys, settings []byte, privateKeys ...ed25519.PrivateKey) {
	t.Helper()
	metadata := wire["metadata"].(map[string]any)
	workspace := uuid.MustParse(metadata["workspaceId"].(string))
	installSharedTunnelPlanFixture(t, workspace, account.Binding.Signing, wire, privateKeys...)
	node := metadata["chain"].([]any)[0].([]any)
	id := uuid.MustParse(metadata["plan"].(resolver.Plan).TunnelID)
	var m vault.BoundaryManifest
	for _, v := range metadata["boundaries"].([]any) {
		row := v.([]any)
		if row[1] == node[5] {
			raw, _ := hex.DecodeString(row[5].(string))
			var err error
			m, err = vault.DecodeBoundaryManifest(raw)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	private := sharedFixtureSigningKey(privateKeys...)
	defer vault.Wipe(private)
	rootPrivate, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{4}, 32))
	copyWire := func(key, holder vault.KeyRef, plain, public []byte) []any {
		b := vault.KeyCopyBinding{WorkspaceID: workspace, Key: key, Holder: holder, Issuer: account.Binding.Signing}
		seed := private.Seed()
		defer vault.Wipe(seed)
		c, err := vault.SealKeyCopy(plain, b, public, seed)
		if err != nil {
			t.Fatal(err)
		}
		row := []any{workspace.String(), "1", "9", key.ID.String(), strconv.Itoa(int(key.Version)), holder.ID.String(), strconv.Itoa(int(holder.Version)), "2", hex.EncodeToString(c.Envelope.Enc), hex.EncodeToString(c.Envelope.Ciphertext), b.Issuer.ID.String(), strconv.Itoa(int(b.Issuer.Version)), hex.EncodeToString(c.Signature), "user-sign", node[12], node[15], node[16], node[17], node[18], node[19], node[20], node[21], node[22]}
		if len(node) == 24 {
			row = append(row, node[23])
		}
		return row
	}
	roots := wire["roots"].([]any)
	if len(roots) == 0 {
		public := account.EncryptionCertificate
		var encryption []byte
		if account.EnrollmentCertificate != nil {
			encryption = account.EnrollmentCertificate.Rekey.Public.Encryption
		} else {
			encryption = public.PublicKey
		}
		roots = append(roots, copyWire(m.Secret.Key, account.Binding.Encryption, rootPrivate.Bytes(), encryption))
		wire["roots"] = roots
	}
	dek := vault.KeyRef{ID: uuid.New(), Version: 1}
	envelope, err := vault.SealSharedValue(bytes.Repeat([]byte{24}, 32), vault.SharedValueBinding{WorkspaceID: workspace, OwnerKind: "tunnel", OwnerID: id, Field: "settings", Version: 1, DEK: dek}, settings)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := vault.EncodeSharedEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	value := []any{workspace.String(), id.String(), "1", "9", "settings", "1", dek.ID.String(), "1", hex.EncodeToString(raw)}
	wire["accounts"] = append(wire["accounts"].([]any), map[string]any{"account": "tunnel", "values": []any{value}, "copies": []any{copyWire(dek, m.Secret.Key, bytes.Repeat([]byte{24}, 32), m.Secret.Public)}})
	wire["formatVersion"] = 4
	if account.EnrollmentCertificate != nil {
		wire["formatVersion"] = 5
	}
	if _, ok := wire["nodeFields"]; !ok {
		wire["nodeFields"] = nil
	}
}

func corruptSharedCiphertext(t *testing.T, wire map[string]any, role string) {
	t.Helper()
	for _, entry := range wire["accounts"].([]any) {
		a := entry.(map[string]any)
		if a["account"] != role {
			continue
		}
		row := a["values"].([]any)[0].([]any)
		raw, _ := hex.DecodeString(row[8].(string))
		e, err := vault.DecodeSharedEnvelope(raw)
		if err != nil {
			t.Fatal(err)
		}
		e.Ciphertext[0] ^= 1
		raw, err = vault.EncodeSharedEnvelope(e)
		if err != nil {
			t.Fatal(err)
		}
		row[8] = hex.EncodeToString(raw)
		return
	}
	t.Fatal("fixture role missing")
}

func sharedRoutedFixture(t *testing.T, protocol int) (*sharedAdmissionController, *credentialReleaseProbe, *vaultFoundationHandler, localvault.SSHBundleRequest, []byte, map[string]any) {
	t.Helper()
	c, p, o, _, account, _, node, wire := credentialControllerFixture(t, vault.Default)
	editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, credential *sharedcatalog.CredentialRecord) {
		id, enabled, pin := uuid.NewString(), true, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		n.TunnelEnabled, n.TunnelConfigID, n.Protocol, n.SshKnownHostFingerprint = &enabled, &id, &protocol, &pin
		credential.Metadata.Protocol = resolver.CredentialProtocol(protocol)
	})
	installSharedTunnelReleaseFixture(t, wire, account, []byte(`{"ProfileOvpn":"test-config","Password":"tunnel-secret"}`))
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c, fileID: uuid.NewString()}}
	t.Cleanup(func() { _ = h.Close() })
	q, private := sharedSSHRequest(node)
	t.Cleanup(func() { vault.Wipe(private) })
	return c, p, h, q, private, wire
}

func sharedRoutedPlan(t *testing.T, h *vaultFoundationHandler, q localvault.SSHBundleRequest) vault.TunnelBundleBinding {
	t.Helper()
	raw, err := h.Handle(context.Background(), "connection-route", vaultInput(t, sharedPlanPayload(q)))
	var route vault.TunnelBundleBinding
	if err != nil || json.Unmarshal(raw, &route) != nil || route.TunnelConfigID == "" {
		t.Fatal("route plan", err)
	}
	return route
}

type sharedWebTunnelProbe struct {
	*sharedPathProbe
	supported func() (bool, error)
	begin     func(context.Context, uuid.UUID, string) (*sharedpg.UseIntent, error)
	fetch     func(context.Context, sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error)
}

func (p *sharedWebTunnelProbe) TunnelUseSupported(context.Context) (bool, error) {
	return p.supported()
}

func (p *sharedWebTunnelProbe) BeginTunnelUse(ctx context.Context, node uuid.UUID, source string) (*sharedpg.UseIntent, error) {
	return p.begin(ctx, node, source)
}

func (p *sharedWebTunnelProbe) FetchTunnelSecret(ctx context.Context, intent sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
	return p.fetch(ctx, intent)
}

func TestSharedWebTunnelUsesScopedReleaseAndSealsSettings(t *testing.T) {
	for _, mode := range []string{"ready", "capability-error", "wrong-ticket"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			c, p, o, _, account, _, node, wire := credentialControllerFixture(t)
			metadata := wire["metadata"].(map[string]any)
			credentialID := metadata["plan"].(resolver.Plan).Credential.ID
			editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.Binding.Signing, wire, func(n *vaultstore.NodeMetadata, _ *sharedcatalog.CredentialRecord) {
				id, enabled, protocol, noAccount := uuid.NewString(), true, 4, 1
				n.TunnelConfigID, n.TunnelEnabled, n.Protocol, n.CredentialMode, n.CredentialID = &id, &enabled, &protocol, &noAccount, nil
			})
			signSharedPathFixture(t, o.Binding.WorkspaceID, account.Binding.Signing, wire, []resolver.EffectiveCredentialSnapshot{{
				NodeID: node.String(), ProtocolPath: "reveal", SourceKind: "saved", CredentialID: credentialID, Username: "retained-user",
			}})
			addSharedPathProjection(wire, sharedpg.WebConnectionPlanPath, nil)
			const fixtureSettings = `{"ProfileOvpn":"fixture-config","Password":"fixture-tunnel-only"}`
			installSharedTunnelReleaseFixture(t, wire, account, []byte(fixtureSettings))
			metadata["formatVersion"], metadata["credential"] = 4, nil
			wire["formatVersion"] = 5
			accounts := wire["accounts"].([]any)
			wire["accounts"] = accounts[len(accounts)-1:]

			plan, begin, fetch := p.plan, p.begin, p.fetch
			p.plan = func(context.Context, uuid.UUID) (*sharedpg.UnverifiedConnectionPlan, error) {
				return nil, sharedpg.ErrImportedConnectionPins
			}
			p.begin = func(context.Context, uuid.UUID, string) (*sharedpg.UseIntent, error) {
				t.Fatal("a web tunnel requested a general credential ticket")
				return nil, nil
			}
			p.fetch = func(context.Context, sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
				t.Fatal("a web tunnel tried to fetch a general credential graph")
				return nil, nil
			}
			uses, reads := 0, 0
			c.session = &sharedWebTunnelProbe{
				sharedPathProbe: &sharedPathProbe{credentialReleaseProbe: p,
					planPath: func(ctx context.Context, id uuid.UUID, path string) (*sharedpg.UnverifiedConnectionPlan, error) {
						if id != node || path != sharedpg.DefaultConnectionPath {
							t.Fatal("the route broker requested the wrong signed node or path")
						}
						return plan(ctx, id)
					}},
				supported: func() (bool, error) {
					if mode == "capability-error" {
						return false, sharedpg.ErrQuery
					}
					return true, nil
				},
				begin: func(ctx context.Context, id uuid.UUID, source string) (*sharedpg.UseIntent, error) {
					uses++
					intent, err := begin(ctx, id, source)
					intent.Path = sharedpg.WebConnectionPlanPath
					if mode == "wrong-ticket" {
						intent.Path = "ssh"
					}
					return intent, err
				},
				fetch: func(ctx context.Context, i sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
					reads++
					return fetch(ctx, i)
				},
			}
			h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c, fileID: uuid.NewString()}}
			t.Cleanup(func() { _ = h.Close() })
			q, private := sharedSSHRequest(node)
			defer vault.Wipe(private)
			payload := sharedPlanPayload(q)
			raw, err := h.Handle(ctx, "tunnel-plan", vaultInput(t, payload))
			var route vault.TunnelBundleBinding
			if err != nil || json.Unmarshal(raw, &route) != nil || route.Protocol != "https" || uses != 0 || reads != 0 {
				t.Fatal("metadata planning did not verify the scoped web route", err)
			}
			payload["publicKey"] = q.PublicKey
			raw, err = h.Handle(ctx, "tunnel-bundle", vaultInput(t, payload))
			if mode != "ready" {
				if err == nil || len(raw) != 0 || c.Unlocked() || mode == "capability-error" && (uses != 0 || reads != 0) {
					t.Fatal("an unverifiable release issued settings or kept admission", err)
				}
				return
			}
			var bundle localvault.TunnelConnectionBundle
			if err != nil || json.Unmarshal(raw, &bundle) != nil || bundle.Binding != route || uses != 1 || reads != 1 || bytes.Contains(raw, []byte("fixture-tunnel-only")) {
				t.Fatal("the native relay did not return the one audited sealed bundle", err)
			}
			settings, err := vault.OpenTunnelBundle(private, route, bundle.Bundle)
			defer vault.Wipe(settings)
			if err != nil || string(settings) != fixtureSettings {
				t.Fatal("the bound tunnel recipient could not open its settings", err)
			}
		})
	}
}

func TestSharedTunnelNativeSettingsAndProtocolBundles(t *testing.T) {
	for _, protocol := range []int{0, 7, 6} {
		t.Run(strconv.Itoa(protocol), func(t *testing.T) {
			c, p, h, q, private, wire := sharedRoutedFixture(t, protocol)
			count, fetches := 0, 0
			begin, fetch := p.begin, p.fetch
			p.begin = func(ctx context.Context, id uuid.UUID, source string) (*sharedpg.UseIntent, error) {
				count++
				return begin(ctx, id, source)
			}
			p.fetch = func(ctx context.Context, i sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
				fetches++
				return fetch(ctx, i)
			}
			route := sharedRoutedPlan(t, h, q)
			if count != 0 || fetches != 0 {
				t.Fatal("planning released ciphertext")
			}
			planned, err := h.Handle(context.Background(), "tunnel-plan", vaultInput(t, sharedPlanPayload(q)))
			var current vault.TunnelBundleBinding
			if err != nil || json.Unmarshal(planned, &current) != nil || current != route {
				t.Fatal("tunnel plan", err)
			}
			// Settings opening does not decrypt a damaged server password.
			original := wire["accounts"].([]any)[0].(map[string]any)["values"].([]any)[0].([]any)[8]
			corruptSharedCiphertext(t, wire, "primary")
			request := sharedPlanPayload(q)
			request["publicKey"] = q.PublicKey
			raw, err := h.Handle(context.Background(), "tunnel-bundle", vaultInput(t, request))
			var tunnel localvault.TunnelConnectionBundle
			if err != nil || json.Unmarshal(raw, &tunnel) != nil || tunnel.Binding != route {
				t.Fatal("settings handoff", err)
			}
			settings, err := vault.OpenTunnelBundle(private, route, tunnel.Bundle)
			if err != nil || string(settings) != `{"ProfileOvpn":"test-config","Password":"tunnel-secret"}` {
				t.Fatal("settings changed", err)
			}
			vault.Wipe(settings)
			if bytes.Contains(raw, []byte("tunnel-secret")) {
				t.Fatal("settings leaked to relay")
			}
			if _, err := vault.OpenBundle(private, route.BundleBinding, tunnel.Bundle); err == nil {
				t.Fatal("tunnel purpose confusion")
			}
			wire["accounts"].([]any)[0].(map[string]any)["values"].([]any)[0].([]any)[8] = original
			// Protocol opening does not decrypt damaged tunnel settings.
			corruptSharedCiphertext(t, wire, "tunnel")
			endpoint := "127.0.0.1:4321"
			request["route"], request["endpoint"] = route, endpoint
			if protocol != 6 {
				hostRequest := sharedPlanPayload(q)
				hostRequest["route"] = route
				host, err := h.Handle(context.Background(), "ssh-host-plan", vaultInput(t, hostRequest))
				var plan localvault.SSHHostPlan
				if err != nil || json.Unmarshal(host, &plan) != nil || plan.Binding != route.BundleBinding || plan.FileID != route.FileID {
					t.Fatal("routed host plan", err)
				}
			}
			operation := "ssh-route-bundle"
			if protocol == 6 {
				operation = "vnc-route-bundle"
			}
			raw, err = h.Handle(context.Background(), operation, vaultInput(t, request))
			var result localvault.RoutedVNCConnectionBundle
			if err != nil || json.Unmarshal(raw, &result) != nil || result.Binding != route || result.Endpoint != endpoint {
				t.Fatal("routed handoff", err)
			}
			frame, err := vault.OpenRoutedBundle(private, route, endpoint, result.Bundle)
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(frame)
			if protocol == 6 {
				payload, err := vault.DecodeVNCBundle(frame)
				if err != nil || !payload.PasswordProvided || string(payload.Password) != "native-connection-secret" {
					t.Fatal("VNC password", err)
				}
			} else {
				payload, err := vault.DecodeSSHBundle(frame)
				if err != nil || payload.Username != "account" || string(payload.Password) != "native-connection-secret" {
					t.Fatal("SSH password", err)
				}
			}
			if _, err := vault.OpenBundle(private, route.BundleBinding, result.Bundle); err == nil {
				t.Fatal("direct purpose confusion")
			}
			if _, err := vault.OpenRoutedBundle(private, route, "127.0.0.1:4322", result.Bundle); err == nil {
				t.Fatal("endpoint substitution")
			}
			if count != 2 || fetches != 2 || !c.Unlocked() {
				t.Fatal("separate audited releases", count, fetches)
			}
		})
	}
}

func TestSharedRoutedManualVNCPreservesOpaquePassword(t *testing.T) {
	c, p, h, q, private, wire := sharedRoutedFixture(t, 6)
	route := sharedRoutedPlan(t, h, q)
	if err := c.privateKeys.With(func(b []byte) error { vault.Wipe(b); return nil }); err != nil {
		t.Fatal(err)
	}
	corruptSharedCiphertext(t, wire, "primary")
	corruptSharedCiphertext(t, wire, "tunnel")
	begins := 0
	old := p.begin
	p.begin = func(ctx context.Context, id uuid.UUID, source string) (*sharedpg.UseIntent, error) {
		begins++
		return old(ctx, id, source)
	}
	endpoint := "127.0.0.1:4321"
	inner, err := vault.SealManualVNCPassword(q.PublicKey, route.BundleBinding, &route, endpoint, []byte("temporary-password"))
	if err != nil {
		t.Fatal(err)
	}
	payload := sharedPlanPayload(q)
	payload["publicKey"], payload["route"], payload["endpoint"], payload["manual"] = q.PublicKey, route, endpoint, inner
	raw, err := h.Handle(context.Background(), "vnc-manual-route-bundle", vaultInput(t, payload))
	var result localvault.RoutedVNCConnectionBundle
	if err != nil || json.Unmarshal(raw, &result) != nil || result.Binding != route || begins != 1 {
		t.Fatal("manual route handoff", err)
	}
	if bytes.Contains(raw, []byte("temporary-password")) {
		t.Fatal("manual relay leak")
	}
	outer, err := vault.OpenRoutedBundle(private, route, endpoint, result.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(outer)
	envelope, err := vault.DecodeVNCManualAuthorization(outer)
	if err != nil || !bytes.Equal(envelope.Ciphertext, inner.Ciphertext) {
		t.Fatal("inner envelope changed", err)
	}
	plain, err := vault.OpenManualVNCPassword(private, route.BundleBinding, &route, endpoint, envelope)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(plain)
	password, err := vault.DecodeVNCBundle(plain)
	if err != nil || string(password.Password) != "temporary-password" {
		t.Fatal(err)
	}
}

func TestSharedRouteRejectsSubstitutionBeforePrivateOpening(t *testing.T) {
	for _, kind := range []string{"ssh", "vnc", "manual"} {
		for _, mode := range []string{"workspace", "file", "node", "session", "request", "protocol", "host", "port", "epoch", "tunnel", "kind", "row", "configuration", "external", "endpoint", "direct", "name-update", "anchor", "fetch", "cancel"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				protocol := 0
				if kind != "ssh" {
					protocol = 6
				}
				c, p, h, ssh, _, wire := sharedRoutedFixture(t, protocol)
				route := sharedRoutedPlan(t, h, ssh)
				q := localvault.TunnelBundleRequest{NodeID: ssh.NodeID, SessionID: ssh.SessionID, RequestID: ssh.RequestID, Epoch: ssh.Epoch, PublicKey: ssh.PublicKey}
				endpoint := "127.0.0.1:4321"
				fileID := h.shared.fileID
				inner, err := vault.SealManualVNCPassword(q.PublicKey, func() vault.BundleBinding { b := route.BundleBinding; b.Protocol = "vnc"; return b }(), func() *vault.TunnelBundleBinding { r := route; r.Protocol = "vnc"; return &r }(), endpoint, []byte("temporary"))
				if err != nil {
					t.Fatal(err)
				}
				// A wrong route must return Policy, before an unusable private key could
				// cause a cryptographic opening error. Manual release needs no key at all.
				if err := c.privateKeys.With(func(b []byte) error { vault.Wipe(b); return nil }); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				want := error(vault.ErrPolicy)
				failure := errors.New("native route failure")
				switch mode {
				case "workspace":
					route.WorkspaceID = uuid.NewString()
				case "file":
					route.FileID = uuid.NewString()
				case "node":
					route.NodeID = uuid.NewString()
				case "session":
					route.SessionID = uuid.NewString()
				case "request":
					route.RequestID = uuid.NewString()
				case "protocol":
					route.Protocol = "https"
				case "host":
					route.Host = "redirected.example"
				case "port":
					route.Port++
				case "epoch":
					route.Epoch++
				case "tunnel":
					route.TunnelConfigID = uuid.NewString()
				case "kind":
					route.Kind++
				case "row":
					route.RowVersion++
				case "configuration":
					route.ConfigurationVersion++
				case "external":
					route.UseExternalClient = true
				case "endpoint":
					endpoint = "192.0.2.1:4321"
					want = vault.ErrFormat
				case "name-update":
					row := wire["metadata"].(map[string]any)["tunnel"].([]any)
					var r sharedcatalog.TunnelRecord
					if json.Unmarshal([]byte(row[4].(string)), &r) != nil {
						t.Fatal("fixture")
					}
					r.Metadata.Name = "Renamed"
					key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{34}, 32))
					defer vault.Wipe(key)
					seal, e := sharedcatalog.SignSelection(c.trustBinding.WorkspaceID, uuid.MustParse(row[5].(string)), r, 2, vault.KeyRef{ID: uuid.MustParse(row[8].(string)), Version: 1}, key)
					if e != nil {
						t.Fatal(e)
					}
					raw, _ := json.Marshal(r)
					row[4], row[6], row[11] = string(raw), "2", hex.EncodeToString(seal.Signature)
				case "anchor":
					c.catalogAnchor = func(context.Context, string, []byte, sharedpg.TrustBinding, sharedpg.TrustState) error {
						return failure
					}
					want = failure
				case "fetch":
					p.fetch = func(context.Context, sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
						return nil, failure
					}
					want = failure
				case "cancel":
					cancel()
					want = context.Canceled
				}
				var bundle vault.SealedBundle
				if kind == "ssh" {
					var out localvault.RoutedSSHConnectionBundle
					if mode == "direct" {
						value, e := c.SealSSHConnection(ctx, ssh, "ui")
						err = e
						bundle = value.Bundle
					} else {
						out, err = c.SealRoutedSSHConnection(ctx, ssh, route, endpoint, fileID, "ui")
						bundle = out.Bundle
					}
				}
				if kind == "vnc" {
					if mode == "direct" {
						out, e := c.SealVNCConnection(ctx, q, "ui")
						err = e
						bundle = out.Bundle
					} else {
						out, e := c.SealRoutedVNCConnection(ctx, q, route, endpoint, fileID, "ui")
						err = e
						bundle = out.Bundle
					}
				}
				if kind == "manual" {
					if mode == "direct" {
						out, e := c.SealManualVNCConnection(ctx, q, route.BundleBinding, inner, "ui")
						err = e
						bundle = out.Bundle
					} else {
						out, e := c.SealRoutedManualVNCConnection(ctx, q, route, endpoint, fileID, inner, "ui")
						err = e
						bundle = out.Bundle
					}
				}
				if !errors.Is(err, want) || len(bundle.Ciphertext) != 0 || len(bundle.Enc) != 0 {
					t.Fatal("route substitution released credential", err, want)
				}
			})
		}
	}
}

func TestSharedTunnelPlanningAndReleaseFailures(t *testing.T) {
	for _, mode := range []string{"nil-context", "node", "override", "recipient", "source", "file", "settings", "fetch", "anchor"} {
		t.Run(mode, func(t *testing.T) {
			c, p, h, q, _, wire := sharedRoutedFixture(t, 0)
			request := localvault.TunnelBundleRequest{NodeID: q.NodeID, SessionID: q.SessionID, RequestID: q.RequestID, Epoch: q.Epoch, PublicKey: q.PublicKey}
			ctx := context.Background()
			source := "ui"
			fileID := h.shared.fileID
			failure := errors.New("tunnel release failed")
			switch mode {
			case "nil-context":
				ctx = nil
			case "node":
				request.NodeID = "invalid"
			case "override":
				request.CredentialOverride = uuid.NewString()
			case "recipient":
				request.PublicKey = nil
			case "source":
				source = "untrusted"
			case "file":
				fileID = uuid.NewString() + "extra"
			case "settings":
				corruptSharedCiphertext(t, wire, "tunnel")
			case "fetch":
				p.fetch = func(context.Context, sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
					return nil, failure
				}
			case "anchor":
				c.catalogAnchor = func(context.Context, string, []byte, sharedpg.TrustBinding, sharedpg.TrustState) error {
					return failure
				}
			}
			result, err := c.SealConnectionTunnel(ctx, request, fileID, source)
			if err == nil || len(result.Bundle.Ciphertext) != 0 || len(result.Bundle.Enc) != 0 {
				t.Fatal("failed tunnel release exposed packet", err)
			}
		})
	}
	c, _, _, _, _, _, node, _ := credentialControllerFixture(t, vault.Default)
	q, _ := sharedSSHRequest(node)
	request := localvault.TunnelPlanRequest{NodeID: q.NodeID, SessionID: q.SessionID, RequestID: q.RequestID, Epoch: q.Epoch}
	if route, err := c.ResolveConnectionRoute(context.Background(), request, uuid.NewString()); err != nil || route != nil {
		t.Fatal("authenticated direct planning", err)
	}
	if _, err := c.PlanConnectionTunnel(context.Background(), request, uuid.NewString()); err != vaultstore.ErrMissing {
		t.Fatal("direct tunnel plan", err)
	}
	if _, err := c.ResolveConnectionRoute(nil, request, uuid.NewString()); err != vault.ErrFormat {
		t.Fatal(err)
	}
	bad := request
	bad.CredentialOverride = uuid.NewString()
	if _, err := c.ResolveConnectionRoute(context.Background(), bad, uuid.NewString()); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	bad = request
	bad.NodeID = "bad"
	if _, err := c.PlanConnectionTunnel(context.Background(), bad, uuid.NewString()); err != vault.ErrFormat {
		t.Fatal(err)
	}
	// No tunnel settings can be sealed for a current direct connection.
	if out, err := c.SealConnectionTunnel(context.Background(), localvault.TunnelBundleRequest{NodeID: q.NodeID, SessionID: q.SessionID, RequestID: q.RequestID, Epoch: q.Epoch, PublicKey: q.PublicKey}, uuid.NewString(), "ui"); err != vault.ErrPolicy || len(out.Bundle.Ciphertext) != 0 {
		t.Fatal("direct tunnel release", err)
	}
}

func TestSharedTunnelBindingSupportsProtocolsAndBounds(t *testing.T) {
	_, _, h, q, _, wire := sharedRoutedFixture(t, 0)
	plan := wire["metadata"].(map[string]any)["plan"].(resolver.Plan)
	tmeta := &sharedpg.ResolvedTunnel{Metadata: vaultstore.TunnelMetadata{ID: plan.TunnelID, Name: "VPN", Kind: 1}, Boundary: uuid.New(), RowVersion: 2, ConfigurationVersion: 1}
	request := localvault.TunnelPlanRequest{NodeID: q.NodeID, SessionID: q.SessionID, RequestID: q.RequestID, Epoch: q.Epoch}
	for protocol, name := range map[int]string{0: "ssh", 1: "rdp", 3: "http", 4: "https", 6: "vnc", 7: "sftp"} {
		p := plan
		p.Protocol = protocol
		b, err := sharedTunnelBinding(h.shared.controller.trustBinding.WorkspaceID, h.shared.fileID, p, request, tmeta)
		if err != nil || b.Protocol != name {
			t.Fatal("protocol mapping", protocol, err)
		}
	}
	for _, mode := range []string{"file", "workspace", "request", "node", "missing", "tunnel", "metadata", "boundary", "row-zero", "row-large", "configuration-zero", "configuration-ahead", "protocol", "host", "port", "external"} {
		p, q, tunnel, file, workspace := plan, request, *tmeta, h.shared.fileID, h.shared.controller.trustBinding.WorkspaceID
		ptr := &tunnel
		switch mode {
		case "file":
			file = "bad"
		case "workspace":
			workspace = uuid.Nil
		case "request":
			q.Epoch = 0
		case "node":
			p.NodeID = uuid.NewString()
		case "missing":
			ptr = nil
		case "tunnel":
			p.TunnelID = uuid.NewString()
		case "metadata":
			tunnel.Metadata.Kind = 10
		case "boundary":
			tunnel.Boundary = uuid.Nil
		case "row-zero":
			tunnel.RowVersion = 0
		case "row-large":
			tunnel.RowVersion = math.MaxInt64 + 1
		case "configuration-zero":
			tunnel.ConfigurationVersion = 0
		case "configuration-ahead":
			tunnel.ConfigurationVersion = 3
		case "protocol":
			p.Protocol = 2
		case "host":
			p.Host = "bad host"
		case "port":
			p.Port = 0
		case "external":
			p.ExternalRDPClient = true
		}
		if _, err := sharedTunnelBinding(workspace, file, p, q, ptr); err != vault.ErrPolicy {
			t.Fatal(mode, err)
		}
	}
}

func TestSharedRouteHandlersValidateNativeOnlyInputs(t *testing.T) {
	for _, operation := range []string{"tunnel-plan", "tunnel-bundle", "ssh-route-bundle", "vnc-route-bundle", "vnc-manual-route-bundle"} {
		for _, mode := range []string{"malformed", "extra-file", "epoch", "node"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				_, _, h, q, _, _ := sharedRoutedFixture(t, func() int {
					if operation == "vnc-route-bundle" || operation == "vnc-manual-route-bundle" {
						return 6
					}
					return 0
				}())
				payload := sharedPlanPayload(q)
				payload["publicKey"] = q.PublicKey
				if operation == "tunnel-plan" {
					delete(payload, "publicKey")
				}
				route := sharedRoutedPlan(t, h, q)
				if operation == "ssh-route-bundle" || operation == "vnc-route-bundle" || operation == "vnc-manual-route-bundle" {
					payload["route"], payload["endpoint"] = route, "127.0.0.1:4321"
				}
				if operation == "vnc-manual-route-bundle" {
					inner, err := vault.SealManualVNCPassword(q.PublicKey, route.BundleBinding, &route, "127.0.0.1:4321", nil)
					if err != nil {
						t.Fatal(err)
					}
					payload["manual"] = inner
				}
				var raw []byte
				switch mode {
				case "malformed":
					raw = []byte("{")
				case "extra-file":
					payload["fileId"] = uuid.NewString()
				case "epoch":
					payload["epoch"] = "01"
				case "node":
					payload["nodeId"] = "bad"
				}
				if raw == nil {
					raw = vaultInput(t, payload)
				}
				if result, err := h.Handle(context.Background(), operation, raw); !errors.Is(err, vaultwire.ErrProtocol) || len(result) != 0 {
					t.Fatal("invalid main request", err)
				}
			})
		}
	}
}
