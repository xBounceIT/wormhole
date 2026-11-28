package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Change the authenticated metadata, rather than patching the resolved plan a
// malicious database would like the client to trust. Both paths use this graph.
func editSharedConnectionFixture(t *testing.T, workspace uuid.UUID, signing vault.KeyRef, wire map[string]any, edit func(*vaultstore.NodeMetadata, *sharedcatalog.CredentialRecord), privateKeys ...ed25519.PrivateKey) {
	t.Helper()
	metadata := wire["metadata"].(map[string]any)
	row := metadata["chain"].([]any)[0].([]any)
	credential := metadata["credential"].([]any)
	var n vaultstore.NodeMetadata
	var c sharedcatalog.CredentialRecord
	if json.Unmarshal([]byte(row[4].(string)), &n) != nil || json.Unmarshal([]byte(credential[4].(string)), &c) != nil {
		t.Fatal("fixture metadata")
	}
	edit(&n, &c)
	key := sharedFixtureSigningKey(privateKeys...)
	defer vault.Wipe(key)
	for i, r := range [][]any{row, credential} {
		rev, _ := strconv.ParseUint(r[6].(string), 10, 64)
		rev++
		var seal vault.RecordSeal
		var err error
		var body []byte
		if i == 0 {
			seal, err = sharedcatalog.SignNode(workspace, uuid.MustParse(r[5].(string)), n, rev, signing, key)
			body, _ = json.Marshal(n)
		} else {
			seal, err = sharedcatalog.SignCredential(workspace, uuid.MustParse(r[5].(string)), c, rev, signing, key)
			body, _ = json.Marshal(c)
		}
		if err != nil {
			t.Fatal(err)
		}
		r[4], r[6], r[11] = string(body), strconv.FormatUint(rev, 10), hex.EncodeToString(seal.Signature)
	}
	p, err := resolver.Resolve([]vaultstore.NodeMetadata{n}, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.Credential.Kind == "saved" || p.Credential.Kind == "override" {
		p, err = resolver.ApplyCredential(p, c.Metadata)
		if err != nil {
			t.Fatal(err)
		}
	}
	metadata["plan"] = p
}

func sharedSSHRequest(node uuid.UUID) (localvault.SSHBundleRequest, []byte) {
	private := bytes.Repeat([]byte{51}, 32)
	key, _ := ecdh.X25519().NewPrivateKey(private)
	return localvault.SSHBundleRequest{NodeID: node.String(), SessionID: uuid.NewString(), RequestID: uuid.NewString(), Epoch: 7, PublicKey: key.PublicKey().Bytes()}, private
}

func sharedPlanPayload(q localvault.SSHBundleRequest) map[string]any {
	return map[string]any{"nodeId": q.NodeID, "credentialOverride": q.CredentialOverride, "sessionId": q.SessionID, "requestId": q.RequestID, "epoch": strconv.FormatUint(q.Epoch, 10)}
}

func TestSharedConnectionPlanCommitAndNoSecretAccess(t *testing.T) {
	c, p, o, root, account, _, node, wire := credentialControllerFixture(t)
	initial := c.trustRevision
	p.begin = func(context.Context, uuid.UUID, string) (*sharedpg.UseIntent, error) {
		t.Fatal("planning issued a Use ticket")
		return nil, nil
	}
	p.fetch = func(context.Context, sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
		t.Fatal("planning requested ciphertext")
		return nil, nil
	}
	// Public planning works even without usable private key material.
	if err := c.privateKeys.With(func(b []byte) error { vault.Wipe(b); return nil }); err != nil {
		t.Fatal(err)
	}
	plan, err := c.PlanConnection(context.Background(), node)
	if err != nil || plan.Plan.Host != "server.example" || plan.Plan.Username != "account" || len(plan.Revision) != 64 {
		t.Fatal(plan, err)
	}
	stored, err := readSharedTrustFile(o.TrustPath, root, o.Binding, initial+1)
	if err != nil || stored.Revision != c.trustRevision || stored.Catalog["node/"+node.String()].Revision != 1 {
		t.Fatal("plan escaped before durable trust", err)
	}
	again, err := c.PlanConnection(context.Background(), node)
	if err != nil || !reflect.DeepEqual(again, plan) || c.trustRevision != initial+1 {
		t.Fatal("unstable planning", err)
	}
	editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, _ *sharedcatalog.CredentialRecord) { n.Name = "Renamed" })
	again, err = c.PlanConnection(context.Background(), node)
	if err != nil || again.Revision == plan.Revision || again.Plan.Host != plan.Plan.Host {
		t.Fatal("host confirmation did not bind all signed inputs", err)
	}
}

func TestSharedConnectionPlanErrorsRetireAndReturnNoPlan(t *testing.T) {
	for _, mode := range []string{"query", "nil", "signature", "anchor", "cancel", "closed"} {
		t.Run(mode, func(t *testing.T) {
			c, p, _, _, _, _, node, wire := credentialControllerFixture(t)
			ctx := context.Background()
			failure := errors.New("planning fixture error")
			switch mode {
			case "query":
				p.plan = func(context.Context, uuid.UUID) (*sharedpg.UnverifiedConnectionPlan, error) { return nil, failure }
			case "nil":
				p.plan = func(context.Context, uuid.UUID) (*sharedpg.UnverifiedConnectionPlan, error) { return nil, nil }
			case "signature":
				wire["metadata"].(map[string]any)["chain"].([]any)[0].([]any)[11] = hex.EncodeToString(make([]byte, 64))
			case "anchor":
				c.catalogAnchor = func(context.Context, string, []byte, sharedpg.TrustBinding, sharedpg.TrustState) error {
					return failure
				}
			case "cancel":
				old := p.plan
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				p.plan = func(ctx context.Context, id uuid.UUID) (*sharedpg.UnverifiedConnectionPlan, error) {
					result, err := old(ctx, id)
					cancel()
					return result, err
				}
			case "closed":
				if err := c.Close(ctx); err != nil {
					t.Fatal(err)
				}
			}
			plan, err := c.PlanConnection(ctx, node)
			if err == nil || !reflect.DeepEqual(plan, sharedpg.ResolvedConnectionPlan{}) || c.Unlocked() || c.privateKeys != nil {
				t.Fatal("failed planning retained result/keys", plan, err)
			}
		})
	}
	c, p, _, _, _, _, node, _ := credentialControllerFixture(t)
	if _, err := c.PlanConnection(nil, node); err != sharedpg.ErrConfiguration {
		t.Fatal(err)
	}
	if _, err := c.PlanConnection(context.Background(), uuid.Nil); err != sharedpg.ErrConfiguration {
		t.Fatal(err)
	}
	c.session = p.catalogProbe
	if _, err := c.PlanConnection(context.Background(), node); err != sharedpg.ErrConfiguration {
		t.Fatal(err)
	}
}

func TestSharedConnectionPlanCloseCancelsRead(t *testing.T) {
	c, p, _, _, _, _, node, _ := credentialControllerFixture(t)
	entered, finished := make(chan struct{}), make(chan error, 1)
	p.plan = func(ctx context.Context, _ uuid.UUID) (*sharedpg.UnverifiedConnectionPlan, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	go func() { _, err := c.PlanConnection(context.Background(), node); finished <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("planning did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if err != context.Canceled {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("close retained planning")
	}
}

// Public planning needs a complete signed tunnel record, even while the native
// shared route handoff is deliberately unavailable. It fetches no settings.
func installSharedTunnelPlanFixture(t *testing.T, workspace uuid.UUID, signing vault.KeyRef, wire map[string]any, privateKeys ...ed25519.PrivateKey) {
	t.Helper()
	metadata := wire["metadata"].(map[string]any)
	p := metadata["plan"].(resolver.Plan)
	row := append([]any{}, metadata["chain"].([]any)[0].([]any)...)
	record := sharedcatalog.TunnelRecord{Metadata: vaultstore.TunnelMetadata{ID: p.TunnelID, Name: "VPN", Kind: 1}, ConfigurationVersion: 1}
	key := sharedFixtureSigningKey(privateKeys...)
	defer vault.Wipe(key)
	seal, err := sharedcatalog.SignSelection(workspace, uuid.MustParse(row[5].(string)), record, 1, signing, key)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	row[1], row[4], row[6], row[11] = p.TunnelID, string(body), "1", hex.EncodeToString(seal.Signature)
	metadata["formatVersion"], metadata["tunnel"] = 2, row
	if len(row) == 24 {
		metadata["formatVersion"] = 3
	}
}

func TestSharedConnectionPlanningNeverDowngradesATunnel(t *testing.T) {
	for _, operation := range []string{"connection-route", "ssh-host-plan"} {
		for _, material := range []string{"signed", "missing"} {
			t.Run(operation+"/"+material, func(t *testing.T) {
				c, p, o, root, account, _, node, wire := credentialControllerFixture(t)
				editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, _ *sharedcatalog.CredentialRecord) {
					enabled, id := true, uuid.NewString()
					n.TunnelEnabled, n.TunnelConfigID = &enabled, &id
				})
				if material == "signed" {
					installSharedTunnelPlanFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire)
				}
				p.begin = func(context.Context, uuid.UUID, string) (*sharedpg.UseIntent, error) {
					t.Fatal("planning issued ticket")
					return nil, nil
				}
				p.fetch = func(context.Context, sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
					t.Fatal("planning fetched ciphertext")
					return nil, nil
				}
				q, _ := sharedSSHRequest(node)
				payload := sharedPlanPayload(q)
				if operation == "ssh-host-plan" {
					payload["route"] = nil
				}
				h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c, fileID: uuid.NewString()}}
				raw, _ := json.Marshal(payload)
				result, err := h.Handle(context.Background(), operation, raw)
				if material == "signed" {
					if operation == "connection-route" {
						var route vault.TunnelBundleBinding
						id := wire["metadata"].(map[string]any)["plan"].(resolver.Plan).TunnelID
						if err != nil || json.Unmarshal(result, &route) != nil || route.TunnelConfigID != id || route.FileID != h.shared.fileID || route.NodeID != q.NodeID || route.SessionID != q.SessionID || route.RequestID != q.RequestID || route.Epoch != q.Epoch || route.Protocol != "ssh" || route.ConfigurationVersion != 1 || route.Host != "server.example" {
							t.Fatal("tunnel did not yield authenticated route", err)
						}
					} else if err != vault.ErrPolicy || len(result) != 0 {
						t.Fatal("routed host request became direct", err)
					}
					if !c.Unlocked() {
						t.Fatal("valid route plan retired admission")
					}
					stored, e := readSharedTrustFile(o.TrustPath, root, o.Binding, c.trustRevision)
					id := wire["metadata"].(map[string]any)["plan"].(resolver.Plan).TunnelID
					if e != nil || stored.Catalog["tunnel/"+id].Revision != 1 {
						t.Fatal("signed tunnel observations not committed", e)
					}
				} else {
					if len(result) != 0 || !errors.Is(err, sharedpg.ErrAdmissionResponse) || !errors.Is(err, vaultwire.ErrRetired) || c.Unlocked() {
						t.Fatal("incomplete tunnel did not retire", err)
					}
				}
			})
		}
	}
}

func TestSharedSSHNativeHandlerSealedRoundTrip(t *testing.T) {
	for _, mode := range []string{"ssh", "sftp", "sftp-only"} {
		t.Run(mode, func(t *testing.T) {
			c, p, o, root, account, _, node, wire := credentialControllerFixture(t)
			pin := "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
			editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, _ *sharedcatalog.CredentialRecord) {
				n.SshKnownHostFingerprint = &pin
				auto := true
				n.SshAutoSudo = &auto
				if mode == "sftp" {
					protocol := 7
					n.Protocol = &protocol
				}
			})
			q, private := sharedSSHRequest(node)
			q.SFTPOnly = mode == "sftp-only"
			defer vault.Wipe(private)
			h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c, fileID: uuid.NewString()}}
			begins, fetches := 0, 0
			oldBegin, oldFetch := p.begin, p.fetch
			p.begin = func(ctx context.Context, n uuid.UUID, s string) (*sharedpg.UseIntent, error) {
				begins++
				return oldBegin(ctx, n, s)
			}
			p.fetch = func(ctx context.Context, i sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
				fetches++
				return oldFetch(ctx, i)
			}
			raw, _ := json.Marshal(sharedPlanPayload(q))
			route, err := h.Handle(context.Background(), "connection-route", raw)
			if err != nil || string(route) != "null" {
				t.Fatal("direct route", string(route), err)
			}
			hostRequest := sharedPlanPayload(q)
			hostRequest["route"] = nil
			raw, _ = json.Marshal(hostRequest)
			hostRaw, err := h.Handle(context.Background(), "ssh-host-plan", raw)
			var host localvault.SSHHostPlan
			if err != nil || json.Unmarshal(hostRaw, &host) != nil || host.Fingerprint != pin || len(host.Revision) != 64 || host.FileID != h.shared.fileID || host.Binding.Epoch != 7 || host.Binding.Protocol != resolver.DefaultPath(map[string]int{"ssh": 0, "sftp": 7, "sftp-only": 0}[mode]) {
				t.Fatal("host plan", host, err)
			}
			if begins != 0 || fetches != 0 {
				t.Fatal("metadata requested release")
			}
			bundleRequest := sharedPlanPayload(q)
			bundleRequest["sftpOnly"] = q.SFTPOnly
			bundleRequest["publicKey"] = q.PublicKey
			raw, _ = json.Marshal(bundleRequest)
			response, err := h.Handle(context.Background(), "ssh-bundle", raw)
			if err != nil || begins != 1 || fetches != 1 {
				t.Fatal("audited sealing", err, begins, fetches)
			}
			if bytes.Contains(response, []byte("native-connection-secret")) || bytes.Contains(response, []byte(base64.StdEncoding.EncodeToString([]byte("native-connection-secret")))) {
				t.Fatal("plaintext in relay")
			}
			var result localvault.SSHConnectionBundle
			if json.Unmarshal(response, &result) != nil || result.Binding != host.Binding || result.SFTPOnly != q.SFTPOnly {
				t.Fatal("binding")
			}
			plain, err := vault.OpenBundle(private, result.Binding, result.Bundle)
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(plain)
			decoded, err := vault.DecodeSSHBundle(plain)
			if err != nil || string(decoded.Password) != "native-connection-secret" || decoded.Username != "account" || decoded.Fingerprint != pin || decoded.SFTPOnly != q.SFTPOnly || decoded.AutoSudo != (mode == "ssh") {
				t.Fatal("sealed recipient payload", err)
			}
			if _, err = readSharedTrustFile(o.TrustPath, root, o.Binding, c.trustRevision); err != nil {
				t.Fatal("missing committed observations", err)
			}
		})
	}
}

func TestSharedSSHReleaseRejectsChangedOrUnsupportedPlanBeforeOpening(t *testing.T) {
	for _, mode := range []string{"unpinned", "vnc", "tunnel", "username", "host", "provider"} {
		t.Run(mode, func(t *testing.T) {
			c, _, o, _, account, _, node, wire := credentialControllerFixture(t)
			pin := "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
			editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, credential *sharedcatalog.CredentialRecord) {
				n.SshKnownHostFingerprint = &pin
			})
			if _, err := c.PlanConnection(context.Background(), node); err != nil {
				t.Fatal(err)
			}
			editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, credential *sharedcatalog.CredentialRecord) {
				switch mode {
				case "unpinned":
					n.SshKnownHostFingerprint = nil
				case "invalid-pin":
					invalid := "untrusted"
					n.SshKnownHostFingerprint = &invalid
				case "vnc":
					protocol := 6
					n.Protocol = &protocol
					credential.Metadata.Protocol = "vnc"
				case "tunnel":
					enabled, id := true, uuid.NewString()
					n.TunnelEnabled = &enabled
					n.TunnelConfigID = &id
				case "username":
					credential.Metadata.Username = "account\nredirect"
				case "host":
					host := "server.example injected"
					n.Host = &host
				case "provider":
					credential.Metadata.Provider = "bitwarden"
					credential.Metadata.BitwardenItemID = "item"
					credential.Fields = nil
				}
			})
			// Policy checks must win over a private decryption failure. Provider
			// selection is checked after opening, and is separately denied below.
			if mode != "provider" {
				if err := c.privateKeys.With(func(b []byte) error { vault.Wipe(b[:32]); return nil }); err != nil {
					t.Fatal(err)
				}
			}
			q, private := sharedSSHRequest(node)
			defer vault.Wipe(private)
			result, err := c.SealSSHConnection(context.Background(), q, "ui")
			if err == nil || !reflect.DeepEqual(result, localvault.SSHConnectionBundle{}) || c.Unlocked() {
				t.Fatal("unsafe plan released", err)
			}
			if mode != "provider" && mode != "tunnel" && !errors.Is(err, vault.ErrPolicy) {
				t.Fatal("private use preceded native policy", err)
			}
		})
	}
}

func TestSharedSSHBindingBounds(t *testing.T) {
	q, _ := sharedSSHRequest(uuid.New())
	request := localvault.TunnelPlanRequest{NodeID: q.NodeID, SessionID: q.SessionID, RequestID: q.RequestID, Epoch: q.Epoch}
	valid := resolver.Plan{NodeID: q.NodeID, Protocol: 0, Host: "server.example", Port: 22}
	for _, mode := range []string{"request", "override", "node", "protocol", "tunnel", "low-port", "high-port", "empty-host", "long-host", "space", "control"} {
		t.Run(mode, func(t *testing.T) {
			p, r := valid, request
			switch mode {
			case "request":
				r.RequestID = ""
			case "override":
				r.CredentialOverride = uuid.NewString()
			case "node":
				p.NodeID = uuid.NewString()
			case "protocol":
				p.Protocol = 1
			case "tunnel":
				p.TunnelID = uuid.NewString()
			case "low-port":
				p.Port = 0
			case "high-port":
				p.Port = 65536
			case "empty-host":
				p.Host = ""
			case "long-host":
				p.Host = strings.Repeat("x", vault.MaxContextBytes+1)
			case "space":
				p.Host = "host\u00a0name"
			case "control":
				p.Host = "host\x00name"
			}
			b, err := sharedSSHBinding(uuid.New(), p, r)
			if err != vault.ErrPolicy || b != (vault.BundleBinding{}) {
				t.Fatal(b, err)
			}
		})
	}
}

func TestSharedSSHMalformedAndClosedRequests(t *testing.T) {
	for _, mode := range []string{"nil-context", "recipient", "override", "source", "closed"} {
		t.Run(mode, func(t *testing.T) {
			c, _, _, _, _, _, node, _ := credentialControllerFixture(t)
			q, private := sharedSSHRequest(node)
			defer vault.Wipe(private)
			ctx := context.Background()
			source := "ui"
			switch mode {
			case "nil-context":
				ctx = nil
			case "recipient":
				q.PublicKey = nil
			case "override":
				q.CredentialOverride = uuid.NewString()
			case "source":
				source = "renderer"
			case "closed":
				if err := c.Close(ctx); err != nil {
					t.Fatal(err)
				}
			}
			result, err := c.SealSSHConnection(ctx, q, source)
			if err == nil || !reflect.DeepEqual(result, localvault.SSHConnectionBundle{}) {
				t.Fatal(err)
			}
		})
	}
}

func TestSharedSSHSealingFailuresRetireWithoutOutput(t *testing.T) {
	for _, mode := range []string{"no-account", "no-password", "recipient", "cipher"} {
		t.Run(mode, func(t *testing.T) {
			c, _, o, _, account, _, node, wire := credentialControllerFixture(t)
			pin := "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
			editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, credential *sharedcatalog.CredentialRecord) {
				n.SshKnownHostFingerprint = &pin
				if mode == "no-password" {
					credential.Fields[0].Present = false
				}
				if mode == "no-account" {
					none, username := 1, "account"
					n.CredentialMode, n.CredentialID, n.Username = &none, nil, &username
				}
			})
			if mode == "no-password" {
				section := wire["accounts"].([]any)[0].(map[string]any)
				section["values"], section["copies"], wire["roots"] = []any{}, []any{}, []any{}
			}
			if mode == "no-account" {
				wire["metadata"].(map[string]any)["credential"] = nil
				wire["accounts"], wire["roots"] = []any{}, []any{}
			}
			if mode == "cipher" {
				if err := c.privateKeys.With(func(b []byte) error { vault.Wipe(b[:32]); return nil }); err != nil {
					t.Fatal(err)
				}
			}
			q, private := sharedSSHRequest(node)
			defer vault.Wipe(private)
			if mode == "recipient" {
				q.PublicKey = make([]byte, 32)
			}
			result, err := c.SealSSHConnection(context.Background(), q, "ui")
			if err == nil || !reflect.DeepEqual(result, localvault.SSHConnectionBundle{}) || c.Unlocked() || c.privateKeys != nil {
				t.Fatal("failed sealer retained output/keys", err)
			}
		})
	}
}

func TestSharedProtocolAdmissionAndHostRestrictions(t *testing.T) {
	for _, mode := range []string{"no-shared", "no-controller", "closed", "nil-context", "stronger-profile", "file-id", "host-route", "host-override", "route-override", "host-trust", "tunnel-plan", "malformed-host", "malformed-route", "malformed-bundle", "bad-epoch-host", "bad-epoch-bundle"} {
		t.Run(mode, func(t *testing.T) {
			c, _, _, _, _, _, node, _ := credentialControllerFixture(t)
			h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c, fileID: uuid.NewString()}}
			q, _ := sharedSSHRequest(node)
			value := sharedPlanPayload(q)
			value["route"] = nil
			op := "ssh-host-plan"
			ctx := context.Background()
			direct := false
			switch mode {
			case "no-shared":
				h.shared = nil
				direct = true
			case "no-controller":
				h.shared.controller = nil
				direct = true
			case "closed":
				h.closed = true
				direct = true
			case "nil-context":
				ctx = nil
				direct = true
			case "stronger-profile":
				c.runtimeProfile = vault.Paranoid
				direct = true
			case "file-id":
				h.shared.fileID = "invalid"
			case "host-route":
				value["route"] = map[string]any{}
			case "host-override":
				value["credentialOverride"] = uuid.NewString()
			case "route-override":
				op = "connection-route"
				delete(value, "route")
				value["credentialOverride"] = uuid.NewString()
			case "host-trust":
				op = "ssh-host-trust"
			case "tunnel-plan":
				op = "tunnel-plan"
			case "bad-epoch-host":
				value["epoch"] = "01"
			case "bad-epoch-bundle":
				op = "ssh-bundle"
				delete(value, "route")
				value["epoch"] = "01"
				value["publicKey"] = q.PublicKey
			case "malformed-bundle":
				op = "ssh-bundle"
				value = map[string]any{}
			case "malformed-route":
				op = "connection-route"
				value = map[string]any{}
			case "malformed-host":
				value = map[string]any{}
			}
			var result json.RawMessage
			var err error
			if direct {
				_, err = h.sharedProtocolController(ctx)
			} else {
				raw, _ := json.Marshal(value)
				result, err = h.Handle(ctx, op, raw)
			}
			if err == nil || len(result) != 0 {
				t.Fatal("invalid shared operation accepted", err)
			}
			if mode == "stronger-profile" {
				if !h.closed {
					t.Fatal("stronger profile did not retire service")
				}
				// Serve closes retired handlers before returning control.
				if e := h.Close(); e != nil || c.Unlocked() || c.privateKeys != nil {
					t.Fatal("retired service retained owner", e)
				}
			}
			if mode == "host-trust" && !errors.Is(err, vaultwire.ErrProtocol) {
				t.Fatal("shared write was admitted", err)
			}
		})
	}
}

func TestSharedProtocolFloorRequiresReadmissionForStandard(t *testing.T) {
	for _, tc := range []struct {
		admitted, floor vault.Profile
		want            error
	}{
		{vault.Default, vault.Default, nil},
		{vault.Standard, vault.Default, nil},
		{vault.Standard, vault.Standard, nil},
		{vault.Default, vault.Standard, sharedpg.ErrProfileChanged},
		{vault.Default, vault.Hardened, errSharedRuntimeUnsupported},
		{vault.Standard, vault.Paranoid, errSharedRuntimeUnsupported},
		{vault.Default, "", errSharedRuntimeUnsupported},
		{"", vault.Default, errSharedRuntimeUnsupported},
	} {
		if err := sharedProtocolFloor(tc.admitted, tc.floor); err != tc.want {
			t.Fatalf("admitted %q, floor %q: %v", tc.admitted, tc.floor, err)
		}
	}
}

func sharedFixtureSigningKey(keys ...ed25519.PrivateKey) ed25519.PrivateKey {
	if len(keys) == 1 {
		return bytes.Clone(keys[0])
	}
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{34}, 32))
}
