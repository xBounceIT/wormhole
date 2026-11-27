package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func sshManualHandlerFixture(t *testing.T, mode string, routed, sftpOnly bool) (*vaultFoundationHandler, map[string]any, localvault.SSHManualPlan, *vault.TunnelBundleBinding) {
	t.Helper()
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	protocol, port, host, pin, user := 0, 22, "manual.example", sealedSSHFixturePayload().Fingerprint, "stored-user"
	autoSudo := true
	n := vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Manual SSH", Kind: 1, Protocol: &protocol, Host: &host, Port: &port, SshKnownHostFingerprint: &pin, Username: &user, SshAutoSudo: &autoSudo}
	if mode == "passphrase" {
		c, err := h.owner.PutCredential(ctx, vaultstore.CredentialMetadata{ID: uuid.NewString(), Name: "Selected key", Protocol: "ssh", Kind: "sshKey", Provider: "local", Username: user}, []localvault.SecretChange{{Field: "privateKey", Value: []byte("selected-key")}, {Field: "passphrase", Value: []byte("must-never-read-stored-passphrase")}}, 0)
		if err != nil {
			t.Fatal(err)
		}
		choice := 2
		n.CredentialMode = &choice
		n.CredentialID = &c.ID
	}
	if routed {
		tunnel, err := h.owner.PutTunnel(ctx, vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "VPN", Kind: 6}, []byte(`{"Host":"gateway","Username":"u","Password":"route-password"}`), 0)
		if err != nil {
			t.Fatal(err)
		}
		enabled := true
		n.TunnelEnabled = &enabled
		n.TunnelConfigID = &tunnel.ID
	}
	if _, err := h.owner.PutNode(ctx, n, nil, 0); err != nil {
		t.Fatal(err)
	}
	request := localvault.TunnelPlanRequest{NodeID: n.ID, SessionID: uuid.NewString(), RequestID: uuid.NewString(), Epoch: 1}
	route, err := h.owner.ResolveConnectionRoute(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	q := map[string]any{"nodeId": n.ID, "credentialOverride": "", "sessionId": request.SessionID, "requestId": request.RequestID, "epoch": "1", "mode": mode, "sftpOnly": sftpOnly, "route": route}
	raw, err := h.Handle(ctx, "ssh-manual-plan", vaultInput(t, q))
	if err != nil {
		t.Fatal(err)
	}
	var plan localvault.SSHManualPlan
	if json.Unmarshal(raw, &plan) != nil {
		t.Fatal("invalid plan")
	}
	return h, q, plan, route
}

func TestVaultSSHManualHandlerAndNativeRecipient(t *testing.T) {
	for _, mode := range []string{"account", "passphrase"} {
		for _, routed := range []bool{false, true} {
			for _, sftpOnly := range []bool{false, true} {
				h, q, plan, route := sshManualHandlerFixture(t, mode, routed, sftpOnly)
				endpoint := ""
				if routed {
					endpoint = "127.0.0.1:2345"
				}
				entered := make(chan struct{})
				child := startSealedSSHModeTestChild(t, func(ctx context.Context, target sshTarget, columns, rows uint16) (*sshNativeSession, string, error) {
					if target.host != plan.Host.Binding.Host || target.socksEndpoint != endpoint || target.knownHostFingerprint != plan.Host.Fingerprint || target.sftpOnly != sftpOnly || target.autoSudo != !sftpOnly || columns != 80 || rows != 24 {
						t.Error("native manual target changed")
					}
					if mode == "account" {
						if target.username != "temporary-user" || target.password != "temporary-password" || len(target.privateKey) != 0 {
							t.Error("manual account changed")
						}
					} else {
						if target.username != "stored-user" || string(target.privateKey) != "selected-key" || target.keyPassphrase != "" || target.password != "" {
							t.Error("empty override fell back to saved account")
						}
					}
					close(entered)
					<-ctx.Done()
					return nil, "", ctx.Err()
				}, mode)
				c := vault.SSHManualContext{Binding: plan.Host.Binding, Route: route, Endpoint: endpoint, Mode: mode, FileID: plan.Host.FileID, Revision: plan.Host.Revision, Fingerprint: plan.Host.Fingerprint, AutoSudo: plan.AutoSudo, SFTPOnly: plan.SFTPOnly}
				p := vault.SSHBundlePayload{Username: "temporary-user", Password: []byte("temporary-password"), Fingerprint: c.Fingerprint}
				if mode == "passphrase" {
					p = vault.SSHBundlePayload{}
				}
				inner, err := vault.SealManualSSHCredentials(child.public, c, p)
				if err != nil {
					t.Fatal(err)
				}
				q["publicKey"], q["expected"], q["manual"], q["endpoint"] = child.public, plan, inner, endpoint
				raw, err := h.Handle(context.Background(), "ssh-manual-bundle", vaultInput(t, q))
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(raw, []byte("temporary-password")) || bytes.Contains(raw, []byte("selected-key")) {
					t.Fatal("secret in native relay")
				}
				var response map[string]any
				if json.Unmarshal(raw, &response) != nil {
					t.Fatal("invalid response")
				}
				response["columns"], response["rows"] = 80, 24
				child.send(t, vaultInput(t, response))
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("manual native dial missing")
				}
				child.send(t, vaultInput(t, map[string]any{"type": "app-lock", "sessionId": plan.Host.Binding.SessionID}))
				if err = child.wait(t); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestVaultSSHManualHandlerRejectsPrivateAndMalformedIntent(t *testing.T) {
	h, planInput, plan, _ := sshManualHandlerFixture(t, "account", false, false)
	ctx := context.Background()
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	c := vault.SSHManualContext{Binding: plan.Host.Binding, Mode: "account", FileID: plan.Host.FileID, Revision: plan.Host.Revision, Fingerprint: plan.Host.Fingerprint, AutoSudo: plan.AutoSudo}
	inner, err := vault.SealManualSSHCredentials(key.PublicKey().Bytes(), c, vault.SSHBundlePayload{Username: "u", Password: []byte("temporary"), Fingerprint: c.Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	q := cloneSFTPPacket(planInput)
	q["publicKey"], q["expected"], q["manual"], q["endpoint"] = key.PublicKey().Bytes(), plan, inner, ""
	for _, operation := range []string{"ssh-manual-plan", "ssh-manual-bundle"} {
		input := planInput
		if operation == "ssh-manual-bundle" {
			input = q
		}
		for field := range input {
			bad := cloneSFTPPacket(input)
			delete(bad, field)
			if _, err = h.Handle(ctx, operation, vaultInput(t, bad)); err == nil {
				t.Fatal("missing field", field)
			}
		}
		for _, field := range []string{"username", "password", "keyPassphrase", "host", "publicKeyOverride"} {
			bad := cloneSFTPPacket(input)
			bad[field] = "private"
			if _, err = h.Handle(ctx, operation, vaultInput(t, bad)); err == nil {
				t.Fatal("private field", field)
			}
		}
		for field, values := range map[string][]any{"epoch": {"01", "0", "invalid"}, "mode": {"bad", nil}, "sftpOnly": {nil, "true"}, "route": {map[string]any{}}} {
			for _, value := range values {
				bad := cloneSFTPPacket(input)
				bad[field] = value
				if _, err = h.Handle(ctx, operation, vaultInput(t, bad)); err == nil {
					t.Fatal("malformed", field)
				}
			}
		}
	}
	for field, values := range map[string][]any{"manual": {map[string]any{}}, "expected": {map[string]any{}, func() localvault.SSHManualPlan { p := plan; p.Mode = "passphrase"; return p }(), func() localvault.SSHManualPlan { p := plan; p.Host.Binding.Host = "changed.example"; return p }()}, "endpoint": {"127.0.0.1:2"}} {
		for _, value := range values {
			bad := cloneSFTPPacket(q)
			bad[field] = value
			if _, err = h.Handle(ctx, "ssh-manual-bundle", vaultInput(t, bad)); err == nil {
				t.Fatal("invalid bundle", field)
			}
		}
	}
	bad := cloneSFTPPacket(q)
	bad["expected"] = map[string]any{"host": map[string]any{}, "mode": "account", "autoSudo": true, "sftpOnly": false}
	if _, err = h.Handle(ctx, "ssh-manual-bundle", vaultInput(t, bad)); err == nil {
		t.Fatal("malformed host plan")
	}
	if _, err = h.sshManual(ctx, "unknown", vaultInput(t, q)); err == nil {
		t.Fatal("unknown operation")
	}
	if _, err = h.sshManual(ctx, "ssh-manual-plan", make([]byte, 3*1024*1024+1)); err == nil {
		t.Fatal("oversized request")
	}
	if _, err = (&vaultFoundationHandler{}).sshManual(ctx, "ssh-manual-plan", vaultInput(t, planInput)); err == nil {
		t.Fatal("missing owner")
	}
	bad = cloneSFTPPacket(planInput)
	bad["nodeId"] = uuid.NewString()
	if _, err = h.Handle(ctx, "ssh-manual-plan", vaultInput(t, bad)); err == nil {
		t.Fatal("unknown node")
	}
	if _, err = h.Handle(ctx, "ssh-manual-bundle", vaultInput(t, q)); err != nil {
		t.Fatal("valid request failed after invalid input", err)
	}
}

func TestVaultSSHManualRecipientRejectsDowngradeAndContextSubstitution(t *testing.T) {
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	b := sealedSSHFixtureBinding()
	pin := sealedSSHFixturePayload().Fingerprint
	c := vault.SSHManualContext{Binding: b, Mode: "account", FileID: uuid.NewString(), Revision: strings.Repeat("a", 64), Fingerprint: pin}
	inner, _ := vault.SealManualSSHCredentials(key.PublicKey().Bytes(), c, vault.SSHBundlePayload{Username: "u", Password: []byte("manual"), Fingerprint: pin})
	raw, _ := vault.EncodeSSHManualAuthorization(vault.SSHManualAuthorization{Mode: c.Mode, FileID: c.FileID, Revision: c.Revision, Base: vault.SSHBundlePayload{Fingerprint: pin}, Manual: inner})
	defer vault.Wipe(raw)
	opening := sealedSSHOpening{binding: b}
	p, plain, err := openSealedSSHManualPayload(key.Bytes(), opening, "account", raw)
	if err != nil || string(p.Password) != "manual" {
		t.Fatal("native manual decode", err)
	}
	vault.Wipe(plain)
	for _, edit := range []func(*sealedSSHOpening){func(o *sealedSSHOpening) { o.sftpOnly = true }, func(o *sealedSSHOpening) { o.binding.SessionID = uuid.NewString() }} {
		bad := opening
		edit(&bad)
		if _, _, err = openSealedSSHManualPayload(key.Bytes(), bad, "account", raw); err == nil {
			t.Fatal("native substitution")
		}
	}
	if _, _, err = openSealedSSHManualPayload(key.Bytes(), opening, "passphrase", raw); err == nil {
		t.Fatal("account into key-passphrase recipient")
	}
	if _, _, err = openSealedSSHManualPayload(key.Bytes(), opening, "account", []byte("invalid")); err == nil {
		t.Fatal("invalid native authorization")
	}
	for _, mode := range []string{"account", "passphrase"} {
		child := startSealedSSHModeTestChild(t, nil, mode)
		child.send(t, sealedSSHPacket(t, child.public, b, sealedSSHFixturePayload()))
		if child.wait(t) == nil {
			t.Fatal("manual CLI accepted a saved credential frame")
		}
	}
	if err = serveSealedSSHMode(io.NopCloser(bytes.NewReader(nil)), io.Discard, nil, "invalid"); err == nil {
		t.Fatal("invalid recipient mode")
	}
}
