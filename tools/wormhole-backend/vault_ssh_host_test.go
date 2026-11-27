package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestSharedSFTPHostConfirmationBindsCurrentTunnel(t *testing.T) {
	workspace, fileID, tunnelID := uuid.New(), uuid.NewString(), uuid.NewString()
	q := localvault.TunnelPlanRequest{NodeID: uuid.NewString(), SessionID: uuid.NewString(), RequestID: uuid.NewString(), Epoch: 1}
	p := sharedpg.ResolvedConnectionPlan{Plan: resolver.Plan{NodeID: q.NodeID, Protocol: 7, Host: "files.example", Port: 22, TunnelID: tunnelID, HostKeyFingerprint: sealedSSHFixturePayload().Fingerprint},
		Tunnel: &sharedpg.ResolvedTunnel{Metadata: vaultstore.TunnelMetadata{ID: tunnelID, Name: "VPN", Kind: 1}, Boundary: uuid.New(), RowVersion: 2, ConfigurationVersion: 1}, Revision: "signed-plan"}
	route, err := sharedTunnelBinding(workspace, fileID, p.Plan, q, p.Tunnel)
	if err != nil {
		t.Fatal(err)
	}
	result, err := sharedHostPlan(workspace, fileID, p, q, &route)
	if err != nil || result.Binding.Protocol != "sftp" || result.Binding.TunnelConfigID != tunnelID || result.Fingerprint != p.Plan.HostKeyFingerprint {
		t.Fatal("SFTP host projection lost its route", err)
	}
	if _, err := sharedHostPlan(workspace, fileID, p, q, nil); err != vault.ErrPolicy {
		t.Fatal("missing route accepted", err)
	}
	if _, err := sharedHostPlan(workspace, uuid.NewString(), p, q, &route); err != vault.ErrPolicy {
		t.Fatal("route from another device file accepted", err)
	}
	p.Plan.HostKeyFingerprint = "invalid"
	if _, err := sharedHostPlan(workspace, fileID, p, q, &route); err != vault.ErrPolicy {
		t.Fatal("noncanonical stored fingerprint accepted", err)
	}
	p.Tunnel = nil
	if _, err := sharedHostPlan(workspace, fileID, p, q, &route); err != vault.ErrPolicy {
		t.Fatal("removed tunnel accepted", err)
	}
}

func TestVaultSSHHostPlanTrustAndStrictBoundary(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	protocol, inline, host := 0, true, "host.example"
	n, err := h.owner.PutNode(ctx, vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "SSH host", Kind: 1, Protocol: &protocol, Host: &host, Username: &host, UseInlinePassword: &inline}, []localvault.SecretChange{{Field: "inlinePassword", Value: []byte("not-in-host-plan")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	q := map[string]any{"nodeId": n.ID, "credentialOverride": "", "sessionId": uuid.NewString(), "requestId": uuid.NewString(), "epoch": "1", "route": nil}
	plan := func() localvault.SSHHostPlan {
		t.Helper()
		raw, err := h.Handle(ctx, "ssh-host-plan", vaultInput(t, q))
		if err != nil || bytes.Contains(raw, []byte("not-in-host-plan")) {
			t.Fatal(err)
		}
		var p localvault.SSHHostPlan
		if json.Unmarshal(raw, &p) != nil {
			t.Fatal("plan response")
		}
		return p
	}
	p := plan()
	action := make(map[string]any)
	for k, v := range q {
		action[k] = v
	}
	action["expected"], action["received"] = p, sealedSSHFixturePayload().Fingerprint
	if _, err := h.Handle(ctx, "shared-ssh-host-trust", vaultInput(t, map[string]any{"action": action})); err == nil || plan().Fingerprint != p.Fingerprint {
		t.Fatal("shared operation changed a local host key")
	}
	if _, err := h.Handle(ctx, "ssh-host-trust", vaultInput(t, action)); err != nil {
		t.Fatal(err)
	}
	if plan().Fingerprint != action["received"] {
		t.Fatal("pin not persisted")
	}
	if _, err := h.Handle(ctx, "ssh-host-trust", vaultInput(t, action)); err == nil {
		t.Fatal("replay")
	}
	if !vaultFreshAction("ssh-host-trust") || vaultFreshAction("ssh-host-plan") {
		t.Fatal("fresh auth admission")
	}
	// The native schema rejects injected context before reading or mutating.
	for key, bad := range map[string]any{"nodeId": "bad", "epoch": "01", "route": map[string]any{}, "extra": true} {
		changed := make(map[string]any)
		for k, v := range q {
			changed[k] = v
		}
		changed[key] = bad
		if _, err := h.Handle(ctx, "ssh-host-plan", vaultInput(t, changed)); err == nil {
			t.Fatal(key)
		}
	}
	for _, raw := range [][]byte{nil, []byte(`{}`), bytes.Repeat([]byte{'x'}, 16385)} {
		if _, err := h.Handle(ctx, "ssh-host-plan", raw); err == nil {
			t.Fatal("malformed plan")
		}
	}
	for _, raw := range []any{nil, map[string]any{}, map[string]any{"binding": nil, "fileId": p.FileID, "revision": p.Revision, "fingerprint": p.Fingerprint}} {
		action["expected"] = raw
		if _, err := h.Handle(ctx, "ssh-host-trust", vaultInput(t, action)); err == nil {
			t.Fatal("malformed expected")
		}
	}
	tunnel, err := h.owner.PutTunnel(ctx, vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "VPN", Kind: 6}, []byte(`{"Host":"gateway"}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	n, err = h.owner.ReadNode(ctx, n.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	m := n.NodeMetadata
	m.TunnelEnabled, m.TunnelConfigID = &inline, &tunnel.ID
	if _, err := h.owner.PutNode(ctx, m, nil, n.RowVersion); err != nil {
		t.Fatal(err)
	}
	route, err := h.owner.PlanConnectionTunnel(ctx, localvault.TunnelPlanRequest{NodeID: n.ID, SessionID: q["sessionId"].(string), RequestID: q["requestId"].(string), Epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	q["route"] = route
	if plan().Binding.TunnelConfigID != tunnel.ID {
		t.Fatal("route lost")
	}
	if h.closed {
		t.Fatal("bad public input retired healthy owner")
	}
	locked := &vaultFoundationHandler{}
	if _, err := locked.Handle(ctx, "ssh-host-plan", vaultInput(t, q)); err == nil {
		t.Fatal("locked plan")
	}
	// A verified factor is still tied to this exact trust mutation.
	p = plan()
	action = make(map[string]any)
	for k, v := range q {
		action[k] = v
	}
	action["expected"], action["received"] = p, "SHA256:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := h.Handle(ctx, "fresh-action", freshActionInput(t, "ssh-host-trust", vaultInput(t, action), bytes.Repeat([]byte{0x32}, 32))); err != nil {
		t.Fatal(err)
	}
	if plan().Fingerprint != action["received"] {
		t.Fatal("fresh trust failed")
	}
	if _, err := h.Handle(ctx, "fresh-action", freshActionInput(t, "ssh-host-trust", vaultInput(t, action), bytes.Repeat([]byte{4}, 32))); err != vault.ErrAuthentication {
		t.Fatal(err)
	}
}
