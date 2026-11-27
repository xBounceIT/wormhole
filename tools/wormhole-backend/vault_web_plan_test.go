package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestVaultWebPlanUsesAuthenticatedMetadataAndSharedURLRules(t *testing.T) {
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	for _, tc := range []struct {
		host, path     string
		protocol, port int
		ignore         bool
		url            string
	}{
		{"web.example", "/a%2Fb?view=1#page", 4, 8443, true, "https://web.example:8443/a%2Fb"},
		{"[::1]", "", 3, 8080, true, "http://[::1]:8080/"},
		{"web.example", "/", 4, 443, false, "https://web.example:443/"},
	} {
		m := vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Vault web", Kind: 1, Protocol: &tc.protocol, Port: &tc.port, Host: &tc.host, HTTPPath: &tc.path, HTTPIgnoreCertErrors: &tc.ignore}
		node, err := h.owner.PutNode(ctx, m, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		q := map[string]any{"nodeId": node.ID, "credentialOverride": "", "sessionId": uuid.NewString(), "requestId": uuid.NewString(), "epoch": "2"}
		raw, err := h.Handle(ctx, "web-plan", vaultInput(t, q))
		if err != nil {
			t.Fatal(err)
		}
		var plan vaultWebPlan
		if json.Unmarshal(raw, &plan) != nil {
			t.Fatal("invalid plan")
		}
		b, target := plan.Binding, plan.Target
		if b.NodeID != node.ID || b.SessionID != q["sessionId"] || b.RequestID != q["requestId"] || b.Epoch != 2 || target.URL != tc.url || target.Host != tc.host || target.IgnoreCertErrors != (tc.protocol == 4 && tc.ignore) || plan.Route != nil || target.ProxyURL != "" {
			t.Fatal("wrong native target", plan)
		}
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(raw, &fields)
		if len(fields) != 4 || len(fields["binding"]) == 0 || string(fields["route"]) != "null" ||
			len(fields["target"]) == 0 || len(plan.ArchiveBinding) != 64 {
			t.Fatal("extra or missing plan fields")
		}
		tunnel, err := h.owner.PutTunnel(ctx, vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "Web VPN " + node.ID, Kind: 6}, []byte("web-plan-must-not-release-settings"), 0)
		if err != nil {
			t.Fatal(err)
		}
		enabled := true
		m = node.NodeMetadata
		m.TunnelEnabled = &enabled
		m.TunnelConfigID = &tunnel.ID
		if _, err = h.owner.PutNode(ctx, m, nil, node.RowVersion); err != nil {
			t.Fatal(err)
		}
		raw, err = h.Handle(ctx, "web-plan", vaultInput(t, q))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte("web-plan-must-not-release-settings")) {
			t.Fatal("secret in metadata")
		}
		if json.Unmarshal(raw, &plan) != nil || plan.Route == nil || plan.Route.BundleBinding != plan.Binding || plan.Route.TunnelConfigID != plan.Target.TunnelConfigID || plan.Route.RowVersion != tunnel.RowVersion {
			t.Fatal("route mismatch")
		}
	}
}

func TestVaultWebPlanRejectsInvalidRequestsAndTargets(t *testing.T) {
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	protocol, port, host := 4, 443, "web.example"
	m := vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Vault web", Kind: 1, Protocol: &protocol, Port: &port, Host: &host}
	node, err := h.owner.PutNode(ctx, m, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	q := map[string]any{"nodeId": node.ID, "credentialOverride": "", "sessionId": uuid.NewString(), "requestId": uuid.NewString(), "epoch": "1"}
	for _, raw := range [][]byte{nil, []byte("[]"), []byte("{}"), bytes.Repeat([]byte(" "), 2049), []byte(`{"nodeId":"a","nodeId":"b"}`)} {
		if _, err := h.Handle(ctx, "web-plan", raw); err == nil {
			t.Fatal("malformed request accepted")
		}
	}
	for key := range q {
		bad := cloneSFTPPacket(q)
		delete(bad, key)
		if _, err := h.Handle(ctx, "web-plan", vaultInput(t, bad)); err == nil {
			t.Fatal("missing field accepted")
		}
	}
	for _, delta := range []map[string]any{{"host": "redirect.example"}, {"ignoreCertErrors": true}, {"tunnelConfigId": uuid.NewString()}, {"publicKey": "recipient"}, {"epoch": "01"}, {"epoch": "-1"}, {"epoch": "9007199254740992"}, {"epoch": 1}, {"credentialOverride": uuid.NewString()}} {
		bad := cloneSFTPPacket(q)
		for key, value := range delta {
			bad[key] = value
		}
		if _, err := h.Handle(ctx, "web-plan", vaultInput(t, bad)); err == nil {
			t.Fatal("override accepted", delta)
		}
	}
	for _, path := range []string{"https://redirect.example", "//redirect.example", "/a\nb", strings.Repeat("x", 4097)} {
		next := node.NodeMetadata
		next.HTTPPath = &path
		updated, e := h.owner.PutNode(ctx, next, nil, node.RowVersion)
		if e != nil {
			continue
		}
		node = updated
		if _, e := h.Handle(ctx, "web-plan", vaultInput(t, q)); !errors.Is(e, vault.ErrPolicy) {
			t.Fatal("unsafe path accepted", e)
		}
	}
	next := node.NodeMetadata
	next.HTTPPath = nil
	badHost := "user@redirect.example"
	next.Host = &badHost
	node, err = h.owner.PutNode(ctx, next, nil, node.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.Handle(ctx, "web-plan", vaultInput(t, q)); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("URL userinfo accepted", err)
	}
	if _, err = (&vaultFoundationHandler{}).Handle(ctx, "web-plan", vaultInput(t, q)); err == nil {
		t.Fatal("locked owner accepted")
	}
}
