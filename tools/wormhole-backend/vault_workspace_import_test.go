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
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/workspaceimport"
)

func TestWorkspaceImportRewritesFortinetFallbackBeforeSealing(t *testing.T) {
	originalID, newID := uuid.NewString(), uuid.NewString()
	configuration, err := json.Marshal(map[string]any{"Host": "vpn.example", "PreSharedKey": "synthetic-fixture-key",
		"UserAuth": 0, "IkeVersion": 2, "FallbackTunnelId": strings.ToUpper(originalID)})
	if err != nil {
		t.Fatal(err)
	}
	result, err := transformWorkspaceImportTunnel(9, configuration, func(id string) (string, error) {
		if id != originalID {
			t.Fatal("the existing runtime did not normalize the original reference")
		}
		return newID, nil
	})
	defer vault.Wipe(result)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := decodeVaultTunnelSettings(result)
	if err != nil {
		t.Fatal(err)
	}
	defer clearTunnelSettingsMap(settings)
	if fallback, err := selectNativeIPsecFallbackSettings(settings); err != nil || fallback != newID ||
		tunnelSettingString(settings, "PreSharedKey") != "synthetic-fixture-key" || bytes.Contains(result, []byte(strings.ToUpper(originalID))) {
		t.Fatal("the import rewrite changed or lost provider settings", err)
	}
	blocked := errors.New("fallback is not permitted")
	if result, err := transformWorkspaceImportTunnel(9, configuration, func(string) (string, error) { return "", blocked }); result != nil || err != blocked {
		t.Fatal("the import did not propagate a fallback validation failure", err)
	}
	if result, err := transformWorkspaceImportTunnel(9, configuration, func(string) (string, error) { return "invalid", nil }); result != nil || err != vault.ErrFormat {
		t.Fatal("invalid translated identity was accepted", err)
	}
}

func TestSharedSetupImportPreviewBindsApprovalToReviewedFallback(t *testing.T) {
	h, ctx := vaultCredentialFixture(t), context.Background()
	fallback := vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "SSL fallback", Kind: 2}
	ipsec := vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "IPsec", Kind: 9}
	if _, err := h.owner.PutTunnel(ctx, fallback, []byte(`{"Host":"vpn.example","Username":"fixture","Password":"synthetic-hidden"}`), 0); err != nil {
		t.Fatal(err)
	}
	ipsecRaw := vaultInput(t, map[string]any{
		"Host": "vpn.example", "PreSharedKey": "synthetic-hidden", "UserAuth": 0, "IkeVersion": 2, "FallbackTunnelId": fallback.ID,
	})
	if _, err := h.owner.PutTunnel(ctx, ipsec, ipsecRaw, 0); err != nil {
		t.Fatal(err)
	}
	source, err := h.owner.CaptureWorkspaceImportWithFallbacks(ctx, workspaceImportFallback)
	if err != nil {
		t.Fatal(err)
	}
	if source.TunnelFallbacks[ipsec.ID] != fallback.ID {
		t.Fatal("the preview lost its authenticated provider dependency")
	}
	target := workspaceimport.Target{WorkspaceID: uuid.New(), UserID: uuid.New(), RequestID: uuid.New()}
	setup := sharedSetupPlan{Summary: sharedSetupSummary{WorkspaceID: target.WorkspaceID.String(), State: setupSubmitted}}
	preview, prepared, err := workspaceimport.Prepare(ctx, source, target, workspaceimport.Selection{})
	if err != nil || prepared == nil || !prepared.IncludesDestination(workspaceimport.Personal) {
		t.Fatal("initial destinations were not personal", err)
	}
	r := &sharedSetupImportReview{id: uuid.New(), target: target, source: source, preview: preview}
	r.approve(prepared)
	original := r.confirmation
	originalDigest, err := prepared.ApprovalDigest()
	if err != nil || original == uuid.Nil {
		t.Fatal("initial import did not get an approval", err)
	}
	h.setupImport = r
	primary := workspaceimport.ItemID{Kind: "tunnel", ID: ipsec.ID}
	dependency := workspaceimport.ItemID{Kind: "tunnel", ID: fallback.ID}
	request := func(id uuid.UUID, selected ...workspaceimport.ItemID) []byte {
		return vaultInput(t, map[string]any{"workspaceId": target.WorkspaceID.String(), "reviewId": id.String(),
			"shared": selected, "decisions": []any{}})
	}
	if _, err := h.reviseSharedSetupImport(ctx, setup, request(uuid.New(), primary)); err != vaultwire.ErrProtocol || h.setupImport.confirmation != original {
		t.Fatal("stale review replaced an existing approval", err)
	}
	raw, err := h.reviseSharedSetupImport(ctx, setup, request(r.id, primary))
	if err != nil || bytes.Contains(raw, []byte("synthetic-hidden")) || h.setupImport.prepared != nil || h.setupImport.confirmation != uuid.Nil ||
		len(h.setupImport.preview.Conflicts) != 1 || h.setupImport.preview.Conflicts[0] != (workspaceimport.PlacementConflict{Item: primary, Dependency: dependency}) {
		t.Fatal("the preview concealed a cross-scope fallback or issued approval anyway", err)
	}
	if _, err := h.reviseSharedSetupImport(ctx, setup, request(r.id, primary, dependency)); err != nil || h.setupImport.prepared == nil ||
		h.setupImport.confirmation == uuid.Nil || h.setupImport.confirmation == original {
		t.Fatal("moving the complete dependency did not issue a fresh approval", err)
	}
	changed, err := h.setupImport.prepared.ApprovalDigest()
	if err != nil || changed == originalDigest {
		t.Fatal("approval omitted tunnel destinations", err)
	}
}

func TestWorkspaceImportChecksTunnelConfigurationWithoutFallback(t *testing.T) {
	for _, tc := range []struct {
		kind          int
		configuration string
		valid         bool
	}{
		{9, `{"Host":"vpn.example","PreSharedKey":"synthetic-fixture-key","UserAuth":0,"IkeVersion":2}`, true},
		{2, `{"Host":"vpn.example","Username":"fixture","Password":"synthetic-password"}`, true},
		{2, `{"Host":"vpn.example"}`, false},
		{9, `{"Host":"vpn.example","Host":"bad.example"}`, false},
		{9, `{"Host":"vpn.example","IkeVersion":2}`, false},
	} {
		input := []byte(tc.configuration)
		result, err := transformWorkspaceImportTunnel(tc.kind, input, func(string) (string, error) {
			t.Fatal("a fallback was inferred for a tunnel without one")
			return "", nil
		})
		if tc.valid && (err != nil || !bytes.Equal(result, input)) || !tc.valid && (err == nil || result != nil) {
			t.Fatal("import did not enforce the original provider validation", tc.kind, err)
		}
	}
}
