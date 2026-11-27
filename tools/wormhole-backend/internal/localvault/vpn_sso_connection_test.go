package localvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func connectionSSOFixture(t *testing.T) (*Owner, vaultstore.Tunnel, TunnelPlanRequest, vault.TunnelBundleBinding, VPNSSODescribeProvider, vault.SlotFile) {
	t.Helper()
	o, _, options, _ := owner(t)
	node, _, _, tunnel := resolutionFixture(t, o)
	metadata := tunnel.TunnelMetadata
	metadata.Kind = 2
	tunnel, err := o.PutTunnel(context.Background(), metadata, []byte("authenticated SSL settings"), tunnel.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	q := TunnelPlanRequest{NodeID: node.ID, SessionID: uuid.NewString(), RequestID: uuid.NewString(), Epoch: 1}
	expected, err := o.PlanConnectionTunnel(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	describe := func(kind uint16, configuration []byte) (VPNSSOProvider, error) {
		if kind != 2 || string(configuration) != "authenticated SSL settings" {
			return VPNSSOProvider{}, vault.ErrAuthentication
		}
		return VPNSSOProvider{GatewayOrigin: "https://vpn.test:443", Realm: "staff", TrustDigest: sha256.Sum256([]byte("native verified trust"))}, nil
	}
	return o, tunnel, q, expected, describe, options.Slots
}

func TestConnectionVPNSSOAdmitsAndRechecksNativeSource(t *testing.T) {
	o, tunnel, q, expected, describe, _ := connectionSSOFixture(t)
	ctx := context.Background()
	planned, err := o.PlanConnectionVPNSSO(ctx, q, expected, describe)
	if err != nil || planned.WorkspaceID != expected.WorkspaceID || planned.FileID != expected.FileID || planned.AccountID != expected.WorkspaceID || planned.TunnelID != tunnel.ID || planned.ConfigurationVersion != tunnel.ConfigurationVersion {
		t.Fatal("native binding", err)
	}
	request, private := vpnTransferRequest(t)
	defer vault.Wipe(private)
	request.SessionID, request.RequestID, request.Epoch = q.SessionID, q.RequestID, q.Epoch
	offer, err := o.BeginConnectionVPNSSOTransfer(ctx, q, expected, planned, request, describe)
	if err != nil {
		t.Fatal(err)
	}
	metadata := tunnel.TunnelMetadata
	metadata.Name = "metadata-only change"
	tunnel, err = o.PutTunnel(ctx, metadata, nil, tunnel.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	restoreVPNTransfer(t, o, offer, private, nil)
	pushVPNTransfer(t, o, offer.Context, []byte("native provider archive"))
	if _, err := o.CommitVPNSSOTransfer(ctx, offer.Context); err != nil {
		t.Fatal("metadata-only edit invalidated configuration", err)
	}
	// A new pending restore cannot survive changing the authenticated settings.
	request, _ = vpnTransferRequest(t)
	request.SessionID, request.RequestID, request.Epoch = q.SessionID, q.RequestID, q.Epoch
	offer, err = o.BeginConnectionVPNSSOTransfer(ctx, q, expected, planned, request, describe)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.PutTunnel(ctx, tunnel.TunnelMetadata, []byte("new SSL settings"), tunnel.RowVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := o.TakeVPNSSOTransfer(ctx, offer.Context, 0); !errors.Is(err, vault.ErrAuthentication) || len(o.vpnSSOTransfers) != 0 {
		t.Fatal("changed source released old archive", err)
	}
}

func TestConnectionVPNSSORefusesSubstitutedAdmissionAndProvider(t *testing.T) {
	o, _, q, expected, describe, _ := connectionSSOFixture(t)
	ctx := context.Background()
	planned, err := o.PlanConnectionVPNSSO(ctx, q, expected, describe)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := vpnTransferRequest(t)
	request.SessionID, request.RequestID, request.Epoch = q.SessionID, q.RequestID, q.Epoch
	for _, change := range []func(*VPNSSOTransferRequest){
		func(r *VPNSSOTransferRequest) { r.SessionID = uuid.NewString() },
		func(r *VPNSSOTransferRequest) { r.RequestID = uuid.NewString() },
		func(r *VPNSSOTransferRequest) { r.Epoch++ },
	} {
		other := request
		change(&other)
		if _, err := o.BeginConnectionVPNSSOTransfer(ctx, q, expected, planned, other, describe); err != vault.ErrAuthentication {
			t.Fatal(err)
		}
	}
	other := planned
	other.Realm = "another-account"
	if _, err := o.BeginConnectionVPNSSOTransfer(ctx, q, expected, other, request, describe); err != vault.ErrAuthentication {
		t.Fatal(err)
	}
	for _, change := range []func(*vault.TunnelBundleBinding){
		func(b *vault.TunnelBundleBinding) { b.Host = "redirected.test" },
		func(b *vault.TunnelBundleBinding) { b.TunnelConfigID = uuid.NewString() },
		func(b *vault.TunnelBundleBinding) { b.SessionID = uuid.NewString() },
		func(b *vault.TunnelBundleBinding) { b.ConfigurationVersion++ },
		func(b *vault.TunnelBundleBinding) { b.Epoch++ },
	} {
		other := expected
		change(&other)
		if _, err := o.PlanConnectionVPNSSO(ctx, q, other, describe); err == nil {
			t.Fatal("substituted route admitted")
		}
	}
	bad := expected
	bad.RowVersion++
	if _, err := o.PlanConnectionVPNSSO(ctx, q, bad, describe); err != vault.ErrRollback {
		t.Fatal(err)
	}
	bad = expected
	bad.RowVersion = 0
	if _, err := o.PlanConnectionVPNSSO(ctx, q, bad, describe); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if _, err := o.PlanConnectionVPNSSO(ctx, q, expected, nil); err != vault.ErrFormat {
		t.Fatal(err)
	}
	invalid := q
	invalid.NodeID = "bad"
	if _, err := o.PlanConnectionVPNSSO(ctx, invalid, expected, describe); err != vault.ErrFormat {
		t.Fatal(err)
	}
	missing := q
	missing.NodeID = uuid.NewString()
	if _, err := o.PlanConnectionVPNSSO(ctx, missing, expected, describe); err == nil {
		t.Fatal("missing node admitted")
	}
	for _, provider := range []VPNSSOProvider{{}, {GatewayOrigin: "http://vpn.test", TrustDigest: planned.TrustDigest}} {
		if _, err := o.PlanConnectionVPNSSO(ctx, q, expected, func(uint16, []byte) (VPNSSOProvider, error) { return provider, nil }); err != vault.ErrFormat {
			t.Fatal(err)
		}
	}
	failure := errors.New("provider refusal")
	if _, err := o.PlanConnectionVPNSSO(ctx, q, expected, func(uint16, []byte) (VPNSSOProvider, error) { return VPNSSOProvider{}, failure }); err != failure {
		t.Fatal(err)
	}
}

func TestConnectionVPNSSOWipesBorrowedSettingsAndCancelsOnSourceRemoval(t *testing.T) {
	o, _, q, expected, describe, _ := connectionSSOFixture(t)
	ctx := context.Background()
	var borrowed []byte
	planned, err := o.PlanConnectionVPNSSO(ctx, q, expected, func(kind uint16, raw []byte) (VPNSSOProvider, error) { borrowed = raw; return describe(kind, raw) })
	if err != nil || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("borrow survived", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	if _, err := o.PlanConnectionVPNSSO(cancelled, q, expected, func(kind uint16, raw []byte) (VPNSSOProvider, error) { cancel(); return describe(kind, raw) }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	request, _ := vpnTransferRequest(t)
	request.SessionID, request.RequestID, request.Epoch = q.SessionID, q.RequestID, q.Epoch
	offer, err := o.BeginConnectionVPNSSOTransfer(ctx, q, expected, planned, request, describe)
	if err != nil {
		t.Fatal(err)
	}
	node, err := o.ReadNode(ctx, q.NodeID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.DeleteNode(ctx, node.ID, node.RowVersion); err != nil {
		t.Fatal(err)
	}
	if err := o.AcknowledgeVPNSSOTransfer(ctx, offer.Context, offer.Manifest); err == nil || len(o.vpnSSOTransfers) != 0 {
		t.Fatal("removed source remained admitted", err)
	}
}

func TestConnectionVPNSSOQuickTargetNeverBecomesAPersistedNode(t *testing.T) {
	o, tunnel, _, _, describe, document := connectionSSOFixture(t)
	ctx := context.Background()
	ref, err := o.RegisterQuickTarget(ctx, QuickTargetRequest{SessionID: uuid.NewString(), Epoch: 1,
		Target: QuickConnectionTarget{Protocol: "https", Host: "quick.test", TunnelID: tunnel.ID}})
	if err != nil {
		t.Fatal(err)
	}
	q := TunnelPlanRequest{NodeID: ref.ID, SessionID: ref.SessionID, RequestID: uuid.NewString(), Epoch: ref.Epoch}
	expected, err := o.PlanConnectionTunnel(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.PlanConnectionVPNSSO(ctx, q, expected, describe); err != nil {
		t.Fatal(err)
	}
	document = checkpointCapture(t, o, document)
	for _, mark := range document.Nodes {
		if mark.NodeID == ref.ID {
			t.Fatal("ephemeral target acquired a persistent node floor")
		}
	}
	if len(document.Tunnels) != 1 || document.Tunnels[0].TunnelID != tunnel.ID {
		t.Fatal("quick target lost its authenticated saved tunnel")
	}
}
