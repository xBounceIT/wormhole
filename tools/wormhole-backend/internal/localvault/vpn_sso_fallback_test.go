package localvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func fallbackSSOProvider(t *testing.T) VPNSSODescribeProvider {
	t.Helper()
	return func(kind uint16, raw []byte) (VPNSSOProvider, error) {
		if kind != 2 || string(raw) != "ssl-configuration" {
			return VPNSSOProvider{}, vault.ErrAuthentication
		}
		return VPNSSOProvider{GatewayOrigin: "https://ssl.test:443", Realm: "staff", TrustDigest: sha256.Sum256([]byte("native SSL trust"))}, nil
	}
}

func beginFallbackSSO(t *testing.T, f fallbackFixture, describe VPNSSODescribeProvider) (VPNSSOTransferOffer, []byte, VPNSSOBinding) {
	t.Helper()
	planned, err := f.o.PlanConnectionFallbackVPNSSO(context.Background(), f.q, f.binding, f.selectFallback, describe)
	if err != nil {
		t.Fatal(err)
	}
	request, private := vpnTransferRequest(t)
	t.Cleanup(func() { vault.Wipe(private) })
	request.RequestID, request.SessionID, request.Epoch = f.q.RequestID, f.q.SessionID, f.q.Epoch
	offer, err := f.o.BeginConnectionFallbackVPNSSOTransfer(context.Background(), f.q, f.binding, planned, request, f.selectFallback, describe)
	if err != nil {
		t.Fatal(err)
	}
	return offer, private, planned
}

func TestFallbackVPNSSORoundtripAndBorrowLifetime(t *testing.T) {
	f, ctx := localFallbackFixture(t), context.Background()
	describe := fallbackSSOProvider(t)
	var primary, secondary []byte
	selector := f.selectFallback
	f.selectFallback = func(raw []byte) (string, error) { primary = raw; return selector(raw) }
	provider := func(kind uint16, raw []byte) (VPNSSOProvider, error) {
		if !bytes.Equal(primary, make([]byte, len(primary))) {
			t.Error("primary loan outlived target opening")
		}
		if f.o.mu.TryLock() {
			f.o.mu.Unlock()
			t.Error("provider escaped owner gate")
		}
		secondary = raw
		return describe(kind, raw)
	}
	offer, private, planned := beginFallbackSSO(t, f, provider)
	if planned.TunnelID != f.fallback.ID || planned.AccountID != f.binding.Primary.WorkspaceID || planned.Kind != 2 || len(secondary) == 0 || !bytes.Equal(secondary, make([]byte, len(secondary))) {
		t.Fatal("source/custody or loan lifetime")
	}
	restoreVPNTransfer(t, f.o, offer, private, nil)
	pushVPNTransfer(t, f.o, offer.Context, []byte("native fallback archive"))
	validate, err := f.o.CaptureVPNSSOReceiptSource(ctx, offer.Context)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := f.o.CommitVPNSSOTransfer(ctx, offer.Context)
	if err != nil {
		t.Fatal(err)
	}
	if err = validate(ctx); err != nil {
		t.Fatal("commit source lost on retirement", err)
	}
	if err = f.o.ValidateVPNSSOReceipt(ctx, offer.Context, &checkpoint); err != nil {
		t.Fatal(err)
	}
	second, key, _ := beginFallbackSSO(t, f, provider)
	restoreVPNTransfer(t, f.o, second, key, []byte("native fallback archive"))
	if err := f.o.CancelVPNSSOTransfer(second.Context); err != nil {
		t.Fatal(err)
	}
}

func TestFallbackVPNSSORechecksBothSourcesAtEveryStage(t *testing.T) {
	for _, side := range []string{"primary", "target"} {
		for _, action := range []string{"begin", "take", "ack", "push", "commit", "receipt"} {
			t.Run(side+"/"+action, func(t *testing.T) {
				f, ctx := localFallbackFixture(t), context.Background()
				describe := fallbackSSOProvider(t)
				seed, private, _ := beginFallbackSSO(t, f, describe)
				restoreVPNTransfer(t, f.o, seed, private, nil)
				pushVPNTransfer(t, f.o, seed.Context, []byte("existing archive"))
				if _, err := f.o.CommitVPNSSOTransfer(ctx, seed.Context); err != nil {
					t.Fatal(err)
				}
				offer, key, planned := beginFallbackSSO(t, f, describe)
				if action == "push" || action == "commit" || action == "receipt" {
					restoreVPNTransfer(t, f.o, offer, key, []byte("existing archive"))
				}
				if action == "ack" {
					packet, err := f.o.TakeVPNSSOTransfer(ctx, offer.Context, 0)
					if err != nil {
						t.Fatal(err)
					}
					vault.Wipe(packet.Bundle.Ciphertext)
				}
				if action == "commit" || action == "receipt" {
					pushVPNTransfer(t, f.o, offer.Context, []byte("replacement archive"))
				}
				var validate func(context.Context) error
				var checkpoint VPNSSOCheckpoint
				if action == "receipt" {
					var err error
					validate, err = f.o.CaptureVPNSSOReceiptSource(ctx, offer.Context)
					if err != nil {
						t.Fatal(err)
					}
					checkpoint, err = f.o.CommitVPNSSOTransfer(ctx, offer.Context)
					if err != nil {
						t.Fatal(err)
					}
				}
				if side == "primary" {
					raw, _ := json.Marshal(map[string]any{"Host": "changed.test", "PreSharedKey": "new-key", "FallbackTunnelId": f.fallback.ID})
					if _, err := f.o.PutTunnel(ctx, f.primary.TunnelMetadata, raw, f.primary.RowVersion); err != nil {
						t.Fatal(err)
					}
				} else {
					if _, err := f.o.PutTunnel(ctx, f.fallback.TunnelMetadata, []byte("changed SSL"), f.fallback.RowVersion); err != nil {
						t.Fatal(err)
					}
				}
				var err error
				switch action {
				case "begin":
					q, _ := vpnTransferRequest(t)
					q.SessionID, q.RequestID, q.Epoch = f.q.SessionID, f.q.RequestID, f.q.Epoch
					_, err = f.o.BeginConnectionFallbackVPNSSOTransfer(ctx, f.q, f.binding, planned, q, f.selectFallback, describe)
				case "take":
					_, err = f.o.TakeVPNSSOTransfer(ctx, offer.Context, 0)
				case "ack":
					err = f.o.AcknowledgeVPNSSOTransfer(ctx, offer.Context, offer.Manifest)
				case "push":
					m, chunks, e := vault.SealVPNSSOTransferArchive(offer.Context, "capture", []byte("new archive"))
					if e != nil {
						t.Fatal(e)
					}
					defer wipeBrowserBundles(chunks)
					err = f.o.PushVPNSSOTransfer(ctx, vault.VPNSSOTransferPacket{Context: offer.Context, Direction: "capture", Manifest: m, Index: 0, Bundle: chunks[0]})
				case "commit":
					_, err = f.o.CommitVPNSSOTransfer(ctx, offer.Context)
				case "receipt":
					// The old archive-floor gate alone still passes after the transfer is
					// retired. The captured native source check is required at publication.
					if e := f.o.ValidateVPNSSOReceipt(ctx, offer.Context, &checkpoint); e != nil {
						t.Fatal("fixture must isolate source gate", e)
					}
					err = validate(ctx)
				}
				if err == nil {
					t.Fatal("changed " + side + " admitted at " + action)
				}
			})
		}
	}
}

func TestFallbackVPNSSOAdmissionAndCacheIdentity(t *testing.T) {
	f, ctx := localFallbackFixture(t), context.Background()
	describe := fallbackSSOProvider(t)
	planned, err := f.o.PlanConnectionFallbackVPNSSO(ctx, f.q, f.binding, f.selectFallback, describe)
	if err != nil {
		t.Fatal(err)
	}
	provider, _ := describe(2, []byte("ssl-configuration"))
	for _, mutate := range []func(*vault.TunnelFallbackBinding){
		func(b *vault.TunnelFallbackBinding) { b.Primary.TunnelConfigID = uuid.NewString() },
		func(b *vault.TunnelFallbackBinding) { b.Primary.RowVersion++; b.Primary.ConfigurationVersion++ },
		func(b *vault.TunnelFallbackBinding) { b.Fallback.TunnelConfigID = uuid.NewString() },
		func(b *vault.TunnelFallbackBinding) { b.Fallback.RowVersion++; b.Fallback.ConfigurationVersion++ },
	} {
		other := f.binding
		mutate(&other)
		b, e := FallbackVPNSSOBinding(other, planned.AccountID, provider)
		if e != nil || b == planned {
			t.Fatal("pair cache identity not separated", e)
		}
	}
	ephemeral := f.binding
	ephemeral.Primary.SessionID = uuid.NewString()
	ephemeral.Fallback.SessionID = ephemeral.Primary.SessionID
	ephemeral.Primary.RequestID = uuid.NewString()
	ephemeral.Fallback.RequestID = uuid.NewString()
	ephemeral.Primary.RowVersion++
	ephemeral.Fallback.RowVersion++
	if b, e := FallbackVPNSSOBinding(ephemeral, planned.AccountID, provider); e != nil || b != planned {
		t.Fatal("attempt metadata became persistent provider identity", e)
	}
	for _, bad := range []vault.TunnelFallbackBinding{{}, func() vault.TunnelFallbackBinding { b := f.binding; b.Fallback.RowVersion++; return b }()} {
		if _, e := f.o.PlanConnectionFallbackVPNSSO(ctx, f.q, bad, f.selectFallback, describe); e == nil {
			t.Fatal("substituted pair")
		}
	}
	for _, badProvider := range []VPNSSODescribeProvider{nil, func(uint16, []byte) (VPNSSOProvider, error) { return VPNSSOProvider{}, vault.ErrPolicy }} {
		if _, e := f.o.PlanConnectionFallbackVPNSSO(ctx, f.q, f.binding, f.selectFallback, badProvider); e == nil {
			t.Fatal("provider refusal ignored")
		}
	}
	if _, e := FallbackVPNSSOBinding(vault.TunnelFallbackBinding{}, planned.AccountID, provider); e == nil {
		t.Fatal("invalid public pair")
	}
	if _, e := FallbackVPNSSOBinding(f.binding, "invalid", provider); e == nil {
		t.Fatal("invalid account")
	}
	request, _ := vpnTransferRequest(t)
	request.SessionID, request.RequestID, request.Epoch = f.q.SessionID, f.q.RequestID, f.q.Epoch
	for _, change := range []func(*VPNSSOTransferRequest){func(r *VPNSSOTransferRequest) { r.SessionID = uuid.NewString() }, func(r *VPNSSOTransferRequest) { r.RequestID = uuid.NewString() }, func(r *VPNSSOTransferRequest) { r.Epoch++ }} {
		q := request
		change(&q)
		if _, e := f.o.BeginConnectionFallbackVPNSSOTransfer(ctx, f.q, f.binding, planned, q, f.selectFallback, describe); e == nil {
			t.Fatal("changed transfer context")
		}
	}
	other := planned
	other.Realm = "other"
	if _, e := f.o.BeginConnectionFallbackVPNSSOTransfer(ctx, f.q, f.binding, other, request, f.selectFallback, describe); e == nil {
		t.Fatal("changed planned cache")
	}
	cancelled, cancel := context.WithCancel(ctx)
	if _, e := f.o.PlanConnectionFallbackVPNSSO(cancelled, f.q, f.binding, f.selectFallback, func(k uint16, raw []byte) (VPNSSOProvider, error) { cancel(); return describe(k, raw) }); !errors.Is(e, context.Canceled) {
		t.Fatal("late cancellation", e)
	}
}

func TestFallbackVPNSSOReceiptSourceLifetimeAndNewObservations(t *testing.T) {
	f, ctx := localFallbackFixture(t), context.Background()
	describe := fallbackSSOProvider(t)
	changedTrust := false
	provider := func(k uint16, raw []byte) (VPNSSOProvider, error) {
		p, e := describe(k, raw)
		if changedTrust {
			p.Realm = "changed"
		}
		return p, e
	}
	offer, _, _ := beginFallbackSSO(t, f, provider)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := f.o.CaptureVPNSSOReceiptSource(nil, offer.Context); e == nil {
		t.Fatal("nil context")
	}
	if _, e := f.o.CaptureVPNSSOReceiptSource(cancelled, offer.Context); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	other := offer.Context
	other.TransferID = uuid.NewString()
	if _, e := f.o.CaptureVPNSSOReceiptSource(ctx, other); e == nil {
		t.Fatal("foreign transfer")
	}
	validate, err := f.o.CaptureVPNSSOReceiptSource(ctx, offer.Context)
	if err != nil {
		t.Fatal(err)
	}
	if e := validate(nil); e == nil {
		t.Fatal("nil validation context")
	}
	if e := validate(cancelled); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	changedTrust = true
	if e := validate(ctx); !errors.Is(e, vault.ErrAuthentication) {
		t.Fatal("provider changed after admission", e)
	}
	changedTrust = false
	node, err := f.o.ReadNode(ctx, f.q.NodeID, 0)
	if err != nil {
		t.Fatal(err)
	}
	metadata := node.NodeMetadata
	metadata.Name = "new node metadata"
	if _, e := f.o.PutNode(ctx, metadata, nil, node.RowVersion); e != nil {
		t.Fatal(e)
	}
	if e := validate(ctx); !errors.Is(e, vault.ErrRollback) {
		t.Fatal("new unpublished node observation allowed final receipt", e)
	}
	if e := validate(ctx); e != nil {
		t.Fatal("stable facts changed source", e)
	}
	if err := f.o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, e := f.o.CaptureVPNSSOReceiptSource(ctx, offer.Context); !errors.Is(e, vaultstore.ErrClosed) {
		t.Fatal(e)
	}
	if e := validate(ctx); !errors.Is(e, vaultstore.ErrClosed) {
		t.Fatal(e)
	}
}

func TestFallbackVPNSSOTransferAdmissionErrors(t *testing.T) {
	f, ctx := localFallbackFixture(t), context.Background()
	describe := fallbackSSOProvider(t)
	planned, err := f.o.PlanConnectionFallbackVPNSSO(ctx, f.q, f.binding, f.selectFallback, describe)
	if err != nil {
		t.Fatal(err)
	}
	q, _ := vpnTransferRequest(t)
	q.RequestID, q.SessionID, q.Epoch = f.q.RequestID, f.q.SessionID, f.q.Epoch
	q.RestorePublicKey = nil
	if _, e := f.o.BeginConnectionFallbackVPNSSOTransfer(ctx, f.q, f.binding, planned, q, f.selectFallback, describe); e == nil {
		t.Fatal("invalid native recipient")
	}
	// A native-only transfer with no external source hook retains the existing
	// owner/receipt checks; capturing a validator does not invent source authority.
	o, _, _, _ := owner(t)
	offer, _ := beginVPNTransfer(t, o, vpnSSOFixture())
	validate, e := o.CaptureVPNSSOReceiptSource(ctx, offer.Context)
	if e != nil {
		t.Fatal(e)
	}
	if e = validate(ctx); e != nil {
		t.Fatal(e)
	}
}
