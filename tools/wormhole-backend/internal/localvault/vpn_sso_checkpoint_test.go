package localvault

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func checkpointCapture(t *testing.T, o *Owner, current vault.SlotFile) vault.SlotFile {
	t.Helper()
	result := current
	err := o.PersistVPNSSOCheckpoints(context.Background(), current, func(next vault.SlotFile, key []byte) error {
		raw, err := vault.EncodeSlotFile(key, next)
		if err != nil {
			return err
		}
		result, err = vault.DecodeSlotFile(raw)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestVPNSSOCheckpointPersistsPartialFloorAcrossOwnerRestart(t *testing.T) {
	o, path, opts, key := owner(t)
	ctx := context.Background()
	binding := vpnSSOFixture()
	id, _ := openVPNSSO(t, o, binding, VPNSSOCheckpoint{})
	full := saveVPNSSO(t, o, binding, id, []byte("encrypted native state"))
	if _, err := o.ObserveVPNSSO(ctx, binding, VPNSSOFloor{Checkpoint: full, RowVersion: 2}); err != nil {
		t.Fatal(err)
	}
	document := checkpointCapture(t, o, opts.Slots)
	if document.FormatVersion != 2 || document.Sequence != 2 || len(document.VPNSSO) != 1 || document.VPNSSO[0].RowVersion != 2 || document.VPNSSO[0].Revision != 1 {
		t.Fatal("checkpoint not persisted")
	}
	if err := o.PersistVPNSSOCheckpoints(ctx, document, func(vault.SlotFile, []byte) error { t.Fatal("unchanged checkpoint rewritten"); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Create = false
	opts.Slots = document
	opts.MinimumSequence = 2
	fresh, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err := fresh.OpenVPNSSO(ctx, binding, id, VPNSSOCheckpoint{}, func(VPNSSOSnapshot) error { t.Fatal("old archive released after restart"); return nil }); err != vault.ErrRollback {
		t.Fatal(err)
	}
}

func TestVPNSSOCheckpointRejectsTunnelDatabaseReplayAfterRestart(t *testing.T) {
	o, path, opts, key := owner(t)
	ctx := context.Background()
	tunnel, err := o.PutTunnel(ctx, tunnelDraft(), []byte("encrypted VPN settings"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	oldDatabase, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	opts.Create = false
	later, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { later.Close() })
	metadata := tunnel.TunnelMetadata
	metadata.Name = "new authenticated tunnel revision"
	updated, err := later.PutTunnel(ctx, metadata, nil, tunnel.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	opts.Slots = checkpointCapture(t, later, opts.Slots)
	opts.MinimumSequence = opts.Slots.Sequence
	if err := later.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, oldDatabase, 0600); err != nil {
		t.Fatal(err)
	}
	fresh, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if fresh.tunnelFloors[tunnel.ID] != updated.RowVersion {
		t.Fatal("native slot tunnel floor was not imported")
	}
	if _, err := fresh.ReadTunnel(ctx, tunnel.ID, 0); err != vault.ErrRollback {
		t.Fatal("old tunnel replay accepted after restart", err)
	}
}

func TestVPNSSOCheckpointWriterFailuresPolicyAndSourceMetadata(t *testing.T) {
	o, _, opts, _ := owner(t)
	ctx := context.Background()
	binding := vpnSSOFixture()
	id, _ := openVPNSSO(t, o, binding, VPNSSOCheckpoint{})
	saveVPNSSO(t, o, binding, id, []byte("archive"))
	failure := errors.New("native checkpoint write")
	if err := o.PersistVPNSSOCheckpoints(ctx, opts.Slots, func(vault.SlotFile, []byte) error { return failure }); err != failure || o.slotFloor != 1 {
		t.Fatal("write failure advanced floor", err)
	}
	document := checkpointCapture(t, o, opts.Slots)
	if err := o.PersistVPNSSOCheckpoints(ctx, opts.Slots, func(vault.SlotFile, []byte) error { t.Fatal("old document written"); return nil }); err != vault.ErrRollback {
		t.Fatal(err)
	}
	policy, err := o.ReadLocalPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	policy.Policy.Sequence++
	if _, err := o.PutLocalPolicy(ctx, policy.Policy, vault.Standard, 1); err != nil {
		t.Fatal(err)
	}
	document = checkpointCapture(t, o, document)
	if document.ProfileSequence != 2 {
		t.Fatal("policy denial floor not anchored")
	}
	if err := o.PersistVPNSSOCheckpoints(ctx, document, nil); err != vault.ErrFormat {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := o.PersistVPNSSOCheckpoints(cancelled, document, func(vault.SlotFile, []byte) error { return nil }); err != context.Canceled {
		t.Fatal(err)
	}
	bad := document
	bad.RootKeyID = opts.Identity.WorkspaceID
	if err := o.PersistVPNSSOCheckpoints(ctx, bad, func(vault.SlotFile, []byte) error { return nil }); err != vault.ErrAuthentication {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if err := o.PersistVPNSSOCheckpoints(ctx, document, func(vault.SlotFile, []byte) error { return nil }); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
}

func TestVPNSSOCheckpointAnchorsConnectionAndTunnelObservations(t *testing.T) {
	o, tunnel, q, expected, describe, doc := connectionSSOFixture(t)
	ctx := context.Background()
	if _, err := o.PlanConnectionVPNSSO(ctx, q, expected, describe); err != nil {
		t.Fatal(err)
	}
	document := checkpointCapture(t, o, doc)
	if len(document.Nodes) == 0 || len(document.Tunnels) != 1 || document.Tunnels[0].TunnelID != tunnel.ID || document.Tunnels[0].Revision != tunnel.RowVersion {
		t.Fatal("source observations not anchored")
	}
}

func TestVPNSSOCheckpointFinalResponseGateRejectsNewerObservations(t *testing.T) {
	ctx, binding := context.Background(), vpnSSOFixture()
	t.Run("prepared restore", func(t *testing.T) {
		o, _, _, _ := owner(t)
		offer, _ := beginVPNTransfer(t, o, binding)
		if err := o.ValidateVPNSSOReceipt(ctx, offer.Context, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := o.ObserveVPNSSO(ctx, binding, VPNSSOFloor{RowVersion: 1}); err != nil {
			t.Fatal(err)
		}
		if err := o.ValidateVPNSSOReceipt(ctx, offer.Context, nil); !errors.Is(err, vaultstore.ErrConflict) {
			t.Fatal("new partial floor released prepared restore", err)
		}
	})
	t.Run("committed receipt", func(t *testing.T) {
		o, _, _, _ := owner(t)
		offer, private := beginVPNTransfer(t, o, binding)
		defer vault.Wipe(private)
		restoreVPNTransfer(t, o, offer, private, nil)
		pushVPNTransfer(t, o, offer.Context, []byte("native capture"))
		receipt, err := o.CommitVPNSSOTransfer(ctx, offer.Context)
		if err != nil {
			t.Fatal(err)
		}
		if err := o.ValidateVPNSSOReceipt(ctx, offer.Context, &receipt); err != nil {
			t.Fatal(err)
		}
		foreign := cloneVPNSSOTransferContext(offer.Context)
		foreign.WorkspaceID = offer.Context.FileID
		if err := o.ValidateVPNSSOReceipt(ctx, foreign, &receipt); err != vault.ErrAuthentication {
			t.Fatal(err)
		}
		invalid := receipt
		invalid.Digest = [32]byte{}
		if err := o.ValidateVPNSSOReceipt(ctx, offer.Context, &invalid); err != vault.ErrAuthentication {
			t.Fatal(err)
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if err := o.ValidateVPNSSOReceipt(cancelled, offer.Context, &receipt); err != context.Canceled {
			t.Fatal(err)
		}
		if _, err := o.ObserveVPNSSO(ctx, binding, VPNSSOFloor{Checkpoint: receipt, RowVersion: receipt.Revision + 1}); err != nil {
			t.Fatal(err)
		}
		if err := o.ValidateVPNSSOReceipt(ctx, offer.Context, &receipt); err != vault.ErrRollback {
			t.Fatal("new partial floor released old commit receipt", err)
		}
		if err := o.Close(); err != nil {
			t.Fatal(err)
		}
		if err := o.ValidateVPNSSOReceipt(ctx, offer.Context, &receipt); err != vaultstore.ErrClosed {
			t.Fatal(err)
		}
	})
}

func TestVPNSSOCheckpointPersistsDeniedNodeRevocation(t *testing.T) {
	o, _, q, expected, describe, document := connectionSSOFixture(t)
	ctx := context.Background()
	if _, err := o.PlanConnectionVPNSSO(ctx, q, expected, describe); err != nil {
		t.Fatal(err)
	}
	document = checkpointCapture(t, o, document)
	node, err := o.ReadNode(ctx, q.NodeID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.DeleteNode(ctx, q.NodeID, node.RowVersion); err != nil {
		t.Fatal(err)
	}
	// Simulate a deletion authenticated by another owner: this owner has not
	// observed the higher row until its next denied source resolution.
	o.nodeFloors[q.NodeID] = node.RowVersion
	if _, err := o.PlanConnectionVPNSSO(ctx, q, expected, describe); err != vaultstore.ErrMissing {
		t.Fatal("deleted source admitted", err)
	}
	if o.vpnSSOObservingNodes {
		t.Fatal("source observer leaked into unrelated reads")
	}
	document = checkpointCapture(t, o, document)
	for _, mark := range document.Nodes {
		if mark.NodeID == q.NodeID && mark.Revision == node.RowVersion+1 {
			return
		}
	}
	t.Fatal("denial discarded an authenticated deletion")
}
