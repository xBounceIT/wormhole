package sharedpg

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestDeviceStorageCheckpointPreservesEnrollmentAndPasswordChange(t *testing.T) {
	p, key, slots := deviceEnrollmentFixture(t)
	previous := devicePasswordSource(t, p, key, slots)
	next := slots
	next.FormatVersion, next.Sequence, next.ProfileSequence = vault.SlotFileFormatVersion, slots.Sequence+1, 7
	next.Nodes = []vault.NodeHighWater{{NodeID: uuid.NewString(), Revision: 9}}
	next.Tunnels = []vault.TunnelHighWater{{TunnelID: uuid.NewString(), Revision: 4}}
	next.VPNSSO = []vault.VPNSSOHighWater{{ScopeID: uuid.NewString(), RowVersion: 2, Revision: 2, Digest: bytes.Repeat([]byte{11}, 32)}}
	raw, err := AdvanceDeviceStorageCheckpoints(context.Background(), key, previous, slots.VaultID, slots.FileID, slots.Sequence, next)
	if err != nil {
		t.Fatal(err)
	}
	actual, envelope, err := DecodeDeviceEnrollmentFile(raw)
	if err != nil || !reflect.DeepEqual(actual.Slots, slots.Slots) || !reflect.DeepEqual(actual.VPNSSO, next.VPNSSO) {
		t.Fatal("checkpoint changed enrollment slots", err)
	}
	metadata, err := OpenDeviceEnrollment(key, actual, slots.VaultID, slots.FileID, next.Sequence, envelope)
	if err != nil || metadata.Binding() != p.root.Binding() {
		t.Fatal("checkpoint enrollment cannot reopen", err)
	}
	// A password rewrap uses the same random storage root and retains the new
	// browser-state floors. It must not reset the cache's security history.
	changed, err := PrepareDevicePasswordFile(context.Background(), key, raw, slots.VaultID, slots.FileID, next.Sequence, []byte("new-device-password"), bytes.Repeat([]byte{8}, 32), vault.Default, vault.Standard)
	if err != nil {
		t.Fatal(err)
	}
	updated, encrypted, err := DecodeDeviceEnrollmentFile(changed)
	if err != nil || updated.ProfileSequence != next.ProfileSequence || !reflect.DeepEqual(updated.VPNSSO, next.VPNSSO) || !reflect.DeepEqual(updated.Nodes, next.Nodes) || !reflect.DeepEqual(updated.Tunnels, next.Tunnels) {
		t.Fatal("password change discarded checkpoints", err)
	}
	root, err := vault.OpenPasswordSlot(context.Background(), slots.VaultID, updated.Slots[len(updated.Slots)-1], []byte("new-device-password"), bytes.Repeat([]byte{8}, 32))
	if err != nil || !bytes.Equal(root, key) {
		t.Fatal("personal root changed at password change", err)
	}
	defer vault.Wipe(root)
	if _, err := OpenDeviceEnrollment(root, updated, slots.VaultID, slots.FileID, updated.Sequence, encrypted); err != nil {
		t.Fatal(err)
	}
	// Advancing observations is allowed, including a partial manifest floor.
	advance := actual
	advance.Sequence++
	advance.Nodes = append([]vault.NodeHighWater(nil), actual.Nodes...)
	advance.Nodes[0].Revision++
	advance.Tunnels = append([]vault.TunnelHighWater(nil), actual.Tunnels...)
	advance.Tunnels[0].Revision++
	advance.VPNSSO = append([]vault.VPNSSOHighWater(nil), actual.VPNSSO...)
	advance.VPNSSO[0].RowVersion++
	if _, err := AdvanceDeviceStorageCheckpoints(context.Background(), key, raw, slots.VaultID, slots.FileID, actual.Sequence, advance); err != nil {
		t.Fatal("monotonic observations rejected", err)
	}
	for _, name := range []string{"sequence", "profile", "format", "node", "tunnel", "sso", "sso-digest", "root", "slots", "epoch", "invalid-new-mark"} {
		t.Run(name, func(t *testing.T) {
			candidate := actual
			candidate.Sequence++
			switch name {
			case "sequence":
				candidate.Sequence++
			case "profile":
				candidate.ProfileSequence--
			case "format":
				candidate.FormatVersion = 1
			case "node":
				candidate.Nodes = nil
			case "tunnel":
				candidate.Tunnels = nil
			case "sso":
				candidate.VPNSSO = nil
			case "sso-digest":
				candidate.VPNSSO = append([]vault.VPNSSOHighWater(nil), actual.VPNSSO...)
				candidate.VPNSSO[0].Digest = bytes.Repeat([]byte{12}, 32)
			case "root":
				candidate.RootKeyVersion++
			case "slots":
				candidate.Slots = nil
			case "epoch":
				candidate.FileEpoch++
			case "invalid-new-mark":
				candidate.Nodes = append(append([]vault.NodeHighWater(nil), actual.Nodes...), vault.NodeHighWater{NodeID: "invalid", Revision: 1})
			}
			if _, err := AdvanceDeviceStorageCheckpoints(context.Background(), key, raw, slots.VaultID, slots.FileID, actual.Sequence, candidate); err == nil {
				t.Fatal("checkpoint mutation accepted")
			}
		})
	}
	if _, err := AdvanceDeviceStorageCheckpoints(nil, key, raw, slots.VaultID, slots.FileID, 1, advance); err == nil {
		t.Fatal("nil context")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := AdvanceDeviceStorageCheckpoints(cancelled, key, raw, slots.VaultID, slots.FileID, 1, advance); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := AdvanceDeviceStorageCheckpoints(context.Background(), key, []byte("corrupted"), slots.VaultID, slots.FileID, 1, advance); err == nil {
		t.Fatal("invalid previous file")
	}
	if _, err := AdvanceDeviceStorageCheckpoints(context.Background(), key, raw, slots.VaultID, slots.FileID, actual.Sequence+1, advance); err == nil {
		t.Fatal("stale sequence")
	}
}
