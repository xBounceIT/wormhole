package main

import (
	"bytes"
	"errors"
	"math"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestVaultMigrationPublicationSlotTransitionsStayNarrow(t *testing.T) {
	for _, mutation := range []string{"complete", "sequence", "overflow", "binding", "phase", "profile", "nodes", "root", "epoch", "slots", "invalid-snapshot", "stale-current"} {
		t.Run(mutation, func(t *testing.T) {
			current, key := localSlotFixture(t)
			current.ProfileSequence = 2
			current.Nodes = []vault.NodeHighWater{{NodeID: uuid.NewString(), Revision: 2}}
			current.Migration = &vault.LocalMigration{Binding: strings.Repeat("a", 64), Phase: vault.MigrationRetiring, Snapshot: &vault.MigrationSnapshot{Bytes: 512, Authentication: bytes.Repeat([]byte{1}, 32), ContentAuthentication: bytes.Repeat([]byte{2}, 32)}}
			path := filepath.Join(t.TempDir(), "fixture.db")
			if err := writeVaultSlotFile(path, key, current, 0); err != nil {
				t.Fatal(err)
			}
			current, _ = readVaultSlotFile(path)
			next := current
			next.Sequence++
			next.Migration = &vault.LocalMigration{Binding: current.Migration.Binding, Phase: vault.MigrationPublishing, Snapshot: current.Migration.Snapshot, SourceSnapshot: &vault.MigrationSnapshot{Bytes: 1024, Authentication: bytes.Repeat([]byte{3}, 32)}}
			switch mutation {
			case "sequence":
				next.Sequence++
			case "overflow":
				current.Sequence, next.Sequence = math.MaxUint64, 0
			case "binding":
				next.Migration.Binding = strings.Repeat("b", 64)
			case "phase":
				next.Migration.Phase = vault.MigrationDomainsCopied
			case "profile":
				next.ProfileSequence = 1
			case "nodes":
				next.Nodes = nil
			case "root":
				next.RootKeyID = uuid.NewString()
			case "epoch":
				next.FileEpoch++
			case "slots":
				next.Slots = nil
			case "invalid-snapshot":
				next.Migration.SourceSnapshot = nil
			case "stale-current":
				changed := current
				changed.Sequence++
				if err := writeVaultSlotFile(path, key, changed, current.Sequence); err != nil {
					t.Fatal(err)
				}
			}
			if err := writeVaultSlotFile(path, key, next, current.Sequence); !errors.Is(err, vault.ErrPolicy) {
				t.Fatal("generic writer admitted publication", err)
			}
			err := writeLegacyPublicationSlots(path, key, current, next)
			if mutation != "complete" {
				if err == nil {
					t.Fatal("publication changed unrelated slot authority")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			publishing, _ := readVaultSlotFile(path)
			final := publishing
			final.Sequence++
			final.Migration = nil
			if err := writeVaultSlotFile(path, key, final, publishing.Sequence); !errors.Is(err, vault.ErrPolicy) {
				t.Fatal("generic writer cleared publication", err)
			}
			if err := writeLegacyPublicationSlots(path, key, publishing, final); err != nil {
				t.Fatal(err)
			}
			if err := writeLegacyPublicationSlots(path, key, final, final); !errors.Is(err, vault.ErrPolicy) {
				t.Fatal("finished document re-entered publication", err)
			}
		})
	}
}
