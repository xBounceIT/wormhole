package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestVaultRootRotationRestagesAfterPreCopyInterruption(t *testing.T) {
	for _, cut := range []string{"intent-journal", "intent-slots", "copy-staged"} {
		t.Run(cut, func(t *testing.T) {
			f := nativeRootRotationMode(t, cut == "copy-staged")
			ctx := context.Background()
			node := vaultstore.NodeMetadata{ID: uuid.NewString(), Kind: 0, Name: "node-observed-before-pending-copy"}
			if _, err := f.owner.PutNode(ctx, node, nil, 0); err != nil {
				t.Fatal(err)
			}
			if _, err := f.owner.ReadNode(ctx, node.ID, 1); err != nil {
				t.Fatal(err)
			}
			stop := errors.New("power cut during staging")
			if err := beginLocalRootRotationMode(ctx, f.source, f.owner, f.slots, bytes.Clone(f.key), func(point string) error {
				if point == cut {
					return stop
				}
				return nil
			}, true); !errors.Is(err, stop) {
				t.Fatalf("cut was not reached: %v", err)
			}
			if _, err := f.owner.ReadNode(ctx, node.ID, 1); !errors.Is(err, vaultstore.ErrClosed) {
				t.Fatalf("source owner survived intent publication: %v", err)
			}
			j, journal := loadRotationJournal(t, f)
			if j.Phase != vault.RotationStaging || j.TargetDatabase.Bytes != 0 || !j.Target.Encrypted {
				t.Fatalf("unexpected pending intent: %s", j.Phase)
			}
			current, err := readVaultSlotFile(f.source)
			if err != nil {
				t.Fatal(err)
			}
			if cut == "intent-journal" {
				if current.Rotation != nil {
					t.Fatal("slot barrier was published before the journal acknowledgement")
				}
			} else {
				if current.Rotation == nil || current.Rotation.Phase != vault.RotationStaging || current.Rotation.Pending == nil ||
					!bytes.Equal(current.Rotation.Pending.KeyCheck, j.Target.KeyCheck) || len(current.Rotation.Pending.Slots) != 2 {
					t.Fatal("pending wrapped roots and KCV were not persisted in the slots")
				}
				if err := vault.VerifySlotFile(f.old, current, current.VaultID, current.FileID, current.Sequence); err != nil {
					t.Fatal(err)
				}
			}
			if cut != "copy-staged" {
				if _, err := os.Lstat(j.stagePath()); !os.IsNotExist(err) {
					t.Fatalf("VACUUM ran before the slots were durable: %v", err)
				}
			}
			if err := resumeLocalRootRotation(ctx, f.source, f.old, noRotationStop); !errors.Is(err, vault.ErrKeyCheck) {
				t.Fatalf("old key was admitted as pending: %v", err)
			}
			if raw, err := os.ReadFile(rootRotationJournalPath(f.source)); err != nil || !bytes.Equal(raw, journal) {
				t.Fatal("wrong key changed the pending intent", err)
			}
			if cut == "intent-slots" {
				// A failed write can leave an incomplete encrypted database and journal.
				partial := []byte{27, 93, 202, 8}
				if err := os.WriteFile(j.backupPath(), partial, 0600); err != nil {
					t.Fatal(err)
				}
				if err := resumeLocalRootRotation(ctx, f.source, f.key, noRotationStop); !errors.Is(err, errVaultSlotConflict) {
					t.Fatalf("recovery accepted a source already retired in staging: %v", err)
				}
				if err := os.Remove(j.backupPath()); err != nil {
					t.Fatal(err)
				}
				for _, suffix := range []string{"", "-journal"} {
					if err := os.WriteFile(j.stagePath()+suffix, partial, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Mkdir(j.stagePath()+"-shm", 0700); err != nil {
					t.Fatal(err)
				}
				if err := resumeLocalRootRotation(ctx, f.source, f.key, noRotationStop); !errors.Is(err, errVaultSlotStorage) {
					t.Fatalf("recovery accepted a non-file sidecar: %v", err)
				}
				if raw, err := os.ReadFile(j.stagePath()); err != nil || !bytes.Equal(raw, partial) {
					t.Fatal("failed validation removed the stage", err)
				}
				if err := os.Remove(j.stagePath() + "-shm"); err != nil {
					t.Fatal(err)
				}
			}
			f.release()

			h := &vaultFoundationHandler{databasePath: f.source, migrationQuiesced: true}
			defer h.Close()
			metadata, err := h.Handle(ctx, "startup", nil)
			var startup vaultStartupMetadata
			if err != nil || json.Unmarshal(metadata, &startup) != nil || startup.Rotation == nil || startup.Slots == nil || !startup.Slots.Encrypted {
				t.Fatalf("startup missed the pending key: %v", err)
			}
			if _, err := h.Handle(ctx, "rotation-resume", rootRotationUnlockInput(t, j.Target, true)); err != nil {
				t.Fatal("pending recovery factor failed to restage", err)
			}
			if got, err := h.owner.ReadNode(ctx, node.ID, 1); err != nil || got.Name != node.Name {
				t.Fatal("restaging lost an observed node", err)
			}
			final, err := readVaultSlotFile(f.source)
			if err != nil || final.Rotation != nil || !sameRootRotationDocument(final, j.Target) {
				t.Fatal("restaging did not publish the pinned target", err)
			}
			for _, suffix := range rotationSQLiteSuffixes {
				if _, err := os.Lstat(j.stagePath() + suffix); !os.IsNotExist(err) {
					t.Fatalf("partial stage survived publication: %v", err)
				}
			}
		})
	}
}

func TestVaultRootRotationIntentRefusesSlotSubstitution(t *testing.T) {
	ctx := context.Background()
	f := nativeRootRotation(t)
	stop := errors.New("intent committed")
	if err := beginLocalRootRotationMode(ctx, f.source, f.owner, f.slots, bytes.Clone(f.key), func(point string) error {
		if point == "intent-slots" {
			return stop
		}
		return nil
	}, true); !errors.Is(err, stop) {
		t.Fatal(err)
	}
	j, recorded := loadRotationJournal(t, f)
	fs, err := openLegacyPublicationFS(filepath.Dir(f.source))
	if err != nil {
		t.Fatal(err)
	}
	defer fs.root.Close()
	foreign := j.stagePath() + "-journal"
	if err := os.WriteFile(foreign, []byte("preexisting sidecar"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := writeRootRotationIntent(ctx, fs, j, f.key, noRotationStop); !errors.Is(err, errVaultSlotConflict) {
		t.Fatalf("initial intent adopted an occupied stage path: %v", err)
	}
	if raw, err := os.ReadFile(foreign); err != nil || string(raw) != "preexisting sidecar" {
		t.Fatal("failed staging changed an unrelated file", err)
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	invalid := j
	invalid.TargetDatabase.Bytes = 4096
	if _, err := writeRootRotationIntent(ctx, fs, invalid, f.key, noRotationStop); !errors.Is(err, vault.ErrFormat) {
		t.Fatalf("unaudited copy acquired a publication fingerprint: %v", err)
	}
	if raw, err := os.ReadFile(rootRotationJournalPath(f.source)); err != nil || !bytes.Equal(raw, recorded) {
		t.Fatal("invalid intent changed the existing journal", err)
	}
	doc, err := readVaultSlotFile(f.source)
	if err != nil {
		t.Fatal(err)
	}
	doc.Rotation.Pending.KeyCheck[0] ^= 1
	tampered, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultSlotPath(f.source), tampered, 0600); err != nil {
		t.Fatal(err)
	}
	if err := resumeLocalRootRotation(ctx, f.source, f.key, noRotationStop); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatalf("pending KCV could be substituted: %v", err)
	}
	if _, err := os.Lstat(j.stagePath()); !os.IsNotExist(err) {
		t.Fatalf("slot substitution triggered a database copy: %v", err)
	}
}
