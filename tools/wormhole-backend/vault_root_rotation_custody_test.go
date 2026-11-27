package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Native-only fixture: production create/unlock still has no OS-only route.
func nativeOSRotation(t *testing.T) (nativeRotationFixture, string) {
	t.Helper()
	f := nativeRootRotation(t)
	ctx := context.Background()
	doc, err := readVaultSlotFile(f.source)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.owner.Close(); err != nil {
		t.Fatal(err)
	}
	slotID := uuid.NewString()
	factor, err := createVaultUnprotectedKey(ctx, f.source, doc.VaultID, slotID)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(factor)
	slot, err := vault.CreateUnprotectedSlot(doc.VaultID, slotID, doc.RootKeyVersion, f.old, factor)
	if err != nil {
		t.Fatal(err)
	}
	doc.FormatVersion, doc.Slots = vault.SlotFileFormatVersion, []vault.Slot{slot}
	raw, err := vault.EncodeSlotFile(f.old, doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultSlotPath(f.source), raw, 0600); err != nil {
		t.Fatal(err)
	}
	doc, err = vault.DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	f.owner, err = localvault.Open(ctx, f.source, localVaultOptions(doc), bytes.Clone(f.old))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.owner.Close(); err != nil {
			t.Error(err)
		}
	})
	path, _, err := vaultUnprotectedKeyIdentity(f.source, doc.VaultID, slotID)
	if err != nil {
		t.Fatal(err)
	}
	return f, path
}

func TestRootCustodyVersionsAndReceiptsCannotAuthorizeAnotherSource(t *testing.T) {
	f, _, _, original, _ := custodyRetiringFixture(t)
	for _, change := range []string{"old-version", "future-version", "missing", "platform", "slot", "digest", "length", "empty", "oversize", "state", "prepared-receipt", "publishing-without-receipt", "protected-source", "unclean-path"} {
		t.Run(change, func(t *testing.T) {
			raw, _ := json.Marshal(original)
			var j rootRotationJournal
			if err := json.Unmarshal(raw, &j); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "old-version":
				j.Version, j.Custody = 1, nil
			case "future-version":
				j.Version = 3
			case "missing":
				j.Custody = nil
			case "platform":
				j.Custody.Platform = "foreign-os"
			case "slot":
				j.Custody.SlotID = j.Source.RootKeyID
			case "digest":
				j.Custody.File.Digest = string(bytes.Repeat([]byte{'a'}, 64))
			case "length":
				j.Custody.File.Bytes++
			case "empty":
				j.Custody.Protected = nil
			case "oversize":
				j.Custody.Protected = make([]byte, maxVaultUnprotectedKeyBlob+1)
			case "state":
				j.Custody.State = "completed"
			case "prepared-receipt":
				j.Phase, j.Custody.State = vault.RotationPrepared, rootCustodyIntent
			case "publishing-without-receipt":
				j.Phase = vault.RotationPublishing
			case "protected-source":
				j.Source.Slots[0].Kind = vault.SlotRecovery
			case "unclean-path":
				j.SourcePath = "relative.db"
			}
			if old, err := authenticateRootRotationJournal(j, f.key); err == nil {
				vault.Wipe(old)
				t.Fatal("invalid receipt authenticated")
			}
		})
	}
	raw, err := encodeRootRotationJournal(context.Background(), original, f.key)
	if err != nil {
		t.Fatal(err)
	}
	var capsule rootRotationCapsule
	if err := json.Unmarshal(raw, &capsule); err != nil {
		t.Fatal(err)
	}
	capsule.Version = 1
	tagged, _ := json.Marshal(capsule)
	if _, err := decodeRootRotationJournal(context.Background(), tagged, f.key); err == nil {
		t.Fatal("capsule version retag accepted")
	}
}

func TestRootCustodyCodecDoesNotEnableOrdinaryOSUnlock(t *testing.T) {
	f, _ := nativeOSRotation(t)
	doc, err := readVaultSlotFile(f.source)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []vaultUnlockInput{
		{VaultID: doc.VaultID, SlotID: doc.Slots[0].ID},
		{VaultID: doc.VaultID, SlotID: doc.Slots[0].ID, Password: []byte("not an OS slot password")},
		{VaultID: doc.VaultID, SlotID: doc.Slots[0].ID, RecoveryKey: bytes.Clone(f.old)},
	} {
		key, err := openVaultUnlockFactor(context.Background(), doc, &input)
		input.wipe()
		if err != vault.ErrPolicy || key != nil {
			vault.Wipe(key)
			t.Fatal("generic factor API opened OS custody", err)
		}
	}
}

func TestRootCustodyResumesEveryRetirementBoundary(t *testing.T) {
	for _, cut := range []string{"journal-prepared", "barrier-prepared", "journal-retiring", "barrier-retiring", "custody-intent", "custody-key-deleted", "custody-key-retired", "custody-file-removed", "custody-file-retired", "journal-publishing", "barrier-publishing", "source-retired", "database-published", "slots-published"} {
		t.Run(cut, func(t *testing.T) {
			f, path := nativeOSRotation(t)
			ctx := context.Background()
			stop := errors.New("durable custody cut")
			step := func(event string) error {
				if event == cut {
					return stop
				}
				return nil
			}
			err := beginLocalRootRotation(ctx, f.source, f.owner, f.slots, bytes.Clone(f.key), step)
			if cut == "journal-prepared" || cut == "barrier-prepared" {
				if !errors.Is(err, stop) {
					t.Fatal(err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if err := resumeLocalRootRotation(ctx, f.source, f.key, step); !errors.Is(err, stop) {
					t.Fatal("cut not reached", err)
				}
			}
			j, raw := loadRotationJournal(t, f)
			if j.Version != 2 || j.Custody == nil || j.Custody.Platform != runtime.GOOS {
				t.Fatal("missing native custody commitment")
			}
			if bytes.Contains(raw, j.Custody.Protected) {
				t.Fatal("OS custody escaped encrypted journal")
			}
			if j.Phase == vault.RotationPublishing && j.Custody.State != rootCustodyRetired {
				t.Fatal("publishing before custody receipt")
			}
			if err := requireNoRootRotation(f.source); err == nil {
				t.Fatal("interrupted OS transition allowed ordinary entry")
			}
			if err := resumeLocalRootRotation(ctx, f.source, f.key, noRotationStop); err != nil {
				t.Fatal("custody retry", err)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("old factor retained", err)
			}
			if _, err := os.Lstat(rootRotationJournalPath(f.source)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("journal retained", err)
			}
			doc, err := readVaultSlotFile(f.source)
			if err != nil || len(doc.Slots) != 2 || doc.RootKeyVersion != 2 {
				t.Fatal("target not published", err)
			}
			owner, err := localvault.Open(ctx, f.source, localVaultOptions(doc), bytes.Clone(f.key))
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			if err := owner.WithSecret(ctx, f.ref, 1, func(value []byte) error {
				if string(value) != "native root transition private value" {
					return vault.ErrAuthentication
				}
				return nil
			}); err != nil {
				t.Fatal("rotation lost secret", err)
			}
			if _, err := localvault.Open(ctx, f.source, localVaultOptions(doc), bytes.Clone(f.old)); err == nil {
				t.Fatal("old OS root accepted")
			}
		})
	}
}

func custodyRetiringFixture(t *testing.T) (nativeRotationFixture, string, *legacyPublicationFS, rootRotationJournal, []byte) {
	t.Helper()
	f, path := nativeOSRotation(t)
	ctx := context.Background()
	if err := beginLocalRootRotation(ctx, f.source, f.owner, f.slots, bytes.Clone(f.key), noRotationStop); err != nil {
		t.Fatal(err)
	}
	cut := errors.New("before intent")
	if err := resumeLocalRootRotation(ctx, f.source, f.key, func(event string) error {
		if event == "barrier-retiring" {
			return cut
		}
		return nil
	}); !errors.Is(err, cut) {
		t.Fatal(err)
	}
	j, raw := loadRotationJournal(t, f)
	fs, err := openLegacyPublicationFS(filepath.Dir(f.source))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fs.root.Close() })
	return f, path, fs, j, raw
}

func TestRootCustodyRechecksReceiptsBeforePublication(t *testing.T) {
	f, path, fs, j, raw := custodyRetiringFixture(t)
	ctx := context.Background()
	adapter := nativeRootRotationCustodyAdapter()
	prepared := j
	prepared.Phase = vault.RotationPrepared
	if err := retireRootRotationCustody(ctx, fs, &prepared, f.key, &raw, noRotationStop, adapter); err != vault.ErrPolicy {
		t.Fatal("retired custody before verified retiring phase", err)
	}
	if err := retireRootRotationCustody(ctx, fs, &j, f.key, &raw, noRotationStop, adapter); err != nil {
		t.Fatal(err)
	}
	if j.Custody.State != rootCustodyRetired {
		t.Fatal("missing positive receipts")
	}
	blocked := adapter
	blocked.retire = func(string, []byte) error { return errors.New("private OS diagnostic") }
	if err := retireRootRotationCustody(ctx, fs, &j, f.key, &raw, noRotationStop, blocked); err != errVaultUnprotectedKeyStorage {
		t.Fatal("inaccessible keychain accepted as absent", err)
	}
	if err := os.WriteFile(path, []byte("foreign ciphertext"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := retireRootRotationCustody(ctx, fs, &j, f.key, &raw, noRotationStop, adapter); err != vault.ErrAuthentication {
		t.Fatal("reappeared file accepted", err)
	}
	value, err := os.ReadFile(path)
	if err != nil || string(value) != "foreign ciphertext" {
		t.Fatal("retired receipt deleted a replacement", err)
	}
	if _, err := inventoryRootRotationCustody(ctx, fs, f.source, vault.SlotFile{}); err != vault.ErrPolicy {
		t.Fatal("empty source accepted", err)
	}
	for _, candidate := range []rootRotationJournal{{Version: 2}, {Version: 2, Custody: j.Custody, Source: j.Source, SourcePath: j.SourcePath, Phase: vault.RotationPrepared}} {
		if err := retireRootRotationCustody(ctx, fs, &candidate, f.key, &raw, noRotationStop, adapter); err == nil {
			t.Fatal("missing intent or invalid phase accepted")
		}
	}
}

func TestRootCustodyRetriesAfterOriginalOSKeyIsUnavailable(t *testing.T) {
	f, _, fs, j, raw := custodyRetiringFixture(t)
	ctx := context.Background()
	adapter := nativeRootRotationCustodyAdapter()
	originalOpen := adapter.open
	missing, opens := false, 0
	adapter.open = func(path string, protected []byte) ([]byte, error) {
		opens++
		if missing {
			return nil, errors.New("original OS key is gone")
		}
		return originalOpen(path, protected)
	}
	// Model the checked provider's positive delete/not-found acknowledgements.
	// The real Windows factor file is still removed by the rooted coordinator.
	adapter.retire = func(string, []byte) error { missing = true; return nil }
	cut := errors.New("OS deletion succeeded before receipt")
	if err := retireRootRotationCustody(ctx, fs, &j, f.key, &raw, func(event string) error {
		if event == "custody-key-deleted" {
			return cut
		}
		return nil
	}, adapter); !errors.Is(err, cut) {
		t.Fatal(err)
	}
	before := opens
	if !missing || before == 0 {
		t.Fatal("OS-loss fixture did not authenticate the original factor")
	}
	j, raw = loadRotationJournal(t, f)
	if j.Custody.State != rootCustodyIntent {
		t.Fatal("lost acknowledgement invented a key receipt")
	}
	if err := retireRootRotationCustody(ctx, fs, &j, f.key, &raw, noRotationStop, adapter); err != nil {
		t.Fatal("original OS key required after intent", err)
	}
	if opens != before {
		t.Fatal("reopened old OS custody on retry")
	}
	if err := resumeLocalRootRotation(ctx, f.source, f.key, noRotationStop); err != nil {
		t.Fatal("new-root escrow cannot finish publication", err)
	}
}

func TestRootCustodyDenialsNeverInventRetirement(t *testing.T) {
	for _, attack := range []string{"missing-before-intent", "changed-file", "bad-material", "wrong-factor", "unavailable", "retire-error", "replacement-after-key", "cancel-before", "cancel-after-intent", "cancel-after-key", "cancel-after-key-receipt", "journal-conflict"} {
		t.Run(attack, func(t *testing.T) {
			f, path, fs, j, raw := custodyRetiringFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			adapter := nativeRootRotationCustodyAdapter()
			retires := 0
			originalRetire := adapter.retire
			adapter.retire = func(path string, protected []byte) error {
				retires++
				if attack == "retire-error" {
					return errors.New("private OS diagnostic")
				}
				err := originalRetire(path, protected)
				if attack == "replacement-after-key" {
					if err := os.WriteFile(path, []byte("foreign ciphertext"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				return err
			}
			var borrowed []byte
			switch attack {
			case "missing-before-intent":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "changed-file":
				if err := os.WriteFile(path, []byte("foreign ciphertext"), 0600); err != nil {
					t.Fatal(err)
				}
			case "bad-material":
				adapter.open = func(string, []byte) ([]byte, error) { borrowed = bytes.Repeat([]byte{0x3a}, 96); return borrowed, nil }
			case "wrong-factor":
				adapter.open = func(string, []byte) ([]byte, error) {
					_, header, err := vaultUnprotectedKeyIdentity(f.source, j.Source.VaultID, j.Custody.SlotID)
					if err != nil {
						t.Fatal(err)
					}
					borrowed = append(header, bytes.Repeat([]byte{0x3a}, 32)...)
					return borrowed, nil
				}
			case "unavailable":
				adapter.open = func(string, []byte) ([]byte, error) { return nil, errors.New("private OS diagnostic") }
			case "cancel-before":
				cancel()
			case "journal-conflict":
				if err := os.WriteFile(rootRotationJournalPath(f.source), []byte("foreign journal"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			step := func(event string) error {
				if attack == "cancel-after-intent" && event == "custody-intent" || attack == "cancel-after-key" && event == "custody-key-deleted" || attack == "cancel-after-key-receipt" && event == "custody-key-retired" {
					cancel()
				}
				return nil
			}
			err := retireRootRotationCustody(ctx, fs, &j, f.key, &raw, step, adapter)
			if err == nil {
				t.Fatal("custody denial accepted")
			}
			if bytes.Contains([]byte(err.Error()), []byte("private")) {
				t.Fatal("OS diagnostics escaped")
			}
			if borrowed != nil && !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("OS plaintext retained")
			}
			if attack != "retire-error" && attack != "replacement-after-key" && attack != "cancel-after-key" && attack != "cancel-after-key-receipt" && retires != 0 {
				t.Fatal("deleted key before authenticated intent")
			}
			if attack == "journal-conflict" {
				if j.Custody.State != rootCustodyRetained {
					t.Fatal("failed journal write retained an unauthenticated intent")
				}
				return
			}
			stored, _ := loadRotationJournal(t, f)
			if stored.Custody.State == rootCustodyRetired || stored.Phase != vault.RotationRetiring {
				t.Fatal("failed deletion gained receipt")
			}
			if attack == "changed-file" || attack == "replacement-after-key" {
				value, err := os.ReadFile(path)
				if err != nil || string(value) != "foreign ciphertext" {
					t.Fatal("unrelated file removed", err)
				}
			}
		})
	}
}
