package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestNativeRootRotationReconcilesOnlyAuthenticatedCrashCopies(t *testing.T) {
	for _, state := range []string{"source-link", "target-link", "foreign-inode", "lost-source-and-backup", "stage-directory", "journal-corrupt", "foreign-source-slots"} {
		t.Run(state, func(t *testing.T) {
			f := nativeRootRotation(t)
			ctx := context.Background()
			if err := beginLocalRootRotation(ctx, f.source, f.owner, f.slots, bytes.Clone(f.key), noRotationStop); err != nil {
				t.Fatal(err)
			}
			j, _ := loadRotationJournal(t, f)
			if state == "journal-corrupt" {
				if err := os.WriteFile(rootRotationJournalPath(f.source), []byte("malformed"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if state == "foreign-source-slots" {
				doc := j.Source
				doc.Sequence++
				raw, err := vault.EncodeSlotFile(f.old, doc)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(vaultSlotPath(f.source), raw, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				stopAt := "barrier-publishing"
				if state == "target-link" {
					stopAt = "database-published"
				}
				stop := errors.New("publication cut")
				if err := resumeLocalRootRotation(ctx, f.source, f.key, func(s string) error {
					if s == stopAt {
						return stop
					}
					return nil
				}); !errors.Is(err, stop) {
					t.Fatal(err)
				}
				switch state {
				case "source-link":
					if err := os.Link(f.source, j.backupPath()); err != nil {
						t.Fatal(err)
					}
				case "target-link":
					if err := os.Link(f.source, j.stagePath()); err != nil {
						t.Fatal(err)
					}
				case "foreign-inode":
					raw, err := os.ReadFile(f.source)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(j.backupPath(), raw, 0600); err != nil {
						t.Fatal(err)
					}
				case "lost-source-and-backup":
					if err := os.Remove(f.source); err != nil {
						t.Fatal(err)
					}
				case "stage-directory":
					if err := os.Remove(j.stagePath()); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(j.stagePath(), 0700); err != nil {
						t.Fatal(err)
					}
				}
			}
			err := resumeLocalRootRotation(ctx, f.source, f.key, noRotationStop)
			if state == "source-link" || state == "target-link" {
				if err != nil {
					t.Fatal("legitimate native link/unlink crash", err)
				}
			} else if err == nil {
				t.Fatal("unproven copy accepted")
			}
		})
	}
	if err := resumeLocalRootRotation(context.Background(), filepath.Join(t.TempDir(), "missing.db"), bytes.Repeat([]byte{8}, 32), noRotationStop); !errors.Is(err, errVaultSlotMissing) {
		t.Fatal(err)
	}
}

func TestNativeRootRotationEncryptedBodyStillRequiresCanonicalAuthority(t *testing.T) {
	f := nativeRootRotation(t)
	ctx := context.Background()
	if err := beginLocalRootRotation(ctx, f.source, f.owner, f.slots, bytes.Clone(f.key), noRotationStop); err != nil {
		t.Fatal(err)
	}
	j, raw := loadRotationJournal(t, f)
	for _, chunkJSON := range []string{"null", "{}", "[null", "[1]", "[]{}", "[{},{},{}]", "[" + strings.Repeat("{},", 10000) + "{}]"} {
		var chunks rootRotationChunks
		if err := chunks.UnmarshalJSON([]byte(chunkJSON)); err == nil {
			t.Fatal("unbounded or invalid chunk array", chunkJSON[:min(20, len(chunkJSON))])
		}
	}
	for _, change := range []string{"invalid-json", "noncanonical-body", "different-id", "different-target", "short-part"} {
		c, err := decodeRootRotationCapsule(raw)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(j)
		switch change {
		case "invalid-json":
			body = []byte("{")
		case "noncanonical-body":
			body = append(body, ' ')
		case "different-id":
			copy := j
			copy.ID = "22222222-2222-4222-8222-222222222222"
			body, _ = json.Marshal(copy)
		case "different-target":
			copy := j
			copy.Target.Sequence++
			body, _ = json.Marshal(copy)
		}
		c.Bytes = len(body)
		c.Chunks = make([]vault.Envelope, 1)
		if change == "short-part" {
			c.Bytes++
		}
		subkey, err := vault.DeriveKey(f.key, []byte(j.Target.VaultID), vault.PurposeLocalSeal)
		if err != nil {
			t.Fatal(err)
		}
		c.Chunks[0], err = vault.Seal(subkey, rootRotationChunkBinding(c, 0), body)
		vault.Wipe(subkey)
		vault.Wipe(body)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(c)
		if _, err := decodeRootRotationJournal(ctx, encoded, f.key); err == nil {
			t.Fatal("encrypted body bypass", change)
		}
	}
	// A valid target MAC cannot authorize removal of required factors.
	copy := j
	copy.Target.Slots = copy.Target.Slots[1:]
	encoded, err := vault.EncodeSlotFile(f.key, copy.Target)
	if err != nil {
		t.Fatal(err)
	}
	copy.Target, _ = vault.DecodeSlotFile(encoded)
	if old, err := authenticateRootRotationJournal(copy, f.key); err != vault.ErrPolicy {
		vault.Wipe(old)
		t.Fatal("recovery-only target accepted", err)
	}
}

func TestNativeRootRotationFingerprintAndRemovalBoundaries(t *testing.T) {
	dir := t.TempDir()
	f, err := openLegacyPublicationFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.root.Close()
	ctx := context.Background()
	path := filepath.Join(dir, "copy.db")
	write := func(raw []byte) {
		t.Helper()
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(bytes.Repeat([]byte{0x61}, 1024))
	fingerprint, err := rootRotationFileFingerprint(ctx, f, path, true)
	if err != nil || fingerprint.Bytes != 1024 {
		t.Fatal(fingerprint, err)
	}
	if err := verifyRootRotationFile(ctx, f, path, fingerprint); err != nil {
		t.Fatal(err)
	}
	wrong := fingerprint
	wrong.Bytes++
	if err := verifyRootRotationFile(ctx, f, path, wrong); err != vault.ErrAuthentication {
		t.Fatal("wrong fingerprint", err)
	}
	if err := removeRootRotationFile(ctx, f, path, wrong); err != vault.ErrAuthentication {
		t.Fatal("removed foreign file", err)
	}
	if _, err := rootRotationFileFingerprint(ctx, f, filepath.Join(t.TempDir(), "outside.db"), false); err != vault.ErrPolicy {
		t.Fatal("path escaped", err)
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		if err := os.WriteFile(path+suffix, nil, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := rootRotationFileFingerprint(ctx, f, path, false); err != errVaultSlotStorage {
			t.Fatal("active SQLite sidecar accepted", err)
		}
		if err := os.Remove(path + suffix); err != nil {
			t.Fatal(err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := rootRotationFileFingerprint(cancelled, f, path, false); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := removeRootRotationFile(cancelled, f, path, fingerprint); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := removeRootRotationFile(ctx, f, path, fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := removeRootRotationFile(ctx, f, path, fingerprint); err != nil {
		t.Fatal("removal replay", err)
	}
	if _, err := rootRotationFileFingerprint(ctx, f, path, false); err != errVaultSlotStorage {
		t.Fatal("missing file", err)
	}
	write([]byte("tiny"))
	if _, err := rootRotationFileFingerprint(ctx, f, path, false); err != errVaultSlotStorage {
		t.Fatal("short file", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := rootRotationFileFingerprint(ctx, f, path, false); err != errVaultSlotStorage {
		t.Fatal("directory", err)
	}
	if err := removeRootRotationFile(ctx, f, path, fingerprint); err != errVaultSlotStorage {
		t.Fatal("directory removal", err)
	}
	if err := f.root.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := rootRotationFileFingerprint(ctx, f, path, false); err == nil {
		t.Fatal("closed native root")
	}
}

func TestNativeRootRotationAdmissionCancellationAndMissingAuthority(t *testing.T) {
	f := nativeRootRotation(t)
	ctx := context.Background()
	for _, run := range []func([]byte) error{
		func(key []byte) error {
			return beginLocalRootRotation(ctx, f.source, nil, f.slots, key, noRotationStop)
		},
		func(key []byte) error { return beginLocalRootRotation(ctx, f.source, f.owner, f.slots, key, nil) },
		func(key []byte) error {
			return beginLocalRootRotation(ctx, filepath.Join(f.source, "missing.db"), f.owner, f.slots, key, noRotationStop)
		},
	} {
		key := bytes.Clone(f.key)
		if err := run(key); err == nil {
			t.Fatal("invalid admission")
		}
		if !bytes.Equal(key, make([]byte, 32)) {
			t.Fatal("key retained after admission denial")
		}
	}
	noSlots := filepath.Join(filepath.Dir(f.source), "no-slots.db")
	if err := os.WriteFile(noSlots, bytes.Repeat([]byte{1}, 512), 0600); err != nil {
		t.Fatal(err)
	}
	if err := beginLocalRootRotation(ctx, noSlots, f.owner, f.slots, bytes.Clone(f.key), noRotationStop); !errors.Is(err, errVaultSlotMissing) {
		t.Fatal("missing source authentication", err)
	}
	if err := resumeLocalRootRotation(ctx, f.source, f.key, nil); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	if err := resumeLocalRootRotation(ctx, f.source, f.key, noRotationStop); err != vault.ErrPolicy {
		t.Fatal("ordinary source treated as completed rotation", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := beginLocalRootRotation(cancelled, f.source, f.owner, f.slots, bytes.Clone(f.key), noRotationStop); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := f.owner.Put(ctx, f.ref, []byte("still usable before acceptance"), 1); err != nil {
		t.Fatal("admission denial retired source", err)
	}
	if err := beginLocalRootRotation(ctx, f.source, f.owner, f.slots, bytes.Clone(f.key), noRotationStop); err != nil {
		t.Fatal(err)
	}
	j, _ := loadRotationJournal(t, f)
	if err := beginLocalRootRotation(ctx, f.source, f.owner, f.slots, bytes.Clone(f.key), noRotationStop); err != vault.ErrPolicy {
		t.Fatal("duplicate rotation", err)
	}
	if err := resumeLocalRootRotation(cancelled, f.source, f.key, noRotationStop); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	next := j.Source
	next.Sequence++
	if err := writeVaultSlotFile(f.source, f.old, next, j.Source.Sequence); err != vault.ErrPolicy {
		t.Fatal("ordinary writer during journal", err)
	}
	if err := os.Remove(rootRotationJournalPath(f.source)); err != nil {
		t.Fatal(err)
	}
	if requireNoRootRotation(f.source) != vault.ErrPolicy {
		t.Fatal("lost journal enabled source barrier")
	}
	if err := resumeLocalRootRotation(ctx, f.source, f.key, noRotationStop); err != vault.ErrPolicy {
		t.Fatal("lost journal accepted", err)
	}
}

func TestNativeRootRotationBarrierScopeAndCanonicalCapsule(t *testing.T) {
	f := nativeRootRotation(t)
	ctx := context.Background()
	if err := beginLocalRootRotation(ctx, f.source, f.owner, f.slots, bytes.Clone(f.key), noRotationStop); err != nil {
		t.Fatal(err)
	}
	j, raw := loadRotationJournal(t, f)
	nativeFS, err := openLegacyPublicationFS(filepath.Dir(f.source))
	if err != nil {
		t.Fatal(err)
	}
	defer nativeFS.root.Close()
	if _, err := rootRotationBarrier(j, "unknown", f.old); err != vault.ErrFormat {
		t.Fatal(err)
	}
	lock, err := tryAcquireExclusiveFileLock(vaultSlotPath(f.source) + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeRootRotationBarrier(nativeFS, j, f.old); err != errVaultSlotConflict {
		t.Fatal("slot lock ignored", err)
	}
	lock()
	if err := os.WriteFile(vaultSlotPath(f.source), []byte("malformed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeRootRotationBarrier(nativeFS, j, f.old); err == nil {
		t.Fatal("malformed source replaced")
	}
	final, _ := vault.EncodeSlotFile(f.key, j.Target)
	if err := os.WriteFile(vaultSlotPath(f.source), final, 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeRootRotationBarrier(nativeFS, j, f.old); err != vault.ErrRollback {
		t.Fatal("final source accepted in old phase", err)
	}
	j.Phase = vault.RotationPublishing
	if err := writeRootRotationBarrier(nativeFS, j, f.old); err != nil {
		t.Fatal("final source replay", err)
	}
	for _, mutate := range []func(*rootRotationCapsule){
		func(c *rootRotationCapsule) { c.Document.FormatVersion = 4 },
		func(c *rootRotationCapsule) { c.Document.Initializing = true },
		func(c *rootRotationCapsule) { c.Bytes = 0 },
		func(c *rootRotationCapsule) { c.ID = "bad" },
	} {
		c, _ := decodeRootRotationCapsule(raw)
		mutate(&c)
		body, _ := json.Marshal(c)
		if _, err := decodeRootRotationCapsule(body); err == nil {
			t.Fatal("unsupported bootstrap")
		}
	}
	// A capsule encrypted with a valid key must still match the duplicated native
	// authority. Re-encrypting modified body data cannot bypass that comparison.
	j.ID = "bad"
	if _, err := authenticateRootRotationJournal(j, f.key); err != vault.ErrFormat {
		t.Fatal(err)
	}
}
