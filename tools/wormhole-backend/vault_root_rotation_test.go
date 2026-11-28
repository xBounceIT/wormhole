package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type nativeRotationFixture struct {
	source   string
	owner    *localvault.Owner
	key, old []byte
	slots    []vault.Slot
	ref      vaultstore.SecretRef
	release  func()
}

func nativeRootRotation(t *testing.T) nativeRotationFixture {
	t.Helper()
	return nativeRootRotationMode(t, false)
}

func nativeRootRotationMode(t *testing.T, encrypted bool) nativeRotationFixture {
	t.Helper()
	source := filepath.Join(t.TempDir(), "workspace.db")
	return nativeRootRotationAt(t, source, encrypted)
}

func nativeRootRotationAt(t *testing.T, source string, encrypted bool) nativeRotationFixture {
	t.Helper()
	ctx := context.Background()
	doc, old := localSlotFixture(t)
	doc.Nodes, doc.ProfileSequence, doc.Initializing = nil, 0, true
	doc.Encrypted = encrypted
	o, err := initializeVaultFiles(ctx, source, doc, old)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { o.Close() })
	release, err := acquireWorkspaceOwnership(source, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	ref := vaultstore.SecretRef{OwnerKind: "slot-value", OwnerID: uuid.NewString(), Field: "password"}
	if _, err := o.Put(ctx, ref, []byte("native root transition private value"), 0); err != nil {
		t.Fatal(err)
	}
	key := vault.NewRecoveryKey()
	t.Cleanup(func() { vault.Wipe(key); vault.Wipe(old) })
	p, err := vault.CreatePasswordSlot(ctx, doc.VaultID, uuid.NewString(), 2, key, []byte("new native transition password"), nil, vault.KDFV1)
	if err != nil {
		t.Fatal(err)
	}
	r, err := vault.CreateRecoverySlot(doc.VaultID, uuid.NewString(), 2, key, bytes.Repeat([]byte{0x7a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return nativeRotationFixture{source: source, owner: o, key: key, old: old, slots: []vault.Slot{p, r}, ref: ref, release: release}
}

func TestVaultRootRotationRetiresBiometricSlotsAfterAnInterruption(t *testing.T) {
	for _, mode := range []string{"hello-rekey", "attested-hello-rekey", "touch-id-encrypt"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			f := nativeRootRotation(t)
			before, err := readVaultSlotFile(f.source)
			if err != nil {
				t.Fatal(err)
			}
			id := uuid.NewString()
			persist := func(next vault.SlotFile, root []byte) error {
				return writeVaultSlotFile(f.source, root, next, before.Sequence)
			}
			if mode != "touch-id-encrypt" {
				private, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				credential := &helloHandlerCredential{key: private}
				if mode == "attested-hello-rekey" {
					credential.attestation = vault.HelloAttestationTPMVerified
				}
				if err := f.owner.EnrollHelloSlot(ctx, before, id, credential, persist); err != nil {
					t.Fatal(err)
				}
			} else if err := f.owner.EnrollTouchIDSlot(ctx, before, id, func(context.Context) ([]byte, error) {
				return bytes.Repeat([]byte{8}, 32), nil
			}, persist); err != nil {
				t.Fatal(err)
			}
			withBiometric, err := readVaultSlotFile(f.source)
			if err != nil || withBiometric.FormatVersion <= vault.SlotFileFormatVersion {
				t.Fatal("fixture lacks the biometric source", err)
			}
			encrypt := mode == "touch-id-encrypt"
			if err := beginLocalRootRotationMode(ctx, f.source, f.owner, f.slots, bytes.Clone(f.key), noRotationStop, encrypt); err != nil {
				t.Fatal("biometric enrollment prevented software-authorized root rotation", err)
			}
			j, _ := loadRotationJournal(t, f)
			if !sameRootRotationDocument(j.Source, withBiometric) || j.Target.FormatVersion != vault.SlotFileFormatVersion || j.Target.Encrypted != encrypt {
				t.Fatal("rotation lost authenticated source or target coordinates")
			}
			interrupted := errors.New("after native custody cleanup attempt")
			err = resumeLocalRootRotation(ctx, f.source, f.key, func(point string) error {
				if point == "biometric-custody-checked" {
					return interrupted
				}
				return nil
			})
			if !errors.Is(err, interrupted) {
				t.Fatal("root publication did not check biometric cleanup", err)
			}
			barrier, err := readVaultSlotFile(f.source)
			if err != nil || barrier.FormatVersion != withBiometric.FormatVersion || barrier.Rotation == nil || barrier.Rotation.Phase != vault.RotationPublishing {
				t.Fatal("the source barrier did not survive the interruption", err)
			}
			f.release()
			h := &vaultFoundationHandler{databasePath: f.source, migrationQuiesced: true}
			defer h.Close()
			if _, err := h.Handle(ctx, "rotation-resume", rootRotationUnlockInput(t, j.Target, true)); err != nil || h.owner == nil {
				t.Fatal("the replacement recovery code did not finish publication", err)
			}
			final, err := readVaultSlotFile(f.source)
			if err != nil || final.Rotation != nil || !sameRootRotationDocument(final, j.Target) || len(final.Slots) != 2 {
				t.Fatal("an old biometric slot survived in the new root epoch", err)
			}
			if _, err := os.Lstat(rootRotationJournalPath(f.source)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("the journal remained after successful publication", err)
			}
		})
	}
}

func TestVaultRootRotationKeepsEncryptedStorageAcrossRestarts(t *testing.T) {
	for _, mode := range []string{"conversion", "rekey"} {
		t.Run(mode, func(t *testing.T) {
			for _, cut := range []string{"journal-prepared", "source-retired", "slots-published", "journal-removed"} {
				t.Run(cut, func(t *testing.T) {
					f := nativeRootRotationMode(t, mode == "rekey")
					ctx := context.Background()
					node := vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "metadata-confidential-after-conversion", Kind: 0}
					if _, err := f.owner.PutNode(ctx, node, nil, 0); err != nil {
						t.Fatal(err)
					}
					stop := errors.New("durable interruption")
					step := func(point string) error {
						if point == cut {
							return stop
						}
						return nil
					}
					var err error
					if mode == "conversion" {
						err = beginLocalRootRotationMode(ctx, f.source, f.owner, f.slots, bytes.Clone(f.key), step, true)
					} else {
						err = beginLocalRootRotation(ctx, f.source, f.owner, f.slots, bytes.Clone(f.key), step)
					}
					if cut == "journal-prepared" {
						if !errors.Is(err, stop) {
							t.Fatal(err)
						}
					} else if err != nil {
						t.Fatal(err)
					}
					j, _ := loadRotationJournal(t, f)
					if !j.Target.Encrypted || j.Source.Encrypted != (mode == "rekey") {
						t.Fatal("journal does not authenticate the expected storage modes")
					}
					if mode == "rekey" && cut == "journal-prepared" {
						downgrade := j
						downgrade.Target.Encrypted = false
						old, err := authenticateRootRotationJournal(downgrade, f.key)
						vault.Wipe(old)
						if !errors.Is(err, vault.ErrFormat) {
							t.Fatalf("journal admitted a plaintext target: %v", err)
						}
					}
					staged, err := os.ReadFile(j.stagePath())
					if err != nil || len(staged) == 0 || bytes.Contains(staged, []byte(node.Name)) || bytes.HasPrefix(staged, []byte("SQLite format 3")) {
						t.Fatal("staging exposed metadata", err)
					}
					if cut != "journal-prepared" {
						if err := resumeLocalRootRotation(ctx, f.source, f.key, step); !errors.Is(err, stop) {
							t.Fatal("publication interruption", err)
						}
					}
					if cut == "journal-removed" {
						if err := resumeLocalRootRotation(ctx, f.source, f.key, noRotationStop); err != nil {
							t.Fatal("lost acknowledgement", err)
						}
						f.release()
					} else {
						f.release()
						resume := &vaultFoundationHandler{databasePath: f.source, migrationQuiesced: true}
						defer resume.Close()
						if _, err := resume.Handle(ctx, "rotation-resume", rootRotationUnlockInput(t, j.Target, true)); err != nil {
							t.Fatal("resumption through the native unlock handler", err)
						}
						if err := resume.Close(); err != nil {
							t.Fatal(err)
						}
					}
					final, err := readVaultSlotFile(f.source)
					if err != nil || !final.Encrypted || final.RootKeyVersion != 2 || final.Rotation != nil {
						t.Fatal("invalid encryption checkpoint", err)
					}
					if _, err := vaultstore.OpenSQLiteEncrypted(ctx, f.source, localVaultOptions(final).Identity, false, f.old); !errors.Is(err, vaultstore.ErrStorage) {
						t.Fatalf("old page key opened the published database: %v", err)
					}
					o, err := openVaultFiles(ctx, f.source, final, f.key)
					if err != nil {
						t.Fatal(err)
					}
					defer o.Close()
					record, err := o.ReadNode(ctx, node.ID, 1)
					if err != nil || record.Name != node.Name {
						t.Fatal("node was lost in rotation", err)
					}
					if err := o.WithSecret(ctx, f.ref, 1, func(value []byte) error {
						if string(value) != "native root transition private value" {
							return vault.ErrAuthentication
						}
						return nil
					}); err != nil {
						t.Fatal("secret was lost in rotation", err)
					}
					for _, path := range []string{j.stagePath(), j.backupPath(), rootRotationJournalPath(f.source)} {
						if _, err := os.Lstat(path); !os.IsNotExist(err) {
							t.Fatal("retired copy retained", err)
						}
					}
				})
			}
		})
	}
}

func noRotationStop(string) error { return nil }

func loadRotationJournal(t *testing.T, f nativeRotationFixture) (rootRotationJournal, []byte) {
	t.Helper()
	raw, err := os.ReadFile(rootRotationJournalPath(f.source))
	if err != nil {
		t.Fatal(err)
	}
	j, err := decodeRootRotationJournal(context.Background(), raw, f.key)
	if err != nil {
		t.Fatal(err)
	}
	return j, raw
}

func TestNativeRootRotationResumesEveryDurableBoundary(t *testing.T) {
	for _, stopAt := range []string{"journal-prepared", "barrier-prepared", "journal-retiring", "barrier-retiring", "journal-publishing", "barrier-publishing", "source-retired", "database-published", "old-copies-removed", "slots-published", "journal-removed"} {
		t.Run(stopAt, func(t *testing.T) {
			f := nativeRootRotation(t)
			ctx := context.Background()
			stop := errors.New("simulated process exit")
			callback := func(s string) error {
				if release, err := acquireWorkspaceOwnership(f.source, true); err == nil {
					release()
					t.Fatal("lost workspace ownership")
				}
				if s != "journal-removed" && requireNoRootRotation(f.source) == nil {
					t.Fatal("ordinary entry enabled during transition")
				}
				if s == stopAt {
					return stop
				}
				return nil
			}
			input := bytes.Clone(f.key)
			err := beginLocalRootRotation(ctx, f.source, f.owner, f.slots, input, callback)
			if !bytes.Equal(input, make([]byte, 32)) {
				t.Fatal("new root input retained")
			}
			if stopAt == "journal-prepared" || stopAt == "barrier-prepared" {
				if !errors.Is(err, stop) {
					t.Fatal("wrong preparation stop", err)
				}
			} else {
				if err != nil {
					t.Fatal("prepare", err)
				}
				err = resumeLocalRootRotation(ctx, f.source, f.key, callback)
				if !errors.Is(err, stop) {
					t.Fatal("wrong publication stop", err)
				}
			}
			if _, err := f.owner.Put(ctx, f.ref, []byte("late old write"), 1); !errors.Is(err, vaultstore.ErrClosed) {
				t.Fatal("retired source writer remained live", err)
			}
			if err := resumeLocalRootRotation(ctx, f.source, f.key, noRotationStop); err != nil {
				t.Fatal("resume", err)
			}
			doc, err := readVaultSlotFile(f.source)
			if err != nil || doc.RootKeyVersion != 2 || doc.Rotation != nil {
				t.Fatal("incomplete final slots", err)
			}
			if err := vault.VerifySlotFile(f.old, doc, doc.VaultID, doc.FileID, 0); err == nil {
				t.Fatal("old root authenticates final slots")
			}
			o, err := openVaultFiles(ctx, f.source, doc, f.key)
			if err != nil {
				t.Fatal("final unlock", err)
			}
			defer o.Close()
			if err := o.WithSecret(ctx, f.ref, 1, func(value []byte) error {
				if string(value) != "native root transition private value" {
					return vault.ErrAuthentication
				}
				return nil
			}); err != nil {
				t.Fatal("secret lost", err)
			}
			if err := requireNoRootRotation(f.source); err != nil {
				t.Fatal("journal survived", err)
			}
			files, err := os.ReadDir(filepath.Dir(f.source))
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range files {
				if strings.Contains(file.Name(), ".rotating-") || strings.Contains(file.Name(), ".retired-") {
					t.Fatal("old copy survived", file.Name())
				}
			}
		})
	}
}

func TestNativeRootRotationQuarantinesEveryOrdinaryEntry(t *testing.T) {
	f := nativeRootRotation(t)
	ctx := context.Background()
	stop := errors.New("stop before barrier")
	if err := beginLocalRootRotation(ctx, f.source, f.owner, f.slots, bytes.Clone(f.key), func(string) error { return stop }); !errors.Is(err, stop) {
		t.Fatal(err)
	}
	j, raw := loadRotationJournal(t, f)
	if bytes.Contains(raw, []byte(f.source)) || bytes.Contains(raw, f.old) || bytes.Contains(raw, f.key) || bytes.Contains(raw, []byte("private value")) || bytes.Contains(raw, []byte("sourceRecovery")) {
		t.Fatal("private journal data exposed")
	}
	if _, err := openVaultFiles(ctx, f.source, j.Source, f.old); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("pre-barrier unlock", err)
	}
	if requireLegacySlotAbsent(f.source) != errVaultOwnerRequired {
		t.Fatal("legacy access restored")
	}
	if requireNewVaultWorkspace(f.source) != vault.ErrPolicy {
		t.Fatal("initialization bypass")
	}
	h := &vaultFoundationHandler{databasePath: f.source}
	defer h.Close()
	metadata, err := h.startup(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var startup vaultStartupMetadata
	if err := json.Unmarshal(metadata, &startup); err != nil || startup.Rotation == nil || !startup.Rotation.Pending || startup.Slots == nil || startup.Slots.Slots[0].ID != j.Target.Slots[0].ID || h.owner != nil {
		t.Fatal("startup offered ordinary unlock", err)
	}
	if _, err := h.open(ctx, "unlock", []byte(`{}`)); err != vault.ErrPolicy {
		t.Fatal("unlock bypass", err)
	}
	for _, malformed := range []bool{false, true} {
		if malformed {
			if err := os.WriteFile(rootRotationJournalPath(f.source), []byte("corrupt"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if requireNoRootRotation(f.source) != vault.ErrPolicy {
			t.Fatal("invalid journal enabled old unlock")
		}
	}
	if err := os.Remove(rootRotationJournalPath(f.source)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(rootRotationJournalPath(f.source), 0700); err != nil {
		t.Fatal(err)
	}
	if requireNoRootRotation(f.source) != vault.ErrPolicy {
		t.Fatal("directory enabled old unlock")
	}
}

func TestNativeRootRotationRejectsFileSubstitutionAndJournalReplay(t *testing.T) {
	for _, attack := range []string{"source", "stage", "missing-stage", "journal-replay", "barrier-tamper", "foreign-backup", "path-rebind", "wrong-key"} {
		t.Run(attack, func(t *testing.T) {
			f := nativeRootRotation(t)
			ctx := context.Background()
			if err := beginLocalRootRotation(ctx, f.source, f.owner, f.slots, bytes.Clone(f.key), noRotationStop); err != nil {
				t.Fatal(err)
			}
			j, raw := loadRotationJournal(t, f)
			key := f.key
			switch attack {
			case "source", "stage":
				path := f.source
				if attack == "stage" {
					path = j.stagePath()
				}
				file, err := os.OpenFile(path, os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = file.WriteAt([]byte{0x7e}, 511)
				file.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "missing-stage":
				if err := os.Remove(j.stagePath()); err != nil {
					t.Fatal(err)
				}
			case "journal-replay":
				stop := errors.New("retiring")
				if err := resumeLocalRootRotation(ctx, f.source, key, func(s string) error {
					if s == "barrier-retiring" {
						return stop
					}
					return nil
				}); !errors.Is(err, stop) {
					t.Fatal(err)
				}
				if err := os.WriteFile(rootRotationJournalPath(f.source), raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "barrier-tamper":
				doc, _ := readVaultSlotFile(f.source)
				doc.Sequence++
				raw, _ := vault.EncodeSlotFile(f.old, doc)
				if err := os.WriteFile(vaultSlotPath(f.source), raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign-backup":
				if err := os.WriteFile(j.backupPath(), bytes.Repeat([]byte{8}, 1024), 0600); err != nil {
					t.Fatal(err)
				}
			case "path-rebind":
				j.SourcePath = filepath.Join(filepath.Dir(f.source), "other.db")
				raw, err := encodeRootRotationJournal(ctx, j, key)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(rootRotationJournalPath(f.source), raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-key":
				key = bytes.Repeat([]byte{0x31}, 32)
			}
			before, _ := os.ReadFile(vaultSlotPath(f.source))
			if err := resumeLocalRootRotation(ctx, f.source, key, noRotationStop); err == nil {
				t.Fatal("attack accepted")
			}
			after, _ := os.ReadFile(vaultSlotPath(f.source))
			if !bytes.Equal(before, after) {
				t.Fatal("denied publication advanced source slots")
			}
			if requireNoRootRotation(f.source) != vault.ErrPolicy {
				t.Fatal("denial enabled old unlock")
			}
		})
	}
}

func TestNativeRootRotationCapsuleRejectsAlternateInterpretations(t *testing.T) {
	f := nativeRootRotation(t)
	ctx := context.Background()
	if err := beginLocalRootRotation(ctx, f.source, f.owner, f.slots, bytes.Clone(f.key), noRotationStop); err != nil {
		t.Fatal(err)
	}
	j, raw := loadRotationJournal(t, f)
	for _, bad := range [][]byte{nil, []byte("null"), []byte(`{"version":1,"version":1}`), append(bytes.Clone(raw), ' '), bytes.Replace(raw, []byte(`"version":1`), []byte(`"Version":1`), 1), bytes.Repeat([]byte{' '}, maxRootRotationJournalBytes+1)} {
		if _, err := decodeRootRotationJournal(ctx, bad, f.key); err == nil {
			t.Fatal("alternate capsule accepted")
		}
	}
	for _, mutate := range []func(*rootRotationCapsule){
		func(c *rootRotationCapsule) { c.Version++ },
		func(c *rootRotationCapsule) { c.ID = uuid.NewString() },
		func(c *rootRotationCapsule) { c.Bytes++ },
		func(c *rootRotationCapsule) { c.Chunks = nil },
		func(c *rootRotationCapsule) { c.Chunks[0].Ciphertext[0] ^= 1 },
		func(c *rootRotationCapsule) { c.Document.Sequence++ },
	} {
		c, _ := decodeRootRotationCapsule(raw)
		mutate(&c)
		bad, _ := json.Marshal(c)
		if _, err := decodeRootRotationJournal(ctx, bad, f.key); err == nil {
			t.Fatal("tampered capsule accepted")
		}
	}
	for _, mutate := range []func(*rootRotationJournal){
		func(j *rootRotationJournal) { j.Version++ },
		func(j *rootRotationJournal) { j.ID = "bad" },
		func(j *rootRotationJournal) { j.Phase = "bad" },
		func(j *rootRotationJournal) { j.SourcePath = "../workspace.db" },
		func(j *rootRotationJournal) { j.SourceDatabase.Bytes = 1 },
		func(j *rootRotationJournal) { j.TargetDatabase.Digest = strings.Repeat("A", 64) },
		func(j *rootRotationJournal) { j.Target.Sequence++ },
		func(j *rootRotationJournal) { j.Target.FileEpoch++ },
		func(j *rootRotationJournal) { j.SourceRecovery.Ciphertext[0] ^= 1 },
	} {
		detachedRaw, _ := json.Marshal(j)
		var changed rootRotationJournal
		json.Unmarshal(detachedRaw, &changed)
		mutate(&changed)
		if _, err := encodeRootRotationJournal(ctx, changed, f.key); err == nil {
			t.Fatal("invalid native journal encoded")
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := encodeRootRotationJournal(cancelled, j, f.key); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := decodeRootRotationJournal(cancelled, raw, f.key); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
