package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"math"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestPrepareDevicePasswordFileLowWithoutASK(t *testing.T) {
	p, key, slots := deviceEnrollmentFixture(t)
	envelope, err := p.SealDeviceEnrollment(key, slots)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := OpenDeviceEnrollment(key, slots, slots.VaultID, slots.FileID, 1, envelope)
	if err != nil {
		t.Fatal(err)
	}
	record := metadata.record
	signed, err := vault.DecodeSignedPolicy(record.Trust.SignedProfile)
	if err != nil {
		t.Fatal(err)
	}
	signed.Policy.Profile, signed.Policy.KDF, signed.Policy.ASKRequired, signed.Policy.LowKDFApproved = vault.Default, vault.KDFLow, false, true
	org := ed25519.NewKeyFromSeed(make([]byte, 32))
	defer vault.Wipe(org)
	signed, err = vault.SignPolicy(signed.Policy, signed.SignerKeyID, signed.SignerKeyVersion, org)
	if err != nil {
		t.Fatal(err)
	}
	record.Trust.SignedProfile, err = vault.EncodeSignedPolicy(signed)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(record.Trust.SignedProfile)
	record.Trust.PolicyDigest = digest[:]
	record.KDF, record.ASKRequired = vault.KDFLow, false
	envelope, err = sealDeviceEnrollmentRecord(key, slots, record)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := EncodeDeviceEnrollmentFile(key, slots, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareDevicePasswordFile(context.Background(), key, previous, slots.VaultID, slots.FileID, 1, []byte("new"), make([]byte, 32), vault.Default, vault.Default); err == nil {
		t.Fatal("added ASK silently")
	}
	next, err := PrepareDevicePasswordFile(context.Background(), key, previous, slots.VaultID, slots.FileID, 1, []byte("new"), nil, vault.Default, vault.Default)
	if err != nil {
		t.Fatal(err)
	}
	updated, encrypted, err := DecodeDeviceEnrollmentFile(next)
	if err != nil {
		t.Fatal(err)
	}
	passwordSlot := updated.Slots[len(updated.Slots)-1]
	if passwordSlot.Preset != vault.KDFV1 || passwordSlot.ASKRequired {
		t.Fatal("pre-unlock KDF floor or factor changed")
	}
	unlocked, err := vault.OpenPasswordSlot(context.Background(), slots.VaultID, passwordSlot, []byte("new"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(unlocked)
	actual, err := OpenDeviceEnrollment(unlocked, updated, slots.VaultID, slots.FileID, 2, encrypted)
	if err != nil || actual.record.KDF != vault.KDFLow {
		t.Fatal("account KDF silently upgraded", err)
	}
	invalid := record
	invalid.SlotSequence++
	if _, err := sealDeviceEnrollmentRecord(key, slots, invalid); err == nil {
		t.Fatal("sequence mismatch")
	}
	if _, err := sealDeviceEnrollmentRecord(nil, slots, record); err == nil {
		t.Fatal("missing root")
	}
}

func devicePasswordSource(t *testing.T, p *PreparedInitialEnrollment, key []byte, slots vault.SlotFile) []byte {
	t.Helper()
	envelope, err := p.SealDeviceEnrollment(key, slots)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeDeviceEnrollmentFile(key, slots, envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPrepareDevicePasswordFileRoundtrip(t *testing.T) {
	p, key, slots := deviceEnrollmentFixture(t)
	ask := bytes.Repeat([]byte{29}, 32)
	oldPassword, newPassword := []byte("old-device-password"), []byte("new-device-password")
	old, err := vault.CreatePasswordSlot(context.Background(), slots.VaultID, uuid.NewString(), 1, key, oldPassword, ask, vault.KDFV2)
	if err != nil {
		t.Fatal(err)
	}
	// Two old slots must both disappear; the recovery slot remains byte-exact.
	slots.Slots = append(slots.Slots, old)
	second, err := vault.CreatePasswordSlot(context.Background(), slots.VaultID, uuid.NewString(), 1, key, oldPassword, ask, vault.KDFV1)
	if err != nil {
		t.Fatal(err)
	}
	slots.Slots = append(slots.Slots, second)
	slots = authenticateDeviceSlots(t, key, slots)
	previous := devicePasswordSource(t, p, key, slots)
	unchanged := bytes.Clone(previous)
	next, err := PrepareDevicePasswordFile(context.Background(), key, previous, slots.VaultID, slots.FileID, slots.Sequence, newPassword, ask, vault.Default, vault.Standard)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(previous, unchanged) {
		t.Fatal("source modified")
	}
	updated, envelope, err := DecodeDeviceEnrollmentFile(next)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Sequence != slots.Sequence+1 || updated.FileEpoch != slots.FileEpoch || updated.RootKeyID != slots.RootKeyID || len(updated.Slots) != 2 || !reflect.DeepEqual(updated.Slots[0], slots.Slots[0]) {
		t.Fatal("identity or recovery changed")
	}
	passwordSlot := updated.Slots[1]
	if passwordSlot.Preset != vault.KDFV2 || passwordSlot.ID == old.ID || passwordSlot.ID == second.ID || bytes.Equal(passwordSlot.Salt, old.Salt) {
		t.Fatal("slot reused or KDF weakened")
	}
	unlocked, err := vault.OpenPasswordSlot(context.Background(), updated.VaultID, passwordSlot, newPassword, ask)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(unlocked)
	metadata, err := OpenDeviceEnrollment(unlocked, updated, slots.VaultID, slots.FileID, updated.Sequence, envelope)
	if err != nil || metadata.Binding() != p.root.Binding() {
		t.Fatal("candidate cannot reopen", err)
	}
	d, _, err := metadata.Derivation(vault.Default, vault.Standard)
	if err != nil || d.Preset != vault.KDFV1 || !d.ASKRequired {
		t.Fatal("account derivation changed", err)
	}
	if got, err := vault.OpenPasswordSlot(context.Background(), updated.VaultID, passwordSlot, oldPassword, ask); err == nil {
		vault.Wipe(got)
		t.Fatal("old password accepted")
	}
	if got, err := vault.OpenPasswordSlot(context.Background(), updated.VaultID, passwordSlot, newPassword, nil); err == nil {
		vault.Wipe(got)
		t.Fatal("ASK removed")
	}
	recovered, err := vault.OpenRecoverySlot(updated.VaultID, updated.Slots[0], bytes.Repeat([]byte{63}, 32))
	if err != nil || !bytes.Equal(recovered, key) {
		t.Fatal("recovery broken", err)
	}
	vault.Wipe(recovered)
	if _, err := OpenDeviceEnrollment(key, slots, slots.VaultID, slots.FileID, updated.Sequence, envelope); err == nil {
		t.Fatal("old slots accepted")
	}
}

func TestPrepareDevicePasswordFileRejectsInvalidState(t *testing.T) {
	p, key, slots := deviceEnrollmentFixture(t)
	previous := devicePasswordSource(t, p, key, slots)
	for _, mode := range []string{"nil-context", "canceled", "malformed", "wrong-root", "wrong-vault", "wrong-file", "rollback", "missing-ask", "short-ask", "empty-password", "long-password", "unknown-floor", "unsupported-floor", "sequence-overflow", "full-recovery"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			root, raw := key, previous
			vaultID, fileID, sequence := slots.VaultID, slots.FileID, slots.Sequence
			password, ask := []byte("new-device-password"), bytes.Repeat([]byte{29}, 32)
			floor := vault.Standard
			switch mode {
			case "nil-context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "malformed":
				raw = []byte("{}")
			case "wrong-root":
				root = bytes.Repeat([]byte{17}, 32)
			case "wrong-vault":
				vaultID = uuid.NewString()
			case "wrong-file":
				fileID = uuid.NewString()
			case "rollback":
				sequence++
			case "missing-ask":
				ask = nil
			case "short-ask":
				ask = ask[:31]
			case "empty-password":
				password = nil
			case "long-password":
				password = bytes.Repeat([]byte{'x'}, 1025)
			case "unknown-floor":
				floor = "unknown"
			case "unsupported-floor":
				floor = vault.Paranoid
			case "sequence-overflow", "full-recovery":
				changed := slots
				if mode == "sequence-overflow" {
					changed.Sequence = math.MaxUint64
				} else {
					changed.Slots = nil
					for i := 0; i < 16; i++ {
						slot, err := vault.CreateRecoverySlot(changed.VaultID, uuid.NewString(), 1, key, bytes.Repeat([]byte{63}, 32))
						if err != nil {
							t.Fatal(err)
						}
						changed.Slots = append(changed.Slots, slot)
					}
				}
				changed = authenticateDeviceSlots(t, key, changed)
				raw = devicePasswordSource(t, p, key, changed)
			}
			if next, err := PrepareDevicePasswordFile(ctx, root, raw, vaultID, fileID, sequence, password, ask, vault.Default, floor); err == nil || next != nil {
				t.Fatal("invalid state accepted", err)
			}
		})
	}
}
