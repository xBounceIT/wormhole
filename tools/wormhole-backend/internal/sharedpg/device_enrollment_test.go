package sharedpg

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func deviceEnrollmentFixture(t *testing.T) (*PreparedInitialEnrollment, []byte, vault.SlotFile) {
	t.Helper()
	f := invitationCommitFixture(t, 1)
	commit, err := f.prepare()
	if err != nil {
		t.Fatal(err)
	}
	b := TrustBinding{WorkspaceID: f.i.WorkspaceID, UserID: f.i.Enrollment.Context.UserID, DeviceID: f.device, KeyID: uuid.New(), KeyVersion: 1}
	root, err := f.master.DeriveTrustRoot(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	p := &PreparedInitialEnrollment{master: f.master, root: root, commit: commit}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	key := bytes.Repeat([]byte{64}, 32)
	t.Cleanup(func() { vault.Wipe(key) })
	slots := vault.SlotFile{FormatVersion: 1, VaultID: uuid.NewString(), FileID: uuid.NewString(), RootKeyID: uuid.NewString(), RootKeyVersion: 1, Sequence: 1, FileEpoch: 1}
	slot, err := vault.CreateRecoverySlot(slots.VaultID, uuid.NewString(), 1, key, bytes.Repeat([]byte{63}, 32))
	if err != nil {
		t.Fatal(err)
	}
	slots.Slots = []vault.Slot{slot}
	return p, key, authenticateDeviceSlots(t, key, slots)
}

func authenticateDeviceSlots(t *testing.T, key []byte, slots vault.SlotFile) vault.SlotFile {
	t.Helper()
	raw, err := vault.EncodeSlotFile(key, slots)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := vault.DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	return actual
}

func TestDeviceEnrollmentSlotAuthentication(t *testing.T) {
	p, key, slots := deviceEnrollmentFixture(t)
	raw, err := p.SealDeviceEnrollment(key, slots)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(p.master.LoginName())) || bytes.Contains(raw, []byte(p.root.Binding().UserID.String())) {
		t.Fatal("unencrypted account metadata")
	}
	// Real slot opening produces only a candidate storage root. The combined
	// slot MAC and envelope validation must still precede account derivation.
	unlocked, err := vault.OpenRecoverySlot(slots.VaultID, slots.Slots[0], bytes.Repeat([]byte{63}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(unlocked)
	e, err := OpenDeviceEnrollment(unlocked, slots, slots.VaultID, slots.FileID, 1, raw)
	if err != nil || e.Binding() != p.root.Binding() {
		t.Fatal("protected enrollment", err)
	}
	d, policy, err := e.Derivation(vault.Default, vault.Standard)
	if err != nil || d.WorkspaceID != p.master.WorkspaceID() || d.LoginName != p.master.LoginName() || d.Preset != vault.KDFV1 || !d.ASKRequired || policy.Profile != vault.Standard {
		t.Fatal("authenticated derivation", err)
	}
	if _, _, err := e.Derivation(vault.Paranoid, vault.Default); err == nil {
		t.Fatal("stronger floor bypassed")
	}
	if _, _, err := e.Derivation("unknown", vault.Default); err == nil {
		t.Fatal("unknown floor relaxed")
	}
	encoded, err := json.Marshal(e)
	if err != nil || string(encoded) != "{}" {
		t.Fatal("native metadata serialized")
	}
	copyBinding := e.Binding()
	copyBinding.UserID = uuid.New()
	if e.Binding() == copyBinding {
		t.Fatal("binding alias")
	}
	var nilEnrollment *DeviceEnrollment
	if nilEnrollment.Binding() != (TrustBinding{}) {
		t.Fatal("nil binding")
	}
	if _, _, err := nilEnrollment.Derivation(vault.Default, vault.Default); err == nil {
		t.Fatal("nil derivation")
	}
}

func TestDeviceEnrollmentRejectsTamperAndRebinding(t *testing.T) {
	for _, mode := range []string{"root", "slot-mac", "selected-vault", "selected-file", "floor", "zero-floor", "new-sequence", "file-rebinding", "key-rebinding", "empty", "oversized", "malformed", "noncanonical", "ciphertext", "closed-preparation", "wiped-request"} {
		t.Run(mode, func(t *testing.T) {
			p, key, slots := deviceEnrollmentFixture(t)
			raw, err := p.SealDeviceEnrollment(key, slots)
			if err != nil {
				t.Fatal(err)
			}
			vaultID, fileID, minimum := slots.VaultID, slots.FileID, uint64(1)
			switch mode {
			case "root":
				key = bytes.Repeat([]byte{99}, 32)
			case "slot-mac":
				slots.Authentication[0] ^= 1
			case "selected-vault":
				vaultID = uuid.NewString()
			case "selected-file":
				fileID = uuid.NewString()
			case "floor":
				minimum = 2
			case "zero-floor":
				minimum = 0
			case "new-sequence":
				slots.Sequence++
				slots = authenticateDeviceSlots(t, key, slots)
			case "file-rebinding":
				slots.FileID = uuid.NewString()
				fileID = slots.FileID
				slots = authenticateDeviceSlots(t, key, slots)
			case "key-rebinding":
				slots.RootKeyID = uuid.NewString()
				slots = authenticateDeviceSlots(t, key, slots)
			case "empty":
				raw = nil
			case "oversized":
				raw = make([]byte, MaxDeviceEnrollmentBytes+1)
			case "malformed":
				raw = []byte("invalid")
			case "noncanonical":
				raw = append(raw, ' ')
			case "ciphertext":
				var envelope vault.Envelope
				if json.Unmarshal(raw, &envelope) != nil {
					t.Fatal("fixture")
				}
				envelope.Ciphertext[0] ^= 1
				raw, _ = json.Marshal(envelope)
			case "closed-preparation":
				if err := p.Close(); err != nil {
					t.Fatal(err)
				}
			case "wiped-request":
				p.commit.Wipe()
			}
			if mode == "closed-preparation" || mode == "wiped-request" {
				if _, err := p.SealDeviceEnrollment(key, slots); err == nil {
					t.Fatal("retired preparation sealed")
				}
				return
			}
			if e, err := OpenDeviceEnrollment(key, slots, vaultID, fileID, minimum, raw); err == nil || e != nil {
				t.Fatal("invalid metadata opened")
			}
			if mode == "root" || mode == "slot-mac" {
				if _, err := p.SealDeviceEnrollment(key, slots); err == nil {
					t.Fatal("invalid storage root sealed")
				}
			}
		})
	}
}

func TestDeviceEnrollmentAuthenticatedPayloadBounds(t *testing.T) {
	p, key, slots := deviceEnrollmentFixture(t)
	raw, err := p.SealDeviceEnrollment(key, slots)
	if err != nil {
		t.Fatal(err)
	}
	e, err := OpenDeviceEnrollment(key, slots, slots.VaultID, slots.FileID, 1, raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"version", "sequence", "binding", "login", "trust", "weak-kdf", "missing-ask", "json", "canonical", "size"} {
		t.Run(mode, func(t *testing.T) {
			r := e.record
			switch mode {
			case "version":
				r.FormatVersion++
			case "sequence":
				r.SlotSequence++
			case "binding":
				r.Binding.KeyVersion = 0
			case "login":
				r.LoginName = "UPPERCASE"
			case "trust":
				r.Trust.PolicySequence++
			case "weak-kdf":
				r.KDF = vault.KDFLow
			case "missing-ask":
				r.ASKRequired = false
			}
			plain, _ := json.Marshal(r)
			if mode == "json" {
				plain = []byte("invalid")
			}
			if mode == "canonical" {
				plain = append(plain, ' ')
			}
			if mode == "size" {
				plain = make([]byte, MaxDeviceEnrollmentBytes/2+1)
			}
			k, err := vault.DeriveKey(key, []byte(slots.FileID), vault.PurposeSharedDeviceSetup)
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(k)
			envelope, err := vault.Seal(k, deviceEnrollmentBinding(slots), plain)
			if err != nil {
				t.Fatal(err)
			}
			bad, _ := json.Marshal(envelope)
			if _, err := OpenDeviceEnrollment(key, slots, slots.VaultID, slots.FileID, 1, bad); err == nil {
				t.Fatal("invalid authenticated record opened")
			}
		})
	}
}

func TestDeviceEnrollmentFileFormat(t *testing.T) {
	p, key, slots := deviceEnrollmentFixture(t)
	envelope, err := p.SealDeviceEnrollment(key, slots)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeDeviceEnrollmentFile(key, slots, envelope)
	if err != nil {
		t.Fatal(err)
	}
	decoded, cipher, err := DecodeDeviceEnrollmentFile(raw)
	if err != nil || decoded.VaultID != slots.VaultID || !bytes.Equal(cipher, envelope) {
		t.Fatal("pair roundtrip", err)
	}
	if _, err := EncodeDeviceEnrollmentFile(nil, slots, envelope); err == nil {
		t.Fatal("unauthenticated pair encoded")
	}
	var file deviceEnrollmentFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"empty", "size", "json", "version", "canonical", "slots", "envelope-size", "envelope-empty"} {
		t.Run(mode, func(t *testing.T) {
			changed := file
			switch mode {
			case "version":
				changed.FormatVersion++
			case "slots":
				changed.Slots = json.RawMessage(`{}`)
			case "envelope-size":
				changed.Enrollment = append([]byte{'"'}, bytes.Repeat([]byte{'x'}, MaxDeviceEnrollmentBytes)...)
				changed.Enrollment = append(changed.Enrollment, '"')
			case "envelope-empty":
				changed.Enrollment = nil
			}
			bad, _ := json.Marshal(changed)
			switch mode {
			case "empty":
				bad = nil
			case "size":
				bad = make([]byte, MaxDeviceEnrollmentFileBytes+1)
			case "json":
				bad = []byte("bad")
			case "canonical":
				bad = append(bad, ' ')
			}
			if _, _, err := DecodeDeviceEnrollmentFile(bad); err == nil {
				t.Fatal("invalid pair decoded")
			}
		})
	}
}

func TestDeviceEnrollmentPasswordSlotFloor(t *testing.T) {
	p, key, slots := deviceEnrollmentFixture(t)
	password := []byte("native device unlock")
	for _, preset := range []vault.KDFPreset{vault.KDFLow, vault.KDFV1} {
		t.Run(string(preset), func(t *testing.T) {
			slot, err := vault.CreatePasswordSlot(context.Background(), slots.VaultID, uuid.NewString(), 1, key, password, nil, preset)
			if err != nil {
				t.Fatal(err)
			}
			s := slots
			s.Slots = []vault.Slot{slot}
			s = authenticateDeviceSlots(t, key, s)
			if preset == vault.KDFLow {
				if _, err := p.SealDeviceEnrollment(key, s); err != vault.ErrPolicy {
					t.Fatal("weak local password protection", err)
				}
				// A valid ciphertext produced for the same slot identity must
				// not be accepted after an authenticated slot downgrade either.
				raw, err := p.SealDeviceEnrollment(key, slots)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := OpenDeviceEnrollment(key, s, s.VaultID, s.FileID, 1, raw); err != vault.ErrPolicy {
					t.Fatal("weak slot opened metadata", err)
				}
				return
			}
			raw, err := p.SealDeviceEnrollment(key, s)
			if err != nil {
				t.Fatal(err)
			}
			unlocked, err := vault.OpenPasswordSlot(context.Background(), s.VaultID, slot, password, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(unlocked)
			if _, err := OpenDeviceEnrollment(unlocked, s, s.VaultID, s.FileID, 1, raw); err != nil {
				t.Fatal(err)
			}
		})
	}
	if deviceSlotsMeetDerivation(vault.SlotFile{}, vault.KDFV1) || deviceSlotsMeetDerivation(slots, "unknown") {
		t.Fatal("invalid floor accepted")
	}
	for _, slot := range []vault.Slot{{Kind: vault.SlotHello}, {Kind: vault.SlotPassword, Preset: "unknown"}} {
		if deviceSlotsMeetDerivation(vault.SlotFile{Slots: []vault.Slot{slot}}, vault.KDFV1) {
			t.Fatal("unsupported slot accepted")
		}
	}
}

func TestDeviceEnrollmentCommitOwnership(t *testing.T) {
	p, key, slots := deviceEnrollmentFixture(t)
	b := p.root.Binding()
	var missing *PreparedInvitationCommit
	if _, err := missing.SealDeviceEnrollment(key, slots, b); err == nil {
		t.Fatal("nil request")
	}
	changed := b
	changed.DeviceID = uuid.New()
	if _, err := p.commit.SealDeviceEnrollment(key, slots, changed); err == nil {
		t.Fatal("foreign device binding")
	}
	p.commit.Wipe()
	if _, err := p.commit.SealDeviceEnrollment(key, slots, b); err == nil {
		t.Fatal("wiped verifier sealed metadata")
	}
}
