package sharedpg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"math"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type deviceTransitionFixture struct {
	old, next, storage, trust, setup, source, target, ask []byte
	b                                                     TrustBinding
	state                                                 TrustState
	slots                                                 vault.SlotFile
}

func newDeviceTransitionFixture(t *testing.T) deviceTransitionFixture {
	t.Helper()
	old, _, b, state, trust, setup := transportTransitionFixture(t)
	p, storage, slots := deviceEnrollmentFixture(t)
	raw, err := p.SealDeviceEnrollment(storage, slots)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := OpenDeviceEnrollment(storage, slots, slots.VaultID, slots.FileID, 1, raw)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := state.Policy()
	if err != nil {
		t.Fatal(err)
	}
	metadata.record.Binding, metadata.record.Trust = b, state
	metadata.record.KDF, metadata.record.ASKRequired = policy.KDF, policy.ASKRequired
	var ask []byte
	if policy.ASKRequired {
		ask = bytes.Repeat([]byte{27}, 32)
	}
	raw, err = sealDeviceEnrollmentRecord(storage, slots, metadata.record)
	if err != nil {
		t.Fatal(err)
	}
	source, err := EncodeDeviceEnrollmentFile(storage, slots, raw)
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("transition-new-password")
	target, err := PrepareDevicePasswordFile(context.Background(), storage, source, slots.VaultID, slots.FileID, 1, password, ask, vault.Default, vault.Default)
	if err != nil {
		t.Fatal(err)
	}
	d, policy, err := metadata.Derivation(vault.Default, vault.Default)
	if err != nil {
		t.Fatal(err)
	}
	master, err := DeriveAccountMaster(context.Background(), d, policy, password, ask)
	if err != nil {
		t.Fatal(err)
	}
	root, err := master.DeriveTrustRoot(context.Background(), b)
	if err != nil {
		master.Close()
		t.Fatal(err)
	}
	var next []byte
	if err := root.Use(func(key []byte) error { next = bytes.Clone(key); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if err := master.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vault.Wipe(next) })
	return deviceTransitionFixture{old, next, storage, trust, setup, source, target, ask, b, state, slots}
}

func TestDeviceRootTransitionPreparationValidation(t *testing.T) {
	f := newDeviceTransitionFixture(t)
	for _, mode := range []string{"bad-source", "bad-storage", "bad-target", "wrong-binding", "overflow", "old-sequence", "skipped-sequence", "changed-login", "changed-epoch", "removed-recovery", "bad-trust", "bad-setup"} {
		t.Run(mode, func(t *testing.T) {
			g := f
			switch mode {
			case "bad-source":
				g.source = []byte("{}")
			case "bad-storage":
				g.storage = bytes.Repeat([]byte{22}, 32)
			case "bad-target":
				g.target = []byte("{}")
			case "wrong-binding":
				g.b.KeyID = uuid.New()
			case "old-sequence":
				g.target = g.source
			case "bad-trust":
				g.trust = []byte("{}")
			case "bad-setup":
				g.setup = []byte("{}")
			default:
				raw := g.target
				if mode == "overflow" {
					raw = g.source
				}
				slots, envelope, err := DecodeDeviceEnrollmentFile(raw)
				if err != nil {
					t.Fatal(err)
				}
				metadata, err := OpenDeviceEnrollment(g.storage, slots, slots.VaultID, slots.FileID, 1, envelope)
				if err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "overflow":
					slots.Sequence = math.MaxUint64
					metadata.record.SlotSequence = slots.Sequence
				case "skipped-sequence":
					slots.Sequence++
					metadata.record.SlotSequence = slots.Sequence
				case "changed-login":
					metadata.record.LoginName = "someone-else"
				case "changed-epoch":
					slots.FileEpoch++
				case "removed-recovery":
					slots.Slots = slots.Slots[1:]
				}
				slots = authenticateDeviceSlots(t, g.storage, slots)
				envelope, err = sealDeviceEnrollmentRecord(g.storage, slots, metadata.record)
				if err != nil {
					t.Fatal(err)
				}
				raw, err = EncodeDeviceEnrollmentFile(g.storage, slots, envelope)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "overflow" {
					g.source = raw
				} else {
					g.target = raw
				}
			}
			if _, raw, err := g.prepare(g.setup); err == nil || raw != nil {
				t.Fatal("invalid transition", err)
			}
		})
	}
}

func TestDevicePasswordSlotsAdvance(t *testing.T) {
	old := vault.Slot{ID: "old", Kind: vault.SlotPassword, Preset: vault.KDFV2, Salt: []byte("old-salt")}
	next := vault.Slot{ID: "new", Kind: vault.SlotPassword, Preset: vault.KDFV2, Salt: []byte("new-salt"), ASKRequired: true}
	if !devicePasswordSlotsAdvance([]vault.Slot{old}, []vault.Slot{next}, true) {
		t.Fatal("valid replacement")
	}
	for _, mode := range []string{"missing", "duplicate", "unsupported", "ask", "low", "unknown", "downgrade", "same-id", "same-salt", "old-unknown"} {
		p, n := old, next
		slots := []vault.Slot{n}
		switch mode {
		case "missing":
			slots = nil
		case "duplicate":
			slots = append(slots, n)
		case "unsupported":
			n.Kind = vault.SlotAND
		case "ask":
			n.ASKRequired = false
		case "low":
			n.Preset = vault.KDFLow
		case "unknown":
			n.Preset = "unknown"
		case "downgrade":
			n.Preset = vault.KDFV1
		case "same-id":
			n.ID = p.ID
		case "same-salt":
			n.Salt = p.Salt
		case "old-unknown":
			p.Preset = "unknown"
		}
		if len(slots) > 0 {
			slots[0] = n
		}
		if devicePasswordSlotsAdvance([]vault.Slot{p}, slots, true) {
			t.Fatal(mode)
		}
	}
}

func (f deviceTransitionFixture) prepare(setup []byte) (TrustRootTransition, []byte, error) {
	return PrepareTrustRootTransitionWithDevice(f.old, f.next, f.b, f.trust, setup, f.storage, f.source, f.target, f.slots.VaultID, f.slots.FileID, 1, f.state.Revision)
}

func TestDeviceRootTransitionRestart(t *testing.T) {
	f := newDeviceTransitionFixture(t)
	for _, withSetup := range []bool{false, true} {
		var setup []byte
		if withSetup {
			setup = f.setup
		}
		record, raw, err := f.prepare(setup)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(f.source)
		if record.FormatVersion != 3 || !bytes.Equal(record.Device.PreviousDigest, digest[:]) {
			t.Fatal("source commitment")
		}
		candidate, err := UnverifiedTransitionDevice(raw)
		if err != nil || !bytes.Equal(candidate, f.target) {
			t.Fatal(err)
		}
		slots, envelope, err := DecodeDeviceEnrollmentFile(candidate)
		if err != nil {
			t.Fatal(err)
		}
		var password vault.Slot
		for _, slot := range slots.Slots {
			if slot.Kind == vault.SlotPassword {
				password = slot
			}
		}
		key, err := vault.OpenPasswordSlot(context.Background(), f.slots.VaultID, password, []byte("transition-new-password"), f.ask)
		if err != nil {
			t.Fatal(err)
		}
		metadata, err := OpenDeviceEnrollment(key, slots, f.slots.VaultID, f.slots.FileID, 2, envelope)
		vault.Wipe(key)
		if err != nil {
			t.Fatal(err)
		}
		d, policy, err := metadata.Derivation(vault.Default, vault.Default)
		if err != nil {
			t.Fatal(err)
		}
		master, err := DeriveAccountMaster(context.Background(), d, policy, []byte("transition-new-password"), f.ask)
		if err != nil {
			t.Fatal(err)
		}
		root, err := master.DeriveTrustRoot(context.Background(), metadata.Binding())
		if err != nil {
			master.Close()
			t.Fatal(err)
		}
		err = root.Use(func(key []byte) error {
			opened, e := OpenTrustRootTransition(key, metadata.Binding(), raw)
			if e == nil && !reflect.DeepEqual(opened, record) {
				t.Fatal("journal changed")
			}
			return e
		})
		if e := root.Close(); e != nil {
			t.Fatal(e)
		}
		if e := master.Close(); e != nil {
			t.Fatal(e)
		}
		if err != nil {
			t.Fatal(err)
		}
		candidate[0] ^= 1
		if again, e := UnverifiedTransitionDevice(raw); e != nil || !bytes.Equal(again, f.target) {
			t.Fatal("projection alias", e)
		}
		observed, err := record.ObserveAccount(f.b, *record.Previous.Account, record.Next.WrappingRevision)
		if err != nil {
			t.Fatal(err)
		}
		raw, err = SealTrustRootTransition(f.next, f.b, observed)
		if err != nil {
			t.Fatal(err)
		}
		opened, err := OpenTrustRootTransition(f.next, f.b, raw)
		if err != nil || !reflect.DeepEqual(opened, observed) {
			t.Fatal("observation", err)
		}
	}
}

func TestDeviceRootTransitionRejectsSubstitution(t *testing.T) {
	f := newDeviceTransitionFixture(t)
	record, raw, err := f.prepare(f.setup)
	if err != nil {
		t.Fatal(err)
	}
	var wrapper deviceTransitionFile
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"candidate", "inner-only", "old-root", "wrong-binding", "legacy-wrapper", "unknown-field", "missing-inner", "bad-device", "trailing", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			input, root, b := raw, f.next, f.b
			w := wrapper
			switch mode {
			case "candidate":
				w.Device = f.source
			case "inner-only":
				input = w.Transition
			case "old-root":
				root = f.old
			case "wrong-binding":
				b.DeviceID = uuid.New()
			case "legacy-wrapper":
				legacy := record
				legacy.FormatVersion = 2
				legacy.Device = nil
				w.Transition, err = SealTrustRootTransition(f.next, f.b, legacy)
				if err != nil {
					t.Fatal(err)
				}
			case "unknown-field":
				input = append(bytes.Clone(raw[:len(raw)-1]), []byte(",\"unknown\":1}")...)
			case "missing-inner":
				w.Transition = nil
			case "bad-device":
				w.Device = json.RawMessage(`{}`)
			case "trailing":
				input = append(bytes.Clone(raw), ' ')
			case "oversize":
				input = bytes.Repeat([]byte{' '}, MaxTrustRootTransitionBytes+1)
			}
			if mode == "candidate" || mode == "legacy-wrapper" || mode == "missing-inner" || mode == "bad-device" {
				input, err = json.Marshal(w)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := OpenTrustRootTransition(root, b, input); err == nil {
				t.Fatal("substitution accepted")
			}
		})
	}
	for _, bad := range [][]byte{nil, []byte("{"), wrapper.Transition} {
		if _, err := UnverifiedTransitionDevice(bad); err == nil {
			t.Fatal("non-wrapper projected")
		}
	}
	for _, version := range []uint16{1, 2, 4} {
		bad := record
		bad.FormatVersion = version
		if _, err := SealTrustRootTransition(f.next, f.b, bad); err == nil {
			t.Fatal("device accepted in old version")
		}
	}
	bad := record
	bad.Device = nil
	if _, err := SealTrustRootTransition(f.next, f.b, bad); err == nil {
		t.Fatal("missing device")
	}
}
