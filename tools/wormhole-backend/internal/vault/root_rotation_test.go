package vault

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestRootRotationBarrierRequiresV3AndAuthenticatesEveryField(t *testing.T) {
	source, key := slotFileFixture(t)
	source.FormatVersion = 3
	source.Rotation = &LocalRootRotation{ID: source.FileID, Phase: RotationPrepared, TargetRootVersion: 2, TargetSlotDigest: strings.Repeat("a", 64)}
	raw, err := EncodeSlotFile(key, source)
	if err != nil {
		t.Fatal(err)
	}
	source, err = DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySlotFile(key, source, source.VaultID, source.FileID, 0); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []RootRotationPhase{RotationRetiring, RotationPublishing} {
		changed := source
		marker := *source.Rotation
		marker.Phase = phase
		changed.Rotation = &marker
		if err := VerifySlotFile(key, changed, changed.VaultID, changed.FileID, 0); err != ErrAuthentication {
			t.Fatal("phase not authenticated", err)
		}
	}
	for _, mutate := range []func(*SlotFile){
		func(f *SlotFile) { f.FormatVersion = 1 }, func(f *SlotFile) { f.FormatVersion = 2 },
		func(f *SlotFile) { f.Initializing = true },
		func(f *SlotFile) { f.Rotation.ID = "bad" }, func(f *SlotFile) { f.Rotation.Phase = "unknown" },
		func(f *SlotFile) { f.Rotation.TargetRootVersion = 1 }, func(f *SlotFile) { f.RootKeyVersion = math.MaxUint32 },
		func(f *SlotFile) { f.Rotation.TargetSlotDigest = strings.Repeat("A", 64) }, func(f *SlotFile) { f.Rotation.TargetSlotDigest = "00" },
	} {
		var changed SlotFile
		json.Unmarshal(raw, &changed)
		mutate(&changed)
		if _, err := EncodeSlotFile(key, changed); err != ErrFormat {
			t.Fatal("invalid barrier accepted", err)
		}
	}
	if bytes.Contains(raw, []byte("unprotected")) {
		t.Fatal("reserved slot activated")
	}
	encrypted := source
	encrypted.Encrypted = true
	if err := VerifySlotFile(key, encrypted, encrypted.VaultID, encrypted.FileID, 0); err != ErrAuthentication {
		t.Fatal("storage mode was not authenticated", err)
	}
	updated, err := EncodeSlotFile(key, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if doc, err := DecodeSlotFile(updated); err != nil || !doc.Encrypted || doc.Rotation.Phase != RotationPrepared {
		t.Fatal("authenticated encrypted barrier could not be read", err)
	}
	// V2 is still a valid old container, and omitting rotation preserves its MAC.
	source.Rotation = nil
	source.FormatVersion = 2
	if _, err := EncodeSlotFile(key, source); err != nil {
		t.Fatal("v2 compatibility", err)
	}
}

func TestRootRotationRecoveryBindsBothCompleteSlotDocuments(t *testing.T) {
	source, old := slotFileFixture(t)
	target := source
	target.FormatVersion = 3
	target.RootKeyVersion++
	target.Sequence += RootRotationSequenceSpan
	target.FileEpoch++
	key := bytes.Repeat([]byte{0x7b}, 32)
	binding := RootRotationRecoveryBinding(source, target)
	envelope, err := Seal(key, binding, old)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(key, binding, envelope)
	defer Wipe(opened)
	if err != nil || !bytes.Equal(opened, old) {
		t.Fatal("native recovery context", err)
	}
	changedSource := source
	changedSource.Sequence++
	changedTarget := target
	changedTarget.FileEpoch++
	for _, changed := range []Binding{RootRotationRecoveryBinding(changedSource, target), RootRotationRecoveryBinding(source, changedTarget)} {
		if value, err := Open(key, changed, envelope); err != ErrAuthentication {
			Wipe(value)
			t.Fatal("recovery rebound to different slot authority", err)
		}
	}
}

func TestRootRotationStagingAuthenticatesOnlyCurrentPendingWraps(t *testing.T) {
	source, key := slotFileFixture(t)
	source.FormatVersion = SlotFileFormatVersion
	newRoot := bytes.Repeat([]byte{0x7b}, 32)
	recovery, err := CreateRecoverySlot(source.VaultID, "55555555-5555-4555-8555-555555555555", 2, newRoot, newRoot)
	if err != nil {
		t.Fatal(err)
	}
	check, err := KeyCheck(newRoot, source.VaultID, source.FileID)
	if err != nil {
		t.Fatal(err)
	}
	source.Rotation = &LocalRootRotation{ID: source.FileID, Phase: RotationStaging, TargetRootVersion: 2, TargetSlotDigest: strings.Repeat("a", 64)}
	if _, err := EncodeSlotFile(key, source); err != ErrFormat {
		t.Fatal("staging marker accepted without pending material", err)
	}
	source.Rotation.Pending = &PendingRotationKey{Slots: []Slot{recovery}, KeyCheck: check[:31]}
	if _, err := EncodeSlotFile(key, source); err != ErrFormat {
		t.Fatal("staging marker accepted a short KCV", err)
	}
	source.Rotation.Pending.KeyCheck = check
	source.Rotation.Pending.Slots = append(source.Rotation.Pending.Slots, source.Slots[0])
	if _, err := EncodeSlotFile(key, source); err != ErrFormat {
		t.Fatal("staging marker accepted a wrap for the previous root", err)
	}
	source.Rotation.Pending.Slots = []Slot{recovery}
	raw, err := EncodeSlotFile(key, source)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSlotFile(raw)
	if err != nil || VerifySlotFile(key, decoded, source.VaultID, source.FileID, source.Sequence) != nil {
		t.Fatal("valid pending material did not round trip", err)
	}
	decoded.Rotation.Phase = RotationPrepared
	if _, err := EncodeSlotFile(key, decoded); err != ErrFormat {
		t.Fatal("prepared phase retained staging-only material", err)
	}
}
