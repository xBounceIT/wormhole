package vault

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestOSMigrationContainerIsTransientAndCannotAuthorizeOtherShapes(t *testing.T) {
	f, key := slotFileFixture(t)
	platform := bytes.Repeat([]byte{0x4b}, 32)
	slot, err := CreateUnprotectedSlot(f.VaultID, f.Slots[0].ID, f.RootKeyVersion, key, platform)
	if err != nil {
		t.Fatal(err)
	}
	f.FormatVersion, f.Slots = SlotFileFormatVersion, []Slot{slot}
	state := &LocalMigration{Binding: strings.Repeat("a", 64), Phase: MigrationCopying}
	pending := MigrationSlotFile(f, state)
	if f.Migration != nil || f.FormatVersion != 3 || pending.FormatVersion != 4 {
		t.Fatal("source mutated or migration version absent")
	}
	raw, err := EncodeSlotFile(key, pending)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSlotFile(raw)
	if err != nil || VerifySlotFile(key, decoded, f.VaultID, f.FileID, 1) != nil {
		t.Fatal("v4 did not authenticate", err)
	}
	final := MigrationSlotFile(decoded, nil)
	if final.FormatVersion != 3 || final.Migration != nil {
		t.Fatal("transient version survived completion")
	}
	if _, err := EncodeSlotFile(key, final); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"v3-marker", "v4-ordinary", "mixed", "protected", "initializing", "encrypted", "rotation", "future"} {
		t.Run(change, func(t *testing.T) {
			raw, _ := json.Marshal(decoded)
			var doc SlotFile
			if json.Unmarshal(raw, &doc) != nil {
				t.Fatal("fixture")
			}
			switch change {
			case "v3-marker":
				doc.FormatVersion = 3
			case "v4-ordinary":
				doc.Migration = nil
			case "mixed":
				other := doc.Slots[0]
				other.ID = doc.RootKeyID
				doc.Slots = append(doc.Slots, other)
			case "protected":
				doc.Slots[0].Kind = SlotRecovery
			case "initializing":
				doc.Initializing = true
			case "encrypted":
				doc.Encrypted = true
			case "rotation":
				doc.Rotation = &LocalRootRotation{}
			case "future":
				doc.FormatVersion = 5
			}
			if _, err := EncodeSlotFile(key, doc); err == nil {
				t.Fatal("invalid OS migration shape accepted")
			}
		})
	}
	protected, _ := slotFileFixture(t)
	if got := MigrationSlotFile(protected, state); got.FormatVersion != protected.FormatVersion {
		t.Fatal("protected migration format changed")
	}
	for _, version := range []uint16{1, 2, 5} {
		bad := f
		bad.FormatVersion = version
		if got := MigrationSlotFile(bad, state); got.FormatVersion != version {
			t.Fatal("unsupported source version repaired")
		}
	}
}
