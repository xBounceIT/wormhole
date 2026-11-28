package vault

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

func TestTouchIDSlotIsDeviceAndVaultBound(t *testing.T) {
	document, root := slotFileFixture(t)
	factor := bytes.Repeat([]byte{0x54}, 32)
	id := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	if _, err := CreateTouchIDSlot(document.VaultID, document.FileID, id, 1, root[:31], factor); !errors.Is(err, ErrFormat) {
		t.Fatal("accepted an invalid root", err)
	}
	if _, err := CreateTouchIDSlot(document.VaultID, document.FileID, id, 1, root, factor[:31]); !errors.Is(err, ErrFormat) {
		t.Fatal("accepted a truncated Keychain factor", err)
	}
	slot, err := CreateTouchIDSlot(document.VaultID, document.FileID, id, document.RootKeyVersion, root, factor)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenTouchIDSlot(document.VaultID, document.FileID, slot, factor)
	defer Wipe(opened)
	if err != nil || !bytes.Equal(opened, root) {
		t.Fatal("device factor did not unwrap the vault root", err)
	}
	for _, test := range []struct {
		vaultID, fileID string
		slot            Slot
		factor          []byte
	}{
		{document.VaultID, document.RootKeyID, slot, factor},
		{document.FileID, document.FileID, slot, factor},
		{document.VaultID, document.FileID, slot, bytes.Repeat([]byte{0x55}, 32)},
		{document.VaultID, document.FileID, slot, nil},
	} {
		if key, err := OpenTouchIDSlot(test.vaultID, test.fileID, test.slot, test.factor); key != nil || err == nil {
			t.Fatal("a substituted coordinate or factor opened the slot", err)
		}
	}
	for _, mutate := range []func(*Slot){
		func(s *Slot) { s.Kind = SlotRecovery },
		func(s *Slot) { s.ID = document.RootKeyID },
		func(s *Slot) { s.WrappedKey.KeyVersion++ },
		func(s *Slot) { s.ASKRequired = true },
		func(s *Slot) { s.Hello = &HelloSlotMetadata{} },
		func(s *Slot) { s.WrappedKey.Ciphertext = s.WrappedKey.Ciphertext[:2] },
	} {
		invalid := slot
		mutate(&invalid)
		if key, err := OpenTouchIDSlot(document.VaultID, document.FileID, invalid, factor); key != nil || err == nil {
			t.Fatal("tampered slot released the root", err)
		}
	}

	document.Slots = append(document.Slots, slot)
	for _, version := range []uint16{1, SlotFileFormatVersion, SlotFileHelloVersion} {
		document.FormatVersion = version
		if _, err := EncodeSlotFile(root, document); !errors.Is(err, ErrFormat) {
			t.Fatal("older format accepted device-only slot", version, err)
		}
	}
	document.FormatVersion = SlotFileTouchIDVersion
	raw, err := EncodeSlotFile(root, document)
	if err != nil || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(factor))) {
		t.Fatal("failed to encode a metadata-only slot", err)
	}
	decoded, err := DecodeSlotFile(raw)
	if err != nil || VerifySlotFile(root, decoded, document.VaultID, document.FileID, document.Sequence) != nil || decoded.Descriptor().Slots[1].Kind != SlotTouchID {
		t.Fatal("v6 slot failed authenticated persistence", err)
	}
	if _, err := OpenRecoverySlot(document.VaultID, decoded.Slots[0], bytes.Repeat([]byte{9}, 32)); err != nil {
		t.Fatal("optional slot broke independent recovery", err)
	}
	duplicate := slot
	duplicate.ID = document.RootKeyID
	document.Slots = append(document.Slots, duplicate)
	if _, err := EncodeSlotFile(root, document); !errors.Is(err, ErrFormat) {
		t.Fatal("accepted two Touch ID slots", err)
	}
	document.Slots = []Slot{slot}
	if _, err := EncodeSlotFile(root, document); !errors.Is(err, ErrPolicy) {
		t.Fatal("allowed a vault with only platform custody", err)
	}
}
