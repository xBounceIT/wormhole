package vault

import (
	"bytes"
	"testing"
)

func TestUnprotectedSlotAuthenticatesCustodyAndContext(t *testing.T) {
	root, platform := testKey(), bytes.Repeat([]byte{0x35}, 32)
	rootBefore, platformBefore := bytes.Clone(root), bytes.Clone(platform)
	slot, err := CreateUnprotectedSlot("vault", "platform", 3, root, platform)
	if err != nil || slot.Kind != SlotUnprotected || slot.Preset != "" || len(slot.Salt) != 0 || slot.ASKRequired || len(slot.FactorIDs) != 0 {
		t.Fatal("invalid OS-only slot", err)
	}
	opened, err := OpenUnprotectedSlot("vault", slot, platform)
	if err != nil || !bytes.Equal(opened, root) || !bytes.Equal(root, rootBefore) || !bytes.Equal(platform, platformBefore) {
		t.Fatal("custody roundtrip or borrowed input changed", err)
	}
	Wipe(opened)
	for _, mode := range []string{"vault", "slot", "version", "key", "ciphertext"} {
		t.Run(mode, func(t *testing.T) {
			changed := slot
			vaultID, factor := "vault", platform
			switch mode {
			case "vault":
				vaultID = "other"
			case "slot":
				changed.ID = "other"
			case "version":
				changed.WrappedKey.KeyVersion++
			case "key":
				factor = bytes.Repeat([]byte{0x36}, 32)
			case "ciphertext":
				changed.WrappedKey.Ciphertext = bytes.Clone(slot.WrappedKey.Ciphertext)
				changed.WrappedKey.Ciphertext[0] ^= 1
			}
			if got, err := OpenUnprotectedSlot(vaultID, changed, factor); err != ErrAuthentication || got != nil {
				t.Fatal("substituted OS custody accepted", err)
			}
		})
	}
	if _, err := OpenRecoverySlot("vault", slot, platform); err != ErrFormat {
		t.Fatal("unprotected slot treated as recovery", err)
	}
	recovery, err := CreateRecoverySlot("vault", slot.ID, 3, root, platform)
	if err != nil {
		t.Fatal(err)
	}
	recovery.Kind = SlotUnprotected
	if got, err := OpenUnprotectedSlot("vault", recovery, platform); err != ErrAuthentication || got != nil {
		t.Fatal("retagged recovery accepted as OS custody", err)
	}
	slot.Kind = SlotRecovery
	if got, err := OpenRecoverySlot("vault", slot, platform); err != ErrAuthentication || got != nil {
		t.Fatal("retagged OS custody accepted as recovery", err)
	}
}

func TestUnprotectedSlotRejectsInvalidFactorsAndReservedShapes(t *testing.T) {
	root, platform := testKey(), bytes.Repeat([]byte{0x37}, 32)
	for _, size := range []int{0, 1, 31, 33, 1024} {
		bad := make([]byte, size)
		if _, err := CreateUnprotectedSlot("vault", "slot", 1, bad, platform); err != ErrFormat {
			t.Fatal("invalid root size accepted", size, err)
		}
		if _, err := CreateUnprotectedSlot("vault", "slot", 1, root, bad); err != ErrFormat {
			t.Fatal("invalid platform key size accepted", size, err)
		}
		if got, err := OpenUnprotectedSlot("vault", Slot{Kind: SlotUnprotected}, bad); err != ErrFormat || got != nil {
			t.Fatal("invalid platform unlock size accepted", size, err)
		}
	}
	for _, change := range []func(*Slot){
		func(s *Slot) { s.Kind = SlotPassword },
		func(s *Slot) { s.Kind = SlotRecovery },
		func(s *Slot) { s.Kind = SlotHello },
		func(s *Slot) { s.Kind = SlotAND },
		func(s *Slot) { s.Preset = KDFV1 },
		func(s *Slot) { s.Salt = []byte{1} },
		func(s *Slot) { s.ASKRequired = true },
		func(s *Slot) { s.FactorIDs = []string{"factor"} },
		func(s *Slot) { s.WrappedKey.KeyVersion = 0 },
		func(s *Slot) { s.WrappedKey.Ciphertext = nil },
	} {
		slot, err := CreateUnprotectedSlot("vault", "slot", 1, root, platform)
		if err != nil {
			t.Fatal(err)
		}
		change(&slot)
		if got, err := OpenUnprotectedSlot("vault", slot, platform); err == nil || got != nil {
			t.Fatal("invalid or reserved platform shape accepted")
		}
	}
	if _, err := CreateUnprotectedSlot("vault", "slot", 0, root, platform); err != ErrFormat {
		t.Fatal("zero root version accepted", err)
	}
	if _, err := CreateUnprotectedSlot("", "slot", 1, root, platform); err != ErrFormat {
		t.Fatal("missing vault identity accepted", err)
	}
	// Older containers cannot encode OS-only custody. v3 authenticates native
	// forward rotation sources; ordinary create/startup needs separate admission.
	f, key := slotFileFixture(t)
	slot, err := CreateUnprotectedSlot(f.VaultID, f.Slots[0].ID, 1, key, platform)
	if err != nil {
		t.Fatal(err)
	}
	f.Slots = []Slot{slot}
	if _, err := EncodeSlotFile(key, f); err != ErrFormat {
		t.Fatal("OS-only slot prematurely published without native lifecycle", err)
	}
}

func TestUnprotectedSourceContainerIsV3SingleSlotOnly(t *testing.T) {
	for _, mutation := range []string{"valid", "older", "mixed", "ask", "salt", "preset", "factors", "encrypted"} {
		t.Run(mutation, func(t *testing.T) {
			f, root := slotFileFixture(t)
			old := f.Slots[0]
			slot, err := CreateUnprotectedSlot(f.VaultID, old.ID, 1, root, bytes.Repeat([]byte{0x3e}, 32))
			if err != nil {
				t.Fatal(err)
			}
			f.FormatVersion, f.Slots = 3, []Slot{slot}
			switch mutation {
			case "older":
				f.FormatVersion = 2
			case "mixed":
				old.ID = f.RootKeyID
				f.Slots = append(f.Slots, old)
			case "ask":
				f.Slots[0].ASKRequired = true
			case "salt":
				f.Slots[0].Salt = bytes.Repeat([]byte{1}, 32)
			case "preset":
				f.Slots[0].Preset = KDFV1
			case "factors":
				f.Slots[0].FactorIDs = []string{f.RootKeyID}
			case "encrypted":
				f.Encrypted = true
			}
			raw, err := EncodeSlotFile(root, f)
			if mutation != "valid" {
				if err == nil {
					t.Fatal("invalid OS source encoded")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			doc, err := DecodeSlotFile(raw)
			if err != nil || VerifySlotFile(root, doc, f.VaultID, f.FileID, f.Sequence) != nil {
				t.Fatal("OS source authentication", err)
			}
		})
	}
}
