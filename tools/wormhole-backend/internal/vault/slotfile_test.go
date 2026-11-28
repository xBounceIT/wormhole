package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func slotFileFixture(t *testing.T) (SlotFile, []byte) {
	t.Helper()
	key := testKey()
	f := SlotFile{FormatVersion: 1, VaultID: "11111111-1111-4111-8111-111111111111", FileID: "22222222-2222-4222-8222-222222222222", Sequence: 1, FileEpoch: 1, ProfileSequence: 2, Nodes: []NodeHighWater{{"33333333-3333-4333-8333-333333333333", 4}}}
	f.RootKeyID, f.RootKeyVersion = "55555555-5555-4555-8555-555555555555", 1
	slot, err := CreateRecoverySlot(f.VaultID, "44444444-4444-4444-8444-444444444444", 1, key, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.Slots = []Slot{slot}
	raw, err := EncodeSlotFile(key, f)
	if err != nil {
		t.Fatal(err)
	}
	f, err = DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	return f, key
}

func TestSlotFileAuthenticationAndDescriptor(t *testing.T) {
	f, key := slotFileFixture(t)
	if err := VerifySlotFile(key, f, f.VaultID, f.FileID, 1); err != nil {
		t.Fatal(err)
	}
	if err := VerifySlotFile(key, f, f.VaultID, f.FileID, 2); err != ErrRollback {
		t.Fatal(err)
	}
	if err := VerifySlotFile(bytes.Repeat([]byte{7}, 32), f, f.VaultID, f.FileID, 0); err != ErrKeyCheck {
		t.Fatal(err)
	}
	if err := VerifySlotFile(key, f, f.VaultID, "other-file", 0); err != ErrKeyCheck {
		t.Fatal(err)
	}
	if err := VerifySlotFile(key, f, "other-vault", f.FileID, 0); err != ErrKeyCheck {
		t.Fatal(err)
	}
	descriptor, _ := json.Marshal(f.Descriptor())
	var fields map[string]json.RawMessage
	json.Unmarshal(descriptor, &fields)
	if len(fields) != 4 || len(fields["slots"]) == 0 {
		t.Fatal("descriptor shape")
	}
	for _, forbidden := range []string{"wrappedKey", "ciphertext", "authentication", "keyCheck", "fileId", "nodes", "salt"} {
		if bytes.Contains(descriptor, []byte(forbidden)) {
			t.Fatalf("descriptor exposes %s", forbidden)
		}
	}
	for _, change := range []func(*SlotFile){
		func(f *SlotFile) { f.RootKeyID = "66666666-6666-4666-8666-666666666666" },
		func(f *SlotFile) { f.RootKeyVersion++ },
		func(f *SlotFile) { f.Initializing = !f.Initializing },
		func(f *SlotFile) { f.Encrypted = true },
		func(f *SlotFile) { f.Sequence++ },
		func(f *SlotFile) { f.ProfileSequence-- },
		func(f *SlotFile) { f.FileEpoch++ },
		func(f *SlotFile) { f.Nodes[0].Revision-- },
		func(f *SlotFile) { f.Nodes = nil },
		func(f *SlotFile) { f.Slots[0].WrappedKey.Ciphertext[0] ^= 1 },
		func(f *SlotFile) { f.Authentication[0] ^= 1 },
	} {
		f, key := slotFileFixture(t)
		change(&f)
		if err := VerifySlotFile(key, f, f.VaultID, f.FileID, 0); err != ErrAuthentication {
			t.Fatalf("tampering accepted: %v", err)
		}
	}
}

func TestSlotFileStrictParsing(t *testing.T) {
	if _, err := DecodeSlotFile([]byte(`{"formatVersion":` + strconv.Itoa(SlotFileTPMAttestationVersion+1) + `,"futureField":true}`)); err != ErrNewerFormat {
		t.Fatal("future schema misclassified", err)
	}
	f, _ := slotFileFixture(t)
	raw, _ := json.Marshal(f)
	for _, bad := range [][]byte{
		nil, []byte("null"), []byte("[]"), []byte("1"), []byte("{"), []byte("{\"x\":"), []byte("[1,"),
		append(bytes.Clone(raw), []byte(" {}")...),
		bytes.Replace(raw, []byte(`"sequence":1`), []byte(`"sequence":1,"sequence":1`), 1),
		bytes.Replace(raw, []byte(`"kind":"recovery"`), []byte(`"kind":"recovery","kind":"recovery"`), 1),
		bytes.Replace(raw, []byte(`"sequence"`), []byte(`"Sequence"`), 1),
		bytes.Replace(raw, []byte(`"kind"`), []byte(`"Kind"`), 1),
		bytes.Replace(raw, []byte(`"sequence"`), []byte(`"unknown"`), 1),
		bytes.Replace(raw, []byte(`"sequence":1`), []byte(`"sequence":"1"`), 1),
		bytes.Replace(raw, []byte(`"formatVersion":1`), []byte(`"formatVersion":1.5`), 1),
		bytes.Repeat([]byte{' '}, MaxSlotFileBytes+1),
		[]byte{0xff},
		[]byte(strings.Repeat("[", 18) + "0" + strings.Repeat("]", 18)),
	} {
		if _, err := DecodeSlotFile(bad); err == nil {
			t.Fatal("malformed slot file accepted")
		}
	}
	if sameJSONFields(map[string]any{"a": nil}, nil) || sameJSONFields([]any{1}, []any{}) {
		t.Fatal("shape mismatch accepted")
	}
}

func TestSlotFileValidationRejectsUnsupportedShapes(t *testing.T) {
	for _, change := range []func(*SlotFile){
		func(f *SlotFile) { f.FormatVersion = 0 },
		func(f *SlotFile) { f.VaultID = "not-a-uuid" },
		func(f *SlotFile) { f.FileID = "00000000-0000-0000-0000-000000000000" },
		func(f *SlotFile) { f.RootKeyID = "invalid" },
		func(f *SlotFile) { f.RootKeyVersion = 0 },
		func(f *SlotFile) { f.Sequence = 0 },
		func(f *SlotFile) { f.FileEpoch = 0 },
		func(f *SlotFile) { f.KeyCheck = nil },
		func(f *SlotFile) { f.Authentication = nil },
		func(f *SlotFile) { f.Slots = nil },
		func(f *SlotFile) { f.Slots = append(f.Slots, f.Slots[0]) },
		func(f *SlotFile) { f.Slots[0].ID = "invalid" },
		func(f *SlotFile) { f.Slots[0].ASKRequired = true },
		func(f *SlotFile) { f.Slots[0].FactorIDs = []string{"a"} },
		func(f *SlotFile) { f.Slots[0].Kind = SlotAND },
		func(f *SlotFile) { f.Slots[0].Salt = []byte{1} },
		func(f *SlotFile) { f.Slots[0].Kind = SlotPassword; f.Slots[0].Preset = KDFLow },
		func(f *SlotFile) { f.Slots[0].Kind = SlotPassword; f.Slots[0].Preset = "unknown" },
		func(f *SlotFile) { f.Slots[0].WrappedKey.KeyVersion = 0 },
		func(f *SlotFile) { f.Slots[0].WrappedKey.SuiteID = 99 },
		func(f *SlotFile) { f.Slots[0].WrappedKey.Ciphertext = make([]byte, 47) },
		func(f *SlotFile) { f.Nodes[0].Revision = 0 },
		func(f *SlotFile) { f.Nodes = append(f.Nodes, f.Nodes[0]) },
	} {
		f, _ := slotFileFixture(t)
		change(&f)
		raw, _ := json.Marshal(f)
		if _, err := DecodeSlotFile(raw); err == nil {
			t.Fatal("unsupported document accepted")
		}
	}
	f, key := slotFileFixture(t)
	f.FormatVersion = SlotFileTPMAttestationVersion + 1
	if _, err := EncodeSlotFile(key, f); err != ErrNewerFormat {
		t.Fatal(err)
	}
	if err := VerifySlotFile(key, f, f.VaultID, f.FileID, 0); err != ErrNewerFormat {
		t.Fatal(err)
	}
	f, _ = slotFileFixture(t)
	f.Slots[0].WrappedKey.FormatVersion = 2
	if _, err := EncodeSlotFile(key, f); err != ErrNewerFormat {
		t.Fatal(err)
	}
	f, _ = slotFileFixture(t)
	if _, err := EncodeSlotFile(nil, f); err != ErrFormat {
		t.Fatal(err)
	}
	if _, err := slotFileMAC(nil, f); err != ErrFormat {
		t.Fatal(err)
	}
}

func TestPasswordSlotFileUnlockAuthenticatesWholeDocument(t *testing.T) {
	f, key := slotFileFixture(t)
	password := []byte("test password")
	ask := bytes.Repeat([]byte{3}, 32)
	slot, err := CreatePasswordSlot(context.Background(), f.VaultID, "55555555-5555-4555-8555-555555555555", 1, key, password, ask, KDFLow)
	if err != nil {
		t.Fatal(err)
	}
	f.Slots = append(f.Slots, slot)
	raw, err := EncodeSlotFile(key, f)
	if err != nil {
		t.Fatal(err)
	}
	f, err = DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	unlocked, err := OpenPasswordSlot(context.Background(), f.VaultID, f.Slots[1], password, ask)
	if err != nil {
		t.Fatal(err)
	}
	defer Wipe(unlocked)
	if err := VerifySlotFile(unlocked, f, f.VaultID, f.FileID, 1); err != nil {
		t.Fatal(err)
	}
	f.Slots = f.Slots[1:]
	if err := VerifySlotFile(unlocked, f, f.VaultID, f.FileID, 1); err != ErrAuthentication {
		t.Fatal("slot removal undetected")
	}
	f.Encrypted = true
	if _, err := EncodeSlotFile(key, f); err != ErrPolicy {
		t.Fatalf("whole-file encryption accepted a password-only slot: %v", err)
	}
	stale, err := CreateRecoverySlot(f.VaultID, "44444444-4444-4444-8444-444444444444", 2, key, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.Slots = append(f.Slots, stale)
	if _, err := EncodeSlotFile(key, f); err != ErrPolicy {
		t.Fatalf("whole-file encryption accepted recovery for another root version: %v", err)
	}
}
