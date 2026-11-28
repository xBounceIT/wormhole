package vault

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
)

func TestPreMigrationSlotMACRemainsCompatible(t *testing.T) {
	f, key := slotFileFixture(t)
	// Independent pre-migration field order. A nil optional journal must not
	// change the exact bytes authenticated by already-created vaults.
	old := struct {
		FormatVersion   uint16          `json:"formatVersion"`
		VaultID         string          `json:"vaultId"`
		FileID          string          `json:"fileId"`
		RootKeyID       string          `json:"rootKeyId"`
		RootKeyVersion  uint32          `json:"rootKeyVersion"`
		Initializing    bool            `json:"initializing"`
		Sequence        uint64          `json:"sequence"`
		Encrypted       bool            `json:"encrypted"`
		Slots           []Slot          `json:"slots"`
		KeyCheck        []byte          `json:"keyCheck"`
		ProfileSequence uint64          `json:"profileSequence"`
		FileEpoch       uint64          `json:"fileEpoch"`
		Nodes           []NodeHighWater `json:"nodes"`
		Authentication  []byte          `json:"authentication"`
	}{f.FormatVersion, f.VaultID, f.FileID, f.RootKeyID, f.RootKeyVersion, f.Initializing, f.Sequence, f.Encrypted, f.Slots, f.KeyCheck, f.ProfileSequence, f.FileEpoch, f.Nodes, nil}
	body, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	subkey, err := DeriveKey(key, []byte(f.VaultID), PurposeLocalSeal)
	if err != nil {
		t.Fatal(err)
	}
	defer Wipe(subkey)
	mac := hmac.New(sha256.New, subkey)
	mac.Write(canonical("wormhole/v1/slot-file", body))
	old.Authentication = mac.Sum(nil)
	raw, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := DecodeSlotFile(raw)
	if err != nil || VerifySlotFile(key, loaded, f.VaultID, f.FileID, 1) != nil {
		t.Fatal("legacy slot file rejected", err)
	}
}

func TestPublishingMigrationRequiresBothSnapshotsAndImmutableContent(t *testing.T) {
	f, key := slotFileFixture(t)
	f.Migration = &LocalMigration{Binding: strings.Repeat("a", 64), Phase: MigrationPublishing,
		Snapshot:       &MigrationSnapshot{Bytes: 4096, Authentication: bytes.Repeat([]byte{1}, 32), ContentAuthentication: bytes.Repeat([]byte{2}, 32)},
		SourceSnapshot: &MigrationSnapshot{Bytes: 8192, Authentication: bytes.Repeat([]byte{3}, 32)}}
	raw, err := EncodeSlotFile(key, f)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := DecodeSlotFile(raw)
	if err != nil || VerifySlotFile(key, loaded, f.VaultID, f.FileID, 1) != nil {
		t.Fatal("publication checkpoint did not authenticate", err)
	}
	for _, changed := range []string{"source", "floors", "database"} {
		var copy SlotFile
		if json.Unmarshal(raw, &copy) != nil {
			t.Fatal("fixture decode failed")
		}
		switch changed {
		case "source":
			copy.Migration.SourceSnapshot.Authentication[0] ^= 1
		case "floors":
			copy.Migration.Snapshot.ContentAuthentication[0] ^= 1
		case "database":
			copy.Migration.Snapshot.Authentication[0] ^= 1
		}
		if VerifySlotFile(key, copy, f.VaultID, f.FileID, 1) == nil {
			t.Fatal("modified publication proof authenticated")
		}
	}
	for _, bad := range []string{"missing-source", "missing-final", "missing-floors", "short-floors", "source-floors", "source-size", "source-mac", "non-publishing-source"} {
		var copy SlotFile
		if json.Unmarshal(raw, &copy) != nil {
			t.Fatal("fixture decode failed")
		}
		switch bad {
		case "missing-source":
			copy.Migration.SourceSnapshot = nil
		case "missing-final":
			copy.Migration.Snapshot = nil
		case "missing-floors":
			copy.Migration.Snapshot.ContentAuthentication = nil
		case "short-floors":
			copy.Migration.Snapshot.ContentAuthentication = []byte{1}
		case "source-floors":
			copy.Migration.SourceSnapshot.ContentAuthentication = bytes.Repeat([]byte{1}, 32)
		case "source-size":
			copy.Migration.SourceSnapshot.Bytes = 511
		case "source-mac":
			copy.Migration.SourceSnapshot.Authentication = nil
		case "non-publishing-source":
			copy.Migration.Phase = MigrationRetiring
		}
		if _, err := EncodeSlotFile(key, copy); err == nil {
			t.Fatal("incomplete publication proof accepted", bad)
		}
	}
}

func TestLocalMigrationSlotAuthentication(t *testing.T) {
	f, key := slotFileFixture(t)
	for _, phase := range []string{MigrationCopying, MigrationDomainsCopied} {
		f.Migration = &LocalMigration{Binding: strings.Repeat("ab", 32), Phase: phase}
		raw, err := EncodeSlotFile(key, f)
		if err != nil {
			t.Fatal(err)
		}
		loaded, err := DecodeSlotFile(raw)
		if err != nil || VerifySlotFile(key, loaded, f.VaultID, f.FileID, 1) != nil {
			t.Fatal("marker roundtrip", err)
		}
		descriptor, _ := json.Marshal(loaded.Descriptor())
		if bytes.Contains(descriptor, []byte("migration")) || bytes.Contains(descriptor, []byte(loaded.Migration.Binding)) {
			t.Fatal("native provenance exposed")
		}
		for _, mutate := range []func(*SlotFile){
			func(d *SlotFile) { d.Migration = nil },
			func(d *SlotFile) { d.Migration = &LocalMigration{Binding: strings.Repeat("cd", 32), Phase: phase} },
			func(d *SlotFile) {
				other := MigrationCopying
				if phase == other {
					other = MigrationDomainsCopied
				}
				d.Migration = &LocalMigration{Binding: f.Migration.Binding, Phase: other}
			},
		} {
			changed := loaded
			mutate(&changed)
			if VerifySlotFile(key, changed, f.VaultID, f.FileID, 1) == nil {
				t.Fatal("marker modification authenticated")
			}
		}
	}
	for _, invalid := range []LocalMigration{{}, {Binding: strings.Repeat("a", 64), Phase: "complete"}, {Binding: strings.Repeat("AB", 32), Phase: MigrationCopying}, {Binding: strings.Repeat("x", 64), Phase: MigrationCopying}, {Binding: "ab", Phase: MigrationCopying}} {
		f.Migration = &invalid
		if _, err := EncodeSlotFile(key, f); err == nil {
			t.Fatal("invalid marker accepted")
		}
	}
	f.Migration = &LocalMigration{Binding: strings.Repeat("a", 64), Phase: MigrationCopying}
	f.Initializing = true
	if _, err := EncodeSlotFile(key, f); err == nil {
		t.Fatal("two initialization protocols accepted")
	}
	f.Initializing, f.Encrypted = false, true
	if _, err := EncodeSlotFile(key, f); err == nil {
		t.Fatal("unsupported encrypted stage accepted")
	}
}

func TestMigrationSnapshotIsAuthenticatedAndNativeOnly(t *testing.T) {
	f, key := slotFileFixture(t)
	f.Migration = &LocalMigration{Binding: strings.Repeat("a", 64), Phase: MigrationDomainsCopied, Snapshot: &MigrationSnapshot{Bytes: 4096, Authentication: bytes.Repeat([]byte{1}, 32)}}
	raw, err := EncodeSlotFile(key, f)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := DecodeSlotFile(raw)
	if err != nil || VerifySlotFile(key, loaded, f.VaultID, f.FileID, 1) != nil {
		t.Fatal(err)
	}
	descriptor, _ := json.Marshal(loaded.Descriptor())
	if bytes.Contains(descriptor, []byte("snapshot")) || bytes.Contains(descriptor, []byte("authentication")) {
		t.Fatal("native snapshot exposed")
	}
	for _, change := range []func(*SlotFile){
		func(d *SlotFile) { d.Migration.Snapshot.Bytes++ },
		func(d *SlotFile) { d.Migration.Snapshot.Authentication[0] ^= 1 },
		func(d *SlotFile) { d.Migration.Snapshot = nil },
	} {
		altered, err := DecodeSlotFile(raw)
		if err != nil {
			t.Fatal(err)
		}
		change(&altered)
		if VerifySlotFile(key, altered, f.VaultID, f.FileID, 1) == nil {
			t.Fatal("snapshot change authenticated")
		}
	}
	for _, snapshot := range []*MigrationSnapshot{{Bytes: -1, Authentication: make([]byte, 32)}, {Bytes: 511, Authentication: make([]byte, 32)}, {Bytes: 512, Authentication: make([]byte, 31)}} {
		f.Migration.Snapshot = snapshot
		if _, err := EncodeSlotFile(key, f); err == nil {
			t.Fatal("invalid snapshot accepted")
		}
	}
	f.Migration.Snapshot = &MigrationSnapshot{Bytes: 512, Authentication: make([]byte, 32)}
	f.Migration.Phase = MigrationCopying
	if _, err := EncodeSlotFile(key, f); err == nil {
		t.Fatal("copying marker carries completed checkpoint")
	}
}
