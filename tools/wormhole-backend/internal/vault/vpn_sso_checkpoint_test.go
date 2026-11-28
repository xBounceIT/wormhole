package vault

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"
)

func checkpointMark() VPNSSOHighWater {
	return VPNSSOHighWater{ScopeID: "33333333-3333-4333-8333-333333333333", RowVersion: 2, Revision: 1, Digest: bytes.Repeat([]byte{5}, 32)}
}

func TestSSOSlotContainerV2AuthenticatesCheckpointAndTunnelFloors(t *testing.T) {
	f, key := slotFileFixture(t)
	old, err := EncodeSlotFile(key, f)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(old, []byte("vpnSso")) || bytes.Contains(old, []byte("tunnels")) {
		t.Fatal("v1 representation changed")
	}
	f.VPNSSO = []VPNSSOHighWater{checkpointMark()}
	if _, err := EncodeSlotFile(key, f); err != ErrFormat {
		t.Fatal("v1 accepted v2 metadata", err)
	}
	f.FormatVersion = 2 // The legacy v2 container remains readable by v3 readers.
	f.Tunnels = []TunnelHighWater{{TunnelID: f.Nodes[0].NodeID, Revision: 4}}
	raw, err := EncodeSlotFile(key, f)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := DecodeSlotFile(raw)
	if err != nil || parsed.FormatVersion != 2 || VerifySlotFile(key, parsed, f.VaultID, f.FileID, 1) != nil {
		t.Fatal("v2 roundtrip", err)
	}
	description, _ := json.Marshal(parsed.Descriptor())
	if bytes.Contains(description, []byte("vpnSso")) || bytes.Contains(description, []byte("tunnels")) || bytes.Contains(description, []byte("digest")) {
		t.Fatal("checkpoint leaked into descriptor")
	}
	parsed.VPNSSO[0].RowVersion++
	if err := VerifySlotFile(key, parsed, f.VaultID, f.FileID, 1); err != ErrAuthentication {
		t.Fatal("checkpoint tamper", err)
	}
	parsed, _ = DecodeSlotFile(raw)
	parsed.Tunnels[0].Revision++
	if err := VerifySlotFile(key, parsed, f.VaultID, f.FileID, 1); err != ErrAuthentication {
		t.Fatal("tunnel floor tamper", err)
	}
	parsed, _ = DecodeSlotFile(raw)
	parsed.VPNSSO = append(parsed.VPNSSO, parsed.VPNSSO[0])
	if _, err := EncodeSlotFile(key, parsed); err != ErrFormat {
		t.Fatal("duplicate checkpoint", err)
	}
	parsed, _ = DecodeSlotFile(raw)
	parsed.Tunnels = append(parsed.Tunnels, parsed.Tunnels[0])
	if _, err := EncodeSlotFile(key, parsed); err != ErrFormat {
		t.Fatal("duplicate tunnel floor", err)
	}
	parsed, _ = DecodeSlotFile(raw)
	parsed.Tunnels[0].Revision = 0
	if _, err := EncodeSlotFile(key, parsed); err != ErrFormat {
		t.Fatal("zero tunnel floor", err)
	}
}

func TestSSOCheckpointValidationAndMonotonicAdvance(t *testing.T) {
	mark := checkpointMark()
	if !mark.Valid() || !mark.Advances(mark) {
		t.Fatal("valid checkpoint rejected")
	}
	for _, change := range []func(*VPNSSOHighWater){
		func(h *VPNSSOHighWater) { h.ScopeID = "bad" }, func(h *VPNSSOHighWater) { h.RowVersion = 0 }, func(h *VPNSSOHighWater) { h.RowVersion = math.MaxUint64 }, func(h *VPNSSOHighWater) { h.Revision = 3 }, func(h *VPNSSOHighWater) { h.Digest = nil }, func(h *VPNSSOHighWater) { h.Digest = make([]byte, 32) },
	} {
		bad := mark
		change(&bad)
		if bad.Valid() || bad.Advances(mark) {
			t.Fatal("bad checkpoint accepted")
		}
	}
	partial := mark
	partial.Revision = 0
	partial.Digest = make([]byte, 32)
	if !partial.Valid() {
		t.Fatal("partial floor rejected")
	}
	partial.Deleted = true
	if partial.Valid() {
		t.Fatal("partial deletion accepted")
	}
	older := mark
	older.RowVersion = 1
	if older.Advances(mark) {
		t.Fatal("manifest rollback accepted")
	}
	other := mark
	other.Digest = bytes.Repeat([]byte{7}, 32)
	if other.Advances(mark) {
		t.Fatal("same revision replacement accepted")
	}
	other = mark
	other.Revision = 2
	other.Deleted = true
	if !other.Advances(mark) {
		t.Fatal("new deletion rejected")
	}
	f, key := slotFileFixture(t)
	f.FormatVersion = 2
	f.VPNSSO = make([]VPNSSOHighWater, 1025)
	if _, err := EncodeSlotFile(key, f); err != ErrFormat {
		t.Fatal("unbounded anchors", err)
	}
}
