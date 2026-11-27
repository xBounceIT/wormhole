package workspaceimport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestDecodeNodeDataBindsCanonicalAttachmentToSignedReference(t *testing.T) {
	id, credential := uuid.NewString(), uuid.NewString()
	protocol := 0
	node := vaultstore.NodeMetadata{ID: id, Kind: 1, Protocol: &protocol}
	pin := resolver.EffectiveCredentialSnapshot{NodeID: id, ProtocolPath: "ssh", CredentialID: credential, SourceKind: "saved", Username: "historical-user"}
	marshal := func(t *testing.T, data NodeData) []byte {
		t.Helper()
		raw, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	reference := func(raw []byte, pins bool) *vaultstore.NodeImportReference {
		digest := sha256.Sum256(raw)
		return &vaultstore.NodeImportReference{Digest: hex.EncodeToString(digest[:]), RetainedPins: pins}
	}
	valid := NodeData{FormatVersion: 1, NodeID: id, NoteVersion: 1, Pins: []resolver.EffectiveCredentialSnapshot{pin}}
	raw := marshal(t, valid)
	viewNote := valid
	viewNote.FormatVersion = viewKeyNoteFormat
	viewRaw := marshal(t, viewNote)
	viewRef := reference(viewRaw, true)
	viewRef.NoteVersion = 1
	duplicate := bytes.Replace(raw, []byte(`"noteVersion":1`), []byte(`"noteVersion":1,"noteVersion":1`), 1)
	for _, tc := range []struct {
		name    string
		raw     []byte
		ref     *vaultstore.NodeImportReference
		want    error
		purpose vault.BoundaryPurpose
	}{
		{"no attachment", nil, nil, nil, ""},
		{"valid", raw, reference(raw, true), nil, vault.BoundarySecret},
		{"view key", viewRaw, viewRef, nil, vault.BoundaryView},
		{"view key needs a signed note revision", viewRaw, reference(viewRaw, true), vault.ErrFormat, ""},
		{"unbound", raw, nil, vault.ErrFormat, ""},
		{"missing", nil, reference(raw, true), vault.ErrFormat, ""},
		{"oversize", make([]byte, MaxNodeDataBytes+1), reference(raw, true), vault.ErrFormat, ""},
		{"bad digest", append(bytes.Clone(raw), ' '), reference(raw, true), vault.ErrAuthentication, ""},
		{"flag mismatch", raw, reference(raw, false), vault.ErrFormat, ""},
		{"signed duplicate", duplicate, reference(duplicate, true), vault.ErrFormat, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node.Imported = tc.ref
			data, err := DecodeNodeData(node, tc.raw)
			if err != tc.want || data.NotePurpose() != tc.purpose {
				t.Fatalf("attachment presence or error did not match the signed reference: %v", err)
			}
			if data != nil && (data.NoteVersion != 1 || len(data.Pins) != 1 || data.Pins[0] != pin) {
				t.Fatal("historical identity or note revision changed")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*NodeData)
		want   error
	}{
		{"newer version", func(d *NodeData) { d.FormatVersion = viewKeyNoteFormat + 1 }, vault.ErrNewerFormat},
		{"view-key format requires a note", func(d *NodeData) { d.FormatVersion, d.NoteVersion = viewKeyNoteFormat, 0 }, vault.ErrFormat},
		{"missing version", func(d *NodeData) { d.FormatVersion = 0 }, vault.ErrFormat},
		{"other node", func(d *NodeData) { d.NodeID = uuid.NewString() }, vault.ErrFormat},
		{"unsupported note revision", func(d *NodeData) { d.NoteVersion++ }, vault.ErrFormat},
		{"null pins", func(d *NodeData) { d.Pins = nil }, vault.ErrFormat},
		{"empty attachment", func(d *NodeData) { d.Pins = d.Pins[:0]; d.NoteVersion = 0 }, vault.ErrFormat},
		{"candidate instead of legacy", func(d *NodeData) { d.Pins[0].ResolverVersion++ }, resolver.ErrImportedPins},
		{"credential path incompatible with protocol", func(d *NodeData) { d.Pins[0].ProtocolPath = "rdp" }, resolver.ErrImportedPins},
		{"duplicate path", func(d *NodeData) { d.Pins = append(d.Pins, d.Pins[0]) }, resolver.ErrImportedPins},
		{"different pin owner", func(d *NodeData) { d.Pins[0].NodeID = uuid.NewString() }, resolver.ErrImportedPins},
		{"unknown source", func(d *NodeData) { d.Pins[0].SourceKind = "other" }, resolver.ErrImportedPins},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := valid
			data.Pins = []resolver.EffectiveCredentialSnapshot{pin}
			tc.change(&data)
			raw := marshal(t, data)
			node.Imported = reference(raw, len(data.Pins) != 0)
			if result, err := DecodeNodeData(node, raw); result != nil || err != tc.want {
				t.Fatalf("invalid attachment accepted or wrong error: %v", err)
			}
		})
	}
}
