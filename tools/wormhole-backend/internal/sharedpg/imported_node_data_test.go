package sharedpg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/workspaceimport"
)

func TestImportedNodeDataResponseRequiresBoundProjection(t *testing.T) {
	f, snapshot, _ := snapshotFixture(t, "none")
	r := AdmissionRequest{WorkspaceID: f.s.WorkspaceID, UserID: f.s.UserID, DeviceID: uuid.New()}
	wire := append(snapshot["chain"].([]any)[0].([]any), nil)
	rowFor := func(t *testing.T, projection []any) [][]byte {
		t.Helper()
		raw, err := json.Marshal(projection)
		if err != nil {
			t.Fatal(err)
		}
		return [][]byte{[]byte(r.UserID.String()), []byte(r.DeviceID.String()), raw, nil}
	}
	row := rowFor(t, wire)
	response, err := parseImportedNodeData([][][]byte{row}, r, f.node())
	if err != nil || response == nil {
		t.Fatal("valid node projection rejected", err)
	}
	if next, data, err := f.s.VerifyImportedNodeData(f.node(), response); err != nil || data != nil || next.Revision <= f.s.Revision {
		t.Fatal("ordinary node could not prove attachment absence", err)
	}
	badWorkspace := append([]any(nil), wire...)
	badWorkspace[0] = uuid.NewString()
	badEpoch := append([]any(nil), wire...)
	badEpoch[2] = "0"
	badNode := append([]any(nil), wire...)
	badNode[4] = "{}"
	for _, invalid := range [][][][]byte{
		nil,
		{row[:3]},
		{{[]byte(uuid.NewString()), row[1], row[2], nil}},
		{{row[0], []byte(uuid.NewString()), row[2], nil}},
		{{row[0], row[1], row[2], make([]byte, 2*workspaceimport.MaxNodeDataBytes+1)}},
		{{row[0], row[1], []byte("null"), nil}},
		{{row[0], row[1], row[2], []byte("g0")}},
		{rowFor(t, badWorkspace)},
		{rowFor(t, badEpoch)},
		{rowFor(t, badNode)},
	} {
		if input, err := parseImportedNodeData(invalid, r, f.node()); input != nil || err != ErrAdmissionResponse {
			t.Fatal("accepted invalid import projection", err)
		}
	}
	s := NewSession()
	defer s.Close(context.Background())
	if _, err := s.ImportedNodeData(context.Background(), uuid.Nil); err != ErrConfiguration {
		t.Fatal("accepted a missing node", err)
	}
	if _, err := s.ImportedNodeData(context.Background(), f.node()); err != ErrAuthentication {
		t.Fatal("read outside an admitted session", err)
	}
}

func TestVerifyImportedNodeDataChecksNodeSealBeforeAttachment(t *testing.T) {
	f := newConnectionFixture(t)
	encoded, err := json.Marshal(workspaceimport.NodeData{FormatVersion: 1, NodeID: f.node().String(),
		NoteVersion: 1, Pins: []resolver.EffectiveCredentialSnapshot{}})
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(encoded)
	record := &f.records.Chain[0]
	record.Node.Metadata.Imported = &vaultstore.NodeImportReference{Digest: hex.EncodeToString(hash[:])}
	f.signChain(t)
	signed := UnverifiedImportedNodeData{workspace: f.s.WorkspaceID, user: f.s.UserID, record: *record, body: encoded}
	if next, data, err := f.s.VerifyImportedNodeData(f.node(), &signed); err != nil || data == nil || data.NoteVersion != 1 || next.Revision <= f.s.Revision {
		t.Fatal("valid signed attachment rejected", err)
	}
	for _, invalid := range []*UnverifiedImportedNodeData{nil, {workspace: f.s.WorkspaceID, user: uuid.New(), record: *record, body: encoded}} {
		if next, data, err := f.s.VerifyImportedNodeData(f.node(), invalid); err != ErrAdmissionResponse || data != nil || next.Revision != 0 {
			t.Fatal("attachment accepted without its expected account", err)
		}
	}
	inactive := f.s
	inactive.Account = nil
	if _, data, err := inactive.VerifyImportedNodeData(f.node(), &signed); err != ErrTrustState || data != nil {
		t.Fatal("attachment accepted without an active account", err)
	}
	changed := signed
	changed.body = bytes.Replace(encoded, []byte(`"noteVersion":1`), []byte(`"noteVersion":0`), 1)
	if next, data, err := f.s.VerifyImportedNodeData(f.node(), &changed); err != vault.ErrAuthentication || data != nil || next.Revision <= f.s.Revision {
		t.Fatal("an altered attachment bypassed authentication or discarded valid observations", err)
	}
	stripped := signed
	stripped.body = nil
	stripped.record.Node.Metadata.Imported = nil
	if _, data, err := f.s.VerifyImportedNodeData(f.node(), &stripped); err == nil || data != nil {
		t.Fatal("stripping the signed reference looked like ordinary absence", err)
	}
}
