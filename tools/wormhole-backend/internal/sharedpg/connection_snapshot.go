package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"strconv"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/workspaceimport"
)

const MaxConnectionSnapshotBytes = 16 * 1024 * 1024

type connectionSnapshotWire struct {
	FormatVersion uint16          `json:"formatVersion"`
	WorkspaceID   string          `json:"workspaceId"`
	UserID        string          `json:"userId"`
	NodeID        string          `json:"nodeId"`
	Epoch         string          `json:"epoch"`
	ChangeSeq     string          `json:"changeSeq"`
	Plan          json.RawMessage `json:"plan"`
	Chain         json.RawMessage `json:"chain"`
	Override      json.RawMessage `json:"override"`
	Slot          json.RawMessage `json:"slot"`
	SlotValue     json.RawMessage `json:"slotValue"`
	Credential    json.RawMessage `json:"credential"`
	Gateway       json.RawMessage `json:"gateway"`
	Boundaries    json.RawMessage `json:"boundaries"`
}

// Version two binds a selected tunnel profile; direct version-one snapshots
// retain their exact wire shape. Null or unrelated tunnel records are refused.
type connectionSnapshotWireV2 struct {
	connectionSnapshotWire
	Tunnel json.RawMessage `json:"tunnel"`
}

type connectionPathSnapshotWire struct {
	connectionSnapshotWireV2
	Path         string  `json:"path"`
	ImportedData *string `json:"importedData"`
}

// UnverifiedConnectionSnapshot is a bound, structurally decoded release metadata
// section. Only VerifyConnectionSnapshot and durable trust publication permit its
// plan to be used. Cipher/key authorization and audited release remain separate.
type UnverifiedConnectionSnapshot struct {
	format                uint16
	workspace, user, node uuid.UUID
	records               CatalogConnectionRecords
	plan                  resolver.Plan
	manifests             []vault.BoundaryManifest
}

// Wire rows contain only strings or nulls, using existing projection column
// layouts. Streaming caps reject excessive rows/columns before allocating them.
func snapshotRow(d *json.Decoder, columns int) ([][]byte, error) {
	token, e := d.Token()
	if e != nil || token != json.Delim('[') {
		return nil, ErrAdmissionResponse
	}
	row := make([][]byte, 0, columns)
	for d.More() {
		if len(row) >= columns {
			return nil, ErrAdmissionResponse
		}
		var text *string
		if d.Decode(&text) != nil {
			return nil, ErrAdmissionResponse
		}
		var value []byte
		if text != nil {
			value = []byte(*text)
		}
		row = append(row, value)
	}
	if token, e = d.Token(); e != nil || token != json.Delim(']') || len(row) != columns {
		return nil, ErrAdmissionResponse
	}
	return row, nil
}
func snapshotRows(raw []byte, maxRows, columns int) ([][][]byte, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, e := d.Token()
	if e != nil || token != json.Delim('[') {
		return nil, ErrAdmissionResponse
	}
	rows := make([][][]byte, 0)
	for d.More() {
		if len(rows) >= maxRows {
			return nil, ErrAdmissionResponse
		}
		r, e := snapshotRow(d, columns)
		if e != nil {
			return nil, e
		}
		rows = append(rows, r)
	}
	if token, e = d.Token(); e != nil || token != json.Delim(']') || d.Decode(new(any)) != io.EOF {
		return nil, ErrAdmissionResponse
	}
	return rows, nil
}
func snapshotOptionalRow(raw []byte, columns int) ([][]byte, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	row, e := snapshotRow(d, columns)
	if e != nil || d.Decode(new(any)) != io.EOF {
		return nil, ErrAdmissionResponse
	}
	return row, nil
}

func snapshotNodeChain(raw []byte, columns int, request AdmissionRequest, epoch, sequence uint64) ([]UnverifiedChainRecord, error) {
	rows, err := snapshotRows(raw, vaultstore.MaxNodeDepth, columns)
	if err != nil || len(rows) == 0 {
		return nil, ErrAdmissionResponse
	}
	chain := make([]UnverifiedChainRecord, 0, len(rows))
	for _, row := range rows {
		id, ok := treeID(row[1])
		if !ok {
			return nil, ErrAdmissionResponse
		}
		m, err := parseTreeMetadata(row[4])
		if err != nil || m.ID != id.String() {
			return nil, ErrAdmissionResponse
		}
		envelope, err := parseCatalogProjectionEnvelope([][][]byte{row}, request, id, epoch, sequence)
		if err != nil {
			return nil, err
		}
		chain = append(chain, UnverifiedChainRecord{Node: UnverifiedTreeNode{Metadata: m, Boundary: envelope.Boundary, Seal: envelope.Seal}, Author: *envelope.Author})
	}
	return chain, nil
}

func parseConnectionSnapshot(raw []byte, request AdmissionRequest, node uuid.UUID, epoch, sequence uint64) (*UnverifiedConnectionSnapshot, error) {
	if len(raw) == 0 || len(raw) > MaxConnectionSnapshotBytes || !utf8.Valid(raw) || request.WorkspaceID == uuid.Nil || request.UserID == uuid.Nil || node == uuid.Nil || epoch == 0 || epoch > math.MaxInt64 || sequence > math.MaxInt64 {
		return nil, ErrAdmissionResponse
	}
	var header struct {
		FormatVersion uint16 `json:"formatVersion"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return nil, ErrAdmissionResponse
	}
	if header.FormatVersion > 4 {
		return nil, vault.ErrNewerFormat
	}
	var w connectionSnapshotWire
	var tunnel json.RawMessage
	var path string
	var imported []byte
	switch header.FormatVersion {
	case 1:
		if _, e := strictCatalogObject(raw, w, "override", "slot", "slotValue", "credential", "gateway"); e != nil {
			return nil, e
		}
		if json.Unmarshal(raw, &w) != nil {
			return nil, ErrAdmissionResponse
		}
	case 2, 3:
		var v connectionSnapshotWireV2
		if _, e := strictCatalogObject(raw, v, "override", "slot", "slotValue", "credential", "gateway", "tunnel"); e != nil {
			return nil, e
		}
		if json.Unmarshal(raw, &v) != nil {
			return nil, ErrAdmissionResponse
		}
		w, tunnel = v.connectionSnapshotWire, v.Tunnel
	case 4:
		var v connectionPathSnapshotWire
		if _, e := strictCatalogObject(raw, v, "override", "slot", "slotValue", "credential", "gateway", "tunnel", "importedData"); e != nil {
			return nil, e
		}
		if json.Unmarshal(raw, &v) != nil || (!resolver.KnownAccountPath(v.Path) && v.Path != WebConnectionPlanPath) {
			return nil, ErrAdmissionResponse
		}
		if v.ImportedData != nil {
			if len(*v.ImportedData) == 0 || len(*v.ImportedData) > 2*workspaceimport.MaxNodeDataBytes {
				return nil, ErrAdmissionResponse
			}
			var e error
			imported, e = hex.DecodeString(*v.ImportedData)
			if e != nil {
				return nil, ErrAdmissionResponse
			}
		}
		w, tunnel, path = v.connectionSnapshotWire, v.Tunnel, v.Path
	default:
		return nil, ErrAdmissionResponse
	}
	if w.WorkspaceID != request.WorkspaceID.String() || w.UserID != request.UserID.String() || w.NodeID != node.String() || w.Epoch != strconv.FormatUint(epoch, 10) || w.ChangeSeq != strconv.FormatUint(sequence, 10) {
		return nil, ErrAdmissionResponse
	}
	fields, e := strictCatalogObject(w.Plan, resolver.Plan{})
	if e != nil {
		return nil, e
	}
	if _, e := strictCatalogObject(fields["credential"], resolver.Choice{}); e != nil {
		return nil, e
	}
	result := &UnverifiedConnectionSnapshot{format: w.FormatVersion, workspace: request.WorkspaceID, user: request.UserID, node: node}
	result.records.Path, result.records.Imported = path, imported
	if json.Unmarshal(w.Plan, &result.plan) != nil || result.plan.Version != resolver.Version || result.plan.NodeID != node.String() {
		return nil, ErrAdmissionResponse
	}
	if w.FormatVersion < 3 && (w.FormatVersion == 2) != (result.plan.TunnelID != "") {
		return nil, ErrAdmissionResponse
	}
	columns := 23
	if w.FormatVersion >= 3 {
		columns = 24
		if (result.plan.TunnelID != "") != (len(tunnel) > 0 && !bytes.Equal(bytes.TrimSpace(tunnel), []byte("null"))) {
			return nil, ErrAdmissionResponse
		}
	}
	result.records.Chain, e = snapshotNodeChain(w.Chain, columns, request, epoch, sequence)
	if e != nil {
		return nil, e
	}
	selection := func(raw []byte, kind string, subject, user uuid.UUID) (*UnverifiedSelectionRecord, error) {
		row, e := snapshotOptionalRow(raw, columns)
		if e != nil || row == nil {
			return nil, e
		}
		if subject == uuid.Nil {
			var ok bool
			subject, ok = treeID(row[1])
			if !ok {
				return nil, ErrAdmissionResponse
			}
		}
		r, a, e := parseSelectionProjection([][][]byte{row}, request, sharedcatalog.SelectionScope{Kind: kind, Subject: subject, User: user}, epoch, sequence)
		if e != nil {
			return nil, e
		}
		return &UnverifiedSelectionRecord{Selection: *r, Author: *a}, nil
	}
	result.records.Override, e = selection(w.Override, "override", node, request.UserID)
	if e != nil {
		return nil, e
	}
	result.records.Slot, e = selection(w.Slot, "slot", uuid.Nil, uuid.Nil)
	if e != nil {
		return nil, e
	}
	var slotID uuid.UUID
	if result.records.Slot != nil {
		slotID = uuid.MustParse(result.records.Slot.Selection.Record.(sharedcatalog.SlotRecord).ID)
	}
	if slotID == uuid.Nil && !bytes.Equal(bytes.TrimSpace(w.SlotValue), []byte("null")) {
		return nil, ErrAdmissionResponse
	}
	result.records.SlotValue, e = selection(w.SlotValue, "slot-value", slotID, request.UserID)
	if e != nil {
		return nil, e
	}
	credential := func(raw []byte) (*UnverifiedCredentialRecord, error) {
		row, e := snapshotOptionalRow(raw, columns)
		if e != nil || row == nil {
			return nil, e
		}
		id, ok := treeID(row[1])
		if !ok {
			return nil, ErrAdmissionResponse
		}
		c, a, e := parseCredentialProjection([][][]byte{row}, request, id, epoch, sequence)
		if e != nil {
			return nil, e
		}
		return &UnverifiedCredentialRecord{Credential: *c, Author: *a}, nil
	}
	result.records.Credential, e = credential(w.Credential)
	if e != nil {
		return nil, e
	}
	result.records.Gateway, e = credential(w.Gateway)
	if e != nil {
		return nil, e
	}
	if result.plan.TunnelID != "" {
		id, ok := treeID([]byte(result.plan.TunnelID))
		if !ok {
			return nil, ErrAdmissionResponse
		}
		result.records.Tunnel, e = selection(tunnel, "tunnel", id, uuid.Nil)
		if e != nil || result.records.Tunnel == nil {
			return nil, ErrAdmissionResponse
		}
	}
	required := make(map[uuid.UUID]bool)
	for _, r := range result.records.Chain {
		required[r.Node.Boundary] = true
	}
	for _, r := range []*UnverifiedSelectionRecord{result.records.Override, result.records.Slot, result.records.SlotValue, result.records.Tunnel} {
		if r != nil {
			required[r.Selection.Boundary] = true
		}
	}
	for _, r := range []*UnverifiedCredentialRecord{result.records.Credential, result.records.Gateway} {
		if r != nil {
			required[r.Credential.Boundary] = true
		}
	}
	rows, e := snapshotRows(w.Boundaries, vaultstore.MaxNodeDepth+6, 9)
	if e != nil || len(rows) != len(required) {
		return nil, ErrAdmissionResponse
	}
	var previous uuid.UUID
	for _, row := range rows {
		id, ok := treeID(row[1])
		if !ok || !required[id] || bytes.Compare(id[:], previous[:]) <= 0 {
			return nil, ErrAdmissionResponse
		}
		m, e := parseBoundaryProjection([][][]byte{row}, request, id, epoch, sequence)
		if e != nil {
			return nil, e
		}
		result.manifests = append(result.manifests, *m)
		previous = id
	}
	return result, nil
}

// VerifyConnectionSnapshot re-resolves the authenticated records and requires
// exact agreement with the server's proposal. It never releases secrets or
// grants Use/Reveal. Persist nonzero observed state even on error before using
// the returned native plan; all intermediate observations form one revision.
func (s TrustState) VerifyConnectionSnapshot(ctx context.Context, node uuid.UUID, snapshot *UnverifiedConnectionSnapshot) (observed TrustState, plan resolver.Plan, err error) {
	if snapshot == nil || node == uuid.Nil || snapshot.node != node || snapshot.workspace != s.WorkspaceID || snapshot.user != s.UserID {
		return TrustState{}, resolver.Plan{}, ErrAdmissionResponse
	}
	observed = cloneTrustState(s)
	changed := false
	defer func() {
		if changed {
			observed.Revision = s.Revision + 1
		}
		if err != nil {
			plan = resolver.Plan{}
		}
	}()
	absorb := func(next TrustState) {
		if next.Revision != 0 {
			changed = changed || next.Revision != s.Revision
			next.Revision = s.Revision
			observed = next
		}
	}
	next, p, e := observed.ResolveCatalogConnection(ctx, node, snapshot.records)
	absorb(next)
	if e != nil {
		return observed, plan, e
	}
	for _, m := range snapshot.manifests {
		if e := ctx.Err(); e != nil {
			return observed, plan, e
		}
		next, e := observed.AdvanceBoundary(m.BoundaryID, m)
		absorb(next)
		if e != nil {
			return observed, plan, e
		}
	}
	if e := ctx.Err(); e != nil {
		return observed, plan, e
	}
	if p != snapshot.plan {
		return observed, plan, ErrAdmissionResponse
	}
	return observed, p, nil
}
