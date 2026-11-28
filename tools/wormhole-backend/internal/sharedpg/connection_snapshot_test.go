package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"sort"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func snapshotFixture(t *testing.T, kind string) (connectionFixture, map[string]any, resolver.Plan) {
	t.Helper()
	f := newConnectionFixture(t)
	switch kind {
	case "tunnel":
		id := uuid.NewString()
		enabled := true
		f.records.Chain[0].Node.Metadata.TunnelEnabled = &enabled
		f.records.Chain[0].Node.Metadata.TunnelConfigID = &id
		f.records.Tunnel = f.selection(t, sharedcatalog.TunnelRecord{Metadata: vaultstore.TunnelMetadata{ID: id, Name: "VPN", Kind: 1}, ConfigurationVersion: 1})
		f.records.Tunnel.Selection.Boundary = uuid.New()
		f.signSelection(t, f.records.Tunnel, 1)
		f.signChain(t)
	case "slot":
		f.slot(t, true)
	case "override":
		f.records.Override = f.selection(t, sharedcatalog.OverrideRecord{NodeID: f.node().String(), UserID: f.s.UserID.String(), CredentialID: f.records.Credential.Credential.Record.Metadata.ID})
	case "none":
		v := 1
		f.records.Chain[0].Node.Metadata.CredentialMode = &v
		f.records.Credential = nil
		f.signChain(t)
	case "gateway":
		p, m, h := 1, 1, "gateway.example"
		f.records.Chain[0].Node.Metadata.Protocol = &p
		f.records.Chain[0].Node.Metadata.RDPGatewayUsageMethod = &m
		f.records.Chain[0].Node.Metadata.RDPGatewayHostname = &h
		f.records.Credential.Credential.Record.Metadata.Protocol = "rdp"
		f.signProfile(t, f.records.Credential, 1)
		f.records.Gateway = f.profile(t, "rdp")
		f.records.Gateway.Credential.Boundary = uuid.New()
		f.signProfile(t, f.records.Gateway, 1)
		f.records.Chain[0].Node.Metadata.RDPGatewayCredentialID = &f.records.Gateway.Credential.Record.Metadata.ID
		f.signChain(t)
	}
	_, plan, e := f.s.ResolveCatalogConnection(context.Background(), f.node(), f.records)
	if e != nil {
		t.Fatal(e)
	}
	row := func(id string, body any, boundary uuid.UUID, seal vault.RecordSeal, a UnverifiedNodeAuthor) []any {
		if c, ok := body.(sharedcatalog.CredentialRecord); ok && c.Fields == nil {
			c.Fields = []vaultstore.CredentialField{}
			body = c
		}
		raw, _ := json.Marshal(body)
		state, e := vault.EncodeUserKeyState(*a.State)
		if e != nil {
			t.Fatal(e)
		}
		r := []any{f.s.WorkspaceID.String(), id, "1", "7", string(raw), boundary.String(), strconv.FormatUint(seal.Revision, 10), "2", seal.SignerKeyID, strconv.Itoa(int(seal.SignerKeyVersion)), nil, hex.EncodeToString(seal.Signature), a.State.UserID.String(), a.Key.ID.String(), strconv.Itoa(int(a.Key.Version)), strconv.FormatUint(a.State.Sequence, 10), hex.EncodeToString(state), nil, nil, nil, nil, nil, nil}
		if seal.CapabilityID != nil {
			r[10] = *seal.CapabilityID
		}
		if c := a.Certificate; c != nil {
			r[17] = "1"
			r[18] = hex.EncodeToString(c.PublicKey)
			r[19] = c.Signer.ID.String()
			r[20] = strconv.Itoa(int(c.Signer.Version))
			r[21] = strconv.FormatUint(c.Revision, 10)
			r[22] = hex.EncodeToString(c.Signature)
		}
		return r
	}
	required := make(map[uuid.UUID]bool)
	chain := []any{}
	for _, r := range f.records.Chain {
		chain = append(chain, row(r.Node.Metadata.ID, r.Node.Metadata, r.Node.Boundary, r.Node.Seal, r.Author))
		required[r.Node.Boundary] = true
	}
	selection := func(r *UnverifiedSelectionRecord) any {
		if r == nil {
			return nil
		}
		scope, _, _ := sharedcatalog.SelectionIdentity(r.Selection.Record)
		required[r.Selection.Boundary] = true
		return row(scope.Subject.String(), r.Selection.Record, r.Selection.Boundary, r.Selection.Seal, r.Author)
	}
	credential := func(r *UnverifiedCredentialRecord) any {
		if r == nil {
			return nil
		}
		required[r.Credential.Boundary] = true
		return row(r.Credential.Record.Metadata.ID, r.Credential.Record, r.Credential.Boundary, r.Credential.Seal, r.Author)
	}
	w := map[string]any{"formatVersion": 1, "workspaceId": f.s.WorkspaceID.String(), "userId": f.s.UserID.String(), "nodeId": f.node().String(), "epoch": "1", "changeSeq": "7", "plan": plan, "chain": chain, "override": selection(f.records.Override), "slot": selection(f.records.Slot), "slotValue": selection(f.records.SlotValue), "credential": credential(f.records.Credential), "gateway": credential(f.records.Gateway)}
	if f.records.Tunnel != nil {
		w["formatVersion"], w["tunnel"] = 2, selection(f.records.Tunnel)
	}
	ids := []uuid.UUID{}
	for id := range required {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
	manifests := []any{}
	for _, id := range ids {
		_, _, _, m, _ := boundaryTrustFixture(t)
		m.WorkspaceID = f.s.WorkspaceID
		m.BoundaryID = id
		m.Signer = vault.KeyRef{ID: uuid.MustParse(f.s.SignerKeyID), Version: f.s.SignerKeyVersion}
		m, e = vault.SignBoundaryManifest(m, f.org)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := vault.EncodeBoundaryManifest(m)
		manifests = append(manifests, []any{m.WorkspaceID.String(), id.String(), "1", "7", "1", hex.EncodeToString(raw), m.Signer.ID.String(), strconv.Itoa(int(m.Signer.Version)), hex.EncodeToString(m.Signature)})
	}
	w["boundaries"] = manifests
	return f, w, plan
}
func snapshotParseFixture(t *testing.T, f connectionFixture, w map[string]any) (*UnverifiedConnectionSnapshot, error) {
	t.Helper()
	raw, e := json.Marshal(w)
	if e != nil {
		t.Fatal(e)
	}
	return parseConnectionSnapshot(raw, AdmissionRequest{WorkspaceID: f.s.WorkspaceID, UserID: f.s.UserID}, f.node(), 1, 7)
}
func TestConnectionSnapshotVerification(t *testing.T) {
	for _, kind := range []string{"saved", "slot", "override", "none", "gateway"} {
		t.Run(kind, func(t *testing.T) {
			f, w, want := snapshotFixture(t, kind)
			raw, _ := json.Marshal(w)
			snapshot, e := parseConnectionSnapshot(raw, AdmissionRequest{WorkspaceID: f.s.WorkspaceID, UserID: f.s.UserID}, f.node(), 1, 7)
			if e != nil {
				t.Fatal(e)
			}
			vault.Wipe(raw)
			next, p, e := f.s.VerifyConnectionSnapshot(context.Background(), f.node(), snapshot)
			if e != nil || p != want || next.Revision != f.s.Revision+1 || f.s.ValidateAdvance(next) != nil {
				t.Fatal("snapshot", e)
			}
			again, p, e := next.VerifyConnectionSnapshot(context.Background(), f.node(), snapshot)
			if e != nil || p != want || !reflect.DeepEqual(next, again) {
				t.Fatal("idempotence", e)
			}
			w["plan"] = func() resolver.Plan { p := want; p.Host = "attacker.example"; return p }()
			bad, e := snapshotParseFixture(t, f, w)
			if e != nil {
				t.Fatal(e)
			}
			observed, p, e := f.s.VerifyConnectionSnapshot(context.Background(), f.node(), bad)
			if e != ErrAdmissionResponse || p != (resolver.Plan{}) || !reflect.DeepEqual(observed, next) {
				t.Fatal("server plan redirect or lost observations", e)
			}
		})
	}
}
func TestConnectionSnapshotMalformed(t *testing.T) {
	for _, mode := range []string{"version", "workspace", "user", "node", "epoch", "sequence", "plan", "plan-choice", "chain-empty", "chain-shape", "chain-id", "chain-body", "chain-header", "override", "slot", "value-without-slot", "value-user", "credential", "gateway", "manifest-missing", "manifest-extra", "manifest-header"} {
		t.Run(mode, func(t *testing.T) {
			f, w, _ := snapshotFixture(t, "slot")
			switch mode {
			case "version":
				w["formatVersion"] = 0
			case "workspace":
				w["workspaceId"] = uuid.NewString()
			case "user":
				w["userId"] = uuid.NewString()
			case "node":
				w["nodeId"] = uuid.NewString()
			case "epoch":
				w["epoch"] = "2"
			case "sequence":
				w["changeSeq"] = "8"
			case "plan":
				w["plan"] = map[string]any{}
			case "plan-choice":
				p := w["plan"].(resolver.Plan)
				raw, _ := json.Marshal(p)
				var obj map[string]any
				json.Unmarshal(raw, &obj)
				obj["credential"] = map[string]any{}
				w["plan"] = obj
			case "chain-empty":
				w["chain"] = []any{}
			case "chain-shape":
				w["chain"] = []any{[]any{}}
			case "chain-id":
				w["chain"].([]any)[0].([]any)[1] = "bad"
			case "chain-body":
				w["chain"].([]any)[0].([]any)[4] = "{}"
			case "chain-header":
				w["chain"].([]any)[0].([]any)[3] = "8"
			case "override":
				w["override"] = []any{}
			case "slot":
				w["slot"].([]any)[1] = "bad"
			case "value-without-slot":
				w["slot"] = nil
			case "value-user":
				r := w["slotValue"].([]any)
				var body map[string]any
				json.Unmarshal([]byte(r[4].(string)), &body)
				body["userId"] = uuid.NewString()
				raw, _ := json.Marshal(body)
				r[4] = string(raw)
			case "credential":
				w["credential"] = []any{}
			case "gateway":
				w["gateway"] = []any{}
			case "manifest-missing":
				w["boundaries"] = []any{}
			case "manifest-extra":
				w["boundaries"] = append(w["boundaries"].([]any), w["boundaries"].([]any)...)
			case "manifest-header":
				w["boundaries"].([]any)[0].([]any)[2] = "2"
			}
			if _, e := snapshotParseFixture(t, f, w); e != ErrAdmissionResponse {
				t.Fatal("malformed accepted", mode, e)
			}
		})
	}
	f, w, _ := snapshotFixture(t, "saved")
	raw, _ := json.Marshal(w)
	request := AdmissionRequest{WorkspaceID: f.s.WorkspaceID, UserID: f.s.UserID}
	for _, bad := range [][]byte{nil, bytes.Repeat([]byte(" "), MaxConnectionSnapshotBytes+1), []byte{255}, []byte("null"), append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"userId":"x"}`)...)} {
		if _, e := parseConnectionSnapshot(bad, request, f.node(), 1, 7); e != ErrAdmissionResponse {
			t.Fatal(e)
		}
	}
	for field := range w {
		copy := make(map[string]any)
		for k, v := range w {
			copy[k] = v
		}
		delete(copy, field)
		if _, e := snapshotParseFixture(t, f, copy); e != ErrAdmissionResponse {
			t.Fatal("missing", field, e)
		}
	}
	for _, n := range []uint64{0, math.MaxUint64} {
		if _, e := parseConnectionSnapshot(raw, request, f.node(), n, 7); e != ErrAdmissionResponse {
			t.Fatal(e)
		}
	}
	if _, e := parseConnectionSnapshot(raw, request, f.node(), 1, math.MaxUint64); e != ErrAdmissionResponse {
		t.Fatal(e)
	}
	w["formatVersion"] = 5
	if _, e := snapshotParseFixture(t, f, w); e != vault.ErrNewerFormat {
		t.Fatal(e)
	}
}
func TestSnapshotRowBounds(t *testing.T) {
	for _, raw := range []string{`null`, `{}`, `[[]]`, `[["a",1]]`, `[["a",true]]`, `[["a","b","c"]]`, `[["a","b"],["c","d"]]`, `[["a","b"]] {}`} {
		if _, e := snapshotRows([]byte(raw), 1, 2); e != ErrAdmissionResponse {
			t.Fatal("rows", raw, e)
		}
	}
	for _, raw := range []string{`[]`, `null {}`, `["a","b"] {}`} {
		if _, e := snapshotOptionalRow([]byte(raw), 2); e != ErrAdmissionResponse {
			t.Fatal("optional row", raw, e)
		}
	}
}

func TestConnectionSnapshotFailureObservations(t *testing.T) {
	f, w, _ := snapshotFixture(t, "saved")
	snapshot, e := snapshotParseFixture(t, f, w)
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"inactive", "bad-signature", "cancel-before", "cancel-after-chain", "cancel-after-manifest", "bad-chain"} {
		t.Run(mode, func(t *testing.T) {
			f, w, _ := snapshotFixture(t, "saved")
			snap, e := snapshotParseFixture(t, f, w)
			if e != nil {
				t.Fatal(e)
			}
			ctx := context.Context(context.Background())
			want := error(vault.ErrPolicy)
			switch mode {
			case "inactive":
				snap.manifests[0].Active = false
				snap.manifests[0], e = vault.SignBoundaryManifest(snap.manifests[0], f.org)
				if e != nil {
					t.Fatal(e)
				}
			case "bad-signature":
				snap.manifests[0].Signature = make([]byte, 64)
				want = vault.ErrAuthentication
			case "cancel-before":
				ctx = &cancelResolutionContext{Context: context.Background(), after: 0}
				want = context.Canceled
			case "cancel-after-chain":
				ctx = &cancelResolutionContext{Context: context.Background(), after: 5}
				want = context.Canceled
			case "cancel-after-manifest":
				ctx = &cancelResolutionContext{Context: context.Background(), after: 6}
				want = context.Canceled
			case "bad-chain":
				snap.records.Chain[0].Node.Seal.Signature = make([]byte, 64)
				want = vault.ErrAuthentication
			}
			observed, p, e := f.s.VerifyConnectionSnapshot(ctx, f.node(), snap)
			if e != want || p != (resolver.Plan{}) || observed.Revision == 0 || (!reflect.DeepEqual(observed, f.s) && f.s.ValidateAdvance(observed) != nil) {
				t.Fatal("failed snapshot", mode, e)
			}
			if mode == "inactive" && observed.Catalog["boundary/"+snap.manifests[0].BoundaryID.String()].Revision != 1 {
				t.Fatal("inactive observation lost")
			}
		})
	}
	for _, invalid := range []*UnverifiedConnectionSnapshot{nil, {}, {workspace: f.s.WorkspaceID, user: uuid.New(), node: f.node()}} {
		if _, _, e = f.s.VerifyConnectionSnapshot(context.Background(), f.node(), invalid); e != ErrAdmissionResponse {
			t.Fatal(e)
		}
	}
	f.s.Revision = math.MaxUint64 - 1
	next, p, e := f.s.VerifyConnectionSnapshot(context.Background(), f.node(), snapshot)
	if e != nil || next.Revision != math.MaxUint64 || p.NodeID != f.node().String() {
		t.Fatal("single counter", e)
	}
	same, _, e := next.VerifyConnectionSnapshot(context.Background(), f.node(), snapshot)
	if e != nil || !reflect.DeepEqual(same, next) {
		t.Fatal("max repeat", e)
	}
}
