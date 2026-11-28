package sharedpg

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func boundaryProjectionRows(t *testing.T) ([][][]byte, AdmissionRequest, TrustState, vault.BoundaryManifest) {
	t.Helper()
	_, b, s, m, _ := boundaryTrustFixture(t)
	raw, e := vault.EncodeBoundaryManifest(m)
	if e != nil {
		t.Fatal(e)
	}
	rows := [][][]byte{{[]byte(b.WorkspaceID.String()), []byte(m.BoundaryID.String()), []byte("1"), []byte("7"), []byte(strconv.FormatUint(m.Revision, 10)), hex.AppendEncode(nil, raw), []byte(m.Signer.ID.String()), []byte(strconv.FormatUint(uint64(m.Signer.Version), 10)), hex.AppendEncode(nil, m.Signature)}}
	return rows, AdmissionRequest{WorkspaceID: b.WorkspaceID, UserID: b.UserID}, s, m
}
func TestBoundaryProjection(t *testing.T) {
	rows, request, trust, want := boundaryProjectionRows(t)
	got, e := parseBoundaryProjection(rows, request, want.BoundaryID, 1, 7)
	if e != nil || !reflect.DeepEqual(*got, want) {
		t.Fatal("projection", e)
	}
	wipeQueryRows(rows)
	if next, e := trust.AdvanceBoundary(want.BoundaryID, *got); e != nil || len(next.Catalog) != 3 {
		t.Fatal("wire alias/authentication", e)
	}
	for col := 0; col < 9; col++ {
		rows, request, _, want = boundaryProjectionRows(t)
		rows[0][col] = []byte("bad")
		if _, e := parseBoundaryProjection(rows, request, want.BoundaryID, 1, 7); e != ErrAdmissionResponse {
			t.Fatal("bad column", col, e)
		}
	}
	rows, request, _, want = boundaryProjectionRows(t)
	for _, shape := range [][][][]byte{nil, {{}}, append(rows, rows...)} {
		if _, e := parseBoundaryProjection(shape, request, want.BoundaryID, 1, 7); e != ErrAdmissionResponse {
			t.Fatal("shape", e)
		}
	}
	for _, invalid := range []struct {
		id         uuid.UUID
		epoch, seq uint64
	}{{uuid.Nil, 1, 7}, {want.BoundaryID, 0, 7}, {want.BoundaryID, 1 << 63, 7}, {want.BoundaryID, 1, 1 << 63}} {
		if _, e := parseBoundaryProjection(rows, request, invalid.id, invalid.epoch, invalid.seq); e != ErrAdmissionResponse {
			t.Fatal("request", e)
		}
	}
	missing := request
	missing.WorkspaceID = uuid.Nil
	if _, e := parseBoundaryProjection(rows, missing, want.BoundaryID, 1, 7); e != ErrAdmissionResponse {
		t.Fatal(e)
	}
	for _, bad := range []struct {
		col   int
		value []byte
	}{{0, []byte(uuid.NewString())}, {1, []byte(uuid.NewString())}, {2, []byte("2")}, {3, []byte("8")}, {4, []byte("2")}, {4, []byte("0")}, {4, []byte("01")}, {5, nil}, {5, bytes.Repeat([]byte("00"), vault.MaxBoundaryManifestBytes+1)}, {5, []byte("ff")}, {5, []byte("0")}, {6, []byte(uuid.NewString())}, {7, []byte("2")}, {7, []byte(strconv.FormatUint(uint64(math.MaxInt32)+1, 10))}, {8, bytes.Repeat([]byte("00"), 63)}, {8, bytes.Repeat([]byte("zz"), 64)}, {8, bytes.Repeat([]byte("00"), 64)}} {
		rows, request, _, want = boundaryProjectionRows(t)
		rows[0][bad.col] = bad.value
		if _, e := parseBoundaryProjection(rows, request, want.BoundaryID, 1, 7); e != ErrAdmissionResponse {
			t.Fatal("header/body mismatch", bad.col, e)
		}
	}
	for _, change := range []func(*vault.BoundaryManifest){func(m *vault.BoundaryManifest) { m.WorkspaceID = uuid.New() }, func(m *vault.BoundaryManifest) { m.BoundaryID = uuid.New() }, func(m *vault.BoundaryManifest) { m.Revision++ }, func(m *vault.BoundaryManifest) { m.Signer.ID = uuid.New() }, func(m *vault.BoundaryManifest) { m.Signer.Version++ }} {
		rows, request, _, want = boundaryProjectionRows(t)
		m := want
		change(&m)
		raw, _ := vault.EncodeBoundaryManifest(m)
		rows[0][5] = hex.AppendEncode(nil, raw)
		if _, e := parseBoundaryProjection(rows, request, want.BoundaryID, 1, 7); e != ErrAdmissionResponse {
			t.Fatal("decoded header binding", e)
		}
	}
	rows, request, trust, want = boundaryProjectionRows(t)
	want.Active = false
	raw, _ := vault.EncodeBoundaryManifest(want)
	rows[0][5] = hex.AppendEncode(nil, raw)
	got, e = parseBoundaryProjection(rows, request, want.BoundaryID, 1, 7)
	if e != nil {
		t.Fatal("parser incorrectly authenticates", e)
	}
	if _, e = trust.AdvanceBoundary(want.BoundaryID, *got); e != vault.ErrAuthentication {
		t.Fatal("tamper accepted", e)
	}
	rows, request, _, want = boundaryProjectionRows(t)
	want.FormatVersion++
	raw, _ = json.Marshal(want)
	rows[0][5] = hex.AppendEncode(nil, raw)
	if _, e := parseBoundaryProjection(rows, request, want.BoundaryID, 1, 7); e != vault.ErrNewerFormat {
		t.Fatal("future format", e)
	}
}
