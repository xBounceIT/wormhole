package sharedpg

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestWebSessionViewGenerationsRejectUnrelatedOrAmbiguousReceipts(t *testing.T) {
	first := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	next := uuid.MustParse("00000000-0000-0000-0000-000000000002")
	generation := uuid.MustParse("33333333-abcd-4444-9999-333333333333")
	expected := map[uuid.UUID]struct{}{first: {}, next: {}}
	encode := func(rows ...[]string) []byte {
		buf, err := json.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
		return buf
	}
	good := []string{first.String(), generation.String()}
	later := []string{next.String(), uuid.NewString()}
	for _, bad := range [][]byte{
		[]byte("null"), []byte("{}"), []byte(`[["bad"`), []byte(strings.Repeat(" ", maxWebSessionViewReply+1)),
		encode(good, good), encode(later, good), encode([]string{first.String()}),
		encode([]string{uuid.NewString(), generation.String()}),
		encode([]string{first.String(), uuid.Nil.String()}),
		encode([]string{first.String(), strings.ToUpper(generation.String())}),
		encode(good, later, []string{uuid.NewString(), generation.String()}),
	} {
		if _, err := parseWebSessionViewGenerations(bad, expected); err != ErrAdmissionResponse {
			t.Fatalf("unexpected receipt accepted: %v", err)
		}
	}
	if got, err := parseWebSessionViewGenerations([]byte("[]"), expected); err != nil || len(got) != 0 {
		t.Fatalf("empty reply must distinguish revocation from transport failure: %v", err)
	}
	if got, err := parseWebSessionViewGenerations(encode(good), expected); err != nil || len(got) != 1 || got[first] != generation {
		t.Fatalf("valid sparse View reply was lost: %v", err)
	}
	req := admissionRequest()
	row := [][]byte{[]byte(req.WorkspaceID.String()), []byte(req.UserID.String()), []byte(req.DeviceID.String()), nil}
	if !validWebSessionViewResponse([][][]byte{row}, req, 4) || validWebSessionViewResponse(nil, req, 4) ||
		validWebSessionViewResponse([][][]byte{row, row}, req, 4) || validWebSessionViewResponse([][][]byte{row[:2]}, req, 4) {
		t.Fatal("response envelope did not bind shape and identity")
	}
	row[2] = []byte(uuid.NewString())
	if validWebSessionViewResponse([][][]byte{row}, req, 4) {
		t.Fatal("response substituted the device")
	}
}

func TestWebSessionViewConfigurationChecks(t *testing.T) {
	s := NewSession()
	ctx := context.Background()
	defer s.Close(ctx)
	node := uuid.New()
	for _, nodes := range [][]uuid.UUID{nil, {uuid.Nil}, {node, node}, make([]uuid.UUID, MaxTreePage+1)} {
		if _, err := s.CheckWebSessionViews(ctx, nodes); err != ErrConfiguration {
			t.Fatal("invalid request reached transport", err)
		}
	}
	if _, err := s.CheckWebSessionViews(nil, []uuid.UUID{node}); err != ErrConfiguration {
		t.Fatal(err)
	}
	if _, err := s.OpenWebSessionView(ctx, uuid.Nil); err != ErrConfiguration {
		t.Fatal(err)
	}
	if _, err := s.OpenWebSessionView(nil, node); err != ErrConfiguration {
		t.Fatal(err)
	}
	if _, err := s.OpenWebSessionView(ctx, node); err != ErrAuthentication {
		t.Fatal("unadmitted register reached the database", err)
	}
	if _, err := s.CheckWebSessionViews(ctx, []uuid.UUID{node}); err != ErrAuthentication {
		t.Fatal("unadmitted lookup reached the database", err)
	}
	if _, err := s.SetWebSessionCheckpoint(ctx, node, uuid.Nil, true); err != ErrConfiguration {
		t.Fatal("missing View generation reached the database", err)
	}
	if _, err := s.SetWebSessionCheckpoint(ctx, node, uuid.New(), true); err != ErrAuthentication {
		t.Fatal("unadmitted checkpoint report reached the database", err)
	}
}

func TestWebSessionCheckpointReceiptBindsDeviceTargetAndGeneration(t *testing.T) {
	request := admissionRequest()
	node, generation := uuid.New(), uuid.New()
	row := [][]byte{[]byte(request.WorkspaceID.String()), []byte(request.UserID.String()), []byte(request.DeviceID.String()),
		[]byte(node.String()), []byte(generation.String()), []byte("true")}
	for _, tc := range []struct {
		column int
		value  []byte
	}{{0, []byte(uuid.NewString())}, {1, []byte(uuid.NewString())}, {2, []byte(uuid.NewString())},
		{3, []byte(uuid.NewString())}, {4, []byte(uuid.NewString())}, {5, []byte("1")}, {5, nil}} {
		substituted := append([][]byte(nil), row...)
		substituted[tc.column] = tc.value
		if accepted, err := parseWebSessionCheckpoint([][][]byte{substituted}, request, node, generation); accepted || err != ErrAdmissionResponse {
			t.Fatalf("receipt accepted a substituted field %d: %v", tc.column, err)
		}
	}
	for _, want := range []bool{true, false} {
		if !want {
			row[5] = []byte("false")
		}
		if accepted, err := parseWebSessionCheckpoint([][][]byte{row}, request, node, generation); accepted != want || err != nil {
			t.Fatal("well-formed receipt lost its decision", err)
		}
	}
}
