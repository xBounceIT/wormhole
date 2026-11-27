package sharedpg

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"
)

func authorRows(t *testing.T) [][][]byte {
	s, _, _ := unlockStateFixture(t)
	r := accountMaterialRows()[0]
	return [][][]byte{{[]byte(testHintID), []byte(treeFirstID), []byte(testHintID), []byte("1"), []byte("7"), r[4], r[5], s[0][1], s[0][0], r[18], r[19], r[20], r[21], r[22], r[23]}}
}
func TestNodeAuthorParsing(t *testing.T) {
	parse := func(r [][][]byte) (*UnverifiedNodeAuthor, error) {
		return parseNodeAuthor(r, admissionRequest(), uuid.MustParse(treeFirstID), 1, 7)
	}
	r := authorRows(t)
	got, err := parse(r)
	if err != nil || got.Certificate == nil || got.State.Sequence != 4 {
		t.Fatal(got, err)
	}
	wipeQueryRows(r)
	if bytes.Equal(got.Certificate.PublicKey, make([]byte, 32)) {
		t.Fatal("certificate aliases wire")
	}
	for i := 0; i < 15; i++ {
		r = authorRows(t)
		r[0][i] = []byte("bad")
		if _, err := parse(r); err != ErrAdmissionResponse {
			t.Fatal("malformed field", i, err)
		}
	}
	for _, r := range [][][][]byte{nil, {{}}, append(authorRows(t), authorRows(t)...)} {
		if _, err := parse(r); err != ErrAdmissionResponse {
			t.Fatal("shape", err)
		}
	}
	r = authorRows(t)
	for i := 9; i < 15; i++ {
		r[0][i] = nil
	}
	if got, err := parse(r); err != nil || got.Certificate != nil {
		t.Fatal("missing certificate", err)
	}
	r[0][14] = []byte("bad")
	if _, err := parse(r); err != ErrAdmissionResponse {
		t.Fatal("partial certificate", err)
	}
	r = authorRows(t)
	r[0][11] = r[0][5]
	if _, err := parse(r); err != ErrAdmissionResponse {
		t.Fatal("self certified", err)
	}
	for _, col := range []int{10, 14} {
		r = authorRows(t)
		r[0][col] = bytes.Repeat([]byte{'z'}, len(r[0][col]))
		if _, err := parse(r); err != ErrAdmissionResponse {
			t.Fatal("invalid hex", err)
		}
	}
}
func TestNodeAuthorValidation(t *testing.T) {
	s := NewSession()
	defer s.Close(context.Background())
	id := uuid.MustParse(treeFirstID)
	if _, err := s.NodeAuthor(nil, id, 1, 0); err != ErrConfiguration {
		t.Fatal(err)
	}
	for _, v := range []TreeCursor{{}, {id, 0, 0}, {id, 1 << 63, 0}, {id, 1, 1 << 63}} {
		if _, err := s.NodeAuthor(context.Background(), v.After, v.Epoch, v.ChangeSeq); err != ErrConfiguration {
			t.Fatal(err)
		}
	}
	if _, err := s.NodeAuthor(context.Background(), id, 1, 0); err != ErrAuthentication {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.NodeAuthor(ctx, id, 1, 0); err != context.Canceled {
		t.Fatal(err)
	}
	seedPasswordSession(t, s)
	if _, err := s.NodeAuthor(context.Background(), id, 1, 0); err != ErrSessionClosed {
		t.Fatal(err)
	}
	fake, _ := readySession(t, false)
	seedPasswordSession(t, fake)
	if _, err := fake.NodeAuthor(context.Background(), id, 1, 0); err != ErrQuery {
		t.Fatal(err)
	}
}
