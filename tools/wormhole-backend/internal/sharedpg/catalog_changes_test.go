package sharedpg

import (
	"context"
	"testing"
)

func changesRows() [][][]byte {
	return [][][]byte{{[]byte(testHintID), []byte(testHintID), []byte("1"), []byte("7"), []byte("1"), []byte("false"), []byte(treeFirstID)}}
}
func TestCatalogChangesParsing(t *testing.T) {
	rows := changesRows()
	r, err := parseCatalogChanges(rows, admissionRequest(), 1, 6)
	if err != nil || r.Reset || len(r.Nodes) != 1 {
		t.Fatal(r, err)
	}
	wipeQueryRows(rows)
	if r.Nodes[0].String() != treeFirstID {
		t.Fatal("wire alias")
	}
	rows = changesRows()
	rows[0][6] = nil
	if _, err := parseCatalogChanges(rows, admissionRequest(), 1, 7); err != nil {
		t.Fatal(err)
	}
	rows[0][5] = []byte("true")
	if r, err := parseCatalogChanges(rows, admissionRequest(), 0, 0); err != nil || !r.Reset {
		t.Fatal(r, err)
	}
	rows = append(changesRows(), changesRows()[0])
	rows[1][6] = []byte(treeSecondID)
	if r, err := parseCatalogChanges(rows, admissionRequest(), 1, 6); err != nil || len(r.Nodes) != 2 {
		t.Fatal(r, err)
	}
	reject := func(rows [][][]byte, e, s uint64) {
		t.Helper()
		if _, err := parseCatalogChanges(rows, admissionRequest(), e, s); err != ErrAdmissionResponse {
			t.Fatal("bad change response", err)
		}
	}
	reject(nil, 1, 6)
	reject([][][]byte{{}}, 1, 6)
	reject(make([][][]byte, 33), 1, 6)
	for i := 0; i < 7; i++ {
		rows = changesRows()
		rows[0][i] = []byte("bad")
		reject(rows, 1, 6)
	}
	reject(changesRows(), 2, 6)
	reject(changesRows(), 1, 8)
	reject(changesRows(), 0, 0)
	reject(changesRows(), 1, 7)
	rows = changesRows()
	rows[0][5] = []byte("true")
	reject(rows, 1, 6)
	for _, col := range []int{2, 3, 5, 6} {
		rows = append(changesRows(), changesRows()[0])
		rows[1][6] = []byte(treeSecondID)
		rows[1][col] = []byte(map[int]string{2: "2", 3: "8", 5: "true", 6: treeFirstID}[col])
		reject(rows, 1, 6)
	}
	rows = append(changesRows(), changesRows()[0])
	rows[1][6] = nil
	reject(rows, 1, 6)
	rows = changesRows()
	rows[0][6] = []byte{}
	reject(rows, 1, 6)
}
func TestCatalogChangesValidation(t *testing.T) {
	s := NewSession()
	defer s.Close(context.Background())
	if _, err := s.ChangesSince(nil, 0, 0); err != ErrConfiguration {
		t.Fatal(err)
	}
	for _, v := range [][2]uint64{{0, 1}, {1 << 63, 0}, {1, 1 << 63}} {
		if _, err := s.ChangesSince(context.Background(), v[0], v[1]); err != ErrConfiguration {
			t.Fatal(err)
		}
	}
	if _, err := s.ChangesSince(context.Background(), 0, 0); err != ErrAuthentication {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ChangesSince(ctx, 0, 0); err != context.Canceled {
		t.Fatal(err)
	}
	seedPasswordSession(t, s)
	if _, err := s.ChangesSince(context.Background(), 0, 0); err != ErrSessionClosed {
		t.Fatal(err)
	}
	fake, _ := readySession(t, false)
	seedPasswordSession(t, fake)
	if _, err := fake.ChangesSince(context.Background(), 0, 0); err != ErrQuery {
		t.Fatal(err)
	}
}
