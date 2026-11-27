package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"testing"
)

const treeFirstID = "22345678-1234-4234-8234-123456789abc"
const treeSecondID = "32345678-1234-4234-8234-123456789abc"

func treeRows() [][][]byte {
	node, _ := json.Marshal(vaultstore.NodeMetadata{ID: treeFirstID, Name: "Node", Kind: 1})
	return [][][]byte{{[]byte(testHintID), []byte(testHintID), []byte("1"), []byte("7"), []byte("1"), []byte("false"), node, []byte("31"), []byte(testHintID), []byte("3"), []byte("2"), []byte(testHintID), []byte("1"), nil, hex.AppendEncode(nil, bytes.Repeat([]byte{7}, 64))}}
}

func TestTreeMetadataImportedReferenceIsOptionalAndStrict(t *testing.T) {
	node := vaultstore.NodeMetadata{ID: treeFirstID, Kind: 1, Name: "Imported node",
		Imported: &vaultstore.NodeImportReference{Digest: hex.EncodeToString(bytes.Repeat([]byte{77}, 32)), RetainedPins: true}}
	raw, err := json.Marshal(node)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := parseTreeMetadata(raw); err != nil || parsed.Imported == nil || *parsed.Imported != *node.Imported {
		t.Fatal("valid signed reference was lost from the projection", err)
	}
	for _, invalid := range []string{`null`, `{}`, `{"digest":"short","retainedPins":true}`,
		`{"retainedPins":false,"retainedPins":true,"digest":"` + node.Imported.Digest + `"}`} {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		fields["imported"] = json.RawMessage(invalid)
		broken, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseTreeMetadata(broken); err != ErrAdmissionResponse {
			t.Fatal("malformed reference reached native verification", err)
		}
	}
}
func TestTreePageParsing(t *testing.T) {
	rows := treeRows()
	page, err := parseTreePage(rows, admissionRequest(), TreeCursor{}, 1)
	if err != nil || len(page.Nodes) != 1 || page.Next != nil || page.Nodes[0].Seal.Revision != 3 {
		t.Fatal(page, err)
	}
	wipeQueryRows(rows)
	if page.Nodes[0].Seal.Signature[0] != 7 {
		t.Fatal("signature aliases wire")
	}
	rows = treeRows()
	rows[0][5] = []byte("true")
	rows[0][13] = []byte(treeSecondID)
	page, err = parseTreePage(rows, admissionRequest(), TreeCursor{}, 1)
	if err != nil || page.Next == nil || page.Next.After.String() != treeFirstID || page.Nodes[0].Seal.CapabilityID == nil {
		t.Fatal(page, err)
	}
	next := treeRows()
	next[0][6] = bytes.ReplaceAll(next[0][6], []byte(treeFirstID), []byte(treeSecondID))
	if _, err := parseTreePage(next, admissionRequest(), *page.Next, 1); err != nil {
		t.Fatal(err)
	}
	empty := treeRows()
	for i := 6; i < 15; i++ {
		empty[0][i] = nil
	}
	if page, err := parseTreePage(empty, admissionRequest(), TreeCursor{}, 1); err != nil || len(page.Nodes) != 0 || page.Next != nil {
		t.Fatal(page, err)
	}
	reject := func(rows [][][]byte, cursor TreeCursor, limit int) {
		t.Helper()
		if _, err := parseTreePage(rows, admissionRequest(), cursor, limit); err != ErrAdmissionResponse {
			t.Fatal("invalid page accepted", err)
		}
	}
	for _, col := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14} {
		rows = treeRows()
		rows[0][col] = []byte("bad")
		reject(rows, TreeCursor{}, 1)
	}
	for _, value := range []string{"0", "2", "32", "031"} {
		rows = treeRows()
		rows[0][7] = []byte(value)
		reject(rows, TreeCursor{}, 1)
	}
	for _, col := range []int{2, 9, 12} {
		rows = treeRows()
		rows[0][col] = []byte("0")
		reject(rows, TreeCursor{}, 1)
	}
	rows = treeRows()
	rows[0][14] = bytes.Repeat([]byte{'z'}, 128)
	reject(rows, TreeCursor{}, 1)
	reject(nil, TreeCursor{}, 1)
	reject([][][]byte{{}}, TreeCursor{}, 1)
	reject(append(treeRows(), treeRows()[0]), TreeCursor{}, 1)
	reject(append(treeRows(), treeRows()[0]), TreeCursor{}, 2)
	for _, col := range []int{2, 3, 5} {
		rows = treeRows()
		second := treeRows()[0]
		second[col] = []byte(map[int]string{2: "2", 3: "8", 5: "true"}[col])
		reject(append(rows, second), TreeCursor{}, 2)
	}
	rows = treeRows()
	rows[0][5] = []byte("true")
	reject(rows, TreeCursor{}, 2)
	reject(treeRows(), TreeCursor{After: uuid.MustParse(treeFirstID), Epoch: 1, ChangeSeq: 7}, 1)
	reject(treeRows(), TreeCursor{After: uuid.MustParse(testHintID), Epoch: 2, ChangeSeq: 7}, 1)
	empty[0][7] = []byte("1")
	reject(empty, TreeCursor{}, 1)
	empty[0][7] = nil
	empty[0][5] = []byte("true")
	reject(empty, TreeCursor{}, 1)
}
func TestTreeMetadataParsing(t *testing.T) {
	valid := treeRows()[0][6]
	for _, raw := range [][]byte{nil, []byte("null"), []byte("[]"), []byte("{"), []byte(`{"id":`), []byte(`{1:2}`), []byte(`{"id":"a","id":"b"}`), []byte(`{"x":true]`), append(bytes.Clone(valid), []byte(" {}")...), append(bytes.Clone(valid), 0xff), bytes.Repeat([]byte{'x'}, 512*1024+1), []byte(`{}`), bytes.Replace(valid, []byte(`"id"`), []byte(`"Id"`), 1), bytes.Replace(valid, []byte(`"kind":1`), []byte(`"kind":null`), 1), bytes.Replace(valid, []byte(`"kind":1`), []byte(`"kind":9`), 1), bytes.Replace(valid, []byte(`"kind":1`), []byte(`"kind":{}`), 1)} {
		if _, err := parseTreeMetadata(raw); err != ErrAdmissionResponse {
			t.Fatal("invalid metadata accepted", err)
		}
	}
	many := make(map[string]int)
	for i := 0; i < 65; i++ {
		many[uuid.NewString()] = i
	}
	raw, _ := json.Marshal(many)
	if _, err := parseTreeMetadata(raw); err != ErrAdmissionResponse {
		t.Fatal("unbounded field set")
	}
}
func TestTreePageValidation(t *testing.T) {
	s := NewSession()
	defer s.Close(context.Background())
	if _, err := s.TreePage(nil, TreeCursor{}, 1); err != ErrConfiguration {
		t.Fatal(err)
	}
	for _, limit := range []int{-1, 0, 33} {
		if _, err := s.TreePage(context.Background(), TreeCursor{}, limit); err != ErrConfiguration {
			t.Fatal(err)
		}
	}
	for _, cursor := range []TreeCursor{{Epoch: 1}, {ChangeSeq: 1}, {After: uuid.New()}, {After: uuid.New(), Epoch: 1 << 63}, {After: uuid.New(), Epoch: 1, ChangeSeq: 1 << 63}} {
		if _, err := s.TreePage(context.Background(), cursor, 1); err != ErrConfiguration {
			t.Fatal(err)
		}
	}
	if _, err := s.TreePage(context.Background(), TreeCursor{}, 1); err != ErrAuthentication {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.TreePage(ctx, TreeCursor{}, 1); err != context.Canceled {
		t.Fatal(err)
	}
	seedPasswordSession(t, s)
	if _, err := s.TreePage(context.Background(), TreeCursor{}, 1); err != ErrSessionClosed {
		t.Fatal(err)
	}
	fake, _ := readySession(t, false)
	seedPasswordSession(t, fake)
	if _, err := fake.TreePage(context.Background(), TreeCursor{}, 1); err != ErrQuery {
		t.Fatal(err)
	}
}
