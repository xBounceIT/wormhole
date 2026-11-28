package sharedpg

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestSelectionProjectionParsing(t *testing.T) {
	records := []sharedcatalog.SelectionRecord{
		sharedcatalog.SlotRecord{ID: uuid.NewString(), Name: "Account", Protocol: "ssh", AllowSelfService: true},
		sharedcatalog.SlotValueRecord{ID: uuid.NewString(), SlotID: uuid.NewString(), UserID: uuid.NewString(), CredentialID: uuid.NewString()},
		sharedcatalog.OverrideRecord{NodeID: uuid.NewString(), UserID: uuid.NewString(), Deleted: true},
	}
	for _, record := range records {
		rows, request, c, author, trust := credentialProjectionRows(t)
		scope, deleted, _ := sharedcatalog.SelectionIdentity(record)
		var wantErr error
		if deleted {
			wantErr = vaultstore.ErrMissing
		}
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{27}, 32))
		seal, e := sharedcatalog.SignSelection(request.WorkspaceID, c.Boundary, record, 1, author.Key, key)
		if e != nil {
			t.Fatal(e)
		}
		rows[0][1] = []byte(scope.Subject.String())
		rows[0][4], _ = json.Marshal(record)
		rows[0][11] = hex.AppendEncode(nil, seal.Signature)
		got, a, e := parseSelectionProjection(rows, request, scope, 1, 7)
		if e != nil || !reflect.DeepEqual(got.Record, record) || !reflect.DeepEqual(*a, author) {
			t.Fatal("projection", e)
		}
		next, e := trust.AdvanceSelection(*got, *a)
		if e != wantErr || next.Revision == 0 || len(next.Catalog) != 3 {
			t.Fatal("unverifiable projection", e)
		}
		for col := 0; col < 23; col++ {
			saved := rows[0][col]
			rows[0][col] = []byte("bad")
			if _, _, e = parseSelectionProjection(rows, request, scope, 1, 7); e != ErrAdmissionResponse {
				t.Fatal("column", col, e)
			}
			rows[0][col] = saved
		}
		for _, p := range []sharedcatalog.SelectionScope{{Kind: scope.Kind, Subject: uuid.New(), User: scope.User}, {Kind: scope.Kind, Subject: scope.Subject, User: uuid.New()}, {Kind: "unknown", Subject: scope.Subject, User: scope.User}} {
			if _, _, e = parseSelectionProjection(rows, request, p, 1, 7); e != ErrAdmissionResponse {
				t.Fatal("scope", e)
			}
		}
		wipeQueryRows(rows)
		if after, e := trust.AdvanceSelection(*got, *a); e != wantErr || after.Revision == 0 || !reflect.DeepEqual(after, next) {
			t.Fatal("wire alias", e)
		}
	}
}

func TestSelectionRecordStrictDecoding(t *testing.T) {
	records := map[string]sharedcatalog.SelectionRecord{
		"slot":       sharedcatalog.SlotRecord{ID: uuid.NewString(), Name: "Account", Protocol: "ssh"},
		"slot-value": sharedcatalog.SlotValueRecord{ID: uuid.NewString(), SlotID: uuid.NewString(), UserID: uuid.NewString(), CredentialID: uuid.NewString()},
		"override":   sharedcatalog.OverrideRecord{NodeID: uuid.NewString(), UserID: uuid.NewString(), CredentialID: uuid.NewString()},
	}
	for kind, r := range records {
		raw, _ := json.Marshal(r)
		var obj map[string]json.RawMessage
		json.Unmarshal(raw, &obj)
		bad := [][]byte{nil, []byte("null"), []byte("[]"), []byte("{}"), []byte{255}, bytes.Repeat([]byte(" "), 16385), append(append([]byte{}, raw...), []byte(" {}")...)}
		for field := range obj {
			for _, value := range []string{"null", "[]", "12"} {
				var copy map[string]json.RawMessage
				json.Unmarshal(raw, &copy)
				copy[field] = json.RawMessage(value)
				v, _ := json.Marshal(copy)
				bad = append(bad, v)
			}
			var copy map[string]json.RawMessage
			json.Unmarshal(raw, &copy)
			delete(copy, field)
			v, _ := json.Marshal(copy)
			bad = append(bad, v)
			prefix := append([]byte{}, raw[:len(raw)-1]...)
			bad = append(bad, append(prefix, []byte(",\""+field+"\":null}")...))
		}
		bad = append(bad, append(append([]byte{}, raw[:len(raw)-1]...), []byte(",\"Deleted\":false}")...))
		for _, v := range bad {
			if _, e := parseSelectionRecord(v, kind); e != ErrAdmissionResponse {
				t.Fatal("invalid JSON accepted", kind, string(v), e)
			}
		}
		var copy map[string]json.RawMessage
		json.Unmarshal(raw, &copy)
		if kind == "slot" {
			copy["protocol"] = json.RawMessage(`"ftp"`)
		} else {
			copy["credentialId"] = json.RawMessage(`""`)
		}
		invalid, _ := json.Marshal(copy)
		if _, e := parseSelectionRecord(invalid, kind); e != ErrAdmissionResponse {
			t.Fatal("invalid content", e)
		}
	}
	if _, e := parseSelectionRecord([]byte("{}"), "other"); e != ErrAdmissionResponse {
		t.Fatal(e)
	}
}
