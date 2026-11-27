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
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func credentialProjectionRows(t *testing.T) ([][][]byte, AdmissionRequest, UnverifiedCredential, UnverifiedNodeAuthor, TrustState) {
	t.Helper()
	_, b, s, c, a, _, _ := credentialTrustFixture(t)
	raw, err := vault.EncodeUserKeyState(*a.State)
	if err != nil {
		t.Fatal(err)
	}
	record, _ := json.Marshal(c.Record)
	cert := a.Certificate
	text := func(n uint64) []byte { return []byte(strconv.FormatUint(n, 10)) }
	rows := [][][]byte{{[]byte(b.WorkspaceID.String()), []byte(c.Record.Metadata.ID), []byte("1"), []byte("7"), record, []byte(c.Boundary.String()), text(c.Seal.Revision), []byte("2"), []byte(c.Seal.SignerKeyID), text(uint64(c.Seal.SignerKeyVersion)), nil, hex.AppendEncode(nil, c.Seal.Signature), []byte(a.State.UserID.String()), []byte(a.Key.ID.String()), text(uint64(a.Key.Version)), text(a.State.Sequence), hex.AppendEncode(nil, raw), []byte("1"), hex.AppendEncode(nil, cert.PublicKey), []byte(cert.Signer.ID.String()), text(uint64(cert.Signer.Version)), text(cert.Revision), hex.AppendEncode(nil, cert.Signature)}}
	return rows, AdmissionRequest{WorkspaceID: b.WorkspaceID, UserID: b.UserID}, c, a, s
}

func TestCredentialProjectionParsing(t *testing.T) {
	rows, request, want, author, trust := credentialProjectionRows(t)
	id := uuid.MustParse(want.Record.Metadata.ID)
	got, a, err := parseCredentialProjection(rows, request, id, 1, 7)
	if err != nil || !reflect.DeepEqual(*got, want) || !reflect.DeepEqual(*a, author) {
		t.Fatal("projection", err)
	}
	wipeQueryRows(rows)
	if next, err := trust.AdvanceCredential(*got, *a); err != nil || len(next.Catalog) != 3 {
		t.Fatal("projection aliases wire or fails authentication", err)
	}
	for col := 0; col < 23; col++ {
		rows, request, want, _, _ = credentialProjectionRows(t)
		id = uuid.MustParse(want.Record.Metadata.ID)
		rows[0][col] = []byte("bad")
		if _, _, err = parseCredentialProjection(rows, request, id, 1, 7); err != ErrAdmissionResponse {
			t.Fatal("malformed column", col, err)
		}
	}
	rows, request, want, _, _ = credentialProjectionRows(t)
	id = uuid.MustParse(want.Record.Metadata.ID)
	for _, bad := range [][][][]byte{nil, {{}}, append(rows, rows...)} {
		if _, _, err = parseCredentialProjection(bad, request, id, 1, 7); err != ErrAdmissionResponse {
			t.Fatal("shape", err)
		}
	}
	for _, invalid := range []struct {
		id         uuid.UUID
		epoch, seq uint64
	}{{uuid.Nil, 1, 7}, {id, 0, 7}, {id, 1 << 63, 7}, {id, 1, 1 << 63}} {
		if _, _, err = parseCredentialProjection(rows, request, invalid.id, invalid.epoch, invalid.seq); err != ErrAdmissionResponse {
			t.Fatal("request bounds", err)
		}
	}
	emptyWorkspace := request
	emptyWorkspace.WorkspaceID = uuid.Nil
	if _, _, err = parseCredentialProjection(rows, emptyWorkspace, id, 1, 7); err != ErrAdmissionResponse {
		t.Fatal("missing workspace", err)
	}
	for i := 17; i < 23; i++ {
		rows[0][i] = nil
	}
	if _, a, err = parseCredentialProjection(rows, request, id, 1, 7); err != nil || a.Certificate != nil {
		t.Fatal("missing certificate", err)
	}
	rows[0][22] = []byte("bad")
	if _, _, err = parseCredentialProjection(rows, request, id, 1, 7); err != ErrAdmissionResponse {
		t.Fatal("partial cert", err)
	}
	for _, col := range []int{13, 14} {
		rows, request, want, _, _ = credentialProjectionRows(t)
		id = uuid.MustParse(want.Record.Metadata.ID)
		if col == 13 {
			rows[0][col] = []byte(uuid.NewString())
		} else {
			rows[0][col] = []byte("3")
		}
		if _, _, err = parseCredentialProjection(rows, request, id, 1, 7); err != ErrAdmissionResponse {
			t.Fatal("author signer mismatch", err)
		}
	}
	rows, request, want, _, _ = credentialProjectionRows(t)
	id = uuid.MustParse(want.Record.Metadata.ID)
	rows[0][11] = bytes.Repeat([]byte("z"), 128)
	if _, _, err = parseCredentialProjection(rows, request, id, 1, 7); err != ErrAdmissionResponse {
		t.Fatal("invalid hex", err)
	}
	rows[0][11] = hex.AppendEncode(nil, want.Seal.Signature)
	capID := uuid.NewString()
	rows[0][10] = []byte(capID)
	if got, _, err = parseCredentialProjection(rows, request, id, 1, 7); err != nil || got.Seal.CapabilityID == nil || *got.Seal.CapabilityID != capID {
		t.Fatal("capability projection", err)
	}
}

func TestCredentialRecordStrictJSON(t *testing.T) {
	_, _, c, _, _ := credentialProjectionRows(t)
	raw, _ := json.Marshal(c.Record)
	reject := func(b []byte) {
		t.Helper()
		if _, err := parseCredentialRecord(b, 1); err != ErrAdmissionResponse {
			t.Fatal("accepted ambiguous record", string(b), err)
		}
	}
	for _, b := range [][]byte{nil, []byte("null"), []byte("[]"), []byte("{"), []byte(`{"metadata":`), []byte("{}"), append(bytes.Clone(raw), []byte(" {}")...), bytes.Repeat([]byte(" "), 128*1024+1), {0xff}} {
		reject(b)
	}
	for _, name := range []string{"metadata", "deleted", "fields"} {
		var m map[string]json.RawMessage
		json.Unmarshal(raw, &m)
		delete(m, name)
		b, _ := json.Marshal(m)
		reject(b)
		json.Unmarshal(raw, &m)
		m[name] = json.RawMessage("null")
		b, _ = json.Marshal(m)
		reject(b)
		json.Unmarshal(raw, &m)
		m[name] = json.RawMessage("1")
		b, _ = json.Marshal(m)
		reject(b)
	}
	metadata, _ := json.Marshal(c.Record.Metadata)
	var expected map[string]json.RawMessage
	json.Unmarshal(metadata, &expected)
	for name := range expected {
		for _, mode := range []string{"missing", "null", "type", "alias"} {
			var m map[string]json.RawMessage
			json.Unmarshal(metadata, &m)
			switch mode {
			case "missing":
				delete(m, name)
			case "null":
				m[name] = json.RawMessage("null")
			case "type":
				m[name] = json.RawMessage("true")
			case "alias":
				m["unexpected"] = m[name]
				delete(m, name)
			}
			badMetadata, _ := json.Marshal(m)
			var whole map[string]json.RawMessage
			json.Unmarshal(raw, &whole)
			whole["metadata"] = badMetadata
			b, _ := json.Marshal(whole)
			reject(b)
		}
	}
	for _, bad := range []string{
		`{"deleted":true,` + string(raw[1:]),
		string(bytes.Replace(raw, []byte(`"name":`), []byte(`"Name":"alias","name":`), 1)),
		string(bytes.Replace(raw, []byte(`"name":`), []byte(`"name":"duplicate","name":`), 1)),
		string(bytes.Replace(raw, []byte(`"present":`), []byte(`"present":false,"present":`), 1)),
		string(bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1.0`), 1)),
		string(bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":9223372036854775808`), 1)),
	} {
		reject([]byte(bad))
	}
	for _, field := range []string{`null`, `{}`, `{"field":"password","version":1}`, `{"field":"password","version":1,"present":null}`, `{"field":"password","version":1,"present":true,"extra":0}`} {
		var whole map[string]json.RawMessage
		json.Unmarshal(raw, &whole)
		whole["fields"] = json.RawMessage("[" + field + "]")
		b, _ := json.Marshal(whole)
		reject(b)
	}
	// Maximum valid field versions are decoded without a float64 round trip.
	c.Record.Fields[0].Version = math.MaxInt64
	raw, _ = json.Marshal(c.Record)
	parsed, err := parseCredentialRecord(raw, 1)
	if err != nil || parsed.Fields[0].Version != math.MaxInt64 {
		t.Fatal("integer precision", err)
	}
	c.Record.Fields = append(c.Record.Fields, make([]vaultstore.CredentialField, 4)...)
	raw, _ = json.Marshal(c.Record)
	reject(raw)
	c.Record.Fields = []vaultstore.CredentialField{}
	raw, _ = json.Marshal(c.Record)
	if _, err = parseCredentialRecord(append(raw, []byte(" \n")...), 1); err != nil {
		t.Fatal("empty manifest", err)
	}
	if _, err = parseCredentialRecord(raw, 0); err != ErrAdmissionResponse {
		t.Fatal("invalid revision", err)
	}
}
