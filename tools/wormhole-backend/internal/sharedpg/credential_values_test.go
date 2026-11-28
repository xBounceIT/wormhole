package sharedpg

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func credentialValueRows(t *testing.T) ([][][]byte, AdmissionRequest, sharedcatalog.CredentialRecord) {
	t.Helper()
	_, b, _, c, _, _, _ := credentialTrustFixture(t)
	c.Record.Fields = []vaultstore.CredentialField{{Field: "password", Version: 5, Present: true}}
	id := uuid.New()
	binding := vault.SharedValueBinding{WorkspaceID: b.WorkspaceID, OwnerKind: "credential", OwnerID: uuid.MustParse(c.Record.Metadata.ID), Field: "password", Version: 5, DEK: vault.KeyRef{ID: id, Version: 2}}
	e, err := vault.SealSharedValue(bytes.Repeat([]byte{23}, 32), binding, []byte("native-only"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := vault.EncodeSharedEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	return [][][]byte{{[]byte(b.WorkspaceID.String()), []byte(c.Record.Metadata.ID), []byte("1"), []byte("7"), []byte("password"), []byte("5"), []byte(id.String()), []byte("2"), hex.AppendEncode(nil, raw)}}, AdmissionRequest{WorkspaceID: b.WorkspaceID, UserID: b.UserID}, c.Record
}
func TestCredentialValuesProjection(t *testing.T) {
	rows, r, c := credentialValueRows(t)
	values, e := parseCredentialValues(rows, r, c, 1, 7)
	if e != nil || len(values) != 1 || values[0].Binding.OwnerID.String() != c.Metadata.ID || values[0].Binding.Version != 5 || values[0].Binding.Field != "password" {
		t.Fatal("values", e)
	}
	wipeQueryRows(rows)
	binding := vault.Binding{WorkspaceID: r.WorkspaceID.String(), Table: "SecretValues/credential", OwnerID: c.Metadata.ID, Field: "shared/v1/5/password", KeyID: values[0].Binding.DEK.ID.String(), KeyVersion: 2}
	plain, e := vault.Open(bytes.Repeat([]byte{23}, 32), binding, values[0].Envelope)
	if e != nil || !bytes.Equal(plain, []byte("native-only")) {
		t.Fatal("value aliases wire", e)
	}
	vault.Wipe(plain)
	for col := 0; col < 9; col++ {
		rows, r, c = credentialValueRows(t)
		rows[0][col] = []byte("bad")
		if _, e := parseCredentialValues(rows, r, c, 1, 7); e != ErrAdmissionResponse {
			t.Fatal("bad value column", col, e)
		}
	}
	rows, r, c = credentialValueRows(t)
	for _, shape := range [][][][]byte{nil, {{}}, append(rows, rows...)} {
		if _, e := parseCredentialValues(shape, r, c, 1, 7); e != ErrAdmissionResponse {
			t.Fatal("shape", e)
		}
	}
	for _, bad := range []struct {
		col   int
		value []byte
	}{{0, []byte(uuid.NewString())}, {1, []byte(uuid.NewString())}, {2, []byte("2")}, {3, []byte("8")}, {4, []byte("privateKey")}, {5, []byte("4")}, {5, []byte("05")}, {6, []byte(uuid.NewString())}, {7, []byte("1")}, {7, []byte(strconv.FormatUint(uint64(math.MaxInt32)+1, 10))}, {8, nil}, {8, []byte("ff")}, {8, []byte("0")}, {8, bytes.Repeat([]byte("00"), vault.MaxSharedEnvelopeBytes+1)}} {
		rows, r, c = credentialValueRows(t)
		rows[0][bad.col] = bad.value
		if _, e := parseCredentialValues(rows, r, c, 1, 7); e != ErrAdmissionResponse {
			t.Fatal("invalid row", bad.col, e)
		}
	}
	rows, r, c = credentialValueRows(t)
	for _, v := range []uint64{0, math.MaxUint64} {
		if _, e := parseCredentialValues(rows, r, c, v, 7); e != ErrAdmissionResponse {
			t.Fatal(e)
		}
	}
	if _, e := parseCredentialValues(rows, r, c, 1, math.MaxUint64); e != ErrAdmissionResponse {
		t.Fatal(e)
	}
	badRequest := r
	badRequest.WorkspaceID = uuid.Nil
	if _, e := parseCredentialValues(rows, badRequest, c, 1, 7); e != ErrAdmissionResponse {
		t.Fatal(e)
	}
	badRecord := c
	badRecord.Deleted = true
	if _, e := parseCredentialValues(rows, r, badRecord, 1, 7); e != ErrAdmissionResponse {
		t.Fatal(e)
	}
	badRecord = c
	badRecord.Metadata.ID = "bad"
	if _, e := parseCredentialValues(rows, r, badRecord, 1, 7); e != ErrAdmissionResponse {
		t.Fatal(e)
	}
	c.Fields[0].Present = false
	if v, e := parseCredentialValues(nil, r, c, 1, 7); e != nil || len(v) != 0 {
		t.Fatal("absent field", e)
	}
	c.Metadata.Provider = "bitwarden"
	c.Metadata.BitwardenItemID = "item"
	if v, e := parseCredentialValues(nil, r, c, 1, 7); e != nil || len(v) != 0 {
		t.Fatal("Bitwarden has no stored values", e)
	}
	rows, r, c = credentialValueRows(t)
	raw, _ := hex.DecodeString(string(rows[0][8]))
	var envelope vault.Envelope
	json.Unmarshal(raw, &envelope)
	envelope.FormatVersion++
	raw, _ = json.Marshal(envelope)
	rows[0][8] = hex.AppendEncode(nil, raw)
	if _, e := parseCredentialValues(rows, r, c, 1, 7); e != vault.ErrNewerFormat {
		t.Fatal(e)
	}
}
func TestCredentialValuesTotalBudget(t *testing.T) {
	rows, r, c := credentialValueRows(t)
	c.Metadata.Kind = "sshKey"
	c.Fields = []vaultstore.CredentialField{{Field: "certificate", Version: 5, Present: true}, {Field: "privateKey", Version: 5, Present: true}}
	raw, _ := hex.DecodeString(string(rows[0][8]))
	var e vault.Envelope
	json.Unmarshal(raw, &e)
	e.Ciphertext = make([]byte, 3*1024*1024+1024)
	raw, err := vault.EncodeSharedEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	first := append([][]byte(nil), rows[0]...)
	second := append([][]byte(nil), rows[0]...)
	first[4] = []byte("certificate")
	second[4] = []byte("privateKey")
	first[8] = hex.AppendEncode(nil, raw)
	second[8] = first[8]
	if _, e := parseCredentialValues([][][]byte{first, second}, r, c, 1, 7); e != ErrAdmissionResponse {
		t.Fatal("aggregate ciphertext budget", e)
	}
}
