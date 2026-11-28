package sharedpg

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"math"
	"reflect"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func keyCopyProjectionRows(t *testing.T, orgIssuer bool) ([][][]byte, AdmissionRequest, TrustState, UnverifiedKeyCopy) {
	t.Helper()
	_, b, s, _, author, org, key := credentialTrustFixture(t)
	issuer := author.Key
	seed := key.Seed()
	kind := "user-sign"
	if orgIssuer {
		issuer = author.State.Signer
		seed = org.Seed()
		kind = "org-sign"
	}
	binding := vault.KeyCopyBinding{WorkspaceID: b.WorkspaceID, Key: vault.KeyRef{ID: uuid.New(), Version: 3}, Holder: author.State.Encryption, Issuer: issuer}
	recipient, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{17}, 32))
	copy, e := vault.SealKeyCopy(bytes.Repeat([]byte{23}, 32), binding, recipient.PublicKey().Bytes(), seed)
	vault.Wipe(seed)
	if e != nil {
		t.Fatal(e)
	}
	n := func(v uint64) []byte { return []byte(strconv.FormatUint(v, 10)) }
	row := [][]byte{[]byte(b.WorkspaceID.String()), []byte("1"), []byte("7"), []byte(binding.Key.ID.String()), n(uint64(binding.Key.Version)), []byte(binding.Holder.ID.String()), n(uint64(binding.Holder.Version)), []byte("2"), hex.AppendEncode(nil, copy.Envelope.Enc), hex.AppendEncode(nil, copy.Envelope.Ciphertext), []byte(issuer.ID.String()), n(uint64(issuer.Version)), hex.AppendEncode(nil, copy.Signature), []byte(kind), nil, nil, nil, nil, nil, nil, nil, nil, nil}
	expected := UnverifiedKeyCopy{Binding: binding, Copy: copy}
	if !orgIssuer {
		raw, e := vault.EncodeUserKeyState(*author.State)
		if e != nil {
			t.Fatal(e)
		}
		c := author.Certificate
		row[14] = []byte(author.State.UserID.String())
		row[15] = n(author.State.Sequence)
		row[16] = hex.AppendEncode(nil, raw)
		row[17] = []byte("1")
		row[18] = hex.AppendEncode(nil, c.PublicKey)
		row[19] = []byte(c.Signer.ID.String())
		row[20] = n(uint64(c.Signer.Version))
		row[21] = n(c.Revision)
		row[22] = hex.AppendEncode(nil, c.Signature)
		expected.Author = &author
	}
	return [][][]byte{row}, AdmissionRequest{WorkspaceID: b.WorkspaceID, UserID: b.UserID}, s, expected
}
func TestKeyCopyProjection(t *testing.T) {
	for _, org := range []bool{false, true} {
		rows, r, s, want := keyCopyProjectionRows(t, org)
		got, e := parseKeyCopyProjection(rows, r, want.Binding.Key, want.Binding.Holder, 1, 7)
		if e != nil || !reflect.DeepEqual(*got, want) {
			t.Fatal("projection", e)
		}
		wipeQueryRows(rows)
		if _, e := s.AdvanceKeyCopy(got.Binding, got.Copy, got.Author); e != nil {
			t.Fatal("wire alias/signature", e)
		}
		for col := 0; col < 23; col++ {
			rows, r, _, want = keyCopyProjectionRows(t, org)
			rows[0][col] = []byte("bad")
			if _, e := parseKeyCopyProjection(rows, r, want.Binding.Key, want.Binding.Holder, 1, 7); e != ErrAdmissionResponse {
				t.Fatal("column", org, col, e)
			}
		}
	}
	rows, r, _, want := keyCopyProjectionRows(t, false)
	for _, shape := range [][][][]byte{nil, {{}}, append(rows, rows...)} {
		if _, e := parseKeyCopyProjection(shape, r, want.Binding.Key, want.Binding.Holder, 1, 7); e != ErrAdmissionResponse {
			t.Fatal(e)
		}
	}
	for _, input := range []struct {
		key, holder vault.KeyRef
		epoch, seq  uint64
	}{{vault.KeyRef{}, want.Binding.Holder, 1, 7}, {want.Binding.Key, vault.KeyRef{}, 1, 7}, {want.Binding.Key, want.Binding.Key, 1, 7}, {vault.KeyRef{ID: uuid.New(), Version: math.MaxUint32}, want.Binding.Holder, 1, 7}, {want.Binding.Key, vault.KeyRef{ID: uuid.New(), Version: math.MaxUint32}, 1, 7}, {want.Binding.Key, want.Binding.Holder, 0, 7}, {want.Binding.Key, want.Binding.Holder, math.MaxUint64, 7}, {want.Binding.Key, want.Binding.Holder, 1, math.MaxUint64}} {
		if _, e := parseKeyCopyProjection(rows, r, input.key, input.holder, input.epoch, input.seq); e != ErrAdmissionResponse {
			t.Fatal("request", e)
		}
	}
	for _, bad := range []struct {
		col int
		v   []byte
	}{{0, []byte(uuid.NewString())}, {1, []byte("2")}, {2, []byte("8")}, {3, []byte(uuid.NewString())}, {4, []byte("1")}, {5, []byte(uuid.NewString())}, {6, []byte("1")}, {7, []byte("1")}, {8, bytes.Repeat([]byte("zz"), 32)}, {9, bytes.Repeat([]byte("zz"), 48)}, {10, []byte("bad")}, {11, []byte("0")}, {12, bytes.Repeat([]byte("zz"), 64)}} {
		rows, r, _, want = keyCopyProjectionRows(t, false)
		rows[0][bad.col] = bad.v
		if _, e := parseKeyCopyProjection(rows, r, want.Binding.Key, want.Binding.Holder, 1, 7); e != ErrAdmissionResponse {
			t.Fatal("bad header", bad.col, e)
		}
	}
	rows, r, s, want := keyCopyProjectionRows(t, false)
	for col := 17; col < 23; col++ {
		rows[0][col] = nil
	}
	got, e := parseKeyCopyProjection(rows, r, want.Binding.Key, want.Binding.Holder, 1, 7)
	if e != nil || got.Author.Certificate != nil {
		t.Fatal("missing certificate material", e)
	}
	observed, e := s.AdvanceKeyCopy(got.Binding, got.Copy, got.Author)
	if e == nil || observed.Revision == 0 || len(observed.Catalog) != 1 {
		t.Fatal("author observation lost", e)
	}
}
