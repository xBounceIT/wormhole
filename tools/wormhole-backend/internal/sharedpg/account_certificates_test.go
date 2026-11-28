package sharedpg

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func accountMaterialRows() [][][]byte {
	rows := accountKeyRows()
	for _, suite := range []string{"2", "1"} {
		rows[0] = append(rows[0], []byte(suite), hex.AppendEncode(nil, bytes.Repeat([]byte{3}, 32)), []byte("42345678-1234-4234-8234-123456789abc"), []byte("1"), []byte("3"), hex.AppendEncode(nil, bytes.Repeat([]byte{4}, 64)))
	}
	return rows
}

func TestParseAccountKeyMaterial(t *testing.T) {
	rows := accountMaterialRows()
	material, err := parseAccountKeyMaterial(rows, admissionRequest(), 1)
	if err != nil || material.EncryptionCertificate.Kind != "user-enc" || material.SigningCertificate.Kind != "user-sign" || material.EncryptionCertificate.Key != material.Binding.Encryption || material.SigningCertificate.Key != material.Binding.Signing || material.EncryptionCertificate.Revision != 3 || material.SigningCertificate.Revision != 3 {
		t.Fatal("certificate reconstruction failed")
	}
	wipeQueryRows(rows)
	if material.EncryptionCertificate.PublicKey[0] != 3 || material.SigningCertificate.Signature[0] != 4 {
		t.Fatal("certificate aliases response buffers")
	}
	for _, rows := range [][][][]byte{nil, {{}}, {accountMaterialRows()[0], accountMaterialRows()[0]}, accountKeyRows()} {
		if value, err := parseAccountKeyMaterial(rows, admissionRequest(), 1); value != nil || err != ErrAdmissionResponse {
			t.Fatal("invalid shape accepted")
		}
	}
	rows = accountMaterialRows()
	rows[0][0] = []byte("bad")
	if value, err := parseAccountKeyMaterial(rows, admissionRequest(), 1); value != nil || err != ErrAdmissionResponse {
		t.Fatal("invalid wrapper accepted")
	}
	for _, start := range []int{12, 18} {
		for _, bad := range []struct {
			offset int
			value  string
		}{
			{0, "3"}, {0, "01"}, {1, "00"}, {5, "00"}, {1, "zz" + string(bytes.Repeat([]byte{'0'}, 62))}, {5, "zz" + string(bytes.Repeat([]byte{'0'}, 126))},
			{2, "bad"}, {2, "00000000-0000-0000-0000-000000000000"}, {2, "42345678-1234-4234-8234-123456789ABC"},
			{3, "0"}, {3, "2147483648"}, {3, "bad"}, {3, "01"}, {4, "0"}, {4, "9223372036854775808"}, {4, "bad"}, {4, "03"},
		} {
			rows := accountMaterialRows()
			rows[0][start+bad.offset] = []byte(bad.value)
			if value, err := parseAccountKeyMaterial(rows, admissionRequest(), 1); value != nil || err != ErrAdmissionResponse {
				t.Fatalf("invalid certificate column %d accepted", start+bad.offset)
			}
		}
		rows := accountMaterialRows()
		keyColumn := 2
		if start == 18 {
			keyColumn = 4
		}
		rows[0][start+2] = bytes.Clone(rows[0][keyColumn])
		if _, err := parseAccountKeyMaterial(rows, admissionRequest(), 1); err != ErrAdmissionResponse {
			t.Fatal("self-certified user key accepted")
		}
	}
	rows = accountMaterialRows()
	rows[0][20] = []byte("52345678-1234-4234-8234-123456789abc")
	if value, err := parseAccountKeyMaterial(rows, admissionRequest(), 1); value != nil || err != ErrAdmissionResponse {
		t.Fatal("mixed organisation signers accepted")
	}
}
