package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"
)

func accountKeyRows() [][][]byte {
	return [][][]byte{{[]byte(testHintID), []byte(testHintID), []byte("22345678-1234-4234-8234-123456789abc"), []byte("1"), []byte("32345678-1234-4234-8234-123456789abc"), []byte("1"), []byte("1"), []byte("kdf-v1"), []byte("true"), hex.AppendEncode(nil, bytes.Repeat([]byte{1}, 12)), hex.AppendEncode(nil, bytes.Repeat([]byte{2}, 81)), []byte("1")}}
}

func TestParseAccountKeys(t *testing.T) {
	rows := accountKeyRows()
	value, err := parseAccountKeys(rows, admissionRequest(), 1)
	if err != nil || value.Binding.Revision != 1 || !value.ASKRequired {
		t.Fatal("valid wrapper rejected")
	}
	wipeQueryRows(rows)
	if value.Envelope.Nonce[0] != 1 || value.Envelope.Ciphertext[0] != 2 {
		t.Fatal("wrapper aliases response buffers")
	}
	rows = accountKeyRows()
	rows[0][8] = []byte("false")
	if value, err := parseAccountKeys(rows, admissionRequest(), 1); err != nil || value.ASKRequired {
		t.Fatal("optional ASK rejected")
	}
	for _, rows := range [][][][]byte{nil, {{}}, {accountKeyRows()[0], accountKeyRows()[0]}} {
		if value, err := parseAccountKeys(rows, admissionRequest(), 1); err != ErrAdmissionResponse || value != nil {
			t.Fatal("bad shape accepted")
		}
	}
	for _, bad := range []struct {
		column int
		value  string
	}{
		{0, "bad"}, {1, "00000000-0000-0000-0000-000000000000"}, {0, "22345678-1234-4234-8234-123456789abc"}, {1, "22345678-1234-4234-8234-123456789abc"}, {2, "22345678-1234-4234-8234-123456789ABC"}, {4, "22345678-1234-4234-8234-123456789abc"},
		{3, "0"}, {3, "2147483648"}, {5, "01"}, {5, "bad"}, {6, "9223372036854775808"}, {11, "2"}, {7, "custom"}, {8, "t"}, {9, "00"}, {10, "00"}, {9, "zz0000000000000000000000"},
	} {
		rows := accountKeyRows()
		rows[0][bad.column] = []byte(bad.value)
		if value, err := parseAccountKeys(rows, admissionRequest(), 1); err != ErrAdmissionResponse || value != nil {
			t.Fatalf("bad column %d accepted", bad.column)
		}
	}
	rows = accountKeyRows()
	rows[0][10][0] = 'z'
	if _, err := parseAccountKeys(rows, admissionRequest(), 1); err != ErrAdmissionResponse {
		t.Fatal("malformed ciphertext accepted")
	}
}

func TestAccountKeysValidation(t *testing.T) {
	s := NewSession()
	defer s.Close(context.Background())
	if _, err := s.AccountKeys(nil); err != ErrConfiguration {
		t.Fatal(err)
	}
	if _, err := s.AccountKeys(context.Background()); err != ErrAuthentication {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.AccountKeys(ctx); err != context.Canceled {
		t.Fatal(err)
	}
	seedPasswordSession(t, s)
	if _, err := s.AccountKeys(context.Background()); err != ErrSessionClosed {
		t.Fatal(err)
	}
	fake, _ := readySession(t, false)
	seedPasswordSession(t, fake)
	if _, err := fake.AccountKeys(context.Background()); err != ErrQuery {
		t.Fatal(err)
	}
}
