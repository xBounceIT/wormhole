package vault

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestVNCBundleBinaryPresenceAndBorrow(t *testing.T) {
	for _, p := range []VNCBundlePayload{{}, {PasswordProvided: true}, {PasswordProvided: true, Password: []byte{0, 255, 239, 187, 191}}, {PasswordProvided: true, Password: bytes.Repeat([]byte("x"), MaxVNCPasswordBytes)}} {
		raw, err := EncodeVNCBundle(p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeVNCBundle(raw)
		if err != nil || got.PasswordProvided != p.PasswordProvided || !bytes.Equal(got.Password, p.Password) {
			t.Fatal(got, err)
		}
		for i := 0; i < len(raw); i++ {
			if _, err := DecodeVNCBundle(raw[:i]); err == nil {
				t.Fatal("truncated frame accepted", i)
			}
		}
		if _, err := DecodeVNCBundle(append(bytes.Clone(raw), 0)); err == nil {
			t.Fatal("trailing bytes accepted")
		}
		Wipe(raw)
		if !bytes.Equal(got.Password, make([]byte, len(got.Password))) {
			t.Fatal("decoder retained a secret copy")
		}
	}
	for _, p := range []VNCBundlePayload{{Password: []byte("unexpected")}, {PasswordProvided: true, Password: make([]byte, MaxVNCPasswordBytes+1)}} {
		if _, err := EncodeVNCBundle(p); err == nil {
			t.Fatal("invalid payload accepted")
		}
	}
	raw, _ := EncodeVNCBundle(VNCBundlePayload{PasswordProvided: true, Password: []byte("password")})
	for _, change := range []func([]byte){func(v []byte) { v[0] = 2 }, func(v []byte) { v[1] = 2 }, func(v []byte) { v[1] = 0 }, func(v []byte) { binary.BigEndian.PutUint32(v[2:], ^uint32(0)) }} {
		bad := bytes.Clone(raw)
		change(bad)
		if _, err := DecodeVNCBundle(bad); err == nil {
			t.Fatal("malformed payload accepted")
		}
	}
	if _, err := DecodeVNCBundle(make([]byte, MaxVNCPasswordBytes+7)); err == nil {
		t.Fatal("oversized frame accepted")
	}
}
