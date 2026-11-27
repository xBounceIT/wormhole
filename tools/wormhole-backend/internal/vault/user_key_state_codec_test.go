package vault

import (
	"bytes"
	"reflect"
	"testing"
)

func TestUserKeyStateCanonicalCodec(t *testing.T) {
	_, _, _, _, _, _, _, state, trust := userStateFixture(t)
	raw, err := EncodeUserKeyState(state)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeUserKeyState(raw)
	if err != nil || !reflect.DeepEqual(decoded, state) {
		t.Fatal("state codec changed data")
	}
	for _, bad := range [][]byte{nil, bytes.Repeat([]byte{' '}, MaxUserKeyStateBytes+1), []byte("bad"), append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte(`"active":true`), []byte(`"active":true,"active":true`), 1), bytes.Replace(raw, []byte(`"active":true`), []byte(`"Active":true`), 1), bytes.Replace(raw, []byte(`"active":true`), []byte(`"active":true,"extra":1`), 1)} {
		if _, err := DecodeUserKeyState(bad); err != ErrFormat {
			t.Fatal("noncanonical state accepted")
		}
	}
	bad := state
	bad.Signature = nil
	if _, err := EncodeUserKeyState(bad); err != ErrFormat {
		t.Fatal("unsigned state encoded")
	}
	malformed := bytes.Replace(raw, []byte(`"formatVersion":1`), []byte(`"formatVersion":2`), 1)
	if _, err := DecodeUserKeyState(malformed); err != ErrNewerFormat {
		t.Fatal("newer format accepted")
	}
	bad = state
	bad.Sequence = 0
	if _, err := EncodeUserKeyState(bad); err != ErrFormat {
		t.Fatal("invalid state encoded")
	}
	// Structural decoding must not be confused with organisation authentication.
	bad = state
	bad.Signature = make([]byte, 64)
	forged, err := EncodeUserKeyState(bad)
	if err != nil {
		t.Fatal(err)
	}
	forgedState, err := DecodeUserKeyState(forged)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyUserKeyState(forgedState, trust); err != ErrAuthentication {
		t.Fatal("codec authenticated forged signature")
	}
	clear(raw)
	if !bytes.Equal(decoded.Signature, state.Signature) {
		t.Fatal("decoded state aliases input")
	}
}
