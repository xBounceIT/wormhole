package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
)

func TestVaultMacProtectedKeyringFormat(t *testing.T) {
	key := []byte("example-protected-file-key")
	padded := "go-keyring-base64:" + base64.StdEncoding.EncodeToString(key)
	hexadecimal := "go-keyring-encoded:" + hex.EncodeToString(key)
	if got := encodeMacProtectedKeyringValue(key); string(got) != padded {
		t.Fatal("new entry changed the legacy representation")
	}
	for _, raw := range []string{padded, hexadecimal, string(key), " " + padded + "\r\n"} {
		input := []byte(raw)
		got, err := decodeMacProtectedKeyringValue(input)
		if err != nil || !bytes.Equal(got, key) {
			t.Fatal("could not decode a historical representation", err)
		}
		clearBytes(got)
		if !bytes.Equal(input, []byte(raw)) {
			t.Fatal("decoded value borrowed the input")
		}
	}
	for _, raw := range [][]byte{
		nil, []byte(" "), []byte("go-keyring-base64:"), []byte("go-keyring-encoded:"),
		[]byte("go-keyring-base64:QQ==!"), []byte("go-keyring-encoded:616?"),
		bytes.Repeat([]byte{'x'}, maxMacProtectedKey+1),
	} {
		if got, err := decodeMacProtectedKeyringValue(raw); got != nil || !errors.Is(err, errMacProtectedKeyringValue) {
			t.Fatal("malformed format returned a value", err)
		}
	}
}
