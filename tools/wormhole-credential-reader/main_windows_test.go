//go:build windows

package main

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestDecodeCredentialBlobPreservesUnicode(t *testing.T) {
	want := "päss🔐"
	units := utf16.Encode([]rune(want))
	blob := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.LittleEndian.PutUint16(blob[index*2:index*2+2], unit)
	}

	got, err := decodeCredentialBlob(&blob[0], uint32(len(blob)))
	if err != nil {
		t.Fatalf("decodeCredentialBlob returned an error: %v", err)
	}
	if got != want {
		t.Fatalf("decodeCredentialBlob returned %q, want %q", got, want)
	}
}

func TestDecodeCredentialBlobRejectsOddLength(t *testing.T) {
	blob := []byte{0x61}
	if _, err := decodeCredentialBlob(&blob[0], uint32(len(blob))); err == nil {
		t.Fatal("decodeCredentialBlob accepted an odd-length blob")
	}
}

func TestDecodeCredentialBlobRejectsOversizedBlob(t *testing.T) {
	blob := []byte{0x61, 0x00}
	if _, err := decodeCredentialBlob(&blob[0], maxCredentialBlobBytes+2); err == nil {
		t.Fatal("decodeCredentialBlob accepted an oversized blob")
	}
}
