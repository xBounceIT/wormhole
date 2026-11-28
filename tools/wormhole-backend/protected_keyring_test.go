package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

func TestVaultProtectedKeyringLookupAndCreation(t *testing.T) {
	const service = "example service"
	const account = "example account"
	failure := errors.New("store unavailable")
	existing := bytes.Repeat([]byte{4}, authProtectionKeyLength)
	for _, mode := range []string{"read", "invalid", "short", "no-create", "unavailable", "create", "collision"} {
		t.Run(mode, func(t *testing.T) {
			var lookup, stored, written []byte
			adapter := protectedKeyringAdapter{
				load: func(gotService, gotAccount string) ([]byte, error) {
					if gotService != service || gotAccount != account {
						t.Fatal("lookup changed key identity")
					}
					switch mode {
					case "read":
						lookup = base64.RawStdEncoding.AppendEncode(nil, existing)
					case "invalid":
						lookup = []byte("!")
					case "short":
						lookup = []byte("AQ")
					case "unavailable":
						lookup = []byte("partial")
						return lookup, failure
					default:
						return nil, errProtectedKeyringNotFound
					}
					return lookup, nil
				},
				store: func(gotService, gotAccount string, value []byte) error {
					if gotService != service || gotAccount != account || (mode != "create" && mode != "collision") {
						t.Fatal("unexpected key write")
					}
					stored, written = value, bytes.Clone(value)
					if mode == "collision" {
						return failure
					}
					return nil
				},
			}
			got, err := adapter.protectionKey(service, account, mode != "no-create")
			defer clearBytes(got)
			defer clearBytes(written)
			switch mode {
			case "read":
				if err != nil || !bytes.Equal(got, existing) {
					t.Fatal("existing key changed", err)
				}
			case "create":
				expected, decodeErr := decodeAuthProtectionKey(written)
				defer clearBytes(expected)
				if err != nil || decodeErr != nil || !bytes.Equal(got, expected) {
					t.Fatal("stored and returned keys differ", err, decodeErr)
				}
			default:
				if got != nil || err == nil {
					t.Fatal("invalid or unavailable key admitted")
				}
			}
			if !bytes.Equal(lookup, make([]byte, len(lookup))) || !bytes.Equal(stored, make([]byte, len(stored))) {
				t.Fatal("encoded protection key remained in temporary storage")
			}
		})
	}
}
