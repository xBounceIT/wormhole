//go:build darwin && cgo

package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestVaultMacProtectedKeyringNative(t *testing.T) {
	store := platformProtectedKeyring()
	value := []byte("fake-keyring-value")
	for _, service := range []string{fileKeyringService, authKeyringService} {
		for _, mode := range []string{"new", "raw", "hex", "base64", "malformed"} {
			t.Run(service+"/"+mode, func(t *testing.T) {
				// Use an isolated account so no existing user key belongs to this test.
				account := "wormhole-test:" + uuid.NewString()
				defer func() {
					if err := store.remove(service, account); err != nil && !errors.Is(err, errProtectedKeyringNotFound) {
						t.Error("failed to clean up fixture", err)
					}
				}()
				var err error
				switch mode {
				case "new":
					err = store.store(service, account, value)
				case "raw":
					err = addMacProtectedKeyringPassword(service, account, value)
				case "hex":
					raw := hex.AppendEncode([]byte(macKeyringHexPrefix), value)
					err = addMacProtectedKeyringPassword(service, account, raw)
				case "base64":
					raw := encodeMacProtectedKeyringValue(value)
					err = addMacProtectedKeyringPassword(service, account, raw)
				case "malformed":
					err = addMacProtectedKeyringPassword(service, account, []byte(macKeyringBase64Prefix+"!"))
				}
				if err != nil {
					t.Fatal("cannot create native fixture", err)
				}
				if err := store.store(service, account, []byte("replacement")); err == nil {
					t.Fatal("duplicate write replaced an existing value")
				}
				got, err := store.load(service, account)
				defer clearBytes(got)
				if mode == "malformed" {
					if got != nil || !errors.Is(err, errMacProtectedKeyringValue) {
						t.Fatal("malformed native value was treated as usable or absent", err)
					}
				} else if err != nil || !bytes.Equal(got, value) {
					t.Fatal("native value changed", err)
				}
				if _, err := store.load("Wormhole Wrong Service", account); !errors.Is(err, errProtectedKeyringNotFound) {
					t.Fatal("account matched under the wrong service", err)
				}
				if err := store.remove(service, account); err != nil {
					t.Fatal("native removal failed", err)
				}
				if _, err := store.load(service, account); !errors.Is(err, errProtectedKeyringNotFound) {
					t.Fatal("deleted key was still usable", err)
				}
			})
		}
	}
}
