//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Use the typed Windows binding as an independent interoperability oracle: a
// round trip through two wrappers with the same argument-order bug can pass.
func nativeDPAPIProtect(t *testing.T, plaintext, entropy []byte) []byte {
	t.Helper()
	input := windows.DataBlob{Size: uint32(len(plaintext)), Data: &plaintext[0]}
	var optional *windows.DataBlob
	if len(entropy) > 0 {
		optional = &windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	}
	var output windows.DataBlob
	if err := windows.CryptProtectData(&input, nil, optional, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		t.Fatal(err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	return append([]byte(nil), unsafe.Slice(output.Data, output.Size)...)
}

func TestBitwardenBrowserStorageReadsNativeDPAPIEntropy(t *testing.T) {
	for _, entropy := range [][]byte{bitwardenBrowserStorageEntropy, nil} {
		t.Run(map[bool]string{true: "legacy", false: "entropy"}[len(entropy) == 0], func(t *testing.T) {
			database := filepath.Join(t.TempDir(), "wormhole.db")
			record := bitwardenBrowserStorageRecord{SchemaVersion: 1, Revision: 79, LocalJson: `{"account":"fixture"}`}
			plaintext, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			protected := nativeDPAPIProtect(t, plaintext, entropy)
			path := bitwardenBrowserStoragePath(database)
			for _, suffix := range []string{"", ".bak"} {
				if err := os.WriteFile(path+suffix, protected, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			manager := &vncManager{databasePath: database}
			snapshot, err := manager.readBitwardenBrowserStorage(t.TempDir())
			if err != nil || !snapshot.Durable || snapshot.Revision != record.Revision || snapshot.LocalJSON != record.LocalJson {
				t.Fatal("native DPAPI checkpoint was classified as read/unavailable")
			}
			for _, suffix := range []string{"", ".bak"} {
				after, err := os.ReadFile(path + suffix)
				if err != nil || !bytes.Equal(after, protected) {
					t.Fatal("read mutated protected checkpoint")
				}
			}
		})
	}
}

func TestDPAPIRequiresMatchingEntropy(t *testing.T) {
	plaintext := []byte("synthetic-secret")
	for _, entropy := range [][]byte{appAuthenticationEntropy, bitwardenBrowserStorageEntropy} {
		protected, err := protectDpapi(plaintext, entropy)
		if err != nil {
			t.Fatal(err)
		}
		for _, wrong := range [][]byte{nil, []byte("other-purpose")} {
			if _, err := unprotectDpapi(protected, wrong); err == nil {
				t.Fatal("ciphertext accepted missing or incorrect entropy")
			}
		}
		decoded, err := unprotectDpapi(nativeDPAPIProtect(t, plaintext, entropy), entropy)
		if err != nil || !bytes.Equal(decoded, plaintext) {
			t.Fatal("native entropy interoperability failed")
		}
	}
}

func TestDPAPIEmptyValuesAndInvalidCiphertext(t *testing.T) {
	for _, entropy := range [][]byte{nil, bitwardenBrowserStorageEntropy} {
		for _, plaintext := range [][]byte{nil, []byte("fixture")} {
			protected, err := protectDpapi(plaintext, entropy)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := unprotectDpapi(protected, entropy)
			if err != nil || !bytes.Equal(decoded, plaintext) {
				t.Fatal("DPAPI round trip failed")
			}
		}
		for _, invalid := range [][]byte{nil, []byte("invalid ciphertext")} {
			if _, err := unprotectDpapiWithLegacyEntropy(invalid, entropy); err == nil {
				t.Fatal("invalid ciphertext was accepted")
			}
		}
	}
}

func TestAuthDocumentReadsNativeAndLegacyDPAPI(t *testing.T) {
	plaintext := []byte(`{"Version":1}`)
	for _, entropy := range [][]byte{nil, appAuthenticationEntropy} {
		protected := nativeDPAPIProtect(t, plaintext, entropy)
		decoded, err := unprotectAuthDocument("unused", protected)
		if err != nil || !bytes.Equal(decoded, plaintext) {
			t.Fatal("existing app authentication document became unreadable")
		}
	}
	if _, err := unprotectAuthDocument("unused", nil); err == nil {
		t.Fatal("empty auth document accepted")
	}
}

func TestDPAPILegacyFallbackRejectsOtherPurposesAndDamage(t *testing.T) {
	plaintext := []byte("fixture")
	otherPurpose := nativeDPAPIProtect(t, plaintext, []byte("different-purpose"))
	damaged := nativeDPAPIProtect(t, plaintext, nil)
	damaged[len(damaged)-1] ^= 0xff
	for _, protected := range [][]byte{otherPurpose, damaged} {
		if _, err := unprotectAuthDocument("unused", protected); err == nil {
			t.Fatal("unrelated or damaged auth document accepted")
		}
		path := filepath.Join(t.TempDir(), "bitwarden.dpapi")
		if err := os.WriteFile(path, protected, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := unprotectBitwardenBrowserStorage(path); err == nil {
			t.Fatal("unrelated or damaged browser document accepted")
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(after, protected) {
			t.Fatal("failed recovery changed the original file")
		}
	}
	if _, err := unprotectBitwardenBrowserStorage(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing protected file accepted")
	}
}

func TestBitwardenBrowserStorageWritesEntropyProtectedCheckpoint(t *testing.T) {
	database := filepath.Join(t.TempDir(), "wormhole.db")
	expected := bitwardenBrowserStorageSnapshot{Revision: 1, LocalJSON: `{"account":"fixture"}`, SessionJSON: "{}"}
	ready, err := persistBitwardenBrowserStorage(database, expected)
	if err != nil || !ready {
		t.Fatal("checkpoint was not saved")
	}
	for _, suffix := range []string{"", ".bak"} {
		protected, err := os.ReadFile(bitwardenBrowserStoragePath(database) + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := unprotectDpapi(protected, nil); err == nil {
			t.Fatal("new checkpoint omitted entropy")
		}
		decoded, err := unprotectDpapi(protected, bitwardenBrowserStorageEntropy)
		if err != nil {
			t.Fatal(err)
		}
		var record bitwardenBrowserStorageRecord
		if err := json.Unmarshal(decoded, &record); err != nil || record.LocalJson != expected.LocalJSON {
			t.Fatal("checkpoint lost account state")
		}
	}
}
