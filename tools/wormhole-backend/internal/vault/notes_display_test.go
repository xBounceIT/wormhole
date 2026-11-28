package vault

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"github.com/google/uuid"
	"math"
	"strconv"
	"testing"
)

func TestNotesDisplayBounds(t *testing.T) {
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ids := []string{uuid.NewString(), uuid.NewString(), uuid.NewString()}
	for index := range ids {
		for _, bad := range []string{"", uuid.Nil.String(), "bad"} {
			input := append([]string{}, ids...)
			input[index] = bad
			if _, err := SealNotesDisplay(key.PublicKey().Bytes(), input[0], input[1], input[2], 1, nil); err != ErrFormat {
				t.Fatal("ID", err)
			}
		}
	}
	for _, version := range []uint64{0, math.MaxUint64} {
		if _, err := SealNotesDisplay(key.PublicKey().Bytes(), ids[0], ids[1], ids[2], version, nil); err != ErrFormat {
			t.Fatal("revision", err)
		}
	}
	if _, err := SealNotesDisplay(key.PublicKey().Bytes(), ids[0], ids[1], ids[2], 1, make([]byte, 65537)); err != ErrFormat {
		t.Fatal("size", err)
	}
	for _, public := range [][]byte{nil, {1}, make([]byte, 32)} {
		if _, err := SealNotesDisplay(public, ids[0], ids[1], ids[2], 1, nil); err == nil {
			t.Fatal("key")
		}
	}
	if _, err := SealNotesDisplay(key.PublicKey().Bytes(), ids[0], ids[1], ids[2], 1, nil); err != nil {
		t.Fatal(err)
	}
}

func TestTunnelEditorDisplayBounds(t *testing.T) {
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	workspace, id, request := uuid.NewString(), uuid.NewString(), uuid.NewString()
	if _, err := SealTunnelEditorDisplay(key.PublicKey().Bytes(), workspace, id, request, 1, make([]byte, 512*1024)); err != nil {
		t.Fatal(err)
	}
	if _, err := SealTunnelEditorDisplay(key.PublicKey().Bytes(), workspace, id, request, 1, make([]byte, 512*1024+1)); err != ErrFormat {
		t.Fatal(err)
	}
	if _, err := SealTunnelEditorDisplay(key.PublicKey().Bytes(), workspace, id, request, 0, nil); err != ErrFormat {
		t.Fatal(err)
	}
}

func TestTunnelImportDisplayDomainAndBounds(t *testing.T) {
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ids := []string{uuid.NewString(), uuid.NewString(), uuid.NewString()}
	bundle, err := SealTunnelImportDisplay(key.PublicKey().Bytes(), ids[0], ids[1], ids[2], 5, []byte("redacted"))
	if err != nil {
		t.Fatal(err)
	}
	private, _ := hpke.NewDHKEMPrivateKey(key)
	for _, change := range []string{"valid", "domain", "workspace", "editor", "import", "kind"} {
		fields := append([]string{}, ids...)
		kind := 5
		domain := "wormhole/v1/tunnel-import"
		switch change {
		case "domain":
			domain = "wormhole/v1/tunnel-editor"
		case "workspace":
			fields[0] = uuid.NewString()
		case "editor":
			fields[1] = uuid.NewString()
		case "import":
			fields[2] = uuid.NewString()
		case "kind":
			kind = 4
		}
		info := canonical(domain, []byte(fields[0]), []byte(fields[1]), []byte(fields[2]), []byte(strconv.Itoa(kind)))
		recipient, e := hpke.NewRecipient(bundle.Enc, private, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
		if e != nil {
			t.Fatal(e)
		}
		plain, e := recipient.Open(nil, bundle.Ciphertext)
		if change == "valid" {
			if e != nil || string(plain) != "redacted" {
				t.Fatal(e)
			}
		} else if e == nil {
			t.Fatal("wrong context opened")
		}
	}
	for i := range ids {
		copyIDs := append([]string{}, ids...)
		copyIDs[i] = "bad"
		if _, err := SealTunnelImportDisplay(key.PublicKey().Bytes(), copyIDs[0], copyIDs[1], copyIDs[2], 1, nil); err != ErrFormat {
			t.Fatal(err)
		}
	}
	for _, kind := range []int{-1, 10} {
		if _, err := SealTunnelImportDisplay(key.PublicKey().Bytes(), ids[0], ids[1], ids[2], kind, nil); err != ErrFormat {
			t.Fatal(err)
		}
	}
	if _, err := SealTunnelImportDisplay(key.PublicKey().Bytes(), ids[0], ids[1], ids[2], 1, make([]byte, 512*1024+1)); err != ErrFormat {
		t.Fatal(err)
	}
}
