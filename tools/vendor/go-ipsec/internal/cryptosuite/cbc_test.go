package cryptosuite

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestCBCMatrix(t *testing.T) {
	for e := 0; e < 4; e++ {
		for a := 0; a < 5; a++ {
			id, ok := ID(e, a)
			if !ok {
				t.Fatal("valid suite rejected")
			}
			p, ok := Lookup(id)
			if !ok || p.PRF != []uint16{1, 2, 5, 6, 7}[a] || p.Integrity != []uint16{1, 2, 12, 13, 14}[a] {
				t.Fatal("wrong IANA transforms")
			}
			block, err := p.Cipher(make([]byte, p.EncryptionBytes))
			if err != nil {
				t.Fatal(err)
			}
			plain, cipher, round := make([]byte, p.BlockBytes), make([]byte, p.BlockBytes), make([]byte, p.BlockBytes)
			block.Encrypt(cipher, plain)
			block.Decrypt(round, cipher)
			if !bytes.Equal(round, plain) {
				t.Fatal("CBC primitive mismatch")
			}
			if _, err := p.Cipher(nil); err == nil {
				t.Fatal("bad key accepted")
			}
			if len(p.Plus([]byte("key"), []byte("seed"), 255)) != 255 {
				t.Fatal("PRF+ length invalid")
			}
			if p.Name == "" {
				t.Fatal("missing suite name")
			}
		}
	}
	for _, pair := range [][2]int{{-1, 0}, {4, 0}, {0, 5}, {0, -1}} {
		if _, ok := ID(pair[0], pair[1]); ok {
			t.Fatal("invalid tuple accepted")
		}
	}
	for _, id := range []uint8{1, 15, 36, 255} {
		if _, ok := Lookup(id); ok {
			t.Fatal("invalid suite accepted")
		}
	}
	if _, ok := Lookup(0); !ok {
		t.Fatal("baseline missing")
	}
}
func TestPRFKnownAnswers(t *testing.T) {
	want := []string{"9294727a3638bb1c13f48ef8158bfc9d", "b617318655057264e28bc0b6fb378c8ef146be00", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6", "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"}
	want[4] = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
	for a, value := range want {
		id, _ := ID(0, a)
		p, _ := Lookup(id)
		n := 20
		if a == 0 {
			n = 16
		}
		if hex.EncodeToString(p.MAC(bytes.Repeat([]byte{0x0b}, n), []byte("Hi There"))) != value {
			t.Fatal("PRF known answer failed", a)
		}
	}
	defer func() {
		if recover() == nil {
			t.Fatal("unbounded PRF+ permitted")
		}
	}()
	p, _ := Lookup(16)
	p.Plus(nil, nil, 16*256)
}
