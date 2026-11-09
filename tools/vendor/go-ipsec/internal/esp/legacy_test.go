package esp

import (
	"bytes"
	"testing"
)

func TestFortinetLegacyESP(t *testing.T) {
	for _, encryption := range []uint16{3, 12} {
		for _, integrity := range []uint16{1, 2, 12, 13, 14} {
			for _, replay := range []bool{false, true} {
				encLen := 32
				if encryption == 3 {
					encLen = 24
				}
				macLen := map[uint16]int{1: 16, 2: 20, 12: 32, 13: 48, 14: 64}[integrity]
				enc := bytes.Repeat([]byte{42}, encLen)
				mac := bytes.Repeat([]byte{12}, macLen)
				sa, err := NewLegacySA(encryption, integrity, 7, 7, enc, mac, enc, mac, replay)
				if err != nil {
					t.Fatal(err)
				}
				packet, err := sa.Encrypt([]byte{0x45, 1, 2, 3})
				if err != nil {
					t.Fatal(err)
				}
				plain, err := sa.Decrypt(packet)
				if err != nil || !bytes.Equal(plain, []byte{0x45, 1, 2, 3}) {
					t.Fatal("ESP roundtrip failed", err)
				}
				_, err = sa.Decrypt(packet)
				if replay && err != ErrReplay || !replay && err != nil {
					t.Fatal("incorrect replay behavior")
				}
				packet[len(packet)-1] ^= 1
				if _, err = sa.Decrypt(packet); err == nil {
					t.Fatal("forged ESP accepted")
				}
			}
		}
	}
	for _, tuple := range [][2]uint16{{0, 2}, {12, 0}, {12, 2}} {
		if _, err := NewLegacySA(tuple[0], tuple[1], 1, 1, nil, nil, nil, nil, true); err == nil {
			t.Fatal("invalid transforms accepted")
		}
	}
}
