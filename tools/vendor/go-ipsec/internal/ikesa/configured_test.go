package ikesa

import (
	"bytes"
	"encoding/binary"
	"github.com/n0madic/go-ipsec/internal/cryptosuite"
	"testing"
)

func TestConfiguredMatrixAndRekey(t *testing.T) {
	ni, nr, shared := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 256)
	for id := cryptosuite.FirstCBC; id < cryptosuite.FirstCBC+20; id++ {
		suite := Suite(id)
		t.Run(suite.String(), func(t *testing.T) {
			var initiator, responder IKESA
			for role, sa := range []*IKESA{&initiator, &responder} {
				if err := sa.Derive(suite, Role(role), 11, 22, ni, nr, shared); err != nil {
					t.Fatal(err)
				}
			}
			p, _ := cryptosuite.Lookup(id)
			if len(initiator.SKd) != p.IntegrityBytes || len(initiator.SKei) != p.EncryptionBytes || len(initiator.SKai) != p.IntegrityBytes {
				t.Fatal("wrong key schedule")
			}
			expected := p.MAC(append(append([]byte{}, ni...), nr...), shared)
			seed := concat(concat(ni, nr), concat(u64(11), u64(22)))
			if !bytes.Equal(initiator.SKd, p.Plus(expected, seed, p.IntegrityBytes)) {
				t.Fatal("SKEYSEED mismatch")
			}
			for _, payload := range [][]byte{nil, []byte("protected payload"), bytes.Repeat([]byte{4}, 257)} {
				sk, err := initiator.EncryptToSK(payload)
				if err != nil {
					t.Fatal(err)
				}
				wire := skFrame(sk)
				if err = initiator.FinalizeSK(wire, len(sk)); err != nil {
					t.Fatal(err)
				}
				plain, ok, err := responder.OpenSK(wire, wire[len(wire)-len(sk):])
				if err != nil || !ok || !bytes.Equal(plain, payload) {
					t.Fatal("SK round trip", err)
				}
				wire[len(wire)-1] ^= 1
				if _, ok, err := responder.OpenSK(wire, wire[len(wire)-len(sk):]); err == nil || ok {
					t.Fatal("invalid ICV accepted")
				}
			}
			if _, err := suite.encryptCBC(nil, nil); err == nil {
				t.Fatal("invalid key accepted")
			}
			if _, err := suite.encryptCBC(initiator.SKei, []byte{1}); err == nil {
				t.Fatal("unaligned plaintext accepted")
			}
			if _, err := suite.decryptCBC(initiator.SKei, []byte{1}); err == nil {
				t.Fatal("short ciphertext accepted")
			}
			if _, err := suite.decryptCBC(nil, make([]byte, p.BlockBytes*2)); err == nil {
				t.Fatal("bad decryption key accepted")
			}
			var short IKESA
			if short.Derive(suite, Initiator, 1, 2, ni[:suite.nonceFloor()-1], nr, shared) == nil {
				t.Fatal("short nonce accepted")
			}
			next := Suite(cryptosuite.FirstCBC + (id-cryptosuite.FirstCBC+1)%20)
			rekey, err := DeriveRekeyIKE(next, initiator.SKd, Initiator, 33, 44, ni, nr, shared, suite)
			if err != nil {
				t.Fatal(err)
			}
			seedKey := suite.prf(initiator.SKd, concat(shared, concat(ni, nr)))
			want := next.plus(seedKey, concat(concat(ni, nr), concat(u64(33), u64(44))), next.prfBytes())
			if !bytes.Equal(rekey.SKd, want) {
				t.Fatal("rekey did not use OLD PRF for SKEYSEED and NEW PRF for key expansion")
			}
			if bytes.Equal(initiator.DeriveChildKeys(ni, nr, 16, 20).EncrIR, initiator.DeriveChildKeysPFS(shared, ni, nr, 16, 20).EncrIR) {
				t.Fatal("PFS secret omitted")
			}
		})
	}
}
func TestConfiguredDHGroups(t *testing.T) {
	for _, group := range []uint16{1, 2, 5, 14, 15, 16, 17, 18, 19, 20, 21} {
		a, err := NewDH(group)
		if err != nil {
			t.Fatal(group, err)
		}
		b, err := NewDH(group)
		if err != nil {
			t.Fatal(err)
		}
		one, err := a.Shared(b.Public)
		if err != nil {
			t.Fatal(group, err)
		}
		two, err := b.Shared(a.Public)
		if err != nil || !bytes.Equal(one, two) {
			t.Fatal("DH mismatch", group, err)
		}
		for _, invalid := range [][]byte{nil, make([]byte, len(a.Public)), append([]byte{1}, a.Public...)} {
			if _, err := a.Shared(invalid); err == nil {
				t.Fatal("invalid DH value accepted", group)
			}
		}
	}
}

func u64(value uint64) []byte { return binary.BigEndian.AppendUint64(nil, value) }

func TestRekeyNonceHonorsOldPRF(t *testing.T) {
	old, _ := cryptosuite.ID(2, 4)
	next, _ := cryptosuite.ID(0, 0)
	if _, err := DeriveRekeyIKE(Suite(next), make([]byte, 64), Initiator, 1, 2, make([]byte, 16), make([]byte, 16), make([]byte, 32), Suite(old)); err == nil {
		t.Fatal("old SHA512 PRF accepted a short rekey nonce")
	}
}
