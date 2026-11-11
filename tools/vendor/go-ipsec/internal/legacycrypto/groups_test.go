package cryptoutil

import (
	"bytes"
	"testing"
)

func TestFortinetDHGroups(t *testing.T) {
	for _, id := range []uint16{1, 2, 5, 14, 15, 16, 17, 18, 19, 20, 21} {
		a, err := NewGroup(id)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := NewGroup(id)
		pubA, err := a.Generate()
		if err != nil {
			t.Fatal(err)
		}
		pubB, err := b.Generate()
		if err != nil {
			t.Fatal(err)
		}
		sharedA, err := a.ComputeSecret(pubB)
		if err != nil {
			t.Fatal(err)
		}
		sharedB, err := b.ComputeSecret(pubA)
		if err != nil || !bytes.Equal(sharedA, sharedB) {
			t.Fatalf("DH %d does not agree", id)
		}
		if group, ok := a.(*modpGroup); ok {
			if !group.prime.ProbablyPrime(16) {
				t.Fatalf("group %d prime is incorrect", id)
			}
			if id == 14 && group.prime.Cmp(modp2048Prime) != 0 {
				t.Fatal("RFC 3526 group 14 mismatch")
			}
			if _, err = a.ComputeSecret([]byte{1}); err == nil {
				t.Fatal("degenerate peer accepted")
			}
		}
	}
	if _, err := NewGroup(3); err == nil {
		t.Fatal("unknown group admitted")
	}
}
