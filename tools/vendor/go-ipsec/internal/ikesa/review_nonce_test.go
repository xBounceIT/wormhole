package ikesa

import (
	"github.com/n0madic/go-ipsec/internal/cryptosuite"
	"strings"
	"testing"
)

func TestIKEKeyScheduleRejectsOversizedNonces(t *testing.T) {
	var sa IKESA
	if err := sa.Derive(0, Initiator, 1, 2, make([]byte, 257), make([]byte, 32), []byte{1}); err == nil || !strings.Contains(err.Error(), "bounds") {
		t.Fatal("oversized initial nonce accepted")
	}
	id, _ := cryptosuite.ID(2, 4)
	if _, err := DeriveRekeyIKE(Suite(id), make([]byte, 64), Initiator, 1, 2, make([]byte, 257), make([]byte, 32), []byte{1}, Suite(id)); err == nil || !strings.Contains(err.Error(), "bounds") {
		t.Fatal("oversized rekey nonce accepted")
	}
}
