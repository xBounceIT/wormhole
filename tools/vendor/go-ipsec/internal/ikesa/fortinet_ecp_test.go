package ikesa

import (
	"bytes"
	"testing"
)

func TestFortinetECPGroups(t *testing.T) {
	for _, group := range []uint16{DHGroup19, DHGroup20} {
		left, err := NewDH(group)
		if err != nil {
			t.Fatal(err)
		}
		right, err := NewDH(group)
		if err != nil {
			t.Fatal(err)
		}
		a, err := left.Shared(right.Public)
		if err != nil {
			t.Fatal(err)
		}
		b, err := right.Shared(left.Public)
		if err != nil || !bytes.Equal(a, b) {
			t.Fatal("ECP shared secrets disagree", err)
		}
		if len(left.Public) != 2*len(a) {
			t.Fatal("ECP wire value contains SEC1 prefix")
		}
		for _, bad := range [][]byte{nil, {4}, make([]byte, len(left.Public)), append([]byte{4}, left.Public...)} {
			if _, err := left.Shared(bad); err == nil {
				t.Fatal("invalid ECP point accepted")
			}
		}
	}
}
