package argon2

import (
	"bytes"
	"testing"

	upstream "golang.org/x/crypto/argon2"
)

func TestSuppliedMatrixMatchesUpstream(t *testing.T) {
	password, salt := []byte("vault test password"), []byte("known public salt")
	for _, tc := range []struct {
		memory, passes uint32
		lanes          uint8
	}{{8, 1, 1}, {32, 1, 4}, {512, 2, 2}, {1024, 4, 4}, {65536, 3, 4}} {
		blocks := make([]Block, tc.memory)
		got := IDKey(password, salt, tc.passes, tc.lanes, blocks)
		want := upstream.IDKey(password, salt, tc.passes, tc.memory, tc.lanes, 32)
		clear(blocks)
		if !bytes.Equal(got, want) {
			t.Fatalf("incompatible result for %d KiB, %d passes, %d lanes", tc.memory, tc.passes, tc.lanes)
		}
	}
	for _, tc := range []struct{ blocks, passes, lanes int }{{0, 1, 1}, {8, 0, 1}, {8, 1, 0}, {9, 1, 1}, {16, 1, 4}} {
		if IDKey(password, salt, uint32(tc.passes), uint8(tc.lanes), make([]Block, tc.blocks)) != nil {
			t.Fatal("accepted an invalid matrix or cost")
		}
	}
}

func TestNativeAndPortableBlockProcessingAgree(t *testing.T) {
	var a, b, native, portable block
	for i := range a {
		a[i], b[i] = uint64(i*i+17), uint64(3*i+5)
	}
	processBlock(&native, &a, &b)
	processBlockGeneric(&portable, &a, &b, false)
	if native != portable {
		t.Fatal("incompatible block implementation")
	}
	processBlockXOR(&native, &a, &a)
	processBlockGeneric(&portable, &a, &a, true)
	if native != portable {
		t.Fatal("incompatible XOR implementation")
	}
}
