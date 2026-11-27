package vault

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestDarwinPasswordMatrix(t *testing.T) {
	password, salt := []byte("public test value"), []byte("public test salt")
	p := KDFParameters{MemoryKiB: 256, Iterations: 2, Parallelism: 4}
	key, err := passwordKey(password, salt, p)
	if err != nil || !bytes.Equal(key, argon2.IDKey(password, salt, 2, 256, 4, 32)) {
		t.Fatal("mapped derivation disagrees with reference", err)
	}
	for _, invalid := range []KDFParameters{{}, {MemoryKiB: 16, Iterations: 1, Parallelism: 4}} {
		if key, err := passwordKey(password, salt, invalid); err == nil || key != nil {
			t.Fatal("invalid mapping size or matrix yielded a key")
		}
	}
}
