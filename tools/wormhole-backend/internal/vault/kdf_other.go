//go:build !darwin

package vault

import "golang.org/x/crypto/argon2"

func passwordKey(password, salt []byte, params KDFParameters) ([]byte, error) {
	return argon2.IDKey(password, salt, params.Iterations, params.MemoryKiB, params.Parallelism, 32), nil
}
