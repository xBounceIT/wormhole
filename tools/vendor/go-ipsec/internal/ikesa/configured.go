package ikesa

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"github.com/n0madic/go-ipsec/internal/cryptosuite"
)

func (s Suite) cbc() cryptosuite.CBC {
	p, ok := cryptosuite.Lookup(uint8(s))
	if !ok {
		p, _ = cryptosuite.Lookup(0)
	}
	return p
}
func (s Suite) prf(key, data []byte) []byte         { return s.cbc().MAC(key, data) }
func (s Suite) plus(key, seed []byte, n int) []byte { return s.cbc().Plus(key, seed, n) }
func (s Suite) prfBytes() int                       { return s.cbc().IntegrityBytes }
func (s Suite) nonceFloor() int {
	n := s.prfBytes() / 2
	if n < minNonceLen {
		return minNonceLen
	}
	return n
}
func (s Suite) encryptCBC(key, plain []byte) ([]byte, error) {
	p := s.cbc()
	block, err := p.Cipher(key)
	if err != nil {
		return nil, err
	}
	if len(plain)%p.BlockBytes != 0 {
		return nil, errors.New("IKE CBC plaintext is not block aligned")
	}
	out := make([]byte, p.BlockBytes+len(plain))
	if _, err = io.ReadFull(rand.Reader, out[:p.BlockBytes]); err != nil {
		return nil, err
	}
	cipher.NewCBCEncrypter(block, out[:p.BlockBytes]).CryptBlocks(out[p.BlockBytes:], plain)
	return out, nil
}
func (s Suite) decryptCBC(key, wire []byte) ([]byte, error) {
	p := s.cbc()
	if len(wire) < 2*p.BlockBytes || (len(wire)-p.BlockBytes)%p.BlockBytes != 0 {
		return nil, errors.New("IKE CBC ciphertext is not block aligned")
	}
	block, err := p.Cipher(key)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(wire)-p.BlockBytes)
	cipher.NewCBCDecrypter(block, wire[:p.BlockBytes]).CryptBlocks(plain, wire[p.BlockBytes:])
	return plain, nil
}

func (s Suite) validNonce(nonce []byte) bool {
	return len(nonce) >= s.nonceFloor() && len(nonce) <= 256
}
func (s *IKESA) ValidNonce(nonce []byte) bool { return s.Suite.validNonce(nonce) }
