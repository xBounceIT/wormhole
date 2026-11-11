// Package cryptosuite describes explicitly configured interoperable CBC suites.
// The default AEAD proposal policy is kept by the calling protocol package.
package cryptosuite

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
)

const FirstCBC uint8 = 16

type CBC struct {
	Encryption, Integrity, PRF, KeyBits                   uint16
	EncryptionBytes, IntegrityBytes, ICVBytes, BlockBytes int
	Hash                                                  func() hash.Hash
	Name                                                  string
}

func ID(encryption, authentication int) (uint8, bool) {
	if encryption < 0 || encryption > 3 || authentication < 0 || authentication > 4 {
		return 0, false
	}
	return FirstCBC + uint8(encryption*5+authentication), true
}

func Lookup(id uint8) (CBC, bool) {
	if id == 0 {
		id, _ = ID(2, 2)
	} // Existing AES-256 / SHA-256 enum retains its meaning.
	if id < FirstCBC || id >= FirstCBC+20 {
		return CBC{}, false
	}
	index := int(id - FirstCBC)
	encryption, authentication := index/5, index%5
	c := CBC{Encryption: 12, KeyBits: uint16(128 + encryption*64), EncryptionBytes: 16 + encryption*8, BlockBytes: 16}
	if encryption == 3 {
		c.Encryption = 3
		c.KeyBits = 0
		c.EncryptionBytes = 24
		c.BlockBytes = 8
	}
	c.Hash = []func() hash.Hash{md5.New, sha1.New, sha256.New, sha512.New384, sha512.New}[authentication]
	c.Integrity = []uint16{1, 2, 12, 13, 14}[authentication]
	c.PRF = []uint16{1, 2, 5, 6, 7}[authentication]
	c.IntegrityBytes = c.Hash().Size()
	c.ICVBytes = []int{12, 12, 16, 24, 32}[authentication]
	cipherName := fmt.Sprintf("aes%d", c.KeyBits)
	if encryption == 3 {
		cipherName = "3des"
	}
	c.Name = cipherName + "-" + []string{"md5", "sha1", "sha256", "sha384", "sha512"}[authentication]
	return c, true
}

func (c CBC) Cipher(key []byte) (cipher.Block, error) {
	if len(key) != c.EncryptionBytes {
		return nil, errors.New("invalid CBC key length")
	}
	if c.Encryption == 3 {
		return des.NewTripleDESCipher(key)
	}
	return aes.NewCipher(key)
}
func (c CBC) MAC(key, data []byte) []byte {
	h := hmac.New(c.Hash, key)
	h.Write(data)
	return h.Sum(nil)
}
func (c CBC) Plus(key, seed []byte, length int) []byte {
	out := make([]byte, 0, length)
	var previous []byte
	for index := 1; len(out) < length; index++ {
		if index > 255 {
			panic("PRF+ output exceeds RFC 7296 bound")
		}
		h := hmac.New(c.Hash, key)
		h.Write(previous)
		h.Write(seed)
		h.Write([]byte{byte(index)})
		previous = h.Sum(nil)
		out = append(out, previous...)
	}
	return out[:length]
}
