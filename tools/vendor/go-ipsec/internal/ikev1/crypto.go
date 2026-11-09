package ikev1

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/sha1" //nolint:gosec // SHA-1 is required for IKEv1 interop (native clients, xl2tpd)
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/n0madic/go-ipsec/internal/legacycrypto"
)

const aesBlockSize = 16

// dhGroup maps a negotiated Group Description to a cryptoutil DH group.
func dhGroup(id uint16) (cryptoutil.DHGroup, error) {
	return cryptoutil.NewGroup(id)
}

// hashCtor maps a negotiated Hash Algorithm to a hash constructor.
func hashCtor(id uint16) (func() hash.Hash, error) {
	switch id {
	case 1:
		return md5.New, nil
	case 5:
		return sha512.New384, nil
	case 6:
		return sha512.New, nil
	case hashSHA2256:
		return sha256.New, nil
	case hashSHA:
		return sha1.New, nil
	default:
		return nil, fmt.Errorf("ikev1: unsupported hash %d", id)
	}
}

// newPRF builds the HMAC PRF over the negotiated phase-1 hash (RFC 2409 uses the
// negotiated hash as the PRF when none is negotiated explicitly).
func newPRF(hashID uint16) (*cryptoutil.PRF, error) {
	ctor, err := hashCtor(hashID)
	if err != nil {
		return nil, err
	}
	return cryptoutil.NewHMACPRF(ctor), nil
}

// cbcEncrypt pads the plaintext to the AES block size and CBC-encrypts it. ISAKMP
// padding has no length octet: the payload chain self-delimits, so trailing pad
// is simply ignored on decrypt (RFC 2408 section 3.6).
func cbcEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	block, err := blockCipher(key, len(iv))
	if err != nil {
		return nil, err
	}
	padded := plaintext
	if rem := len(plaintext) % block.BlockSize(); rem != 0 {
		padded = append(append([]byte(nil), plaintext...), make([]byte, block.BlockSize()-rem)...)
	}
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	return ct, nil
}

// cbcDecrypt CBC-decrypts a block-aligned ciphertext.
func cbcDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := blockCipher(key, len(iv))
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("ikev1: ciphertext not block-aligned")
	}
	pt := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ciphertext)
	return pt, nil
}

// lastBlock returns the final cipher block of ct, the CBC IV for the next message
// in the same exchange (RFC 2409 Appendix B).
func blockCipher(key []byte, size int) (cipher.Block, error) {
	if size == 8 {
		return des.NewTripleDESCipher(key)
	}
	return aes.NewCipher(key)
}

func lastBlock(ct []byte, sizes ...int) []byte {
	size := aesBlockSize
	if len(sizes) > 0 {
		size = sizes[0]
	}
	if len(ct) < size {
		return make([]byte, size)
	}
	return append([]byte(nil), ct[len(ct)-size:]...)
}
