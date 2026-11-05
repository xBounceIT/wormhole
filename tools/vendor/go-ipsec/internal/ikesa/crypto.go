package ikesa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// Fixed sizes for the negotiable transform suites. They double as the SK_*
// key lengths fed into prf+ during key derivation.
const (
	// prfKeyLen is the PRF_HMAC_SHA2_256 key/output length → SK_d, SK_p*.
	prfKeyLen = 32
	// integKeyLen is the AUTH_HMAC_SHA2_256_128 key length → SK_a* (CBC suite).
	integKeyLen = 32
	// integICVLen is the AUTH_HMAC_SHA2_256_128 truncated output (128 bits).
	integICVLen = 16
	// encrKeyLen is the ENCR_AES_CBC-256 key length → SK_e* (CBC suite).
	encrKeyLen = 32
	// aesBlock is the AES/CBC block and IV size.
	aesBlock = aes.BlockSize

	// AEAD SK{} framing (RFC 5282): an 8-byte per-message IV on the wire, a
	// 12-byte nonce built as salt(4) | IV(8), and a 16-octet ICV (tag).
	aeadIVLen   = 8
	aeadSaltLen = 4
	aeadTagLen  = 16
	// aeadEncrKeyLen is the AEAD SK_e* length: a 32-byte key with the 4-byte
	// salt taken from the END of the keying material (RFC 5282 §7.1/§7.4,
	// RFC 7634 §3). The AEAD suites have no SK_a* (RFC 5282 §7).
	aeadEncrKeyLen = 32 + aeadSaltLen

	// ikeHdrLen/genericHdrLen bound the minimum SK-body offset inside a
	// message: the fixed IKE header plus the SK payload's generic header.
	ikeHdrLen     = 28
	genericHdrLen = 4
)

// newAEAD constructs the AEAD primitive for an AEAD suite from a 32-byte key
// (a deliberate mirror of internal/esp's helper — the packages stay
// independent so ikesa never imports the data plane).
func newAEAD(suite Suite, key []byte) (cipher.AEAD, error) {
	switch suite {
	case SuiteAESGCM256:
		b, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(b)
	case SuiteChaCha20Poly1305:
		return chacha20poly1305.New(key)
	default:
		return nil, fmt.Errorf("ikesa: suite %v is not an AEAD suite", suite)
	}
}

// prf is the negotiated pseudorandom function, PRF_HMAC_SHA2_256. It returns
// the keyed MAC of data — RFC 7296's prf(key, data).
func prf(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// prfPlus implements prf+ (RFC 7296 §2.13):
//
//	prf+(K,S) = T1 | T2 | T3 | ...
//	T1 = prf(K, S | 0x01)
//	Tn = prf(K, T(n-1) | S | n)
//
// It returns the first keyLen bytes of the stream.
func prfPlus(key, seed []byte, keyLen int) []byte {
	out := make([]byte, 0, keyLen+sha256.Size)
	var prev []byte
	for i := 1; len(out) < keyLen; i++ {
		// The block index is a single octet (RFC 7296 §2.13), so prf+ yields at most
		// 255 blocks. This client's fixed suites never request more than a handful, so
		// an i past 255 is an internal invariant violation, not a wire-driven case;
		// guard rather than let byte(i) silently wrap to 0 and produce wrong keys.
		if i > 255 {
			panic("ikesa: prfPlus requested more than 255 blocks")
		}
		h := hmac.New(sha256.New, key)
		h.Write(prev)
		h.Write(seed)
		h.Write([]byte{byte(i)})
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:keyLen]
}

// integ computes the AUTH_HMAC_SHA2_256_128 ICV over data, truncated to 128
// bits.
func integ(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)[:integICVLen]
}

// aesCBCEncrypt encrypts plaintext (already a multiple of the block size) under
// AES-CBC with a fresh random IV, returning IV || ciphertext.
func aesCBCEncrypt(key, plaintext []byte) ([]byte, error) {
	if len(plaintext)%aesBlock != 0 {
		return nil, errors.New("ikesa: plaintext not block-aligned")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, aesBlock+len(plaintext))
	iv := out[:aesBlock]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out[aesBlock:], plaintext)
	return out, nil
}

// aesCBCDecrypt decrypts IV || ciphertext under AES-CBC, returning the padded
// plaintext (caller strips the RFC 7296 self-describing pad).
func aesCBCDecrypt(key, ivAndCT []byte) ([]byte, error) {
	if len(ivAndCT) < aesBlock {
		return nil, errors.New("ikesa: SK ciphertext shorter than IV")
	}
	iv := ivAndCT[:aesBlock]
	ct := ivAndCT[aesBlock:]
	if len(ct) == 0 || len(ct)%aesBlock != 0 {
		return nil, errors.New("ikesa: SK ciphertext not block-aligned")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
	return out, nil
}
