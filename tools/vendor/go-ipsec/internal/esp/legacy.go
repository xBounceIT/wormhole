package esp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

// NewLegacySA uses negotiated IANA transforms. It never broadens the peer's
// admitted proposals; legacy algorithms require an explicit profile selection.
func NewLegacySA(encryption, integrity uint16, outSPI, inSPI uint32, outEnc, outMAC, inEnc, inMAC []byte, replay bool) (*SA, error) {
	var newBlock func([]byte) (cipher.Block, error)
	switch encryption {
	case 12:
		newBlock = aes.NewCipher
	case 3:
		newBlock = des.NewTripleDESCipher
	default:
		return nil, errors.New("ESP encryption unsupported")
	}
	var h func() hash.Hash
	size := 0
	switch integrity {
	case 1:
		h = md5.New
		size = 12
	case 2:
		h = sha1.New
		size = 12
	case 12:
		h = sha256.New
		size = 16
	case 13:
		h = sha512.New384
		size = 24
	case 14:
		h = sha512.New
		size = 32
	default:
		return nil, errors.New("ESP integrity unsupported")
	}
	if len(outMAC) != h().Size() || len(inMAC) != h().Size() {
		return nil, errors.New("ESP integrity key length invalid")
	}
	out, err := newBlock(outEnc)
	if err != nil {
		return nil, err
	}
	in, err := newBlock(inEnc)
	if err != nil {
		return nil, err
	}
	return &SA{outSPI: outSPI, inSPI: inSPI, outBlock: out, inBlock: in, outInteg: append([]byte(nil), outMAC...), inInteg: append([]byte(nil), inMAC...), hash: h, icvLen: size, replay: NewReplayWindow(64), noReplay: !replay}, nil
}
