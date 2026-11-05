package esp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/n0madic/go-ipsec/internal/secretmem"
)

// Suite identifies the ESP transform suite an SA runs. The zero value is the
// AES-CBC-256 + HMAC-SHA2-256-128 suite, so pre-suite constructions keep their
// meaning.
type Suite uint8

const (
	// SuiteAESCBC256SHA256 is AES-CBC-256 encryption with HMAC-SHA2-256-128
	// integrity (RFC 3602 + RFC 4868). Key material per direction: a 32-byte
	// encryption key and a 32-byte integrity key.
	SuiteAESCBC256SHA256 Suite = iota
	// SuiteAESGCM256 is AES-GCM-256 with a 16-octet ICV (RFC 4106). Key
	// material per direction: 36 bytes (32-byte key + 4-byte salt), no
	// integrity key.
	SuiteAESGCM256
	// SuiteChaCha20Poly1305 is ChaCha20-Poly1305 (RFC 7634). Key material per
	// direction: 36 bytes (32-byte key + 4-byte salt), no integrity key.
	SuiteChaCha20Poly1305
)

// String implements fmt.Stringer with the conventional (strongSwan-style)
// transform names, for diagnostics.
func (s Suite) String() string {
	switch s {
	case SuiteAESCBC256SHA256:
		return "aes256-sha256"
	case SuiteAESGCM256:
		return "aes256gcm16"
	case SuiteChaCha20Poly1305:
		return "chacha20poly1305"
	default:
		return fmt.Sprintf("esp-suite-%d", uint8(s))
	}
}

const (
	espHeaderLen = 8  // SPI(4) | SeqNum(4)
	cbcIVLen     = 16 // AES-CBC IV
	espICVLen    = 16 // HMAC-SHA2-256-128 truncated ICV; also the AEAD tag length
	espBlock     = aes.BlockSize
	// AEAD framing (RFC 4106 / RFC 7634): an 8-byte per-packet IV on the wire,
	// with the 12-byte nonce built as salt(4) | IV(8).
	aeadIVLen   = 8
	aeadSaltLen = 4
	// Per-direction key material lengths NewSA validates.
	cbcEncrKeyLen  = 32               // AES-256
	cbcIntegKeyLen = 32               // HMAC-SHA2-256 (RFC 4868)
	aeadEncrKeyLen = 32 + aeadSaltLen // 32-byte key + 4-byte salt (RFC 4106 §8.1 / RFC 7634 §2)
	// nextHeaderIPv4 / nextHeaderIPv6 are the ESP Next Header values for a
	// tunnelled IPv4 / IPv6 packet (RFC 4303 tunnel mode).
	nextHeaderIPv4 = 4
	nextHeaderIPv6 = 41
)

// ErrReplay is returned by Decrypt when a packet fails the anti-replay check.
var ErrReplay = errors.New("esp: replay or out-of-window sequence")

// ErrSeqExhausted is returned by Encrypt when the 32-bit outbound sequence
// counter is about to wrap. RFC 4303 §3.3.3 forbids reusing a sequence number,
// so the SA must be rekeyed before this happens; Encrypt refuses to emit a
// wrapped (and therefore replayed) packet rather than silently stalling the peer.
// For the AEAD suites the pinned counter additionally guarantees the per-packet
// IV (= the sequence number) is never reused — nonce reuse under GCM is
// catastrophic, so this pin must never be bypassed.
var ErrSeqExhausted = errors.New("esp: outbound sequence number space exhausted, rekey required")

// SA is one directional pair of Child SA crypto contexts (outbound to the peer,
// inbound from the peer). It owns the outbound sequence counter and the inbound
// anti-replay window. Encrypt/Decrypt are safe for concurrent use.
type SA struct {
	suite Suite

	outSPI uint32 // peer's SPI: goes in packets we send
	inSPI  uint32 // our SPI: expected in packets we receive

	// CBC+HMAC state (SuiteAESCBC256SHA256 only).
	outBlock cipher.Block
	inBlock  cipher.Block
	outInteg []byte
	inInteg  []byte

	// AEAD state (SuiteAESGCM256 / SuiteChaCha20Poly1305 only); the nonce is
	// salt(4) | IV(8).
	outAEAD cipher.AEAD
	inAEAD  cipher.AEAD
	outSalt []byte
	inSalt  []byte

	seq    atomic.Uint32
	replay *ReplayWindow
}

// NewSA builds a Child SA transform for the given suite. outSPI is the
// responder's SPI (placed in outbound packets); inSPI is our SPI (matched on
// inbound). The key arguments are the directional ESP key material, whose
// lengths must match the suite: 32-byte encryption + 32-byte integrity keys for
// AES-CBC, or 36-byte encryption material (32-byte key + 4-byte salt) with
// empty integrity keys for the AEAD suites. Construction runs inside
// secretmem.Do so the cipher key schedules and key copies are runtime-tracked
// and erased once the SA is dropped on rekey or teardown (see internal/secretmem).
func NewSA(suite Suite, outSPI, inSPI uint32, outEncr, outInteg, inEncr, inInteg []byte, replayWindow uint32) (*SA, error) {
	var sa *SA
	var err error
	secretmem.Do(func() { sa, err = newSA(suite, outSPI, inSPI, outEncr, outInteg, inEncr, inInteg, replayWindow) })
	return sa, err
}

func newSA(suite Suite, outSPI, inSPI uint32, outEncr, outInteg, inEncr, inInteg []byte, replayWindow uint32) (*SA, error) {
	sa := &SA{
		suite:  suite,
		outSPI: outSPI,
		inSPI:  inSPI,
		replay: NewReplayWindow(replayWindow),
	}
	switch suite {
	case SuiteAESCBC256SHA256:
		for _, k := range [...]struct {
			name        string
			encr, integ []byte
		}{{"outbound", outEncr, outInteg}, {"inbound", inEncr, inInteg}} {
			if len(k.encr) != cbcEncrKeyLen || len(k.integ) != cbcIntegKeyLen {
				return nil, fmt.Errorf("esp: %s %s key material: encr %d + integ %d bytes, want %d + %d",
					suite, k.name, len(k.encr), len(k.integ), cbcEncrKeyLen, cbcIntegKeyLen)
			}
		}
		ob, err := aes.NewCipher(outEncr)
		if err != nil {
			return nil, fmt.Errorf("esp: outbound cipher: %w", err)
		}
		ib, err := aes.NewCipher(inEncr)
		if err != nil {
			return nil, fmt.Errorf("esp: inbound cipher: %w", err)
		}
		sa.outBlock, sa.inBlock = ob, ib
		sa.outInteg = append([]byte(nil), outInteg...)
		sa.inInteg = append([]byte(nil), inInteg...)
	case SuiteAESGCM256, SuiteChaCha20Poly1305:
		for _, k := range [...]struct {
			name        string
			encr, integ []byte
		}{{"outbound", outEncr, outInteg}, {"inbound", inEncr, inInteg}} {
			if len(k.encr) != aeadEncrKeyLen || len(k.integ) != 0 {
				return nil, fmt.Errorf("esp: %s %s key material: encr %d + integ %d bytes, want %d + 0",
					suite, k.name, len(k.encr), len(k.integ), aeadEncrKeyLen)
			}
		}
		oa, err := newAEAD(suite, outEncr[:aeadEncrKeyLen-aeadSaltLen])
		if err != nil {
			return nil, fmt.Errorf("esp: outbound cipher: %w", err)
		}
		ia, err := newAEAD(suite, inEncr[:aeadEncrKeyLen-aeadSaltLen])
		if err != nil {
			return nil, fmt.Errorf("esp: inbound cipher: %w", err)
		}
		sa.outAEAD, sa.inAEAD = oa, ia
		sa.outSalt = append([]byte(nil), outEncr[aeadEncrKeyLen-aeadSaltLen:]...)
		sa.inSalt = append([]byte(nil), inEncr[aeadEncrKeyLen-aeadSaltLen:]...)
	default:
		return nil, fmt.Errorf("esp: unknown suite %d", suite)
	}
	return sa, nil
}

// newAEAD constructs the AEAD primitive for an AEAD suite from a 32-byte key.
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
		return nil, fmt.Errorf("esp: suite %d is not an AEAD suite", suite)
	}
}

// OutSPI / InSPI expose the SA's SPIs for demux and DELETE.
func (sa *SA) OutSPI() uint32 { return sa.outSPI }
func (sa *SA) InSPI() uint32  { return sa.inSPI }

// Seq returns the last outbound sequence number used (for rekey heuristics).
func (sa *SA) Seq() uint32 { return sa.seq.Load() }

// Encrypt wraps one inner IP datagram (IPv4 or IPv6) in an ESP packet (RFC 4303
// tunnel mode). CBC framing: SPI | Seq | IV(16) | AES-CBC(inner | pad | padLen |
// nextHdr) | ICV(16). AEAD framing: SPI | Seq | IV(8) | AEAD(inner | pad |
// padLen | nextHdr) | Tag(16), with SPI | Seq as the associated data.
func (sa *SA) Encrypt(inner []byte) ([]byte, error) {
	// Allocate the next sequence number with a CAS loop so concurrent Encrypt
	// callers can never observe the same value: a two-step Add+Store could let a
	// second goroutine read the wrapped 0 before the pin lands. First packet is
	// sequence 1; 0 is never emitted, and once the counter reaches 2^32-1 it
	// stays pinned (exhausted) until the SA is replaced (RFC 4303 §3.3.3). For
	// the AEAD suites this uniqueness also guarantees the per-packet IV (= seq)
	// is never reused under one key.
	var seq uint32
	for {
		cur := sa.seq.Load()
		if cur == ^uint32(0) {
			return nil, ErrSeqExhausted
		}
		seq = cur + 1
		if sa.seq.CompareAndSwap(cur, seq) {
			break
		}
	}
	if sa.suite == SuiteAESCBC256SHA256 {
		return sa.encryptCBC(inner, seq)
	}
	return sa.encryptAEAD(inner, seq), nil
}

func (sa *SA) encryptCBC(inner []byte, seq uint32) ([]byte, error) {
	// RFC 4303 §2.4 padding: monotonic 1,2,3,... so that the plaintext
	// (inner | pad | padLen(1) | nextHdr(1)) is a multiple of the block size.
	padLen := (espBlock - (len(inner)+2)%espBlock) % espBlock
	plainLen := len(inner) + padLen + 2

	out := make([]byte, espHeaderLen+cbcIVLen+plainLen+espICVLen)
	binary.BigEndian.PutUint32(out[0:4], sa.outSPI)
	binary.BigEndian.PutUint32(out[4:8], seq)

	iv := out[espHeaderLen : espHeaderLen+cbcIVLen]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Assemble plaintext in place at the ciphertext position, then encrypt it.
	ctStart := espHeaderLen + cbcIVLen
	plain := out[ctStart : ctStart+plainLen]
	fillTrailer(plain, inner, padLen)
	cipher.NewCBCEncrypter(sa.outBlock, iv).CryptBlocks(plain, plain)

	// ICV over SPI | Seq | IV | ciphertext.
	mac := hmac.New(sha256.New, sa.outInteg)
	mac.Write(out[:ctStart+plainLen])
	icv := mac.Sum(nil)[:espICVLen]
	copy(out[ctStart+plainLen:], icv)
	return out, nil
}

func (sa *SA) encryptAEAD(inner []byte, seq uint32) []byte {
	// RFC 4303 §2.4: the trailer must align the payload to a 4-byte boundary;
	// the AEAD ciphers impose no block size of their own.
	padLen := (4 - (len(inner)+2)%4) % 4
	plainLen := len(inner) + padLen + 2

	out := make([]byte, espHeaderLen+aeadIVLen+plainLen+espICVLen)
	binary.BigEndian.PutUint32(out[0:4], sa.outSPI)
	binary.BigEndian.PutUint32(out[4:8], seq)
	// The per-packet IV is the sequence number widened to 64 bits: unique for
	// the SA's lifetime because the CAS loop in Encrypt never hands out a seq
	// twice and pins the counter at exhaustion. No random IV (an accidental
	// collision under GCM would forfeit authenticity) and no second counter to
	// keep in sync. RFC 4106 §3.1 explicitly permits a counter-based IV.
	binary.BigEndian.PutUint64(out[espHeaderLen:espHeaderLen+aeadIVLen], uint64(seq))

	var nonce [aeadSaltLen + aeadIVLen]byte
	copy(nonce[:aeadSaltLen], sa.outSalt)
	copy(nonce[aeadSaltLen:], out[espHeaderLen:espHeaderLen+aeadIVLen])

	// Assemble the plaintext in place at the ciphertext position, then seal it
	// in place (out already reserves the 16-byte tag past plain's length). The
	// associated data is SPI | Seq; the IV is NOT part of it (RFC 4106 §5).
	ctStart := espHeaderLen + aeadIVLen
	plain := out[ctStart : ctStart+plainLen]
	fillTrailer(plain, inner, padLen)
	sa.outAEAD.Seal(plain[:0], nonce[:], plain, out[:espHeaderLen])
	return out
}

// fillTrailer lays out the RFC 4303 §2.4 plaintext (inner | pad | padLen |
// nextHdr) into plain: monotonic 1,2,...,padLen pad octets, the pad length, and
// the Next Header derived from the inner packet's IP version.
func fillTrailer(plain, inner []byte, padLen int) {
	copy(plain, inner)
	for i := range padLen {
		plain[len(inner)+i] = byte(i + 1)
	}
	plain[len(plain)-2] = byte(padLen)
	plain[len(plain)-1] = nextHeaderFor(inner)
}

// nextHeaderFor maps the inner packet's IP version to the ESP Next Header
// (RFC 4303 tunnel mode): IPv6 (41) for a 0x6x datagram, IPv4 (4) otherwise.
// The peer's de-encapsulator routes the decrypted inner packet by this field,
// so a v6 datagram mislabeled as v4 is dropped at the far end (a one-way
// inner-IPv6 black hole).
func nextHeaderFor(inner []byte) byte {
	if len(inner) > 0 && inner[0]>>4 == 6 {
		return nextHeaderIPv6
	}
	return nextHeaderIPv4
}

// Decrypt verifies and decrypts an inbound ESP packet, returning the inner IP
// datagram (IPv4 or IPv6). The returned slice never aliases pkt.
func (sa *SA) Decrypt(pkt []byte) ([]byte, error) {
	if sa.suite == SuiteAESCBC256SHA256 {
		return sa.decryptCBC(pkt)
	}
	return sa.decryptAEAD(pkt)
}

func (sa *SA) decryptCBC(pkt []byte) ([]byte, error) {
	if len(pkt) < espHeaderLen+cbcIVLen+espBlock+espICVLen {
		return nil, errors.New("esp: packet too short")
	}
	if spi := binary.BigEndian.Uint32(pkt[0:4]); spi != sa.inSPI {
		return nil, fmt.Errorf("esp: unknown SPI %08x", spi)
	}
	seq := binary.BigEndian.Uint32(pkt[4:8])

	// Verify ICV before doing anything else with the contents.
	icvStart := len(pkt) - espICVLen
	mac := hmac.New(sha256.New, sa.inInteg)
	mac.Write(pkt[:icvStart])
	if !hmac.Equal(mac.Sum(nil)[:espICVLen], pkt[icvStart:]) {
		return nil, errors.New("esp: ICV verification failed")
	}
	if !sa.replay.Accept(seq) {
		return nil, ErrReplay
	}

	iv := pkt[espHeaderLen : espHeaderLen+cbcIVLen]
	ct := pkt[espHeaderLen+cbcIVLen : icvStart]
	if len(ct) == 0 || len(ct)%espBlock != 0 {
		return nil, errors.New("esp: ciphertext not block-aligned")
	}
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(sa.inBlock, iv).CryptBlocks(plain, ct)
	return parseTrailer(plain)
}

func (sa *SA) decryptAEAD(pkt []byte) ([]byte, error) {
	// Minimum: header, IV, the 2 mandatory trailer bytes, and the tag.
	if len(pkt) < espHeaderLen+aeadIVLen+2+espICVLen {
		return nil, errors.New("esp: packet too short")
	}
	if spi := binary.BigEndian.Uint32(pkt[0:4]); spi != sa.inSPI {
		return nil, fmt.Errorf("esp: unknown SPI %08x", spi)
	}
	seq := binary.BigEndian.Uint32(pkt[4:8])

	// Open authenticates the associated data (SPI | Seq), the ciphertext and
	// the tag in one pass; nothing about the packet is trusted before it
	// succeeds. Decrypt into a fresh buffer — pkt is the transport's lent
	// read buffer and must not back the returned datagram.
	var nonce [aeadSaltLen + aeadIVLen]byte
	copy(nonce[:aeadSaltLen], sa.inSalt)
	copy(nonce[aeadSaltLen:], pkt[espHeaderLen:espHeaderLen+aeadIVLen])
	plain, err := sa.inAEAD.Open(nil, nonce[:], pkt[espHeaderLen+aeadIVLen:], pkt[:espHeaderLen])
	if err != nil {
		return nil, errors.New("esp: AEAD authentication failed")
	}
	// The invariant "only authenticated packets move the replay window" holds:
	// Open verified the tag above.
	if !sa.replay.Accept(seq) {
		return nil, ErrReplay
	}
	return parseTrailer(plain)
}

// parseTrailer validates the decrypted RFC 4303 §2.4 trailer and returns the
// inner datagram (a sub-slice of plain, which both decrypt paths allocate
// fresh, so it never aliases the caller's packet buffer).
func parseTrailer(plain []byte) ([]byte, error) {
	if len(plain) < 2 {
		return nil, errors.New("esp: plaintext shorter than the ESP trailer")
	}
	padLen := int(plain[len(plain)-2])
	if padLen+2 > len(plain) {
		return nil, errors.New("esp: pad length out of range")
	}
	// RFC 4303 §2.4: the pad octets must be the monotonic sequence 1,2,...,padLen.
	// The ICV/tag verified before decryption already proves authenticity, so this
	// is a defense-in-depth / spec-conformance check against a buggy or tampering
	// (key-holding) sender rather than a guard against an unauthenticated attacker.
	for i, b := range plain[len(plain)-2-padLen : len(plain)-2] {
		if int(b) != i+1 {
			return nil, errors.New("esp: malformed self-describing padding")
		}
	}
	// plain[len-1] is NextHeader; for tunnel mode accept only IPv4 (4) and IPv6
	// (41) so a peer-controlled payload of any other protocol is rejected rather
	// than handed up to the netstack as if it were an IP datagram.
	if nh := plain[len(plain)-1]; nh != nextHeaderIPv4 && nh != nextHeaderIPv6 {
		return nil, fmt.Errorf("esp: unexpected next header %d", nh)
	}
	return plain[:len(plain)-padLen-2], nil
}
