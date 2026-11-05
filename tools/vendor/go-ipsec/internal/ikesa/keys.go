package ikesa

import (
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/n0madic/go-ipsec/internal/secretmem"
)

// Role identifies which end of the IKE SA this client plays. go-ipsec is
// initiator-only, but the role still selects the correct directional keys and
// makes the encrypt/decrypt round-trip testable from both ends.
type Role int

const (
	Initiator Role = iota
	Responder
)

// Suite identifies the SK{} envelope transform suite the IKE SA runs. The zero
// value is the classic AES-CBC-256 + HMAC-SHA2-256-128 suite, so pre-suite
// constructions keep their meaning. The PRF is PRF_HMAC_SHA2_256 for every
// suite (it also drives the AUTH signed octets and the SKEYSEED schedule).
type Suite uint8

const (
	// SuiteAESCBC256SHA256 is AES-CBC-256 encryption with HMAC-SHA2-256-128
	// integrity (RFC 7296 baseline). SK_e* = 32 bytes, SK_a* = 32 bytes.
	SuiteAESCBC256SHA256 Suite = iota
	// SuiteAESGCM256 is AES-GCM-256 with a 16-octet ICV in the SK{} envelope
	// (RFC 5282). SK_e* = 36 bytes (32-byte key + 4-byte salt), no SK_a*.
	SuiteAESGCM256
	// SuiteChaCha20Poly1305 is ChaCha20-Poly1305 in the SK{} envelope
	// (RFC 5282 + RFC 7634). SK_e* = 36 bytes (key + salt), no SK_a*.
	SuiteChaCha20Poly1305
)

// String implements fmt.Stringer with the conventional (strongSwan-style)
// transform names, matching esp.Suite for consistent diagnostics.
func (s Suite) String() string {
	switch s {
	case SuiteAESCBC256SHA256:
		return "aes256-sha256"
	case SuiteAESGCM256:
		return "aes256gcm16"
	case SuiteChaCha20Poly1305:
		return "chacha20poly1305"
	default:
		return fmt.Sprintf("ike-suite-%d", uint8(s))
	}
}

// aead reports whether the suite is a combined-mode (AEAD) cipher.
func (s Suite) aead() bool {
	return s == SuiteAESGCM256 || s == SuiteChaCha20Poly1305
}

// keyLens returns the suite's SK_e*/SK_a* lengths for the RFC 7296 §2.14 /
// RFC 5282 §7 key schedule: an AEAD SK_e* includes the trailing 4-byte salt
// and SK_a* is absent (zero bytes are taken from the prf+ stream).
func (s Suite) keyLens() (encr, integ int) {
	if s.aead() {
		return aeadEncrKeyLen, 0
	}
	return encrKeyLen, integKeyLen
}

// minNonceLen is the RFC 7296 §2.10 floor: nonces must be at least 128 bits
// and at least half the key size of the negotiated PRF (16 bytes for
// PRF_HMAC_SHA2_256, the only PRF this client offers). A shorter peer nonce
// weakens the freshness the nonces contribute to SKEYSEED and the AUTH signed
// octets, so key derivation fails closed on it.
const minNonceLen = 16

// IKESA holds the derived IKE SA key material and the directional crypto state
// for the SK{} envelope.
type IKESA struct {
	Role         Role
	Suite        Suite
	InitiatorSPI uint64
	ResponderSPI uint64

	SKd  []byte // child-SA key-derivation key
	SKai []byte // integrity, initiator → responder (empty for AEAD suites)
	SKar []byte // integrity, responder → initiator (empty for AEAD suites)
	SKei []byte // encryption, initiator → responder (key | salt for AEAD)
	SKer []byte // encryption, responder → initiator (key | salt for AEAD)
	SKpi []byte // AUTH, initiator
	SKpr []byte // AUTH, responder

	// Directional AEAD state (AEAD suites only), oriented by Role at
	// derivation time: out* protects what we send, in* opens what we receive.
	outAEAD cipher.AEAD
	inAEAD  cipher.AEAD
	outSalt []byte
	inSalt  []byte

	// skSeq is the outbound SK{} IV counter. AEAD nonce uniqueness rides on two
	// invariants: every EncryptToSK burns a fresh counter value, and encoded
	// messages are never re-encoded (retransmits resend the cached bytes).
	skSeq atomic.Uint64
}

// Derive runs the RFC 7296 §2.14 key schedule:
//
//	SKEYSEED = prf(Ni | Nr, g^ir)
//	{SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr}
//	        = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)
//
// suite selects the negotiated SK{} envelope transform (it fixes the SK_e*/
// SK_a* lengths per RFC 5282 §7). nonceI/nonceR are the initiator/responder
// nonces, dhShared the DH shared secret, and spii/spir the negotiated SPIs.
func (s *IKESA) Derive(suite Suite, role Role, spii, spir uint64, nonceI, nonceR, dhShared []byte) error {
	if len(nonceI) < minNonceLen || len(nonceR) < minNonceLen {
		return errors.New("ikesa: nonce shorter than the RFC 7296 §2.10 minimum of 16 bytes")
	}
	if len(dhShared) == 0 {
		return errors.New("ikesa: empty DH shared secret")
	}
	// Derive inside secretmem.Do: the SK_* buffers (the SKEYSEED intermediate,
	// and the AEAD key schedules built from them) are then runtime-tracked and
	// erased once this IKESA is dropped on rekey or teardown (see
	// internal/secretmem).
	var derr error
	secretmem.Do(func() {
		// Initial SKEYSEED = prf(Ni | Nr, g^ir) (RFC 7296 §2.14).
		skeyseed := prf(concat(nonceI, nonceR), dhShared)
		derr = s.deriveFromSKEYSEED(suite, role, spii, spir, nonceI, nonceR, skeyseed)
	})
	return derr
}

// DeriveRekeyIKE derives a new IKE SA during a CREATE_CHILD_SA IKE-SA rekey
// (RFC 7296 §2.18):
//
//	SKEYSEED = prf(SK_d (old SA), g^ir (new) | Ni | Nr)
//	{SK_d | ... | SK_pr} = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)   (new SPIs)
//
// suite is the suite negotiated for the NEW SA (a rekey may change it) and
// oldSKd the SK_d of the IKE SA being rekeyed.
func DeriveRekeyIKE(suite Suite, oldSKd []byte, role Role, spii, spir uint64, nonceI, nonceR, dhShared []byte) (*IKESA, error) {
	if len(oldSKd) == 0 {
		return nil, errors.New("ikesa: empty old SK_d")
	}
	if len(nonceI) < minNonceLen || len(nonceR) < minNonceLen {
		return nil, errors.New("ikesa: rekey nonce shorter than the RFC 7296 §2.10 minimum of 16 bytes")
	}
	if len(dhShared) == 0 {
		return nil, errors.New("ikesa: empty rekey DH shared secret")
	}
	var s *IKESA
	var derr error
	secretmem.Do(func() {
		seed := make([]byte, 0, len(dhShared)+len(nonceI)+len(nonceR))
		seed = append(seed, dhShared...)
		seed = append(seed, nonceI...)
		seed = append(seed, nonceR...)
		skeyseed := prf(oldSKd, seed)

		s = &IKESA{}
		derr = s.deriveFromSKEYSEED(suite, role, spii, spir, nonceI, nonceR, skeyseed)
	})
	if derr != nil {
		return nil, derr
	}
	return s, nil
}

// deriveFromSKEYSEED expands SKEYSEED into the SK_* set and builds the
// directional AEAD state, shared by the initial and rekey derivations. It must
// run inside secretmem.Do (both callers guarantee that).
func (s *IKESA) deriveFromSKEYSEED(suite Suite, role Role, spii, spir uint64, nonceI, nonceR, skeyseed []byte) error {
	s.Suite = suite
	s.Role = role
	s.InitiatorSPI = spii
	s.ResponderSPI = spir

	seed := make([]byte, 0, len(nonceI)+len(nonceR)+16)
	seed = append(seed, nonceI...)
	seed = append(seed, nonceR...)
	seed = appendUint64(seed, spii)
	seed = appendUint64(seed, spir)

	encrLen, integLen := suite.keyLens()
	total := prfKeyLen + 2*integLen + 2*encrLen + 2*prfKeyLen
	ks := prfPlus(skeyseed, seed, total)

	var off int
	// Copy each key into its own slice rather than aliasing the shared prf+
	// output buffer, so an in-place mutation of one key can never corrupt an
	// adjacent one (mirrors DeriveChildKeys in child.go).
	take := func(n int) []byte {
		b := make([]byte, n)
		copy(b, ks[off:off+n])
		off += n
		return b
	}
	s.SKd = take(prfKeyLen)
	s.SKai = take(integLen)
	s.SKar = take(integLen)
	s.SKei = take(encrLen)
	s.SKer = take(encrLen)
	s.SKpi = take(prfKeyLen)
	s.SKpr = take(prfKeyLen)

	if !suite.aead() {
		return nil
	}
	// AEAD SK_e* = key(32) | salt(4) with the salt at the END (RFC 5282
	// §7.1/§7.4, RFC 7634 §3). Building the primitives here keeps their key
	// schedules inside the caller's secretmem.Do.
	out, in := s.outboundEncrKey(), s.inboundEncrKey()
	var err error
	if s.outAEAD, err = newAEAD(suite, out[:encrLen-aeadSaltLen]); err != nil {
		return fmt.Errorf("ikesa: outbound SK cipher: %w", err)
	}
	if s.inAEAD, err = newAEAD(suite, in[:encrLen-aeadSaltLen]); err != nil {
		return fmt.Errorf("ikesa: inbound SK cipher: %w", err)
	}
	s.outSalt = append([]byte(nil), out[encrLen-aeadSaltLen:]...)
	s.inSalt = append([]byte(nil), in[encrLen-aeadSaltLen:]...)
	return nil
}

// outboundIntegKey / inboundIntegKey / outboundEncrKey / inboundEncrKey select
// the directional key for this role.
func (s *IKESA) outboundIntegKey() []byte {
	if s.Role == Initiator {
		return s.SKai
	}
	return s.SKar
}

func (s *IKESA) inboundIntegKey() []byte {
	if s.Role == Initiator {
		return s.SKar
	}
	return s.SKai
}

func (s *IKESA) outboundEncrKey() []byte {
	if s.Role == Initiator {
		return s.SKei
	}
	return s.SKer
}

func (s *IKESA) inboundEncrKey() []byte {
	if s.Role == Initiator {
		return s.SKer
	}
	return s.SKei
}

// EncryptToSK prepares the body of an Encrypted (SK{}) payload for plaintext
// (the concatenated inner IKE payloads). The body is a placeholder to be
// completed by FinalizeSK on the fully encoded message:
//
//	CBC:  IV(16) | AES-CBC(plaintext | pad | padLen) | zeroed ICV(16)
//	AEAD: IV(8)  | plaintext | padLen(=0)            | zeroed tag(16)
//
// The AEAD IV comes from a monotonic counter: an SK{} message is encoded
// exactly once (retransmits resend the cached bytes), so the counter both
// numbers and uniquifies every nonce; a random IV would risk collision under
// GCM. RFC 5282 §3 needs no block alignment, so we send an empty pad with a
// zero Pad Length octet.
func (s *IKESA) EncryptToSK(plaintext []byte) ([]byte, error) {
	if s.Suite.aead() {
		seq := s.skSeq.Add(1)
		body := make([]byte, aeadIVLen+len(plaintext)+1+aeadTagLen)
		binary.BigEndian.PutUint64(body[:aeadIVLen], seq)
		copy(body[aeadIVLen:], plaintext)
		return body, nil
	}
	// RFC 7296 §3.14 self-describing padding: append padLen pad octets then a
	// one-octet Pad Length, making the total a multiple of the block size.
	padLen := (aesBlock - (len(plaintext)+1)%aesBlock) % aesBlock
	padded := make([]byte, 0, len(plaintext)+padLen+1)
	padded = append(padded, plaintext...)
	for i := 1; i <= padLen; i++ {
		padded = append(padded, byte(i))
	}
	padded = append(padded, byte(padLen))

	ivCT, err := aesCBCEncrypt(s.outboundEncrKey(), padded)
	if err != nil {
		return nil, err
	}
	return append(ivCT, make([]byte, integICVLen)...), nil
}

// FinalizeSK completes the SK{} protection of a fully encoded message whose
// LAST skDataLen bytes are the Encrypted-payload body EncryptToSK produced
// (the SK payload must be the last payload — RFC 7296 §3.14). For the CBC
// suite it computes the trailing HMAC ICV and patches it in place. For an AEAD
// suite it seals the plaintext in place per RFC 5282 §5.1: the associated data
// is everything from the first octet of the IKE header through the last octet
// of the SK generic header (the IV is NOT part of the AAD), and the nonce is
// salt(4) | IV(8). Call it exactly once per encoded message.
func (s *IKESA) FinalizeSK(raw []byte, skDataLen int) error {
	if !s.Suite.aead() {
		return s.checksum(raw)
	}
	skStart := len(raw) - skDataLen
	if skStart < ikeHdrLen+genericHdrLen || skDataLen < aeadIVLen+1+aeadTagLen {
		return errors.New("ikesa: SK message too short to finalize")
	}
	nonce := make([]byte, 0, aeadSaltLen+aeadIVLen)
	nonce = append(nonce, s.outSalt...)
	nonce = append(nonce, raw[skStart:skStart+aeadIVLen]...)
	pt := raw[skStart+aeadIVLen : len(raw)-aeadTagLen]
	// In-place Seal: dst reuses the plaintext's storage; ciphertext plus the
	// 16-byte tag exactly fill the remainder of raw.
	s.outAEAD.Seal(pt[:0], nonce, pt, raw[:skStart])
	return nil
}

// OpenSK verifies and decrypts an inbound SK{} message. raw is the full
// datagram and skData the Encrypted-payload body, which must be the trailing
// bytes of raw (RFC 7296 §3.14 mandates the SK payload be last; a datagram
// violating that yields a wrong AAD and fails authentication — fail closed).
// icvOK=false reports an integrity failure, meaning the caller may retry the
// datagram under a different (superseded) IKE SA; errors after successful
// authentication return icvOK=true.
func (s *IKESA) OpenSK(raw, skData []byte) (plaintext []byte, icvOK bool, err error) {
	if s.Suite.aead() {
		skStart := len(raw) - len(skData)
		if skStart < ikeHdrLen+genericHdrLen || len(skData) < aeadIVLen+1+aeadTagLen {
			return nil, false, errors.New("ikesa: SK payload too short")
		}
		nonce := make([]byte, 0, aeadSaltLen+aeadIVLen)
		nonce = append(nonce, s.inSalt...)
		nonce = append(nonce, skData[:aeadIVLen]...)
		padded, oerr := s.inAEAD.Open(nil, nonce, skData[aeadIVLen:], raw[:skStart])
		if oerr != nil {
			return nil, false, errors.New("ikesa: SK message AEAD authentication failed")
		}
		// Strip the RFC 5282 §3 trailer: a Pad Length octet preceded by that
		// many pad octets. We always send padLen=0, but a peer MAY pad.
		padLen := int(padded[len(padded)-1])
		if padLen+1 > len(padded) {
			return nil, true, errors.New("ikesa: SK pad length out of range")
		}
		return padded[:len(padded)-padLen-1], true, nil
	}
	if !s.verifyChecksum(raw) {
		return nil, false, errors.New("ikesa: SK message ICV verification failed")
	}
	pt, derr := s.decryptSK(skData)
	if derr != nil {
		return nil, true, derr
	}
	return pt, true, nil
}

// decryptSK reverses the CBC branch of EncryptToSK for an inbound SK{} body.
// OpenSK verifies the message ICV before calling this.
func (s *IKESA) decryptSK(skData []byte) ([]byte, error) {
	if len(skData) < integICVLen+aesBlock {
		return nil, errors.New("ikesa: SK payload too short")
	}
	ivCT := skData[:len(skData)-integICVLen]
	padded, err := aesCBCDecrypt(s.inboundEncrKey(), ivCT)
	if err != nil {
		return nil, err
	}
	padLen := int(padded[len(padded)-1])
	if padLen+1 > len(padded) {
		return nil, errors.New("ikesa: SK pad length out of range")
	}
	return padded[:len(padded)-padLen-1], nil
}

// checksum computes the CBC-suite message ICV over msg[:len-ICV] with the
// outbound integrity key and writes it into the trailing ICV bytes in place.
func (s *IKESA) checksum(msg []byte) error {
	if len(msg) < integICVLen {
		return errors.New("ikesa: message shorter than ICV")
	}
	mac := integ(s.outboundIntegKey(), msg[:len(msg)-integICVLen])
	copy(msg[len(msg)-integICVLen:], mac)
	return nil
}

// verifyChecksum recomputes the CBC-suite ICV over an inbound message with the
// inbound integrity key and constant-time compares it to the trailing ICV.
func (s *IKESA) verifyChecksum(msg []byte) bool {
	if len(msg) < integICVLen {
		return false
	}
	want := msg[len(msg)-integICVLen:]
	got := integ(s.inboundIntegKey(), msg[:len(msg)-integICVLen])
	return hmac.Equal(want, got)
}

// PRF exposes the negotiated PRF for the AUTH machinery (signed octets).
func (s *IKESA) PRF(key, data []byte) []byte { return prf(key, data) }

// concat returns a || b in a fresh slice.
func concat(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return out
}

func appendUint64(b []byte, v uint64) []byte {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], v)
	return append(b, tmp[:]...)
}
