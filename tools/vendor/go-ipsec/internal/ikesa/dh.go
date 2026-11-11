// Package ikesa implements the IKEv2 key schedule (RFC 7296 §2.14–2.17) and
// the SK{} authenticated-encryption envelope for the narrow transform set this
// client negotiates: DH Curve25519 (group 31) or MODP-2048 (group 14),
// PRF_HMAC_SHA2_256, ENCR_AES_CBC-256 and AUTH_HMAC_SHA2_256_128.
//
// It is hand-rolled on the standard library rather than vendored from an
// upstream IKE library because the candidate upstreams only ship the legacy
// HMAC-MD5/SHA1 primitives, while modern IKEv2-EAP responders negotiate the
// SHA2-256 suite above. Every primitive here is gated by an RFC known-answer
// test (see the package tests).
package ikesa

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/n0madic/go-ipsec/internal/legacycrypto"
	"math/big"

	"github.com/n0madic/go-ipsec/internal/secretmem"
)

// DH group identifiers from the IANA "Transform Type 4 - Diffie-Hellman Group
// Transform IDs" registry. The wire transform ID equals the group number.
const (
	DHGroup14 uint16 = 14 // 2048-bit MODP (RFC 3526 §3)
	DHGroup19 uint16 = 19 // NIST P-256 (RFC 5903)
	DHGroup20 uint16 = 20 // NIST P-384 (RFC 5903)
	DHGroup31 uint16 = 31 // Curve25519 / x25519 (RFC 8031, RFC 7748)
)

// x25519Len is the byte length of a Curve25519 public value and shared secret
// (RFC 7748).
const x25519Len = 32

// modp2048Hex is the 2048-bit MODP group prime from RFC 3526 §3 (group 14).
const modp2048Hex = "" +
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
	"15728E5A8AACAA68FFFFFFFFFFFFFFFF"

// modp2048Len is the byte length of the group modulus (2048 bits / 8). Public
// values and the shared secret are always this exact length, left-padded with
// zeros (RFC 7296 §2.14).
const modp2048Len = 256

var (
	modp2048P *big.Int
	modp2048G = big.NewInt(2)
	// pMinus2 bounds the private exponent to [2, p-2].
	modp2048PMinus2 *big.Int
)

func init() {
	var ok bool
	modp2048P, ok = new(big.Int).SetString(modp2048Hex, 16)
	if !ok {
		panic("ikesa: invalid MODP-2048 prime constant")
	}
	modp2048PMinus2 = new(big.Int).Sub(modp2048P, big.NewInt(2))
}

// DH is one side of an ephemeral Diffie-Hellman exchange. Group selects the
// primitive and holds exactly one of the two private keys.
type DH struct {
	// Group is the IANA DH-group transform ID (DHGroup14 or DHGroup31).
	Group uint16
	extra cryptoutil.DHGroup
	// Public is the local public value, ready to drop into a KE payload: g^priv
	// mod p left-padded to modp2048Len bytes for group 14, or the 32-byte
	// Curve25519 public for group 31.
	Public []byte

	privModp   *big.Int         // group 14 private exponent
	privX25519 *ecdh.PrivateKey // group 31 private key
}

// NewDH generates a fresh ephemeral key pair for the given DH group. Key
// generation runs inside secretmem.Do so the private key (and its temporaries)
// is runtime-tracked and erased once the DH is dropped after the exchange.
func NewDH(group uint16) (*DH, error) {
	var d *DH
	var err error
	secretmem.Do(func() { d, err = newDH(group) })
	return d, err
}

func newDH(group uint16) (*DH, error) {
	switch group {
	case 1, 2, 5, 15, 16, 17, 18, 21:
		extra, err := cryptoutil.NewGroup(group)
		if err != nil {
			return nil, err
		}
		pub, err := extra.Generate()
		if err != nil {
			return nil, err
		}
		return &DH{Group: group, extra: extra, Public: pub}, nil
	}
	switch group {
	case DHGroup14:
		// rand.Int yields [0, p-2); shift into [2, p-2].
		n, err := rand.Int(rand.Reader, new(big.Int).Sub(modp2048PMinus2, big.NewInt(1)))
		if err != nil {
			return nil, err
		}
		priv := n.Add(n, big.NewInt(2))
		pub := new(big.Int).Exp(modp2048G, priv, modp2048P)
		return &DH{Group: group, privModp: priv, Public: leftPad(pub.Bytes(), modp2048Len)}, nil
	case DHGroup31:
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return &DH{Group: group, privX25519: priv, Public: priv.PublicKey().Bytes()}, nil
	case DHGroup19, DHGroup20:
		curve := ecdh.P256()
		if group == DHGroup20 {
			curve = ecdh.P384()
		}
		priv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		// RFC 5903 transmits X || Y, without SEC1's uncompressed prefix.
		return &DH{Group: group, privX25519: priv, Public: priv.PublicKey().Bytes()[1:]}, nil
	default:
		return nil, fmt.Errorf("ikesa: unsupported DH group %d", group)
	}
}

// Shared computes the DH shared secret from the peer's public value, returned in
// the canonical wire form for the group: g^(priv·peer) mod p left-padded to
// modp2048Len bytes for group 14 (RFC 7296 §2.14), or the raw 32-byte Curve25519
// output for group 31 (RFC 7748). The computation runs inside secretmem.Do so
// the shared secret (and the exponentiation temporaries) is runtime-tracked
// and erased once dropped after key derivation.
func (d *DH) Shared(peerPublic []byte) ([]byte, error) {
	var shared []byte
	var err error
	secretmem.Do(func() { shared, err = d.shared(peerPublic) })
	return shared, err
}

func (d *DH) shared(peerPublic []byte) ([]byte, error) {
	if d.extra != nil {
		if len(peerPublic) != len(d.Public) {
			return nil, errors.New("ikesa: invalid DH public value length")
		}
		return d.extra.ComputeSecret(peerPublic)
	}
	switch d.Group {
	case DHGroup19, DHGroup20:
		curve := ecdh.P256()
		size := 64
		if d.Group == DHGroup20 {
			curve = ecdh.P384()
			size = 96
		}
		if len(peerPublic) != size {
			return nil, errors.New("ikesa: invalid ECP public value length")
		}
		public, err := curve.NewPublicKey(append([]byte{4}, peerPublic...))
		if err != nil {
			return nil, errors.New("ikesa: invalid ECP point")
		}
		return d.privX25519.ECDH(public)
	case DHGroup14:
		// A group-14 public is exactly the modulus length (RFC 7296 §2.14). Reject any
		// other length up front: a short/long KE would otherwise be SetBytes-parsed
		// into an in-range integer the peer never sent, yielding a shared secret that
		// silently disagrees with the peer's (mismatched KEYMAT → black-holed ESP).
		if len(peerPublic) != modp2048Len {
			return nil, errors.New("ikesa: peer DH public value wrong length")
		}
		peer := new(big.Int).SetBytes(peerPublic)
		// Reject degenerate peer values (0, 1, p-1, ≥p) that collapse the shared
		// secret to a small subgroup.
		if peer.Cmp(big.NewInt(1)) <= 0 || peer.Cmp(modp2048PMinus2) > 0 {
			return nil, errors.New("ikesa: peer DH public value out of range")
		}
		// big.Int.Exp does not document constant-time behaviour, so this is in
		// principle a timing side channel on the private exponent. Accepted for
		// the fallback group: the exponent is ephemeral (single handshake), and
		// the preferred path is x25519 via crypto/ecdh, which is constant-time.
		shared := new(big.Int).Exp(peer, d.privModp, modp2048P)
		return leftPad(shared.Bytes(), modp2048Len), nil
	case DHGroup31:
		// NewPublicKey enforces the 32-byte length; ECDH rejects the low-order points
		// that collapse the shared secret to all-zero (RFC 7748 §6.1).
		pub, err := ecdh.X25519().NewPublicKey(peerPublic)
		if err != nil {
			return nil, fmt.Errorf("ikesa: peer X25519 public value invalid: %w", err)
		}
		shared, err := d.privX25519.ECDH(pub)
		if err != nil {
			return nil, fmt.Errorf("ikesa: X25519 ECDH: %w", err)
		}
		return shared, nil
	default:
		return nil, fmt.Errorf("ikesa: unsupported DH group %d", d.Group)
	}
}

// leftPad returns b left-padded with zero bytes to exactly n bytes. b must not
// be longer than n.
func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}
