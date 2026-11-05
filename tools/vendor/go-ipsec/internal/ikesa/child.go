package ikesa

import "github.com/n0madic/go-ipsec/internal/secretmem"

// ChildKeys holds the directional ESP key material for one Child SA. Names are
// from the initiator's point of view: the "I→R" pair is what this client uses
// to protect outbound packets, the "R→I" pair what it uses to verify and
// decrypt inbound packets.
type ChildKeys struct {
	EncrIR  []byte // ESP encryption key, initiator → responder (outbound)
	IntegIR []byte // ESP integrity key, initiator → responder (outbound)
	EncrRI  []byte // ESP encryption key, responder → initiator (inbound)
	IntegRI []byte // ESP integrity key, responder → initiator (inbound)
}

// DeriveChildKeys produces the Child SA key material created without a separate
// DH exchange (IKE_AUTH, or a non-PFS CREATE_CHILD_SA rekey), per RFC 7296 §2.17:
//
//	KEYMAT = prf+(SK_d, Ni | Nr)
//
// split in order into the initiator's encryption/integrity keys followed by the
// responder's. encrLen and integLen are the negotiated ESP key lengths (32 and
// 32 for AES-CBC-256 + HMAC-SHA2-256-128).
func (s *IKESA) DeriveChildKeys(nonceI, nonceR []byte, encrLen, integLen int) ChildKeys {
	return s.deriveChildKeys(nil, nonceI, nonceR, encrLen, integLen)
}

// DeriveChildKeysPFS produces the Child SA key material for a CREATE_CHILD_SA
// rekey that performed a fresh ephemeral Diffie-Hellman exchange (PFS), per RFC
// 7296 §2.17:
//
//	KEYMAT = prf+(SK_d, g^ir (new) | Ni | Nr)
//
// where dhShared is the new DH shared secret (g^ir, big-endian, zero-padded to
// the modulus length). It differs from DeriveChildKeys only by prepending
// dhShared to the prf+ seed.
func (s *IKESA) DeriveChildKeysPFS(dhShared, nonceI, nonceR []byte, encrLen, integLen int) ChildKeys {
	return s.deriveChildKeys(dhShared, nonceI, nonceR, encrLen, integLen)
}

// deriveChildKeys is the shared KEYMAT expansion. dhShared is prepended to the
// prf+ seed for PFS and is nil (a no-op append) for the non-PFS case. It runs
// inside secretmem.Do so the ESP key buffers (and the KEYMAT intermediate) are
// runtime-tracked and erased once the Child SA is dropped on rekey or teardown.
func (s *IKESA) deriveChildKeys(dhShared, nonceI, nonceR []byte, encrLen, integLen int) ChildKeys {
	var ck ChildKeys
	secretmem.Do(func() {
		seed := make([]byte, 0, len(dhShared)+len(nonceI)+len(nonceR))
		seed = append(seed, dhShared...)
		seed = append(seed, nonceI...)
		seed = append(seed, nonceR...)
		ks := prfPlus(s.SKd, seed, 2*(encrLen+integLen))

		var off int
		take := func(n int) []byte {
			b := make([]byte, n)
			copy(b, ks[off:off+n])
			off += n
			return b
		}
		ck = ChildKeys{
			EncrIR:  take(encrLen),
			IntegIR: take(integLen),
			EncrRI:  take(encrLen),
			IntegRI: take(integLen),
		}
	})
	return ck
}
