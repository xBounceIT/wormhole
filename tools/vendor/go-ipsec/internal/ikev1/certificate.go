package ikev1

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/n0madic/go-ipsec/internal/auth"
)

func (s *Session) findAuthentication(payloads []payload) (payload, bool) {
	if s.cfg.Certificate != nil {
		return findPayload(payloads, 9)
	}
	return findPayload(payloads, payloadHash)
}

func (s *Session) authenticationPayloads(hash []byte) ([]payload, error) {
	if s.cfg.Certificate == nil {
		return []payload{{typ: payloadHash, body: hash}}, nil
	}
	key, ok := s.cfg.Certificate.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("IKEv1 requires an RSA client certificate")
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, 0, hash)
	if err != nil {
		return nil, err
	}
	var out []payload
	for _, cert := range s.cfg.Certificate.Certificate {
		out = append(out, payload{typ: 6, body: append([]byte{4}, cert...)})
	}
	out = append(out, payload{typ: 9, body: signature})
	return out, nil
}

func (s *Session) verifyAuthentication(payloads []payload, want, proof []byte) error {
	if s.cfg.Role == Initiator && (s.cfg.RemoteIDType != 0 || len(s.cfg.RemoteIDData) != 0) {
		id := s.idR
		if len(id) < 4 || s.cfg.RemoteIDType == 0 || id[0] != s.cfg.RemoteIDType || !constEq(id[4:], s.cfg.RemoteIDData) {
			return fmt.Errorf("%w: remote identity mismatch", ErrAuth)
		}
	}
	if s.cfg.Certificate == nil {
		if !constEq(want, proof) {
			return fmt.Errorf("%w: peer PSK proof failed", ErrAuth)
		}
		return nil
	}
	var certs [][]byte
	for _, p := range payloads {
		if p.typ == 6 && len(p.body) > 1 && p.body[0] == 4 {
			certs = append(certs, p.body[1:])
		}
	}
	leaf, err := auth.VerifyServerChain(certs, s.cfg.RootCAs, s.peerName(), time.Now())
	if err != nil {
		return fmt.Errorf("%w: peer certificate rejected", ErrAuth)
	}
	key, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok || rsa.VerifyPKCS1v15(key, 0, want, proof) != nil {
		return fmt.Errorf("%w: peer signature rejected", ErrAuth)
	}
	return nil
}

// Preserve the configured wire type when matching certificate identities.
// Opaque or malformed identities cannot downgrade to chain-only trust.
func (s *Session) peerName() auth.PeerName {
	data := s.cfg.RemoteIDData
	switch s.cfg.RemoteIDType {
	case 2:
		if len(data) > 0 {
			return auth.PeerName{DNS: string(data)}
		}
	case 3:
		if len(data) > 0 {
			return auth.PeerName{Email: string(data)}
		}
	case 1, 5:
		if ip, ok := netip.AddrFromSlice(data); ok && ((s.cfg.RemoteIDType == 1 && ip.Is4()) || (s.cfg.RemoteIDType == 5 && ip.Is6() && !ip.Is4In6())) {
			return auth.PeerName{IP: ip}
		}
	case 9:
		if len(data) > 0 {
			return auth.PeerName{DN: data}
		}
	}
	return auth.PeerName{Unverifiable: s.cfg.RemoteIDType != 0 || len(data) != 0}
}
