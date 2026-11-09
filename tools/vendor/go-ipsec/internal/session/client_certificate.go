package session

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/asn1"
	"errors"

	"github.com/n0madic/go-ipsec/internal/auth"
	"github.com/n0madic/go-ipsec/internal/ikemsg"
)

func (s *Session) ikeAuthCertificate(ctx context.Context) error {
	spi, err := s.allocChildSPI()
	if err != nil {
		return err
	}
	method, signature, err := signClientCertificate(s.cfg.ClientCertificate.PrivateKey, s.initiatorSignedOctets())
	if err != nil {
		return err
	}
	first := ikemsg.Payloads{&ikemsg.IDiPayload{IDType: ikemsg.IDType(s.cfg.LocalID.Type), Data: s.cfg.LocalID.Data}}
	for _, cert := range s.cfg.ClientCertificate.Certificate {
		first = append(first, &ikemsg.CertPayload{Encoding: 4, Data: cert})
	}
	first = append(first, &ikemsg.AuthPayload{Method: method, Data: signature}, &ikemsg.SAPayload{Proposals: buildProposals(spi, s.enabledESPSuites())})
	appendTrafficSelectors(&first, s.cfg.RequestIPv6)
	buildCPRequest(&first, s.cfg.RequestIPv6)
	response, err := s.exchangeSK(ctx, ikemsg.ExchangeIKEAuth, s.messageID, first)
	if err != nil {
		return err
	}
	s.messageID++
	return s.handleFinalAuthResponse(response, nil)
}

func signClientCertificate(key any, message []byte) (uint8, []byte, error) {
	switch private := key.(type) {
	case *rsa.PrivateKey:
		digest := sha1.Sum(message)
		signature, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA1, digest[:])
		return auth.MethodRSADigitalSignature, signature, err
	case *ecdsa.PrivateKey:
		digest := sha256.Sum256(message)
		signature, err := ecdsa.SignASN1(rand.Reader, private, digest[:])
		if err != nil {
			return 0, nil, err
		}
		algorithm, _ := asn1.Marshal(struct{ OID asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}})
		return auth.MethodDigitalSignature, append(append([]byte{byte(len(algorithm))}, algorithm...), signature...), nil
	default:
		return 0, nil, errors.New("unsupported IPsec certificate private key")
	}
}
