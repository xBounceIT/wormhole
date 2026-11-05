package auth

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/n0madic/go-ipsec/internal/secretmem"
)

// keyPad is the constant string mixed into shared-secret AUTH (RFC 7296 §2.15).
var keyPad = []byte("Key Pad for IKEv2")

// IKEv2 Authentication Method values (RFC 7296 §3.8, RFC 7427).
const (
	MethodRSADigitalSignature uint8 = 1
	MethodSharedKeyMIC        uint8 = 2
	MethodDSSDigitalSignature uint8 = 3
	MethodDigitalSignature    uint8 = 14 // RFC 7427
)

// PRF is the negotiated pseudorandom function, prf(key, data).
type PRF func(key, data []byte) []byte

// SignedOctets assembles the RFC 7296 §2.15 signed octets:
//
//	SignedOctets = RealMessage | PeerNonce | prf(macKey, IDPrime)
//
// realMessage is the verbatim IKE_SA_INIT datagram of the signer's side,
// peerNonce is the OTHER party's nonce data, idPrime is the signer's ID payload
// body (ID Type | RESERVED(3) | Identification Data), and macKey is SK_pi for
// the initiator or SK_pr for the responder.
func SignedOctets(prf PRF, realMessage, peerNonce, idPrime, macKey []byte) []byte {
	mac := prf(macKey, idPrime)
	out := make([]byte, 0, len(realMessage)+len(peerNonce)+len(mac))
	out = append(out, realMessage...)
	out = append(out, peerNonce...)
	out = append(out, mac...)
	return out
}

// SharedSecretAuth computes the RFC 7296 §2.15 shared-secret AUTH value — the
// "double-prf" construction shared by both authentication modes: with a
// pre-shared key the secret is the PSK, and with EAP the secret is the derived
// MSK (RFC 7296 §2.16 feeds the MSK into §2.15 as the shared secret):
//
//	AUTH = prf( prf(secret, "Key Pad for IKEv2"), SignedOctets )
//
// The computation runs inside secretmem.Do so the inner prf key (derived
// directly from the PSK or MSK) is runtime-tracked and erased once dropped.
// The returned AUTH value itself is wire data.
func SharedSecretAuth(prf PRF, secret, signedOctets []byte) []byte {
	var out []byte
	secretmem.Do(func() {
		inner := prf(secret, keyPad)
		out = prf(inner, signedOctets)
	})
	return out
}

// VerifyCertAuth verifies the responder's certificate-based AUTH payload
// (message 4) over its signed octets using the leaf certificate's public key.
// It supports the legacy RSA Digital Signature method (1) and the RFC 7427
// Digital Signature method (14, RSA-PKCS1v15 / RSA-PSS / ECDSA). SHA-1 RSA
// signatures are accepted: many deployed gateways still sign IKE_AUTH with SHA-1,
// and the certificate chain is verified independently while the signed octets
// carry fresh nonces.
func VerifyCertAuth(method uint8, authData, signedOctets []byte, leaf *x509.Certificate) error {
	switch method {
	case MethodRSADigitalSignature:
		// RFC 7296 §3.8: RSASSA-PKCS1-v1_5 with SHA-1.
		return leaf.CheckSignature(x509.SHA1WithRSA, signedOctets, authData)
	case MethodDigitalSignature:
		algo, sig, err := parseRFC7427(authData)
		if err != nil {
			return err
		}
		return leaf.CheckSignature(algo, signedOctets, sig)
	default:
		return fmt.Errorf("auth: unsupported responder AUTH method %d", method)
	}
}

// parseRFC7427 decodes an RFC 7427 Digital Signature AUTH payload into an
// x509.SignatureAlgorithm and the raw signature.
//
//	authData = ASN.1Length(1) | AlgorithmIdentifier(DER) | Signature
func parseRFC7427(authData []byte) (x509.SignatureAlgorithm, []byte, error) {
	if len(authData) < 1 {
		return 0, nil, errors.New("auth: empty RFC 7427 AUTH data")
	}
	algoLen := int(authData[0])
	if 1+algoLen > len(authData) {
		return 0, nil, errors.New("auth: RFC 7427 AlgorithmIdentifier length overflows AUTH data")
	}
	algoDER := authData[1 : 1+algoLen]
	sig := authData[1+algoLen:]
	if len(sig) == 0 {
		return 0, nil, errors.New("auth: RFC 7427 AUTH has empty signature")
	}

	var ai algorithmIdentifier
	if _, err := asn1.Unmarshal(algoDER, &ai); err != nil {
		return 0, nil, fmt.Errorf("auth: parse RFC 7427 AlgorithmIdentifier: %w", err)
	}
	algo := oidToSignatureAlgorithm(ai)
	if algo == x509.UnknownSignatureAlgorithm {
		return 0, nil, fmt.Errorf("auth: unsupported RFC 7427 signature OID %v", ai.Algorithm)
	}
	return algo, sig, nil
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

var (
	oidSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// oidToSignatureAlgorithm maps an RFC 7427 AlgorithmIdentifier to a Go
// signature algorithm. RSASSA-PSS carries the hash in its parameters.
func oidToSignatureAlgorithm(ai algorithmIdentifier) x509.SignatureAlgorithm {
	switch {
	case ai.Algorithm.Equal(oidSHA1WithRSA):
		return x509.SHA1WithRSA
	case ai.Algorithm.Equal(oidSHA256WithRSA):
		return x509.SHA256WithRSA
	case ai.Algorithm.Equal(oidSHA384WithRSA):
		return x509.SHA384WithRSA
	case ai.Algorithm.Equal(oidSHA512WithRSA):
		return x509.SHA512WithRSA
	case ai.Algorithm.Equal(oidECDSAWithSHA256):
		return x509.ECDSAWithSHA256
	case ai.Algorithm.Equal(oidECDSAWithSHA384):
		return x509.ECDSAWithSHA384
	case ai.Algorithm.Equal(oidECDSAWithSHA512):
		return x509.ECDSAWithSHA512
	case ai.Algorithm.Equal(oidRSAPSS):
		return rsaPSSHash(ai.Parameters)
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

// rsaPSSHash extracts the hash algorithm from RSASSA-PSS parameters and maps it
// to the corresponding Go PSS signature algorithm.
func rsaPSSHash(params asn1.RawValue) x509.SignatureAlgorithm {
	if len(params.FullBytes) == 0 {
		return x509.SHA256WithRSAPSS // default per RFC 4055 is SHA-1, but strongSwan uses SHA-256+
	}
	var p pssParameters
	if _, err := asn1.Unmarshal(params.FullBytes, &p); err != nil {
		return x509.UnknownSignatureAlgorithm
	}
	switch {
	case p.Hash.Algorithm.Equal(oidSHA256):
		return x509.SHA256WithRSAPSS
	case p.Hash.Algorithm.Equal(oidSHA384):
		return x509.SHA384WithRSAPSS
	case p.Hash.Algorithm.Equal(oidSHA512):
		return x509.SHA512WithRSAPSS
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

type pssParameters struct {
	Hash         algorithmIdentifier `asn1:"explicit,tag:0,optional"`
	MGF          algorithmIdentifier `asn1:"explicit,tag:1,optional"`
	SaltLength   int                 `asn1:"explicit,tag:2,optional"`
	TrailerField int                 `asn1:"explicit,tag:3,optional,default:1"`
}
