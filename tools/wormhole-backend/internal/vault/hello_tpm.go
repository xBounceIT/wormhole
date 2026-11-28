package vault

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"slices"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// Windows Platform Crypto Provider's key attestation container contains a TPM
// certify statement, an AIK signature and a PCP key blob with the TPM public area.
const (
	pcpAttestationHeader = 24
	pcpKeyHeader         = 52
	pcpTPM20             = 2
	tpmRSA               = 0x0001
	tpmSHA256            = 0x000b
	tpmNull              = 0x0010
	tpmRSASSA            = 0x0014
	tpmGenerated         = 0xff544347
	tpmCertify           = 0x8017
	// The object was generated in, remains bound to, and supports signing in the TPM.
	tpmFixedSigningKey = 0x00000002 | 0x00000010 | 0x00000020 | 0x00040000
)

var aikCertificateUsage = asn1.ObjectIdentifier{2, 23, 133, 8, 3}

// VerifyHelloTPMAttestation accepts a TPM 2.0 PCP proof only when a trusted
// attestation identity key certified the exact non-migratable signing key.
// Roots must come from attestation policy, never the supplied certificate chain.
// This is hardware key attestation, with no claim about the boot state.
func VerifyHelloTPMAttestation(proof []byte, certificates []*x509.Certificate, roots *x509.CertPool, public *rsa.PublicKey, now time.Time) error {
	if roots == nil || !rsa2048(public) || now.IsZero() || len(certificates) < 1 || len(certificates) > 8 {
		return ErrFormat
	}
	statement, signature, area, err := parseHelloTPMProof(proof)
	if err != nil {
		return err
	}
	if err := checkHelloTPMKey(area, public); err != nil {
		return err
	}
	if err := checkHelloTPMCertify(statement, area); err != nil {
		return err
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certificates {
		if cert == nil {
			return ErrFormat
		}
		if cert.IsCA {
			intermediates.AddCert(cert)
		}
	}
	digest := sha256.Sum256(statement)
	for _, cert := range certificates {
		key, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok || !rsa2048(key) || key.Equal(public) || cert.IsCA || !hasAIKUsage(cert) ||
			cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
			rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
			continue
		}
		chains, err := cert.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: intermediates, CurrentTime: now,
			// Go represents the TPM AIK usage as an unknown EKU. Apply it explicitly.
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err == nil && slices.ContainsFunc(chains, permitsAIKChain) {
			return nil
		}
	}
	return ErrAuthentication
}

func rsa2048(key *rsa.PublicKey) bool {
	return key != nil && key.N != nil && key.N.Sign() == 1 && key.N.BitLen() == 2048 && key.E == 65537
}

func hasAIKUsage(cert *x509.Certificate) bool {
	return slices.ContainsFunc(cert.UnknownExtKeyUsage, aikCertificateUsage.Equal)
}

func permitsAIKChain(chain []*x509.Certificate) bool {
	// A root that is also the leaf is not an attestation issuer. Honor issuer EKU
	// restrictions even though the verifier above had to select ExtKeyUsageAny.
	if len(chain) < 2 {
		return false
	}
	for _, cert := range chain[1:] {
		if len(cert.ExtKeyUsage)+len(cert.UnknownExtKeyUsage) != 0 &&
			!slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageAny) && !hasAIKUsage(cert) {
			return false
		}
	}
	return true
}

func parseHelloTPMProof(proof []byte) (statement, signature, area []byte, err error) {
	if len(proof) < pcpAttestationHeader || len(proof) > 1<<20 || string(proof[:4]) != "KADS" ||
		binary.LittleEndian.Uint32(proof[4:]) != pcpTPM20 || binary.LittleEndian.Uint32(proof[8:]) != pcpAttestationHeader {
		return nil, nil, nil, ErrFormat
	}
	statementSize := uint64(binary.LittleEndian.Uint32(proof[12:]))
	signatureSize := uint64(binary.LittleEndian.Uint32(proof[16:]))
	keySize := uint64(binary.LittleEndian.Uint32(proof[20:]))
	if statementSize < 6 || statementSize > 512 || signatureSize != 256 || keySize < pcpKeyHeader ||
		pcpAttestationHeader+statementSize+signatureSize+keySize != uint64(len(proof)) {
		return nil, nil, nil, ErrFormat
	}
	statementEnd := pcpAttestationHeader + int(statementSize)
	signatureEnd := statementEnd + int(signatureSize)
	keyBlob := proof[signatureEnd:]
	header := uint64(binary.LittleEndian.Uint32(keyBlob[4:]))
	if string(keyBlob[:4]) != "PCPM" || binary.LittleEndian.Uint32(keyBlob[8:]) != pcpTPM20 ||
		(header != pcpKeyHeader && header != 56) {
		return nil, nil, nil, ErrFormat
	}
	length := header
	for off := 16; off < pcpKeyHeader; off += 4 {
		length += uint64(binary.LittleEndian.Uint32(keyBlob[off:]))
	}
	publicSize := uint64(binary.LittleEndian.Uint32(keyBlob[16:]))
	if length != keySize || publicSize < 2 || publicSize > 512 {
		return nil, nil, nil, ErrFormat
	}
	publicField := cryptobyte.String(keyBlob[header : header+publicSize])
	var publicArea cryptobyte.String
	if !publicField.ReadUint16LengthPrefixed(&publicArea) || !publicField.Empty() {
		return nil, nil, nil, ErrFormat
	}
	return proof[pcpAttestationHeader:statementEnd], proof[statementEnd:signatureEnd], publicArea, nil
}

func checkHelloTPMKey(area []byte, expected *rsa.PublicKey) error {
	public := cryptobyte.String(area)
	var keyType, nameAlgorithm, symmetric, scheme, keyBits uint16
	var attrs, exponent uint32
	var policy, modulus cryptobyte.String
	if !public.ReadUint16(&keyType) || keyType != tpmRSA ||
		!public.ReadUint16(&nameAlgorithm) || nameAlgorithm != tpmSHA256 ||
		!public.ReadUint32(&attrs) || !public.ReadUint16LengthPrefixed(&policy) ||
		(len(policy) != 0 && len(policy) != sha256.Size) ||
		!public.ReadUint16(&symmetric) || symmetric != tpmNull || !public.ReadUint16(&scheme) {
		return ErrFormat
	}
	if scheme != tpmNull {
		var hash uint16
		if scheme != tpmRSASSA || !public.ReadUint16(&hash) || hash != tpmSHA256 {
			return ErrFormat
		}
	}
	if !public.ReadUint16(&keyBits) || keyBits != 2048 || !public.ReadUint32(&exponent) ||
		!public.ReadUint16LengthPrefixed(&modulus) || len(modulus) != 256 || !public.Empty() {
		return ErrFormat
	}
	if exponent == 0 {
		exponent = 65537 // TPM default RSA public exponent.
	}
	if attrs&tpmFixedSigningKey != tpmFixedSigningKey || exponent != uint32(expected.E) || !bytes.Equal(modulus, expected.N.Bytes()) {
		return ErrAuthentication
	}
	return nil
}

func checkHelloTPMCertify(statement, area []byte) error {
	fields := cryptobyte.String(statement)
	var magic uint32
	var kind uint16
	var signer, extra, name, qualified cryptobyte.String
	if !fields.ReadUint32(&magic) || magic != tpmGenerated || !fields.ReadUint16(&kind) || kind != tpmCertify ||
		!fields.ReadUint16LengthPrefixed(&signer) || len(signer) > 68 ||
		!fields.ReadUint16LengthPrefixed(&extra) || len(extra) > 64 ||
		!fields.Skip(25) || // TPMS_CLOCK_INFO (17 bytes) and firmware version (8 bytes).
		!fields.ReadUint16LengthPrefixed(&name) || len(name) != 2+sha256.Size ||
		!fields.ReadUint16LengthPrefixed(&qualified) || len(qualified) > 68 || !fields.Empty() {
		return ErrFormat
	}
	digest := sha256.Sum256(area)
	if binary.BigEndian.Uint16(name) != tpmSHA256 || !bytes.Equal(name[2:], digest[:]) {
		return ErrAuthentication
	}
	return nil
}
