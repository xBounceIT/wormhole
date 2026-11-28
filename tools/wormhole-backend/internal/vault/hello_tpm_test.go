package vault

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"
	"time"
)

func tpmRSAFixture(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func tpmCertificateFixture(t *testing.T, template, issuer *x509.Certificate, public any, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, public, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func tpm2BFixture(out, value []byte) []byte {
	return append(binary.BigEndian.AppendUint16(out, uint16(len(value))), value...)
}

func tpmAreaFixture(public *rsa.PublicKey, attrs uint32, explicitScheme bool) []byte {
	area := binary.BigEndian.AppendUint16(nil, tpmRSA)
	area = binary.BigEndian.AppendUint16(area, tpmSHA256)
	area = binary.BigEndian.AppendUint32(area, attrs)
	area = tpm2BFixture(area, make([]byte, 32))
	area = binary.BigEndian.AppendUint16(area, tpmNull)
	if explicitScheme {
		area = binary.BigEndian.AppendUint16(area, tpmRSASSA)
		area = binary.BigEndian.AppendUint16(area, tpmSHA256)
	} else {
		area = binary.BigEndian.AppendUint16(area, tpmNull)
	}
	area = binary.BigEndian.AppendUint16(area, 2048)
	area = binary.BigEndian.AppendUint32(area, 0)
	return tpm2BFixture(area, public.N.Bytes())
}

func tpmCertifyFixture(area []byte) []byte {
	statement := binary.BigEndian.AppendUint32(nil, tpmGenerated)
	statement = binary.BigEndian.AppendUint16(statement, tpmCertify)
	statement = tpm2BFixture(statement, nil)
	statement = tpm2BFixture(statement, nil)
	statement = append(statement, make([]byte, 25)...)
	digest := sha256.Sum256(area)
	name := binary.BigEndian.AppendUint16(nil, tpmSHA256)
	name = append(name, digest[:]...)
	statement = tpm2BFixture(statement, name)
	return tpm2BFixture(statement, name)
}

func tpmProofFixture(t *testing.T, key *rsa.PrivateKey, area, statement []byte, hash crypto.Hash, header int) []byte {
	t.Helper()
	var digest []byte
	if hash == crypto.SHA1 {
		value := sha1.Sum(statement)
		digest = value[:]
	} else {
		value := sha256.Sum256(statement)
		digest = value[:]
	}
	signature, err := rsa.SignPKCS1v15(nil, key, hash, digest)
	if err != nil {
		t.Fatal(err)
	}
	public := tpm2BFixture(nil, area)
	keyBlob := make([]byte, header)
	copy(keyBlob, "PCPM")
	binary.LittleEndian.PutUint32(keyBlob[4:], uint32(header))
	binary.LittleEndian.PutUint32(keyBlob[8:], pcpTPM20)
	binary.LittleEndian.PutUint32(keyBlob[16:], uint32(len(public)))
	keyBlob = append(keyBlob, public...)
	proof := []byte("KADS")
	for _, value := range []uint32{pcpTPM20, pcpAttestationHeader, uint32(len(statement)), uint32(len(signature)), uint32(len(keyBlob))} {
		proof = binary.LittleEndian.AppendUint32(proof, value)
	}
	proof = append(proof, statement...)
	proof = append(proof, signature...)
	return append(proof, keyBlob...)
}

func TestHelloTPMAttestationRequiresTrustedAIKAndExactHardwareKey(t *testing.T) {
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	makeTemplate := func(number int64, commonName string) x509.Certificate {
		return x509.Certificate{SerialNumber: big.NewInt(number), Subject: pkix.Name{CommonName: commonName}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true}
	}
	rootTemplate := makeTemplate(1, "Attestation fixture root")
	rootTemplate.IsCA = true
	rootTemplate.KeyUsage = x509.KeyUsageCertSign
	root := tpmCertificateFixture(t, &rootTemplate, &rootTemplate, rootKey.Public(), rootKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	aik, hello := tpmRSAFixture(t), tpmRSAFixture(t)
	makeAIK := func(usage bool, parent *x509.Certificate, signer crypto.Signer, signing bool) *x509.Certificate {
		template := makeTemplate(2, "Attestation fixture AIK")
		if signing {
			template.KeyUsage = x509.KeyUsageDigitalSignature
		}
		if usage {
			template.UnknownExtKeyUsage = []asn1.ObjectIdentifier{aikCertificateUsage}
		} else {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		return tpmCertificateFixture(t, &template, parent, aik.Public(), signer)
	}
	leaf := makeAIK(true, root, rootKey, true)
	for _, header := range []int{pcpKeyHeader, 56} {
		area := tpmAreaFixture(&hello.PublicKey, tpmFixedSigningKey, header == 56)
		proof := tpmProofFixture(t, aik, area, tpmCertifyFixture(area), crypto.SHA256, header)
		if err := VerifyHelloTPMAttestation(proof, []*x509.Certificate{root, leaf}, roots, &hello.PublicKey, now); err != nil {
			t.Fatal("valid fixture was refused", err)
		}
	}
	area := tpmAreaFixture(&hello.PublicKey, tpmFixedSigningKey, false)
	statement := tpmCertifyFixture(area)
	valid := tpmProofFixture(t, aik, area, statement, crypto.SHA256, pcpKeyHeader)
	restricted := makeTemplate(3, "Server-only issuing certificate")
	restricted.IsCA = true
	restricted.KeyUsage = x509.KeyUsageCertSign
	restricted.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer := tpmCertificateFixture(t, &restricted, root, issuerKey.Public(), rootKey)
	certificates := []*x509.Certificate{leaf}
	for _, test := range []struct {
		name  string
		chain []*x509.Certificate
		roots *x509.CertPool
		key   *rsa.PublicKey
		when  time.Time
	}{
		{"peer-installed root", []*x509.Certificate{leaf, root}, x509.NewCertPool(), &hello.PublicKey, now},
		{"ordinary signing certificate", []*x509.Certificate{makeAIK(false, root, rootKey, true)}, roots, &hello.PublicKey, now},
		{"non-signing certificate", []*x509.Certificate{makeAIK(true, root, rootKey, false)}, roots, &hello.PublicKey, now},
		{"issuer prohibits AIK usage", []*x509.Certificate{issuer, makeAIK(true, issuer, issuerKey, true)}, roots, &hello.PublicKey, now},
		{"expired certificate", certificates, roots, &hello.PublicKey, now.Add(2 * time.Hour)},
		{"another Hello key", certificates, roots, &aik.PublicKey, now},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := VerifyHelloTPMAttestation(valid, test.chain, test.roots, test.key, test.when); !errors.Is(err, ErrAuthentication) {
				t.Fatal("proof obtained hardware authority", err)
			}
		})
	}
	if err := VerifyHelloTPMAttestation(valid, []*x509.Certificate{leaf, nil}, roots, &hello.PublicKey, now); !errors.Is(err, ErrFormat) {
		t.Fatal("invalid certificate list", err)
	}
	if err := VerifyHelloTPMAttestation(valid, certificates, nil, &hello.PublicKey, now); !errors.Is(err, ErrFormat) {
		t.Fatal("missing attestation policy defaulted to system roots", err)
	}
	exportable := tpmAreaFixture(&hello.PublicKey, tpmFixedSigningKey&^0x10, true)
	for name, proof := range map[string][]byte{
		"substituted public area": tpmProofFixture(t, aik, area, tpmCertifyFixture(exportable), crypto.SHA256, pcpKeyHeader),
		"migratable key":          tpmProofFixture(t, aik, exportable, tpmCertifyFixture(exportable), crypto.SHA256, pcpKeyHeader),
		"legacy digest":           tpmProofFixture(t, aik, area, statement, crypto.SHA1, pcpKeyHeader),
		"untrusted signer":        tpmProofFixture(t, hello, area, statement, crypto.SHA256, pcpKeyHeader),
	} {
		if err := VerifyHelloTPMAttestation(proof, certificates, roots, &hello.PublicKey, now); !errors.Is(err, ErrAuthentication) {
			t.Fatal(name, "obtained hardware authority", err)
		}
	}
	for _, mutate := range []func([]byte){
		func(data []byte) { data[0] ^= 1 },
		func(data []byte) { binary.LittleEndian.PutUint32(data[4:], 1) },
		func(data []byte) { binary.LittleEndian.PutUint32(data[20:], ^uint32(0)) },
		func(data []byte) { data[pcpAttestationHeader] ^= 1 },
		func(data []byte) { data[pcpAttestationHeader+5] ^= 1 },
		func(data []byte) { data[pcpAttestationHeader+6] = 0xff },
		func(data []byte) { binary.LittleEndian.PutUint32(data[pcpAttestationHeader+len(statement)+256+4:], 53) },
		func(data []byte) {
			binary.LittleEndian.PutUint32(data[pcpAttestationHeader+len(statement)+256+16:], ^uint32(0))
		},
		func(data []byte) { data[pcpAttestationHeader+len(statement)+256+pcpKeyHeader] ^= 0x80 },
	} {
		input := bytes.Clone(valid)
		mutate(input)
		if err := VerifyHelloTPMAttestation(input, certificates, roots, &hello.PublicKey, now); !errors.Is(err, ErrFormat) {
			t.Fatal("malformed attestation was not rejected", err)
		}
	}
	for end := range len(valid) {
		if err := VerifyHelloTPMAttestation(valid[:end], certificates, roots, &hello.PublicKey, now); !errors.Is(err, ErrFormat) {
			t.Fatal("truncation accepted", end, err)
		}
	}
}

func TestHelloTPMVerifiedFlagNeedsNewSlotVersion(t *testing.T) {
	document, root := slotFileFixture(t)
	credential := newHelloProofFixture(t)
	credential.status = HelloAttestationTPMVerified
	slot, err := CreateHelloSlot(t.Context(), document.VaultID, document.FileID, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", document.RootKeyVersion, root, credential)
	if err != nil {
		t.Fatal(err)
	}
	document.Slots = append(document.Slots, slot)
	for _, version := range []uint16{SlotFileHelloVersion, SlotFileTouchIDVersion} {
		document.FormatVersion = version
		if _, err := EncodeSlotFile(root, document); !errors.Is(err, ErrFormat) {
			t.Fatal("earlier format accepted new attestation state", err)
		}
	}
	document.FormatVersion = SlotFileTPMAttestationVersion
	raw, err := EncodeSlotFile(root, document)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := DecodeSlotFile(raw)
	if err != nil || VerifySlotFile(root, saved, document.VaultID, document.FileID, document.Sequence) != nil {
		t.Fatal("new attestation state did not survive authenticated serialization", err)
	}
	saved.Slots[1].Hello.Attestation = HelloAttestationPresent
	if err := VerifySlotFile(root, saved, document.VaultID, document.FileID, document.Sequence); !errors.Is(err, ErrAuthentication) {
		t.Fatal("attestation result was not authenticated", err)
	}
}
