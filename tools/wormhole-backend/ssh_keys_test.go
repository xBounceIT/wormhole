package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh"
)

func testASN1(t *testing.T, value any) []byte {
	t.Helper()
	data, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func testOID(value string) asn1.ObjectIdentifier {
	var result asn1.ObjectIdentifier
	for _, part := range strings.Split(value, ".") {
		var n int
		for _, r := range part {
			n = n*10 + int(r-'0')
		}
		result = append(result, n)
	}
	return result
}

func testAlgorithm(t *testing.T, oid string, parameters any) pkix.AlgorithmIdentifier {
	return pkix.AlgorithmIdentifier{Algorithm: testOID(oid), Parameters: asn1.RawValue{FullBytes: testASN1(t, parameters)}}
}

func testPKCS8Key(t *testing.T, private any, password string, useScrypt bool, cipherOID string) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(der)
	salt := []byte("wormhole-test-salt")
	size := 32
	switch cipherOID {
	case "2.16.840.1.101.3.4.1.2", "2.16.840.1.101.3.4.1.6":
		size = 16
	case "2.16.840.1.101.3.4.1.22", "2.16.840.1.101.3.4.1.26", "1.2.840.113549.3.7":
		size = 24
	}
	var key []byte
	var kdf pkix.AlgorithmIdentifier
	if useScrypt {
		kdf = testAlgorithm(t, "1.3.6.1.4.1.11591.4.11", struct {
			Salt    []byte
			N, R, P int
		}{salt, 1024, 8, 1})
		key, err = scrypt.Key([]byte(password), salt, 1024, 8, 1, size)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		kdf = testAlgorithm(t, "1.2.840.113549.1.5.12", struct {
			Salt       []byte
			Iterations int
			PRF        pkix.AlgorithmIdentifier
		}{salt, 1024, pkix.AlgorithmIdentifier{Algorithm: testOID("1.2.840.113549.2.9")}})
		key = pbkdf2.Key([]byte(password), salt, 1024, size, sha256.New)
	}
	defer clearBytes(key)
	var block cipher.Block
	if cipherOID == "1.2.840.113549.3.7" {
		block, err = des.NewTripleDESCipher(key)
	} else {
		block, err = aes.NewCipher(key)
	}
	if err != nil {
		t.Fatal(err)
	}
	var data []byte
	var encryption pkix.AlgorithmIdentifier
	if strings.HasSuffix(cipherOID, ".6") || strings.HasSuffix(cipherOID, ".26") || strings.HasSuffix(cipherOID, ".46") {
		nonce := make([]byte, 12)
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		data = aead.Seal(nil, nonce, der, nil)
		encryption = testAlgorithm(t, cipherOID, struct {
			Nonce   []byte
			TagSize int
		}{nonce, 16})
	} else {
		iv := make([]byte, block.BlockSize())
		padding := block.BlockSize() - len(der)%block.BlockSize()
		padded := append(bytes.Clone(der), bytes.Repeat([]byte{byte(padding)}, padding)...)
		defer clearBytes(padded)
		data = make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, padded)
		encryption = testAlgorithm(t, cipherOID, iv)
	}
	envelope := sshPKCS8Envelope{Algorithm: testAlgorithm(t, "1.2.840.113549.1.5.13", sshPBES2Params{KDF: kdf, Cipher: encryption}), Data: data}
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: testASN1(t, envelope)})
}

func testSSHCertificate(t *testing.T, signer ssh.Signer, certType uint32, after, before uint64) (*ssh.Certificate, ssh.Signer) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	cert := &ssh.Certificate{Key: signer.PublicKey(), CertType: certType, KeyId: "wormhole-test", ValidPrincipals: []string{"operator"}, ValidAfter: after, ValidBefore: before}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return cert, ca
}

func TestParseSSHSignerFormats(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey), []byte("pass"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name     string
		key      []byte
		password string
	}{
		{"OpenSSH", testSshPrivateKey(t, ""), ""},
		{"OpenSSH encrypted", testSshPrivateKey(t, "pass"), "pass"},
		{"PKCS1", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}), ""},
		{"SEC1", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}), ""},
		{"PKCS8 plain", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER}), ""},
		{"legacy encrypted", pem.EncodeToMemory(legacy), "pass"},
	} {
		t.Run(item.name, func(t *testing.T) {
			if _, err := parseSSHSigner(item.key, []byte(item.password)); err != nil {
				t.Fatal(err)
			}
			if err := validateSshPrivateKey(item.key, item.password); err != nil {
				t.Fatal(err)
			}
			if item.password != "" {
				var missing *ssh.PassphraseMissingError
				if _, err := parseSSHSigner(item.key, nil); !errors.As(err, &missing) {
					t.Fatalf("missing password: %v", err)
				}
				if _, err := parseSSHSigner(item.key, []byte("wrong")); !errors.Is(err, x509.IncorrectPasswordError) {
					t.Fatalf("wrong password: %v", err)
				}
			}
		})
	}
	for _, useScrypt := range []bool{false, true} {
		for _, oid := range []string{"2.16.840.1.101.3.4.1.2", "2.16.840.1.101.3.4.1.22", "2.16.840.1.101.3.4.1.42", "2.16.840.1.101.3.4.1.6", "2.16.840.1.101.3.4.1.26", "2.16.840.1.101.3.4.1.46", "1.2.840.113549.3.7"} {
			key := testPKCS8Key(t, rsaKey, "pass", useScrypt, oid)
			if _, err := parseSSHSigner(key, []byte("pass")); err != nil {
				t.Fatalf("%s scrypt=%v: %v", oid, useScrypt, err)
			}
			var missing *ssh.PassphraseMissingError
			if _, err := parseSSHSigner(key, nil); !errors.As(err, &missing) {
				t.Fatalf("missing PKCS8 password: %v", err)
			}
			if err := validateSshPrivateKey(key, ""); err != nil {
				t.Fatal(err)
			}
			if _, err := parseSSHSigner(key, []byte("wrong")); !errors.Is(err, x509.IncorrectPasswordError) {
				t.Fatalf("wrong PKCS8 password: %v", err)
			}
		}
	}
	for _, key := range [][]byte{nil, []byte("invalid"), bytes.Repeat([]byte("x"), maxSshPrivateKeyBytes+1)} {
		if _, err := parseSSHSigner(key, nil); !errors.Is(err, errUnsupportedSSHKey) {
			t.Fatal(err)
		}
	}
	if _, err := parseSSHSigner([]byte("PuTTY-User-Key-File-3: ssh-ed25519"), nil); err == nil || !strings.Contains(err.Error(), "puttygen") {
		t.Fatal(err)
	}
}

func TestSSHUserCertificateValidation(t *testing.T) {
	key := testSshPrivateKey(t, "")
	signer, err := parseSSHSigner(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert, _ := testSSHCertificate(t, signer, ssh.UserCert, uint64(now.Unix()-60), uint64(now.Unix()+3600))
	line := ssh.MarshalAuthorizedKey(cert)
	if parsed, err := parseSSHUserCertificate(line); err != nil || parsed.KeyId != cert.KeyId {
		t.Fatal(err)
	}
	for _, comment := range []struct{ input, expected string }{
		{"", ""}, {"   ", ""}, {"\x00\x1b", ""}, {"  renewed\x1b-key  ", "renewed-key"},
	} {
		input := append(bytes.Clone(bytes.TrimSpace(line)), []byte(" "+comment.input+"\n")...)
		expected := strings.TrimSpace(string(line))
		if comment.expected != "" {
			expected += " " + comment.expected
		}
		if actual := canonicalSSHCertificate(cert, input); actual != expected {
			t.Fatalf("canonical certificate changed public content or comment: %q", comment.input)
		}
	}
	if _, err := sshCertificateSigner(cert, signer, now); err != nil {
		t.Fatal(err)
	}
	host, _ := testSSHCertificate(t, signer, ssh.HostCert, 0, ssh.CertTimeInfinity)
	for _, item := range []struct {
		line    []byte
		message string
	}{
		{nil, "16 KiB"}, {bytes.Repeat([]byte("x"), maxSSHCertificateBytes+1), "16 KiB"},
		{append(bytes.Clone(line), line...), "exactly one"},
		{[]byte("invalid"), "not an OpenSSH"}, {ssh.MarshalAuthorizedKey(signer.PublicKey()), "public key"},
		{ssh.MarshalAuthorizedKey(host), "host certificate"}, {append([]byte("no-pty "), line...), "not an OpenSSH"},
	} {
		if _, err := parseSSHUserCertificate(item.line); err == nil || !strings.Contains(err.Error(), item.message) {
			t.Fatalf("expected %q: %v", item.message, err)
		}
	}
	other, _ := parseSSHSigner(testSshPrivateKey(t, ""), nil)
	if _, err := sshCertificateSigner(cert, other, now); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatal(err)
	}
	cert.ValidBefore = uint64(now.Unix() - 60)
	if _, err := sshCertificateSigner(cert, signer, now); err == nil || !strings.Contains(err.Error(), "expired on") {
		t.Fatal(err)
	}
	cert.ValidBefore = ssh.CertTimeInfinity
	if _, err := sshCertificateSigner(cert, signer, now); err != nil {
		t.Fatal(err)
	}
	cert.ValidAfter = uint64(now.Unix() + 60)
	if _, err := sshCertificateSigner(cert, signer, now); err == nil || !strings.Contains(err.Error(), "not yet valid") {
		t.Fatal(err)
	}
	cert.ValidAfter = uint64(now.Unix() + 10)
	if _, err := sshCertificateSigner(cert, signer, now); err != nil {
		t.Fatalf("clock skew: %v", err)
	}

	for _, password := range []string{"", "pass"} {
		encrypted := testSshPrivateKey(t, "pass")
		matching, _ := parseSSHSigner(encrypted, []byte("pass"))
		cert, _ := testSSHCertificate(t, matching, ssh.UserCert, 0, ssh.CertTimeInfinity)
		if err := validateSSHCertificateKey(cert, encrypted, password); err != nil {
			t.Fatal(err)
		}
		if err := validateSSHCertificateKey(host, encrypted, password); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatal(err)
		}
	}
	if err := validateSSHCertificateKey(cert, []byte("bad"), ""); err == nil {
		t.Fatal("accepted invalid key")
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSSHCertificateKey(cert, testPKCS8Key(t, rsaKey, "pass", false, "2.16.840.1.101.3.4.1.42"), ""); err != nil {
		t.Fatalf("PEM match should be deferred: %v", err)
	}
}

func TestSSHPKCS8RejectsUnsafeAndMalformedParameters(t *testing.T) {
	password := []byte("pass")
	for _, oid := range []string{"", "1.2.840.113549.2.7", "1.2.840.113549.2.8", "1.2.840.113549.2.9", "1.2.840.113549.2.10", "1.2.840.113549.2.11"} {
		var prf pkix.AlgorithmIdentifier
		if oid != "" {
			prf.Algorithm = testOID(oid)
		}
		kdf := testAlgorithm(t, "1.2.840.113549.1.5.12", struct {
			Salt       []byte
			Iterations int
			KeyLength  int
			PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
		}{[]byte("salt"), 1, 32, prf})
		if _, err := deriveSSHPKCS8Key(kdf, password, 32); err != nil {
			t.Fatal(err)
		}
	}
	for _, kdf := range []pkix.AlgorithmIdentifier{
		testAlgorithm(t, "1.2.840.113549.1.5.12", struct {
			Salt       []byte
			Iterations int
		}{[]byte("salt"), 10000001}),
		testAlgorithm(t, "1.2.840.113549.1.5.12", struct {
			Salt       []byte
			Iterations int
			KeyLength  int
		}{[]byte("salt"), 1, 16}),
		testAlgorithm(t, "1.2.840.113549.1.5.12", struct {
			Salt       []byte
			Iterations int
			PRF        pkix.AlgorithmIdentifier
		}{[]byte("salt"), 1, pkix.AlgorithmIdentifier{Algorithm: testOID("1.2.3")}}),
		testAlgorithm(t, "1.2.840.113549.1.5.12", "bad"),
		testAlgorithm(t, "1.3.6.1.4.1.11591.4.11", struct {
			Salt    []byte
			N, R, P int
		}{[]byte("salt"), 1 << 30, 8, 1}),
		testAlgorithm(t, "1.3.6.1.4.1.11591.4.11", struct {
			Salt    []byte
			N, R, P int
		}{[]byte("salt"), 3, 8, 1}),
		testAlgorithm(t, "1.3.6.1.4.1.11591.4.11", "bad"), testAlgorithm(t, "1.2.3", "bad"),
	} {
		if _, err := deriveSSHPKCS8Key(kdf, password, 32); err == nil {
			t.Fatal("accepted unsafe KDF")
		}
	}
	if err := decodeSSHASN1(append(testASN1(t, 1), 0), new(int)); err == nil {
		t.Fatal("accepted trailing ASN1 data")
	}
	if _, err := decryptSSHPKCS8([]byte("bad"), password); err == nil {
		t.Fatal("accepted bad envelope")
	}
	kdf := testAlgorithm(t, "1.2.840.113549.1.5.12", struct {
		Salt       []byte
		Iterations int
	}{[]byte("salt"), 1})
	for _, encryption := range []pkix.AlgorithmIdentifier{
		testAlgorithm(t, "1.2.3", []byte{}),
		testAlgorithm(t, "2.16.840.1.101.3.4.1.42", "bad"),
		testAlgorithm(t, "2.16.840.1.101.3.4.1.42", []byte("bad")),
		testAlgorithm(t, "2.16.840.1.101.3.4.1.6", "bad"),
		testAlgorithm(t, "2.16.840.1.101.3.4.1.6", struct {
			Nonce   []byte
			TagSize int
		}{[]byte("bad"), 16}),
	} {
		der := testASN1(t, sshPKCS8Envelope{Algorithm: testAlgorithm(t, "1.2.840.113549.1.5.13", sshPBES2Params{KDF: kdf, Cipher: encryption}), Data: []byte("bad")})
		if _, err := decryptSSHPKCS8(der, password); err == nil {
			t.Fatal("accepted bad cipher parameters")
		}
	}
	for _, algorithm := range []pkix.AlgorithmIdentifier{testAlgorithm(t, "1.2.3", 0), testAlgorithm(t, "1.2.840.113549.1.5.13", "bad")} {
		if _, err := decryptSSHPKCS8(testASN1(t, sshPKCS8Envelope{Algorithm: algorithm}), password); err == nil {
			t.Fatal("accepted bad PBES2")
		}
	}
}
