package sshauth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
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
	defer clear(der)
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
	defer clear(key)
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
		defer clear(padded)
		data = make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, padded)
		encryption = testAlgorithm(t, cipherOID, iv)
	}
	envelope := sshPKCS8Envelope{Algorithm: testAlgorithm(t, "1.2.840.113549.1.5.13", sshPBES2Params{KDF: kdf, Cipher: encryption}), Data: data}
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: testASN1(t, envelope)})
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

func TestPKCS8SharedParserSupportedCiphersAndKDFs(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, algorithm := range []string{"2.16.840.1.101.3.4.1.2", "2.16.840.1.101.3.4.1.22", "2.16.840.1.101.3.4.1.42", "2.16.840.1.101.3.4.1.6", "2.16.840.1.101.3.4.1.26", "2.16.840.1.101.3.4.1.46", "1.2.840.113549.3.7"} {
		for _, useScrypt := range []bool{false, true} {
			encoded := testPKCS8Key(t, private, "pass", useScrypt, algorithm)
			signer, err := ParsePrivateKey(encoded, []byte("pass"))
			if err != nil {
				t.Fatalf("cipher %s: %v", algorithm, err)
			}
			message := []byte("shared parser round trip")
			signature, err := signer.Sign(rand.Reader, message)
			if err != nil || signer.PublicKey().Verify(message, signature) != nil {
				t.Fatal("decrypted signer failed its round trip")
			}
			var missing *ssh.PassphraseMissingError
			if _, err := ParsePrivateKey(encoded, nil); !errors.As(err, &missing) {
				t.Fatal("encrypted key did not request a passphrase")
			}
			if _, err := ParsePrivateKey(encoded, []byte("wrong")); !errors.Is(err, x509.IncorrectPasswordError) {
				t.Fatal("wrong password did not fail closed")
			}
		}
	}
}
