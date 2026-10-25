package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh"
)

const maxSSHCertificateBytes = 16 * 1024
const sshCertificateClockSkew = 30 * time.Second

type sshCertificateAuthError struct {
	error
	credentialID string
}

func (err *sshCertificateAuthError) Unwrap() error { return err.error }

func readCredentialSSHCertificate(path string, key []byte, passphrase string) (string, string, error) {
	if path == "" {
		return "", "", nil
	}
	line, err := readBoundedRegularFile(path, maxSSHCertificateBytes)
	if err != nil {
		return "", "", errors.New("SSH certificate is invalid or exceeds 16 KiB")
	}
	cert, err := parseSSHUserCertificate(line)
	if err == nil {
		err = validateSSHCertificateKey(cert, key, passphrase)
	}
	if err == nil {
		err = checkSSHCertificateTime(cert, time.Now())
	}
	if err != nil {
		return "", "", err
	}
	return canonicalSSHCertificate(cert, line), sshCertificateDisplayName(filepath.Base(path)), nil
}

// Import and backup repair share the same representation of validated public certificates.
func canonicalSSHCertificate(cert *ssh.Certificate, line []byte) string {
	_, comment, _, _, _ := ssh.ParseAuthorizedKey(line)
	canonical := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
	if comment = strings.TrimSpace(sshCertificateText(comment)); comment != "" {
		canonical += " " + comment
	}
	return canonical
}

var errUnsupportedSSHKey = errors.New("the selected file is not a supported SSH private key")

// Import and connection use the same parser. In particular, an encrypted PKCS#8
// key without a password must take the existing one-shot passphrase prompt path.
func parseSSHSigner(key, passphrase []byte) (ssh.Signer, error) {
	if len(key) == 0 || len(key) > maxSshPrivateKeyBytes {
		return nil, errUnsupportedSSHKey
	}
	if bytes.HasPrefix(bytes.TrimSpace(key), []byte("PuTTY-User-Key-File-")) {
		return nil, errors.New("PuTTY .ppk keys are not supported yet. Convert with puttygen key.ppk -O private-openssh")
	}
	block, _ := pem.Decode(key)
	if block != nil {
		defer clearBytes(block.Bytes)
		if block.Type == "ENCRYPTED PRIVATE KEY" {
			der, err := decryptSSHPKCS8(block.Bytes, passphrase)
			if err != nil {
				return nil, err
			}
			defer clearBytes(der)
			private, err := x509.ParsePKCS8PrivateKey(der)
			if err != nil {
				return nil, x509.IncorrectPasswordError
			}
			return ssh.NewSignerFromKey(private)
		}
	}
	signer, err := ssh.ParsePrivateKey(key)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) && len(passphrase) > 0 {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(key, passphrase)
	}
	if err != nil && !errors.As(err, &missing) {
		if len(passphrase) > 0 && (errors.Is(err, x509.IncorrectPasswordError) || strings.Contains(err.Error(), "incorrect passphrase")) {
			return nil, x509.IncorrectPasswordError
		}
		return nil, errUnsupportedSSHKey
	}
	return signer, err
}

func parseSSHUserCertificate(line []byte) (*ssh.Certificate, error) {
	if len(line) == 0 || len(line) > maxSSHCertificateBytes {
		return nil, errors.New("SSH certificate must be one authorized_keys line up to 16 KiB")
	}
	trimmed := bytes.TrimSpace(line)
	if bytes.ContainsAny(trimmed, "\r\n") {
		return nil, errors.New("SSH certificate must contain exactly one authorized_keys line")
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey(trimmed)
	if err != nil || len(bytes.TrimSpace(rest)) != 0 || len(options) != 0 {
		return nil, errors.New("the selected file is not an OpenSSH user certificate")
	}
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("the selected file is a public key, not an OpenSSH user certificate")
	}
	if cert.CertType != ssh.UserCert {
		return nil, errors.New("file is a host certificate, not a user certificate")
	}
	if err := checkSSHCertificateSignature(cert); err != nil {
		return nil, err
	}
	return cert, nil
}

func checkSSHCertificateSignature(cert *ssh.Certificate) error {
	// Reuse the library verifier, including its OpenSSH security-key CA rules.
	// The signed principal, options and start time avoid applying server policy
	// here. Import/runtime check the current validity window separately, while
	// backup may retain an expired certificate for independent renewal.
	principal := ""
	if len(cert.ValidPrincipals) > 0 {
		principal = cert.ValidPrincipals[0]
	}
	options := make([]string, 0, len(cert.CriticalOptions))
	for option := range cert.CriticalOptions {
		options = append(options, option)
	}
	checker := ssh.CertChecker{
		SupportedCriticalOptions: options,
		Clock:                    func() time.Time { return time.Unix(int64(cert.ValidAfter), 0) },
	}
	if err := checker.CheckCert(principal, cert); err != nil {
		return fmt.Errorf("SSH certificate is invalid: %w", err)
	}
	return nil
}

func checkSSHCertificateKey(cert *ssh.Certificate, public ssh.PublicKey) error {
	if !bytes.Equal(cert.Key.Marshal(), public.Marshal()) {
		return errors.New("SSH certificate does not match the private key")
	}
	return nil
}

func checkSSHCertificateTime(cert *ssh.Certificate, now time.Time) error {
	if cert.ValidAfter > uint64(max(now.Add(sshCertificateClockSkew).Unix(), 0)) {
		return errors.New("SSH certificate is not yet valid (check its validity window and the system clock)")
	}
	if cert.ValidBefore != ssh.CertTimeInfinity && cert.ValidBefore <= uint64(max(now.Add(-sshCertificateClockSkew).Unix(), 0)) {
		return fmt.Errorf("SSH certificate expired on %s; replace the certificate", time.Unix(int64(cert.ValidBefore), 0).UTC().Format("2006-01-02 15:04 UTC"))
	}
	return nil
}

func sshCertificateSigner(cert *ssh.Certificate, signer ssh.Signer, now time.Time) (ssh.Signer, error) {
	if err := checkSSHCertificateKey(cert, signer.PublicKey()); err != nil {
		return nil, err
	}
	if err := checkSSHCertificateTime(cert, now); err != nil {
		return nil, err
	}
	return ssh.NewCertSigner(cert, signer)
}

// Encrypted OpenSSH keys expose their public half without decrypting. PEM and
// PKCS#8 don't, so their match check is deferred until a passphrase is supplied.
func validateSSHCertificateKey(cert *ssh.Certificate, key []byte, passphrase string) error {
	password := []byte(passphrase)
	defer clearBytes(password)
	signer, err := parseSSHSigner(key, password)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if missing.PublicKey != nil {
			return checkSSHCertificateKey(cert, missing.PublicKey)
		}
		return nil
	}
	if err != nil {
		return err
	}
	return checkSSHCertificateKey(cert, signer.PublicKey())
}

func sshCertificateText(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value)
}

func sshCertificateDisplayName(value string) string {
	name := sshCertificateText(value)
	if name == "" || !validCredentialText(name, maxCredentialNameLength) {
		return "SSH certificate"
	}
	return name
}

type sshCertificateMetadata struct {
	KeyID                string   `json:"keyId"`
	Principals           []string `json:"principals"`
	ValidAfter           string   `json:"validAfter,omitempty"`
	ValidBefore          string   `json:"validBefore,omitempty"`
	SigningCAFingerprint string   `json:"signingCaFingerprint"`
}

func setSSHCertificateMetadata(record *credentialRecord, line, fileName string) {
	if line == "" {
		return
	}
	record.HasCertificate = true
	record.CertificateFileName = sshCertificateDisplayName(fileName)
	cert, err := parseSSHUserCertificate([]byte(line))
	if err != nil {
		return // Never expose malformed stored content to the renderer.
	}
	metadata := &sshCertificateMetadata{
		KeyID: sshCertificateText(cert.KeyId), Principals: make([]string, len(cert.ValidPrincipals)),
		SigningCAFingerprint: ssh.FingerprintSHA256(cert.SignatureKey),
	}
	for i, principal := range cert.ValidPrincipals {
		metadata.Principals[i] = sshCertificateText(principal)
	}
	// RFC3339 timestamps avoid loss of precision for CertTimeInfinity in JS.
	if cert.ValidAfter <= 253402300799 {
		metadata.ValidAfter = time.Unix(int64(cert.ValidAfter), 0).UTC().Format(time.RFC3339)
	}
	if cert.ValidBefore != ssh.CertTimeInfinity && cert.ValidBefore <= 253402300799 {
		metadata.ValidBefore = time.Unix(int64(cert.ValidBefore), 0).UTC().Format(time.RFC3339)
	}
	record.Certificate = metadata
}

// PBES2 decoding stays here so derived keys and decrypted DER can be wiped and
// untrusted KDF parameters are bounded before allocating or doing expensive work.
type sshPKCS8Envelope struct {
	Algorithm pkix.AlgorithmIdentifier
	Data      []byte
}

type sshPBES2Params struct {
	KDF    pkix.AlgorithmIdentifier
	Cipher pkix.AlgorithmIdentifier
}

func decodeSSHASN1(der []byte, value any) error {
	rest, err := asn1.Unmarshal(der, value)
	if err != nil || len(rest) != 0 {
		return errors.New("invalid encrypted PKCS#8 parameters")
	}
	return nil
}

func decryptSSHPKCS8(der, passphrase []byte) ([]byte, error) {
	var envelope sshPKCS8Envelope
	if err := decodeSSHASN1(der, &envelope); err != nil {
		return nil, err
	}
	if envelope.Algorithm.Algorithm.String() != "1.2.840.113549.1.5.13" {
		return nil, errors.New("encrypted PKCS#8 key requires PBES2 encryption")
	}
	var params sshPBES2Params
	if err := decodeSSHASN1(envelope.Algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, err
	}
	keySize, gcm := 0, false
	switch params.Cipher.Algorithm.String() {
	case "2.16.840.1.101.3.4.1.2":
		keySize = 16
	case "2.16.840.1.101.3.4.1.22":
		keySize = 24
	case "2.16.840.1.101.3.4.1.42", "1.2.840.113549.3.7":
		keySize = 32
		if params.Cipher.Algorithm.String() == "1.2.840.113549.3.7" {
			keySize = 24
		}
	case "2.16.840.1.101.3.4.1.6":
		keySize, gcm = 16, true
	case "2.16.840.1.101.3.4.1.26":
		keySize, gcm = 24, true
	case "2.16.840.1.101.3.4.1.46":
		keySize, gcm = 32, true
	default:
		return nil, errors.New("unsupported encrypted PKCS#8 cipher (use AES or 3DES PBES2)")
	}
	// Cipher parameters are public. Reject malformed files before treating a
	// missing password as a supported key or spending time on the KDF.
	var iv []byte
	var parameters struct {
		Nonce   []byte
		TagSize int `asn1:"optional,default:12"`
	}
	if gcm {
		if err := decodeSSHASN1(params.Cipher.Parameters.FullBytes, &parameters); err != nil {
			return nil, err
		}
		if len(parameters.Nonce) != 12 || parameters.TagSize < 12 || parameters.TagSize > 16 || len(envelope.Data) < parameters.TagSize {
			return nil, errors.New("invalid encrypted PKCS#8 GCM parameters")
		}
	} else {
		if err := decodeSSHASN1(params.Cipher.Parameters.FullBytes, &iv); err != nil {
			return nil, err
		}
		blockSize := aes.BlockSize
		if params.Cipher.Algorithm.String() == "1.2.840.113549.3.7" {
			blockSize = des.BlockSize
		}
		if len(iv) != blockSize || len(envelope.Data) == 0 || len(envelope.Data)%blockSize != 0 {
			return nil, errors.New("invalid encrypted PKCS#8 CBC parameters")
		}
	}
	// Check the KDF even without a password; an unsupported key must not be saved.
	key, err := deriveSSHPKCS8Key(params.KDF, passphrase, keySize)
	if err != nil {
		return nil, err
	}
	defer clearBytes(key)
	if gcm {
		block, _ := aes.NewCipher(key)
		aead, err := cipher.NewGCMWithTagSize(block, parameters.TagSize)
		if err != nil {
			return nil, errors.New("invalid encrypted PKCS#8 GCM parameters")
		}
		plain, err := aead.Open(nil, parameters.Nonce, envelope.Data, nil)
		if err != nil {
			return nil, x509.IncorrectPasswordError
		}
		return plain, nil
	}
	var block cipher.Block
	if params.Cipher.Algorithm.String() == "1.2.840.113549.3.7" {
		block, err = des.NewTripleDESCipher(key)
	} else {
		block, err = aes.NewCipher(key)
	}
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(envelope.Data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, envelope.Data)
	padding := int(plain[len(plain)-1])
	if padding == 0 || padding > block.BlockSize() || !bytes.Equal(plain[len(plain)-padding:], bytes.Repeat([]byte{byte(padding)}, padding)) {
		clearBytes(plain)
		return nil, x509.IncorrectPasswordError
	}
	return plain[:len(plain)-padding], nil
}

func deriveSSHPKCS8Key(algorithm pkix.AlgorithmIdentifier, password []byte, size int) ([]byte, error) {
	switch algorithm.Algorithm.String() {
	case "1.2.840.113549.1.5.12":
		var params struct {
			Salt       []byte
			Iterations int
			KeyLength  int                      `asn1:"optional"`
			PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
		}
		if err := decodeSSHASN1(algorithm.Parameters.FullBytes, &params); err != nil {
			return nil, err
		}
		if len(params.Salt) < 1 || len(params.Salt) > 1024 || params.Iterations < 1 || params.Iterations > 10000000 || (params.KeyLength != 0 && params.KeyLength != size) {
			return nil, errors.New("encrypted PKCS#8 PBKDF2 parameters exceed safety limits")
		}
		var digest func() hash.Hash
		switch params.PRF.Algorithm.String() {
		case "", "1.2.840.113549.2.7":
			digest = sha1.New
		case "1.2.840.113549.2.8":
			digest = sha256.New224
		case "1.2.840.113549.2.9":
			digest = sha256.New
		case "1.2.840.113549.2.10":
			digest = sha512.New384
		case "1.2.840.113549.2.11":
			digest = sha512.New
		default:
			return nil, errors.New("unsupported encrypted PKCS#8 PBKDF2 digest")
		}
		if len(password) == 0 {
			return nil, &ssh.PassphraseMissingError{}
		}
		return pbkdf2.Key(password, params.Salt, params.Iterations, size, digest), nil
	case "1.3.6.1.4.1.11591.4.11":
		var params struct {
			Salt      []byte
			N, R, P   int
			KeyLength int `asn1:"optional"`
		}
		if err := decodeSSHASN1(algorithm.Parameters.FullBytes, &params); err != nil {
			return nil, err
		}
		// Bounds make the products below safe on 32-bit platforms as well.
		if len(params.Salt) < 1 || len(params.Salt) > 1024 || params.N < 2 || params.N > 1<<20 || params.N&(params.N-1) != 0 || params.R < 1 || params.R > 32 || params.P < 1 || params.P > 32 || uint64(params.N)*uint64(params.R)*128 > 256<<20 || uint64(params.N)*uint64(params.R)*uint64(params.P) > 1<<25 || (params.KeyLength != 0 && params.KeyLength != size) {
			return nil, errors.New("encrypted PKCS#8 scrypt parameters exceed safety limits")
		}
		if len(password) == 0 {
			return nil, &ssh.PassphraseMissingError{}
		}
		return scrypt.Key(password, params.Salt, params.N, params.R, params.P, size)
	default:
		return nil, errors.New("unsupported encrypted PKCS#8 key derivation (use PBKDF2 or scrypt)")
	}
}
