package main

import (
	"errors"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/xBounceIT/wormhole/tools/internal/sshauth"
	"golang.org/x/crypto/ssh"
)

const maxSSHCertificateBytes = sshauth.MaxCertificateBytes
const sshCertificateClockSkew = sshauth.CertificateClockSkew

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

var errUnsupportedSSHKey = sshauth.ErrUnsupportedKey

// Import and connection use the same parser. In particular, an encrypted PKCS#8
// key without a password must take the existing one-shot passphrase prompt path.
func parseSSHSigner(key, passphrase []byte) (ssh.Signer, error) {
	return sshauth.ParsePrivateKey(key, passphrase)
}

func parseSSHUserCertificate(line []byte) (*ssh.Certificate, error) {
	return sshauth.ParseUserCertificate(line)
}

func checkSSHCertificateTime(cert *ssh.Certificate, now time.Time) error {
	return sshauth.CheckCertificateTime(cert, now)
}

func sshCertificateSigner(cert *ssh.Certificate, signer ssh.Signer, now time.Time) (ssh.Signer, error) {
	return sshauth.CertificateSigner(cert, signer, now)
}

func validateSSHCertificateKey(cert *ssh.Certificate, key []byte, passphrase string) error {
	return sshauth.ValidateCertificateKey(cert, key, passphrase)
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
