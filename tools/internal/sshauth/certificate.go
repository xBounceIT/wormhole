package sshauth

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

const MaxCertificateBytes = 16 * 1024
const CertificateClockSkew = 30 * time.Second

func ParseUserCertificate(line []byte) (*ssh.Certificate, error) {
	if len(line) == 0 || len(line) > MaxCertificateBytes {
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
	if err := CheckCertificateSignature(cert); err != nil {
		return nil, err
	}
	return cert, nil
}

func CheckCertificateSignature(cert *ssh.Certificate) error {
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

func CheckCertificateKey(cert *ssh.Certificate, public ssh.PublicKey) error {
	if !bytes.Equal(cert.Key.Marshal(), public.Marshal()) {
		return errors.New("SSH certificate does not match the private key")
	}
	return nil
}

func CheckCertificateTime(cert *ssh.Certificate, now time.Time) error {
	if cert.ValidAfter > uint64(max(now.Add(CertificateClockSkew).Unix(), 0)) {
		return errors.New("SSH certificate is not yet valid (check its validity window and the system clock)")
	}
	if cert.ValidBefore != ssh.CertTimeInfinity && cert.ValidBefore <= uint64(max(now.Add(-CertificateClockSkew).Unix(), 0)) {
		return fmt.Errorf("SSH certificate expired on %s; replace the certificate", time.Unix(int64(cert.ValidBefore), 0).UTC().Format("2006-01-02 15:04 UTC"))
	}
	return nil
}

func CertificateSigner(cert *ssh.Certificate, signer ssh.Signer, now time.Time) (ssh.Signer, error) {
	if err := CheckCertificateKey(cert, signer.PublicKey()); err != nil {
		return nil, err
	}
	if err := CheckCertificateTime(cert, now); err != nil {
		return nil, err
	}
	return ssh.NewCertSigner(cert, signer)
}

// Encrypted OpenSSH keys expose their public half without decrypting. PEM and
// PKCS#8 don't, so their match check is deferred until a passphrase is supplied.
func ValidateCertificateKey(cert *ssh.Certificate, key []byte, passphrase string) error {
	password := []byte(passphrase)
	defer clear(password)
	signer, err := ParsePrivateKey(key, password)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if missing.PublicKey != nil {
			return CheckCertificateKey(cert, missing.PublicKey)
		}
		return nil
	}
	if err != nil {
		return err
	}
	return CheckCertificateKey(cert, signer.PublicKey())
}
