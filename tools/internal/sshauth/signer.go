// Package sshauth implements the credential parsing shared by SSH sessions and jump hosts.
package sshauth

import (
	"bytes"
	"encoding/pem"
	"errors"
	"time"

	"golang.org/x/crypto/ssh"
)

const MaxKeyBytes = 1024 * 1024

// ParseSigner composes a private key with its optional OpenSSH user certificate.
// Sidecars accept an explicit certificate or one appended to the PEM key.
func ParseSigner(key, passphrase, certificate []byte) (ssh.Signer, error) {
	if len(key) == 0 || len(key) > MaxKeyBytes || len(certificate) > MaxCertificateBytes || len(passphrase) > 16384 {
		return nil, errors.New("SSH key material is invalid or too large")
	}
	signer, err := ParsePrivateKey(key, passphrase)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(certificate)) == 0 {
		block, rest := pem.Decode(key)
		if block != nil {
			clear(block.Bytes)
		}
		if len(bytes.TrimSpace(rest)) > 0 {
			certificate = bytes.TrimSpace(rest)
		}
	}
	if len(certificate) == 0 {
		return signer, nil
	}
	cert, err := ParseUserCertificate(certificate)
	if err != nil {
		return nil, err
	}
	return CertificateSigner(cert, signer, time.Now())
}
