// Package sshauth implements the credential parsing shared by SSH sessions and jump hosts.
package sshauth

import (
	"bytes"
	"encoding/pem"
	"errors"

	"golang.org/x/crypto/ssh"
)

const MaxKeyBytes = 1024 * 1024

// ParseSigner accepts PEM/OpenSSH keys, optionally followed by an OpenSSH user certificate.
// Bundling the public certificate with the key lets the existing protected credential store
// and its backup transaction own both. An explicit certificate is also accepted by sidecars.
func ParseSigner(key, passphrase, certificate []byte) (ssh.Signer, error) {
	if len(key) == 0 || len(key) > MaxKeyBytes || len(certificate) > MaxKeyBytes || len(passphrase) > 16384 {
		return nil, errors.New("SSH key material is invalid or too large")
	}
	var signer ssh.Signer
	var err error
	if len(passphrase) == 0 {
		signer, err = ssh.ParsePrivateKey(key)
	} else {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(key, passphrase)
		// Unencrypted keys may still have a stored passphrase from an older credential.
		if err != nil {
			if plain, plainErr := ssh.ParsePrivateKey(key); plainErr == nil {
				signer, err = plain, nil
			}
		}
	}
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, missing
		}
		return nil, errors.New("could not read the SSH private key or passphrase")
	}
	if len(bytes.TrimSpace(certificate)) == 0 {
		if _, rest := pem.Decode(key); len(bytes.TrimSpace(rest)) > 0 {
			certificate = bytes.TrimSpace(rest)
		}
	}
	if len(certificate) == 0 {
		return signer, nil
	}
	public, _, _, rest, err := ssh.ParseAuthorizedKey(certificate)
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("SSH user certificate is invalid")
	}
	cert, ok := public.(*ssh.Certificate)
	if !ok || cert.CertType != ssh.UserCert {
		return nil, errors.New("SSH user certificate is required")
	}
	signer, err = ssh.NewCertSigner(cert, signer)
	if err != nil {
		return nil, errors.New("SSH certificate does not match the private key")
	}
	return signer, nil
}
