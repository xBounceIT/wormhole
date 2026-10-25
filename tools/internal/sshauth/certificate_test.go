package sshauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSharedCertificateValidation(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(private)
	_, caPrivate, _ := ed25519.GenerateKey(rand.Reader)
	ca, _ := ssh.NewSignerFromKey(caPrivate)
	now := time.Now()
	certificate := &ssh.Certificate{Key: signer.PublicKey(), CertType: ssh.UserCert, KeyId: "fixture", ValidPrincipals: []string{"ops"}, ValidAfter: uint64(now.Unix() - 60), ValidBefore: uint64(now.Unix() + 3600)}
	if err := certificate.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	encoded := ssh.MarshalAuthorizedKey(certificate)
	parsed, err := ParseUserCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CertificateSigner(parsed, signer, now); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{nil, bytes.Repeat([]byte("x"), MaxCertificateBytes+1), signer.PublicKey().Marshal(), ssh.MarshalAuthorizedKey(signer.PublicKey()), append(encoded, encoded...), append([]byte("no-pty "), encoded...), []byte("bad")} {
		if _, err := ParseUserCertificate(invalid); err == nil {
			t.Fatal("invalid public certificate was accepted")
		}
	}
	certificate.CertType = ssh.HostCert
	_ = certificate.SignCert(rand.Reader, ca)
	if _, err := ParseUserCertificate(ssh.MarshalAuthorizedKey(certificate)); err == nil {
		t.Fatal("host certificate was accepted for user authentication")
	}
	certificate.CertType = ssh.UserCert
	_ = certificate.SignCert(rand.Reader, ca)
	certificate.KeyId = "tampered"
	if _, err := ParseUserCertificate(ssh.MarshalAuthorizedKey(certificate)); err == nil {
		t.Fatal("modified signature was accepted")
	}
	certificate.KeyId = "fixture"
	_ = certificate.SignCert(rand.Reader, ca)
	if _, err := CertificateSigner(certificate, ca, now); err == nil {
		t.Fatal("mismatched private key was accepted")
	}
	certificate.ValidBefore = uint64(now.Unix() - 31)
	if _, err := CertificateSigner(certificate, signer, now); err == nil {
		t.Fatal("expired certificate was accepted")
	}
	certificate.ValidBefore = ssh.CertTimeInfinity
	certificate.ValidAfter = uint64(now.Unix() + 31)
	if _, err := CertificateSigner(certificate, signer, now); err == nil {
		t.Fatal("future certificate was accepted")
	}
	certificate.ValidAfter = 0
	for _, password := range []string{"", "phrase"} {
		block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "", []byte("phrase"))
		if err != nil {
			t.Fatal(err)
		}
		key := pem.EncodeToMemory(block)
		if err := ValidateCertificateKey(certificate, key, password); err != nil {
			t.Fatal(err)
		}
		certificate.Key = ca.PublicKey()
		if err := ValidateCertificateKey(certificate, key, password); err == nil {
			t.Fatal("encrypted key mismatch was accepted")
		}
		certificate.Key = signer.PublicKey()
	}
	if err := ValidateCertificateKey(certificate, []byte("bad"), ""); err == nil {
		t.Fatal("invalid private key was accepted")
	}
}
