package sshauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestParseSigner(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := ssh.MarshalPrivateKey(key, "")
	encrypted, _ := ssh.MarshalPrivateKeyWithPassphrase(key, "", []byte("phrase"))
	signer, _ := ssh.NewSignerFromKey(key)
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	ca, _ := ssh.NewSignerFromKey(caKey)
	certificate := &ssh.Certificate{Key: signer.PublicKey(), CertType: ssh.UserCert, ValidBefore: ssh.CertTimeInfinity}
	if err := certificate.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	cert := ssh.MarshalAuthorizedKey(certificate)
	for _, test := range []struct{ key, pass, cert []byte }{
		{pem.EncodeToMemory(plain), nil, nil},
		{pem.EncodeToMemory(plain), []byte("obsolete"), nil},
		{pem.EncodeToMemory(encrypted), []byte("phrase"), nil},
		{pem.EncodeToMemory(plain), nil, cert},
		{pem.EncodeToMemory(encrypted), []byte("phrase"), cert},
		{append(pem.EncodeToMemory(plain), cert...), nil, nil},
	} {
		parsed, err := ParseSigner(test.key, test.pass, test.cert)
		if err != nil {
			t.Fatal(err)
		}
		signers, err := ParseSigners(test.key, test.pass, test.cert)
		if err != nil {
			t.Fatal(err)
		}
		expected := 1
		if len(test.cert) > 0 || bytes.Contains(test.key, []byte("-cert-v01@openssh.com")) {
			expected = 2
			if _, ok := parsed.PublicKey().(*ssh.Certificate); !ok {
				t.Fatal("certificate was discarded")
			}
		}
		if len(signers) != expected || !bytes.Equal(signers[0].PublicKey().Marshal(), parsed.PublicKey().Marshal()) ||
			!bytes.Equal(signers[len(signers)-1].PublicKey().Marshal(), signer.PublicKey().Marshal()) {
			t.Fatal("authentication must offer the certificate first and the raw key last")
		}
		for _, offered := range signers {
			challenge := []byte("authentication fixture")
			signature, err := offered.Sign(rand.Reader, challenge)
			if err != nil || offered.PublicKey().Verify(challenge, signature) != nil {
				t.Fatal("offered key cannot sign an authentication challenge")
			}
		}
	}
	for _, test := range []struct{ key, pass, cert []byte }{
		{nil, nil, nil}, {[]byte(strings.Repeat("x", MaxKeyBytes+1)), nil, nil}, {pem.EncodeToMemory(plain), []byte(strings.Repeat("x", 16385)), nil},
		{[]byte("bad"), nil, nil}, {pem.EncodeToMemory(encrypted), []byte("wrong"), nil},
		{pem.EncodeToMemory(plain), nil, []byte("bad")}, {pem.EncodeToMemory(plain), nil, ssh.MarshalAuthorizedKey(signer.PublicKey())},
		{pem.EncodeToMemory(plain), nil, append(cert, cert...)},
	} {
		if _, err := ParseSigner(test.key, test.pass, test.cert); err == nil {
			t.Fatal("invalid key accepted")
		}
	}
	if _, err := ParseSigner(pem.EncodeToMemory(encrypted), nil, nil); err == nil {
		t.Fatal("missing passphrase accepted")
	} else {
		var missing *ssh.PassphraseMissingError
		if !errors.As(err, &missing) {
			t.Fatal(err)
		}
	}
	certificate.Key = ca.PublicKey()
	_ = certificate.SignCert(rand.Reader, ca)
	if _, err := ParseSigner(pem.EncodeToMemory(plain), nil, ssh.MarshalAuthorizedKey(certificate)); err == nil {
		t.Fatal("mismatched certificate accepted")
	}
	certificate.Key = signer.PublicKey()
	for _, window := range []struct{ after, before uint64 }{
		{0, 1}, {uint64(time.Now().Unix() + 3600), ssh.CertTimeInfinity},
	} {
		certificate.ValidAfter, certificate.ValidBefore = window.after, window.before
		if err := certificate.SignCert(rand.Reader, ca); err != nil {
			t.Fatal(err)
		}
		if signers, err := ParseSigners(pem.EncodeToMemory(plain), nil, ssh.MarshalAuthorizedKey(certificate)); err == nil || len(signers) != 0 {
			t.Fatal("invalid certificate validity must fail before offering the raw key")
		}
	}
}
