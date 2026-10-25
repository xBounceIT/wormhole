package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHUserCertificateRejectsTamperedSignatures(t *testing.T) {
	signer, _ := parseSSHSigner(testSshPrivateKey(t, ""), nil)
	cert, ca := testSSHCertificate(t, signer, ssh.UserCert, 0, ssh.CertTimeInfinity)
	// Critical options and principals are server policy, independent of integrity.
	cert.ValidPrincipals = []string{"a-server-managed-principal"}
	cert.CriticalOptions = map[string]string{"force-command": "managed-command", "vendor-option": "managed-value"}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	line := ssh.MarshalAuthorizedKey(cert)
	if _, err := parseSSHUserCertificate(line); err != nil {
		t.Fatalf("valid signed certificate was rejected by client policy: %v", err)
	}
	for name, mutate := range map[string]func(*ssh.Certificate){
		"signature bytes": func(c *ssh.Certificate) { c.Signature.Blob[0] ^= 0x80 },
		"signed metadata": func(c *ssh.Certificate) { c.KeyId += "-tampered" },
		"signing CA": func(c *ssh.Certificate) {
			other, _ := parseSSHSigner(testSshPrivateKey(t, ""), nil)
			c.SignatureKey = other.PublicKey()
		},
	} {
		t.Run(name, func(t *testing.T) {
			public, _, _, _, err := ssh.ParseAuthorizedKey(line)
			if err != nil {
				t.Fatal(err)
			}
			changed := public.(*ssh.Certificate)
			mutate(changed)
			if _, err := parseSSHUserCertificate(ssh.MarshalAuthorizedKey(changed)); err == nil || !strings.Contains(err.Error(), "signature") {
				t.Fatalf("tampered certificate was accepted: %v", err)
			}
		})
	}
}

func TestSSHCertificateSignatureVerificationPreservesValidityAndRSA(t *testing.T) {
	signer, _ := parseSSHSigner(testSshPrivateKey(t, ""), nil)
	privateCA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ssh.NewSignerFromKey(privateCA)
	if err != nil {
		t.Fatal(err)
	}
	for _, algorithm := range []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512} {
		t.Run(algorithm, func(t *testing.T) {
			authority, err := ssh.NewSignerWithAlgorithms(ca.(ssh.AlgorithmSigner), []string{algorithm})
			if err != nil {
				t.Fatal(err)
			}
			for _, window := range []struct{ after, before uint64 }{
				{0, ssh.CertTimeInfinity},
				{0, uint64(time.Now().Unix() - 3600)},
				{uint64(time.Now().Unix() + 3600), ssh.CertTimeInfinity},
			} {
				cert := &ssh.Certificate{Key: signer.PublicKey(), CertType: ssh.UserCert, ValidAfter: window.after, ValidBefore: window.before}
				if err := cert.SignCert(rand.Reader, authority); err != nil {
					t.Fatal(err)
				}
				if cert.Signature.Format != algorithm {
					t.Fatal("test did not use the requested CA algorithm")
				}
				if _, err := parseSSHUserCertificate(ssh.MarshalAuthorizedKey(cert)); err != nil {
					t.Fatalf("signature validation applied current validity policy: %v", err)
				}
			}
		})
	}
}

func TestSSHCertificateTamperingCannotChangeCredentialOrDial(t *testing.T) {
	_, _, protectedKeys, _ := installSshKeyCredentialTestStores(t)
	key := testSshPrivateKey(t, "")
	credentialPrivateKeyUnprotect = func(string) ([]byte, error) { return bytes.Clone(key), nil }
	signer, _ := parseSSHSigner(key, nil)
	cert, _ := testSSHCertificate(t, signer, ssh.UserCert, 0, ssh.CertTimeInfinity)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
	request := credentialCreateRequest{
		Name: "Signed certificate", Protocol: "ssh", Kind: "sshKey", Username: "operator",
		PrivateKeyPath: writeSSHTestFile(t, "id_key", key), CertificatePath: writeSSHTestFile(t, "id-cert.pub", []byte(line)),
	}
	dbPath := filepath.Join(t.TempDir(), "workspace.db")
	created, err := createCredential(dbPath, request)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := credentialPrivateKeyPath(dbPath, created.ID)
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	cert.KeyId += "-tampered"
	tampered := ssh.MarshalAuthorizedKey(cert)
	request.Name = "Rejected certificate"
	request.CertificatePath = writeSSHTestFile(t, "tampered-cert.pub", tampered)
	if _, err := createCredential(dbPath, request); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tampered certificate was imported: %v", err)
	}
	request.Name = created.Name
	request.PrivateKeyPath = ""
	if _, err := updateCredential(dbPath, credentialUpdateRequest{ID: created.ID, credentialCreateRequest: request}); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tampered certificate replaced valid metadata: %v", err)
	}
	db, err := openDatabase(dbPath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var stored, name string
	var count int
	if err := db.QueryRow("SELECT SshCertificate, SshCertificateFileName FROM CredentialProfiles WHERE Id = ?", created.ID).Scan(&stored, &name); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM CredentialProfiles").Scan(&count); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(keyPath)
	if err != nil || !bytes.Equal(before, after) || len(*protectedKeys) != 1 || stored != line || name != "id-cert.pub" || count != 1 {
		t.Fatal("rejected certificate changed the credential or protected key", err)
	}
	_, _, err = dialNativeSSH(context.Background(), sshTarget{host: "127.0.0.1", port: 0, username: "operator", privateKey: key, certificate: tampered}, 80, 24)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("runtime did not reject tampering before dialing: %v", err)
	}
}
