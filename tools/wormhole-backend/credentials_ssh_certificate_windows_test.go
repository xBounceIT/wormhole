//go:build windows

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSSHCertificateRenewalReadsLegacyElectronPassphrase(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for format, key := range map[string][]byte{
		"OpenSSH": testSshPrivateKey(t, "stored-passphrase"),
		"PKCS8":   testPKCS8Key(t, private, "stored-passphrase", false, "2.16.840.1.101.3.4.1.42"),
	} {
		t.Run(format, func(t *testing.T) {
			_, _, protectedKeys, _ := installSshKeyCredentialTestStores(t)
			credentialPrivateKeyUnprotect = func(string) ([]byte, error) { return bytes.Clone(key), nil }
			signer, _ := parseSSHSigner(key, []byte("stored-passphrase"))
			cert, _ := testSSHCertificate(t, signer, ssh.UserCert, 0, ssh.CertTimeInfinity)
			dbPath := filepath.Join(t.TempDir(), "workspace.db")
			request := credentialCreateRequest{Name: "Legacy SSH key", Protocol: "ssh", Kind: "sshKey", Username: "operator", PrivateKeyPath: writeSSHTestFile(t, "id_key", key)}
			created, err := createCredential(dbPath, request)
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(credentialPrivateKeyPath(dbPath, created.ID))
			if err != nil {
				t.Fatal(err)
			}
			userDataPath := t.TempDir()
			encoded := writeElectronSafeStorageFixture(t, userDataPath, "stored-passphrase", []byte("01234567890123456789012345678901"))
			db, err := openDatabase(dbPath, false)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec("INSERT INTO CredentialSecrets (Id,Secret,Encoding,UpdatedAt) VALUES (?,?,?,'now')", created.ID, encoded, electronSafeStorageSecretEncoding); err != nil {
				t.Fatal(err)
			}
			request.PrivateKeyPath = ""
			request.CertificatePath = writeSSHTestFile(t, "renewed-cert.pub", ssh.MarshalAuthorizedKey(cert))
			updated, err := updateCredential(dbPath, credentialUpdateRequest{ID: created.ID, credentialCreateRequest: request}, userDataPath)
			if err != nil || !updated.HasCertificate {
				t.Fatalf("renewal lost the migrated passphrase: %v", err)
			}
			other, _ := parseSSHSigner(testSshPrivateKey(t, ""), nil)
			wrong, _ := testSSHCertificate(t, other, ssh.UserCert, 0, ssh.CertTimeInfinity)
			request.CertificatePath = writeSSHTestFile(t, "wrong-cert.pub", ssh.MarshalAuthorizedKey(wrong))
			if _, err := updateCredential(dbPath, credentialUpdateRequest{ID: created.ID, credentialCreateRequest: request}, userDataPath); err == nil || !strings.Contains(err.Error(), "does not match") {
				t.Fatalf("expected certificate mismatch: %v", err)
			}
			after, _ := os.ReadFile(credentialPrivateKeyPath(dbPath, created.ID))
			if !bytes.Equal(before, after) || len(*protectedKeys) != 1 {
				t.Fatal("renewal rewrote the protected key")
			}
			var stored string
			if err := db.QueryRow("SELECT Secret FROM CredentialSecrets WHERE Id = ?", created.ID).Scan(&stored); err != nil || stored != encoded {
				t.Fatalf("renewal changed the stored passphrase: %v", err)
			}
		})
	}
}
