//go:build linux

package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
)

func TestLinuxCredentialSaveRetriesAfterSecretServiceBecomesAvailable(t *testing.T) {
	keyPath := writeSSHTestFile(t, "id_ed25519", testSshPrivateKey(t, ""))
	for _, draft := range []credentialCreateRequest{
		{Name: "SSH password", Protocol: "ssh", Username: "operator", Password: "test-password"},
		{Name: "SSH key", Protocol: "ssh", Username: "operator", Kind: "sshKey", PrivateKeyPath: keyPath},
	} {
		t.Run(draft.Name, func(t *testing.T) {
			databasePath := filepath.Join(t.TempDir(), "wormhole.db")
			keyring.MockInitWithError(errors.New("raw provider failure"))
			t.Cleanup(keyring.MockInit)
			_, err := createCredential(databasePath, draft)
			if err == nil || !strings.Contains(err.Error(), "freedesktop Secret Service") ||
				!strings.Contains(err.Error(), "unlock") || strings.Contains(err.Error(), "raw provider failure") {
				t.Fatalf("unexpected save diagnostic: %v", err)
			}
			db, err := openDatabase(databasePath, true)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var profiles, secrets int
			if err := db.QueryRow(`
SELECT (SELECT COUNT(*) FROM CredentialProfiles), (SELECT COUNT(*) FROM CredentialSecrets);
`).Scan(&profiles, &secrets); err != nil {
				t.Fatal(err)
			}
			if profiles != 0 || secrets != 0 {
				t.Fatalf("failed save left %d profiles and %d secrets", profiles, secrets)
			}

			keyring.MockInit()
			if _, err := createCredential(databasePath, draft); err != nil {
				t.Fatalf("retry failed: %v", err)
			}
		})
	}
}

func TestLinuxCredentialCertificateRenewalRetriesAfterKeyringReadFailure(t *testing.T) {
	installLinuxCredentialStoreMock(t)
	const passphrase = "test-passphrase"
	key := testSshPrivateKey(t, passphrase)
	signer, err := parseSSHSigner(key, []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := testSSHCertificate(t, signer, ssh.UserCert, 0, ssh.CertTimeInfinity)
	dbPath := filepath.Join(t.TempDir(), "wormhole.db")
	draft := credentialCreateRequest{
		Name: "SSH key", Protocol: "ssh", Kind: "sshKey", Username: "operator",
		PrivateKeyPath: writeSSHTestFile(t, "id_ed25519", key), Passphrase: passphrase,
	}
	created, err := createCredential(dbPath, draft)
	if err != nil {
		t.Fatal(err)
	}
	draft.PrivateKeyPath, draft.Passphrase = "", ""
	draft.CertificatePath = writeSSHTestFile(t, "renewed-cert.pub", ssh.MarshalAuthorizedKey(cert))
	request := credentialUpdateRequest{ID: created.ID, credentialCreateRequest: draft}
	get := linuxCredentialStore.get
	for _, tc := range []struct {
		failure error
		want    string
	}{
		{errors.New("provider failure: " + passphrase), "freedesktop Secret Service"},
		{keyring.ErrNotFound, "stored SSH secret could not be decrypted"},
	} {
		linuxCredentialStore.get = func(string, string) (string, error) { return "", tc.failure }
		if _, err := updateCredential(dbPath, request); err == nil || !strings.Contains(err.Error(), tc.want) ||
			strings.Contains(err.Error(), passphrase) {
			t.Fatalf("unexpected certificate renewal error: %v", err)
		}
	}
	linuxCredentialStore.get = get
	updated, err := updateCredential(dbPath, request)
	if err != nil || !updated.HasCertificate {
		t.Fatalf("certificate renewal retry failed: %v", err)
	}
}

func installLinuxCredentialStoreMock(t *testing.T) map[string]string {
	t.Helper()
	previousStore := linuxCredentialStore
	stored := make(map[string]string)
	linuxCredentialStore.set = func(service, account, value string) error {
		if service != "Wormhole" {
			t.Fatalf("service = %q", service)
		}
		stored[account] = value
		return nil
	}
	linuxCredentialStore.get = func(service, account string) (string, error) {
		if service != "Wormhole" {
			t.Fatalf("service = %q", service)
		}
		value, ok := stored[account]
		if !ok {
			return "", keyring.ErrNotFound
		}
		return value, nil
	}
	linuxCredentialStore.delete = func(service, account string) error {
		if service != "Wormhole" {
			t.Fatalf("service = %q", service)
		}
		if _, ok := stored[account]; !ok {
			return keyring.ErrNotFound
		}
		delete(stored, account)
		return nil
	}
	t.Cleanup(func() { linuxCredentialStore = previousStore })
	return stored
}

func TestLinuxVncSavedCredentialIDCase(t *testing.T) {
	installLinuxCredentialStoreMock(t)
	testVncSavedCredentialIDCase(t)
}

func TestLinuxCredentialSecretRoundTripUsesDBusKeyring(t *testing.T) {
	stored := installLinuxCredentialStoreMock(t)

	reference, encoding, err := storeCredentialSecret(credentialSecretKeyringTestID, "", "manual-password")
	if err != nil {
		t.Fatal(err)
	}
	if encoding != "linux-secret-service-dbus-v1" {
		t.Fatalf("encoding = %q", encoding)
	}
	secret, err := unprotectPlatformCredentialSecret(credentialSecretKeyringTestID, reference, encoding)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "manual-password" {
		t.Fatalf("secret = %q", secret)
	}
	if err := deleteStoredCredentialSecret(credentialSecretKeyringTestID, reference, encoding); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 0 {
		t.Fatalf("stored entries after delete = %d", len(stored))
	}
}
