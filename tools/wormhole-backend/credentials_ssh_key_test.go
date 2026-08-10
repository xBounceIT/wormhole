package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testSshPrivateKey(t *testing.T, passphrase string) []byte {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(privateKey, "wormhole test key")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(
			privateKey,
			"wormhole test key",
			[]byte(passphrase),
		)
	}
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}

func installSshKeyCredentialTestStores(t *testing.T) (*int, *[]string, *[][]byte, *[]string) {
	t.Helper()
	previousStore := credentialSecretStore
	previousDelete := credentialSecretDelete
	previousProtect := credentialPrivateKeyProtect
	previousUnprotect := credentialPrivateKeyUnprotect
	secretStores := 0
	deletedSecrets := make([]string, 0)
	protectedKeys := make([][]byte, 0)
	storedSecrets := make([]string, 0)
	credentialSecretStore = func(id, value string) (string, string, error) {
		secretStores++
		storedSecrets = append(storedSecrets, value)
		return "protected-secret-" + id + "-" + strconv.Itoa(secretStores), "test-protected-v1", nil
	}
	credentialSecretDelete = func(_ string, encoded, _ string) error {
		deletedSecrets = append(deletedSecrets, encoded)
		return nil
	}
	credentialPrivateKeyProtect = func(path string, plaintext []byte) error {
		protectedKeys = append(protectedKeys, append([]byte(nil), plaintext...))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("protected-key-placeholder"), 0o600)
	}
	credentialPrivateKeyUnprotect = func(string) ([]byte, error) {
		return nil, os.ErrNotExist
	}
	t.Cleanup(func() {
		credentialSecretStore = previousStore
		credentialSecretDelete = previousDelete
		credentialPrivateKeyProtect = previousProtect
		credentialPrivateKeyUnprotect = previousUnprotect
	})
	return &secretStores, &deletedSecrets, &protectedKeys, &storedSecrets
}

func TestSshKeyCredentialCreateStoresProtectedKeyAndPassphrase(t *testing.T) {
	secretStores, deletedSecrets, protectedKeys, storedSecrets := installSshKeyCredentialTestStores(t)
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	privateKey := testSshPrivateKey(t, "key-passphrase")
	if err := os.WriteFile(keyPath, privateKey, 0o600); err != nil {
		t.Fatal(err)
	}

	created, err := createCredential(databasePath, credentialCreateRequest{
		Name: "Production key", Protocol: "ssh", Kind: "sshKey", Username: "operator",
		Passphrase: "key-passphrase", PrivateKeyPath: keyPath, Provider: "Local",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Kind != "sshKey" || created.Protocol != "ssh" || created.Username != "operator" ||
		created.PrivateKeyFileName != "id_ed25519" || !created.CanEdit || !created.CanDelete {
		t.Fatalf("created SSH key credential = %#v", created)
	}
	if *secretStores != 1 || len(*storedSecrets) != 1 || (*storedSecrets)[0] != "key-passphrase" ||
		len(*protectedKeys) != 1 || !bytes.Equal((*protectedKeys)[0], privateKey) {
		t.Fatalf("protected writes = secrets:%d keys:%d", *secretStores, len(*protectedKeys))
	}

	database, err := openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var kind, protocol, provider int
	var fileName, encoded string
	if err := database.QueryRow(`
SELECT p.Kind, p.Protocol, p.SecretProvider, p.PrivateKeyFileName, s.Secret
FROM CredentialProfiles p JOIN CredentialSecrets s ON s.Id = p.Id
WHERE p.Id = ?;`, created.ID).Scan(&kind, &protocol, &provider, &fileName, &encoded); err != nil {
		t.Fatal(err)
	}
	if kind != 1 || protocol != 0 || provider != 0 || fileName != "id_ed25519" ||
		strings.Contains(encoded, "key-passphrase") {
		t.Fatalf("stored SSH key metadata = kind:%d protocol:%d provider:%d file:%q secret:%q", kind, protocol, provider, fileName, encoded)
	}
	protectedPath := credentialPrivateKeyPath(databasePath, created.ID)
	protectedContents, err := os.ReadFile(protectedPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(protectedContents, privateKey) {
		t.Fatal("the private key was written to its protected destination as plaintext")
	}

	workspace, err := loadWorkspace(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(workspace.Credentials) != 1 || workspace.Credentials[0].Kind != "sshKey" ||
		!workspace.Credentials[0].CanEdit || workspace.Credentials[0].PrivateKeyFileName != "id_ed25519" {
		t.Fatalf("workspace SSH key credential = %#v", workspace.Credentials)
	}
	if err := deleteCredential(databasePath, credentialDeleteRequest{ID: created.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(protectedPath); !os.IsNotExist(err) {
		t.Fatalf("protected private key was not deleted: %v", err)
	}
	if len(*deletedSecrets) != 1 || (*deletedSecrets)[0] != encoded {
		t.Fatalf("passphrase cleanup = %#v", *deletedSecrets)
	}
}

func TestSshKeyCredentialAllowsRuntimePassphrasePrompt(t *testing.T) {
	secretStores, _, protectedKeys, _ := installSshKeyCredentialTestStores(t)
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	keyPath := filepath.Join(t.TempDir(), "encrypted.pem")
	if err := os.WriteFile(keyPath, testSshPrivateKey(t, "ask-at-runtime"), 0o600); err != nil {
		t.Fatal(err)
	}
	created, err := createCredential(databasePath, credentialCreateRequest{
		Name: "Prompting key", Protocol: "ssh", Kind: "sshKey", Username: "operator",
		PrivateKeyPath: keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if *secretStores != 0 || len(*protectedKeys) != 1 {
		t.Fatalf("unexpected protected writes = secrets:%d keys:%d", *secretStores, len(*protectedKeys))
	}
	database, err := openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM CredentialSecrets WHERE Id = ?;", created.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("passphrase row count = %d, want 0", count)
	}
}

func TestSshKeyCredentialPreservesSelectedPathExactly(t *testing.T) {
	installSshKeyCredentialTestStores(t)
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	keyPath := filepath.Join(t.TempDir(), " key.pem")
	if err := os.WriteFile(keyPath, testSshPrivateKey(t, ""), 0o600); err != nil {
		t.Fatal(err)
	}
	created, err := createCredential(databasePath, credentialCreateRequest{
		Name: "Key with spaced path", Protocol: "ssh", Kind: "sshKey", Username: "operator",
		PrivateKeyPath: keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.PrivateKeyFileName != " key.pem" {
		t.Fatalf("private key file name = %q, want exact selected name", created.PrivateKeyFileName)
	}
	workspace, err := loadWorkspace(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(workspace.Credentials) != 1 || workspace.Credentials[0].PrivateKeyFileName != " key.pem" {
		t.Fatalf("reloaded private key file name = %#v", workspace.Credentials)
	}
}

func TestSshKeyCredentialRejectsInvalidKeyAndPassphrase(t *testing.T) {
	_, _, protectedKeys, _ := installSshKeyCredentialTestStores(t)
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	tests := []struct {
		name       string
		contents   []byte
		passphrase string
		want       string
	}{
		{"not a key", []byte("not a private key"), "", "not a supported SSH private key"},
		{"wrong passphrase", testSshPrivateKey(t, "correct"), "wrong", "passphrase is incorrect"},
		{"passphrase for clear key", testSshPrivateKey(t, ""), "unneeded", "is not encrypted"},
		{"oversized key", make([]byte, maxSshPrivateKeyBytes+1), "", "invalid or too large"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keyPath := filepath.Join(t.TempDir(), "key.pem")
			if err := os.WriteFile(keyPath, test.contents, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := createCredential(databasePath, credentialCreateRequest{
				Name: test.name, Protocol: "ssh", Kind: "sshKey", Username: "operator",
				Passphrase: test.passphrase, PrivateKeyPath: keyPath,
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("create error = %v, want %q", err, test.want)
			}
		})
	}
	if len(*protectedKeys) != 0 {
		t.Fatalf("invalid keys reached protected storage: %d", len(*protectedKeys))
	}
}

func TestSshKeyCredentialCreateCleansProtectedArtifactsWhenDatabaseWriteFails(t *testing.T) {
	_, deletedSecrets, protectedKeys, _ := installSshKeyCredentialTestStores(t)
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureCredentialWriteSchema(database); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if _, err := database.Exec(`
CREATE TRIGGER reject_ssh_key_credential
BEFORE INSERT ON CredentialProfiles
BEGIN
    SELECT RAISE(FAIL, 'simulated write failure');
END;`); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, testSshPrivateKey(t, "passphrase"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = createCredential(databasePath, credentialCreateRequest{
		Name: "Rejected key", Protocol: "ssh", Kind: "sshKey", Username: "operator",
		Passphrase: "passphrase", PrivateKeyPath: keyPath,
	})
	if err == nil {
		t.Fatal("SSH key creation should fail when the profile insert is rejected")
	}
	if len(*protectedKeys) != 1 || len(*deletedSecrets) != 1 {
		t.Fatalf("failed create cleanup = keys:%d secrets:%#v", len(*protectedKeys), *deletedSecrets)
	}
	entries, err := os.ReadDir(filepath.Join(filepath.Dir(databasePath), "keys"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed create left protected key files: %#v", entries)
	}
}

func TestSshKeyCredentialReplacementRollbackRestoresProtectedFile(t *testing.T) {
	installSshKeyCredentialTestStores(t)
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	id := "11111111-1111-4111-8111-111111111111"
	keyPath := credentialPrivateKeyPath(databasePath, id)
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := []byte("previous-protected-key")
	if err := os.WriteFile(keyPath, previous, 0o600); err != nil {
		t.Fatal(err)
	}
	rollback, err := replaceCredentialPrivateKey(databasePath, id, []byte("replacement-plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	replaced, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(replaced, previous) {
		t.Fatal("replacement did not update the protected key file")
	}
	rollback()
	restored, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, previous) {
		t.Fatalf("rollback restored %q, want %q", restored, previous)
	}
}

func TestSshKeyCredentialUpdateReplacesKeyAndSecretAtomically(t *testing.T) {
	_, deletedSecrets, protectedKeys, storedSecrets := installSshKeyCredentialTestStores(t)
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	firstPath := filepath.Join(t.TempDir(), "first.pem")
	secondPath := filepath.Join(t.TempDir(), "second.pem")
	if err := os.WriteFile(firstPath, testSshPrivateKey(t, "first-passphrase"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondPath, testSshPrivateKey(t, "second-passphrase"), 0o600); err != nil {
		t.Fatal(err)
	}
	created, err := createCredential(databasePath, credentialCreateRequest{
		Name: "SSH key", Protocol: "ssh", Kind: "sshKey", Username: "first-user",
		Passphrase: "first-passphrase", PrivateKeyPath: firstPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := updateCredential(databasePath, credentialUpdateRequest{
		ID: created.ID,
		credentialCreateRequest: credentialCreateRequest{
			Name: "Updated SSH key", Protocol: "ssh", Kind: "sshKey", Username: "second-user",
			Passphrase: "second-passphrase", PrivateKeyPath: secondPath,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Kind != "sshKey" || updated.Username != "second-user" || updated.PrivateKeyFileName != "second.pem" {
		t.Fatalf("updated SSH key credential = %#v", updated)
	}
	if len(*protectedKeys) != 2 || len(*storedSecrets) != 2 || (*storedSecrets)[0] != "first-passphrase" ||
		(*storedSecrets)[1] != "second-passphrase" || len(*deletedSecrets) != 1 {
		t.Fatalf("replacement cleanup = keys:%d secrets:%#v", len(*protectedKeys), *deletedSecrets)
	}

	metadataOnly, err := updateCredential(databasePath, credentialUpdateRequest{
		ID: created.ID,
		credentialCreateRequest: credentialCreateRequest{
			Name: "Renamed SSH key", Protocol: "ssh", Kind: "sshKey", Username: "third-user",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if metadataOnly.PrivateKeyFileName != "second.pem" || len(*protectedKeys) != 2 || len(*deletedSecrets) != 1 {
		t.Fatalf("metadata update changed key state: %#v keys:%d secrets:%#v", metadataOnly, len(*protectedKeys), *deletedSecrets)
	}

	database, err := openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var secret sql.NullString
	if err := database.QueryRow("SELECT Secret FROM CredentialSecrets WHERE Id = ?;", created.ID).Scan(&secret); err != nil {
		t.Fatal(err)
	}
	if !secret.Valid || strings.Contains(secret.String, "second-passphrase") {
		t.Fatalf("replacement passphrase = %#v", secret)
	}
}

func TestSshKeyCredentialUpdateCanForgetSavedPassphrase(t *testing.T) {
	_, deletedSecrets, protectedKeys, _ := installSshKeyCredentialTestStores(t)
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	keyPath := filepath.Join(t.TempDir(), "encrypted.pem")
	if err := os.WriteFile(keyPath, testSshPrivateKey(t, "saved-passphrase"), 0o600); err != nil {
		t.Fatal(err)
	}
	created, err := createCredential(databasePath, credentialCreateRequest{
		Name: "Saved passphrase", Protocol: "ssh", Kind: "sshKey", Username: "operator",
		Passphrase: "saved-passphrase", PrivateKeyPath: keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := updateCredential(databasePath, credentialUpdateRequest{
		ID: created.ID,
		credentialCreateRequest: credentialCreateRequest{
			Name: "Prompt instead", Protocol: "ssh", Kind: "sshKey", Username: "operator",
			ClearPassphrase: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.PrivateKeyFileName != "encrypted.pem" || len(*protectedKeys) != 1 || len(*deletedSecrets) != 1 {
		t.Fatalf("forget passphrase result = %#v keys:%d deleted:%#v", updated, len(*protectedKeys), *deletedSecrets)
	}
	database, err := openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM CredentialSecrets WHERE Id = ?;", created.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("passphrase row count = %d, want 0", count)
	}
}

func TestSshKeyCredentialDeletePreservesProfileWhenKeyRemovalFails(t *testing.T) {
	installSshKeyCredentialTestStores(t)
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	keyPath := filepath.Join(t.TempDir(), "encrypted.pem")
	if err := os.WriteFile(keyPath, testSshPrivateKey(t, "saved-passphrase"), 0o600); err != nil {
		t.Fatal(err)
	}
	created, err := createCredential(databasePath, credentialCreateRequest{
		Name: "Removal failure", Protocol: "ssh", Kind: "sshKey", Username: "operator",
		Passphrase: "saved-passphrase", PrivateKeyPath: keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	previousRemove := credentialPrivateKeyStageRemove
	credentialPrivateKeyStageRemove = func(string) error { return os.ErrPermission }
	t.Cleanup(func() { credentialPrivateKeyStageRemove = previousRemove })

	err = deleteCredential(databasePath, credentialDeleteRequest{ID: created.ID})
	if err == nil || !strings.Contains(err.Error(), "protected SSH private key") {
		t.Fatalf("delete error = %v", err)
	}
	if _, err := os.Stat(credentialPrivateKeyPath(databasePath, created.ID)); err != nil {
		t.Fatalf("protected key should remain after failed deletion: %v", err)
	}
	database, err := openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var profiles, secrets int
	if err := database.QueryRow("SELECT COUNT(*) FROM CredentialProfiles WHERE Id = ?;", created.ID).Scan(&profiles); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow("SELECT COUNT(*) FROM CredentialSecrets WHERE Id = ?;", created.ID).Scan(&secrets); err != nil {
		t.Fatal(err)
	}
	if profiles != 1 || secrets != 1 {
		t.Fatalf("failed deletion left profiles:%d secrets:%d, want 1 each", profiles, secrets)
	}
}

func TestSshKeyCredentialValidationRejectsIncompatibleContracts(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	tests := []credentialCreateRequest{
		{Name: "Missing key", Protocol: "ssh", Kind: "sshKey", Username: "user"},
		{Name: "Clear on create", Protocol: "ssh", Kind: "sshKey", Username: "user", ClearPassphrase: true, PrivateKeyPath: keyPath},
		{Name: "Clear password", Protocol: "ssh", Kind: "password", Username: "user", Password: "password", ClearPassphrase: true},
		{Name: "RDP key", Protocol: "rdp", Kind: "sshKey", Username: "user", Domain: "domain", PrivateKeyPath: keyPath},
		{Name: "Bitwarden key", Protocol: "ssh", Kind: "sshKey", Username: "user", Provider: "Bitwarden", BitwardenItemID: "item", PrivateKeyPath: keyPath},
		{Name: "Mixed secret", Protocol: "ssh", Kind: "sshKey", Username: "user", Password: "password", PrivateKeyPath: keyPath},
	}
	for _, request := range tests {
		if _, err := normalizeCredentialDraft(request, false); err == nil {
			t.Fatalf("incompatible SSH key request was accepted: %#v", request)
		}
	}
}
