package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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

func testProtectedKeyContents(plaintext []byte) []byte {
	digest := sha256.Sum256(plaintext)
	return append([]byte("protected-key-placeholder-"), []byte(hex.EncodeToString(digest[:]))...)
}

func installSshKeyCredentialTestStores(t *testing.T) (*int, *[]string, *[][]byte, *[]string) {
	t.Helper()
	previousStore := credentialSecretStore
	previousDelete := credentialSecretDelete
	previousStageProtect := credentialPrivateKeyStageProtect
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
	credentialPrivateKeyStageProtect = func(_ string, pendingPath string, plaintext []byte) error {
		protectedKeys = append(protectedKeys, append([]byte(nil), plaintext...))
		if err := os.MkdirAll(filepath.Dir(pendingPath), 0o700); err != nil {
			return err
		}
		return os.WriteFile(pendingPath, testProtectedKeyContents(plaintext), 0o600)
	}
	credentialPrivateKeyUnprotect = func(string) ([]byte, error) {
		return nil, os.ErrNotExist
	}
	t.Cleanup(func() {
		credentialSecretStore = previousStore
		credentialSecretDelete = previousDelete
		credentialPrivateKeyStageProtect = previousStageProtect
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

func TestSshKeyCredentialRecoveryDiscardsUncommittedCreation(t *testing.T) {
	installSshKeyCredentialTestStores(t)
	previousProtectionDelete := credentialPrivateKeyProtectionDelete
	deletedProtectionKeys := make([]string, 0)
	credentialPrivateKeyProtectionDelete = func(path string) {
		deletedProtectionKeys = append(deletedProtectionKeys, path)
	}
	t.Cleanup(func() { credentialPrivateKeyProtectionDelete = previousProtectionDelete })
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	id := "11111111-1111-4111-8111-111111111111"
	staged, err := stageCredentialPrivateKeyWrite(databasePath, id, []byte("new-private-key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := recoverCredentialPrivateKeyOperations(databasePath); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{staged.finalPath, staged.pendingPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("uncommitted creation left protected key %q: %v", path, err)
		}
	}
	if len(deletedProtectionKeys) != 1 || deletedProtectionKeys[0] != staged.finalPath {
		t.Fatalf("uncommitted creation keyring cleanup = %#v", deletedProtectionKeys)
	}
}

func TestSshKeyCredentialRecoveryFinishesCommittedCreation(t *testing.T) {
	installSshKeyCredentialTestStores(t)
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if err := ensureElectronWorkspaceSchema(databasePath); err != nil {
		t.Fatal(err)
	}
	id := "11111111-1111-4111-8111-111111111111"
	staged, err := stageCredentialPrivateKeyWrite(databasePath, id, []byte("new-private-key"))
	if err != nil {
		t.Fatal(err)
	}
	pending, err := os.ReadFile(staged.pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`
INSERT INTO CredentialProfiles
    (Id, Name, Username, Domain, Kind, PrivateKeyFileName, Protocol, SecretProvider,
     BitwardenItemId, BitwardenItemName, BitwardenFieldPath, CreatedAt)
VALUES (?, 'SSH key', 'operator', NULL, 1, 'id_ed25519', 0, 0, NULL, NULL, '', ?);`,
		id, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := recordCredentialPrivateKeyCreation(tx, staged); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	_ = database.Close()
	if _, err := os.Stat(staged.finalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("committed creation activated protected key before recovery: %v", err)
	}
	if err := recoverCredentialPrivateKeyOperations(databasePath); err != nil {
		t.Fatal(err)
	}
	final, err := os.ReadFile(staged.finalPath)
	if err != nil || !bytes.Equal(final, pending) {
		t.Fatalf("committed creation recovered %q, want %q: %v", final, pending, err)
	}
	if _, err := os.Stat(staged.pendingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("committed creation stage survived recovery: %v", err)
	}
	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var operations int
	if err := database.QueryRow("SELECT COUNT(*) FROM CredentialPrivateKeyOperations;").Scan(&operations); err != nil {
		t.Fatal(err)
	}
	if operations != 0 {
		t.Fatalf("completed creation operations = %d, want 0", operations)
	}
}

func TestSshKeyCredentialReplacementRollbackLeavesProtectedFileUntouched(t *testing.T) {
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
	staged, err := stageCredentialPrivateKeyWrite(databasePath, id, []byte("replacement-plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current, previous) {
		t.Fatalf("staging changed the protected key to %q", current)
	}
	if _, err := os.Stat(staged.pendingPath); err != nil {
		t.Fatalf("pending replacement was not written: %v", err)
	}
	staged.rollback()
	if _, err := os.Stat(staged.pendingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending replacement survived rollback: %v", err)
	}
	current, err = os.ReadFile(keyPath)
	if err != nil || !bytes.Equal(current, previous) {
		t.Fatalf("rollback changed protected key to %q: %v", current, err)
	}
}

func TestSshKeyCredentialRecoveryDiscardsUncommittedReplacement(t *testing.T) {
	installSshKeyCredentialTestStores(t)
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	firstPath := filepath.Join(t.TempDir(), "first.pem")
	if err := os.WriteFile(firstPath, testSshPrivateKey(t, "first-passphrase"), 0o600); err != nil {
		t.Fatal(err)
	}
	created, err := createCredential(databasePath, credentialCreateRequest{
		Name: "SSH key", Protocol: "ssh", Kind: "sshKey", Username: "operator",
		Passphrase: "first-passphrase", PrivateKeyPath: firstPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	finalPath := credentialPrivateKeyPath(databasePath, created.ID)
	before, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := stageCredentialPrivateKeyWrite(
		databasePath,
		created.ID,
		testSshPrivateKey(t, "second-passphrase"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := recoverCredentialPrivateKeyOperations(databasePath); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(finalPath)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("uncommitted recovery changed protected key to %q: %v", after, err)
	}
	if _, err := os.Stat(staged.pendingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("uncommitted stage survived recovery: %v", err)
	}
}

func TestSshKeyCredentialRecoveryPromotesCommittedReplacement(t *testing.T) {
	installSshKeyCredentialTestStores(t)
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	firstPath := filepath.Join(t.TempDir(), "first.pem")
	if err := os.WriteFile(firstPath, testSshPrivateKey(t, "first-passphrase"), 0o600); err != nil {
		t.Fatal(err)
	}
	created, err := createCredential(databasePath, credentialCreateRequest{
		Name: "SSH key", Protocol: "ssh", Kind: "sshKey", Username: "operator",
		Passphrase: "first-passphrase", PrivateKeyPath: firstPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	finalPath := credentialPrivateKeyPath(databasePath, created.ID)
	before, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := stageCredentialPrivateKeyWrite(
		databasePath,
		created.ID,
		testSshPrivateKey(t, "second-passphrase"),
	)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := os.ReadFile(staged.pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(
		"UPDATE CredentialProfiles SET PrivateKeyFileName = ? WHERE Id = ?;",
		"second.pem",
		created.ID,
	); err != nil {
		t.Fatal(err)
	}
	if err := recordCredentialPrivateKeyReplacement(tx, staged); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	_ = database.Close()
	stillOld, err := os.ReadFile(finalPath)
	if err != nil || !bytes.Equal(stillOld, before) {
		t.Fatalf("commit replaced protected key before recovery: %q, %v", stillOld, err)
	}
	if err := recoverCredentialPrivateKeyOperations(databasePath); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(finalPath)
	if err != nil || !bytes.Equal(after, pending) {
		t.Fatalf("committed recovery promoted %q, want %q: %v", after, pending, err)
	}
	if _, err := os.Stat(staged.pendingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("committed stage survived recovery: %v", err)
	}
	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var operations int
	if err := database.QueryRow("SELECT COUNT(*) FROM CredentialPrivateKeyOperations;").Scan(&operations); err != nil {
		t.Fatal(err)
	}
	if operations != 0 {
		t.Fatalf("completed recovery operations = %d, want 0", operations)
	}
}

func TestSshKeyCredentialRecoveryRecognizesPromotedReplacement(t *testing.T) {
	installSshKeyCredentialTestStores(t)
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if err := ensureElectronWorkspaceSchema(databasePath); err != nil {
		t.Fatal(err)
	}
	id := "11111111-1111-4111-8111-111111111111"
	staged, err := stageCredentialPrivateKeyWrite(databasePath, id, []byte("replacement"))
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := recordCredentialPrivateKeyReplacement(tx, staged); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	_ = database.Close()
	if err := credentialPrivateKeyPromote(staged.pendingPath, staged.finalPath); err != nil {
		t.Fatal(err)
	}
	if err := recoverCredentialPrivateKeyOperations(databasePath); err != nil {
		t.Fatal(err)
	}
	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var operations int
	if err := database.QueryRow("SELECT COUNT(*) FROM CredentialPrivateKeyOperations;").Scan(&operations); err != nil {
		t.Fatal(err)
	}
	if operations != 0 {
		t.Fatalf("already promoted recovery operations = %d, want 0", operations)
	}
}

func TestSshKeyCredentialDeleteWaitsForCommittedReplacement(t *testing.T) {
	installSshKeyCredentialTestStores(t)
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	keyPath := filepath.Join(t.TempDir(), "encrypted.pem")
	if err := os.WriteFile(keyPath, testSshPrivateKey(t, "saved-passphrase"), 0o600); err != nil {
		t.Fatal(err)
	}
	created, err := createCredential(databasePath, credentialCreateRequest{
		Name: "Concurrent replacement", Protocol: "ssh", Kind: "sshKey", Username: "operator",
		Passphrase: "saved-passphrase", PrivateKeyPath: keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	finalPath := credentialPrivateKeyPath(databasePath, created.ID)
	before, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := stageCredentialPrivateKeyWrite(databasePath, created.ID, []byte("replacement"))
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := recordCredentialPrivateKeyReplacement(tx, staged); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	_ = database.Close()

	if _, err := updateCredential(databasePath, credentialUpdateRequest{
		ID: created.ID,
		credentialCreateRequest: credentialCreateRequest{
			Name: "Concurrent replacement", Protocol: "ssh", Kind: "sshKey", Username: "operator",
		},
	}); err == nil || !strings.Contains(err.Error(), "still being finalized") {
		t.Fatalf("update during replacement error = %v", err)
	}
	if err := deleteCredential(databasePath, credentialDeleteRequest{ID: created.ID}); err == nil ||
		!strings.Contains(err.Error(), "still being finalized") {
		t.Fatalf("delete during replacement error = %v", err)
	}
	current, err := os.ReadFile(finalPath)
	if err != nil || !bytes.Equal(current, before) {
		t.Fatalf("concurrent delete changed protected key to %q: %v", current, err)
	}
	if _, err := os.Stat(staged.pendingPath); err != nil {
		t.Fatalf("concurrent delete removed replacement stage: %v", err)
	}
	if err := recoverCredentialPrivateKeyOperations(databasePath); err != nil {
		t.Fatal(err)
	}
	if err := deleteCredential(databasePath, credentialDeleteRequest{ID: created.ID}); err != nil {
		t.Fatalf("delete after replacement recovery: %v", err)
	}
}

func TestSshKeyCredentialRecoveryRejectsAlteredReplacement(t *testing.T) {
	installSshKeyCredentialTestStores(t)
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if err := ensureElectronWorkspaceSchema(databasePath); err != nil {
		t.Fatal(err)
	}
	id := "11111111-1111-4111-8111-111111111111"
	finalPath := credentialPrivateKeyPath(databasePath, id)
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte("original-protected-key")
	if err := os.WriteFile(finalPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	staged, err := stageCredentialPrivateKeyWrite(databasePath, id, []byte("replacement"))
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := recordCredentialPrivateKeyReplacement(tx, staged); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	_ = database.Close()
	if err := os.WriteFile(staged.pendingPath, []byte("altered-protected-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverCredentialPrivateKeyOperations(databasePath); err == nil {
		t.Fatal("altered SSH private key replacement was recovered")
	}
	current, err := os.ReadFile(finalPath)
	if err != nil || !bytes.Equal(current, original) {
		t.Fatalf("failed recovery changed protected key to %q: %v", current, err)
	}
	if _, err := os.Stat(staged.pendingPath); err != nil {
		t.Fatalf("failed recovery removed pending evidence: %v", err)
	}
	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var operations int
	if err := database.QueryRow("SELECT COUNT(*) FROM CredentialPrivateKeyOperations;").Scan(&operations); err != nil {
		t.Fatal(err)
	}
	if operations != 1 {
		t.Fatalf("failed recovery operations = %d, want 1", operations)
	}
}

func TestSshKeyCredentialDeleteRollbackRestoresDurableStage(t *testing.T) {
	installSshKeyCredentialTestStores(t)
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	keyPath := filepath.Join(t.TempDir(), "encrypted.pem")
	if err := os.WriteFile(keyPath, testSshPrivateKey(t, "saved-passphrase"), 0o600); err != nil {
		t.Fatal(err)
	}
	created, err := createCredential(databasePath, credentialCreateRequest{
		Name: "Rejected deletion", Protocol: "ssh", Kind: "sshKey", Username: "operator",
		Passphrase: "saved-passphrase", PrivateKeyPath: keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`
CREATE TRIGGER reject_private_key_deletion_journal
BEFORE INSERT ON CredentialPrivateKeyOperations
WHEN NEW.OperationKind = 'delete'
BEGIN
    SELECT RAISE(FAIL, 'simulated deletion journal failure');
END;`); err != nil {
		database.Close()
		t.Fatal(err)
	}
	_ = database.Close()

	if err := deleteCredential(databasePath, credentialDeleteRequest{ID: created.ID}); err == nil {
		t.Fatal("SSH key deletion should fail when its journal insert is rejected")
	}
	finalPath := credentialPrivateKeyPath(databasePath, created.ID)
	if _, err := os.Stat(finalPath); err != nil {
		t.Fatalf("rollback did not restore protected SSH key: %v", err)
	}
	if _, err := os.Stat(finalPath + credentialPrivateKeyDeletingSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback left durable deletion stage: %v", err)
	}
	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var profiles int
	if err := database.QueryRow("SELECT COUNT(*) FROM CredentialProfiles WHERE Id = ?;", created.ID).Scan(&profiles); err != nil {
		t.Fatal(err)
	}
	if profiles != 1 {
		t.Fatalf("rollback profile count = %d, want 1", profiles)
	}
}

func TestSshKeyCredentialDeletionStagingRejectsChangedFile(t *testing.T) {
	installSshKeyCredentialTestStores(t)
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	id := "11111111-1111-4111-8111-111111111111"
	finalPath := credentialPrivateKeyPath(databasePath, id)
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(finalPath, []byte("original-protected-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousDelete := credentialPrivateKeyStageDelete
	credentialPrivateKeyStageDelete = func(source, target string) error {
		if err := os.Rename(source, target); err != nil {
			return err
		}
		return os.WriteFile(target, []byte("changed-protected-key"), 0o600)
	}
	t.Cleanup(func() { credentialPrivateKeyStageDelete = previousDelete })

	if _, err := stageCredentialPrivateKeyDeletion(databasePath, id); err == nil {
		t.Fatal("changed SSH private key deletion stage was accepted")
	}
	if _, err := os.Stat(finalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("changed deletion stage was restored over the original path: %v", err)
	}
	if _, err := os.Stat(finalPath + credentialPrivateKeyDeletingSuffix); err != nil {
		t.Fatalf("changed deletion stage evidence was not preserved: %v", err)
	}
}

func TestSshKeyCredentialRecoveryRestoresUncommittedDeletion(t *testing.T) {
	installSshKeyCredentialTestStores(t)
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	keyPath := filepath.Join(t.TempDir(), "encrypted.pem")
	if err := os.WriteFile(keyPath, testSshPrivateKey(t, "saved-passphrase"), 0o600); err != nil {
		t.Fatal(err)
	}
	created, err := createCredential(databasePath, credentialCreateRequest{
		Name: "Interrupted deletion", Protocol: "ssh", Kind: "sshKey", Username: "operator",
		Passphrase: "saved-passphrase", PrivateKeyPath: keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	finalPath := credentialPrivateKeyPath(databasePath, created.ID)
	before, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("DELETE FROM CredentialProfiles WHERE Id = ?;", created.ID); err != nil {
		t.Fatal(err)
	}
	staged, err := stageCredentialPrivateKeyDeletion(databasePath, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := recordCredentialPrivateKeyDeletion(tx, staged); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	_ = database.Close()
	if _, err := os.Stat(finalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("interrupted deletion unexpectedly retained final key: %v", err)
	}
	if err := recoverCredentialPrivateKeyOperations(databasePath); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(finalPath)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("recovery restored protected key %q, want %q: %v", after, before, err)
	}
	if _, err := os.Stat(staged.stagedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("uncommitted deletion stage survived recovery: %v", err)
	}
}

func TestSshKeyCredentialRecoveryFinishesCommittedDeletion(t *testing.T) {
	installSshKeyCredentialTestStores(t)
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	keyPath := filepath.Join(t.TempDir(), "encrypted.pem")
	if err := os.WriteFile(keyPath, testSshPrivateKey(t, "saved-passphrase"), 0o600); err != nil {
		t.Fatal(err)
	}
	created, err := createCredential(databasePath, credentialCreateRequest{
		Name: "Committed deletion", Protocol: "ssh", Kind: "sshKey", Username: "operator",
		Passphrase: "saved-passphrase", PrivateKeyPath: keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	finalPath := credentialPrivateKeyPath(databasePath, created.ID)
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("DELETE FROM CredentialProfiles WHERE Id = ?;", created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("DELETE FROM CredentialSecrets WHERE Id = ?;", created.ID); err != nil {
		t.Fatal(err)
	}
	staged, err := stageCredentialPrivateKeyDeletion(databasePath, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := recordCredentialPrivateKeyDeletion(tx, staged); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	_ = database.Close()
	if _, err := os.Stat(staged.stagedPath); err != nil {
		t.Fatalf("committed deletion lost its durable stage before recovery: %v", err)
	}
	if err := recoverCredentialPrivateKeyOperations(databasePath); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{finalPath, staged.stagedPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("committed deletion left protected key %q: %v", path, err)
		}
	}
	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var profiles, operations int
	if err := database.QueryRow("SELECT COUNT(*) FROM CredentialProfiles WHERE Id = ?;", created.ID).Scan(&profiles); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow("SELECT COUNT(*) FROM CredentialPrivateKeyOperations;").Scan(&operations); err != nil {
		t.Fatal(err)
	}
	if profiles != 0 || operations != 0 {
		t.Fatalf("completed deletion left profiles:%d operations:%d, want 0 each", profiles, operations)
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
	previousDelete := credentialPrivateKeyStageDelete
	credentialPrivateKeyStageDelete = func(string, string) error { return os.ErrPermission }
	t.Cleanup(func() { credentialPrivateKeyStageDelete = previousDelete })

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
