package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

const mremoteTestPassword = "custom-master"
const mremoteTestIterations = 10_000

func TestMRemoteImportValidEncryptedFixturePlansAndCommitsMappings(t *testing.T) {
	databasePath := newMRemoteTestDatabase(t)
	fixture := writeMRemoteFixture(t, validMRemoteFixture(t))
	request := mremoteImportRequest{Path: fixture, Password: mremoteTestPassword, PlanNonce: "11111111-1111-4111-8111-111111111111"}

	inspection, err := inspectMRemoteImport(request)
	if err != nil {
		t.Fatal(err)
	}
	if !inspection.PasswordRequired || inspection.ConfVersion != "2.7" {
		t.Fatalf("unexpected inspection: %+v", inspection)
	}
	plan, err := analyzeMRemoteImport(databasePath, request)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Folders != 2 || plan.Connections != 3 || plan.Credentials != 3 || plan.SkippedUnsupported != 1 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	request.PlanToken = plan.PlanToken
	previousStore, previousDelete := credentialSecretStore, credentialSecretDelete
	stored := map[string]string{}
	credentialSecretStore = func(id, password string) (string, string, error) {
		stored[id] = password
		return "protected-" + id, "test", nil
	}
	credentialSecretDelete = func(id, _, _ string) error { delete(stored, id); return nil }
	t.Cleanup(func() { credentialSecretStore = previousStore; credentialSecretDelete = previousDelete })

	result, err := commitMRemoteImport(databasePath, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.FoldersCreated != 2 || result.ConnectionsCreated != 3 || result.CredentialsCreated != 3 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(stored) != 3 {
		t.Fatalf("expected three protected secrets, got %d", len(stored))
	}
	db, err := openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var parentCount, rdpCount, vncCredentialCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM Nodes WHERE ParentId IS NOT NULL;").Scan(&parentCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM Nodes WHERE Protocol=1 AND RdpDomain='ACME' AND RdpScreenSize='Full connection content' AND RdpFullScreen=0;").Scan(&rdpCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM Nodes WHERE Protocol=6 AND Username IS NULL AND CredentialId IS NOT NULL;").Scan(&vncCredentialCount); err != nil {
		t.Fatal(err)
	}
	if parentCount != 3 || rdpCount != 1 || vncCredentialCount != 1 {
		t.Fatalf("mapping mismatch parent=%d rdp=%d vnc=%d", parentCount, rdpCount, vncCredentialCount)
	}
}

func TestMRemoteImportSilentlyUsesFactoryDefaultPassword(t *testing.T) {
	databasePath := newMRemoteTestDatabase(t)
	verifier := encryptMRemoteFixture(t, mremoteVerifier, mremoteDefaultPassword)
	secret := encryptMRemoteFixture(t, "default-secret", mremoteDefaultPassword)
	fixture := writeMRemoteFixture(t, fmt.Sprintf(`<?xml version="1.0"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" ConfVersion="2.7" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="%d" FullFileEncryption="false" Protected="%s">
  <Node Name="SSH" Type="Connection" Protocol="SSH2" Hostname="host" Username="user" Password="%s" />
</mrng:Connections>`, mremoteTestIterations, verifier, secret))
	request := mremoteImportRequest{Path: fixture, PlanNonce: "99999999-9999-4999-8999-999999999999"}
	inspection, err := inspectMRemoteImport(request)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.PasswordRequired {
		t.Fatal("factory-default password should not require user input")
	}
	plan, err := analyzeMRemoteImport(databasePath, request)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Credentials != 1 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}

func TestMRemoteImportRejectsControlCharactersFromNamesAndMappedFields(t *testing.T) {
	node := mremoteXMLNode{Hostname: "unsafe\u0085host"}
	if got := displayMRemoteName(node, workspaceNodeConnection); got != "Connection" {
		t.Fatalf("unsafe host became display name %q", got)
	}
	if got := nullableMRemoteText("user\u0085name", maxCredentialUsernameLength); got.Valid {
		t.Fatalf("unsafe username was accepted: %+v", got)
	}
}

func TestMRemoteImportRejectsMalformedOversizedAndWrongPasswordFixtures(t *testing.T) {
	databasePath := newMRemoteTestDatabase(t)
	t.Run("malformed", func(t *testing.T) {
		_, err := inspectMRemoteImport(mremoteImportRequest{Path: writeMRemoteFixture(t, "<broken")})
		if err == nil {
			t.Fatal("expected malformed XML rejection")
		}
	})
	t.Run("oversized", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "large.xml")
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(mremoteMaxFileBytes + 1); err != nil {
			t.Fatal(err)
		}
		_ = file.Close()
		_, err = inspectMRemoteImport(mremoteImportRequest{Path: path})
		if err == nil || !strings.Contains(err.Error(), "limit") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("wrong password", func(t *testing.T) {
		request := mremoteImportRequest{Path: writeMRemoteFixture(t, validMRemoteFixture(t)), Password: "wrong", PlanNonce: "22222222-2222-4222-8222-222222222222"}
		_, err := analyzeMRemoteImport(databasePath, request)
		if err == nil || !strings.Contains(err.Error(), "incorrect") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("full file encryption", func(t *testing.T) {
		xml := strings.Replace(validMRemoteFixture(t), `FullFileEncryption="false"`, `FullFileEncryption="true"`, 1)
		request := mremoteImportRequest{Path: writeMRemoteFixture(t, xml), Password: mremoteTestPassword, PlanNonce: "33333333-3333-4333-8333-333333333333"}
		_, err := analyzeMRemoteImport(databasePath, request)
		if err == nil || !strings.Contains(err.Error(), "full-file") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestMRemoteImportStructureOnlyNeverStoresDecryptedSecrets(t *testing.T) {
	databasePath := newMRemoteTestDatabase(t)
	request := mremoteImportRequest{Path: writeMRemoteFixture(t, validMRemoteFixture(t)), StructureOnly: true, PlanNonce: "44444444-4444-4444-8444-444444444444"}
	plan, err := analyzeMRemoteImport(databasePath, request)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Credentials != 0 || len(plan.Warnings) == 0 {
		t.Fatalf("unexpected structure plan: %+v", plan)
	}
	request.PlanToken = plan.PlanToken
	previousStore := credentialSecretStore
	credentialSecretStore = func(_, _ string) (string, string, error) {
		t.Fatal("secret store must not be called")
		return "", "", nil
	}
	t.Cleanup(func() { credentialSecretStore = previousStore })
	result, err := commitMRemoteImport(databasePath, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.CredentialsCreated != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestMRemoteImportDuplicateAllocatesCollisionFreeCredentialNames(t *testing.T) {
	databasePath := newMRemoteTestDatabase(t)
	fixture := writeMRemoteFixture(t, validMRemoteFixture(t))
	previousStore, previousDelete := credentialSecretStore, credentialSecretDelete
	credentialSecretStore = func(id, password string) (string, string, error) { return "protected-" + id, "test", nil }
	credentialSecretDelete = func(_, _, _ string) error { return nil }
	t.Cleanup(func() { credentialSecretStore = previousStore; credentialSecretDelete = previousDelete })
	for index, nonce := range []string{"55555555-5555-4555-8555-555555555555", "66666666-6666-4666-8666-666666666666"} {
		request := mremoteImportRequest{Path: fixture, Password: mremoteTestPassword, PlanNonce: nonce}
		plan, err := analyzeMRemoteImport(databasePath, request)
		if err != nil {
			t.Fatal(err)
		}
		request.PlanToken = plan.PlanToken
		if _, err := commitMRemoteImport(databasePath, request); err != nil {
			t.Fatalf("duplicate %d failed: %v", index, err)
		}
	}
	db, err := openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var total, distinct int
	if err := db.QueryRow("SELECT COUNT(*), COUNT(DISTINCT Name) FROM CredentialProfiles;").Scan(&total, &distinct); err != nil {
		t.Fatal(err)
	}
	if total != 6 || distinct != 6 {
		t.Fatalf("credentials total=%d distinct=%d", total, distinct)
	}
}

func TestMRemoteImportCancellationAndFailureRollbackAtomically(t *testing.T) {
	databasePath := newMRemoteTestDatabase(t)
	request := mremoteImportRequest{Path: writeMRemoteFixture(t, validMRemoteFixture(t)), Password: mremoteTestPassword, PlanNonce: "77777777-7777-4777-8777-777777777777"}
	plan, err := analyzeMRemoteImport(databasePath, request)
	if err != nil {
		t.Fatal(err)
	}
	request.PlanToken = plan.PlanToken
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := commitMRemoteImportContext(ctx, databasePath, request); err == nil {
		t.Fatal("expected cancellation")
	}
	assertMRemoteDatabaseEmpty(t, databasePath)

	previousStore, previousDelete := credentialSecretStore, credentialSecretDelete
	stored := map[string]bool{}
	credentialSecretStore = func(id, _ string) (string, string, error) { stored[id] = true; return "protected-" + id, "test", nil }
	credentialSecretDelete = func(id, _, _ string) error { delete(stored, id); return nil }
	t.Cleanup(func() { credentialSecretStore = previousStore; credentialSecretDelete = previousDelete })
	db, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TRIGGER fail_mremote_nodes BEFORE INSERT ON Nodes BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;`)
	_ = db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := commitMRemoteImport(databasePath, request); err == nil {
		t.Fatal("expected injected database failure")
	}
	if len(stored) != 0 {
		t.Fatalf("orphaned protected secrets: %v", stored)
	}
	assertMRemoteDatabaseEmpty(t, databasePath)
}

func TestMRemoteImportPlanRejectsFileOrWorkspaceDrift(t *testing.T) {
	databasePath := newMRemoteTestDatabase(t)
	path := writeMRemoteFixture(t, validMRemoteFixture(t))
	request := mremoteImportRequest{Path: path, Password: mremoteTestPassword, PlanNonce: "88888888-8888-4888-8888-888888888888"}
	plan, err := analyzeMRemoteImport(databasePath, request)
	if err != nil {
		t.Fatal(err)
	}
	request.PlanToken = plan.PlanToken
	if err := os.WriteFile(path, []byte(strings.Replace(validMRemoteFixture(t), "Top", "Changed", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := commitMRemoteImport(databasePath, request); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("unexpected error: %v", err)
	}
	assertMRemoteDatabaseEmpty(t, databasePath)
}

func newMRemoteTestDatabase(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wormhole.db")
	if err := ensureElectronWorkspaceSchema(path); err != nil {
		t.Fatal(err)
	}
	return path
}
func writeMRemoteFixture(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.xml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
func assertMRemoteDatabaseEmpty(t *testing.T, path string) {
	t.Helper()
	db, err := openDatabase(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, table := range []string{"Nodes", "CredentialProfiles", "CredentialSecrets"} {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s contains %d rows", table, count)
		}
	}
}

func validMRemoteFixture(t *testing.T) string {
	t.Helper()
	verifier := encryptMRemoteFixture(t, mremoteVerifier, mremoteTestPassword)
	shared := encryptMRemoteFixture(t, "shared-secret", mremoteTestPassword)
	vnc := encryptMRemoteFixture(t, "vnc-secret", mremoteTestPassword)
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" ConfVersion="2.7" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="%d" FullFileEncryption="false" Protected="%s">
  <Node Name="Top" Type="Container">
    <Node Name="SSH" Type="Connection" Protocol="SSH2" Hostname="ssh.example" Port="22" Username="alice" Password="%s" />
    <Node Name="Inner" Type="Container">
      <Node Name="RDP" Type="Connection" Protocol="RDP" Hostname="rdp.example" Port="3389" Username="alice" Domain="ACME" Password="%s" Resolution="FitToWindow" />
    </Node>
  </Node>
  <Node Name="VNC" Type="Connection" Protocol="VNC" Hostname="vnc.example" Username="ignored" Password="%s" />
  <Node Name="Unsupported" Type="Connection" Protocol="Telnet" Hostname="legacy.example" />
</mrng:Connections>`, mremoteTestIterations, verifier, shared, shared, vnc)
}
func encryptMRemoteFixture(t *testing.T, plain, password string) string {
	t.Helper()
	salt := make([]byte, 16)
	nonce := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	key := pbkdf2.Key([]byte(password), salt, mremoteTestIterations, 32, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plain), salt)
	blob := append(append(append([]byte{}, salt...), nonce...), ciphertext...)
	return base64.StdEncoding.EncodeToString(blob)
}
