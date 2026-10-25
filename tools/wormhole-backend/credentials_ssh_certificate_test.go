package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func writeSSHTestFile(t *testing.T, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCredentialSSHCertificateCreateReplaceClearAndMatch(t *testing.T) {
	_, _, protectedKeys, _ := installSshKeyCredentialTestStores(t)
	key := testSshPrivateKey(t, "")
	credentialPrivateKeyUnprotect = func(string) ([]byte, error) { return bytes.Clone(key), nil }
	signer, _ := parseSSHSigner(key, nil)
	cert, _ := testSSHCertificate(t, signer, ssh.UserCert, 0, ssh.CertTimeInfinity)
	certificatePath := writeSSHTestFile(t, "id_ed25519-cert.pub", append(bytes.TrimSpace(ssh.MarshalAuthorizedKey(cert)), []byte(" comment\x1b[31m")...))
	dbPath := filepath.Join(t.TempDir(), "wormhole.db")
	request := credentialCreateRequest{Name: "SSH certificate", Protocol: "ssh", Kind: "sshKey", Username: "operator", PrivateKeyPath: writeSSHTestFile(t, "id_ed25519", key), CertificatePath: certificatePath, Provider: "Local"}
	created, err := createCredential(dbPath, request)
	if err != nil {
		t.Fatal(err)
	}
	if !created.HasCertificate || created.CertificateFileName != "id_ed25519-cert.pub" || created.Certificate.KeyID != cert.KeyId || created.Certificate.ValidBefore != "" {
		t.Fatalf("metadata = %#v", created)
	}
	encoded, _ := json.Marshal(created)
	if bytes.Contains(encoded, []byte("PRIVATE KEY")) || bytes.Contains(encoded, bytes.Fields(ssh.MarshalAuthorizedKey(cert))[1]) {
		t.Fatal("secret or certificate body reached credential record")
	}
	keyPath := credentialPrivateKeyPath(dbPath, created.ID)
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	cert.KeyId = "renewed"
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	request.PrivateKeyPath = ""
	request.CertificatePath = writeSSHTestFile(t, "renewed-cert.pub", ssh.MarshalAuthorizedKey(cert))
	updated, err := updateCredential(dbPath, credentialUpdateRequest{ID: created.ID, credentialCreateRequest: request})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(keyPath)
	if !bytes.Equal(before, after) || len(*protectedKeys) != 1 || updated.Certificate.KeyID != "renewed" {
		t.Fatal("certificate-only update rewrote the key or lost metadata")
	}
	database, err := openDatabase(dbPath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	loaded, _, err := loadStoredCredentials(database)
	if err != nil || len(loaded) != 1 || loaded[0].Certificate.KeyID != "renewed" {
		t.Fatalf("loaded=%#v err=%v", loaded, err)
	}
	var target sshTarget
	if err := loadSSHCredential(database, dbPath, created.ID, &target, "", "", false, false); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(target.certificate, bytes.TrimSpace(ssh.MarshalAuthorizedKey(cert))) || target.credentialID != created.ID {
		t.Fatal("runtime certificate wasn't loaded")
	}
	request.CertificatePath = ""
	request.ClearCertificate = true
	cleared, err := updateCredential(dbPath, credentialUpdateRequest{ID: created.ID, credentialCreateRequest: request})
	if err != nil || cleared.HasCertificate || cleared.Certificate != nil {
		t.Fatalf("clear=%#v err=%v", cleared, err)
	}
	request.ClearCertificate = false
	request.CertificatePath = certificatePath
	otherKey := testSshPrivateKey(t, "")
	request.PrivateKeyPath = writeSSHTestFile(t, "other_key", otherKey)
	if _, err := updateCredential(dbPath, credentialUpdateRequest{ID: created.ID, credentialCreateRequest: request}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatal(err)
	}
	if len(*protectedKeys) != 1 {
		t.Fatal("mismatch touched protected storage")
	}
}

func TestCredentialSSHCertificateEncryptedImportAndErrors(t *testing.T) {
	installSshKeyCredentialTestStores(t)
	key := testSshPrivateKey(t, "pass")
	signer, _ := parseSSHSigner(key, []byte("pass"))
	cert, _ := testSSHCertificate(t, signer, ssh.UserCert, 0, ssh.CertTimeInfinity)
	request := credentialCreateRequest{Name: "Encrypted", Protocol: "ssh", Kind: "sshKey", Username: "operator", PrivateKeyPath: writeSSHTestFile(t, "encrypted", key), CertificatePath: writeSSHTestFile(t, "cert.pub", ssh.MarshalAuthorizedKey(cert))}
	if _, err := createCredential(filepath.Join(t.TempDir(), "workspace.db"), request); err != nil {
		t.Fatal(err)
	}
	other, _ := parseSSHSigner(testSshPrivateKey(t, ""), nil)
	wrong, _ := testSSHCertificate(t, other, ssh.UserCert, 0, ssh.CertTimeInfinity)
	request.CertificatePath = writeSSHTestFile(t, "wrong.pub", ssh.MarshalAuthorizedKey(wrong))
	if _, err := createCredential(filepath.Join(t.TempDir(), "workspace.db"), request); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatal(err)
	}
	for _, mutate := range []func(*credentialCreateRequest){
		func(r *credentialCreateRequest) { r.ClearCertificate = true },
		func(r *credentialCreateRequest) { r.CertificatePath = "relative.pub" },
		func(r *credentialCreateRequest) { r.Kind = "password"; r.Password = "pass"; r.PrivateKeyPath = "" },
	} {
		invalid := request
		mutate(&invalid)
		if _, err := normalizeCredentialDraft(invalid, false); err == nil {
			t.Fatal("accepted invalid certificate request")
		}
	}
	if _, _, err := readCredentialSSHCertificate(writeSSHTestFile(t, "huge.pub", bytes.Repeat([]byte("x"), maxSSHCertificateBytes+1)), key, ""); err == nil {
		t.Fatal("accepted oversized certificate")
	}
	if _, _, err := readCredentialSSHCertificate(writeSSHTestFile(t, "bad.pub", []byte("not a cert")), key, ""); err == nil {
		t.Fatal("accepted invalid certificate")
	}
	cert.ValidBefore = uint64(time.Now().Unix() - 3600)
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readCredentialSSHCertificate(writeSSHTestFile(t, "expired.pub", ssh.MarshalAuthorizedKey(cert)), key, ""); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatal(err)
	}
	if sshCertificateDisplayName("a\x00b.pub") != "ab.pub" || sshCertificateDisplayName("") != "SSH certificate" || sshCertificateDisplayName(strings.Repeat("a", 257)) != "SSH certificate" {
		t.Fatal("unsafe display name")
	}
	var record credentialRecord
	setSSHCertificateMetadata(&record, "bad", "broken.pub")
	if !record.HasCertificate || record.Certificate != nil {
		t.Fatal("malformed metadata escaped")
	}
	cert.ValidBefore = uint64(time.Now().Unix() + 3600)
	cert.ValidAfter = 1
	cert.KeyId = "test\x1b"
	cert.ValidPrincipals = []string{"op\x00erator"}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	setSSHCertificateMetadata(&record, string(ssh.MarshalAuthorizedKey(cert)), "cert.pub")
	if record.Certificate.KeyID != "test" || record.Certificate.Principals[0] != "operator" || record.Certificate.ValidBefore == "" || record.Certificate.ValidAfter == "" {
		t.Fatal("metadata wasn't bounded and sanitized")
	}
}

func TestSSHCertificateMigrationFrom0020IsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspace.db")
	if err := ensureElectronWorkspaceSchema(path); err != nil {
		t.Fatal(err)
	}
	db, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"ALTER TABLE CredentialProfiles DROP COLUMN SshCertificate;", "ALTER TABLE CredentialProfiles DROP COLUMN SshCertificateFileName;", "DELETE FROM __migration_history WHERE Id = '0021_credential_ssh_certificate';"} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	for range 2 {
		if err := ensureElectronWorkspaceSchema(path); err != nil {
			t.Fatal(err)
		}
	}
	db, err = openDatabase(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM __migration_history WHERE Id = '0021_credential_ssh_certificate';").Scan(&count); err != nil || count != 1 {
		t.Fatal(err, count)
	}
}

func TestDialNativeSSHCertificateAuthentication(t *testing.T) {
	for _, mode := range []string{"certificate-only", "plain-fallback", "rejected", "without-certificate", "rsa-sha2", "pkcs8-encrypted"} {
		t.Run(mode, func(t *testing.T) {
			key := testSshPrivateKey(t, "")
			if mode == "rsa-sha2" || mode == "pkcs8-encrypted" {
				private, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "pkcs8-encrypted" {
					key = testPKCS8Key(t, private, "pass", true, "2.16.840.1.101.3.4.1.42")
				} else {
					block, err := ssh.MarshalPrivateKey(private, "")
					if err != nil {
						t.Fatal(err)
					}
					key = pem.EncodeToMemory(block)
				}
			}
			signer, err := parseSSHSigner(key, []byte("pass"))
			if err != nil {
				t.Fatal(err)
			}
			cert, ca := testSSHCertificate(t, signer, ssh.UserCert, 0, ssh.CertTimeInfinity)
			_, hostKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			hostSigner, err := ssh.NewSignerFromKey(hostKey)
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var attempts []bool
			checker := ssh.CertChecker{IsUserAuthority: func(key ssh.PublicKey) bool { return bytes.Equal(key.Marshal(), ca.PublicKey().Marshal()) }}
			config := &ssh.ServerConfig{PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				_, isCertificate := key.(*ssh.Certificate)
				mu.Lock()
				attempts = append(attempts, isCertificate)
				mu.Unlock()
				if mode == "plain-fallback" {
					if !isCertificate && bytes.Equal(key.Marshal(), signer.PublicKey().Marshal()) {
						return nil, nil
					}
					return nil, errors.New("raw key required")
				}
				if mode == "rejected" {
					return nil, errors.New("untrusted CA")
				}
				return checker.Authenticate(conn, key)
			}}
			if mode == "rsa-sha2" {
				config.PublicKeyAuthAlgorithms = []string{ssh.KeyAlgoRSASHA256}
			}
			config.AddHostKey(hostSigner)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				server, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					channel, requests, err := incoming.Accept()
					if err != nil {
						return
					}
					go func() {
						defer channel.Close()
						for request := range requests {
							_ = request.Reply(request.Type == "pty-req" || request.Type == "shell", nil)
						}
					}()
				}
			}()
			target := sshTarget{host: "127.0.0.1", port: listener.Addr().(*net.TCPAddr).Port, username: "operator", privateKey: key, certificate: ssh.MarshalAuthorizedKey(cert), keyPassphrase: "pass"}
			if mode == "without-certificate" {
				target.certificate = nil
			}
			native, _, err := dialNativeSSH(context.Background(), target, 80, 24)
			if mode == "rejected" || mode == "without-certificate" {
				if err == nil {
					t.Fatal("unauthorized connection succeeded")
				}
				if mode == "rejected" && !strings.Contains(err.Error(), "TrustedUserCAKeys") {
					t.Fatal(err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				native.close(false)
			}
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("SSH test server didn't stop")
			}
			mu.Lock()
			defer mu.Unlock()
			if mode == "plain-fallback" && (len(attempts) < 2 || !attempts[0] || attempts[len(attempts)-1]) {
				t.Fatalf("auth order=%v", attempts)
			}
		})
	}
}

func TestSSHCertificateErrorsKeepTheCredentialAndClearDialMaterial(t *testing.T) {
	key := testSshPrivateKey(t, "")
	signer, _ := parseSSHSigner(key, nil)
	cert, _ := testSSHCertificate(t, signer, ssh.UserCert, 0, uint64(time.Now().Unix()-3600))
	line := ssh.MarshalAuthorizedKey(cert)
	target := &sshTarget{credentialID: backupTestKeyID, host: "127.0.0.1", port: 22, username: "operator", privateKey: key, certificate: line}
	_, _, err := openNativeSSH(context.Background(), "", "", "", target, "", "", nil, "", "", false, false, "", 80, 24)
	var certificateError *sshCertificateAuthError
	if !errors.As(err, &certificateError) || certificateError.credentialID != backupTestKeyID || !strings.Contains(err.Error(), "expired") {
		t.Fatal(err)
	}
	if !bytes.Equal(key, make([]byte, len(key))) || !bytes.Equal(line, make([]byte, len(line))) {
		t.Fatal("dial material was retained")
	}
	if !errors.Is(&sshCertificateAuthError{error: context.Canceled}, context.Canceled) {
		t.Fatal("wrapped cancellation must stay cancellable")
	}
	for _, initial := range []bool{false, true} {
		var output synchronizedBuffer
		state := &sshReconnectState{command: sshWireCommand{SessionID: "certificate", Password: "one-shot"}}
		server := &sshServer{output: &sshEventWriter{encoder: json.NewEncoder(&output)}, pending: map[string]context.CancelFunc{"certificate": func() {}}, lifecycles: map[string]*sshReconnectState{"certificate": state}, openSSH: func(context.Context, *sshReconnectState) (*sshNativeSession, sshTarget, error) {
			return nil, sshTarget{}, err
		}}
		if initial {
			server.connectSSH(context.Background(), state, true)
		} else {
			server.reconnectAttemptFailed(state, err)
		}
		var event sshWireEvent
		if decodeErr := json.Unmarshal(output.Bytes(), &event); decodeErr != nil {
			t.Fatal(decodeErr, output.String())
		}
		if event.Type != "error" || event.CredentialID != backupTestKeyID || state.commandSnapshot().Password != "" {
			t.Fatalf("certificate error lost recovery context: %#v", event)
		}
	}
}

func TestSSHCertificateBackupRoundTripAndMismatch(t *testing.T) {
	installBackupTestSecretStore(t)
	key := testSshPrivateKey(t, "")
	signer, _ := parseSSHSigner(key, nil)
	cert, _ := testSSHCertificate(t, signer, ssh.UserCert, 0, ssh.CertTimeInfinity)
	for _, mode := range []string{"valid", "mismatch", "missing-key", "malformed", "password-profile"} {
		t.Run(mode, func(t *testing.T) {
			payload := newBackupPayload()
			line := string(ssh.MarshalAuthorizedKey(cert))
			kind := 1
			if mode == "mismatch" {
				other, _ := parseSSHSigner(testSshPrivateKey(t, ""), nil)
				wrong, _ := testSSHCertificate(t, other, ssh.UserCert, 0, ssh.CertTimeInfinity)
				line = string(ssh.MarshalAuthorizedKey(wrong))
			}
			if mode == "malformed" {
				line = "invalid"
			}
			if mode == "password-profile" {
				kind = 0
			}
			object := backupTestObject(map[string]any{"id": backupTestKeyID, "name": "Certificate key", "username": "operator", "kind": kind, "protocol": 0, "secretProvider": 0, "sshCertificate": line, "sshCertificateFileName": "id-cert.pub", "createdAt": time.Now().UTC().Format(time.RFC3339)})
			payload.Credentials = []*backupObject{&object}
			if mode != "missing-key" {
				payload.PrivateKeys = []*backupPrivateKeyEntry{{CredentialID: backupTestKeyID, DataB64: base64.StdEncoding.EncodeToString(key)}}
			}
			path := writeBackupTestPayload(t, payload)
			dbPath := filepath.Join(t.TempDir(), "workspace.db")
			result, err := importBackup(dbPath, backupRequest{Path: path})
			if err != nil {
				t.Fatal(err)
			}
			db := openBackupTestDatabase(t, dbPath)
			defer db.Close()
			var stored sql.NullString
			if err := db.QueryRow("SELECT SshCertificate FROM CredentialProfiles WHERE Id = ?;", backupTestKeyID).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			if mode == "valid" {
				if !stored.Valid || strings.TrimSpace(stored.String) != strings.TrimSpace(line) {
					t.Fatal("certificate lost during restore")
				}
				exportPath := filepath.Join(t.TempDir(), "export.json")
				if _, err := exportBackup(dbPath, backupRequest{Path: exportPath, Password: "backup-password"}); err != nil {
					t.Fatal(err)
				}
				restoredPath := filepath.Join(t.TempDir(), "restored.db")
				if _, err := importBackup(restoredPath, backupRequest{Path: exportPath, Password: "backup-password"}); err != nil {
					t.Fatal(err)
				}
				restored := openBackupTestDatabase(t, restoredPath)
				defer restored.Close()
				if err := restored.QueryRow("SELECT SshCertificate FROM CredentialProfiles WHERE Id = ?;", backupTestKeyID).Scan(&stored); err != nil || !stored.Valid {
					t.Fatal("certificate export roundtrip failed", err)
				}
			} else if stored.Valid || !strings.Contains(strings.Join(result.Warnings, " "), "certificate") {
				t.Fatalf("invalid certificate retained: %#v", result)
			}
			if mode == "mismatch" {
				restored, err := readBackupPrivateKey(credentialPrivateKeyPath(dbPath, backupTestKeyID))
				if err != nil || !bytes.Equal(restored, key) {
					t.Fatal("mismatch discarded key", err)
				}
			}
		})
	}
}
