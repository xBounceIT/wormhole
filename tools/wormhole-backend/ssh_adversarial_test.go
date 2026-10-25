package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHCertificateBackupMetadataValidationWithRetainedKey(t *testing.T) {
	installBackupTestSecretStore(t)
	key := testSshPrivateKey(t, "saved-passphrase")
	signer, err := parseSSHSigner(key, []byte("saved-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "mismatch", "tampered-signature", "unreadable-passphrase", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			certificateSigner := signer
			if mode == "mismatch" {
				certificateSigner, _ = parseSSHSigner(testSshPrivateKey(t, ""), nil)
			}
			cert, _ := testSSHCertificate(t, certificateSigner, ssh.UserCert, 0, ssh.CertTimeInfinity)
			if mode == "tampered-signature" {
				cert.KeyId += "-tampered"
			}
			line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))) + " renewed\x1b-key"
			dbPath := filepath.Join(t.TempDir(), "workspace.db")
			db := openBackupTestDatabase(t, dbPath)
			defer db.Close()
			profile := backupTestObject(map[string]any{
				"id": backupTestKeyID, "name": "Retained key", "kind": 1, "protocol": 0, "secretProvider": 0,
				"createdAt": time.Now().UTC().Format(time.RFC3339), "sshCertificate": line, "sshCertificateFileName": "id-cert.pub",
			})
			if err := insertBackupObject(db, "CredentialProfiles", backupCredentialColumns, profile); err != nil {
				t.Fatal(err)
			}
			keyPath := credentialPrivateKeyPath(dbPath, backupTestKeyID)
			if err := protectFile(keyPath, key); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := storeBackupPassword(db, backupTestKeyID, "saved-passphrase"); err != nil {
				t.Fatal(err)
			}
			if mode == "unreadable-passphrase" {
				if _, err := db.Exec("UPDATE CredentialSecrets SET Encoding = 'unavailable' WHERE Id = ?", backupTestKeyID); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "canceled" {
				cancel()
			}
			result := backupImportResult{}
			err = validateRestoredSSHCertificates(ctx, db, dbPath, map[string]struct{}{backupTestKeyID: {}}, &result)
			if mode == "canceled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled validation: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			var stored, name sql.NullString
			if err := db.QueryRow("SELECT SshCertificate, SshCertificateFileName FROM CredentialProfiles WHERE Id = ?", backupTestKeyID).Scan(&stored, &name); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "valid":
				if stored.String != strings.ReplaceAll(line, "\x1b", "") || name.String != "id-cert.pub" || len(result.Warnings) != 0 {
					t.Fatal("valid metadata lost its certificate or canonical comment")
				}
			case "canceled":
				if stored.String != line || name.String != "id-cert.pub" || len(result.Warnings) != 0 {
					t.Fatal("canceled validation mutated certificate metadata")
				}
			default:
				expected := "does not match"
				if mode == "unreadable-passphrase" {
					expected = "passphrase is unavailable"
				}
				if mode == "tampered-signature" {
					expected = "signature"
				}
				if stored.Valid || name.Valid || !strings.Contains(strings.Join(result.Warnings, " "), expected) {
					t.Fatalf("unsafe metadata retained or missing warning: %#v", result)
				}
			}
			after, err := os.ReadFile(keyPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("metadata validation changed the retained protected key", err)
			}
		})
	}
}

func TestSSHCertificateBackupRevalidatesRepairedExistingKeys(t *testing.T) {
	installBackupTestSecretStore(t)
	key := testSshPrivateKey(t, "")
	signer, _ := parseSSHSigner(key, nil)
	for _, matches := range []bool{false, true} {
		t.Run(map[bool]string{false: "mismatch", true: "renewed-matching"}[matches], func(t *testing.T) {
			certificateSigner := signer
			if !matches {
				certificateSigner, _ = parseSSHSigner(testSshPrivateKey(t, ""), nil)
			}
			cert, _ := testSSHCertificate(t, certificateSigner, ssh.UserCert, 0, ssh.CertTimeInfinity)
			line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
			dbPath := filepath.Join(t.TempDir(), "workspace.db")
			db := openBackupTestDatabase(t, dbPath)
			profile := backupTestObject(map[string]any{
				"id": backupTestKeyID, "name": "Existing renewed key", "username": "operator", "kind": 1,
				"protocol": 0, "secretProvider": 0, "createdAt": time.Now().UTC().Format(time.RFC3339),
				"sshCertificate": line, "sshCertificateFileName": "renewed-cert.pub",
			})
			if err := insertBackupObject(db, "CredentialProfiles", backupCredentialColumns, profile); err != nil {
				t.Fatal(err)
			}
			db.Close()
			payload := newBackupPayload()
			payload.Credentials = []*backupObject{&profile}
			payload.PrivateKeys = []*backupPrivateKeyEntry{{CredentialID: backupTestKeyID, DataB64: base64.StdEncoding.EncodeToString(key)}}
			result, err := importBackup(dbPath, backupRequest{Path: writeBackupTestPayload(t, payload)})
			if err != nil {
				t.Fatal(err)
			}
			if result.PrivateKeysImported != 1 || result.CredentialsImported != 0 {
				t.Fatalf("not a key repair: %#v", result)
			}
			db = openBackupTestDatabase(t, dbPath)
			defer db.Close()
			var stored, name sql.NullString
			if err := db.QueryRow("SELECT SshCertificate, SshCertificateFileName FROM CredentialProfiles WHERE Id = ?", backupTestKeyID).Scan(&stored, &name); err != nil {
				t.Fatal(err)
			}
			if matches {
				if stored.String != line || name.String != "renewed-cert.pub" {
					t.Fatal("backup overwrote a valid renewed certificate")
				}
			} else if stored.Valid || name.Valid || !strings.Contains(strings.Join(result.Warnings, " "), "does not match") {
				t.Fatalf("repair retained a mismatched certificate: present=%v warnings=%v", stored.Valid, result.Warnings)
			}
			restored, err := readBackupPrivateKey(credentialPrivateKeyPath(dbPath, backupTestKeyID))
			if err != nil || !bytes.Equal(restored, key) {
				t.Fatalf("repair lost key: %v", err)
			}
			clearBytes(restored)
		})
	}
}

func TestSSHPKCS8RejectsMalformedCipherBeforeRequestingPassphrase(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name, oid string
		data      []byte
		parameter any
	}{
		{"CBC bad IV", "2.16.840.1.101.3.4.1.42", make([]byte, 16), []byte{1}},
		{"CBC empty ciphertext", "2.16.840.1.101.3.4.1.42", []byte{}, make([]byte, 16)},
		{"CBC truncated ciphertext", "2.16.840.1.101.3.4.1.42", []byte{1}, make([]byte, 16)},
		{"GCM bad nonce", "2.16.840.1.101.3.4.1.46", make([]byte, 16), struct {
			Nonce   []byte
			TagSize int
		}{[]byte{1}, 16}},
		{"GCM bad tag size", "2.16.840.1.101.3.4.1.46", make([]byte, 16), struct {
			Nonce   []byte
			TagSize int
		}{make([]byte, 12), 1}},
		{"GCM truncated ciphertext", "2.16.840.1.101.3.4.1.46", []byte{1}, struct {
			Nonce   []byte
			TagSize int
		}{make([]byte, 12), 16}},
	} {
		t.Run(item.name, func(t *testing.T) {
			block, _ := pem.Decode(testPKCS8Key(t, private, "pass", false, item.oid))
			var envelope sshPKCS8Envelope
			if err := decodeSSHASN1(block.Bytes, &envelope); err != nil {
				t.Fatal(err)
			}
			var params sshPBES2Params
			if err := decodeSSHASN1(envelope.Algorithm.Parameters.FullBytes, &params); err != nil {
				t.Fatal(err)
			}
			params.Cipher = testAlgorithm(t, item.oid, item.parameter)
			envelope.Algorithm = testAlgorithm(t, "1.2.840.113549.1.5.13", params)
			envelope.Data = item.data
			key := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: testASN1(t, envelope)})
			if err := validateSshPrivateKey(key, ""); err == nil {
				t.Fatal("malformed encrypted PKCS#8 key was accepted without its passphrase")
			}
		})
	}
}

func TestSSHCertificateBackupKeyRepairRollsBackCertificateOnJournalFailure(t *testing.T) {
	installBackupTestSecretStore(t)
	key := testSshPrivateKey(t, "")
	other, _ := parseSSHSigner(testSshPrivateKey(t, ""), nil)
	cert, _ := testSSHCertificate(t, other, ssh.UserCert, 0, ssh.CertTimeInfinity)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
	dbPath := filepath.Join(t.TempDir(), "workspace.db")
	db := openBackupTestDatabase(t, dbPath)
	defer db.Close()
	profile := backupTestObject(map[string]any{
		"id": backupTestKeyID, "name": "Existing key", "kind": 1, "protocol": 0, "secretProvider": 0,
		"createdAt": time.Now().UTC().Format(time.RFC3339), "sshCertificate": line, "sshCertificateFileName": "current-cert.pub",
	})
	if err := insertBackupObject(db, "CredentialProfiles", backupCredentialColumns, profile); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER reject_test_key_journal BEFORE INSERT ON CredentialPrivateKeyOperations BEGIN SELECT RAISE(ABORT, 'injected journal failure'); END;`); err != nil {
		t.Fatal(err)
	}
	payload := newBackupPayload()
	payload.Credentials = []*backupObject{&profile}
	payload.PrivateKeys = []*backupPrivateKeyEntry{{CredentialID: backupTestKeyID, DataB64: base64.StdEncoding.EncodeToString(key)}}
	if _, err := importBackup(dbPath, backupRequest{Path: writeBackupTestPayload(t, payload)}); err == nil {
		t.Fatal("injected journal failure wasn't returned")
	}
	var stored, name string
	if err := db.QueryRow("SELECT SshCertificate, SshCertificateFileName FROM CredentialProfiles WHERE Id = ?", backupTestKeyID).Scan(&stored, &name); err != nil {
		t.Fatal(err)
	}
	if stored != line || name != "current-cert.pub" {
		t.Fatal("failed key repair changed its certificate")
	}
	for _, path := range []string{credentialPrivateKeyPath(dbPath, backupTestKeyID), credentialPrivateKeyPath(dbPath, backupTestKeyID) + credentialPrivateKeyPendingSuffix} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("failed repair retained a staged key: %v", err)
		}
	}
}
