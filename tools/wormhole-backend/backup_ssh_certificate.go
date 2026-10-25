package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
)

// New profiles without a successfully restored key still need validation.
// Successful key snapshots reconcile their certificate inside their transaction.
func validateRestoredSSHCertificates(ctx context.Context, database *sql.DB, databasePath string, inserted map[string]struct{}, result *backupImportResult) error {
	for id := range inserted {
		if err := ctx.Err(); err != nil {
			return err
		}
		var line, name string
		var kind, provider int64
		if err := database.QueryRowContext(ctx, `SELECT COALESCE(SshCertificate, ''), COALESCE(SshCertificateFileName, ''), Kind, COALESCE(SecretProvider, 0) FROM CredentialProfiles WHERE lower(Id) = ?;`, id).Scan(&line, &name, &kind, &provider); err != nil {
			return err
		}
		if line == "" {
			continue
		}
		cert, validationErr := parseSSHUserCertificate([]byte(line))
		if kind != 1 || provider != 0 {
			validationErr = errors.New("certificate requires a local SSH key credential")
		}
		if validationErr == nil {
			key, err := readBackupPrivateKey(credentialPrivateKeyPath(databasePath, id))
			if err != nil {
				validationErr = errors.New("the restored private key is unavailable")
			} else {
				password, _, err := readBackupPassword(database, id)
				if err != nil {
					validationErr = errors.New("the restored passphrase is unavailable")
				} else {
					validationErr = validateSSHCertificateKey(cert, key, password)
				}
				clearBytes(key)
			}
		}
		var certificate, fileName any
		if validationErr == nil {
			// Expired certificates survive backup too; runtime reports their expiry
			// and lets the user replace them without importing the key again.
			certificate = canonicalSSHCertificate(cert, []byte(line))
			fileName = sshCertificateDisplayName(filepath.Base(name))
		} else {
			addBackupWarning(result, fmt.Sprintf("SSH certificate for credential %s was dropped: %s. The private key was kept.", id, validationErr))
		}
		if _, err := database.ExecContext(ctx, "UPDATE CredentialProfiles SET SshCertificate = ?, SshCertificateFileName = ? WHERE lower(Id) = ?;", certificate, fileName, id); err != nil {
			return err
		}
	}
	return nil
}

func reconcileRestoredSSHCertificate(transaction *sql.Tx, id string, key []byte, password string) (string, error) {
	var line, name string
	if err := transaction.QueryRow(`SELECT COALESCE(SshCertificate, ''), COALESCE(SshCertificateFileName, '') FROM CredentialProfiles WHERE lower(Id) = ?;`, id).Scan(&line, &name); err != nil {
		return "", err
	}
	if line == "" {
		return "", nil
	}
	cert, validationErr := parseSSHUserCertificate([]byte(line))
	if validationErr == nil {
		validationErr = validateSSHCertificateKey(cert, key, password)
	}
	var certificate, fileName any
	warning := ""
	if validationErr == nil {
		certificate, fileName = canonicalSSHCertificate(cert, []byte(line)), sshCertificateDisplayName(filepath.Base(name))
	} else {
		warning = fmt.Sprintf("SSH certificate for credential %s was dropped: %s. The private key was kept.", id, validationErr)
	}
	_, err := transaction.Exec("UPDATE CredentialProfiles SET SshCertificate = ?, SshCertificateFileName = ? WHERE lower(Id) = ?;", certificate, fileName, id)
	return warning, err
}
