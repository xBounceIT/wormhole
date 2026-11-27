package main

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

var errVaultMigrationSource = errors.New("vault_migration_source_invalid")

// CreatedAt accompanies metadata into Owner.ImportCredential. Ordinary editor
// DTOs cannot overwrite this authenticated migration provenance.
type legacyVaultCredential struct {
	Metadata    vaultstore.CredentialMetadata
	CreatedAt   string
	certificate []byte
}

type legacyVaultCredentialReaders struct {
	secret     legacyVaultSecretReader
	privateKey func(string) ([]byte, error)
}

type legacyVaultSecretReader func(string, string, string, ...string) ([]byte, error)

// The source must already be reserved by withLegacyResolverMigration, and its
// private-key lock acquired BEFORE the SQLite writer reservation. Recovery
// journals must be empty. This reader never mutates/deletes source rows, files or
// keychain values, and never publishes a destination. Any sink writes belong in
// an unpublished, journaled staging vault: a late error invalidates that stage.
// The sink borrows all plaintext only until return; it must not retain slices.
func visitLegacyVaultCredentials(reader resolverCaptureReader, databasePath, electronUserDataPath string, visit func(legacyVaultCredential, []localvault.SecretChange) error) error {
	return readLegacyVaultCredentials(reader, databasePath, electronUserDataPath, legacyVaultCredentialReaders{
		secret: migrationSecretReader(reader.ctx, maxStoredCredentialBytes), privateKey: unprotectSshPrivateKey,
	}, visit)
}

func readLegacyVaultCredentials(reader resolverCaptureReader, databasePath, electronUserDataPath string, readers legacyVaultCredentialReaders, visit func(legacyVaultCredential, []localvault.SecretChange) error) error {
	if !filepath.IsAbs(databasePath) || visit == nil || readers.secret == nil || readers.privateKey == nil {
		return errVaultMigrationSource
	}
	secretTable, err := validateLegacyVaultSecretSource(reader)
	if err != nil {
		return err
	}
	after := ""
	for {
		page, err := readLegacyVaultCredentialPage(reader, after)
		if err != nil {
			return err
		}
		limit := len(page)
		if limit > 64 {
			limit = 64
		}
		for i := 0; i < limit; i++ {
			record := page[i]
			err = borrowLegacyVaultCredential(reader, record, secretTable, databasePath, electronUserDataPath, readers, visit)
			if err != nil {
				break
			}
			after = record.Metadata.ID
		}
		for i := range page {
			vault.Wipe(page[i].certificate)
		}
		if err != nil {
			return err
		}
		if reader.ctx.Err() != nil {
			return errVaultMigrationSource
		}
		if len(page) <= 64 {
			return nil
		}
	}
}

func validateLegacyVaultSecretSource(reader resolverCaptureReader) (bool, error) {
	for _, table := range []string{"CredentialPrivateKeyOperations", "CredentialSecretOperations"} {
		exists, err := tableExists(reader, table)
		if err != nil {
			return false, errVaultMigrationSource
		}
		if exists {
			var pending bool
			if reader.QueryRow("SELECT EXISTS(SELECT 1 FROM "+table+");").Scan(&pending) != nil || pending {
				return false, errVaultMigrationSource
			}
		}
	}
	secretTable, err := tableExists(reader, "CredentialSecrets")
	if err != nil {
		return false, errVaultMigrationSource
	}
	return secretTable, nil
}

func readLegacyVaultCredentialPage(reader resolverCaptureReader, after string) (result []legacyVaultCredential, resultErr error) {
	columns := []string{shadowText("Id", 36), shadowText("Name", 1024), shadowText("Username", 2048), shadowText("Domain", 2048), "Kind", "Protocol", "SecretProvider", shadowText("PrivateKeyFileName", 1024), shadowText("SshCertificateFileName", 1024), shadowText("BitwardenItemId", 2048), shadowText("BitwardenItemName", 4096), shadowText("BitwardenFieldPath", 2048), shadowText("CreatedAt", 128), shadowText("SshCertificate", maxSSHCertificateBytes)}
	rows, err := reader.Query("SELECT "+strings.Join(columns, ",")+" FROM CredentialProfiles WHERE (?='' OR lower(Id)>?) ORDER BY lower(Id),Id LIMIT 65;", after, after)
	if err != nil {
		return nil, errVaultMigrationSource
	}
	defer rows.Close()
	defer func() {
		if resultErr != nil {
			for i := range result {
				vault.Wipe(result[i].certificate)
			}
			result = nil
		}
	}()
	previous := after
	for rows.Next() {
		var record legacyVaultCredential
		var username, domain, keyName, certificateName, itemID, itemName, fieldPath, certificate sql.NullString
		var kind, protocol, provider int
		m := &record.Metadata
		if rows.Scan(&m.ID, &m.Name, &username, &domain, &kind, &protocol, &provider, &keyName, &certificateName, &itemID, &itemName, &fieldPath, &record.CreatedAt, &certificate) != nil {
			return result, errVaultMigrationSource
		}
		m.ID = strings.ToLower(m.ID)
		if !vaultCredentialID(m.ID) || m.ID <= previous {
			return result, errVaultMigrationSource
		}
		previous = m.ID
		m.Username, m.Domain, m.PrivateKeyName, m.CertificateName = username.String, domain.String, keyName.String, certificateName.String
		m.Protocol = map[int]string{0: "ssh", 1: "rdp", 6: "vnc"}[protocol]
		m.Kind = map[int]string{0: "password", 1: "sshKey"}[kind]
		m.Provider = map[int]string{0: "local", 1: "bitwarden"}[provider]
		m.BitwardenItemID, m.BitwardenItemName, m.BitwardenFieldPath = itemID.String, itemName.String, fieldPath.String
		if m.Provider == "local" && (m.BitwardenFieldPath == "" || m.BitwardenFieldPath == "login.password") {
			m.BitwardenFieldPath = ""
		}
		// Reuse the destination's complete metadata validator without writing it.
		candidate := vaultstore.Credential{CredentialMetadata: *m, RowVersion: 1, Seal: make([]byte, 32)}
		if candidate.Validate() != nil || !utf8.ValidString(record.CreatedAt) || len(record.CreatedAt) > 128 || strings.ContainsRune(record.CreatedAt, 0) || len(certificate.String) > maxSSHCertificateBytes {
			return result, errVaultMigrationSource
		}
		if certificate.String != "" {
			if m.Kind != "sshKey" || m.Provider != "local" {
				return result, errVaultMigrationSource
			}
			if _, err := parseSSHUserCertificate([]byte(certificate.String)); err != nil {
				return result, errVaultMigrationSource
			}
			record.certificate = []byte(certificate.String)
		}
		result = append(result, record)
	}
	if rows.Err() != nil {
		return result, errVaultMigrationSource
	}
	return result, nil
}

func borrowLegacyVaultCredential(reader resolverCaptureReader, record legacyVaultCredential, secretTable bool, databasePath, electronUserDataPath string, readers legacyVaultCredentialReaders, visit func(legacyVaultCredential, []localvault.SecretChange) error) error {
	var changes []localvault.SecretChange
	defer func() {
		for _, change := range changes {
			vault.Wipe(change.Value)
		}
	}()
	if reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	if secretTable {
		encoded, encoding, present, err := readLegacyVaultSecretRow(reader, record.Metadata.ID)
		if err != nil {
			return err
		}
		// Values no longer used by this provider are copied by the coordinator's
		// orphan archive pass, never attached to the active credential.
		if present && record.Metadata.Provider == "local" {
			value, err := readers.secret(record.Metadata.ID, encoded, encoding, electronUserDataPath)
			field := "password"
			if record.Metadata.Kind == "sshKey" {
				field = "passphrase"
			}
			changes = append(changes, localvault.SecretChange{Field: field, Value: value})
			if err != nil || len(value) > maxStoredCredentialBytes {
				return errVaultMigrationSource
			}
		}
	}
	if record.Metadata.Kind == "sshKey" {
		if reader.ctx.Err() != nil {
			return errVaultMigrationSource
		}
		value, err := readers.privateKey(credentialPrivateKeyPath(databasePath, record.Metadata.ID))
		changes = append(changes, localvault.SecretChange{Field: "privateKey", Value: value})
		if err != nil || len(value) == 0 || len(value) > maxSshPrivateKeyBytes {
			return errVaultMigrationSource
		}
		if record.certificate != nil {
			changes = append(changes, localvault.SecretChange{Field: "certificate", Value: record.certificate})
		}
	}
	if reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	if err := visit(record, changes); err != nil {
		return err
	}
	if reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	return nil
}

func readLegacyVaultSecretRow(reader resolverCaptureReader, id string) (encoded, encoding string, present bool, err error) {
	return readLegacyVaultSecretRowLimit(reader, id, 128*1024)
}

func readLegacyVaultSecretRowLimit(reader resolverCaptureReader, id string, maximum int) (encoded, encoding string, present bool, err error) {
	return readLegacyVaultSecretRowMatch(reader, id, maximum, false)
}

// exact is used only after the inventory validates canonical identity uniqueness
// and retains the stored spelling. The indexed lookup avoids scanning all source
// secrets for each orphan; domain readers still reject case-ambiguous matches.
func readLegacyVaultSecretRowMatch(reader resolverCaptureReader, id string, maximum int, exact bool) (encoded, encoding string, present bool, err error) {
	if maximum < 1 || maximum > 6*1024*1024 {
		return "", "", false, errVaultMigrationSource
	}
	// Bound encrypted inputs before crossing into a platform decryptor. The extra
	// byte preserves oversize detection; BLOB slicing preserves embedded NUL.
	column := "lower(Id)"
	if exact {
		column = "Id"
	}
	rows, e := reader.Query("SELECT "+shadowText("Secret", maximum)+","+shadowText("Encoding", 128)+" FROM CredentialSecrets WHERE "+column+"=? LIMIT 2;", id)
	if e != nil {
		return "", "", false, errVaultMigrationSource
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return "", "", false, errVaultMigrationSource
		}
		return "", "", false, nil
	}
	if rows.Scan(&encoded, &encoding) != nil || len(encoded) > maximum || len(encoding) > 128 || encoding == "" || !utf8.ValidString(encoded) || !utf8.ValidString(encoding) || strings.ContainsRune(encoded, 0) || strings.ContainsRune(encoding, 0) || rows.Next() || rows.Err() != nil {
		return "", "", false, errVaultMigrationSource
	}
	return encoded, encoding, true, nil
}
