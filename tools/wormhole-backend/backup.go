package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/unicode/norm"
)

// The backup contract is intentionally wire-compatible with the frozen WinUI service.
// Electron can therefore restore every historical Wormhole schema-v1/v2 backup, and the legacy
// app can consume new plaintext or encrypted exports produced by this backend.
const (
	backupCurrentSchemaVersion          = 2
	backupEncryptionNone                = "none"
	backupEncryptionAESGCM              = "aes-gcm"
	backupKDFPBKDF2SHA256               = "pbkdf2-sha256"
	backupPBKDF2Iterations              = 600_000
	backupMaxAcceptedIterations         = 5_000_000
	backupSaltLength                    = 16
	backupNonceLength                   = 12
	backupKeyLength                     = 32
	backupTagLength                     = 16
	backupMaxFileBytes            int64 = 64 * 1024 * 1024
	backupMaxNestingDepth               = 4096
	backupMaxPasswordBytes              = 16 * 1024
	backupMaxImportWarnings             = 1000
	backupMaxImportWarningBytes         = 1024
	backupSecretExportConcurrency       = 4
	bitwardenVirtualIDNamespace         = "wormhole-bitwarden-virtual-credential-v1"
)

var (
	errBackupPasswordRequired = errors.New("Backup file is encrypted; password required.")
	errBackupBadPassword      = errors.New("Backup password is incorrect or the file is corrupt.")

	// Tests replace this indirection so backup semantics can be exercised on hosts without an
	// interactive OS keychain. Production always delegates to the platform secret implementation.
	backupUnprotectStoredSecret = unprotectStoredSecret
)

type backupRequest struct {
	Path     string `json:"path"`
	Password string `json:"password"`
}

type backupDocument struct {
	SchemaVersion    int                     `json:"schemaVersion"`
	App              string                  `json:"app"`
	ExportedAt       string                  `json:"exportedAt"`
	Encryption       string                  `json:"encryption"`
	Payload          *backupPayload          `json:"payload,omitempty"`
	EncryptedPayload *backupEncryptedPayload `json:"encryptedPayload,omitempty"`
}

type backupEncryptedPayload struct {
	KDF           string `json:"kdf"`
	Iterations    int    `json:"iterations"`
	SaltB64       string `json:"saltB64"`
	NonceB64      string `json:"nonceB64"`
	CiphertextB64 string `json:"ciphertextB64"`
	TagB64        string `json:"tagB64"`
}

// Metadata objects stay as JSON maps so the Go boundary can preserve the complete legacy model
// without teaching renderer code about database columns. Access is still bounded and typed by the
// column contracts below; unknown/computed JSON properties are ignored on import.
type backupObject map[string]json.RawMessage

type backupPayload struct {
	Nodes                    []*backupObject              `json:"nodes"`
	Credentials              []*backupObject              `json:"credentials"`
	Tunnels                  []*backupObject              `json:"tunnels"`
	BitwardenCredentialCache []*backupObject              `json:"bitwardenCredentialCache"`
	Passwords                []*backupPasswordEntry       `json:"passwords"`
	InlinePasswords          []*backupInlinePasswordEntry `json:"inlinePasswords"`
	PrivateKeys              []*backupPrivateKeyEntry     `json:"privateKeys"`
	TunnelPayloads           []*backupTunnelPayloadEntry  `json:"tunnelPayloads"`
}

type backupPasswordEntry struct {
	CredentialID string `json:"credentialId"`
	Password     string `json:"password"`
}

type backupInlinePasswordEntry struct {
	NodeID   string `json:"nodeId"`
	Password string `json:"password"`
}

type backupPrivateKeyEntry struct {
	CredentialID     string  `json:"credentialId"`
	OriginalFileName *string `json:"originalFileName,omitempty"`
	DataB64          string  `json:"dataB64"`
}

type backupTunnelPayloadEntry struct {
	TunnelConfigID string `json:"tunnelConfigId"`
	DataB64        string `json:"dataB64"`
}

type backupExportResult struct {
	Path               string `json:"path"`
	NodeCount          int    `json:"nodeCount"`
	CredentialCount    int    `json:"credentialCount"`
	TunnelCount        int    `json:"tunnelCount"`
	PasswordCount      int    `json:"passwordCount"`
	PrivateKeyCount    int    `json:"privateKeyCount"`
	TunnelPayloadCount int    `json:"tunnelPayloadCount"`
	Encrypted          bool   `json:"encrypted"`
}

type backupImportResult struct {
	NodesImported          int      `json:"nodesImported"`
	NodesSkipped           int      `json:"nodesSkipped"`
	CredentialsImported    int      `json:"credentialsImported"`
	CredentialsSkipped     int      `json:"credentialsSkipped"`
	TunnelsImported        int      `json:"tunnelsImported"`
	TunnelsSkipped         int      `json:"tunnelsSkipped"`
	PasswordsImported      int      `json:"passwordsImported"`
	PrivateKeysImported    int      `json:"privateKeysImported"`
	TunnelPayloadsImported int      `json:"tunnelPayloadsImported"`
	Warnings               []string `json:"warnings"`
	warningCount           int
}

func addBackupWarning(result *backupImportResult, warning string) {
	result.warningCount++
	if len(result.Warnings) < backupMaxImportWarnings {
		result.Warnings = append(result.Warnings, boundBackupWarning(warning))
		return
	}
	omitted := result.warningCount - (backupMaxImportWarnings - 1)
	result.Warnings[backupMaxImportWarnings-1] = fmt.Sprintf(
		"%d additional import warnings were omitted.", omitted,
	)
}

func boundBackupWarning(warning string) string {
	bounded := warning
	if len(bounded) > backupMaxImportWarningBytes {
		const suffix = "..."
		cutoff := backupMaxImportWarningBytes - len(suffix)
		for cutoff > 0 && !utf8.RuneStart(bounded[cutoff]) {
			cutoff--
		}
		bounded = bounded[:cutoff] + suffix
	}
	return strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return ' '
		}
		return character
	}, bounded)
}

type backupInspectResult struct {
	Encrypted     bool   `json:"encrypted"`
	SchemaVersion int    `json:"schemaVersion"`
	ExportedAt    string `json:"exportedAt"`
}

type backupValueKind int

const (
	backupString backupValueKind = iota
	backupInteger
	backupBoolean
)

type backupColumn struct {
	DB       string
	JSON     string
	Kind     backupValueKind
	Required bool
	Default  any
	SQLType  string
}

var backupNodeColumns = []backupColumn{
	{DB: "Id", JSON: "id", Kind: backupString, Required: true, Default: "", SQLType: "TEXT PRIMARY KEY NOT NULL"},
	{DB: "ParentId", JSON: "parentId", Kind: backupString, SQLType: "TEXT NULL REFERENCES Nodes(Id) ON DELETE CASCADE"},
	{DB: "Name", JSON: "name", Kind: backupString, Required: true, Default: "", SQLType: "TEXT NOT NULL"},
	{DB: "Kind", JSON: "kind", Kind: backupInteger, Required: true, Default: int64(0), SQLType: "INTEGER NOT NULL"},
	{DB: "SortOrder", JSON: "sortOrder", Kind: backupInteger, Required: true, Default: int64(0), SQLType: "INTEGER NOT NULL DEFAULT 0"},
	{DB: "Protocol", JSON: "protocol", Kind: backupInteger, SQLType: "INTEGER NULL"},
	{DB: "Host", JSON: "host", Kind: backupString, SQLType: "TEXT NULL"},
	{DB: "Port", JSON: "port", Kind: backupInteger, SQLType: "INTEGER NULL"},
	{DB: "Username", JSON: "username", Kind: backupString, SQLType: "TEXT NULL"},
	{DB: "CredentialId", JSON: "credentialId", Kind: backupString, SQLType: "TEXT NULL"},
	{DB: "CredentialMode", JSON: "credentialMode", Kind: backupInteger, SQLType: "INTEGER NULL"},
	{DB: "UseInlinePassword", JSON: "useInlinePassword", Kind: backupBoolean, SQLType: "INTEGER NULL"},
	{DB: "RdpDomain", JSON: "rdpDomain", Kind: backupString, SQLType: "TEXT NULL"},
	{DB: "RdpScreenSize", JSON: "rdpScreenSize", Kind: backupString, SQLType: "TEXT NULL"},
	{DB: "RdpFullScreen", JSON: "rdpFullScreen", Kind: backupBoolean, SQLType: "INTEGER NULL"},
	{DB: "RdpColorDepth", JSON: "rdpColorDepth", Kind: backupInteger, SQLType: "INTEGER NULL"},
	{DB: "RdpUseAllMonitors", JSON: "rdpUseAllMonitors", Kind: backupBoolean, SQLType: "INTEGER NULL"},
	{DB: "RdpAudioMode", JSON: "rdpAudioMode", Kind: backupInteger, SQLType: "INTEGER NULL"},
	{DB: "RdpAudioCaptureMode", JSON: "rdpAudioCaptureMode", Kind: backupInteger, SQLType: "INTEGER NULL"},
	{DB: "RdpKeyboardHookMode", JSON: "rdpKeyboardHookMode", Kind: backupInteger, SQLType: "INTEGER NULL"},
	{DB: "RdpRedirectClipboard", JSON: "rdpRedirectClipboard", Kind: backupBoolean, SQLType: "INTEGER NULL"},
	{DB: "RdpRedirectPrinters", JSON: "rdpRedirectPrinters", Kind: backupBoolean, SQLType: "INTEGER NULL"},
	{DB: "RdpRedirectSmartCards", JSON: "rdpRedirectSmartCards", Kind: backupBoolean, SQLType: "INTEGER NULL"},
	{DB: "RdpRedirectPorts", JSON: "rdpRedirectPorts", Kind: backupBoolean, SQLType: "INTEGER NULL"},
	{DB: "RdpRedirectDevices", JSON: "rdpRedirectDevices", Kind: backupBoolean, SQLType: "INTEGER NULL"},
	{DB: "RdpRedirectDrives", JSON: "rdpRedirectDrives", Kind: backupString, SQLType: "TEXT NULL"},
	{DB: "RdpConnectionSpeed", JSON: "rdpConnectionSpeed", Kind: backupInteger, SQLType: "INTEGER NULL"},
	{DB: "RdpDesktopBackground", JSON: "rdpDesktopBackground", Kind: backupBoolean, SQLType: "INTEGER NULL"},
	{DB: "RdpFontSmoothing", JSON: "rdpFontSmoothing", Kind: backupBoolean, SQLType: "INTEGER NULL"},
	{DB: "RdpDesktopComposition", JSON: "rdpDesktopComposition", Kind: backupBoolean, SQLType: "INTEGER NULL"},
	{DB: "RdpWindowDrag", JSON: "rdpWindowDrag", Kind: backupBoolean, SQLType: "INTEGER NULL"},
	{DB: "RdpMenuAnimation", JSON: "rdpMenuAnimation", Kind: backupBoolean, SQLType: "INTEGER NULL"},
	{DB: "RdpVisualStyles", JSON: "rdpVisualStyles", Kind: backupBoolean, SQLType: "INTEGER NULL"},
	{DB: "RdpBitmapCaching", JSON: "rdpBitmapCaching", Kind: backupBoolean, SQLType: "INTEGER NULL"},
	{DB: "RdpAutoReconnect", JSON: "rdpAutoReconnect", Kind: backupBoolean, SQLType: "INTEGER NULL"},
	{DB: "RdpServerAuthentication", JSON: "rdpServerAuthentication", Kind: backupInteger, SQLType: "INTEGER NULL"},
	{DB: "RdpGatewayUsageMethod", JSON: "rdpGatewayUsageMethod", Kind: backupInteger, SQLType: "INTEGER NULL"},
	{DB: "RdpGatewayHostname", JSON: "rdpGatewayHostname", Kind: backupString, SQLType: "TEXT NULL"},
	{DB: "RdpGatewayCredentialId", JSON: "rdpGatewayCredentialId", Kind: backupString, SQLType: "TEXT NULL"},
	{DB: "RdpGatewayBypassLocal", JSON: "rdpGatewayBypassLocal", Kind: backupBoolean, SQLType: "INTEGER NULL"},
	{DB: "RdpGatewayUseSameCreds", JSON: "rdpGatewayUseSameCreds", Kind: backupBoolean, SQLType: "INTEGER NULL"},
	{DB: "RdpUseExternalClient", JSON: "rdpUseExternalClient", Kind: backupBoolean, SQLType: "INTEGER NULL"},
	{DB: "SshKeyFileName", JSON: "sshKeyFileName", Kind: backupString, SQLType: "TEXT NULL"},
	{DB: "SshKnownHostFingerprint", JSON: "sshKnownHostFingerprint", Kind: backupString, SQLType: "TEXT NULL"},
	{DB: "SshAutoSudo", JSON: "sshAutoSudo", Kind: backupBoolean, SQLType: "INTEGER NULL"},
	{DB: "SerialBaudRate", JSON: "serialBaudRate", Kind: backupInteger, SQLType: "INTEGER NULL"},
	{DB: "SerialDataBits", JSON: "serialDataBits", Kind: backupInteger, SQLType: "INTEGER NULL"},
	{DB: "SerialStopBits", JSON: "serialStopBits", Kind: backupInteger, SQLType: "INTEGER NULL"},
	{DB: "SerialParity", JSON: "serialParity", Kind: backupInteger, SQLType: "INTEGER NULL"},
	{DB: "SerialFlowControl", JSON: "serialFlowControl", Kind: backupInteger, SQLType: "INTEGER NULL"},
	{DB: "HttpIgnoreCertErrors", JSON: "httpIgnoreCertErrors", Kind: backupBoolean, SQLType: "INTEGER NULL"},
	{DB: "TunnelEnabled", JSON: "tunnelEnabled", Kind: backupBoolean, SQLType: "INTEGER NULL"},
	{DB: "TunnelConfigId", JSON: "tunnelConfigId", Kind: backupString, SQLType: "TEXT NULL"},
	{DB: "CreatedAt", JSON: "createdAt", Kind: backupString, Required: true, Default: "", SQLType: "TEXT NOT NULL"},
	{DB: "UpdatedAt", JSON: "updatedAt", Kind: backupString, Required: true, Default: "", SQLType: "TEXT NOT NULL"},
}

var backupCredentialColumns = []backupColumn{
	{DB: "Id", JSON: "id", Kind: backupString, Required: true, Default: "", SQLType: "TEXT PRIMARY KEY NOT NULL"},
	{DB: "Name", JSON: "name", Kind: backupString, Required: true, Default: "", SQLType: "TEXT NOT NULL"},
	{DB: "Username", JSON: "username", Kind: backupString, SQLType: "TEXT NULL"},
	{DB: "Domain", JSON: "domain", Kind: backupString, SQLType: "TEXT NULL"},
	{DB: "Kind", JSON: "kind", Kind: backupInteger, Required: true, Default: int64(0), SQLType: "INTEGER NOT NULL DEFAULT 0"},
	{DB: "PrivateKeyFileName", JSON: "privateKeyFileName", Kind: backupString, SQLType: "TEXT NULL"},
	{DB: "Protocol", JSON: "protocol", Kind: backupInteger, Required: true, Default: int64(0), SQLType: "INTEGER NOT NULL DEFAULT 0"},
	{DB: "SecretProvider", JSON: "secretProvider", Kind: backupInteger, Required: true, Default: int64(0), SQLType: "INTEGER NOT NULL DEFAULT 0"},
	{DB: "BitwardenItemId", JSON: "bitwardenItemId", Kind: backupString, SQLType: "TEXT NULL"},
	{DB: "BitwardenItemName", JSON: "bitwardenItemName", Kind: backupString, SQLType: "TEXT NULL"},
	{DB: "BitwardenFieldPath", JSON: "bitwardenFieldPath", Kind: backupString, Required: true, Default: "login.password", SQLType: "TEXT NOT NULL DEFAULT 'login.password'"},
	{DB: "CreatedAt", JSON: "createdAt", Kind: backupString, Required: true, Default: "", SQLType: "TEXT NOT NULL"},
}

var backupTunnelColumns = []backupColumn{
	{DB: "Id", JSON: "id", Kind: backupString, Required: true, Default: "", SQLType: "TEXT PRIMARY KEY NOT NULL"},
	{DB: "Name", JSON: "name", Kind: backupString, Required: true, Default: "", SQLType: "TEXT NOT NULL"},
	{DB: "Kind", JSON: "kind", Kind: backupInteger, Required: true, Default: int64(0), SQLType: "INTEGER NOT NULL"},
	{DB: "CreatedAt", JSON: "createdAt", Kind: backupString, Required: true, Default: "", SQLType: "TEXT NOT NULL"},
	{DB: "UpdatedAt", JSON: "updatedAt", Kind: backupString, Required: true, Default: "", SQLType: "TEXT NOT NULL"},
}

var backupBitwardenColumns = []backupColumn{
	{DB: "ItemId", JSON: "itemId", Kind: backupString, Required: true, Default: "", SQLType: "TEXT PRIMARY KEY NOT NULL"},
	{DB: "SshCredentialId", JSON: "sshCredentialId", Kind: backupString, Required: true, Default: "00000000-0000-0000-0000-000000000000", SQLType: "TEXT NOT NULL"},
	{DB: "RdpCredentialId", JSON: "rdpCredentialId", Kind: backupString, Required: true, Default: "00000000-0000-0000-0000-000000000000", SQLType: "TEXT NOT NULL"},
	{DB: "VncCredentialId", JSON: "vncCredentialId", Kind: backupString, Required: true, Default: "00000000-0000-0000-0000-000000000000", SQLType: "TEXT NOT NULL"},
	{DB: "Name", JSON: "name", Kind: backupString, Required: true, Default: "", SQLType: "TEXT NOT NULL"},
	{DB: "Username", JSON: "username", Kind: backupString, SQLType: "TEXT NULL"},
	{DB: "RevisionDate", JSON: "revisionDate", Kind: backupString, SQLType: "TEXT NULL"},
	{DB: "LastSeenSyncUtc", JSON: "lastSeenSyncUtc", Kind: backupString, Required: true, Default: "", SQLType: "TEXT NOT NULL"},
	{DB: "UpdatedAtUtc", JSON: "updatedAtUtc", Kind: backupString, Required: true, Default: "", SQLType: "TEXT NOT NULL"},
}

func inspectBackup(request backupRequest) (backupInspectResult, error) {
	contents, err := readBackupFile(request.Path)
	if err != nil {
		return backupInspectResult{}, err
	}
	defer clearBytes(contents)
	var document backupDocument
	if err := json.Unmarshal(contents, &document); err != nil {
		return backupInspectResult{}, errors.New("Backup file is empty or malformed.")
	}
	if err := validateBackupDocumentMetadata(document); err != nil {
		return backupInspectResult{}, err
	}
	return backupInspectResult{
		Encrypted:     strings.EqualFold(document.Encryption, backupEncryptionAESGCM),
		SchemaVersion: document.SchemaVersion,
		ExportedAt:    document.ExportedAt,
	}, nil
}

func exportBackup(databasePath string, request backupRequest) (backupExportResult, error) {
	return exportBackupContext(context.Background(), databasePath, request, nil)
}

func exportBackupContext(
	ctx context.Context,
	databasePath string,
	request backupRequest,
	progress operationProgress,
) (backupExportResult, error) {
	if err := validateBackupRequest(request, true); err != nil {
		return backupExportResult{}, err
	}
	if isBackupWorkspaceStoragePath(databasePath, request.Path) {
		return backupExportResult{}, errors.New("The backup destination cannot be Wormhole workspace storage.")
	}
	if err := ctx.Err(); err != nil {
		return backupExportResult{}, err
	}
	reportOperationProgress(progress, "reading", "Reading workspace metadata…", 10)

	payload := newBackupPayload()
	if err := populateBackupPayloadContext(ctx, databasePath, payload, progress); err != nil {
		return backupExportResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return backupExportResult{}, err
	}
	reportOperationProgress(progress, "encoding", "Encrypting and encoding the backup…", 70)

	document := backupDocument{
		SchemaVersion: backupCurrentSchemaVersion,
		App:           "Wormhole",
		ExportedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		Encryption:    backupEncryptionNone,
		Payload:       payload,
	}
	encrypted := request.Password != ""
	if encrypted {
		plaintext, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			return backupExportResult{}, errors.New("Could not serialize the backup payload.")
		}
		sealed, sealErr := sealBackupPayload(plaintext, request.Password)
		clearBytes(plaintext)
		if sealErr != nil {
			return backupExportResult{}, sealErr
		}
		document.Encryption = backupEncryptionAESGCM
		document.Payload = nil
		document.EncryptedPayload = &sealed
	}

	encoded, err := encodeBackupDocument(document, backupMaxFileBytes)
	if err != nil {
		return backupExportResult{}, err
	}
	defer clearBytes(encoded)
	if err := ctx.Err(); err != nil {
		return backupExportResult{}, err
	}
	reportOperationProgress(progress, "writing", "Writing the backup file…", 90)
	if err := writeBackupFile(request.Path, encoded); err != nil {
		return backupExportResult{}, err
	}

	result := backupExportResult{
		Path:               request.Path,
		NodeCount:          len(payload.Nodes),
		CredentialCount:    len(payload.Credentials),
		TunnelCount:        len(payload.Tunnels),
		PasswordCount:      len(payload.Passwords) + len(payload.InlinePasswords),
		PrivateKeyCount:    len(payload.PrivateKeys),
		TunnelPayloadCount: len(payload.TunnelPayloads),
		Encrypted:          encrypted,
	}
	logInfo("backup exported: nodes=%d credentials=%d tunnels=%d encrypted=%t",
		result.NodeCount, result.CredentialCount, result.TunnelCount, encrypted)
	reportOperationProgress(progress, "complete", "Backup export complete.", 100)
	return result, nil
}

func populateBackupPayloadContext(
	ctx context.Context,
	databasePath string,
	payload *backupPayload,
	progress operationProgress,
) error {
	release, err := acquireRecoveredCredentialPrivateKeyLock(databasePath)
	if err != nil {
		return err
	}
	defer release()

	database, err := openDatabase(databasePath, true)
	if err != nil {
		return err
	}
	if database == nil {
		return nil
	}
	defer database.Close()
	if payload.Nodes, err = loadBackupObjectsContext(ctx, database, "Nodes", backupNodeColumns); err != nil {
		return err
	}
	if payload.Credentials, err = loadBackupObjectsContext(ctx, database, "CredentialProfiles", backupCredentialColumns); err != nil {
		return err
	}
	if payload.Tunnels, err = loadBackupObjectsContext(ctx, database, "TunnelConfigs", backupTunnelColumns); err != nil {
		return err
	}
	if payload.BitwardenCredentialCache, err = loadBackupObjectsContext(ctx, database, "BitwardenCredentialCache", backupBitwardenColumns); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	reportOperationProgress(progress, "secrets", "Reading protected secrets…", 35)
	return exportBackupSecretsContext(ctx, database, databasePath, payload)
}

func encodeBackupDocument(document backupDocument, maximumBytes int64) ([]byte, error) {
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, errors.New("Could not serialize the backup file.")
	}
	encoded = append(encoded, '\n')
	if int64(len(encoded)) > maximumBytes {
		clearBytes(encoded)
		return nil, fmt.Errorf("Backup contents exceed the %d-byte safety limit.", maximumBytes)
	}
	return encoded, nil
}

func newBackupPayload() *backupPayload {
	return &backupPayload{
		Nodes:                    []*backupObject{},
		Credentials:              []*backupObject{},
		Tunnels:                  []*backupObject{},
		BitwardenCredentialCache: []*backupObject{},
		Passwords:                []*backupPasswordEntry{},
		InlinePasswords:          []*backupInlinePasswordEntry{},
		PrivateKeys:              []*backupPrivateKeyEntry{},
		TunnelPayloads:           []*backupTunnelPayloadEntry{},
	}
}

func loadBackupObjectsContext(
	ctx context.Context,
	database *sql.DB,
	table string,
	columns []backupColumn,
) ([]*backupObject, error) {
	exists, err := tableExists(database, table)
	if err != nil || !exists {
		return []*backupObject{}, err
	}
	available, err := tableColumns(database, table)
	if err != nil {
		return nil, err
	}
	selects := make([]string, len(columns))
	for index, column := range columns {
		if _, ok := available[column.DB]; ok {
			selects[index] = quoteBackupIdentifier(column.DB)
		} else {
			selects[index] = "NULL"
		}
	}
	order := ""
	if table == "Nodes" {
		order = " ORDER BY SortOrder, Name, Id"
	} else if table == "BitwardenCredentialCache" {
		order = " ORDER BY Name, ItemId"
	} else {
		order = " ORDER BY Name, Id"
	}
	rows, err := database.QueryContext(ctx, "SELECT "+strings.Join(selects, ", ")+" FROM "+quoteBackupIdentifier(table)+order+";")
	if err != nil {
		return nil, fmt.Errorf("Could not read backup metadata: %w", err)
	}
	defer rows.Close()
	objects := make([]*backupObject, 0)
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		values := make([]any, len(columns))
		destinations := make([]any, len(columns))
		for index := range values {
			destinations[index] = &values[index]
		}
		if err := rows.Scan(destinations...); err != nil {
			return nil, fmt.Errorf("Could not read backup metadata: %w", err)
		}
		object := backupObject{}
		for index, column := range columns {
			value := values[index]
			if value == nil {
				if !column.Required {
					continue
				}
				value = column.Default
			}
			converted, err := backupJSONValue(column, value)
			if err != nil {
				return nil, err
			}
			object[column.JSON] = converted
		}
		objects = append(objects, &object)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("Could not enumerate backup metadata: %w", err)
	}
	return objects, nil
}

func backupJSONValue(column backupColumn, value any) (json.RawMessage, error) {
	var normalized any
	switch column.Kind {
	case backupString:
		switch typed := value.(type) {
		case string:
			normalized = typed
		case []byte:
			normalized = string(typed)
		default:
			normalized = fmt.Sprint(value)
		}
		if isBackupTimestampField(column.JSON) {
			normalized = normalizeBackupTimestamp(normalized.(string))
		}
	case backupInteger:
		integer, ok := backupDatabaseInteger(value)
		if !ok {
			return nil, fmt.Errorf("Backup metadata field %s is not an integer", column.DB)
		}
		normalized = integer
	case backupBoolean:
		integer, ok := backupDatabaseInteger(value)
		if !ok {
			return nil, fmt.Errorf("Backup metadata field %s is not a boolean", column.DB)
		}
		normalized = integer != 0
	}
	encoded, err := json.Marshal(normalized)
	return json.RawMessage(encoded), err
}

func isBackupTimestampField(name string) bool {
	switch name {
	case "createdAt", "updatedAt", "lastSeenSyncUtc", "updatedAtUtc":
		return true
	default:
		return false
	}
}

func normalizeBackupTimestamp(value string) string {
	if parsed, ok := parseBackupTimestamp(value); ok {
		return parsed.UTC().Format(time.RFC3339Nano)
	}
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func parseBackupTimestamp(value string) (time.Time, bool) {
	trimmed := strings.TrimSpace(value)
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05.999999999 Z07:00",
		"2006-01-02T15:04:05.999999999",
		"2006-01-02 15:04:05.999999999",
	} {
		parsed, err := time.Parse(layout, trimmed)
		if err == nil && parsed.Year() > 1 {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func backupDatabaseInteger(value any) (int64, bool) {
	switch typed := value.(type) {
	case int64:
		return typed, true
	case int:
		return int64(typed), true
	case bool:
		if typed {
			return 1, true
		}
		return 0, true
	case []byte:
		var result int64
		_, err := fmt.Sscan(string(typed), &result)
		return result, err == nil
	case string:
		var result int64
		_, err := fmt.Sscan(typed, &result)
		return result, err == nil
	default:
		return 0, false
	}
}

func exportBackupSecretsContext(ctx context.Context, database *sql.DB, databasePath string, payload *backupPayload) error {
	passwordEntries := make([]*backupPasswordEntry, len(payload.Credentials))
	privateKeyEntries := make([]*backupPrivateKeyEntry, len(payload.Credentials))
	if err := runBackupSecretReadsContext(ctx, len(payload.Credentials), func(index int) error {
		credential := payload.Credentials[index]
		if credential == nil {
			return nil
		}
		id := backupObjectString(*credential, "id")
		kind, _ := backupObjectInteger(*credential, "kind")
		provider, _ := backupObjectInteger(*credential, "secretProvider")
		if (kind == 0 || kind == 1) && provider != 1 {
			password, found, err := readBackupPassword(database, id)
			if err != nil {
				return fmt.Errorf("Could not read a credential secret for backup: %w", err)
			}
			if found {
				passwordEntries[index] = &backupPasswordEntry{CredentialID: id, Password: password}
			}
		}
		if kind != 1 || provider != 0 {
			return nil
		}
		keyPath := credentialPrivateKeyPath(databasePath, id)
		keyBytes, err := readBackupPrivateKey(keyPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return errors.New("Could not read an SSH private key for backup")
		}
		encoded := base64.StdEncoding.EncodeToString(keyBytes)
		clearBytes(keyBytes)
		fileName := backupObjectOptionalString(*credential, "privateKeyFileName")
		privateKeyEntries[index] = &backupPrivateKeyEntry{
			CredentialID: id, OriginalFileName: fileName, DataB64: encoded,
		}
		return nil
	}); err != nil {
		return err
	}
	for index := range passwordEntries {
		if passwordEntries[index] != nil {
			payload.Passwords = append(payload.Passwords, passwordEntries[index])
		}
		if privateKeyEntries[index] != nil {
			payload.PrivateKeys = append(payload.PrivateKeys, privateKeyEntries[index])
		}
	}

	inlinePasswordEntries := make([]*backupInlinePasswordEntry, len(payload.Nodes))
	if err := runBackupSecretReadsContext(ctx, len(payload.Nodes), func(index int) error {
		node := payload.Nodes[index]
		if node == nil {
			return nil
		}
		kind, _ := backupObjectInteger(*node, "kind")
		inline, present := backupObjectBoolean(*node, "useInlinePassword")
		if kind != 1 || !present || !inline {
			return nil
		}
		id := backupObjectString(*node, "id")
		password, found, err := readBackupPassword(database, id)
		if err != nil {
			return fmt.Errorf("Could not read an inline password for backup: %w", err)
		}
		if found && password != "" {
			inlinePasswordEntries[index] = &backupInlinePasswordEntry{NodeID: id, Password: password}
		}
		return nil
	}); err != nil {
		return err
	}
	for _, entry := range inlinePasswordEntries {
		if entry != nil {
			payload.InlinePasswords = append(payload.InlinePasswords, entry)
		}
	}

	tunnelPayloadEntries := make([]*backupTunnelPayloadEntry, len(payload.Tunnels))
	if err := runBackupSecretReadsContext(ctx, len(payload.Tunnels), func(index int) error {
		tunnel := payload.Tunnels[index]
		if tunnel == nil {
			return nil
		}
		id := backupObjectString(*tunnel, "id")
		settings, found, err := readBackupTunnelSettings(database, databasePath, id)
		if !found && err == nil {
			return nil
		}
		if err != nil {
			return errors.New("Could not read a VPN tunnel payload for backup")
		}
		encoded := base64.StdEncoding.EncodeToString(settings)
		clearBytes(settings)
		tunnelPayloadEntries[index] = &backupTunnelPayloadEntry{TunnelConfigID: id, DataB64: encoded}
		return nil
	}); err != nil {
		return err
	}
	for _, entry := range tunnelPayloadEntries {
		if entry != nil {
			payload.TunnelPayloads = append(payload.TunnelPayloads, entry)
		}
	}
	return nil
}

func readBackupPrivateKey(path string) ([]byte, error) {
	return unprotectSshPrivateKey(path)
}

func runBackupSecretReads(count int, read func(index int) error) error {
	return runBackupSecretReadsContext(context.Background(), count, read)
}

func runBackupSecretReadsContext(ctx context.Context, count int, read func(index int) error) error {
	semaphore := make(chan struct{}, backupSecretExportConcurrency)
	var waitGroup sync.WaitGroup
	var errorLock sync.Mutex
	var firstError error
readLoop:
	for index := 0; index < count; index++ {
		select {
		case semaphore <- struct{}{}:
		case <-ctx.Done():
			break readLoop
		}
		errorLock.Lock()
		stopped := firstError != nil
		errorLock.Unlock()
		if stopped {
			<-semaphore
			break
		}
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			defer func() { <-semaphore }()
			if err := ctx.Err(); err != nil {
				errorLock.Lock()
				if firstError == nil {
					firstError = err
				}
				errorLock.Unlock()
			} else if err := read(index); err != nil {
				errorLock.Lock()
				if firstError == nil {
					firstError = err
				}
				errorLock.Unlock()
			}
		}(index)
	}
	waitGroup.Wait()
	if err := ctx.Err(); err != nil && firstError == nil {
		return err
	}
	return firstError
}

func readBackupTunnelSettings(database *sql.DB, databasePath, id string) ([]byte, bool, error) {
	secretPath := legacyTunnelSecretPath(databasePath, id)
	if info, statErr := os.Stat(secretPath); statErr == nil && info.Size() > maxTunnelProtectedBytes {
		return nil, false, errors.New("VPN tunnel payload exceeds the supported size")
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return nil, false, statErr
	}
	settings, err := unprotectFile(secretPath)
	if err == nil {
		return validateBackupTunnelSettings(settings)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	exists, err := tableExists(database, "CredentialSecrets")
	if err != nil || !exists {
		return nil, false, err
	}
	secretID := tunnelSecretID(id)
	var encoded, encoding string
	err = database.QueryRow(
		"SELECT Secret, Encoding FROM CredentialSecrets WHERE Id = ? LIMIT 1;", secretID,
	).Scan(&encoded, &encoding)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	settings, err = backupUnprotectStoredSecret(secretID, encoded, encoding)
	if err != nil {
		return nil, false, err
	}
	return validateBackupTunnelSettings(settings)
}

func validateBackupTunnelSettings(settings []byte) ([]byte, bool, error) {
	defer clearBytes(settings)
	validated, err := validateStoredTunnelSettings(settings)
	if err != nil {
		return nil, false, err
	}
	return validated, true, nil
}

func readBackupPassword(database *sql.DB, id string) (string, bool, error) {
	exists, err := tableExists(database, "CredentialSecrets")
	if err != nil || !exists {
		return "", false, err
	}
	var encoded, encoding string
	err = database.QueryRow(
		"SELECT Secret, Encoding FROM CredentialSecrets WHERE lower(Id) = lower(?) LIMIT 1;", id,
	).Scan(&encoded, &encoding)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	secret, err := backupUnprotectStoredSecret(id, encoded, encoding)
	if err != nil {
		return "", false, err
	}
	defer clearBytes(secret)
	return string(secret), true, nil
}

func sealBackupPayload(plaintext []byte, password string) (backupEncryptedPayload, error) {
	salt := make([]byte, backupSaltLength)
	nonce := make([]byte, backupNonceLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return backupEncryptedPayload{}, errors.New("Could not create backup encryption salt")
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return backupEncryptedPayload{}, errors.New("Could not create backup encryption nonce")
	}
	key := deriveBackupKey(password, salt, backupPBKDF2Iterations)
	defer clearBytes(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return backupEncryptedPayload{}, errors.New("Could not initialize backup encryption")
	}
	gcm, err := cipher.NewGCMWithTagSize(block, backupTagLength)
	if err != nil {
		return backupEncryptedPayload{}, errors.New("Could not initialize backup encryption")
	}
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	ciphertext := sealed[:len(sealed)-backupTagLength]
	tag := sealed[len(sealed)-backupTagLength:]
	return backupEncryptedPayload{
		KDF:           backupKDFPBKDF2SHA256,
		Iterations:    backupPBKDF2Iterations,
		SaltB64:       base64.StdEncoding.EncodeToString(salt),
		NonceB64:      base64.StdEncoding.EncodeToString(nonce),
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
		TagB64:        base64.StdEncoding.EncodeToString(tag),
	}, nil
}

func unsealBackupPayload(sealed backupEncryptedPayload, password string) ([]byte, error) {
	if !strings.EqualFold(sealed.KDF, backupKDFPBKDF2SHA256) {
		return nil, errors.New("Encrypted backup uses an unsupported key derivation function.")
	}
	salt, saltErr := base64.StdEncoding.DecodeString(sealed.SaltB64)
	nonce, nonceErr := base64.StdEncoding.DecodeString(sealed.NonceB64)
	ciphertext, ciphertextErr := base64.StdEncoding.DecodeString(sealed.CiphertextB64)
	tag, tagErr := base64.StdEncoding.DecodeString(sealed.TagB64)
	if saltErr != nil || nonceErr != nil || ciphertextErr != nil || tagErr != nil {
		return nil, errors.New("Encrypted backup envelope is malformed.")
	}
	iterations := sealed.Iterations
	if iterations <= 0 {
		iterations = backupPBKDF2Iterations
	}
	if iterations > backupMaxAcceptedIterations {
		return nil, fmt.Errorf("Backup file declares %d PBKDF2 iterations, which exceeds the maximum accepted value (%d). Refusing to decrypt.", iterations, backupMaxAcceptedIterations)
	}
	if len(nonce) != backupNonceLength || len(tag) < 12 || len(tag) > 16 || len(salt) == 0 || len(ciphertext) == 0 {
		return nil, errors.New("Encrypted backup envelope has malformed nonce, tag, salt, or ciphertext lengths.")
	}
	key := deriveBackupKey(password, salt, iterations)
	defer clearBytes(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errBackupBadPassword
	}
	gcm, err := cipher.NewGCMWithTagSize(block, len(tag))
	if err != nil {
		return nil, errors.New("Encrypted backup envelope has malformed nonce, tag, salt, or ciphertext lengths.")
	}
	combined := make([]byte, 0, len(ciphertext)+len(tag))
	combined = append(combined, ciphertext...)
	combined = append(combined, tag...)
	plaintext, err := gcm.Open(nil, nonce, combined, nil)
	clearBytes(combined)
	if err != nil {
		return nil, errBackupBadPassword
	}
	return plaintext, nil
}

func deriveBackupKey(password string, salt []byte, iterations int) []byte {
	// Matches BackupService.DeriveKey: NFC normalization makes composed/decomposed passwords
	// interoperable across Windows, macOS and Linux.
	passwordBytes := []byte(norm.NFC.String(password))
	key := pbkdf2.Key(passwordBytes, salt, iterations, backupKeyLength, sha256.New)
	clearBytes(passwordBytes)
	return key
}

func validateBackupRequest(request backupRequest, allowPassword bool) error {
	path := strings.TrimSpace(request.Path)
	if path == "" || !filepath.IsAbs(path) || strings.ContainsRune(path, 0) {
		return errors.New("Backup path is invalid.")
	}
	if !allowPassword && request.Password != "" {
		return errors.New("Backup request is invalid.")
	}
	if len([]byte(request.Password)) > backupMaxPasswordBytes {
		return errors.New("Backup password is too long.")
	}
	return nil
}

func readBackupFile(path string) ([]byte, error) {
	if err := validateBackupRequest(backupRequest{Path: path}, false); err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, errors.New("Could not open the backup file.")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("Backup path is not a regular file.")
	}
	if info.Size() > backupMaxFileBytes {
		return nil, fmt.Errorf("Backup file is %d bytes; refusing to read anything larger than %d bytes.", info.Size(), backupMaxFileBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("Could not open the backup file.")
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, backupMaxFileBytes+1))
	if err != nil {
		return nil, errors.New("Could not read the backup file.")
	}
	if int64(len(contents)) > backupMaxFileBytes {
		return nil, fmt.Errorf("Backup file exceeds the %d-byte safety limit.", backupMaxFileBytes)
	}
	return contents, nil
}

func writeBackupFile(path string, contents []byte) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".wormhole-backup-*.tmp")
	if err != nil {
		return errors.New("Could not create the backup file.")
	}
	temporaryPath := file.Name()
	written := false
	defer func() {
		_ = file.Close()
		if !written {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return errors.New("Could not secure the backup file.")
	}
	if _, err := file.Write(contents); err != nil {
		return errors.New("Could not write the backup file.")
	}
	if err := file.Sync(); err != nil {
		return errors.New("Could not flush the backup file.")
	}
	if err := file.Close(); err != nil {
		return errors.New("Could not close the backup file.")
	}
	if err := replaceBackupFile(temporaryPath, path); err != nil {
		return errors.New("Could not finish the backup file.")
	}
	written = true
	return nil
}

func sameBackupFile(left, right string) bool {
	leftAbsolute := canonicalBackupPath(left)
	rightAbsolute := canonicalBackupPath(right)
	leftInfo, leftStatErr := os.Stat(leftAbsolute)
	rightInfo, rightStatErr := os.Stat(rightAbsolute)
	if leftStatErr == nil && rightStatErr == nil && os.SameFile(leftInfo, rightInfo) {
		return true
	}
	return equalBackupPaths(leftAbsolute, rightAbsolute)
}

func canonicalBackupPath(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		absolute = filepath.Clean(path)
	}
	resolvedDirectory, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return absolute
	}
	return filepath.Join(resolvedDirectory, filepath.Base(absolute))
}

func isBackupWorkspaceStoragePath(databasePath, targetPath string) bool {
	for _, reserved := range []string{
		databasePath,
		databasePath + "-journal",
		databasePath + "-shm",
		databasePath + "-wal",
		credentialPrivateKeyLockPath(databasePath),
	} {
		if sameBackupFile(reserved, targetPath) {
			return true
		}
	}
	keysDirectory := filepath.Join(filepath.Dir(databasePath), "keys")
	relative, err := filepath.Rel(canonicalBackupPath(keysDirectory), canonicalBackupPath(targetPath))
	return err == nil && relative != ".." &&
		!filepath.IsAbs(relative) && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func validateBackupEncryption(encryption string) error {
	if strings.EqualFold(encryption, backupEncryptionNone) || strings.EqualFold(encryption, backupEncryptionAESGCM) {
		return nil
	}
	if encryption == "" {
		return errors.New("Backup file is missing its encryption marker.")
	}
	return errors.New("Backup file uses unsupported encryption.")
}

func validateBackupDocumentMetadata(document backupDocument) error {
	if err := validateBackupEncryption(document.Encryption); err != nil {
		return err
	}
	if len(document.ExportedAt) > 128 {
		return errors.New("Backup file has invalid export metadata.")
	}
	if document.ExportedAt != "" {
		if _, ok := parseBackupTimestamp(document.ExportedAt); !ok {
			return errors.New("Backup file has invalid export metadata.")
		}
	}
	return nil
}

func quoteBackupIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func backupObjectString(object backupObject, key string) string {
	raw, ok := object[key]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return ""
	}
	return value
}

func backupObjectOptionalString(object backupObject, key string) *string {
	raw, ok := object[key]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return nil
	}
	return &value
}

func backupObjectInteger(object backupObject, key string) (int64, bool) {
	raw, ok := object[key]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return 0, false
	}
	var value int64
	if json.Unmarshal(raw, &value) == nil {
		return value, true
	}
	return 0, false
}

func backupObjectBoolean(object backupObject, key string) (bool, bool) {
	raw, ok := object[key]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return false, false
	}
	var value bool
	if json.Unmarshal(raw, &value) == nil {
		return value, true
	}
	var integer int64
	if json.Unmarshal(raw, &integer) == nil {
		return integer != 0, true
	}
	return false, false
}

func setBackupObjectValue(object backupObject, key string, value any) {
	if value == nil {
		delete(object, key)
		return
	}
	encoded, _ := json.Marshal(value)
	object[key] = encoded
}

func canonicalBackupID(value string) (string, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if len(trimmed) != 36 {
		return "", false
	}
	for index, character := range trimmed {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return "", false
			}
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return "", false
		}
	}
	return trimmed, true
}

func backupDotNetGuidFromBytes(bytes []byte) string {
	if len(bytes) < 16 {
		return "00000000-0000-0000-0000-000000000000"
	}
	ordered := []byte{
		bytes[3], bytes[2], bytes[1], bytes[0], bytes[5], bytes[4], bytes[7], bytes[6],
		bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
	}
	hexValue := hex.EncodeToString(ordered)
	return hexValue[0:8] + "-" + hexValue[8:12] + "-" + hexValue[12:16] + "-" + hexValue[16:20] + "-" + hexValue[20:32]
}

func importBackup(databasePath string, request backupRequest) (backupImportResult, error) {
	return importBackupContext(context.Background(), databasePath, request, nil)
}

func importBackupContext(
	ctx context.Context,
	databasePath string,
	request backupRequest,
	progress operationProgress,
) (backupImportResult, error) {
	result := backupImportResult{Warnings: []string{}}
	if err := validateBackupRequest(request, true); err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	reportOperationProgress(progress, "reading", "Reading and validating the backup…", 10)
	contents, err := readBackupFile(request.Path)
	if err != nil {
		return result, err
	}
	defer clearBytes(contents)
	var document backupDocument
	if err := json.Unmarshal(contents, &document); err != nil {
		return result, errors.New("Backup file is empty or malformed.")
	}
	if document.SchemaVersion > backupCurrentSchemaVersion {
		return result, fmt.Errorf("Backup file schema version %d is newer than this app supports.", document.SchemaVersion)
	}
	if err := validateBackupDocumentMetadata(document); err != nil {
		return result, err
	}

	payload := document.Payload
	if strings.EqualFold(document.Encryption, backupEncryptionAESGCM) {
		if request.Password == "" {
			return result, errBackupPasswordRequired
		}
		if document.EncryptedPayload == nil {
			return result, errors.New("Encrypted backup is missing its sealed payload.")
		}
		plaintext, err := unsealBackupPayload(*document.EncryptedPayload, request.Password)
		if err != nil {
			return result, err
		}
		payload = newBackupPayload()
		if err := json.Unmarshal(plaintext, payload); err != nil {
			clearBytes(plaintext)
			return result, errors.New("Decrypted payload is empty or malformed.")
		}
		clearBytes(plaintext)
	}
	if payload == nil {
		return result, errors.New("Backup is missing its payload.")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	normalizeBackupPayloadLists(payload)
	nullDrops := filterBackupNulls(payload)
	if nullDrops > 0 {
		addBackupWarning(&result,
			fmt.Sprintf("Dropped %d null entries from the backup payload (malformed or hand-edited file).", nullDrops))
	}
	if len(payload.PrivateKeys) > 0 {
		release, err := acquireRecoveredCredentialPrivateKeyLock(databasePath)
		if err != nil {
			return result, err
		}
		defer release()
	}

	database, err := openDatabase(databasePath, false)
	if err != nil {
		return result, err
	}
	defer database.Close()
	if err := ensureBackupSchema(database); err != nil {
		return result, err
	}
	if _, err := database.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		return result, fmt.Errorf("Could not enable backup integrity checks: %w", err)
	}

	state, err := loadBackupImportStateContext(ctx, database)
	if err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	reportOperationProgress(progress, "metadata", "Merging credentials and connection metadata…", 35)
	insertedCredentials, err := importBackupCredentialsContext(ctx, database, payload.Credentials, state, &result)
	if err != nil {
		return result, err
	}
	if err := importBackupBitwardenCacheContext(ctx, database, payload.BitwardenCredentialCache, state); err != nil {
		return result, err
	}
	reportOperationProgress(progress, "metadata", "Merging VPN tunnels…", 50)
	insertedTunnels, err := importBackupTunnelsContext(ctx, database, payload.Tunnels, state, &result)
	if err != nil {
		return result, err
	}
	reportOperationProgress(progress, "metadata", "Merging workspace nodes…", 65)
	insertedNodes, err := importBackupNodesContext(ctx, database, payload.Nodes, state, &result)
	if err != nil {
		return result, err
	}
	reportOperationProgress(progress, "secrets", "Restoring protected secrets…", 80)
	if err := restoreBackupSecretsContext(
		ctx,
		database, databasePath, payload, state,
		insertedCredentials, insertedTunnels, insertedNodes, &result,
	); err != nil {
		return result, err
	}

	for _, warning := range result.Warnings {
		logInfo("backup import warning: %s", warning)
	}
	logInfo("backup imported: nodes=%d/%d credentials=%d/%d tunnels=%d/%d warnings=%d",
		result.NodesImported, result.NodesSkipped,
		result.CredentialsImported, result.CredentialsSkipped,
		result.TunnelsImported, result.TunnelsSkipped, len(result.Warnings))
	reportOperationProgress(progress, "complete", "Backup import complete.", 100)
	return result, nil
}

func normalizeBackupPayloadLists(payload *backupPayload) {
	if payload.Nodes == nil {
		payload.Nodes = []*backupObject{}
	}
	if payload.Credentials == nil {
		payload.Credentials = []*backupObject{}
	}
	if payload.Tunnels == nil {
		payload.Tunnels = []*backupObject{}
	}
	if payload.BitwardenCredentialCache == nil {
		payload.BitwardenCredentialCache = []*backupObject{}
	}
	if payload.Passwords == nil {
		payload.Passwords = []*backupPasswordEntry{}
	}
	if payload.InlinePasswords == nil {
		payload.InlinePasswords = []*backupInlinePasswordEntry{}
	}
	if payload.PrivateKeys == nil {
		payload.PrivateKeys = []*backupPrivateKeyEntry{}
	}
	if payload.TunnelPayloads == nil {
		payload.TunnelPayloads = []*backupTunnelPayloadEntry{}
	}
}

func filterBackupNulls(payload *backupPayload) int {
	dropped := 0
	payload.Nodes, dropped = filterBackupPointers(payload.Nodes, dropped)
	payload.Credentials, dropped = filterBackupPointers(payload.Credentials, dropped)
	payload.Tunnels, dropped = filterBackupPointers(payload.Tunnels, dropped)
	payload.BitwardenCredentialCache, dropped = filterBackupPointers(payload.BitwardenCredentialCache, dropped)
	payload.Passwords, dropped = filterBackupPointers(payload.Passwords, dropped)
	payload.InlinePasswords, dropped = filterBackupPointers(payload.InlinePasswords, dropped)
	payload.PrivateKeys, dropped = filterBackupPointers(payload.PrivateKeys, dropped)
	payload.TunnelPayloads, dropped = filterBackupPointers(payload.TunnelPayloads, dropped)
	return dropped
}

func filterBackupPointers[T any](values []*T, dropped int) ([]*T, int) {
	filtered := values[:0]
	for _, value := range values {
		if value == nil {
			dropped++
			continue
		}
		filtered = append(filtered, value)
	}
	return filtered, dropped
}

type backupImportState struct {
	credentialIDs         map[string]struct{}
	credentialNames       map[string]struct{}
	credentialKinds       map[string]int64
	credentialProviders   map[string]int64
	tunnelIDs             map[string]struct{}
	tunnelNames           map[string]struct{}
	nodeIDs               map[string]struct{}
	nodesByID             map[string]*backupObject
	resolvableCredentials map[string]struct{}
	resolvableTunnels     map[string]struct{}
}

func loadBackupImportStateContext(ctx context.Context, database *sql.DB) (*backupImportState, error) {
	state := &backupImportState{
		credentialIDs:         map[string]struct{}{},
		credentialNames:       map[string]struct{}{},
		credentialKinds:       map[string]int64{},
		credentialProviders:   map[string]int64{},
		tunnelIDs:             map[string]struct{}{},
		tunnelNames:           map[string]struct{}{},
		nodeIDs:               map[string]struct{}{},
		nodesByID:             map[string]*backupObject{},
		resolvableCredentials: map[string]struct{}{},
		resolvableTunnels:     map[string]struct{}{},
	}
	credentials, err := loadBackupObjectsContext(ctx, database, "CredentialProfiles", backupCredentialColumns)
	if err != nil {
		return nil, err
	}
	for _, credential := range credentials {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if credential == nil {
			continue
		}
		id, ok := canonicalBackupID(backupObjectString(*credential, "id"))
		if !ok {
			continue
		}
		state.credentialIDs[id] = struct{}{}
		state.resolvableCredentials[id] = struct{}{}
		state.credentialNames[backupObjectString(*credential, "name")] = struct{}{}
		kind, _ := backupObjectInteger(*credential, "kind")
		state.credentialKinds[id] = kind
		provider, _ := backupObjectInteger(*credential, "secretProvider")
		state.credentialProviders[id] = provider
	}
	tunnels, err := loadBackupObjectsContext(ctx, database, "TunnelConfigs", backupTunnelColumns)
	if err != nil {
		return nil, err
	}
	for _, tunnel := range tunnels {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if tunnel == nil {
			continue
		}
		id, ok := canonicalBackupID(backupObjectString(*tunnel, "id"))
		if !ok {
			continue
		}
		state.tunnelIDs[id] = struct{}{}
		state.resolvableTunnels[id] = struct{}{}
		state.tunnelNames[backupObjectString(*tunnel, "name")] = struct{}{}
	}
	nodes, err := loadBackupObjectsContext(ctx, database, "Nodes", backupNodeColumns)
	if err != nil {
		return nil, err
	}
	for _, node := range nodes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if node == nil {
			continue
		}
		id, ok := canonicalBackupID(backupObjectString(*node, "id"))
		if !ok {
			continue
		}
		setBackupObjectValue(*node, "id", id)
		state.nodeIDs[id] = struct{}{}
		state.nodesByID[id] = node
	}
	cache, err := loadBackupObjectsContext(ctx, database, "BitwardenCredentialCache", backupBitwardenColumns)
	if err != nil {
		return nil, err
	}
	if err := addBackupBitwardenVirtualIDsContext(ctx, state.resolvableCredentials, cache); err != nil {
		return nil, err
	}
	return state, nil
}

func importBackupCredentialsContext(
	ctx context.Context,
	database *sql.DB,
	credentials []*backupObject,
	state *backupImportState,
	result *backupImportResult,
) (map[string]struct{}, error) {
	inserted := map[string]struct{}{}
	for _, credential := range credentials {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		object := *credential
		id, ok := canonicalBackupID(backupObjectString(object, "id"))
		if !ok {
			return nil, errors.New("Backup contains a credential with an invalid ID.")
		}
		setBackupObjectValue(object, "id", id)
		name := backupObjectString(object, "name")
		setBackupObjectValue(object, "name", name)
		if _, exists := state.credentialIDs[id]; exists {
			result.CredentialsSkipped++
			continue
		}
		if _, exists := state.credentialNames[name]; exists {
			result.CredentialsSkipped++
			addBackupWarning(result,
				fmt.Sprintf("Credential '%s' already exists with a different ID and was skipped.", name))
			continue
		}
		if strings.TrimSpace(backupObjectString(object, "bitwardenFieldPath")) == "" {
			setBackupObjectValue(object, "bitwardenFieldPath", "login.password")
		}
		setBackupObjectValue(object, "createdAt", normalizeBackupTimestamp(backupObjectString(object, "createdAt")))
		if err := insertBackupObject(database, "CredentialProfiles", backupCredentialColumns, object); err != nil {
			return nil, fmt.Errorf("Could not import credential '%s': %w", name, err)
		}
		state.credentialIDs[id] = struct{}{}
		state.resolvableCredentials[id] = struct{}{}
		state.credentialNames[name] = struct{}{}
		kind, _ := backupObjectInteger(object, "kind")
		state.credentialKinds[id] = kind
		provider, _ := backupObjectInteger(object, "secretProvider")
		state.credentialProviders[id] = provider
		inserted[id] = struct{}{}
		result.CredentialsImported++
	}
	return inserted, nil
}

func importBackupTunnelsContext(
	ctx context.Context,
	database *sql.DB,
	tunnels []*backupObject,
	state *backupImportState,
	result *backupImportResult,
) (map[string]struct{}, error) {
	inserted := map[string]struct{}{}
	for _, tunnel := range tunnels {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		object := *tunnel
		id, ok := canonicalBackupID(backupObjectString(object, "id"))
		if !ok {
			return nil, errors.New("Backup contains a VPN tunnel with an invalid ID.")
		}
		setBackupObjectValue(object, "id", id)
		name := backupObjectString(object, "name")
		setBackupObjectValue(object, "name", name)
		if _, exists := state.tunnelIDs[id]; exists {
			result.TunnelsSkipped++
			continue
		}
		if _, exists := state.tunnelNames[name]; exists {
			result.TunnelsSkipped++
			addBackupWarning(result,
				fmt.Sprintf("Tunnel '%s' already exists with a different ID and was skipped.", name))
			continue
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		setBackupObjectValue(object, "createdAt", now)
		setBackupObjectValue(object, "updatedAt", now)
		if err := insertBackupObject(database, "TunnelConfigs", backupTunnelColumns, object); err != nil {
			return nil, fmt.Errorf("Could not import VPN tunnel '%s': %w", name, err)
		}
		state.tunnelIDs[id] = struct{}{}
		state.resolvableTunnels[id] = struct{}{}
		state.tunnelNames[name] = struct{}{}
		inserted[id] = struct{}{}
		result.TunnelsImported++
	}
	return inserted, nil
}

func importBackupBitwardenCache(
	database *sql.DB,
	entries []*backupObject,
	state *backupImportState,
) error {
	return importBackupBitwardenCacheContext(context.Background(), database, entries, state)
}

func importBackupBitwardenCacheContext(
	ctx context.Context,
	database *sql.DB,
	entries []*backupObject,
	state *backupImportState,
) error {
	// Match BitwardenCredentialCacheRepository.Normalize: duplicate ItemIds use the final
	// payload entry, so a newer row later in the backup wins deterministically.
	byItemID := map[string]*backupObject{}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		object := *entry
		itemID := strings.TrimSpace(backupObjectString(object, "itemId"))
		if itemID == "" {
			continue
		}
		setBackupObjectValue(object, "itemId", itemID)
		name := strings.TrimSpace(backupObjectString(object, "name"))
		if name == "" {
			name = itemID
		}
		setBackupObjectValue(object, "name", name)
		if username := backupObjectOptionalString(object, "username"); username != nil {
			trimmed := strings.TrimSpace(*username)
			if trimmed == "" {
				setBackupObjectValue(object, "username", nil)
			} else {
				setBackupObjectValue(object, "username", trimmed)
			}
		}
		if revision := backupObjectOptionalString(object, "revisionDate"); revision != nil {
			trimmed := strings.TrimSpace(*revision)
			if trimmed == "" {
				setBackupObjectValue(object, "revisionDate", nil)
			} else {
				setBackupObjectValue(object, "revisionDate", trimmed)
			}
		}
		ensureBackupBitwardenObjectIDs(object)
		setBackupObjectValue(object, "lastSeenSyncUtc", normalizeBackupTimestamp(backupObjectString(object, "lastSeenSyncUtc")))
		setBackupObjectValue(object, "updatedAtUtc", normalizeBackupTimestamp(backupObjectString(object, "updatedAtUtc")))
		byItemID[itemID] = entry
	}
	normalized := make([]*backupObject, 0, len(byItemID))
	for _, entry := range byItemID {
		normalized = append(normalized, entry)
	}
	sort.Slice(normalized, func(left, right int) bool {
		return backupObjectString(*normalized[left], "name") < backupObjectString(*normalized[right], "name")
	})
	transaction, err := database.Begin()
	if err != nil {
		return fmt.Errorf("Could not import Bitwarden credential metadata: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = transaction.Rollback()
		}
	}()
	for _, entry := range normalized {
		if err := ctx.Err(); err != nil {
			return err
		}
		object := *entry
		if err := upsertBackupBitwardenObject(transaction, object); err != nil {
			return err
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("Could not import Bitwarden credential metadata: %w", err)
	}
	committed = true
	return addBackupBitwardenVirtualIDsContext(ctx, state.resolvableCredentials, normalized)
}

func importBackupNodesContext(
	ctx context.Context,
	database *sql.DB,
	nodes []*backupObject,
	state *backupImportState,
	result *backupImportResult,
) (map[string]struct{}, error) {
	ordered, err := topologicallyOrderBackupNodesContext(ctx, nodes, state.nodeIDs, result)
	if err != nil {
		return nil, err
	}
	for _, node := range ordered {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		id := backupObjectString(*node, "id")
		if _, exists := state.nodesByID[id]; !exists {
			state.nodesByID[id] = node
		}
	}
	inserted := map[string]struct{}{}
	for _, node := range ordered {
		object := *node
		id := backupObjectString(object, "id")
		if _, exists := state.nodeIDs[id]; exists {
			result.NodesSkipped++
			continue
		}
		scrubBackupNodeReferences(object, state, result)
		now := time.Now().UTC().Format(time.RFC3339Nano)
		setBackupObjectValue(object, "createdAt", now)
		setBackupObjectValue(object, "updatedAt", now)
		if err := insertBackupObject(database, "Nodes", backupNodeColumns, object); err != nil {
			return nil, fmt.Errorf("Could not import node '%s': %w", backupObjectString(object, "name"), err)
		}
		state.nodeIDs[id] = struct{}{}
		state.nodesByID[id] = node
		inserted[id] = struct{}{}
		result.NodesImported++
	}
	return inserted, nil
}

func topologicallyOrderBackupNodesContext(
	ctx context.Context,
	nodes []*backupObject,
	existingIDs map[string]struct{},
	result *backupImportResult,
) ([]*backupObject, error) {
	byID := map[string]*backupObject{}
	inputOrder := make([]string, 0, len(nodes))
	for _, node := range nodes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		object := *node
		id, ok := canonicalBackupID(backupObjectString(object, "id"))
		if !ok {
			return nil, errors.New("Backup contains a node with an invalid ID.")
		}
		setBackupObjectValue(object, "id", id)
		setBackupObjectValue(object, "name", backupObjectString(object, "name"))
		if parent := backupObjectOptionalString(object, "parentId"); parent != nil {
			canonicalParent, ok := canonicalBackupID(*parent)
			if !ok {
				addBackupWarning(result,
					fmt.Sprintf("Node '%s' has an invalid parent ID; imported at root.", backupObjectString(object, "name")))
				setBackupObjectValue(object, "parentId", nil)
			} else {
				setBackupObjectValue(object, "parentId", canonicalParent)
			}
		}
		if _, duplicate := byID[id]; duplicate {
			addBackupWarning(result,
				fmt.Sprintf("Duplicate node id %s in backup; only the first occurrence was imported.", id))
			continue
		}
		byID[id] = node
		inputOrder = append(inputOrder, id)
	}

	ordered := make([]*backupObject, 0, len(byID))
	visited := map[string]struct{}{}
	inFlight := map[string]struct{}{}
	var visit func(node *backupObject, from *backupObject, depth int) error
	visit = func(node *backupObject, from *backupObject, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth > backupMaxNestingDepth {
			return fmt.Errorf("Backup nesting depth exceeds %d; refusing to import.", backupMaxNestingDepth)
		}
		id := backupObjectString(*node, "id")
		if _, done := visited[id]; done {
			return nil
		}
		if _, cycling := inFlight[id]; cycling {
			if from != nil {
				addBackupWarning(result,
					fmt.Sprintf("Cycle detected between '%s' and '%s'; '%s' imported at root.",
						backupObjectString(*from, "name"), backupObjectString(*node, "name"), backupObjectString(*from, "name")))
				setBackupObjectValue(*from, "parentId", nil)
			}
			return nil
		}
		inFlight[id] = struct{}{}
		if parent := backupObjectOptionalString(*node, "parentId"); parent != nil {
			if *parent == id {
				addBackupWarning(result,
					fmt.Sprintf("Node '%s' references itself as parent; imported at root.", backupObjectString(*node, "name")))
				setBackupObjectValue(*node, "parentId", nil)
			} else if _, exists := existingIDs[*parent]; exists {
				// Existing parent already satisfies the relationship.
			} else if parentNode, exists := byID[*parent]; exists {
				if err := visit(parentNode, node, depth+1); err != nil {
					return err
				}
			} else {
				addBackupWarning(result,
					fmt.Sprintf("Node '%s' references unknown parent %s; will be imported at root.", backupObjectString(*node, "name"), *parent))
				setBackupObjectValue(*node, "parentId", nil)
			}
		}
		delete(inFlight, id)
		visited[id] = struct{}{}
		ordered = append(ordered, node)
		return nil
	}
	for _, id := range inputOrder {
		if err := visit(byID[id], nil, 0); err != nil {
			return nil, err
		}
	}
	return ordered, nil
}

func scrubBackupNodeReferences(object backupObject, state *backupImportState, result *backupImportResult) {
	name := backupObjectString(object, "name")
	if protocol, present := backupObjectInteger(object, "protocol"); present &&
		protocol != 0 && protocol != 1 && protocol != 3 && protocol != 4 && protocol != 5 && protocol != 6 {
		addBackupWarning(result,
			fmt.Sprintf("Node '%s' uses an unsupported protocol (%d); imported as SSH.", name, protocol))
		setBackupObjectValue(object, "protocol", int64(0))
	}
	if id := backupObjectOptionalString(object, "credentialId"); id != nil {
		canonical, ok := canonicalBackupID(*id)
		_, resolvable := state.resolvableCredentials[canonical]
		if !ok || !resolvable {
			addBackupWarning(result,
				fmt.Sprintf("Node '%s' references missing credential %s; credential cleared.", name, *id))
			setBackupObjectValue(object, "credentialId", nil)
			mode, present := backupObjectInteger(object, "credentialMode")
			if !present || mode != 0 {
				setBackupObjectValue(object, "credentialMode", int64(1))
			}
		} else {
			setBackupObjectValue(object, "credentialId", canonical)
		}
	}
	if id := backupObjectOptionalString(object, "rdpGatewayCredentialId"); id != nil {
		canonical, ok := canonicalBackupID(*id)
		_, resolvable := state.resolvableCredentials[canonical]
		if !ok || !resolvable {
			addBackupWarning(result,
				fmt.Sprintf("Node '%s' references missing RDP gateway credential %s; cleared.", name, *id))
			setBackupObjectValue(object, "rdpGatewayCredentialId", nil)
		} else {
			setBackupObjectValue(object, "rdpGatewayCredentialId", canonical)
		}
	}
	if id := backupObjectOptionalString(object, "tunnelConfigId"); id != nil {
		canonical, ok := canonicalBackupID(*id)
		_, resolvable := state.resolvableTunnels[canonical]
		if !ok || !resolvable {
			addBackupWarning(result,
				fmt.Sprintf("Node '%s' references missing tunnel %s; tunnel cleared.", name, *id))
			setBackupObjectValue(object, "tunnelConfigId", nil)
		} else {
			setBackupObjectValue(object, "tunnelConfigId", canonical)
		}
	}
	kind, _ := backupObjectInteger(object, "kind")
	if kind == 1 {
		enabled, resolvable := resolveBackupTunnelState(object, state)
		if enabled && !resolvable {
			addBackupWarning(result,
				fmt.Sprintf("Node '%s' had tunneling enabled but no resolvable tunnel config; tunneling disabled.", name))
			setBackupObjectValue(object, "tunnelEnabled", false)
		}
	}
}

func resolveBackupTunnelState(object backupObject, state *backupImportState) (bool, bool) {
	current := &object
	seen := map[string]struct{}{}
	var effective *bool
	for current != nil {
		id := backupObjectString(*current, "id")
		if _, duplicate := seen[id]; duplicate {
			break
		}
		seen[id] = struct{}{}
		if effective == nil {
			if enabled, present := backupObjectBoolean(*current, "tunnelEnabled"); present {
				effective = &enabled
			}
		}
		if tunnelID := backupObjectOptionalString(*current, "tunnelConfigId"); tunnelID != nil {
			if canonical, ok := canonicalBackupID(*tunnelID); ok {
				if _, resolvable := state.resolvableTunnels[canonical]; resolvable {
					return effective != nil && *effective, true
				}
			}
		}
		parentID := backupObjectOptionalString(*current, "parentId")
		if parentID == nil {
			break
		}
		current = state.nodesByID[*parentID]
	}
	return effective != nil && *effective, false
}

func restoreBackupSecretsContext(
	ctx context.Context,
	database *sql.DB,
	databasePath string,
	payload *backupPayload,
	state *backupImportState,
	insertedCredentials map[string]struct{},
	insertedTunnels map[string]struct{},
	insertedNodes map[string]struct{},
	result *backupImportResult,
) error {
	for _, entry := range payload.Passwords {
		if err := ctx.Err(); err != nil {
			return err
		}
		id, ok := canonicalBackupID(entry.CredentialID)
		if !ok {
			addBackupWarning(result, "A password entry with an invalid credential ID was skipped.")
			continue
		}
		kind := state.credentialKinds[id]
		if (kind != 0 && kind != 1) || state.credentialProviders[id] == 1 {
			continue
		}
		if len(entry.Password) > maxStoredCredentialBytes {
			addBackupWarning(result,
				fmt.Sprintf("Password for credential %s exceeded the protected-store limit and was skipped.", id))
			continue
		}
		shouldRestore, warning, err := shouldRestoreBackupPassword(database, id, insertedCredentials, state.credentialIDs)
		if warning != "" {
			addBackupWarning(result, warning)
		}
		if err != nil {
			return err
		}
		if !shouldRestore {
			continue
		}
		if err := storeBackupPassword(database, id, entry.Password); err != nil {
			return fmt.Errorf("Could not restore a credential password: %w", err)
		}
		result.PasswordsImported++
	}
	for _, entry := range payload.InlinePasswords {
		if err := ctx.Err(); err != nil {
			return err
		}
		id, ok := canonicalBackupID(entry.NodeID)
		if !ok {
			addBackupWarning(result, "An inline password entry with an invalid node ID was skipped.")
			continue
		}
		if len(entry.Password) > maxStoredCredentialBytes {
			addBackupWarning(result,
				fmt.Sprintf("Inline password for node %s exceeded the protected-store limit and was skipped.", id))
			continue
		}
		shouldRestore, warning, err := shouldRestoreBackupPassword(database, id, insertedNodes, state.nodeIDs)
		if warning != "" {
			addBackupWarning(result, warning)
		}
		if err != nil {
			return err
		}
		if !shouldRestore {
			continue
		}
		if err := storeBackupPassword(database, id, entry.Password); err != nil {
			return fmt.Errorf("Could not restore an inline password: %w", err)
		}
		result.PasswordsImported++
	}
	for _, entry := range payload.PrivateKeys {
		if err := ctx.Err(); err != nil {
			return err
		}
		id, ok := canonicalBackupID(entry.CredentialID)
		if !ok {
			addBackupWarning(result, "A private-key entry with an invalid credential ID was skipped.")
			continue
		}
		if !backupIDExists(id, insertedCredentials, state.credentialIDs) {
			continue
		}
		if state.credentialKinds[id] != 1 || state.credentialProviders[id] != 0 {
			addBackupWarning(result,
				fmt.Sprintf("Private key for credential %s did not match a local SSH key profile and was skipped.", id))
			continue
		}
		path := credentialPrivateKeyPath(databasePath, id)
		if _, inserted := insertedCredentials[id]; !inserted {
			existing, err := readBackupPrivateKey(path)
			if err == nil {
				clearBytes(existing)
				continue
			}
			if !errors.Is(err, os.ErrNotExist) {
				addBackupWarning(result,
					fmt.Sprintf("Existing private key for credential %s could not be read; restoring it from backup.", id))
			}
		}
		keyBytes, err := base64.StdEncoding.DecodeString(entry.DataB64)
		if err != nil || len(keyBytes) == 0 || len(keyBytes) > maxSshPrivateKeyBytes {
			clearBytes(keyBytes)
			addBackupWarning(result,
				fmt.Sprintf("Private key for credential %s was malformed and was skipped.", id))
			continue
		}
		if err := protectFile(path, keyBytes); err != nil {
			clearBytes(keyBytes)
			return errors.New("Could not restore an SSH private key")
		}
		clearBytes(keyBytes)
		result.PrivateKeysImported++
	}
	for _, entry := range payload.TunnelPayloads {
		if err := ctx.Err(); err != nil {
			return err
		}
		id, ok := canonicalBackupID(entry.TunnelConfigID)
		if !ok {
			addBackupWarning(result, "A tunnel-payload entry with an invalid tunnel ID was skipped.")
			continue
		}
		if !backupIDExists(id, insertedTunnels, state.tunnelIDs) {
			continue
		}
		path := legacyTunnelSecretPath(databasePath, id)
		if _, inserted := insertedTunnels[id]; !inserted {
			existing, found, err := readBackupTunnelSettings(database, databasePath, id)
			if err == nil && found {
				clearBytes(existing)
				continue
			}
			if err != nil {
				addBackupWarning(result,
					fmt.Sprintf("Existing tunnel payload for %s could not be read; restoring it from backup.", id))
			}
		}
		if len(entry.DataB64) > base64.StdEncoding.EncodedLen(backendMaxTunnelRequestBytes) {
			addBackupWarning(result,
				fmt.Sprintf("Tunnel payload for %s exceeded the supported size and was skipped.", id))
			continue
		}
		settings, err := base64.StdEncoding.DecodeString(entry.DataB64)
		if err != nil || len(settings) == 0 || len(settings) > backendMaxTunnelRequestBytes {
			clearBytes(settings)
			addBackupWarning(result,
				fmt.Sprintf("Tunnel payload for %s was malformed and was skipped.", id))
			continue
		}
		validated, validationErr := validateStoredTunnelSettings(settings)
		clearBytes(settings)
		if validationErr != nil {
			addBackupWarning(result,
				fmt.Sprintf("Tunnel payload for %s was malformed and was skipped.", id))
			continue
		}
		if err := protectFile(path, validated); err != nil {
			clearBytes(validated)
			return errors.New("Could not restore a VPN tunnel payload")
		}
		clearBytes(validated)
		if _, err := database.Exec("DELETE FROM CredentialSecrets WHERE Id = ?;", tunnelSecretID(id)); err != nil {
			return errors.New("Could not finish restoring a VPN tunnel payload")
		}
		result.TunnelPayloadsImported++
	}
	return nil
}

func backupIDExists(id string, inserted, existing map[string]struct{}) bool {
	if _, ok := inserted[id]; ok {
		return true
	}
	_, ok := existing[id]
	return ok
}

func shouldRestoreBackupPassword(
	database *sql.DB,
	id string,
	inserted map[string]struct{},
	existing map[string]struct{},
) (bool, string, error) {
	if _, ok := inserted[id]; ok {
		return true, "", nil
	}
	if _, ok := existing[id]; !ok {
		return false, "", nil
	}
	_, found, err := readBackupPassword(database, id)
	if err != nil {
		return true, fmt.Sprintf("Existing password for %s could not be read; restoring it from backup.", id), nil
	}
	return !found, "", nil
}

func storeBackupPassword(database *sql.DB, id, password string) error {
	encoded, encoding, err := credentialSecretStore(id, password)
	if err != nil {
		return errors.New("the platform could not protect the password")
	}
	transaction, err := database.Begin()
	if err != nil {
		_ = credentialSecretDelete(id, encoded, encoding)
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = transaction.Rollback()
			_ = credentialSecretDelete(id, encoded, encoding)
		}
	}()
	var previousEncoded, previousEncoding sql.NullString
	readErr := transaction.QueryRow(
		"SELECT Secret, Encoding FROM CredentialSecrets WHERE lower(Id) = lower(?) LIMIT 1;", id,
	).Scan(&previousEncoded, &previousEncoding)
	if readErr != nil && !errors.Is(readErr, sql.ErrNoRows) {
		return readErr
	}
	if err := upsertCredentialSecret(transaction, id, encoded, encoding); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return err
	}
	committed = true
	if previousEncoded.Valid && previousEncoding.Valid &&
		(previousEncoded.String != encoded || previousEncoding.String != encoding) {
		_ = credentialSecretDelete(id, previousEncoded.String, previousEncoding.String)
	}
	return nil
}

func insertBackupObject(database *sql.DB, table string, columns []backupColumn, object backupObject) error {
	names := make([]string, len(columns))
	placeholders := make([]string, len(columns))
	values := make([]any, len(columns))
	for index, column := range columns {
		names[index] = quoteBackupIdentifier(column.DB)
		placeholders[index] = "?"
		values[index] = backupDatabaseValue(object, column)
	}
	_, err := database.Exec(
		"INSERT INTO "+quoteBackupIdentifier(table)+" ("+strings.Join(names, ", ")+") VALUES ("+strings.Join(placeholders, ", ")+");",
		values...,
	)
	return err
}

func backupDatabaseValue(object backupObject, column backupColumn) any {
	raw, exists := object[column.JSON]
	if !exists || len(raw) == 0 || string(raw) == "null" {
		if column.Required {
			return column.Default
		}
		return nil
	}
	switch column.Kind {
	case backupString:
		var value string
		if json.Unmarshal(raw, &value) == nil {
			return value
		}
	case backupInteger:
		var value int64
		if json.Unmarshal(raw, &value) == nil {
			return value
		}
	case backupBoolean:
		var value bool
		if json.Unmarshal(raw, &value) == nil {
			if value {
				return int64(1)
			}
			return int64(0)
		}
		var integer int64
		if json.Unmarshal(raw, &integer) == nil {
			if integer != 0 {
				return int64(1)
			}
			return int64(0)
		}
	}
	if column.Required {
		return column.Default
	}
	return nil
}

func ensureBackupSchema(database *sql.DB) error {
	if _, err := database.Exec(backupCreateNodesSQL()); err != nil {
		return fmt.Errorf("Could not create connection backup storage: %w", err)
	}
	if err := ensureBackupColumns(database, "Nodes", backupNodeColumns); err != nil {
		return err
	}
	if err := ensureCredentialWriteSchema(database); err != nil {
		return err
	}
	if err := ensureBackupColumns(database, "CredentialProfiles", backupCredentialColumns); err != nil {
		return err
	}
	if err := ensureMigrationSchema(database); err != nil {
		return err
	}
	if err := ensureBackupColumns(database, "TunnelConfigs", backupTunnelColumns); err != nil {
		return err
	}
	if _, err := database.Exec(backupCreateBitwardenSQL()); err != nil {
		return fmt.Errorf("Could not create Bitwarden backup storage: %w", err)
	}
	if err := ensureBackupColumns(database, "BitwardenCredentialCache", backupBitwardenColumns); err != nil {
		return err
	}
	_, err := database.Exec(`
CREATE INDEX IF NOT EXISTS IX_Nodes_ParentId ON Nodes(ParentId);
CREATE INDEX IF NOT EXISTS IX_Nodes_TunnelConfigId ON Nodes(TunnelConfigId) WHERE TunnelConfigId IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS UX_CredentialProfiles_Name ON CredentialProfiles(Name);
CREATE UNIQUE INDEX IF NOT EXISTS UX_TunnelConfigs_Name ON TunnelConfigs(Name);
CREATE INDEX IF NOT EXISTS IX_BitwardenCredentialCache_Name ON BitwardenCredentialCache(Name);`)
	if err != nil {
		return fmt.Errorf("Could not create backup storage indexes: %w", err)
	}
	return nil
}

func backupCreateNodesSQL() string {
	definitions := make([]string, len(backupNodeColumns))
	for index, column := range backupNodeColumns {
		definitions[index] = quoteBackupIdentifier(column.DB) + " " + column.SQLType
	}
	return "CREATE TABLE IF NOT EXISTS Nodes (" + strings.Join(definitions, ", ") + ");"
}

func backupCreateBitwardenSQL() string {
	definitions := make([]string, len(backupBitwardenColumns))
	for index, column := range backupBitwardenColumns {
		definitions[index] = quoteBackupIdentifier(column.DB) + " " + column.SQLType
	}
	return "CREATE TABLE IF NOT EXISTS BitwardenCredentialCache (" + strings.Join(definitions, ", ") + ");"
}

func ensureBackupColumns(database *sql.DB, table string, columns []backupColumn) error {
	available, err := tableColumns(database, table)
	if err != nil {
		return err
	}
	for _, column := range columns {
		if _, exists := available[column.DB]; exists {
			continue
		}
		// SQLite cannot add a PRIMARY KEY column and a table missing its identity is not a
		// supported Wormhole schema. Every additive compatibility column is safe to append.
		if strings.Contains(column.SQLType, "PRIMARY KEY") {
			return fmt.Errorf("Backup storage table %s is missing identity column %s", table, column.DB)
		}
		statement := "ALTER TABLE " + quoteBackupIdentifier(table) + " ADD COLUMN " + quoteBackupIdentifier(column.DB) + " " + column.SQLType + ";"
		if _, err := database.Exec(statement); err != nil {
			return fmt.Errorf("Could not add backup storage column %s.%s: %w", table, column.DB, err)
		}
	}
	return nil
}

type backupSQLExecutor interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func upsertBackupBitwardenObject(database backupSQLExecutor, object backupObject) error {
	columns := backupBitwardenColumns
	names := make([]string, len(columns))
	placeholders := make([]string, len(columns))
	values := make([]any, len(columns))
	updates := make([]string, 0, len(columns)-1)
	for index, column := range columns {
		names[index] = quoteBackupIdentifier(column.DB)
		placeholders[index] = "?"
		values[index] = backupDatabaseValue(object, column)
		if column.DB != "ItemId" {
			updates = append(updates, quoteBackupIdentifier(column.DB)+" = excluded."+quoteBackupIdentifier(column.DB))
		}
	}
	_, err := database.Exec(
		"INSERT INTO BitwardenCredentialCache ("+strings.Join(names, ", ")+") VALUES ("+strings.Join(placeholders, ", ")+") "+
			"ON CONFLICT(ItemId) DO UPDATE SET "+strings.Join(updates, ", ")+";",
		values...,
	)
	if err != nil {
		return fmt.Errorf("Could not import Bitwarden credential metadata: %w", err)
	}
	return nil
}

func ensureBackupBitwardenObjectIDs(object backupObject) {
	itemID := strings.TrimSpace(backupObjectString(object, "itemId"))
	for _, protocol := range []struct {
		field string
		name  string
	}{
		{field: "sshCredentialId", name: "Ssh"},
		{field: "rdpCredentialId", name: "Rdp"},
		{field: "vncCredentialId", name: "Vnc"},
	} {
		value, ok := canonicalBackupID(backupObjectString(object, protocol.field))
		if ok && value != "00000000-0000-0000-0000-000000000000" {
			setBackupObjectValue(object, protocol.field, value)
			continue
		}
		material := bitwardenVirtualIDNamespace + ":" + protocol.name + ":" + itemID
		hash := sha256.Sum256([]byte(material))
		setBackupObjectValue(object, protocol.field, backupDotNetGuidFromBytes(hash[:16]))
	}
}

func addBackupBitwardenVirtualIDsContext(
	ctx context.Context,
	target map[string]struct{},
	entries []*backupObject,
) error {
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry == nil || strings.TrimSpace(backupObjectString(*entry, "itemId")) == "" {
			continue
		}
		ensureBackupBitwardenObjectIDs(*entry)
		for _, field := range []string{"sshCredentialId", "rdpCredentialId", "vncCredentialId"} {
			if id, ok := canonicalBackupID(backupObjectString(*entry, field)); ok {
				target[id] = struct{}{}
			}
		}
	}
	return nil
}
