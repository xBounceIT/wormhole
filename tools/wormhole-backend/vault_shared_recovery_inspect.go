package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"unicode/utf8"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedRecoveryInspectReply struct {
	Status  string                             `json:"status"`
	Summary *sharedpg.WorkspaceRecoverySummary `json:"summary,omitempty"`
	Digest  string                             `json:"archiveDigest,omitempty"`
}

// The backup and the password are handled on the native bridge. An optional
// destination receives only the deployment script for the authenticated ID.
func (h *vaultFoundationHandler) inspectSharedRecoveryBackup(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if err := h.requireWorkspaceRecoveryDestination(); err != nil {
		return nil, err
	}
	var source, destination string
	var encodedPassword json.RawMessage
	var password []byte
	defer func() {
		vault.Wipe(encodedPassword)
		vault.Wipe(password)
	}()
	if len(payload) > 16*1024 || decodeVaultObject(payload, map[string]any{
		"path": &source, "scriptPath": &destination, "password": &encodedPassword,
	}, "path", "password") != nil ||
		!sharedFilePathValid(source, ".json") || !decodeSharedRestoreFactor(encodedPassword, &password) || len(password) != 76 ||
		(destination != "" && !sharedFilePathValid(destination, ".sql")) {
		return nil, vaultwire.ErrProtocol
	}
	return json.Marshal(inspectRecoveryBackupFile(ctx, source, destination, password))
}

func (h *vaultFoundationHandler) requireWorkspaceRecoveryDestination() error {
	if h.owner != nil || h.shared != nil || h.sharedSelection != nil || h.enrollment != nil || h.rotationMaterial != nil || h.migrationQuiesced {
		return vault.ErrPolicy
	}
	if !filepath.IsAbs(h.databasePath) || filepath.Clean(h.databasePath) != h.databasePath {
		return vaultwire.ErrProtocol
	}
	return requireNewVaultWorkspace(h.databasePath)
}

func readSharedRecoveryBackup(ctx context.Context, source string, password []byte) ([]byte, string) {
	recoveryKey, err := vault.ParseRecoveryKey(password)
	if err != nil {
		return nil, "invalid-password"
	}
	vault.Wipe(recoveryKey)
	raw, err := readSharedTrustBytes(source, backupMaxFileBytes)
	defer vault.Wipe(raw)
	if err != nil || int64(len(raw)) > backupMaxFileBytes || ctx.Err() != nil {
		return nil, "invalid-backup"
	}
	plain, err := openSharedRecoveryBackupEnvelope(raw, password)
	if errors.Is(err, errBackupBadPassword) {
		return nil, "invalid-password"
	}
	if err != nil {
		return nil, "invalid-backup"
	}
	return plain, ""
}

func inspectRecoveryBackupFile(ctx context.Context, source, destination string, password []byte) sharedRecoveryInspectReply {
	plain, failure := readSharedRecoveryBackup(ctx, source, password)
	defer vault.Wipe(plain)
	if failure != "" {
		return sharedRecoveryInspectReply{Status: failure}
	}
	summary, err := sharedpg.InspectWorkspaceRecoverySnapshot(plain)
	if err != nil || ctx.Err() != nil {
		return sharedRecoveryInspectReply{Status: "invalid-backup"}
	}
	digest := sha256.Sum256(plain)
	result := sharedRecoveryInspectReply{Status: "ready", Summary: &summary, Digest: hex.EncodeToString(digest[:])}
	if destination != "" {
		script, err := deploy.SchemaScript(summary.RoleTag, summary.WorkspaceID.String())
		if err != nil || ctx.Err() != nil || publishSharedSetupFile(destination, []byte(script)) != nil {
			result.Status = "save-failed"
		} else {
			result.Status = "saved"
		}
	}
	return result
}

func openSharedRecoveryBackupEnvelope(raw, password []byte) ([]byte, error) {
	var schema int
	var app, exportedAt, encryption string
	var payload backupEncryptedPayload
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if !utf8.Valid(raw) || !decodeRecoveryBackupObject(decoder, map[string]any{
		"schemaVersion": &schema, "app": &app, "exportedAt": &exportedAt, "encryption": &encryption,
		"encryptedPayload": map[string]any{
			"kdf": &payload.KDF, "iterations": &payload.Iterations, "saltB64": &payload.SaltB64,
			"nonceB64": &payload.NonceB64, "ciphertextB64": &payload.CiphertextB64, "tagB64": &payload.TagB64,
		},
	}) || decoder.Decode(new(json.RawMessage)) != io.EOF ||
		schema != sharedRecoveryBackupSchemaVersion || app != "Wormhole" ||
		encryption != backupEncryptionAESGCM || payload.KDF != backupKDFPBKDF2SHA256 ||
		payload.Iterations < backupPBKDF2Iterations || len(exportedAt) > 128 {
		return nil, vault.ErrFormat
	}
	if _, ok := parseBackupTimestamp(exportedAt); !ok {
		return nil, vault.ErrFormat
	}
	return unsealBackupPayloadWithBytes(payload, password)
}

// Stream exact field names without copying the large ciphertext field into an
// intermediate RawMessage or relying on Go's case-insensitive struct decoder.
func decodeRecoveryBackupObject(decoder *json.Decoder, fields map[string]any) bool {
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return false
	}
	for decoder.More() {
		token, err := decoder.Token()
		name, _ := token.(string)
		field, known := fields[name]
		if err != nil || !known {
			return false
		}
		delete(fields, name)
		if nested, ok := field.(map[string]any); ok {
			if !decodeRecoveryBackupObject(decoder, nested) {
				return false
			}
		} else if decoder.Decode(field) != nil {
			return false
		}
	}
	token, err := decoder.Token()
	return err == nil && token == json.Delim('}') && len(fields) == 0
}
