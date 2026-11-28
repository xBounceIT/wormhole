package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

const sharedRecoveryBackupSchemaVersion = 3

type sharedWorkspaceRecoveryExportSession interface {
	sharedRuntimeStateSession
	ReadWorkspaceRecoverySnapshot(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, []byte, []byte) (*sharedpg.WorkspaceRecoverySnapshot, error)
}

type sharedRecoveryBackupReply struct {
	Status   string              `json:"status"`
	VaultID  string              `json:"vaultId,omitempty"`
	ExportID string              `json:"exportId,omitempty"`
	Bundle   *vault.SealedBundle `json:"bundle,omitempty"`
}

func (h *vaultFoundationHandler) exportSharedRecoveryBackup(ctx context.Context, payload []byte) (json.RawMessage, error) {
	var path string
	var recipient []byte
	var encoded json.RawMessage
	defer func() { vault.Wipe(encoded) }()
	if len(payload) > 32*1024 || decodeVaultObject(payload, map[string]any{"path": &path, "recipient": &recipient, "authentication": &encoded}, "path", "recipient") != nil ||
		!sharedFilePathValid(path, ".json") || len(recipient) != 32 {
		return nil, vaultwire.ErrProtocol
	}
	var auth vaultUnlockInput
	defer auth.wipe()
	if encoded != nil {
		var err error
		auth, err = decodeSharedExportAuthentication(encoded)
		if err != nil {
			return nil, err
		}
	}
	controller, err := h.sharedOwner(ctx)
	if err != nil {
		return nil, err
	}
	session, ok := controller.session.(sharedWorkspaceRecoveryExportSession)
	if !ok {
		return nil, h.retire(sharedpg.ErrConfiguration)
	}
	reply := sharedRecoveryBackupReply{Status: "unavailable"}
	err = controller.withWorkspaceTrust(ctx, session, func(ctx context.Context, trust sharedpg.TrustState, bundle *sharedpg.VerifiedTLSBundle) error {
		if bundle == nil {
			return nil
		}
		if controller.runtimeProfile == vault.Standard {
			if encoded == nil {
				reply.Status = "authentication-required"
				return nil
			}
			valid, err := h.verifySharedExportFactors(ctx, controller, trust.Revision, auth)
			if err != nil {
				return err
			}
			if !valid {
				reply.Status = "invalid-authentication"
				return nil
			}
		}
		var snapshot *sharedpg.WorkspaceRecoverySnapshot
		err := controller.privateKeys.With(func(keys []byte) error {
			if len(keys) != 64 {
				return sharedpg.ErrAuthentication
			}
			var err error
			snapshot, err = session.ReadWorkspaceRecoverySnapshot(ctx, trust, bundle, keys[:32:32], keys[32:])
			return err
		})
		defer snapshot.Close()
		switch {
		case errors.Is(err, sharedpg.ErrServerCertificateAuthority):
			return nil
		case errors.Is(err, sharedpg.ErrResultLimit):
			reply.Status = "too-large"
			return nil
		case err != nil:
			return err
		}
		reply, err = saveSharedRecoveryBackup(ctx, path, recipient, snapshot)
		return err
	})
	if err != nil {
		return nil, h.retire(err)
	}
	return json.Marshal(reply)
}

func saveSharedRecoveryBackup(ctx context.Context, path string, recipient []byte, snapshot *sharedpg.WorkspaceRecoverySnapshot) (sharedRecoveryBackupReply, error) {
	var reply sharedRecoveryBackupReply
	if err := ctx.Err(); err != nil {
		return reply, err
	}
	if snapshot == nil || snapshot.FormatVersion != 1 || snapshot.WorkspaceID == uuid.Nil {
		return reply, sharedpg.ErrAdmissionResponse
	}
	key := vault.NewRecoveryKey()
	defer vault.Wipe(key)
	password, err := vault.FormatRecoveryKey(key)
	if err != nil {
		return reply, err
	}
	defer vault.Wipe(password)
	workspace := snapshot.WorkspaceID.String()
	issuance := uuid.NewString()
	display, err := vault.SealRecoveryDisplay(recipient, workspace, issuance, password)
	if err != nil {
		return reply, err
	}
	raw, err := encodeSharedRecoveryBackup(snapshot, password, time.Now())
	if errors.Is(err, sharedpg.ErrResultLimit) {
		return sharedRecoveryBackupReply{Status: "too-large"}, nil
	}
	if err != nil {
		return reply, err
	}
	if err := ctx.Err(); err != nil {
		return reply, err
	}
	if err := publishSharedSetupFile(path, raw); err != nil {
		return sharedRecoveryBackupReply{Status: "save-failed"}, nil
	}
	return sharedRecoveryBackupReply{Status: "exported", VaultID: workspace, ExportID: issuance, Bundle: &display}, nil
}

func encodeSharedRecoveryBackup(snapshot *sharedpg.WorkspaceRecoverySnapshot, password []byte, now time.Time) ([]byte, error) {
	plaintext, err := json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(plaintext)
	if int64(len(plaintext)) > (backupMaxFileBytes-4096)*3/4 {
		return nil, sharedpg.ErrResultLimit
	}
	encrypted, err := sealBackupPayloadWithBytes(plaintext, password)
	if err != nil {
		return nil, err
	}
	return encodeBackupDocument(backupDocument{
		SchemaVersion:    sharedRecoveryBackupSchemaVersion,
		App:              "Wormhole",
		ExportedAt:       now.UTC().Format(time.RFC3339Nano),
		Encryption:       backupEncryptionAESGCM,
		EncryptedPayload: &encrypted,
	}, backupMaxFileBytes)
}
