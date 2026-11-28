package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func (h *vaultFoundationHandler) restoreSharedRecoveryBackup(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if err := h.requireWorkspaceRecoveryDestination(); err != nil {
		return nil, err
	}
	var target sharedpg.WorkspaceRecoveryTarget
	var path, digest, tag string
	var encodedPassword, encodedDeployer json.RawMessage
	var password, deployer []byte
	defer func() {
		for _, secret := range [][]byte{encodedPassword, encodedDeployer, password, deployer} {
			vault.Wipe(secret)
		}
	}()
	if len(payload) > 16*1024 || decodeVaultObject(payload, map[string]any{
		"path": &path, "archiveDigest": &digest, "workspaceId": &target.WorkspaceID, "roleTag": &tag,
		"host": &target.Endpoint.Host, "port": &target.Endpoint.Port, "database": &target.Database,
		"password": &encodedPassword, "deployerPassword": &encodedDeployer,
	}, "path", "archiveDigest", "workspaceId", "roleTag", "host", "port", "database", "password", "deployerPassword") != nil ||
		!sharedFilePathValid(path, ".json") || deploy.ValidateIdentity(tag, target.WorkspaceID.String()) != nil ||
		len(digest) != 64 ||
		!decodeSharedRestoreFactor(encodedPassword, &password) || len(password) != 76 ||
		!decodeSharedRestoreFactor(encodedDeployer, &deployer) || !validSharedRecoveryPassword(deployer) {
		return nil, vaultwire.ErrProtocol
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return nil, vaultwire.ErrProtocol
	}
	target.DeployerRole = "wh_" + tag + "_deployer"
	plain, status := readSharedRecoveryBackup(ctx, path, password)
	defer vault.Wipe(plain)
	if status != "" {
		return json.Marshal(status)
	}
	fingerprint := sha256.Sum256(plain)
	if digest != hex.EncodeToString(fingerprint[:]) {
		return json.Marshal("archive-changed")
	}
	result, err := sharedpg.RestoreWorkspaceRecoverySnapshot(ctx, target, plain, deployer)
	if err != nil {
		return json.Marshal(sharedWorkspaceRestoreFailure(err))
	}
	return json.Marshal(result)
}

func sharedWorkspaceRestoreFailure(err error) string {
	switch {
	case errors.Is(err, sharedpg.ErrWorkspaceRestoreLogging):
		return "logging-enabled"
	case errors.Is(err, sharedpg.ErrDeploymentUncertain), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "uncertain"
	default:
		return "rejected"
	}
}

func decodeSharedRestoreFactor(encoded json.RawMessage, destination *[]byte) bool {
	return len(encoded) != 0 && encoded[0] == '"' && json.Unmarshal(encoded, destination) == nil
}
