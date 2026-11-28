package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

const localBackupExtension = ".whvault"
const localBackupInstallSuffix = ".restored"

var errLocalBackupCommitUncertain = errors.New("vault_backup_commit_uncertain")

func (h *vaultFoundationHandler) exportLocalBackup(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if h.owner == nil || h.enrollment != nil {
		return nil, vault.ErrPolicy
	}
	var path string
	if len(payload) > 8*1024 || decodeVaultObject(payload, map[string]any{"path": &path}, "path") != nil ||
		!sharedFilePathValid(path, localBackupExtension) || isBackupWorkspaceStoragePath(h.databasePath, path) {
		return nil, vaultwire.ErrProtocol
	}
	if err := requireNoRootRotation(h.databasePath); err != nil {
		return nil, err
	}
	document, err := readVaultSlotFile(h.databasePath)
	if err != nil {
		return nil, err
	}
	if !document.Encrypted || document.Initializing || document.Migration != nil || document.Rotation != nil {
		return nil, vault.ErrPolicy
	}
	if err := h.persistVaultCheckpoint(ctx, document); err != nil {
		return nil, err
	}
	slots, err := readVaultSlotBytes(h.databasePath)
	if err != nil {
		return nil, err
	}
	stage, err := newLocalBackupStaging(path)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)
	source := filepath.Join(stage, "backup"+localBackupExtension)
	file, err := os.OpenFile(source, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, vaultstore.ErrStorage
	}
	if err := h.owner.WriteEncryptedBackup(ctx, stage, slots, file); err != nil {
		file.Close()
		return nil, err
	}
	if errors.Join(file.Sync(), file.Close()) != nil || protectPrivateFile(source) != nil {
		return nil, vaultstore.ErrStorage
	}
	if err := publishLocalBackup(ctx, source, path); err != nil {
		return nil, err
	}
	return json.RawMessage(`"exported"`), nil
}

func (h *vaultFoundationHandler) inspectLocalBackup(payload []byte) (json.RawMessage, error) {
	if err := h.requireLocalBackupInstall(); err != nil {
		return nil, err
	}
	var path string
	if len(payload) > 8*1024 || decodeVaultObject(payload, map[string]any{"path": &path}, "path") != nil ||
		!sharedFilePathValid(path, localBackupExtension) {
		return nil, vaultwire.ErrProtocol
	}
	file, archive, err := openLocalBackup(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	slots, fingerprint := archive.RecoveryContext()
	return json.Marshal(struct {
		Slots       vault.SlotFileDescriptor `json:"slots"`
		Fingerprint string                   `json:"fingerprint"`
	}{slots, hex.EncodeToString(fingerprint[:])})
}

func (h *vaultFoundationHandler) requireLocalBackupInstall() error {
	if h.owner != nil || h.shared != nil || h.sharedSelection != nil || h.enrollment != nil || h.migrationQuiesced {
		return vault.ErrPolicy
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(h.databasePath + suffix); !errors.Is(err, os.ErrNotExist) {
			return vaultstore.ErrConflict
		}
	}
	return requireNewVaultWorkspace(h.databasePath)
}

// Install selects the reserved sibling directory of an unused workspace.
// The explicit-target operation can also export a recovery copy to a new
// directory without changing the startup selection. Factors use stdin.
func (h *vaultFoundationHandler) restoreLocalBackup(ctx context.Context, payload []byte, install bool) (json.RawMessage, error) {
	defer vault.Wipe(payload)
	if h.owner != nil || h.enrollment != nil || h.migrationQuiesced {
		return nil, vault.ErrPolicy
	}
	var path, target, fingerprint string
	var code []byte
	defer func() { vault.Wipe(code) }()
	targets := map[string]any{"path": &path, "recoveryCode": &code}
	field := "target"
	if install {
		if err := h.requireLocalBackupInstall(); err != nil {
			return nil, err
		}
		target = h.databasePath + localBackupInstallSuffix
		field = "fingerprint"
		targets[field] = &fingerprint
	} else {
		targets[field] = &target
	}
	if len(payload) > 16*1024 || decodeVaultObject(payload, targets, "path", "recoveryCode", field) != nil ||
		!sharedFilePathValid(path, localBackupExtension) || !localBackupRestoreTarget(target) || (install && len(fingerprint) != 64) {
		return nil, vaultwire.ErrProtocol
	}
	key, err := vault.ParseRecoveryKey(code)
	vault.Wipe(code)
	vault.Wipe(payload)
	if err != nil {
		return nil, vault.ErrAuthentication
	}
	defer vault.Wipe(key)
	file, archive, err := openLocalBackup(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if install {
		_, current := archive.RecoveryContext()
		if hex.EncodeToString(current[:]) != fingerprint {
			return nil, vault.ErrAuthentication
		}
	}
	stage, err := newLocalBackupStaging(target)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)
	workspace, err := archive.Stage(ctx, stage, key)
	if err != nil {
		return nil, err
	}
	if protectPrivateDirectory(workspace) != nil || syncPrivateFileDirectory(workspace) != nil {
		return nil, vaultstore.ErrStorage
	}
	if install {
		if err := h.requireLocalBackupInstall(); err != nil {
			return nil, err
		}
	}
	if err := publishLocalBackup(ctx, workspace, target); err != nil {
		return nil, err
	}
	return json.RawMessage(`"restored"`), nil
}

func openLocalBackup(path string) (*os.File, *localvault.EncryptedBackup, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, nil, vaultstore.ErrStorage
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, vaultstore.ErrStorage
	}
	info, err := file.Stat()
	if err != nil || !os.SameFile(before, info) {
		file.Close()
		return nil, nil, vaultstore.ErrStorage
	}
	archive, err := localvault.ReadEncryptedBackup(file, info.Size())
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	return file, archive, nil
}

func requireNoLocalBackupInstall(databasePath string) error {
	if _, err := os.Lstat(databasePath + localBackupInstallSuffix); !errors.Is(err, os.ErrNotExist) {
		return vaultstore.ErrConflict
	}
	return nil
}

func localBackupRestoreTarget(path string) bool {
	return len(path) <= 4096 && filepath.IsAbs(path) && filepath.Clean(path) == path &&
		filepath.Dir(path) != path && strings.IndexFunc(path, unicode.IsControl) < 0
}

func newLocalBackupStaging(target string) (string, error) {
	if _, err := os.Lstat(target); err == nil {
		return "", vaultstore.ErrConflict
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", vaultstore.ErrStorage
	}
	stage, err := os.MkdirTemp(filepath.Dir(target), ".vault-backup-staging-")
	if err != nil {
		return "", vaultstore.ErrStorage
	}
	if err := protectPrivateDirectory(stage); err != nil {
		os.Remove(stage)
		return "", vaultstore.ErrStorage
	}
	return stage, nil
}

func publishLocalBackup(ctx context.Context, source, target string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := publishVaultExtensionDirectory(source, target); err != nil {
		// Windows can report access denied when the destination is an existing
		// directory. The atomic move still refuses to overwrite it.
		if _, statErr := os.Lstat(target); errors.Is(err, os.ErrExist) || statErr == nil {
			return vaultstore.ErrConflict
		}
		return vaultstore.ErrStorage
	}
	if syncPrivateFileDirectory(filepath.Dir(target)) != nil {
		return errLocalBackupCommitUncertain
	}
	return nil
}
