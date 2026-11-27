package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

const (
	serverKitPending  = "pending"
	serverKitSaved    = "saved"
	serverKitVerified = "verified"
	serverKitRemoved  = "removed"
	serverKeyName     = "server.key"
	retiredServerKey  = ".server.key.retiring"
)

type sharedSetupServerKitReceipt struct {
	Folder string `json:"folder"`
	State  string `json:"state"`
}

// Only the pending publication may retain an encrypted copy of the server
// key. Keep its digest after publication to scope optional local removal.
type sharedSetupServerKit struct {
	sharedSetupServerKitReceipt
	KeyDigest    [32]byte `json:"keyDigest"`
	EncryptedKey []byte   `json:"encryptedKey,omitempty"`
}

func (k *sharedSetupServerKit) valid(workspace string) bool {
	if !filepath.IsAbs(k.Folder) || filepath.Clean(k.Folder) != k.Folder ||
		filepath.Base(k.Folder) != workspace || len(k.Folder) > 4096 || k.KeyDigest == [32]byte{} {
		return false
	}
	switch k.State {
	case serverKitPending:
		return len(k.EncryptedKey) > 0 && len(k.EncryptedKey) <= sharedpg.MaxEncryptedServerKeyBytes &&
			sha256.Sum256(k.EncryptedKey) == k.KeyDigest
	case serverKitSaved, serverKitVerified, serverKitRemoved:
		return len(k.EncryptedKey) == 0
	default:
		return false
	}
}

func (p sharedSetupPlan) kitReceipt() *sharedSetupServerKitReceipt {
	if p.ServerKit == nil {
		return nil
	}
	return &p.ServerKit.sharedSetupServerKitReceipt
}

func resolveServerKitFolder(workspace string, createCache bool) (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil || !filepath.IsAbs(cache) {
		return "", errSharedTrustStorage
	}
	resolved, err := filepath.EvalSymlinks(cache)
	if createCache && errors.Is(err, os.ErrNotExist) {
		parent, parentErr := filepath.EvalSymlinks(filepath.Dir(cache))
		if parentErr != nil || !isLocalServerKitCache(parent) {
			return "", errSharedTrustStorage
		}
		if err := os.Mkdir(filepath.Join(parent, filepath.Base(cache)), 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return "", errSharedTrustStorage
		}
		resolved, err = filepath.EvalSymlinks(cache)
	}
	if err != nil || !isLocalServerKitCache(resolved) {
		return "", errSharedTrustStorage
	}
	return filepath.Join(resolved, "Wormhole-Server-Setup", workspace), nil
}

func captureServerKitDirectory(path string) (os.FileInfo, error) {
	if !isLocalServerKitCache(path) {
		return nil, errSharedTrustStorage
	}
	return captureInitialJoinDirectory(path)
}

const serverTLSConfig = `ssl = on
ssl_cert_file = 'server.pem'
ssl_key_file = 'server.key'
ssl_passphrase_command_supports_reload = on
# Set ssl_passphrase_command to a helper that reads the key passphrase from
# the server's secret store. Keep the passphrase out of this file.
`

func serverKitFiles(plan sharedSetupPlan) map[string][]byte {
	return map[string][]byte{
		serverKeyName:         plan.ServerKit.EncryptedKey,
		"server.pem":          []byte(plan.TLS.ServerPEM),
		"workspace-ca.pem":    plan.CAPEM,
		"postgresql-tls.conf": []byte(serverTLSConfig),
	}
}

func serverKitStagePath(folder string) string {
	return filepath.Join(filepath.Dir(folder), "."+filepath.Base(folder)+".pending")
}

func saveSharedServerKit(ctx context.Context, plan sharedSetupPlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	kit := plan.ServerKit
	target, err := resolveServerKitFolder(plan.Summary.WorkspaceID, false)
	if err != nil || target != kit.Folder {
		return errSharedTrustStorage
	}
	parent := filepath.Dir(target)
	if err := os.Mkdir(parent, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return errSharedTrustStorage
	}
	if _, err := captureServerKitDirectory(parent); err != nil {
		return err
	}
	if protectPrivateDirectory(parent) != nil || privateFileDirectorySync(filepath.Dir(parent)) != nil {
		return errSharedTrustStorage
	}
	files := serverKitFiles(plan)
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		info, err := captureServerKitDirectory(target)
		if err != nil {
			return errSharedTrustConflict
		}
		// An exact directory may already exist after an interrupted publication.
		existing := &sharedInitialPublication{target: target, directory: info, published: true, files: files, written: files}
		if err := existing.check(false); err != nil {
			return err
		}
		if protectPrivateDirectory(target) != nil || protectPrivateFile(filepath.Join(target, serverKeyName)) != nil {
			return errSharedTrustStorage
		}
		return privateFileDirectorySync(parent)
	}
	// Use the workspace's one staging directory. A crash during an individual
	// write can leave only a prefix of that file, which the next Save resumes.
	stage := serverKitStagePath(target)
	if err := os.Mkdir(stage, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return errSharedTrustStorage
	}
	info, err := captureServerKitDirectory(stage)
	if err != nil {
		return err
	}
	publication := &sharedInitialPublication{target: target, stage: stage, directory: info, files: files, written: files}
	if err := protectPrivateDirectory(stage); err != nil {
		return errSharedTrustStorage
	}
	if err := writeServerKitStage(ctx, publication); err != nil {
		return err
	}
	if protectPrivateFile(filepath.Join(stage, serverKeyName)) != nil || privateFileDirectorySync(stage) != nil {
		return errSharedTrustStorage
	}
	if err := publication.check(false); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err = publishVaultExtensionDirectory(stage, target)
	actual, statErr := captureServerKitDirectory(target)
	if statErr != nil || !os.SameFile(actual, info) {
		return errSharedTrustConflict
	}
	if err != nil {
		return errSharedTrustCommitUncertain
	}
	return privateFileDirectorySync(parent)
}

func writeServerKitStage(ctx context.Context, publication *sharedInitialPublication) error {
	root, err := publication.open()
	if err != nil {
		return err
	}
	defer root.Close()
	for name, data := range publication.files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := writeServerKitStageFile(root, name, data); err != nil {
			return err
		}
	}
	return nil
}

func writeServerKitStageFile(root *os.Root, name string, data []byte) error {
	info, err := root.Lstat(name)
	openFlags := os.O_RDWR
	if errors.Is(err, os.ErrNotExist) {
		openFlags |= os.O_CREATE | os.O_EXCL
	} else if err != nil || !info.Mode().IsRegular() {
		return errSharedTrustConflict
	}
	file, err := root.OpenFile(name, openFlags, 0600)
	if err != nil {
		return errSharedTrustStorage
	}
	defer file.Close()
	actual, err := file.Stat()
	if err != nil || !actual.Mode().IsRegular() || (info != nil && !os.SameFile(info, actual)) {
		return errSharedTrustConflict
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(len(data)+1)))
	if err != nil || !bytes.HasPrefix(data, raw) {
		return errSharedTrustConflict
	}
	if _, err := file.Write(data[len(raw):]); err != nil {
		return errSharedTrustStorage
	}
	if err := file.Sync(); err != nil {
		return errSharedTrustStorage
	}
	return nil
}

func discardUnpublishedServerKit(plan sharedSetupPlan) error {
	if plan.ServerKit == nil || plan.ServerKit.State != serverKitPending {
		return nil
	}
	folder, err := resolveServerKitFolder(plan.Summary.WorkspaceID, false)
	if err != nil || folder != plan.ServerKit.Folder {
		return errSharedTrustStorage
	}
	stage := serverKitStagePath(folder)
	if _, err := os.Lstat(stage); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	info, err := captureServerKitDirectory(stage)
	if err != nil {
		return err
	}
	files := serverKitFiles(plan)
	publication := &sharedInitialPublication{stage: stage, directory: info, files: files, written: map[string][]byte{}}
	for name, expected := range files {
		data, err := readSharedTrustBytes(filepath.Join(stage, name), int64(len(expected)))
		if errors.Is(err, errSharedTrustMissing) {
			continue
		}
		if err != nil || !bytes.HasPrefix(expected, data) {
			return errSharedTrustConflict
		}
		publication.written[name] = data
	}
	return publication.cleanup()
}

func deleteSharedSetupServerKey(plan sharedSetupPlan) error {
	kit := plan.ServerKit
	target, err := resolveServerKitFolder(plan.Summary.WorkspaceID, false)
	if err != nil || target != kit.Folder {
		return errSharedTrustStorage
	}
	if _, err := captureServerKitDirectory(filepath.Dir(target)); err != nil {
		return err
	}
	info, err := captureServerKitDirectory(target)
	if err != nil {
		return err
	}
	publication := &sharedInitialPublication{target: target, directory: info, published: true}
	root, err := publication.open()
	if err != nil {
		return err
	}
	defer root.Close()
	active := filepath.Join(target, serverKeyName)
	retiring := filepath.Join(target, retiredServerKey)
	// Keep an exact digest-bound retirement name so a lost reply can resume.
	activeDigest, activeErr := readServerKitKeyDigest(root, serverKeyName)
	retiringDigest, retiringErr := readServerKitKeyDigest(root, retiredServerKey)
	if errors.Is(retiringErr, errSharedTrustMissing) {
		if errors.Is(activeErr, errSharedTrustMissing) {
			return privateFileDirectorySync(target)
		}
		if activeErr != nil || activeDigest != kit.KeyDigest {
			return errSharedTrustConflict
		}
		if err := publishVaultExtensionDirectory(active, retiring); err != nil {
			return errSharedTrustStorage
		}
		retiringDigest, retiringErr = readServerKitKeyDigest(root, retiredServerKey)
		if retiringErr != nil || retiringDigest != kit.KeyDigest {
			if current, err := captureServerKitDirectory(target); err == nil && os.SameFile(info, current) {
				_ = publishVaultExtensionDirectory(retiring, active)
			}
			return errSharedTrustConflict
		}
	} else if !errors.Is(activeErr, errSharedTrustMissing) || retiringErr != nil || retiringDigest != kit.KeyDigest {
		return errSharedTrustConflict
	}
	if err := root.Remove(retiredServerKey); err != nil {
		return errSharedTrustStorage
	}
	return privateFileDirectorySync(target)
}

func readServerKitKeyDigest(root *os.Root, name string) (digest [32]byte, err error) {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return digest, errSharedTrustMissing
	}
	if err != nil || !info.Mode().IsRegular() {
		return digest, errSharedTrustConflict
	}
	file, err := root.Open(name)
	if err != nil {
		return digest, errSharedTrustConflict
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(opened, info) {
		return digest, errSharedTrustConflict
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, sharedpg.MaxEncryptedServerKeyBytes+1))
	if err != nil || n == 0 || n > sharedpg.MaxEncryptedServerKeyBytes {
		return digest, errSharedTrustConflict
	}
	hash.Sum(digest[:0])
	return digest, nil
}

func changeSharedServerKit(ctx context.Context, path string, plan sharedSetupPlan, operation string, payload []byte, protection sharedStartupProtection) (json.RawMessage, error) {
	var id string
	if plan.ServerKit == nil || decodeVaultObject(payload, map[string]any{"workspaceId": &id}, "workspaceId") != nil || id != plan.Summary.WorkspaceID {
		return nil, vaultwire.ErrProtocol
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	next := *plan.ServerKit
	switch operation {
	case "shared-setup-save-server-kit":
		if next.State != serverKitPending {
			return nil, errSharedTrustConflict
		}
		if err := saveSharedServerKit(ctx, plan); err != nil {
			return nil, err
		}
		next.EncryptedKey, next.State = nil, serverKitSaved
	case "shared-setup-delete-server-key":
		if next.State != serverKitVerified {
			return nil, errSharedTrustConflict
		}
		if err := deleteSharedSetupServerKey(plan); err != nil {
			return nil, err
		}
		next.State = serverKitRemoved
	default:
		return nil, vaultwire.ErrProtocol
	}
	plan.ServerKit = &next
	if err := writeSharedSetupPlan(path, plan, protection); err != nil {
		return nil, err
	}
	return json.Marshal(sharedSetupReply{Plan: &plan.Summary, TLS: plan.tlsOutput(), ServerKit: plan.kitReceipt()})
}
