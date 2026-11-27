package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

var errVaultExtensionCleanup = errors.New("vault_extension_cleanup_unconfirmed")
var errVaultExtensionCommit = errors.New("vault_extension_commit_unconfirmed")

// Called after native action authorization, with a user-selected source and a
// native-owned destination root. Never replaces the active directory. All new
// files remain unreferenced until authenticated CAS; old installations are kept.
func installVaultBitwardenFolder(ctx context.Context, owner vaultBitwardenInstallerOwner, base, source *os.Root, expected uint64) (revision uint64, err error) {
	if owner == nil || base == nil || source == nil {
		return 0, errVaultExtensionFiles
	}
	sourcePath, e := filepath.EvalSymlinks(source.Name())
	if e != nil {
		return 0, errVaultExtensionFiles
	}
	basePath, e := filepath.EvalSymlinks(base.Name())
	if e != nil {
		return 0, errVaultExtensionFiles
	}
	relative, e := filepath.Rel(sourcePath, basePath)
	if e == nil && (relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)) {
		return 0, errVaultExtensionFiles
	}
	if _, e = readVaultBitwardenPackage(source); e != nil {
		return 0, e
	}
	return installVaultBitwardenTree(ctx, owner, base, source.FS(), expected)
}

// Folder and ZIP sources share bounded copy, no-replace publication and the
// authenticated commit point. Uncertain commits retain their referenced package.
func installVaultBitwardenTree(ctx context.Context, owner vaultBitwardenInstallerOwner, base *os.Root, source fs.FS, expected uint64) (revision uint64, err error) {
	if owner == nil || base == nil || source == nil {
		return 0, errVaultExtensionFiles
	}
	_, current, e := owner.ReadBitwardenInstallation(ctx, expected)
	if e != nil {
		return 0, e
	}
	if current != expected {
		return 0, errVaultExtensionFiles
	}
	journal, journaled := owner.(*scopedVaultBitwardenInstaller)
	if journaled {
		if e = journal.recoverIntent(ctx, base); e != nil {
			return 0, e
		}
	}
	digest, e := hashVaultExtensionFiles(ctx, source)
	if e != nil {
		return 0, e
	}
	id := uuid.NewString()
	stage := ".stage-" + id
	if _, e = base.Lstat(id); !errors.Is(e, os.ErrNotExist) {
		return 0, errVaultExtensionFiles
	}
	if journaled {
		if _, e = base.Lstat(stage); !errors.Is(e, os.ErrNotExist) {
			return 0, errVaultExtensionFiles
		}
		if e = journal.beginIntent(ctx, id, expected); e != nil {
			return 0, e
		}
		defer func() {
			if journal.recoverIntent(ctx, base) != nil {
				err = errVaultExtensionCleanup
			}
		}()
	}
	if e = base.Mkdir(stage, 0700); e != nil {
		return 0, errVaultExtensionFiles
	}
	retain := false
	published := false
	defer func() {
		if !retain {
			if base.RemoveAll(stage) != nil {
				err = errVaultExtensionCleanup
			}
			if published && base.RemoveAll(id) != nil {
				err = errVaultExtensionCleanup
			}
		}
	}()
	if journaled {
		if e = syncPrivateFileDirectory(base.Name()); e != nil {
			return 0, errVaultExtensionFiles
		}
		if e = journal.advanceIntent(ctx, "created"); e != nil {
			return 0, e
		}
	}
	destination, e := base.OpenRoot(stage)
	if e != nil {
		return 0, errVaultExtensionFiles
	}
	copyErr := copyVaultExtensionTree(ctx, source, destination)
	closeErr := destination.Close()
	if copyErr != nil || closeErr != nil {
		return 0, errVaultExtensionFiles
	}
	if !filepath.IsAbs(base.Name()) || publishVaultExtensionDirectory(filepath.Join(base.Name(), stage), filepath.Join(base.Name(), id)) != nil {
		return 0, errVaultExtensionFiles
	}
	published = true
	if syncPrivateFileDirectory(base.Name()) != nil {
		return 0, errVaultExtensionFiles
	}
	if journaled {
		if e = journal.advanceIntent(ctx, "published"); e != nil {
			return 0, e
		}
	}
	revision, err = activateVaultBitwardenInstallation(ctx, owner, base, id, expected, digest)
	if err != nil {
		// A failed acknowledgement is not proof that the database did not commit.
		// Remove files only after authenticated state confirms a different ID.
		current, _, readErr := owner.ReadBitwardenInstallation(ctx, 0)
		if readErr != nil || current.InstallationID == id {
			retain = true
			return 0, errVaultExtensionCommit
		}
		return 0, err
	}
	retain = true
	return revision, nil
}

func copyVaultExtensionTree(ctx context.Context, source fs.FS, destination *os.Root) error {
	if source == nil || destination == nil {
		return errVaultExtensionFiles
	}
	count := 0
	total := int64(0)
	buffer := make([]byte, 64*1024)
	directories := []string{"."}
	err := fs.WalkDir(boundedExtensionTree{FS: source, ctx: ctx}, ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || ctx.Err() != nil {
			return errVaultExtensionFiles
		}
		if path == "." {
			return nil
		}
		count++
		if count > bitwardenMaxExtractedFiles || len(path) > 1024 || strings.Count(path, "/") > 32 {
			return errVaultExtensionFiles
		}
		info, e := entry.Info()
		if e != nil {
			return errVaultExtensionFiles
		}
		if info.IsDir() {
			if e = destination.Mkdir(path, 0700); e != nil {
				return errVaultExtensionFiles
			}
			directories = append(directories, path)
			return nil
		}
		if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > bitwardenMaxExtractedBytes-total {
			return errVaultExtensionFiles
		}
		total += info.Size()
		input, e := source.Open(path)
		if e != nil {
			return errVaultExtensionFiles
		}
		output, e := destination.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			input.Close()
			return errVaultExtensionFiles
		}
		copyErr := streamVaultExtensionFile(ctx, output, input, info.Size(), buffer)
		syncErr := output.Sync()
		outputErr := output.Close()
		inputErr := input.Close()
		if copyErr != nil || syncErr != nil || outputErr != nil || inputErr != nil {
			return errVaultExtensionFiles
		}
		return nil
	})
	if err != nil {
		return errVaultExtensionFiles
	}
	for i := len(directories) - 1; i >= 0; i-- {
		if ctx.Err() != nil || syncPrivateFileDirectory(filepath.Join(destination.Name(), filepath.FromSlash(directories[i]))) != nil {
			return errVaultExtensionFiles
		}
	}
	return nil
}

// Main-only selected-folder mutation. Standard+ reaches this handler only through
// fresh-action, with the exact source and expected revision bound to authentication.
func (h *vaultFoundationHandler) installBitwardenFolder(ctx context.Context, raw []byte) (json.RawMessage, error) {
	return h.installBitwardenPackage(ctx, raw, false)
}
func (h *vaultFoundationHandler) installBitwardenZip(ctx context.Context, raw []byte) (json.RawMessage, error) {
	return h.installBitwardenPackage(ctx, raw, true)
}
func (h *vaultFoundationHandler) installBitwardenPackage(ctx context.Context, raw []byte, archive bool) (json.RawMessage, error) {
	if h.owner == nil || len(raw) > 8192 {
		return nil, vaultwire.ErrProtocol
	}
	var workspace, sourcePath, expected string
	sourceField := "sourceDirectory"
	if archive {
		sourceField = "sourceFile"
	}
	if decodeVaultObject(raw, map[string]any{"workspaceId": &workspace, sourceField: &sourcePath, "expectedRevision": &expected}, "workspaceId", sourceField, "expectedRevision") != nil || !vaultCredentialID(workspace) || len(sourcePath) > 4096 || !filepath.IsAbs(sourcePath) || strings.IndexByte(sourcePath, 0) >= 0 {
		return nil, vaultwire.ErrProtocol
	}
	revision, err := vaultCredentialRevision(expected, true)
	if err != nil {
		return nil, vaultwire.ErrProtocol
	}
	actual, err := h.owner.WorkspaceID(ctx)
	if err != nil {
		return nil, err
	}
	if actual != workspace {
		return nil, vaultwire.ErrProtocol
	}
	base, err := openVaultBitwardenInstallRoot(h.databasePath, 1, true)
	if err != nil {
		return nil, err
	}
	defer base.Close()
	var next uint64
	if archive {
		next, err = installVaultBitwardenZipFile(ctx, &scopedVaultBitwardenInstaller{Owner: h.owner, namespace: vaultBitwardenDatabaseNamespace(h.databasePath)}, base, sourcePath, revision)
	} else {
		source, openErr := os.OpenRoot(sourcePath)
		if openErr != nil {
			return nil, errVaultExtensionFiles
		}
		defer source.Close()
		next, err = installVaultBitwardenFolder(ctx, &scopedVaultBitwardenInstaller{Owner: h.owner, namespace: vaultBitwardenDatabaseNamespace(h.databasePath)}, base, source, revision)
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		WorkspaceID string `json:"workspaceId"`
		Revision    string `json:"revision"`
	}{workspace, strconv.FormatUint(next, 10)})
}
