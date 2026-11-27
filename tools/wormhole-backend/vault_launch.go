package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func checkVaultInstallationFloor(ctx context.Context) error {
	floor, err := ospolicy.ReadFloor(ctx)
	if err != nil {
		return vault.ErrPolicy
	}
	return ospolicy.CheckInstallationFloor(ctx, floor, updateManifestPublicKeyHex)
}

// Fixed main-process selections, never a wire payload. A migration launch is a
// native assertion that the previous Chromium owner has exited and the current
// process uses a distinct session-data directory. Fresh factors are still required.
type vaultLaunchOptions struct {
	userDataPath         string
	migrationSessionData string
	touchIDChannel       bool
	touchIDBroker        *touchIDBrokerClient
}

func (o vaultLaunchOptions) validate() error {
	if o.migrationSessionData == "" {
		return nil
	}
	paths := []string{o.userDataPath, o.migrationSessionData}
	for i, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || !utf8.ValidString(path) || strings.ContainsRune(path, 0) {
			return vault.ErrPolicy
		}
		canonical, err := filepath.EvalSymlinks(path)
		if err != nil {
			return vault.ErrPolicy
		}
		info, err := os.Stat(canonical)
		if err != nil || !info.IsDir() {
			return vault.ErrPolicy
		}
		paths[i] = canonical
	}
	for i := range paths {
		relative, err := filepath.Rel(paths[i], paths[1-i])
		if err != nil || relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return vault.ErrPolicy
		}
	}
	return nil
}

// Synchronous pre-Chromium probe. This opens neither SQLite nor a persistent
// vault service, and cannot migrate, initialize logs or write a workspace lock.
func runVaultStartupCLI(databasePath string, output, errorOutput io.Writer) int {
	// Shared startup may briefly borrow an OS-protected file key even though
	// the returned hints contain no account material. Apply native dump policy.
	if err := securemem.DisableProcessDumps(); err != nil {
		writeErrorTo(errorOutput, "vault_memory_unavailable")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := checkVaultInstallationFloor(ctx); err != nil {
		writeErrorTo(errorOutput, err.Error())
		return 1
	}
	effective, selection, err := resolveVaultWorkspace(databasePath, nativeSharedStartupProtection())
	if err != nil {
		writeErrorTo(errorOutput, "vault_startup_unavailable")
		return 1
	}
	h := &vaultFoundationHandler{databasePath: effective, sharedSelection: selection}
	raw, err := h.startup(ctx, nil)
	if err == nil {
		_, err = output.Write(append(raw, '\n'))
	}
	if err != nil {
		writeErrorTo(errorOutput, "vault_startup_unavailable")
		return 1
	}
	return 0
}
