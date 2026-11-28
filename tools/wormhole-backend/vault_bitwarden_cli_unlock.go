package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type vaultBitwardenCLIUnlock struct {
	binding  vault.BitwardenCLIUnlockBinding
	key      *securemem.Buffer
	revision uint64
}

func vaultBitwardenCLIConfiguration(path string) (bitwardenCliSettings, string, error) {
	settings, err := readBitwardenCliSettings(path)
	if err != nil || !settings.Enabled {
		return settings, "", vault.ErrPolicy
	}
	var identity struct {
		Path, Executable string
		Region           int
	}
	identity.Path, identity.Region = settings.Path, settings.ServerRegion
	identity.Executable = resolveBitwardenCliExecutable(settings)
	if identity.Executable == "" {
		return settings, "", vault.ErrPolicy
	}
	raw, _ := json.Marshal(identity)
	digest := sha256.Sum256(raw)
	return settings, hex.EncodeToString(digest[:]), nil
}

func (h *vaultFoundationHandler) closeBitwardenCLIUnlock() error {
	if h.bitwardenCLIUnlock != nil {
		if err := h.bitwardenCLIUnlock.key.Close(); err != nil {
			return err
		}
		h.bitwardenCLIUnlock = nil
	}
	return nil
}

func (h *vaultFoundationHandler) bitwardenCLIUnlockOperation(ctx context.Context, operation string, raw []byte) (json.RawMessage, error) {
	if h.owner == nil || h.shared != nil {
		return nil, vault.ErrPolicy
	}
	if operation == "bitwarden-cli-unlock-begin" {
		return h.beginBitwardenCLIUnlock(ctx, raw)
	}
	var id string
	fields := map[string]any{"requestId": &id}
	required := []string{"requestId"}
	var sealedRaw json.RawMessage
	if operation == "bitwarden-cli-unlock-commit" {
		fields["session"] = &sealedRaw
		required = append(required, "session")
	}
	if len(raw) > maxBitwardenFrame || decodeVaultObject(raw, fields, required...) != nil || !vaultCredentialID(id) {
		return nil, vaultwire.ErrProtocol
	}
	pending := h.bitwardenCLIUnlock
	if operation == "bitwarden-cli-unlock-cancel" && pending == nil {
		return json.RawMessage(`{"cancelled":true}`), nil
	}
	if pending == nil || pending.binding.RequestID != id {
		return nil, vault.ErrPolicy
	}
	if operation == "bitwarden-cli-unlock-cancel" {
		if err := h.closeBitwardenCLIUnlock(); err != nil {
			return nil, h.retire(err)
		}
		return json.RawMessage(`{"cancelled":true}`), nil
	}
	return h.commitBitwardenCLIUnlock(ctx, pending, sealedRaw)
}

func (h *vaultFoundationHandler) beginBitwardenCLIUnlock(ctx context.Context, raw []byte) (json.RawMessage, error) {
	if len(raw) != 0 {
		return nil, vaultwire.ErrProtocol
	}
	now := time.Now()
	if pending := h.bitwardenCLIUnlock; pending != nil {
		if pending.binding.ExpiresAt > now.UnixMilli() {
			return nil, vault.ErrPolicy
		}
		if err := h.closeBitwardenCLIUnlock(); err != nil {
			return nil, h.retire(err)
		}
	}
	_, configuration, err := vaultBitwardenCLIConfiguration(h.databasePath)
	if err != nil {
		return nil, err
	}
	workspace, err := h.owner.WorkspaceID(ctx)
	if err != nil {
		return nil, err
	}
	state, err := h.owner.ReadLocalState(ctx, "bitwarden-cli", workspace, 0)
	if err != nil && !errors.Is(err, vaultstore.ErrMissing) {
		return nil, err
	}
	key, public, err := newSealedTunnelRecipientKey()
	if err != nil {
		return nil, err
	}
	binding := vault.BitwardenCLIUnlockBinding{
		WorkspaceID: workspace, RequestID: uuid.NewString(), Configuration: configuration,
		VaultKey: public, ExpiresAt: now.Add(vault.BitwardenCLIUnlockLifetime).UnixMilli(),
	}
	h.bitwardenCLIUnlock = &vaultBitwardenCLIUnlock{binding: binding, key: key, revision: state.RowVersion}
	return json.Marshal(binding)
}

func (h *vaultFoundationHandler) commitBitwardenCLIUnlock(ctx context.Context, pending *vaultBitwardenCLIUnlock, raw []byte) (json.RawMessage, error) {
	var sealed vault.SealedBundle
	var payload []byte
	defer func() { vault.Wipe(payload) }()
	err := decodeBitwardenExchangeBundle(raw, &sealed)
	if err == nil {
		err = pending.key.With(func(private []byte) error {
			var err error
			payload, err = vault.OpenBitwardenCLISession(private, pending.binding, sealed, time.Now())
			return err
		})
	}
	if closeErr := h.closeBitwardenCLIUnlock(); closeErr != nil {
		return nil, h.retire(closeErr)
	}
	if err != nil {
		return nil, err
	}
	settings, configuration, err := vaultBitwardenCLIConfiguration(h.databasePath)
	if err != nil || configuration != pending.binding.Configuration {
		return nil, vault.ErrAuthentication
	}
	var stored bitwardenSavedSession
	if decodeVaultObject(payload, map[string]any{"path": &stored.Path, "region": &stored.Region, "key": &stored.Key}, "path", "region", "key") != nil ||
		!bitwardenCliPathsEqual(stored.Path, settings.Path) || stored.Region != settings.ServerRegion {
		return nil, vault.ErrAuthentication
	}
	if key, err := bitwardenCliReadSessionKey(stored.Key); err != nil || key != stored.Key || strings.ContainsRune(key, 0) {
		return nil, vault.ErrAuthentication
	}
	if _, err := h.owner.PutLocalState(ctx, "bitwarden-cli", pending.binding.WorkspaceID, payload, pending.revision); err != nil {
		return nil, err
	}
	return json.RawMessage(`{"unlocked":true}`), nil
}

type nativeBitwardenCLIUnlock func(context.Context, bitwardenCliSettings, []byte) (string, error)

type bitwardenPasswordPipe struct {
	path    string
	stdin   io.Reader
	deliver func(context.Context, int, []byte) error
	close   func()
}

func unlockVaultBitwardenCLI(parent context.Context, settings bitwardenCliSettings, password []byte) (string, error) {
	if len(password) == 0 || bytes.IndexAny(password, "\r\n") >= 0 {
		return "", vault.ErrFormat
	}
	executable := resolveBitwardenCliExecutable(settings)
	if executable == "" {
		return "", vault.ErrPolicy
	}
	frame := make([]byte, len(password)+1)
	defer vault.Wipe(frame)
	copy(frame, password)
	frame[len(password)] = '\n'
	pipe, err := openVaultBitwardenPasswordPipe(frame)
	if err != nil {
		return "", err
	}
	defer pipe.close()
	ctx, stop := context.WithTimeout(parent, bitwardenCliProcessTimeout)
	defer stop()
	cmd := exec.CommandContext(ctx, executable, "unlock", "--passwordfile", pipe.path, "--raw", "--nointeraction")
	cmd.WaitDelay = 2 * time.Second
	cmd.Stdin = pipe.stdin
	cmd.Env = bitwardenCliMergeEnv(os.Environ(), map[string]string{
		"BW_SESSION": "", bitwardenCliPasswordEnvVar: "",
	})
	stdout := &bitwardenCliOutputBuffer{maxBytes: vault.MaxBitwardenSession}
	cmd.Stdout = stdout
	if err := startOwnedHelper(cmd); err != nil {
		return "", err
	}
	if pipe.deliver == nil {
		err = cmd.Wait()
	} else {
		var workerErr error
		// Keep the original Windows process object alive while verifying its
		// pipe client PID, including if the command exits during delivery.
		err = cmd.Process.WithHandle(func(_ uintptr) {
			input, finishInput := context.WithCancel(ctx)
			defer finishInput()
			stopped := make(chan error, 1)
			go func() {
				stopped <- cmd.Wait()
				finishInput()
			}()
			delivered := pipe.deliver(input, cmd.Process.Pid, frame)
			if delivered != nil {
				stop()
			}
			workerErr = errors.Join(delivered, <-stopped)
		})
		if err != nil {
			stop()
			_ = cmd.Wait()
		}
		err = errors.Join(err, workerErr)
	}
	if err != nil || stdout.overflowed || ctx.Err() != nil {
		return "", vault.ErrAuthentication
	}
	return bitwardenCliReadSessionKey(stdout.String())
}

func serveVaultBitwardenCLIUnlock(parent context.Context, input io.ReadCloser, output io.Writer, databasePath string, unlock nativeBitwardenCLIUnlock) error {
	return serveVaultBitwardenExchange(parent, input, output, vault.BitwardenCLIUnlockLifetime, func(ctx context.Context, key *securemem.Buffer, raw []byte) (any, error) {
		var b vault.BitwardenCLIUnlockBinding
		var bindingRaw, passwordRaw json.RawMessage
		if len(raw) > 8192 || decodeVaultObject(raw, map[string]any{
			"binding": &bindingRaw, "password": &passwordRaw,
		}, "binding", "password") != nil {
			return nil, vaultwire.ErrProtocol
		}
		var sealed vault.SealedBundle
		if decodeVaultObject(bindingRaw, map[string]any{
			"workspaceId": &b.WorkspaceID, "requestId": &b.RequestID, "configuration": &b.Configuration,
			"vaultKey": &b.VaultKey, "expiresAt": &b.ExpiresAt,
		}, "workspaceId", "requestId", "configuration", "vaultKey", "expiresAt") != nil ||
			decodeBitwardenExchangeBundle(passwordRaw, &sealed) != nil {
			return nil, vaultwire.ErrProtocol
		}
		settings, configuration, err := vaultBitwardenCLIConfiguration(databasePath)
		if err != nil || configuration != b.Configuration {
			return nil, vault.ErrPolicy
		}
		var password []byte
		defer func() { vault.Wipe(password) }()
		err = key.With(func(private []byte) error {
			var err error
			password, err = vault.OpenBitwardenCLIPassword(private, b, sealed, time.Now())
			return err
		})
		_ = key.Close()
		if err != nil {
			return nil, err
		}
		deadline, cancel := context.WithDeadline(ctx, time.UnixMilli(b.ExpiresAt))
		defer cancel()
		if deadline.Err() != nil {
			return nil, vault.ErrPolicy
		}
		sessionKey, err := unlock(deadline, settings, password)
		vault.Wipe(password)
		if err != nil || deadline.Err() != nil {
			return nil, vault.ErrAuthentication
		}
		if normalized, err := bitwardenCliReadSessionKey(sessionKey); err != nil || normalized != sessionKey || strings.ContainsRune(sessionKey, 0) {
			return nil, vault.ErrAuthentication
		}
		payload, err := json.Marshal(bitwardenSavedSession{Key: sessionKey, Path: settings.Path, Region: settings.ServerRegion})
		defer vault.Wipe(payload)
		if err != nil {
			return nil, err
		}
		return vault.SealBitwardenCLISession(b, payload, time.Now())
	})
}

func runVaultBitwardenCLIUnlock(databasePath string, input io.Reader, output, diagnostic io.Writer) int {
	reader, ok := input.(io.ReadCloser)
	if !ok || !filepath.IsAbs(databasePath) || securemem.DisableProcessDumps() != nil ||
		serveVaultBitwardenCLIUnlock(context.Background(), reader, output, databasePath, unlockVaultBitwardenCLI) != nil {
		writeErrorTo(diagnostic, "vault_bitwarden_unavailable")
		return 1
	}
	return 0
}
