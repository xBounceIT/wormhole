//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"time"
)

// Linux uses the freedesktop Secret Service through secret-tool. Password bytes are supplied on
// stdin, never as an argument or in the SQLite database. Distributions without a running Secret
// Service receive a clear save error instead of a plaintext fallback.
const (
	linuxSecretServiceEncoding = "linux-secret-service-v1"
	linuxSecretToolTimeout     = 20 * time.Second
)

func storeCredentialSecret(id, value string) (string, string, error) {
	reference, err := newCredentialSecretReference(id)
	if err != nil {
		return "", "", err
	}
	account, err := credentialSecretAccount(id, reference)
	if err != nil {
		return "", "", err
	}
	commandPath, err := exec.LookPath("secret-tool")
	if err != nil {
		return "", "", errors.New("the system secret store is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), linuxSecretToolTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, commandPath, "store", "--label=Wormhole credential", "service", "Wormhole", "account", account)
	command.Stdin = strings.NewReader(value)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return "", "", errors.New("the system secret store is unavailable")
	}
	return reference, linuxSecretServiceEncoding, nil
}

func unprotectPlatformCredentialSecret(id, encoded, encoding string) ([]byte, error) {
	if strings.TrimSpace(encoding) != linuxSecretServiceEncoding {
		return nil, errUnsupportedSecretEncoding
	}
	account, err := credentialSecretAccount(id, encoded)
	if err != nil {
		return nil, errors.New("stored credential reference is invalid")
	}
	commandPath, err := exec.LookPath("secret-tool")
	if err != nil {
		return nil, errors.New("the system secret store is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), linuxSecretToolTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, commandPath, "lookup", "service", "Wormhole", "account", account)
	command.Stderr = io.Discard
	stdout, err := command.StdoutPipe()
	if err != nil || command.Start() != nil {
		return nil, errors.New("the system secret store is unavailable")
	}
	value, readErr := io.ReadAll(io.LimitReader(stdout, int64(maxStoredCredentialBytes+2)))
	if readErr != nil || len(value) > maxStoredCredentialBytes+1 {
		cancel()
		_ = command.Wait()
		return nil, errors.New("the system secret store is unavailable")
	}
	waitErr := command.Wait()
	if waitErr != nil {
		return nil, errors.New("the system secret store is unavailable")
	}
	return bytes.TrimSuffix(value, []byte{'\n'}), nil
}

func deleteStoredCredentialSecret(id, encoded, encoding string) error {
	if strings.TrimSpace(encoding) != linuxSecretServiceEncoding {
		return nil
	}
	account, err := credentialSecretAccount(id, encoded)
	if err != nil {
		return err
	}
	commandPath, err := exec.LookPath("secret-tool")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), linuxSecretToolTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, commandPath, "clear", "service", "Wormhole", "account", account)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}
