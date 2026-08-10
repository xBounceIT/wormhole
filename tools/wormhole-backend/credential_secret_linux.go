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

	"github.com/zalando/go-keyring"
)

// Linux uses the freedesktop Secret Service over D-Bus. Older releases invoked secret-tool, so
// that reader remains available for existing references while new writes no longer require the
// optional libsecret-tools package. There is deliberately no plaintext fallback when a Secret
// Service is unavailable.
const (
	linuxSecretServiceName = "Wormhole"
	linuxSecretToolTimeout = 20 * time.Second
)

var linuxCredentialStore = credentialSecretKeyring{
	service:  linuxSecretServiceName,
	encoding: linuxSecretServiceEncoding,
	set:      keyring.Set,
	get:      keyring.Get,
	delete:   keyring.Delete,
	notFound: keyring.ErrNotFound,
}

func prepareCredentialSecretStorage(id string) (string, string, error) {
	reference, err := newCredentialSecretReference(id)
	return reference, linuxSecretServiceEncoding, err
}

func storeCredentialSecret(id, reference, value string) (string, string, error) {
	if reference == "" {
		return linuxCredentialStore.store(id, value)
	}
	if err := linuxCredentialStore.storeAtReference(id, reference, value); err != nil {
		return "", "", err
	}
	return reference, linuxSecretServiceEncoding, nil
}

func unprotectPlatformCredentialSecret(id, encoded, encoding string) ([]byte, error) {
	switch strings.TrimSpace(encoding) {
	case linuxSecretServiceEncoding:
		return linuxCredentialStore.load(id, encoded)
	case linuxLegacySecretServiceEncoding:
		return unprotectLegacyLinuxCredentialSecret(id, encoded)
	default:
		return nil, errUnsupportedSecretEncoding
	}
}

func deleteStoredCredentialSecret(id, encoded, encoding string) error {
	switch strings.TrimSpace(encoding) {
	case linuxSecretServiceEncoding:
		return linuxCredentialStore.remove(id, encoded)
	case linuxLegacySecretServiceEncoding:
		return deleteLegacyLinuxCredentialSecret(id, encoded)
	default:
		return nil
	}
}

func unprotectLegacyLinuxCredentialSecret(id, encoded string) ([]byte, error) {
	account, err := credentialSecretAccount(id, encoded)
	if err != nil {
		return nil, errors.New("stored credential reference is invalid")
	}
	commandPath, err := exec.LookPath("secret-tool")
	if err != nil {
		return nil, errCredentialSecretStoreUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), linuxSecretToolTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, commandPath, "lookup", "service", "Wormhole", "account", account)
	command.Stderr = io.Discard
	stdout, err := command.StdoutPipe()
	if err != nil || command.Start() != nil {
		return nil, errCredentialSecretStoreUnavailable
	}
	value, readErr := io.ReadAll(io.LimitReader(stdout, int64(maxStoredCredentialBytes+2)))
	if readErr != nil || len(value) > maxStoredCredentialBytes+1 {
		cancel()
		_ = command.Wait()
		return nil, errCredentialSecretStoreUnavailable
	}
	waitErr := command.Wait()
	if waitErr != nil {
		return nil, errCredentialSecretStoreUnavailable
	}
	return bytes.TrimSuffix(value, []byte{'\n'}), nil
}

func deleteLegacyLinuxCredentialSecret(id, encoded string) error {
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
