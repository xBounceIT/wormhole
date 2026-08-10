//go:build linux

package main

import (
	"testing"

	"github.com/zalando/go-keyring"
)

func installLinuxCredentialStoreMock(t *testing.T) map[string]string {
	t.Helper()
	previousStore := linuxCredentialStore
	stored := make(map[string]string)
	linuxCredentialStore.set = func(service, account, value string) error {
		if service != "Wormhole" {
			t.Fatalf("service = %q", service)
		}
		stored[account] = value
		return nil
	}
	linuxCredentialStore.get = func(service, account string) (string, error) {
		if service != "Wormhole" {
			t.Fatalf("service = %q", service)
		}
		value, ok := stored[account]
		if !ok {
			return "", keyring.ErrNotFound
		}
		return value, nil
	}
	linuxCredentialStore.delete = func(service, account string) error {
		if service != "Wormhole" {
			t.Fatalf("service = %q", service)
		}
		if _, ok := stored[account]; !ok {
			return keyring.ErrNotFound
		}
		delete(stored, account)
		return nil
	}
	t.Cleanup(func() { linuxCredentialStore = previousStore })
	return stored
}

func TestLinuxCredentialSecretRoundTripUsesDBusKeyring(t *testing.T) {
	stored := installLinuxCredentialStoreMock(t)

	reference, encoding, err := storeCredentialSecret(credentialSecretKeyringTestID, "", "manual-password")
	if err != nil {
		t.Fatal(err)
	}
	if encoding != "linux-secret-service-dbus-v1" {
		t.Fatalf("encoding = %q", encoding)
	}
	secret, err := unprotectPlatformCredentialSecret(credentialSecretKeyringTestID, reference, encoding)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "manual-password" {
		t.Fatalf("secret = %q", secret)
	}
	if err := deleteStoredCredentialSecret(credentialSecretKeyringTestID, reference, encoding); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 0 {
		t.Fatalf("stored entries after delete = %d", len(stored))
	}
}
