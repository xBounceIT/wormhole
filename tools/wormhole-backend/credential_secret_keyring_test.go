package main

import (
	"errors"
	"strings"
	"testing"
)

const credentialSecretKeyringTestID = "40000000-0000-4000-8000-000000000001"

func TestCredentialSecretKeyringRoundTrip(t *testing.T) {
	stored := make(map[string]string)
	notFound := errors.New("not found")
	secretKeyring := credentialSecretKeyring{
		service:  "Wormhole test",
		encoding: "test-keyring-v1",
		set: func(service, account, value string) error {
			if service != "Wormhole test" {
				t.Fatalf("service = %q", service)
			}
			stored[account] = value
			return nil
		},
		get: func(_ string, account string) (string, error) {
			value, ok := stored[account]
			if !ok {
				return "", notFound
			}
			return value, nil
		},
		delete: func(_ string, account string) error {
			if _, ok := stored[account]; !ok {
				return notFound
			}
			delete(stored, account)
			return nil
		},
		notFound: notFound,
	}

	reference, encoding, err := secretKeyring.store(credentialSecretKeyringTestID, "manual-password")
	if err != nil {
		t.Fatal(err)
	}
	if encoding != "test-keyring-v1" {
		t.Fatalf("encoding = %q", encoding)
	}
	account, err := credentialSecretAccount(credentialSecretKeyringTestID, reference)
	if err != nil {
		t.Fatal(err)
	}
	if stored[account] != "manual-password" {
		t.Fatalf("stored value = %q", stored[account])
	}

	secret, err := secretKeyring.load(credentialSecretKeyringTestID, reference)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "manual-password" {
		t.Fatalf("secret = %q", secret)
	}
	if err := secretKeyring.remove(credentialSecretKeyringTestID, reference); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 0 {
		t.Fatalf("stored entries after delete = %d", len(stored))
	}
	if err := secretKeyring.remove(credentialSecretKeyringTestID, reference); err != nil {
		t.Fatalf("missing keyring entry delete = %v", err)
	}
}

func TestCredentialSecretKeyringErrorsDoNotExposePassword(t *testing.T) {
	stored := make(map[string]string)
	deleteCalls := 0
	secretKeyring := credentialSecretKeyring{
		service:  "Wormhole test",
		encoding: "test-keyring-v1",
		set: func(_ string, account, value string) error {
			stored[account] = value
			return errors.New("keyring unavailable")
		},
		delete: func(_ string, account string) error {
			deleteCalls++
			delete(stored, account)
			return nil
		},
	}

	_, _, err := secretKeyring.store(credentialSecretKeyringTestID, "do-not-leak")
	if err == nil {
		t.Fatal("store should fail")
	}
	if strings.Contains(err.Error(), "do-not-leak") {
		t.Fatalf("error exposes password: %v", err)
	}
	if deleteCalls != 1 || len(stored) != 0 {
		t.Fatalf("failed store cleanup = calls:%d entries:%d", deleteCalls, len(stored))
	}
}
