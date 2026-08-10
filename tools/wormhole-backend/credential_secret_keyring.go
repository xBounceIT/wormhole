package main

import "errors"

var errCredentialSecretStoreUnavailable = errors.New("the system secret store is unavailable")

const (
	linuxLegacySecretServiceEncoding = "linux-secret-service-v1"
	linuxSecretServiceEncoding       = "linux-secret-service-dbus-v1"
	darwinKeychainEncoding           = "macos-keychain-v1"
)

type credentialSecretKeyring struct {
	service  string
	encoding string
	set      func(service, account, value string) error
	get      func(service, account string) (string, error)
	delete   func(service, account string) error
	notFound error
}

func (keyring credentialSecretKeyring) store(id, value string) (string, string, error) {
	reference, err := newCredentialSecretReference(id)
	if err != nil {
		return "", "", err
	}
	if err := keyring.storeAtReference(id, reference, value); err != nil {
		return "", "", err
	}
	return reference, keyring.encoding, nil
}

func (keyring credentialSecretKeyring) storeAtReference(id, reference, value string) error {
	account, err := credentialSecretAccount(id, reference)
	if err != nil {
		return err
	}
	if err := keyring.set(keyring.service, account, value); err != nil {
		// The Secret Service may have committed the item before a D-Bus response is lost. The
		// random reference is not shared with any prior item, so a best-effort delete safely
		// closes that unknown-outcome window without risking an existing credential.
		_ = keyring.delete(keyring.service, account)
		return errCredentialSecretStoreUnavailable
	}
	return nil
}

func (keyring credentialSecretKeyring) load(id, reference string) ([]byte, error) {
	account, err := credentialSecretAccount(id, reference)
	if err != nil {
		return nil, errors.New("stored credential reference is invalid")
	}
	value, err := keyring.get(keyring.service, account)
	if err != nil {
		return nil, errCredentialSecretStoreUnavailable
	}
	return []byte(value), nil
}

func (keyring credentialSecretKeyring) remove(id, reference string) error {
	account, err := credentialSecretAccount(id, reference)
	if err != nil {
		return err
	}
	if err := keyring.delete(keyring.service, account); err != nil && !errors.Is(err, keyring.notFound) {
		return errCredentialSecretStoreUnavailable
	}
	return nil
}
