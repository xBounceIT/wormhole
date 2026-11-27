package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

type protectedKeyringAdapter struct {
	load   func(string, string) ([]byte, error)
	store  func(string, string, []byte) error
	remove func(string, string) error
}

var errProtectedKeyringNotFound = keyring.ErrNotFound

func (keyring protectedKeyringAdapter) protectionKey(service, account string, create bool) ([]byte, error) {
	encoded, err := keyring.load(service, account)
	defer clearBytes(encoded)
	if err == nil {
		return decodeAuthProtectionKey(encoded)
	}
	if !errors.Is(err, errProtectedKeyringNotFound) {
		return nil, errCredentialSecretStoreUnavailable
	}
	if !create {
		return nil, fmt.Errorf("system keychain is unavailable: %w", err)
	}

	key := make([]byte, authProtectionKeyLength)
	if _, err := rand.Read(key); err != nil {
		return nil, errors.New("cannot generate an authentication protection key")
	}
	newEncoding := base64.RawStdEncoding.AppendEncode(nil, key)
	defer clearBytes(newEncoding)
	if err := keyring.store(service, account, newEncoding); err != nil {
		clearBytes(key)
		return nil, errCredentialSecretStoreUnavailable
	}
	return key, nil
}

func decodeAuthProtectionKey(encoded []byte) ([]byte, error) {
	key, err := base64.RawStdEncoding.AppendDecode(nil, encoded)
	if err != nil || len(key) != authProtectionKeyLength {
		clearBytes(key)
		return nil, errors.New("system keychain contains an invalid authentication key")
	}
	return key, nil
}
