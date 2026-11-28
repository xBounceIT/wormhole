//go:build !windows

package main

import "github.com/zalando/go-keyring"

var desktopProtectedKeys = platformProtectedKeyring()

func legacyProtectedKeyring() protectedKeyringAdapter {
	return protectedKeyringAdapter{
		load: func(service, account string) ([]byte, error) {
			value, err := keyring.Get(service, account)
			return []byte(value), err
		},
		store: func(service, account string, value []byte) error {
			return keyring.Set(service, account, string(value))
		},
		remove: keyring.Delete,
	}
}
