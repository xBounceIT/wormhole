package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

const (
	macKeyringBase64Prefix = "go-keyring-base64:"
	macKeyringHexPrefix    = "go-keyring-encoded:"
	maxMacProtectedKey     = 256
)

var errMacProtectedKeyringValue = errors.New("system keychain contains an invalid protected key")

func encodeMacProtectedKeyringValue(value []byte) []byte {
	// Keep entries readable by releases using go-keyring's security CLI.
	return base64.StdEncoding.AppendEncode([]byte(macKeyringBase64Prefix), value)
}

func decodeMacProtectedKeyringValue(value []byte) ([]byte, error) {
	if len(value) == 0 || len(value) > maxMacProtectedKey {
		return nil, errMacProtectedKeyringValue
	}
	value = bytes.TrimSpace(value)
	var result []byte
	var err error
	switch {
	case bytes.HasPrefix(value, []byte(macKeyringBase64Prefix)):
		result, err = base64.StdEncoding.AppendDecode(nil, value[len(macKeyringBase64Prefix):])
	case bytes.HasPrefix(value, []byte(macKeyringHexPrefix)):
		result, err = hex.AppendDecode(nil, value[len(macKeyringHexPrefix):])
	default:
		result = bytes.Clone(value)
	}
	if err != nil || len(result) == 0 {
		clearBytes(result)
		return nil, errMacProtectedKeyringValue
	}
	return result, nil
}
