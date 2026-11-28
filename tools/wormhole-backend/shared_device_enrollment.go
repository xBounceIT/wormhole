package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func sharedDeviceEnrollmentPath(path string) string { return path + ".device" }

// Stage one self-contained slot/enrollment pair before any initial join intent.
// The caller owns unlocked storageRoot and authenticates selection independently.
// On uncertain durability confirm the exact bytes; never infer commit from readback.
func stageSharedDeviceEnrollment(path string, storageRoot []byte, slots vault.SlotFile, envelope []byte) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errSharedTrustStorage
	}
	raw, err := sharedpg.EncodeDeviceEnrollmentFile(storageRoot, slots, envelope)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, errSharedTrustStorage
	}
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		return nil, errSharedTrustConflict
	}
	defer release()
	if err := requireMissingSharedTrust(path); err != nil {
		return nil, err
	}
	if err := requireNoSharedPendingEnrollment(path); err != nil {
		return nil, err
	}
	for _, destination := range []string{sharedDeviceEnrollmentPath(path), sharedTransportSetupPath(path)} {
		_, err := os.Lstat(destination)
		if err == nil {
			return nil, errSharedTrustConflict
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, errSharedTrustStorage
		}
	}
	err = persistSharedTransitionBytes(sharedDeviceEnrollmentPath(path), raw)
	return raw, err
}

func readSharedDeviceEnrollment(path string) (vault.SlotFile, []byte, error) {
	if !filepath.IsAbs(path) {
		return vault.SlotFile{}, nil, errSharedTrustStorage
	}
	raw, err := readSharedTrustBytes(sharedDeviceEnrollmentPath(path), sharedpg.MaxDeviceEnrollmentFileBytes)
	if err != nil {
		return vault.SlotFile{}, nil, err
	}
	return sharedpg.DecodeDeviceEnrollmentFile(raw)
}

func confirmSharedDeviceEnrollment(path string, storageRoot []byte, vaultID, fileID string, minimum uint64, expected []byte) error {
	return confirmSharedDeviceEnrollmentState(path, storageRoot, vaultID, fileID, minimum, expected, func() error { return requireNoSharedPendingEnrollment(path) })
}

func confirmSharedDeviceEnrollmentState(path string, storageRoot []byte, vaultID, fileID string, minimum uint64, expected []byte, validateIntent func() error) error {
	if !filepath.IsAbs(path) {
		return errSharedTrustStorage
	}
	slots, envelope, err := sharedpg.DecodeDeviceEnrollmentFile(expected)
	if err != nil {
		return err
	}
	if _, err := sharedpg.OpenDeviceEnrollment(storageRoot, slots, vaultID, fileID, minimum, envelope); err != nil {
		return err
	}
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		return errSharedTrustConflict
	}
	defer release()
	if err := requireMissingSharedTrust(path); err != nil {
		return err
	}
	if err := validateIntent(); err != nil {
		return err
	}
	actual, err := readSharedTrustBytes(sharedDeviceEnrollmentPath(path), sharedpg.MaxDeviceEnrollmentFileBytes)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, expected) {
		return errSharedTrustConflict
	}
	return persistSharedTransitionBytes(sharedDeviceEnrollmentPath(path), expected)
}
