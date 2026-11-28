package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func sharedTransportSetupPath(path string) string { return path + ".connection" }

func (c *sharedAdmissionController) currentTransportSettings(trust sharedpg.TrustState) (sharedpg.Settings, error) {
	var settings sharedpg.Settings
	err := c.root.With(func(key []byte) error {
		var err error
		settings, err = readSharedTransportSetup(sharedAdmissionOptions{
			TrustPath: c.trustPath, Binding: c.trustBinding, OSFloor: c.runtimeOSFloor,
			UserFloor: c.runtimeUserFloor, Request: sharedpg.AdmissionRequest{API: 1},
		}, key, trust)
		return err
	})
	return settings, err
}

// Stage the authenticated native connection settings before initial join intent.
// This file contains no password, ASK or root. It cannot replace key-slot storage.
func stageSharedTransportSetup(o sharedAdmissionOptions, root []byte, trust sharedpg.TrustState) error {
	if !filepath.IsAbs(o.TrustPath) {
		return errSharedTrustStorage
	}
	raw, err := sharedpg.SealTransportSetup(root, o.Binding, o.Settings, trust, o.OSFloor, o.UserFloor, o.Request.API)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(o.TrustPath), 0700); err != nil {
		return errSharedTrustStorage
	}
	release, err := tryAcquireExclusiveFileLock(o.TrustPath + ".lock")
	if err != nil {
		return errSharedTrustConflict
	}
	defer release()
	if err := requireMissingSharedTrust(o.TrustPath); err != nil {
		return err
	}
	if err := requireNoSharedPendingEnrollment(o.TrustPath); err != nil {
		return err
	}
	_, err = os.Lstat(sharedTransportSetupPath(o.TrustPath))
	if err == nil {
		return errSharedTrustConflict
	}
	if !errors.Is(err, os.ErrNotExist) {
		return errSharedTrustStorage
	}
	return persistSharedTransitionBytes(sharedTransportSetupPath(o.TrustPath), raw)
}

func readSharedTransportSetup(o sharedAdmissionOptions, root []byte, trust sharedpg.TrustState) (sharedpg.Settings, error) {
	if !filepath.IsAbs(o.TrustPath) {
		return sharedpg.Settings{}, errSharedTrustStorage
	}
	raw, err := readSharedTrustBytes(sharedTransportSetupPath(o.TrustPath), sharedpg.MaxTransportSnapshotBytes*2)
	if err != nil {
		return sharedpg.Settings{}, err
	}
	return openSharedTransportSetup(o, root, trust, raw)
}

func openSharedTransportSetup(o sharedAdmissionOptions, root []byte, trust sharedpg.TrustState, raw []byte) (sharedpg.Settings, error) {
	settings, err := sharedpg.OpenTransportSetup(root, o.Binding, raw, trust, o.OSFloor, o.UserFloor, o.Request.API)
	if !errors.Is(err, vault.ErrRollback) {
		return settings, err
	}
	// The cache is published before the durable trust floor. Recover its exact
	// current bundle without rewriting independently authenticated host settings.
	bundle, err := readSharedTLSCache(o.TrustPath, trust)
	if err != nil {
		return sharedpg.Settings{}, err
	}
	return sharedpg.OpenTransportSetupWithTLS(root, o.Binding, raw, trust, o.OSFloor, o.UserFloor, o.Request.API, bundle)
}

// Confirm exact settings under the same lock, then durably rewrite. A successful
// readback alone never authorizes dispatch after uncertain directory sync.
func confirmSharedTransportSetup(o sharedAdmissionOptions, root []byte, trust sharedpg.TrustState) error {
	if !filepath.IsAbs(o.TrustPath) {
		return errSharedTrustStorage
	}
	release, err := tryAcquireExclusiveFileLock(o.TrustPath + ".lock")
	if err != nil {
		return errSharedTrustConflict
	}
	defer release()
	if err := requireMissingSharedTrust(o.TrustPath); err != nil {
		return err
	}
	actual, err := readSharedTransportSetup(o, root, trust)
	if err != nil {
		return err
	}
	a, err := sharedpg.EncodeTransportSnapshot(actual, trust, o.OSFloor, o.UserFloor, o.Request.API)
	if err != nil {
		return err
	}
	expected, err := sharedpg.EncodeTransportSnapshot(o.Settings, trust, o.OSFloor, o.UserFloor, o.Request.API)
	if err != nil {
		return err
	}
	if !bytes.Equal(a, expected) {
		return errSharedTrustConflict
	}
	raw, err := sharedpg.SealTransportSetup(root, o.Binding, actual, trust, o.OSFloor, o.UserFloor, o.Request.API)
	if err != nil {
		return err
	}
	return persistSharedTransitionBytes(sharedTransportSetupPath(o.TrustPath), raw)
}
