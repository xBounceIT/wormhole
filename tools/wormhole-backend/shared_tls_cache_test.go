package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestSharedTLSCacheIntegrityAndLimits(t *testing.T) {
	c, _, o, root, _, _, org := sharedUnlockFixture(t)
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
	if err != nil {
		t.Fatal(err)
	}
	v := sharedTLSFixture(t, &o, state, org, 3)
	next, err := state.AdvanceTLS(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSharedTLSCache(o.TrustPath, v); err != nil {
		t.Fatal(err)
	}
	loaded, err := readSharedTLSCache(o.TrustPath, next)
	if err != nil || !bytes.Equal(loaded.Encode(), v.Encode()) {
		t.Fatal("cache roundtrip", err)
	}
	newer := sharedTLSFixture(t, &o, state, org, 4)
	if err := writeSharedTLSCache(o.TrustPath, newer); err != nil {
		t.Fatal(err)
	}
	if _, err := readSharedTLSCache(o.TrustPath, next); err != nil {
		t.Fatal("new bundle replaced committed old snapshot", err)
	}
	path, _ := sharedTLSCachePath(o.TrustPath, next.TLSDigest)
	if err := os.WriteFile(path, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSharedTLSCache(o.TrustPath, next); err != sharedpg.ErrTrustRollback {
		t.Fatal("tamper accepted", err)
	}
	if err := writeSharedTLSCache(o.TrustPath, v); err != nil {
		t.Fatal("repair authenticated snapshot", err)
	}
	o.Settings.TLSBundle = nil
	if err := loadSharedTLSCache(&o, next); err != nil || o.Settings.TLSBundle == nil {
		t.Fatal("load", err)
	}
	if err := loadSharedTLSCache(&o, next); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	o.Settings.TLSBundle = nil
	if err := loadSharedTLSCache(&o, next); !errors.Is(err, errSharedTrustMissing) {
		t.Fatal("missing cache fallback", err)
	}
	o.Settings.TLS = sharedpg.TLSOff
	if err := loadSharedTLSCache(&o, next); err != nil {
		t.Fatal("explicit nonverified mode", err)
	}
	o.Settings.TLS = sharedpg.TLSVerified
	if err := loadSharedTLSCache(&o, state); err != nil {
		t.Fatal("legacy state", err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeSharedTLSCache(o.TrustPath, v); err != errSharedTrustStorage {
		t.Fatal("nonregular target", err)
	}
	if _, err := readSharedTLSCache(o.TrustPath, next); err != errSharedTrustStorage {
		t.Fatal("nonregular read", err)
	}
	if err := writeSharedTLSCache(o.TrustPath, nil); err != errSharedTrustStorage {
		t.Fatal("nil bundle", err)
	}
	if _, err := sharedTLSCachePath("relative", next.TLSDigest); err == nil {
		t.Fatal("relative path")
	}
	if _, err := readSharedTLSCache(o.TrustPath, state); err == nil {
		t.Fatal("missing floor")
	}
	bad := o.TrustPath + "-bad"
	if err := os.WriteFile(bad+".tls", []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeSharedTLSCache(bad, v); err != errSharedTrustStorage {
		t.Fatal("cache directory is file", err)
	}
	if _, err := readSharedTLSCache(bad, next); err != errSharedTrustStorage {
		t.Fatal("invalid cache directory read", err)
	}
	locked := o.TrustPath + "-locked"
	release, err := tryAcquireExclusiveFileLock(locked + ".tls-cache.lock")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSharedTLSCache(locked, v); err != errSharedTrustConflict {
		t.Fatal("cache lock bypass", err)
	}
	release()
	quota := o.TrustPath + "-quota"
	if err := writeSharedTLSCache(quota, v); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < maxSharedTLSCacheEntries; i++ {
		if err := os.WriteFile(filepath.Join(quota+".tls", fmt.Sprint(i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeSharedTLSCache(quota, newer); err != errSharedTLSCacheFull {
		t.Fatal("unbounded cache", err)
	}
	if err := writeSharedTLSCache(quota, v); err != nil {
		t.Fatal("full cache blocked existing snapshot", err)
	}
}

func TestSharedTLSCacheRestartAndRecovery(t *testing.T) {
	c, previous, o, root, _, _, org := sharedUnlockFixture(t)
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
	if err != nil {
		t.Fatal(err)
	}
	sharedTLSFixture(t, &o, state, org, 3)
	next, err := acceptSharedTLSBundle(o, root, state)
	if err != nil {
		t.Fatal(err)
	}
	o.Settings.TLSBundle = nil
	lifetime, cancel := context.WithCancel(context.Background())
	p := &sharedAdmissionProbe{ctx: lifetime, cancel: cancel, response: previous.response, loginMaterial: previous.loginMaterial}
	fresh := newSharedAdmissionControllerWithSession(p)
	defer fresh.Close(context.Background())
	p.open = func(_ context.Context, s sharedpg.Settings) error {
		if s.TLSBundle == nil || s.TLSBundle.Pin().MinimumSequence != 3 {
			t.Fatal("cache not used on restart")
		}
		return nil
	}
	if err := fresh.Open(context.Background(), o, root, p.loginMaterial); err != nil {
		t.Fatal("restart", err)
	}
	path, _ := sharedTLSCachePath(o.TrustPath, next.TLSDigest)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	otherLifetime, otherCancel := context.WithCancel(context.Background())
	badProbe := &sharedAdmissionProbe{ctx: otherLifetime, cancel: otherCancel, response: previous.response, loginMaterial: previous.loginMaterial}
	bad := newSharedAdmissionControllerWithSession(badProbe)
	defer bad.Close(context.Background())
	if err := bad.Open(context.Background(), o, root, p.loginMaterial); err == nil || badProbe.opens.Load() != 0 {
		t.Fatal("missing cache allowed network", err)
	}

	recovery, rp, ro, master, newRoot, oldRoot, _, recoveryOrg := sharedRecoveryFixture(t, true)
	pending, err := readSharedTrustRootTransition(ro.TrustPath, newRoot, ro.Binding)
	if err != nil {
		t.Fatal(err)
	}
	sharedTLSFixture(t, &ro, pending.ObservedTrust(), recoveryOrg, 7)
	observed, err := pending.ObserveTLS(ro.Binding, ro.Settings.TLSBundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSharedTLSCache(ro.TrustPath, ro.Settings.TLSBundle); err != nil {
		t.Fatal(err)
	}
	if err := persistSharedRecoveryObservation(ro, newRoot, &pending, observed); err != nil {
		t.Fatal(err)
	}
	ro.Settings.TLSBundle = nil
	rp.open = func(_ context.Context, s sharedpg.Settings) error {
		if s.TLSBundle == nil || s.TLSBundle.Pin().MinimumSequence != 7 {
			t.Fatal("recovery ignored observed bundle")
		}
		return nil
	}
	if _, err := recovery.RecoverPasswordChange(context.Background(), ro, master, newRoot, oldRoot, vault.KDFV1, false, sharedRecoveryNewPassword); err != nil {
		t.Fatal("recover from cache", err)
	}
}

func TestSharedTLSCacheMissingRecoveryBlocksNetwork(t *testing.T) {
	c, p, o, master, newRoot, oldRoot, _, org := sharedRecoveryFixture(t, true)
	pending, err := readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding)
	if err != nil {
		t.Fatal(err)
	}
	sharedTLSFixture(t, &o, pending.ObservedTrust(), org, 9)
	observed, err := pending.ObserveTLS(o.Binding, o.Settings.TLSBundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistSharedRecoveryObservation(o, newRoot, &pending, observed); err != nil {
		t.Fatal(err)
	}
	o.Settings.TLSBundle = nil
	if _, err := c.RecoverPasswordChange(context.Background(), o, master, newRoot, oldRoot, vault.KDFV1, false, sharedRecoveryNewPassword); err == nil || p.opens.Load() != 0 {
		t.Fatal("missing recovery cache allowed network", err)
	}
	if _, err := readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding); err != nil {
		t.Fatal("missing cache erased journal", err)
	}
}
