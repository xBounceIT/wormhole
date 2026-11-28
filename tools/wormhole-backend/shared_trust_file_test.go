package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func sharedTrustFileFixture(t *testing.T) ([]byte, sharedpg.TrustBinding, sharedpg.TrustState, sharedpg.TrustState) {
	return sharedTrustFileFixtureWithProfile(t, vault.Standard)
}

func TestSharedTrustFileAccountRevocationSurvivesRestart(t *testing.T) {
	root, b, base, _ := sharedTrustFileFixture(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(private)
	signer := uuid.New()
	policy, err := vault.DecodeSignedPolicy(base.SignedProfile)
	if err != nil {
		t.Fatal(err)
	}
	policy, err = vault.SignPolicy(policy.Policy, signer.String(), 1, private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := vault.EncodeSignedPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	request := sharedpg.AdmissionRequest{API: 1, AppVersion: "1.2.3", Source: "ui", WorkspaceID: b.WorkspaceID, UserID: b.UserID, DeviceID: b.DeviceID}
	admission := &sharedpg.UnverifiedAdmission{WorkspaceID: b.WorkspaceID, UserID: b.UserID, DeviceID: b.DeviceID, MinAPI: 1, MaxAPI: 1, SignedProfile: raw}
	initial, err := sharedpg.NewTrustState(admission, request, sharedpg.PolicyTrust{WorkspaceID: b.WorkspaceID, SignerKeyID: signer.String(), SignerKeyVersion: 1, PublicKey: public, MinimumSequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "account.trust")
	if err := writeSharedTrustFile(path, root, b, initial, 0); err != nil {
		t.Fatal(err)
	}
	account := vault.UserKeyState{FormatVersion: 1, WorkspaceID: b.WorkspaceID, UserID: b.UserID, Sequence: 1, Active: true, Encryption: vault.KeyRef{ID: uuid.New(), Version: 1}, Signing: vault.KeyRef{ID: uuid.New(), Version: 1}, MinimumEncryptionCertificate: 1, MinimumSigningCertificate: 1, Signer: vault.KeyRef{ID: signer, Version: 1}}
	account, err = vault.SignUserKeyState(account, private)
	if err != nil {
		t.Fatal(err)
	}
	current, err := initial.AdvanceAccount(account, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSharedTrustFile(path, root, b, current, initial.Revision); err != nil {
		t.Fatal(err)
	}
	revoked := account
	revoked.Sequence++
	revoked.Active = false
	revoked, _ = vault.SignUserKeyState(revoked, private)
	next, err := current.AdvanceAccount(revoked, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSharedTrustFile(path, root, b, next, current.Revision); err != nil {
		t.Fatal(err)
	}
	restarted, err := readSharedTrustFile(path, root, b, next.Revision)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := restarted.AccountTrust()
	if err != nil || restarted.Account.Active {
		t.Fatal("revocation lost on restart")
	}
	if err := vault.VerifyUserKeyState(account, trust); err != vault.ErrRollback {
		t.Fatal("old active state accepted after restart")
	}
	rollback := initial
	rollback.Revision = next.Revision + 1
	if err := writeSharedTrustFile(path, root, b, rollback, next.Revision); err != sharedpg.ErrTrustRollback {
		t.Fatalf("writer permitted account floor removal: %v", err)
	}
	equivocal := revoked
	equivocal.Active = true
	equivocal, _ = vault.SignUserKeyState(equivocal, private)
	forged := next
	forged.Revision++
	forged.Account = &equivocal
	if err := writeSharedTrustFile(path, root, b, forged, next.Revision); err != sharedpg.ErrAccountEquivocation {
		t.Fatal("writer permitted same-sequence reactivation")
	}
	if err := confirmSharedTrustFile(path, root, b, restarted); err != nil {
		t.Fatal(err)
	}
}

func sharedTrustFileFixtureWithProfile(t *testing.T, nextProfile vault.Profile, initialProfile ...vault.Profile) ([]byte, sharedpg.TrustBinding, sharedpg.TrustState, sharedpg.TrustState) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := sharedpg.TrustBinding{WorkspaceID: uuid.New(), UserID: uuid.New(), DeviceID: uuid.New(), KeyID: uuid.New(), KeyVersion: 1}
	request := sharedpg.AdmissionRequest{API: 1, AppVersion: "1.2.3", Source: "ui", WorkspaceID: b.WorkspaceID, UserID: b.UserID, DeviceID: b.DeviceID}
	trust := sharedpg.PolicyTrust{WorkspaceID: b.WorkspaceID, SignerKeyID: "organisation", SignerKeyVersion: 1, PublicKey: pub, MinimumSequence: 1}
	admission := &sharedpg.UnverifiedAdmission{WorkspaceID: b.WorkspaceID, UserID: b.UserID, DeviceID: b.DeviceID, MinAPI: 1, MaxAPI: 1}
	policy := vault.Policy{FormatVersion: 1, WorkspaceID: b.WorkspaceID.String(), Sequence: 1, Profile: vault.Standard, KDF: vault.KDFV1, OrgEscrow: true, MinAPI: 1, MaxAPI: 1}
	if len(initialProfile) != 0 {
		policy.Profile = initialProfile[0]
	}
	sign := func() {
		t.Helper()
		signed, err := vault.SignPolicy(policy, "organisation", 1, priv)
		if err != nil {
			t.Fatal(err)
		}
		admission.SignedProfile, err = vault.EncodeSignedPolicy(signed)
		if err != nil {
			t.Fatal(err)
		}
	}
	sign()
	current, err := sharedpg.NewTrustState(admission, request, trust)
	if err != nil {
		t.Fatal(err)
	}
	policy.Sequence = 2
	policy.Profile = nextProfile
	if nextProfile == vault.Hardened {
		policy.KDF = vault.KDFV2
	}
	if nextProfile == vault.Paranoid {
		policy.KDF = vault.KDFV3
		policy.ASKRequired = true
	}
	sign()
	next, err := current.Advance(admission, request)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Repeat([]byte{0x68}, 32), b, current, next
}

func TestSharedTrustFilePersistence(t *testing.T) {
	root, b, current, next := sharedTrustFileFixture(t)
	path := filepath.Join(t.TempDir(), "device.trust")
	if _, err := readSharedTrustFile(path, root, b, 1); err != errSharedTrustMissing {
		t.Fatal("missing state not distinguished")
	}
	if err := writeSharedTrustFile(path, root, b, current, 0); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || bytes.Contains(raw, root) || bytes.Contains(raw, []byte(current.SignerKeyID)) {
		t.Fatal("plaintext trust storage")
	}
	loaded, err := readSharedTrustFile(path, root, b, 1)
	if err != nil || loaded.Revision != 1 || loaded.PolicySequence != 1 {
		t.Fatal("trust readback failed")
	}
	if err := writeSharedTrustFile(path, root, b, current, 0); err != errSharedTrustConflict {
		t.Fatal("existing enrollment replaced")
	}
	if err := writeSharedTrustFile(path, root, b, next, 1); err != nil {
		t.Fatal(err)
	}
	loaded, err = readSharedTrustFile(path, root, b, 2)
	if err != nil || loaded.PolicySequence != 2 {
		t.Fatal("trust advance not durable")
	}
	if err := writeSharedTrustFile(path, root, b, next, 1); err != errSharedTrustConflict {
		t.Fatal("stale revision overwrote trust")
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSharedTrustFile(path, root, b, 2); err != sharedpg.ErrTrustRollback {
		t.Fatal("known revision replay accepted")
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeSharedTrustFile(path, root, b, current, 0); err != sharedpg.ErrTrustState {
		t.Fatal("corruption reset as enrollment")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := writeSharedTrustFile(path, root, b, next, 1); err != errSharedTrustConflict {
		t.Fatal("missing trust recreated during update")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed update created state")
	}
}

func TestSharedTrustFileRejectsPinAndSequenceChanges(t *testing.T) {
	for _, change := range []func(*sharedpg.TrustState){
		func(s *sharedpg.TrustState) { s.SignerKeyID = "other" }, func(s *sharedpg.TrustState) { s.SignerKeyVersion++ }, func(s *sharedpg.TrustState) { s.PublicKey = bytes.Repeat([]byte{3}, 32) },
		func(s *sharedpg.TrustState) { s.PolicySequence = 1 }, func(s *sharedpg.TrustState) { s.PolicySequence = 0 }, func(s *sharedpg.TrustState) { s.PolicySequence = 999 }, func(s *sharedpg.TrustState) { s.DeviceID = uuid.New() },
	} {
		root, b, current, next := sharedTrustFileFixture(t)
		path := filepath.Join(t.TempDir(), "device.trust")
		if err := writeSharedTrustFile(path, root, b, current, 0); err != nil {
			t.Fatal(err)
		}
		change(&next)
		if err := writeSharedTrustFile(path, root, b, next, 1); err == nil {
			t.Fatal("invalid transition accepted")
		}
		loaded, err := readSharedTrustFile(path, root, b, 1)
		if err != nil || loaded.Revision != 1 {
			t.Fatal("rejected transition changed state")
		}
	}
}

func TestSharedTrustFileFailureAndLockPaths(t *testing.T) {
	root, b, current, next := sharedTrustFileFixture(t)
	if _, err := readSharedTrustFile("relative.trust", root, b, 1); err != errSharedTrustStorage {
		t.Fatal("relative path accepted")
	}
	if err := writeSharedTrustFile("relative.trust", root, b, current, 0); err != errSharedTrustStorage {
		t.Fatal("relative write accepted")
	}
	dir := t.TempDir()
	if _, err := readSharedTrustFile(dir, root, b, 1); err != errSharedTrustStorage {
		t.Fatal("directory read accepted")
	}
	if err := writeSharedTrustFile(dir, root, b, current, 0); err != errSharedTrustStorage {
		t.Fatal("directory overwritten")
	}
	path := filepath.Join(dir, "device.trust")
	if err := writeSharedTrustFile(path, root, b, current, math.MaxUint64); err != errSharedTrustConflict {
		t.Fatal("revision overflow accepted")
	}
	if err := writeSharedTrustFile(path, root, b, next, 0); err != errSharedTrustConflict {
		t.Fatal("noninitial revision created")
	}
	if err := writeSharedTrustFile(path, nil, b, current, 0); err != sharedpg.ErrTrustState {
		t.Fatal("invalid key accepted")
	}
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSharedTrustFile(path, root, b, current, 0); err != errSharedTrustConflict {
		t.Fatal("busy state overwritten")
	}
	release()
	parent := filepath.Join(dir, "file")
	if err := os.WriteFile(parent, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeSharedTrustFile(filepath.Join(parent, "child"), root, b, current, 0); err != errSharedTrustStorage {
		t.Fatal("invalid parent accepted")
	}
}

func TestSharedTrustFileConcurrentUpdates(t *testing.T) {
	root, b, current, next := sharedTrustFileFixture(t)
	path := filepath.Join(t.TempDir(), "device.trust")
	if err := writeSharedTrustFile(path, root, b, current, 0); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- writeSharedTrustFile(path, root, b, next, 1) }()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if err != errSharedTrustConflict {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatal("concurrent updates had no unique winner")
	}
}

func TestSharedTrustFileUncertainDurability(t *testing.T) {
	root, b, current, next := sharedTrustFileFixture(t)
	path := filepath.Join(t.TempDir(), "device.trust")
	if err := writeSharedTrustFile(path, root, b, current, 0); err != nil {
		t.Fatal(err)
	}
	original := privateFileDirectorySync
	t.Cleanup(func() { privateFileDirectorySync = original })
	privateFileDirectorySync = func(string) error { return errors.New("synthetic directory sync failure") }
	if err := writeSharedTrustFile(path, root, b, next, 1); err != errSharedTrustCommitUncertain {
		t.Fatal("uncertain durability reported as success")
	}
	if err := confirmSharedTrustFile(path, root, b, next); err != errSharedTrustCommitUncertain {
		t.Fatal("continuing durability failure was hidden")
	}
	privateFileDirectorySync = original
	if err := confirmSharedTrustFile(path, root, b, next); err != nil {
		t.Fatal(err)
	}
	loaded, err := readSharedTrustFile(path, root, b, 2)
	if err != nil || loaded.Revision != 2 {
		t.Fatal("uncertain committed state unreadable")
	}
	if err := writeSharedTrustFile(path, root, b, next, 1); err != errSharedTrustConflict {
		t.Fatal("blind retry accepted after uncertain commit")
	}
}

func TestSharedTrustConfirmationCannotChangeState(t *testing.T) {
	root, b, current, next := sharedTrustFileFixture(t)
	path := filepath.Join(t.TempDir(), "device.trust")
	if err := confirmSharedTrustFile(path, root, b, current); err != errSharedTrustMissing {
		t.Fatal("confirmation created missing state")
	}
	if err := writeSharedTrustFile(path, root, b, current, 0); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*sharedpg.TrustState){
		func(s *sharedpg.TrustState) { s.PolicySequence++ }, func(s *sharedpg.TrustState) { s.SignerKeyID = "other" }, func(s *sharedpg.TrustState) { s.SignerKeyVersion++ },
		func(s *sharedpg.TrustState) { s.PublicKey = bytes.Repeat([]byte{2}, 32) }, func(s *sharedpg.TrustState) { s.PolicyDigest = bytes.Repeat([]byte{3}, 32) },
		func(s *sharedpg.TrustState) { s.UserID = uuid.New() }, func(s *sharedpg.TrustState) { s.DeviceID = uuid.New() }, func(s *sharedpg.TrustState) { s.WorkspaceID = uuid.New() },
		func(s *sharedpg.TrustState) { s.FormatVersion++ },
		func(s *sharedpg.TrustState) { s.SignedProfile = append(bytes.Clone(s.SignedProfile), ' ') },
	} {
		bad := current
		change(&bad)
		if err := confirmSharedTrustFile(path, root, b, bad); err != errSharedTrustConflict {
			t.Fatal("confirmation changed state")
		}
	}
	if err := confirmSharedTrustFile(path, root, b, next); err != sharedpg.ErrTrustRollback {
		t.Fatal("confirmation accepted an older revision")
	}
	if err := confirmSharedTrustFile("relative", root, b, current); err != errSharedTrustStorage {
		t.Fatal("relative path accepted")
	}
	if err := confirmSharedTrustFile(path, root, b, sharedpg.TrustState{}); err != errSharedTrustConflict {
		t.Fatal("empty expected state accepted")
	}
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if err := confirmSharedTrustFile(path, root, b, current); err != errSharedTrustConflict {
		t.Fatal("busy state confirmed")
	}
	release()
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := confirmSharedTrustFile(path, root, b, current); err != sharedpg.ErrTrustState {
		t.Fatal("confirmation reset corruption")
	}
}
